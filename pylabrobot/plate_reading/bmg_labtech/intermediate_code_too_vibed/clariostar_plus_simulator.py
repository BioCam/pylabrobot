import datetime
import math
import random
import struct
from typing import Dict, List, Optional, Tuple, Union

from pylabrobot.plate_reading.bmg_labtech.clariostar_plus_backend import (
  CLARIOstarPlusBackend,
  CLARIOstarPlusConfig,
  CommandGroup,
  Command,
  _wrap_payload,
  _validate_packet_and_extract_payload,
  _wrap_payload as _frame,  # backward compat
)
from pylabrobot.plate_reading.bmg_labtech.clariostar_plus_protocol import decode_frame
from pylabrobot.resources.plate import Plate
from pylabrobot.resources.well import Well


class CLARIOstarPlusSimulatorBackend(CLARIOstarPlusBackend):
  """A simulator backend for the CLARIOstar plate reader.

  Inherits from ``CLARIOstarPlusBackend`` so that all real command-building code
  (plate geometry encoding, scan modes, wavelength configs, shaker parameters)
  runs through the production path. The I/O layer (``send_command``) is
  overridden to print the framed command bytes and return canned responses,
  following the same pattern as ``STARChatterboxBackend``.

  When ``verbose=True``, every command sent to the instrument is printed as
  a hex dump with decoded byte-level annotations.

  Generates realistic random data from configurable mean/CV per modality,
  or accepts explicit mock data passed via ``**backend_kwargs``.

  Return formats match the real ``CLARIOstarPlusBackend`` exactly.

  Supports ``wait=False`` in read methods (returns None immediately) and
  ``collect_*_measurement()`` for deferred retrieval, mirroring the real backend.
  """

  _AMBIENT_TEMP: float = 21.0

  # Default calibration constants matching real instrument ranges
  _DEFAULT_C_HI: float = 100000.0
  _DEFAULT_R_HI: float = 200000.0

  def __init__(
    self,
    absorbance_mean: float = 0.5,
    absorbance_cv: float = 0.05,
    fluorescence_mean: float = 10000.0,
    fluorescence_cv: float = 0.10,
    luminescence_mean: float = 5000.0,
    luminescence_cv: float = 0.10,
    seed: Optional[int] = None,
    verbose: bool = False,
    machine_type_code: int = 0x0024,
  ):
    # Skip CLARIOstarPlusBackend.__init__() which creates an FTDI device.
    # Initialize all state attributes that the parent expects.
    self.timeout = 150
    self.read_timeout = 20
    self.write_timeout = 10
    self._eeprom_data: Optional[bytes] = None
    self._firmware_data: Optional[bytes] = None
    self._incubation_target: float = 0.0
    self._last_scan_params: Dict = {}
    self._machine_type_code: int = machine_type_code
    self._measurement_cache: list = []
    self._measurement_counter: int = 0
    self._pending_measurement = None

    # Simulator-specific attributes
    self.absorbance_mean = absorbance_mean
    self.absorbance_cv = absorbance_cv
    self.fluorescence_mean = fluorescence_mean
    self.fluorescence_cv = fluorescence_cv
    self.luminescence_mean = luminescence_mean
    self.luminescence_cv = luminescence_cv
    self._rng = random.Random(seed)
    self._is_open = False
    self._plate_in_drawer = False
    self._verbose = verbose

  def set_verbose(self, enabled: bool = True) -> None:
    """Enable or disable verbose mode.

    When enabled, every command frame is printed as a hex dump with decoded
    byte-level annotations, and measurement response frames are also printed.
    """
    self._verbose = enabled

  @property
  def _current_temperature(self) -> float:
    """The simulated temperature: incubation target if heating, else ambient."""
    if self._incubation_target > 0:
      return self._incubation_target
    return self._AMBIENT_TEMP

  # === Life cycle ===

  async def setup(self) -> None:
    # Build synthetic EEPROM + firmware frames so get_machine_config() works.
    self._eeprom_data = self._build_mock_eeprom_frame()
    self._firmware_data = self._build_mock_firmware_frame()

  async def stop(self) -> None:
    pass

  # === I/O overrides (the chatterbox core) ===

  async def send_command(
    self,
    command_group: "CommandGroup",
    command: "Optional[Command]" = None,
    *,
    payload: bytes = b"",
    read_timeout=None,
  ) -> bytes:
    """Print the framed command bytes and return a canned unframed response.

    Matches the new ``CLARIOstarPlusBackend.send_command()`` signature.
    """
    if command is not None:
      data = bytes([command_group, command]) + payload
    else:
      data = bytes([command_group]) + payload
    cmd = _wrap_payload(data)
    print(f"\n[SIM] SEND ({len(cmd):>4d} B): {cmd.hex(' ')}")
    if self._verbose:
      try:
        ann = decode_frame("SEND", cmd)
        print(ann.render())
      except Exception:
        pass
    return self._mock_response(data)

  async def _write_frame(self, frame: bytes) -> None:
    """Capture written frames for temperature/measurement commands that bypass send_command."""
    print(f"\n[SIM] WRITE ({len(frame):>4d} B): {frame.hex(' ')}")
    if self._verbose:
      try:
        ann = decode_frame("SEND", frame)
        print(ann.render())
      except Exception:
        pass
    # Extract the payload from the frame for mock dispatch
    try:
      inner_payload = _validate_packet_and_extract_payload(frame)
    except Exception:
      inner_payload = frame[4:-4] if len(frame) >= 8 else frame
    self._last_written_payload = inner_payload

  async def _read_frame(self, timeout=None) -> bytes:
    """Return a canned framed response for the last written payload."""
    inner_payload = getattr(self, "_last_written_payload", b"")
    response_payload = self._mock_response(inner_payload)
    # Wrap the unframed response back into a frame for _validate_packet_and_extract_payload
    return _wrap_payload(response_payload)

  async def read_resp(self, timeout=None) -> bytes:
    return await self._read_frame(timeout=timeout)

  async def _drain_buffer(self):
    pass

  async def get_stat(self):
    return "0x0000"

  async def _wait_for_ready_and_return(self, ret, timeout=None):
    return ret

  async def _wait_for_ready_with_progress(
    self,
    run_response,
    on_progress=None,
    poll_interval: float = 3.0,
    timeout=None,
  ):
    return run_response

  # === Canned response dispatch ===

  def _mock_response(self, payload: bytes) -> bytes:
    """Return a valid unframed response payload based on the command payload."""
    if not payload:
      return self._build_status_response()

    family = payload[0]

    if family == CommandGroup.STATUS:
      return self._build_hw_status_response()
    elif family == CommandGroup.HW_STATUS:
      return self._build_hw_status_response()
    elif family == CommandGroup.INITIALIZE:
      return self._build_status_response()
    elif family == CommandGroup.TRAY:
      if len(payload) > 1 and payload[1] == Command.TRAY_OPEN:
        self._is_open = True
      else:
        self._is_open = False
      return self._build_status_response()
    elif family == CommandGroup.REQUEST:
      sub = payload[1] if len(payload) > 1 else 0
      if sub == Command.REQUEST_EEPROM:
        return self._eeprom_data or self._build_mock_eeprom_payload()
      elif sub == Command.REQUEST_FIRMWARE_INFO:
        return self._firmware_data or self._build_mock_firmware_payload()
      elif sub == Command.REQUEST_MEASUREMENT:
        return self._build_status_response()
      elif sub == Command.REQUEST_USAGE_COUNTERS:
        return self._build_mock_usage_payload()
      else:
        return self._build_status_response()
    elif family == CommandGroup.TEMPERATURE:
      return self._build_status_response()
    elif family == 0x04 or len(payload) > 20:  # Measurement run
      return self._build_run_accepted_response()
    else:
      return self._build_status_response()

  def _build_status_response(self) -> bytes:
    """Build a 5-byte unframed status response: valid=T, initialized=T, not busy."""
    status = bytearray(5)
    status[1] = 0x01  # VALID
    status[3] = 0x20  # INITIALIZED
    if self._is_open:
      status[3] |= 0x01  # OPEN
    if self._plate_in_drawer:
      status[3] |= 0x02  # PLATE_DETECTED
    return bytes(status)

  def _build_hw_status_response(self) -> bytes:
    """Build a 15-byte unframed status response with temperature and state flags."""
    status = bytearray(15)
    status[1] = 0x01  # VALID
    status[3] = 0x20  # INITIALIZED
    if self._is_open:
      status[3] |= 0x01  # OPEN
    if self._plate_in_drawer:
      status[3] |= 0x02  # PLATE_DETECTED
    temp_raw = round(self._current_temperature * 10)
    status[11:13] = temp_raw.to_bytes(2, "big")  # bottom plate temp
    status[13:15] = temp_raw.to_bytes(2, "big")  # top plate temp
    return bytes(status)

  def _build_run_accepted_response(self) -> bytes:
    """Build a run-accepted unframed response (byte 0 = 0x03, 14 payload bytes)."""
    payload = bytearray(14)
    payload[0] = 0x03  # accepted echo
    payload[12:14] = (100).to_bytes(2, "big")  # dummy total values
    return bytes(payload)

  def _build_mock_eeprom_payload(self) -> bytes:
    """Build a synthetic 264-byte unframed EEPROM response payload."""
    payload = bytearray(264)
    payload[0] = 0x07  # subcommand echo
    payload[1] = 0x05  # family echo
    payload[2:4] = self._machine_type_code.to_bytes(2, "big")
    payload[11] = 0x01  # has_absorbance
    payload[12] = 0x01  # has_fluorescence
    payload[13] = 0x01  # has_luminescence
    return bytes(payload)

  # Keep old name as alias
  _build_mock_eeprom_frame = _build_mock_eeprom_payload

  def _build_mock_firmware_payload(self) -> bytes:
    """Build a synthetic 32-byte unframed firmware info response payload."""
    payload = bytearray(32)
    payload[0] = 0x09  # subcommand echo
    payload[1] = 0x05  # family echo
    payload[6:8] = (1350).to_bytes(2, "big")  # version 1.35
    date_str = b"Jan 01 2025\x00"
    payload[8:8 + len(date_str)] = date_str
    time_str = b"00:00:00"
    payload[20:20 + len(time_str)] = time_str
    return bytes(payload)

  # Keep old name as alias
  _build_mock_firmware_frame = _build_mock_firmware_payload

  def _build_mock_usage_payload(self) -> bytes:
    """Build a synthetic 43-byte unframed usage counters response payload."""
    payload = bytearray(43)
    payload[0] = 0x21  # subcommand echo
    payload[1] = 0x05  # family echo
    return bytes(payload)

  # Keep old name as alias
  _build_mock_usage_response = _build_mock_usage_payload

  # === Config / device info overrides ===

  def get_machine_config(self) -> CLARIOstarPlusConfig:
    """Return a synthetic CLARIOstarPlusConfig for the simulated instrument."""
    return CLARIOstarPlusConfig(
      serial_number="SIM-0000",
      firmware_version="1.35",
      firmware_build_timestamp="Jan 01 2025 00:00:00",
      model_name="CLARIOstar Plus (Simulator)",
      machine_type_code=self._machine_type_code,
      has_absorbance=True,
      has_fluorescence=True,
      has_luminescence=True,
      has_alpha_technology=False,
      has_pump1=False,
      has_pump2=False,
      has_stacker=False,
      monochromator_range=(220, 1000),
      num_filter_slots=11,
    )

  def get_eeprom_data(self) -> Optional[bytes]:
    """Return None (no physical EEPROM in simulation)."""
    return None

  def dump_eeprom_str(self) -> Optional[str]:
    """Return None (no physical EEPROM in simulation)."""
    return None

  # === Status / drawer / temperature overrides ===

  async def close(self, plate: Optional[Plate] = None) -> None:
    await super().close(plate)
    if plate is not None:
      self._plate_in_drawer = True

  # === Mock data generation ===

  def _generate_grid(self, rows: int, cols: int, mean: float, cv: float) -> List[List[float]]:
    """Generate a rows x cols grid of random values drawn from N(mean, mean*cv)."""
    sigma = mean * cv
    return [[self._rng.gauss(mean, sigma) for _ in range(cols)] for _ in range(rows)]

  def _mask_grid(
    self,
    grid: List[List[float]],
    wells: List[Well],
    plate: Plate,
  ) -> List[List[Optional[float]]]:
    """Mask unselected wells to None, matching CLARIOstarPlusBackend behavior."""
    rows = plate.num_items_y
    cols = plate.num_items_x
    masked: List[List[Optional[float]]] = [[None] * cols for _ in range(rows)]
    for well in wells:
      r, c = well.get_row(), well.get_column()
      if r < rows and c < cols:
        masked[r][c] = grid[r][c]
    return masked

  # === Absorbance ===

  async def read_absorbance(
    self,
    plate: Plate,
    wells: List[Well],
    wavelength: int,
    **backend_kwargs,
  ) -> Optional[List[Dict]]:
    wait = backend_kwargs.pop("wait", True)
    wavelengths = backend_kwargs.pop("wavelengths", [wavelength])
    if isinstance(wavelengths, int):
      wavelengths = [wavelengths]
    report = backend_kwargs.pop("report", "OD")
    mock_data = backend_kwargs.pop("mock_data", None)
    mean = backend_kwargs.pop("mean", self.absorbance_mean)
    cv = backend_kwargs.pop("cv", self.absorbance_cv)

    # Generate and print the command bytes the real backend would send.
    try:
      await self._start_absorbance_measurement(
        wavelengths=wavelengths, plate=plate, wells=wells,
      )
    except Exception:
      pass  # Don't let command generation errors affect mock flow

    if not wait:
      # Stash params for deferred collection
      self._pending_absorbance = {
        "plate": plate, "wells": wells, "wavelengths": wavelengths,
        "report": report, "mock_data": mock_data, "mean": mean, "cv": cv,
      }
      return None

    return self._generate_absorbance(plate, wells, wavelengths, report, mock_data, mean, cv)

  def _generate_absorbance(
    self, plate, wells, wavelengths, report, mock_data, mean, cv,
  ) -> List[Dict]:
    """Generate absorbance data via binary round-trip through the real parser.

    When ``mock_data`` is provided, it is returned directly (testing convenience).
    Otherwise:

    1. Generate target OD values (random).
    2. Reverse-engineer detector counts from OD: T = 10^(-OD),
       sample = T * c_hi * (ref / r_hi).
    3. Build a binary response frame via ``build_absorbance_response()``.
    4. If verbose, decode and print the frame.
    5. Parse through ``CLARIOstarPlusBackend._parse_absorbance_response()``.
    6. Convert parsed transmittance -> OD/transmittance/raw dicts.
    """
    # mock_data bypass: return the grid directly (no binary round-trip)
    if mock_data is not None:
      return self._generate_absorbance_mock(plate, wells, wavelengths, report, mock_data)

    rows, cols = plate.num_items_y, plate.num_items_x
    num_wells = len(wells)
    num_wl = len(wavelengths)

    c_hi = self._DEFAULT_C_HI
    r_hi = self._DEFAULT_R_HI

    # Generate per-well reference detector counts (one per well, shared across wavelengths)
    references = [self._rng.gauss(r_hi, r_hi * 0.01) for _ in range(num_wells)]

    # Generate target OD values and reverse-engineer sample detector counts
    # Layout: wells x wavelengths in row-major order (well0_wl0, well1_wl0, ..., well0_wl1, ...)
    samples: List[float] = []
    well_positions = sorted(
      [(w.get_row(), w.get_column()) for w in wells],
    )

    for wl_idx in range(num_wl):
      for i, (r, c) in enumerate(well_positions):
        od = self._rng.gauss(mean, mean * cv)
        od = max(0.0, od)  # OD can't be negative
        T = 10.0 ** (-od)
        ref_well = references[i]
        sample = T * c_hi * (ref_well / r_hi)
        samples.append(max(0.0, sample))

    # Calibration
    chromatic_cal = [(c_hi, 0.0)] * num_wl
    reference_cal = (r_hi, 0.0)

    # Temperature
    temp_raw = int(self._current_temperature * 10)
    schema = 0xA9 if self._incubation_target > 0 else 0x29

    # Build binary frame
    frame = self.build_absorbance_response(
      num_wells=num_wells,
      num_wavelengths=num_wl,
      samples=samples,
      references=references,
      chromatic_cal=chromatic_cal,
      reference_cal=reference_cal,
      temperature_raw=temp_raw,
      schema=schema,
    )

    # Verbose: decode and print the binary payload
    if self._verbose:
      framed = _wrap_payload(frame)
      try:
        ann = decode_frame("RECV", framed)
        label = f"ABSORBANCE_RESPONSE ({len(frame)} bytes payload, " \
                f"{num_wl} wl x {num_wells} wells, report={report})"
        print(f"\n[SIM] {label}")
        print(ann.render())
      except Exception:
        pass

    # Parse through the real backend parser (takes unframed payload)
    transmission_data, temperature, raw = CLARIOstarPlusBackend._parse_absorbance_response(
      frame, num_wl,
    )

    # Convert parsed data to result dicts (same format as real backend)
    results = []
    timestamp = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    if report == "raw":
      for wl_idx, wl in enumerate(wavelengths):
        raw_for_wl: List[Optional[float]] = []
        for well_idx in range(num_wells):
          flat_idx = well_idx + wl_idx * num_wells
          raw_for_wl.append(
            raw["samples"][flat_idx] if flat_idx < len(raw["samples"]) else None
          )
        results.append({
          "wavelength": wl,
          "data": self._sim_readings_to_grid(raw_for_wl, plate, wells),
          "references": raw["references"],
          "chromatic_cal": raw["chromatic_cal"][wl_idx],
          "reference_cal": raw["reference_cal"],
          "temperature": temperature if temperature is not None else self._current_temperature,
          "time": timestamp,
        })
    else:
      for wl_idx, wl in enumerate(wavelengths):
        trans_for_wl: List[Optional[float]] = []
        for well_idx in range(num_wells):
          if well_idx < len(transmission_data):
            t = (
              transmission_data[well_idx][wl_idx]
              if wl_idx < len(transmission_data[well_idx])
              else None
            )
          else:
            t = None
          trans_for_wl.append(t)

        if report == "OD":
          final_vals: List[Optional[float]] = [
            math.log10(100.0 / t) if t is not None and t > 0 else None
            for t in trans_for_wl
          ]
        elif report == "transmittance":
          final_vals = trans_for_wl
        else:
          raise ValueError(f"Invalid report type: {report}")

        results.append({
          "wavelength": wl,
          "data": self._sim_readings_to_grid(final_vals, plate, wells),
          "temperature": temperature if temperature is not None else self._current_temperature,
          "time": timestamp,
        })

    return results

  def _generate_absorbance_mock(
    self, plate, wells, wavelengths, report, mock_data,
  ) -> List[Dict]:
    """Return mock_data directly without binary round-trip (testing convenience)."""
    results = []
    for wl in wavelengths:
      entry: Dict = {
        "wavelength": wl,
        "data": mock_data,
        "temperature": self._current_temperature,
        "time": datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
      }
      if report == "raw":
        num_wells = len(wells)
        entry["references"] = [self._rng.gauss(100000, 1000) for _ in range(num_wells)]
        entry["chromatic_cal"] = (self._DEFAULT_C_HI, 0.0)
        entry["reference_cal"] = (self._DEFAULT_R_HI, 0.0)
      results.append(entry)
    return results

  @staticmethod
  def _sim_readings_to_grid(
    readings: List[Optional[float]],
    plate: Plate,
    wells: List[Well],
  ) -> List[List[Optional[float]]]:
    """Map a flat list of per-well readings onto a 2D plate grid.

    Wells are sorted by (row, col) to match firmware row-major scan order.
    Unselected wells are None.
    """
    rows, cols = plate.num_items_y, plate.num_items_x
    grid: List[List[Optional[float]]] = [[None] * cols for _ in range(rows)]
    sorted_wells = sorted(wells, key=lambda w: (w.get_row(), w.get_column()))
    for reading, well in zip(readings, sorted_wells):
      grid[well.get_row()][well.get_column()] = reading
    return grid

  async def collect_absorbance_measurement(
    self,
    plate: Plate,
    wells: List[Well],
    wavelengths: List[int],
    report: str = "OD",
  ) -> List[Dict]:
    """Retrieve absorbance data after a ``wait=False`` read."""
    pending = getattr(self, "_pending_absorbance", None)
    if pending is not None:
      result = self._generate_absorbance(**pending)
      self._pending_absorbance = None
      return result
    return self._generate_absorbance(
      plate, wells, wavelengths, report, None, self.absorbance_mean, self.absorbance_cv,
    )

  # === Fluorescence ===

  async def read_fluorescence(
    self,
    plate: Plate,
    wells: List[Well],
    excitation_wavelength: int,
    emission_wavelength: int,
    focal_height: float,
    **backend_kwargs,
  ) -> Optional[List[Dict]]:
    wait = backend_kwargs.pop("wait", True)
    mock_data = backend_kwargs.pop("mock_data", None)
    mean = backend_kwargs.pop("mean", self.fluorescence_mean)
    cv = backend_kwargs.pop("cv", self.fluorescence_cv)

    # Generate and print the command bytes the real backend would send.
    try:
      await self._start_fluorescence_measurement(
        excitation_wavelength=excitation_wavelength,
        emission_wavelength=emission_wavelength,
        focal_height=focal_height,
        plate=plate, wells=wells,
      )
    except Exception:
      pass

    if not wait:
      self._pending_fluorescence = {
        "plate": plate, "wells": wells,
        "excitation_wavelength": excitation_wavelength,
        "emission_wavelength": emission_wavelength,
        "mock_data": mock_data, "mean": mean, "cv": cv,
      }
      return None

    return self._generate_fluorescence(
      plate, wells, excitation_wavelength, emission_wavelength, mock_data, mean, cv,
    )

  def _generate_fluorescence(
    self, plate, wells, excitation_wavelength, emission_wavelength, mock_data, mean, cv,
  ) -> List[Dict]:
    rows, cols = plate.num_items_y, plate.num_items_x
    if mock_data is not None:
      data = mock_data
    else:
      full = self._generate_grid(rows, cols, mean, cv)
      data = self._mask_grid(full, wells, plate)

    return [{
      "ex_wavelength": excitation_wavelength,
      "em_wavelength": emission_wavelength,
      "data": data,
      "temperature": self._current_temperature,
      "time": datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
    }]

  async def collect_fluorescence_measurement(
    self,
    plate: Plate,
    wells: List[Well],
    excitation_wavelength: int,
    emission_wavelength: int,
  ) -> List[Dict]:
    """Retrieve fluorescence data after a ``wait=False`` read."""
    pending = getattr(self, "_pending_fluorescence", None)
    if pending is not None:
      result = self._generate_fluorescence(**pending)
      self._pending_fluorescence = None
      return result
    return self._generate_fluorescence(
      plate, wells, excitation_wavelength, emission_wavelength,
      None, self.fluorescence_mean, self.fluorescence_cv,
    )

  # === Luminescence ===

  async def read_luminescence(
    self,
    plate: Plate,
    wells: List[Well],
    focal_height: float,
    **backend_kwargs,
  ) -> Optional[List[Dict]]:
    wait = backend_kwargs.pop("wait", True)
    mock_data = backend_kwargs.pop("mock_data", None)
    mean = backend_kwargs.pop("mean", self.luminescence_mean)
    cv = backend_kwargs.pop("cv", self.luminescence_cv)

    # Generate and print the command bytes the real backend would send.
    try:
      await self._start_luminescence_measurement(
        focal_height=focal_height, plate=plate, wells=wells,
      )
    except Exception:
      pass

    if not wait:
      self._pending_luminescence = {
        "plate": plate, "wells": wells,
        "mock_data": mock_data, "mean": mean, "cv": cv,
      }
      return None

    return self._generate_luminescence(plate, wells, mock_data, mean, cv)

  def _generate_luminescence(self, plate, wells, mock_data, mean, cv) -> List[Dict]:
    rows, cols = plate.num_items_y, plate.num_items_x
    if mock_data is not None:
      data = mock_data
    else:
      full = self._generate_grid(rows, cols, mean, cv)
      data = self._mask_grid(full, wells, plate)

    return [{
      "data": data,
      "temperature": self._current_temperature,
      "time": datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
    }]

  async def collect_luminescence_measurement(
    self,
    plate: Plate,
    wells: List[Well],
  ) -> List[Dict]:
    """Retrieve luminescence data after a ``wait=False`` read."""
    pending = getattr(self, "_pending_luminescence", None)
    if pending is not None:
      result = self._generate_luminescence(**pending)
      self._pending_luminescence = None
      return result
    return self._generate_luminescence(
      plate, wells, None, self.luminescence_mean, self.luminescence_cv,
    )

  # === Binary response builder ===

  @staticmethod
  def build_absorbance_response(
    num_wells: int,
    num_wavelengths: int,
    samples: List[float],
    references: List[float],
    chromatic_cal: List[Tuple[float, float]],
    reference_cal: Tuple[float, float],
    temperature_raw: int = 250,
    schema: int = 0x29,
  ) -> bytes:
    """Build a binary absorbance response frame matching firmware format.

    The returned bytes can be parsed by ``CLARIOstarPlusBackend._parse_absorbance_response()``.

    Args:
      num_wells: Number of wells in the measurement.
      num_wavelengths: Number of wavelengths measured.
      samples: Detector counts for group 0 (chromatic 1). Length = num_wells * num_wavelengths.
      references: Reference detector counts per well. Length = num_wells.
      chromatic_cal: Per-wavelength calibration (hi, lo) pairs. Length = num_wavelengths.
      reference_cal: Reference channel calibration (hi, lo) pair.
      temperature_raw: Raw temperature value (temperature_celsius * 10). Default 250 = 25.0 C.
      schema: Schema byte. 0x29 = normal, 0xA9 = incubation active/was active.

    Returns:
      Unframed binary response payload bytes.
    """
    # 36-byte header
    # Bytes 0-1: command echo (0x02 = GET_DATA, 0x05 = DATA/QUERY family)
    # so decode_frame() correctly identifies this as a data response.
    header = bytearray(36)
    header[0] = 0x02  # GET_DATA subcommand echo
    header[1] = 0x05  # DATA/QUERY command family echo
    header[6] = schema
    total_values = num_wells * num_wavelengths * 2 + num_wavelengths * 4
    header[7:9] = total_values.to_bytes(2, "big")  # total values expected
    header[9:11] = total_values.to_bytes(2, "big")  # complete count
    header[18:20] = num_wavelengths.to_bytes(2, "big")
    header[20:22] = num_wells.to_bytes(2, "big")
    if schema & 0x80:
      header[34:36] = temperature_raw.to_bytes(2, "big")
    else:
      header[23:25] = temperature_raw.to_bytes(2, "big")

    payload = bytearray(header)

    # Group 0: chromatic 1 (sample detector counts)
    for v in samples:
      payload += struct.pack(">I", int(v))
    # Group 1: chromatic 2 (zeros)
    payload += b"\x00" * (num_wells * 4)
    # Group 2: chromatic 3 (zeros)
    payload += b"\x00" * (num_wells * 4)
    # Group 3: reference detector counts
    for v in references:
      payload += struct.pack(">I", int(v))

    # Calibration: 4 pairs (chromat1, chromat2, chromat3, ref)
    for hi, lo in chromatic_cal:
      payload += struct.pack(">II", int(hi), int(lo))
    for _ in range(len(chromatic_cal), 3):
      payload += b"\x00" * 8
    payload += struct.pack(">II", int(reference_cal[0]), int(reference_cal[1]))

    # Trailing byte
    payload += b"\x00"

    return bytes(payload)
