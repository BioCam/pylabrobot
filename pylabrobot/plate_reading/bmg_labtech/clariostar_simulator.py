import datetime
import math
import random
import struct
import warnings
from typing import Dict, List, Literal, Optional, Tuple

from pylabrobot.plate_reading.backend import PlateReaderBackend
from pylabrobot.plate_reading.bmg_labtech.clariostar_backend import (
  CLARIOstarBackend,
  CLARIOstarConfig,
  _frame,
)
from pylabrobot.plate_reading.bmg_labtech.clariostar_protocol import decode_frame
from pylabrobot.resources.plate import Plate
from pylabrobot.resources.well import Well


class CLARIOstarSimulatorBackend(PlateReaderBackend):
  """A simulator backend for the CLARIOstar plate reader.

  Generates realistic random data from configurable mean/CV per modality,
  or accepts explicit mock data passed via ``**backend_kwargs``.

  Return formats match the real ``CLARIOstarBackend`` exactly.

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
  ):
    self.absorbance_mean = absorbance_mean
    self.absorbance_cv = absorbance_cv
    self.fluorescence_mean = fluorescence_mean
    self.fluorescence_cv = fluorescence_cv
    self.luminescence_mean = luminescence_mean
    self.luminescence_cv = luminescence_cv
    self._incubation_target: float = 0.0
    self._rng = random.Random(seed)
    self._is_open = False
    self._plate_in_drawer = False
    self._verbose = verbose

  def set_verbose(self, enabled: bool = True) -> None:
    """Enable or disable verbose mode.

    When enabled, binary frames are printed with decoded byte-level annotations
    for every simulated measurement response.
    """
    self._verbose = enabled

  @property
  def _current_temperature(self) -> float:
    """The simulated temperature: incubation target if heating, else ambient."""
    if self._incubation_target > 0:
      return self._incubation_target
    return self._AMBIENT_TEMP

  async def setup(self) -> None:
    pass

  async def stop(self) -> None:
    pass

  async def open(self) -> None:
    self._is_open = True

  async def close(self, plate: Optional[Plate] = None) -> None:
    self._is_open = False
    if plate is not None:
      self._plate_in_drawer = True

  async def request_machine_status(self) -> Dict[str, bool]:
    """Return simulated status flags reflecting current simulator state."""
    return {
      "standby": False,
      "valid": True,
      "busy": False,
      "running": False,
      "unread_data": False,
      "initialized": True,
      "lid_open": False,
      "drawer_open": self._is_open,
      "plate_detected": self._plate_in_drawer,
      "z_probed": False,
      "active": False,
      "filter_cover_open": False,
    }

  async def request_drawer_open(self) -> bool:
    """Request whether the drawer is currently open."""
    return (await self.request_machine_status())["drawer_open"]

  async def request_plate_detected(self) -> bool:
    """Request whether a plate is detected in the drawer."""
    return (await self.request_machine_status())["plate_detected"]

  async def request_busy(self) -> bool:
    """Request whether the machine is currently executing a command."""
    return (await self.request_machine_status())["busy"]

  async def request_initialization_status(self) -> bool:
    """Request whether the instrument has been initialized."""
    return (await self.request_machine_status())["initialized"]

  def get_eeprom_data(self) -> Optional[bytes]:
    """Return None (no physical EEPROM in simulation)."""
    return None

  def get_machine_config(self) -> CLARIOstarConfig:
    """Return a synthetic CLARIOstarConfig for the simulated instrument."""
    return CLARIOstarConfig(
      serial_number="SIM-0000",
      firmware_version="1.35",
      firmware_build_timestamp="Jan 01 2025 00:00:00",
      model_name="CLARIOstar Plus (Simulator)",
      machine_type_code=0x0024,
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

  def dump_eeprom_str(self) -> Optional[str]:
    """Return None (no physical EEPROM in simulation)."""
    return None

  async def request_usage_counters(self) -> Dict[str, int]:
    """Return synthetic usage counters for the simulated instrument."""
    return {
      "flashes": 0, "testruns": 0, "wells": 0, "well_movements": 0,
      "active_time_s": 0, "shake_time_s": 0,
      "pump1_usage": 0, "pump2_usage": 0, "alpha_time": 0,
    }

  _MAX_TEMPERATURE: float = 45.0

  async def start_temperature_control(self, temperature: float) -> None:
    """Start active temperature control (simulated incubation).

    Raises:
      ValueError: If temperature is outside the 0–45 °C range.
    """
    if not 0 <= temperature <= self._MAX_TEMPERATURE:
      raise ValueError(
        f"Temperature must be between 0 and {self._MAX_TEMPERATURE} °C, got {temperature}."
      )

    heater_overshoot_tolerance = 0.5
    if temperature > 0 and temperature < self._current_temperature - heater_overshoot_tolerance:
      warnings.warn(
        f"Target {temperature} °C is below the current temperature "
        f"({self._current_temperature} °C). The CLARIOstar has no active cooling "
        f"and will not reach this target unless the ambient temperature drops.",
        stacklevel=2,
      )

    self._incubation_target = temperature

  async def enable_temperature_monitoring(self) -> None:
    """Enable temperature sensor monitoring without heating (no-op in simulation)."""
    pass

  async def stop_temperature_control(self) -> None:
    """Switch off the incubator and re-enable passive temperature monitoring."""
    self._incubation_target = 0.0
    await self.enable_temperature_monitoring()

  async def measure_temperature(
    self,
    sensor: Literal["mean", "bottom", "top"] = "bottom",
  ) -> float:
    """Return the current simulated incubator temperature.

    Args:
      sensor: Which heating plate sensor to read. "bottom", "top", or "mean".
        In simulation all return the same value.

    Returns:
      Temperature in °C.
    """
    return self._current_temperature

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
    """Mask unselected wells to None, matching CLARIOstarBackend behavior."""
    rows = plate.num_items_y
    cols = plate.num_items_x
    masked: List[List[Optional[float]]] = [[None] * cols for _ in range(rows)]
    for well in wells:
      r, c = well.get_row(), well.get_column()
      if r < rows and c < cols:
        masked[r][c] = grid[r][c]
    return masked

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
    5. Parse through ``CLARIOstarBackend._parse_absorbance_response()``.
    6. Convert parsed transmittance → OD/transmittance/raw dicts.
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
    # Layout: wells × wavelengths in row-major order (well0_wl0, well1_wl0, ..., well0_wl1, ...)
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

    # Verbose: decode and print the binary frame
    if self._verbose:
      ann = decode_frame("RECV", frame)
      label = f"ABSORBANCE_RESPONSE ({len(frame)} bytes, " \
              f"{num_wl} wl × {num_wells} wells, report={report})"
      print(f"\n[SIM] {label}")
      print(ann.render())

    # Parse through the real backend parser
    transmission_data, temperature, raw = CLARIOstarBackend._parse_absorbance_response(
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
          "data": self._readings_to_grid(raw_for_wl, plate, wells),
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
          "data": self._readings_to_grid(final_vals, plate, wells),
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
  def _readings_to_grid(
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

    The returned bytes can be parsed by ``CLARIOstarBackend._parse_absorbance_response()``.

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
      Framed binary response bytes.
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

    return _frame(bytes(payload))
