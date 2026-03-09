"""CLARIOstar Plus fluorescence mixin: discrete, spectrum, and filter auto-detection."""

import logging
import math
import time
from typing import Dict, List, Literal, Optional, Tuple, Union

from pylabrobot.resources.plate import Plate
from pylabrobot.resources.well import Well

from ._framing import (
  FrameError,
  _CORE_REFERENCE,
  _PRE_REFERENCE,
  _REFERENCE_BLOCK,
  _SEPARATOR,
  _TRAILER,
)
from ..optical_elements import (
  OpticalFilter,
  DichroicFilter,
)

logger = logging.getLogger("pylabrobot")


class _FluorescenceMixin:
  """Discrete fluorescence and fluorescence spectrum measurement methods."""

  # --------------------------------------------------------------------------
  # Feature: Fluorescence Measurement
  # --------------------------------------------------------------------------
  # NOTE: Gain must be set explicitly -- no auto-gain on firmware 1.35.
  # EDR is supported (verified via capture F-P01).
  # Multi-chromatic (1-5), filter, flying, matrix supported.

  # Fixed constant blocks verified identical across all 29 FL USB captures.
  _FL_MULTICHROMATIC_TEMPLATE = b"\x00\x00\x01\x00\x00\x00\x00\x00\x0c"  # 9 bytes; byte[2]=count
  _FL_INTER_CHROMATIC_SEP = b"\x00\x00\x0c"  # 3 bytes between chromatic blocks
  _FL_SLIT_MONO_MONO = b"\x00\x04\x00\x03\x00"  # 5 bytes: mono Em, mono Ex
  _FL_PAUSE = b"\x00\x00\x00"  # 3 bytes
  _FL_TRAILER = b"\x00\x00\x00\x00\x00\x00\x01\x00\x00\x00\x01"  # 11 bytes (byte 0 differs from ABS)
  _FL_TAIL = b"\x00\x01\x00"  # 3 bytes

  def _build_fluorescence_payload(
    self,
    plate: Plate,
    wells: List[Well],
    excitation_wavelength: int,
    emission_wavelength: int,
    focal_height: float,
    *,
    excitation_bandwidth: int = 15,
    emission_bandwidth: int = 20,
    dichroic_split_wavelength: Optional[float] = None,
    gain: int = 1000,
    optic_position: Literal["top", "bottom"] = "top",
    flashes: int = 10,
    settling_time_s: float = 0.1,
    well_scan: Literal["point", "orbital", "spiral", "matrix"] = "point",
    scan_diameter_mm: int = 3,
    matrix_size: int = 0,
    bidirectional: bool = True,
    vertical: bool = True,
    corner: Literal["TL", "TR", "BL", "BR"] = "TL",
    shake_pattern: Optional[Literal["orbital", "linear", "double_orbital", "meander"]] = None,
    shake_rpm: int = 0,
    shake_duration_s: int = 0,
    edr: bool = False,
    flying_mode: bool = False,
    excitation_filter: Optional["CLARIOstarPlusBackend.OpticalFilter"] = None,
    emission_filter: Optional["CLARIOstarPlusBackend.OpticalFilter"] = None,
    dichroic_filter: Optional["CLARIOstarPlusBackend.DichroicFilter"] = None,
    chromatics: Optional[List[Dict]] = None,
    # Test overrides (pass exact captured edge values to bypass ±2 firmware calibration)
    _ex_hi: Optional[int] = None,
    _ex_lo: Optional[int] = None,
    _em_hi: Optional[int] = None,
    _em_lo: Optional[int] = None,
    _dichroic_raw: Optional[int] = None,
    _chromatic_overrides: Optional[List[Dict]] = None,
  ) -> bytes:
    """Build the payload for a MEASUREMENT_RUN fluorescence command.

    Passed to ``send_command(CommandFamily.RUN, parameters=...)``, which prepends
    the 0x04 command family byte.

    Supports single chromatic (default), multi-chromatic (1-5), filter modes,
    EDR, flying mode, and matrix/orbital/spiral well scans.

    Post-separator layout per chromatic:
      settle(1) + focal(2) + multi_header(9) +
      [gain(2) + ExHi(2) + ExLo(2) + Dich(2) + EmHi(2) + EmLo(2) + slit(5)] × N +
      [inter_sep(3)] × (N-1) +
      pause(3) + trailer(11) + flashes(2) + tail(3)

    Verified byte-for-byte against 29 FL USB captures (F-A01 through F-S01).
    """
    # --- Derive mode from filter presence ---
    excitation_mode = "filter" if excitation_filter is not None else "monochromator"
    emission_mode = "filter" if emission_filter is not None else "monochromator"
    dichroic_mode = "filter" if dichroic_filter is not None else "lvdm"
    ex_filter_slot = excitation_filter.slot if excitation_filter is not None else 1
    em_filter_slot = emission_filter.slot if emission_filter is not None else 1

    # --- Build chromatic list ---
    if chromatics is not None:
      chrom_list = chromatics
    else:
      chrom_list = [{
        "excitation_wavelength": excitation_wavelength,
        "excitation_bandwidth": excitation_bandwidth,
        "emission_wavelength": emission_wavelength,
        "emission_bandwidth": emission_bandwidth,
        "gain": gain,
        "dichroic_split_wavelength": dichroic_split_wavelength,
        "excitation_filter": excitation_filter,
        "emission_filter": emission_filter,
        "ex_filter_slot": ex_filter_slot,
        "em_filter_slot": em_filter_slot,
      }]
    n_chrom = len(chrom_list)

    # 1. Plate geometry + well mask (63 bytes)
    plate_bytes = self._plate_field(plate, wells)

    # 2. Scan direction (1 byte)
    scan_byte = bytes([self._scan_direction_byte(
      bidirectional, vertical, corner, flying=flying_mode)])

    # 3. Pre-separator block (31 bytes)
    scan_mode_map = {
      "point": self.WellScanMode.POINT,
      "orbital": self.WellScanMode.ORBITAL,
      "spiral": self.WellScanMode.SPIRAL,
      "matrix": self.WellScanMode.MATRIX,
    }
    wsm = scan_mode_map[well_scan]
    optic_pos = self.OpticPosition.BOTTOM if optic_position == "bottom" else self.OpticPosition.TOP
    pre_sep = self._pre_separator_block(
      detection_mode=self.DetectionMode.FLUORESCENCE,
      well_scan_mode=wsm,
      shake_pattern=shake_pattern,
      shake_rpm=shake_rpm,
      shake_duration_s=shake_duration_s,
      optic_position=optic_pos,
      edr=edr,
    )

    # 4. Separator (4 bytes)
    sep = _SEPARATOR

    # 5. Well scan field (0 or 5 bytes for orbital/spiral/matrix)
    well_0 = plate.get_all_items()[0]
    well_diam_100 = int(round(min(well_0.get_size_x(), well_0.get_size_y()) * 100))
    wsf = self._well_scan_field(
      wsm, self.DetectionMode.FLUORESCENCE, scan_diameter_mm, well_diam_100, matrix_size
    )

    # 6. Settling time (1 byte): flying forces raw=1
    if flying_mode:
      settling = bytes([1])
    else:
      settling_raw = max(int(settling_time_s / 0.02), 1) if settling_time_s >= 0 else 1
      settling = bytes([settling_raw])

    # 7. Focal height (2 bytes u16 BE): raw = focal_mm * 100
    focal_raw = int(round(focal_height * 100))
    focal = focal_raw.to_bytes(2, "big")

    # 8. Multichromatic header (9 bytes) -- byte[2] = N chromatics
    multi = bytearray(self._FL_MULTICHROMATIC_TEMPLATE)
    multi[2] = n_chrom

    # 9. Per-chromatic blocks (17 bytes each, 3-byte inter-sep between them)
    chrom_data = bytearray()
    for i, chrom in enumerate(chrom_list):
      if i > 0:
        chrom_data += self._FL_INTER_CHROMATIC_SEP

      c_gain = chrom.get("gain", 1000)

      # Resolve per-chromatic filter objects → mode + slot
      c_ex_filter = chrom.get("excitation_filter", excitation_filter)
      c_em_filter = chrom.get("emission_filter", emission_filter)
      c_dich_filter = chrom.get("dichroic_filter", dichroic_filter)
      c_ex_mode = "filter" if c_ex_filter is not None else "monochromator"
      c_em_mode = "filter" if c_em_filter is not None else "monochromator"
      c_dich_mode = "filter" if c_dich_filter is not None else "lvdm"
      if c_ex_filter is not None:
        chrom = {**chrom, "ex_filter_slot": c_ex_filter.slot}
      if c_em_filter is not None:
        chrom = {**chrom, "em_filter_slot": c_em_filter.slot}

      ovr = (_chromatic_overrides[i]
             if _chromatic_overrides and i < len(_chromatic_overrides) else {})

      # Gain (2 bytes u16 BE)
      chrom_data += c_gain.to_bytes(2, "big")

      # --- Excitation edges ---
      if c_ex_mode == "filter":
        c_ex_hi = 0x0002  # filter flag
        c_ex_lo = chrom.get("ex_filter_slot", 1)
      elif ovr.get("ex_hi") is not None:
        c_ex_hi, c_ex_lo = ovr["ex_hi"], ovr["ex_lo"]
      elif i == 0 and _ex_hi is not None:
        c_ex_hi, c_ex_lo = _ex_hi, _ex_lo
      else:
        c_ex_wl = chrom["excitation_wavelength"]
        c_ex_bw = chrom.get("excitation_bandwidth", 15)
        c_ex_hi = int((c_ex_wl + c_ex_bw / 2) * 10)
        c_ex_lo = int((c_ex_wl - c_ex_bw / 2) * 10)

      # --- Emission edges ---
      if c_em_mode == "filter":
        c_em_hi = chrom.get("em_filter_slot", 1)
        c_em_lo = 0x0002  # filter flag (reversed from Ex!)
      elif ovr.get("em_hi") is not None:
        c_em_hi, c_em_lo = ovr["em_hi"], ovr["em_lo"]
      elif i == 0 and _em_hi is not None:
        c_em_hi, c_em_lo = _em_hi, _em_lo
      else:
        c_em_wl = chrom["emission_wavelength"]
        c_em_bw = chrom.get("emission_bandwidth", 20)
        c_em_hi = int((c_em_wl + c_em_bw / 2) * 10)
        c_em_lo = int((c_em_wl - c_em_bw / 2) * 10)

      # --- Dichroic ---
      if c_dich_mode == "filter" or c_ex_mode == "filter" or c_em_mode == "filter":
        c_dich = 0x0002  # filter flag when any channel uses filter
      elif ovr.get("dichroic") is not None:
        c_dich = ovr["dichroic"]
      elif i == 0 and _dichroic_raw is not None:
        c_dich = _dichroic_raw
      elif chrom.get("dichroic_split_wavelength") is not None:
        c_dich = int(chrom["dichroic_split_wavelength"] * 10)
      else:
        c_dich = (c_ex_hi + c_em_lo) // 2  # auto-dichroic

      chrom_data += c_ex_hi.to_bytes(2, "big")
      chrom_data += c_ex_lo.to_bytes(2, "big")
      chrom_data += c_dich.to_bytes(2, "big")
      chrom_data += c_em_hi.to_bytes(2, "big")
      chrom_data += c_em_lo.to_bytes(2, "big")

      # --- Slit config (5 bytes) ---
      slit = bytearray(5)
      slit[1] = 0x01 if c_em_mode == "filter" else 0x04
      slit[3] = 0x01 if c_ex_mode == "filter" else 0x03
      chrom_data += bytes(slit)

    # 10. Fixed tail: pause + trailer + flashes + tail
    actual_flashes = 1 if flying_mode else flashes

    payload = (
      plate_bytes
      + scan_byte
      + pre_sep
      + sep
      + wsf
      + settling
      + focal
      + bytes(multi)
      + bytes(chrom_data)
      + self._FL_PAUSE
      + self._FL_TRAILER
      + actual_flashes.to_bytes(2, "big")
      + self._FL_TAIL
    )

    return payload

  def _parse_fluorescence_response(
    self,
    payload: bytes,
    plate: Plate,
    wells: List[Well],
    chromatics: List[Tuple[int, int]],
  ) -> List[Dict]:
    """Parse a FL DATA_RESPONSE payload into result dicts.

    FL responses are simpler than ABS -- no reference groups, no chromatic calibration.
    Just raw u32 counts per well.

    Args:
      payload: Raw response payload (after frame extraction).
      plate: The plate resource.
      wells: Wells that were measured.
      chromatics: List of (ex_wavelength, em_wavelength) tuples, one per chromatic.

    Response layout:
      [6]     schema: 0xA1 (FL+incubation) or 0x21 (FL no incubation)
      [7:9]   total values (u16 BE) = wells × chromatics × matrix_positions
      [11:15] overflow threshold (u32 BE) -- 260000 normal, 700M EDR
      [32:34] temperature (u16 BE ÷10 → °C) when schema has 0x80 bit
      [34:]   data values, u32 BE per reading

    Returns:
      List of dicts, one per chromatic. Each dict:
        ``"ex_wavelength"``, ``"em_wavelength"``, ``"time"``, ``"temperature"``, ``"data"``
      For matrix mode, each well's value is the mean of its matrix positions.
    """
    if len(payload) < 34:
      raise FrameError(f"FL response too short: {len(payload)} bytes (need >= 34)")

    schema = payload[6]
    total_values = int.from_bytes(payload[7:9], "big")

    temp: Optional[float] = None
    if schema & 0x80:  # incubation flag set (0xA1)
      raw_temp = int.from_bytes(payload[32:34], "big")
      if raw_temp > 1:
        temp = raw_temp / 10.0

    # Read all data values (u32 BE from byte 34)
    all_readings: List[float] = []
    data_start = 34
    for i in range(total_values):
      offset = data_start + i * 4
      if offset + 4 <= len(payload):
        val = int.from_bytes(payload[offset : offset + 4], "big")
        all_readings.append(float(val))

    n_chrom = len(chromatics)
    n_wells = len(wells)
    values_per_well = total_values // max(n_wells * n_chrom, 1)

    # Split into per-chromatic groups and map to plate grid
    results: List[Dict] = []
    chunk_size = n_wells * values_per_well
    now = time.time()

    for c_idx, (ex_wl, em_wl) in enumerate(chromatics):
      c_start = c_idx * chunk_size
      c_end = c_start + chunk_size
      c_readings = all_readings[c_start:c_end]

      if values_per_well > 1:
        # Matrix mode: average positions per well
        averaged = [
          sum(c_readings[w * values_per_well : (w + 1) * values_per_well]) / values_per_well
          for w in range(n_wells)
        ]
      else:
        averaged = c_readings

      grid = self._map_readings_to_plate_grid(averaged, wells, plate)
      results.append({
        "ex_wavelength": ex_wl,
        "em_wavelength": em_wl,
        "time": now,
        "temperature": temp,
        "data": grid,
      })

    return results

  async def read_fluorescence(
    self,
    plate: Plate,
    wells: List[Well],
    excitation_wavelength: int,
    emission_wavelength: int,
    focal_height: float,
    *,
    # Monochromator/LVDM Usage
    excitation_bandwidth: int = 15,
    emission_bandwidth: int = 20,
    dichroic_split_wavelength: Optional[float] = None,
    # Filter/Beam Split Usage 
    excitation_filter: Optional["OpticalFilter"] = None,
    emission_filter: Optional["OpticalFilter"] = None,
    dichroic_filter: Optional["DichroicFilter"] = None,
    #
    gain: int = 1000,
    optic_position: Literal["top", "bottom"] = "top",
    # Well scan parameters
    flashes: int = 10,
    settling_time_s: float = 0.1,
    well_scan: Literal["point", "orbital", "spiral", "matrix"] = "point",
    scan_diameter_mm: int = 3,
    matrix_size: Optional[int] = None,
    # Plate scan direction arguments
    bidirectional: bool = True,
    vertical: bool = True,
    corner: Literal["TL", "TR", "BL", "BR"] = "TL",
    # Shaking parameters
    shake_pattern: Optional[Literal["orbital", "linear", "double_orbital", "meander"]] = None,
    shake_rpm: Optional[int] = None,
    shake_duration_s: Optional[int] = None,
    # Non-blocking
    wait: bool = True,
    # Enhanced Dynamic Range (raises overflow ceiling to 700M)
    edr: bool = False,
    flying_mode: bool = False,
    chromatics: Optional[List[Dict]] = None,
    read_timeout: Optional[float] = 7200,
  ) -> List[Dict]:
    """Measure fluorescence intensity.

    Sends a MEASUREMENT_RUN command, optionally polls for completion, and returns
    parsed results. Follows the same orchestration pattern as ``read_absorbance``.

    Args:
      plate: The plate to measure.
      wells: Wells to measure.
      excitation_wavelength: Excitation center wavelength in nm (320-840).
        Ignored when ``chromatics`` is provided.
      emission_wavelength: Emission center wavelength in nm (320-840).
        Ignored when ``chromatics`` is provided.
      focal_height: Focal height in mm (0-25).
      excitation_bandwidth: Excitation bandwidth in nm (default 15).
      emission_bandwidth: Emission bandwidth in nm (default 20).
      dichroic_split_wavelength: LVDM split wavelength in nm (float). None =
        auto-calculated as ``(ex_upper + em_lower) / 2``.
      gain: PMT gain (0-4095, default 1000).
      optic_position: ``"top"`` (default) or ``"bottom"`` reading.
      flashes: Flashes per well (default 10). Flying mode forces 1.
      settling_time_s: Wait time after plate movement (0.0-5.0 s, default 0.1).
      well_scan: ``"point"`` (default), ``"orbital"``, ``"spiral"``, or ``"matrix"``.
      scan_diameter_mm: Scan diameter for orbital/spiral/matrix (1-6 mm).
      bidirectional: Serpentine "snake-line" scanning (default True).
      vertical: Scan columns first (default True).
      corner: Starting corner: ``"TL"``, ``"TR"``, ``"BL"``, ``"BR"``.
      shake_pattern: ``None``, ``"orbital"``, ``"linear"``, ``"double_orbital"``, or
        ``"meander"``. Meander is limited to 300 RPM max.
      shake_rpm: Shake speed in RPM (multiples of 100, 100-700; meander
        max 300).
      shake_duration_s: Shake duration in seconds.
      read_timeout: Safety timeout in seconds (default 7200).
      wait: If True, poll until complete. If False, return empty list.
      edr: Enhanced Dynamic Range (raises overflow ceiling to 700M).
      flying_mode: Flying mode (forces settling=0, flashes=1). Point scan only.
      excitation_filter: An ``OpticalFilter`` object. When provided, selects filter
        mode for excitation (uses filter sentinel + slot). ``None`` = monochromator.
      emission_filter: An ``OpticalFilter`` object. Same behaviour for emission.
      dichroic_filter: A ``DichroicFilter`` object. Selects filter dichroic.
        ``None`` = LVDM (Linear Variable Dichroic Mirror).
      chromatics: List of 1-5 dicts for multi-chromatic measurement.
        When provided, overrides per-chromatic wavelength/gain/dichroic/filter params.
        Each dict requires ``"excitation_wavelength"`` and ``"emission_wavelength"``
        and optionally ``"excitation_bandwidth"``, ``"emission_bandwidth"``, ``"gain"``,
        ``"dichroic_split_wavelength"``, ``"excitation_filter"``,
        ``"emission_filter"``, ``"dichroic_filter"``.

    Returns:
      List of dicts (one per chromatic) when wait=True. Each dict:
        ``"ex_wavelength"``: int, ``"em_wavelength"``: int, ``"time"``: float,
        ``"temperature"``: Optional[float], ``"data"``: List[List[Optional[float]]]
      Empty list when wait=False.
    """
    # --- filter slot validation (EEPROM-based) ---
    if excitation_filter is not None:
      max_slots = self.configuration.get("excitation_filter_slots", 0)
      if max_slots > 0 and not 1 <= excitation_filter.slot <= max_slots:
        raise ValueError(
          f"excitation_filter slot {excitation_filter.slot} out of range "
          f"(instrument has {max_slots} excitation filter slots)")
    if emission_filter is not None:
      max_slots = self.configuration.get("emission_filter_slots", 0)
      if max_slots > 0 and not 1 <= emission_filter.slot <= max_slots:
        raise ValueError(
          f"emission_filter slot {emission_filter.slot} out of range "
          f"(instrument has {max_slots} emission filter slots)")
    if dichroic_filter is not None:
      max_slots = self.configuration.get("dichroic_filter_slots", 0)
      if max_slots > 0 and not 1 <= dichroic_filter.slot <= max_slots:
        raise ValueError(
          f"dichroic_filter slot {dichroic_filter.slot} out of range "
          f"(instrument has {max_slots} dichroic filter slots)")

    # --- input validation ---
    fl_lo, fl_hi = self._FL_WAVELENGTH_RANGE
    if chromatics is not None:
      if not 1 <= len(chromatics) <= 5:
        raise ValueError(f"chromatics must have 1-5 entries, got {len(chromatics)}.")
      for ci, chrom in enumerate(chromatics):
        for key in ("excitation_wavelength", "emission_wavelength"):
          if key not in chrom:
            raise ValueError(f"chromatics[{ci}] missing required key: '{key}'.")
        for wl_key in ("excitation_wavelength", "emission_wavelength"):
          wl_val = chrom[wl_key]
          filter_key = "excitation_filter" if "excitation" in wl_key else "emission_filter"
          c_has_filter = chrom.get(filter_key) is not None
          if not c_has_filter:
            self._validate_wavelength(wl_val, f"chromatics[{ci}]['{wl_key}']", fl_lo, fl_hi)
        c_gain = chrom.get("gain", 1000)
        self._validate_gain(c_gain)
      chromatic_wavelengths = [
        (c["excitation_wavelength"], c["emission_wavelength"]) for c in chromatics
      ]
    else:
      # Single-chromatic validation
      if excitation_filter is None:
        self._validate_wavelength(excitation_wavelength, "excitation_wavelength", fl_lo, fl_hi)
      if emission_filter is None:
        self._validate_wavelength(emission_wavelength, "emission_wavelength", fl_lo, fl_hi)
      self._validate_gain(gain)
      chromatic_wavelengths = [(excitation_wavelength, emission_wavelength)]

    self._validate_focal_height(focal_height)

    if optic_position not in self._VALID_OPTIC_POSITIONS:
      raise ValueError(
        f"optic_position must be one of {self._VALID_OPTIC_POSITIONS}, got '{optic_position}'."
      )

    well_scan = self._validate_well_scan_params(
      well_scan, flashes if not flying_mode else None, scan_diameter_mm, matrix_size)

    if flying_mode and well_scan != "point":
      raise ValueError("flying_mode is only supported with point well scan.")

    corner = self._normalize_corner(corner)
    self._validate_shake_params(shake_pattern, shake_rpm, shake_duration_s)

    if read_timeout is not None and read_timeout <= 0:
      raise ValueError(f"read_timeout must be > 0, got {read_timeout}.")

    _shake_rpm = shake_rpm or 0
    _shake_duration_s = shake_duration_s or 0

    # 1. Build and send measurement parameters via send_command(RUN)
    measurement_params = self._build_fluorescence_payload(
      plate,
      wells,
      excitation_wavelength,
      emission_wavelength,
      focal_height,
      excitation_bandwidth=excitation_bandwidth,
      emission_bandwidth=emission_bandwidth,
      dichroic_split_wavelength=dichroic_split_wavelength,
      gain=gain,
      optic_position=optic_position,
      flashes=flashes,
      settling_time_s=settling_time_s,
      well_scan=well_scan,
      scan_diameter_mm=scan_diameter_mm,
      matrix_size=matrix_size if matrix_size is not None else 0,
      bidirectional=bidirectional,
      vertical=vertical,
      corner=corner,
      shake_pattern=shake_pattern,
      shake_rpm=_shake_rpm,
      shake_duration_s=_shake_duration_s,
      edr=edr,
      flying_mode=flying_mode,
      excitation_filter=excitation_filter,
      emission_filter=emission_filter,
      dichroic_filter=dichroic_filter,
      chromatics=chromatics,
    )
    await self.send_command(
      command_family=self.CommandFamily.RUN,
      parameters=measurement_params,
    )

    if not wait:
      return []

    # Store resume context for fluorescence discrete.
    if self.pause_on_interrupt:
      self._resume_context = {
        "poll_mode": "progressive",
        "log_prefix": "FL measurement",
        "read_timeout": read_timeout,
        "collect_fn": lambda resp, prog_complete: (
          self._parse_fluorescence_response(resp, plate, wells, chromatic_wavelengths)
          if prog_complete else None
        ),
        "fallback_collect_fn": lambda: self._collect_fl_discrete(
          plate, wells, chromatic_wavelengths
        ),
      }

    # 2. Progressive data + interleaved status polling.
    response, progressive_complete = await self._poll_progressive(
      read_timeout, log_prefix="FL measurement")
    self._resume_context = None

    # 3. Parse results.
    if progressive_complete:
      return self._parse_fluorescence_response(
        response, plate, wells, chromatic_wavelengths
      )
    else:
      final = await self._request_measurement_data(progressive=False)
      return self._parse_fluorescence_response(
        final, plate, wells, chromatic_wavelengths
      )

  # --------------------------------------------------------------------------
  # Feature: Fluorescence Spectrum Measurement
  # --------------------------------------------------------------------------
  # Sweep excitation or emission monochromator across a wavelength range.
  # Reuses MEASUREMENT_RUN (0x04) with mode_flag=0x02 in the scan header.
  # Data returns as schema 0xA0 -- one page per well, N×u32 BE per page.
  # Verified against 2 USB captures: F-SCAN-A01 (ex scan) + F-SCAN-A02 (em scan).

  def _build_fl_spectrum_payload(
    self,
    plate: Plate,
    wells: List[Well],
    start_wavelength: int,
    end_wavelength: int,
    fixed_wavelength: int,
    focal_height: float,
    *,
    scan: Literal["excitation", "emission"] = "emission",
    scan_bandwidth: int = 10,
    fixed_bandwidth: int = 20,
    gain: int = 1000,
    flashes_per_step: int = 10,
    settling_time_s: float = 0.1,
    optic_position: Literal["top", "bottom"] = "top",
    well_scan: Literal["point", "orbital", "spiral"] = "point",
    scan_diameter_mm: int = 3,
    bidirectional: bool = True,
    vertical: bool = True,
    corner: Literal["TL", "TR", "BL", "BR"] = "TL",
    shake_pattern: Optional[Literal["orbital", "linear", "double_orbital", "meander"]] = None,
    shake_rpm: int = 0,
    shake_duration_s: int = 0,
    # Test overrides (pass exact captured edge values to bypass ±2 firmware calibration)
    _start_ex_hi: Optional[int] = None,
    _start_ex_lo: Optional[int] = None,
    _start_em_hi: Optional[int] = None,
    _start_em_lo: Optional[int] = None,
    _start_dichroic: Optional[int] = None,
    _stop_ex_hi: Optional[int] = None,
    _stop_ex_lo: Optional[int] = None,
    _stop_em_hi: Optional[int] = None,
    _stop_em_lo: Optional[int] = None,
    _stop_dichroic: Optional[int] = None,
  ) -> bytes:
    """Build the payload for a MEASUREMENT_RUN fluorescence spectral scan.

    Post-separator layout (68 bytes):
      settling(1) + focal(2) + scan_header(7) + 2×block(20) + tail(18)

    Each 20-byte block:
      slit_const(2) + flashes(2) + ExHi(2) + ExLo(2) + Dich(2) +
      EmHi(2) + EmLo(2) + filter_cfg(4) + pad(2)

    Block 1 = START wavelength config, Block 2 = STOP config.
    The firmware linearly interpolates between them.
    """
    # 1. Plate geometry + well mask (63 bytes)
    plate_bytes = self._plate_field(plate, wells)

    # 2. Scan direction (1 byte)
    scan_byte = bytes([self._scan_direction_byte(bidirectional, vertical, corner)])

    # 3. Pre-separator block (31 bytes)
    scan_mode_map = {
      "point": self.WellScanMode.POINT,
      "orbital": self.WellScanMode.ORBITAL,
      "spiral": self.WellScanMode.SPIRAL,
    }
    wsm = scan_mode_map[well_scan]
    optic_pos = self.OpticPosition.BOTTOM if optic_position == "bottom" else self.OpticPosition.TOP
    pre_sep = self._pre_separator_block(
      detection_mode=self.DetectionMode.FLUORESCENCE,
      well_scan_mode=wsm,
      shake_pattern=shake_pattern,
      shake_rpm=shake_rpm,
      shake_duration_s=shake_duration_s,
      optic_position=optic_pos,
    )

    # 4. Separator (4 bytes)
    sep = _SEPARATOR

    # 5. Well scan field (0 or 5 bytes)
    well_0 = plate.get_all_items()[0]
    well_diam_100 = int(round(min(well_0.get_size_x(), well_0.get_size_y()) * 100))
    wsf = self._well_scan_field(wsm, self.DetectionMode.FLUORESCENCE, scan_diameter_mm, well_diam_100)

    # --- Post-separator (68 bytes) ---

    # Settling (1 byte)
    settling_raw = max(int(settling_time_s / 0.02), 1) if settling_time_s >= 0 else 1
    settling = bytes([settling_raw])

    # Focal height (2 bytes u16 BE)
    focal_raw = int(round(focal_height * 100))
    focal = focal_raw.to_bytes(2, "big")

    # Scan header (7 bytes): mode_flag=0x02, step_count u16 BE, 4 zeros
    step_count = end_wavelength - start_wavelength + 1
    scan_header = bytes([0x02]) + step_count.to_bytes(2, "big") + b"\x00\x00\x00\x00"

    # --- Build two 20-byte chromatic blocks (START + STOP) ---
    def _build_spectral_block(
      ex_center: int, ex_bw: int, em_center: int, em_bw: int,
      ovr_ex_hi: Optional[int], ovr_ex_lo: Optional[int],
      ovr_em_hi: Optional[int], ovr_em_lo: Optional[int],
      ovr_dich: Optional[int],
    ) -> bytes:
      slit_const = b"\x00\x0c"
      flashes_bytes = flashes_per_step.to_bytes(2, "big")

      if ovr_ex_hi is not None:
        b_ex_hi, b_ex_lo = ovr_ex_hi, ovr_ex_lo
      else:
        b_ex_hi = int((ex_center + ex_bw / 2) * 10)
        b_ex_lo = int((ex_center - ex_bw / 2) * 10)

      if ovr_em_hi is not None:
        b_em_hi, b_em_lo = ovr_em_hi, ovr_em_lo
      else:
        b_em_hi = int((em_center + em_bw / 2) * 10)
        b_em_lo = int((em_center - em_bw / 2) * 10)

      if ovr_dich is not None:
        b_dich = ovr_dich
      else:
        b_dich = (b_ex_hi + b_em_lo) // 2

      # filter_cfg: excitation scan = 00 03 00 02, emission scan = 00 02 00 03
      if scan == "excitation":
        filter_cfg = b"\x00\x03\x00\x02"
      else:
        filter_cfg = b"\x00\x02\x00\x03"

      pad = b"\x00\x00"
      return (
        slit_const + flashes_bytes
        + b_ex_hi.to_bytes(2, "big") + b_ex_lo.to_bytes(2, "big")
        + b_dich.to_bytes(2, "big")
        + b_em_hi.to_bytes(2, "big") + b_em_lo.to_bytes(2, "big")
        + filter_cfg + pad
      )

    if scan == "excitation":
      # Excitation sweeps: start/stop use start/end for excitation, fixed for emission
      block_start = _build_spectral_block(
        start_wavelength, scan_bandwidth, fixed_wavelength, fixed_bandwidth,
        _start_ex_hi, _start_ex_lo, _start_em_hi, _start_em_lo, _start_dichroic)
      block_stop = _build_spectral_block(
        end_wavelength, scan_bandwidth, fixed_wavelength, fixed_bandwidth,
        _stop_ex_hi, _stop_ex_lo, _stop_em_hi, _stop_em_lo, _stop_dichroic)
    else:
      # Emission sweeps: start/stop use start/end for emission, fixed for excitation
      block_start = _build_spectral_block(
        fixed_wavelength, fixed_bandwidth, start_wavelength, scan_bandwidth,
        _start_ex_hi, _start_ex_lo, _start_em_hi, _start_em_lo, _start_dichroic)
      block_stop = _build_spectral_block(
        fixed_wavelength, fixed_bandwidth, end_wavelength, scan_bandwidth,
        _stop_ex_hi, _stop_ex_lo, _stop_em_hi, _stop_em_lo, _stop_dichroic)

    # Tail (18 bytes): byte[14] = 0x05 (spectral scan marker)
    tail = b"\x00" * 8 + b"\x01\x00\x00\x00\x01\x00\x05\x00\x01\x00"

    payload = (
      plate_bytes + scan_byte + pre_sep + sep + wsf
      + settling + focal + scan_header
      + block_start + block_stop
      + tail
    )
    return payload

  def _parse_fl_spectrum_pages(
    self,
    pages: List[bytes],
    plate: Plate,
    wells: List[Well],
    wavelengths: List[int],
    scan: str,
    fixed_wavelength: int,
  ) -> List[Dict]:
    """Parse FL spectral scan DATA_RESPONSE pages into per-wavelength result dicts.

    FL spectral scan responses use schema 0xA0 -- one page per well, each
    containing N u32 BE intensity values (N = step_count). This method
    transposes from per-well spectra to per-wavelength plate grids.

    Args:
      pages: Raw response payloads (one per well).
      plate: The plate resource.
      wells: Wells that were measured.
      wavelengths: Ordered list of wavelength values (1 nm steps).
      scan: ``"excitation"`` or ``"emission"``.
      fixed_wavelength: The fixed-axis wavelength.

    Returns:
      List of result dicts, one per wavelength step.
    """
    if not pages:
      raise ValueError("No FL spectrum pages to parse.")

    n_wells = len(wells)
    n_steps = len(wavelengths)

    # Extract per-well spectra and temperature from pages
    per_well_spectra: List[List[float]] = []
    temp: Optional[float] = None

    for page in pages:
      if len(page) < 34:
        raise FrameError(f"FL spectrum page too short: {len(page)} bytes (need >= 34)")
      schema = page[6]
      if temp is None and (schema & 0x80):
        raw_temp = int.from_bytes(page[32:34], "big")
        if raw_temp > 1:
          temp = raw_temp / 10.0

      # Extract u32 BE values from byte 34
      data_start = 34
      values: List[float] = []
      for i in range(n_steps):
        offset = data_start + i * 4
        if offset + 4 <= len(page):
          val = int.from_bytes(page[offset:offset + 4], "big")
          values.append(float(val))
        else:
          values.append(0.0)
      per_well_spectra.append(values)

    # Transpose: per_well_spectra[well][step] → per_step_readings[step][well]
    now = time.time()
    results: List[Dict] = []
    for step_idx, wl in enumerate(wavelengths):
      readings = [per_well_spectra[w][step_idx] for w in range(min(n_wells, len(per_well_spectra)))]
      grid = self._map_readings_to_plate_grid(readings, wells, plate)

      if scan == "excitation":
        ex_wl = wl
        em_wl = fixed_wavelength
      else:
        ex_wl = fixed_wavelength
        em_wl = wl

      results.append({
        "wavelength": wl,
        "ex_wavelength": ex_wl,
        "em_wavelength": em_wl,
        "time": now,
        "temperature": temp,
        "data": grid,
      })

    return results

  async def read_fluorescence_spectrum(
    self,
    plate: Plate,
    wells: List[Well],
    start_wavelength: int,
    end_wavelength: int,
    fixed_wavelength: int,
    focal_height: float,
    *,
    scan: Literal["excitation", "emission"] = "emission",
    scan_bandwidth: int = 10,
    fixed_bandwidth: int = 20,
    gain: int = 1000,
    flashes_per_step: int = 10,
    settling_time_s: float = 0.1,
    optic_position: Literal["top", "bottom"] = "top",
    well_scan: Literal["point", "orbital", "spiral"] = "point",
    scan_diameter_mm: int = 3,
    bidirectional: bool = True,
    vertical: bool = True,
    corner: Literal["TL", "TR", "BL", "BR"] = "TL",
    shake_pattern: Optional[Literal["orbital", "linear", "double_orbital", "meander"]] = None,
    shake_rpm: Optional[int] = None,
    shake_duration_s: Optional[int] = None,
    wait: bool = True,
    read_timeout: Optional[float] = 7200,
  ) -> List[Dict]:
    """Measure fluorescence spectrum across a wavelength range.

    Sweeps the excitation or emission monochromator from ``start_wavelength``
    to ``end_wavelength`` in 1 nm steps, keeping the other axis fixed at
    ``fixed_wavelength``. Returns one result dict per wavelength step.

    Protocol: MEASUREMENT_RUN (0x04) with mode_flag=0x02 in scan header,
    two 20-byte chromatic blocks (start + stop), and tail byte[14]=0x05.
    Data returns as schema 0xA0 -- one page per well, N×u32 BE per page.

    Args:
      plate: The plate to measure.
      wells: Wells to measure.
      start_wavelength: Start of scan range in nm (320-840).
      end_wavelength: End of scan range in nm (320-840), must be > start.
      fixed_wavelength: Fixed-axis wavelength in nm (320-840).
      focal_height: Focal height in mm (0-25).
      scan: ``"emission"`` (sweep emission, fix excitation) or
        ``"excitation"`` (sweep excitation, fix emission).
      scan_bandwidth: Monochromator slit width for swept axis (nm, default 10).
      fixed_bandwidth: Monochromator slit width for fixed axis (nm, default 20).
      gain: PMT gain (0-4095, default 1000).
      flashes_per_step: Flashes at each wavelength step (default 1000).
      settling_time_s: Wait time after plate movement (0.0-5.0 s, default 0.1).
      optic_position: ``"top"`` (default) or ``"bottom"`` reading.
      well_scan: ``"point"`` (default), ``"orbital"``, or ``"spiral"``.
        Matrix mode is not supported (untested on hardware).
      scan_diameter_mm: Scan diameter for orbital/spiral (1-6 mm).
      bidirectional: Serpentine "snake-line" scanning (default True).
      vertical: Scan columns first (default True).
      corner: Starting corner: ``"TL"``, ``"TR"``, ``"BL"``, ``"BR"``.
      shake_pattern: ``None``, ``"orbital"``, ``"linear"``, ``"double_orbital"``,
        or ``"meander"``.
      shake_rpm: Shake speed in RPM (multiples of 100, 100-700).
      shake_duration_s: Shake duration in seconds.
      wait: If True, poll until complete and return results. If False, fire
        measurement and return empty list.
      read_timeout: Safety timeout in seconds (default 7200 = 2 hours).

    Returns:
      List of result dicts when wait=True, one per wavelength step. Each dict:
        ``"wavelength"``: int (nm, swept axis),
        ``"ex_wavelength"``: int (nm), ``"em_wavelength"``: int (nm),
        ``"time"``: float (epoch seconds),
        ``"temperature"``: Optional[float] (°C or None),
        ``"data"``: List[List[Optional[float]]] (2D grid, rows x cols)
      Empty list when wait=False.
    """
    # --- input validation ---
    valid_scans = ("excitation", "emission")
    if scan not in valid_scans:
      raise ValueError(f"scan must be one of {valid_scans}, got '{scan}'.")

    fl_lo, fl_hi = self._FL_WAVELENGTH_RANGE
    self._validate_wavelength(start_wavelength, "start_wavelength", fl_lo, fl_hi)
    self._validate_wavelength(end_wavelength, "end_wavelength", fl_lo, fl_hi)
    if end_wavelength <= start_wavelength:
      raise ValueError(
        f"end_wavelength ({end_wavelength}) must be > start_wavelength ({start_wavelength})."
      )
    self._validate_wavelength(fixed_wavelength, "fixed_wavelength", fl_lo, fl_hi)

    self._validate_focal_height(focal_height)
    self._validate_gain(gain)

    well_scan = self._validate_well_scan_params(
      well_scan, None, scan_diameter_mm, None, allow_matrix=False)
    corner = self._normalize_corner(corner)

    if optic_position not in self._VALID_OPTIC_POSITIONS:
      raise ValueError(
        f"optic_position must be one of {self._VALID_OPTIC_POSITIONS}, got '{optic_position}'."
      )

    self._validate_shake_params(shake_pattern, shake_rpm, shake_duration_s)

    if read_timeout is not None and read_timeout <= 0:
      raise ValueError(f"read_timeout must be > 0, got {read_timeout}.")

    _shake_rpm = shake_rpm or 0
    _shake_duration_s = shake_duration_s or 0

    # 1. Build and send measurement payload
    measurement_params = self._build_fl_spectrum_payload(
      plate, wells,
      start_wavelength, end_wavelength, fixed_wavelength, focal_height,
      scan=scan,
      scan_bandwidth=scan_bandwidth,
      fixed_bandwidth=fixed_bandwidth,
      gain=gain,
      flashes_per_step=flashes_per_step,
      settling_time_s=settling_time_s,
      optic_position=optic_position,
      well_scan=well_scan,
      scan_diameter_mm=scan_diameter_mm,
      bidirectional=bidirectional,
      vertical=vertical,
      corner=corner,
      shake_pattern=shake_pattern,
      shake_rpm=_shake_rpm,
      shake_duration_s=_shake_duration_s,
    )
    await self.send_command(
      command_family=self.CommandFamily.RUN,
      parameters=measurement_params,
    )

    if not wait:
      return []

    # Store resume context for FL spectrum.
    num_wells = len(wells)
    wavelengths = list(range(start_wavelength, end_wavelength + 1))
    if self.pause_on_interrupt:
      self._resume_context = {
        "poll_mode": "status_only",
        "log_prefix": "FL spectrum",
        "read_timeout": read_timeout,
        "collect_fn": lambda: self._collect_fl_spectrum(
          num_wells, plate, wells, wavelengths, scan, fixed_wavelength
        ),
      }

    # 2. Status-only polling (no progressive GET_DATA for spectrum).
    await self._poll_status_only(read_timeout, log_prefix="FL spectrum")
    self._resume_context = None

    # 3. Retrieve one page per well via standard GET_DATA
    pages: List[bytes] = []
    for page_num in range(num_wells):
      try:
        page = await self._request_measurement_data(progressive=False)
      except FrameError as e:
        logger.warning("FL spectrum page %d: frame error (%s), stopping", page_num, e)
        break
      if not page or len(page) < 34:
        logger.warning("FL spectrum page %d: response too short (%d bytes), stopping",
                       page_num, len(page) if page else 0)
        break
      pages.append(page)

      # Check status byte -- 0x25 = busy (more pages), 0x05 = done
      if len(page) >= 2 and not (page[1] & 0x20):
        logger.info("FL spectrum: final page reached at page %d", page_num)
        break

    if not pages:
      logger.warning("FL spectrum: no data pages retrieved")
      return []

    # 4. Parse pages into per-wavelength results
    return self._parse_fl_spectrum_pages(
      pages, plate, wells, wavelengths, scan, fixed_wavelength
    )

  # --------------------------------------------------------------------------
  # Feature: Filter Auto-Detection
  # --------------------------------------------------------------------------
  #
  # The CLARIOstar Plus has 11 physical filter positions across 5 filter slides:
  #   - 4 excitation (2 slides × 2 positions each)
  #   - 3 dichroic   (1 slide  × 3 positions)
  #   - 4 emission   (2 slides × 2 positions each)
  #
  # The "Detect all filters" routine scans each position spectroscopically
  # using the 0x24 FILTER_SCAN command, then reads characterization results
  # via CMD_05/0x1b (FILTER_RESULT).
  #
  # Wire protocol verified against clariostar_plus_filter_autodetection_routine USB capture.
  # See FILTER_AUTODETECT_PROTOCOL.md for the full byte-level analysis.

  # (scan_mode, motor_index, motor_value, label, category, slot)
  _FILTER_SCAN_TABLE = (
    (0x20, 1, 2, "Ex 1",   "excitation", 1),
    (0x20, 1, 3, "Ex 2",   "excitation", 2),
    (0x20, 2, 2, "Ex 3",   "excitation", 3),
    (0x20, 2, 3, "Ex 4",   "excitation", 4),
    (0x23, 3, 2, "Dich A", "dichroic",   1),
    (0x23, 3, 3, "Dich B", "dichroic",   2),
    (0x23, 3, 4, "Dich C", "dichroic",   3),
    (0x21, 5, 2, "Em 5",   "emission",   1),
    (0x21, 5, 3, "Em 6",   "emission",   2),
    (0x21, 4, 2, "Em 7",   "emission",   3),
    (0x21, 4, 3, "Em 8",   "emission",   4),
  )

  # Emission scans (mode 0x21) need these 8 bytes at payload positions 6-13.
  # Configures the excitation monochromator/lamp for measuring emission filters.
  # Excitation and dichroic scans use all zeros.
  # Observed constant across all 4 emission scans in the USB capture.
  _EMISSION_SCAN_WAVELENGTH_CONFIG = bytes([
    0x04, 0x4C, 0x04, 0xB0, 0x04, 0x4C, 0x04, 0x7E,
  ])

  @staticmethod
  def _build_filter_scan_payload(
    scan_mode: int,
    motor_index: int,
    motor_value: int,
  ) -> bytes:
    """Build the parameters for a 0x24 FILTER_SCAN command.

    The full command payload sent to ``send_command`` is
    ``[0x24, scan_mode] + parameters``. This method builds the *parameters*
    portion (26 bytes).

    Args:
      scan_mode: 0x20 (excitation), 0x21 (emission), or 0x23 (dichroic).
      motor_index: Which of the 8 motor slots (0-7) to move.
      motor_value: Target position for that motor (2+ = filter slot).

    Returns:
      26-byte parameters block.
    """
    # Bytes 0-7: wavelength config (emission) or zeros (excitation/dichroic)
    if scan_mode == 0x21:
      wl_config = _FluorescenceMixin._EMISSION_SCAN_WAVELENGTH_CONFIG
    else:
      wl_config = b"\x00" * 8

    # Byte 8: 0x00, Byte 9: 0x01
    preamble = b"\x00\x01"

    # Bytes 10-25: 8 × u16 BE motor positions, all 0x0001 except target
    motors = bytearray()
    for i in range(8):
      val = motor_value if i == motor_index else 1
      motors.extend(val.to_bytes(2, "big"))

    return wl_config + preamble + bytes(motors)

  @staticmethod
  def _parse_filter_result(
    payload: bytes,
    slot: int,
    category: str,
  ) -> Optional["_FilterBase"]:
    """Parse a 0x1b FILTER_RESULT response into an OpticalFilter or DichroicFilter.

    Args:
      payload: Full response payload from ``send_command`` (starts with 0x1b).
      slot: The filter slot number (1-based) for the resulting object.
      category: ``"excitation"``, ``"emission"``, or ``"dichroic"``.

    Returns:
      ``OpticalFilter`` for occupied bandpass positions,
      ``DichroicFilter`` for occupied dichroic positions,
      ``None`` for empty positions.
    """
    # Payload byte 6: type byte (0x80=ex, 0x81=em, 0x83=dichroic)
    # Bytes 7-8: center wavelength (u16 BE, nm×10) -- bandpass only
    # Bytes 9-10: bandwidth (u16 BE, nm×10) -- bandpass only
    # Bytes 11-12: low edge (u16 BE, nm×10) -- bandpass only (or cut-on for dichroic)
    type_byte = payload[6]

    if type_byte in (0x80, 0x81):
      # TODO: "BP" assumes bandpass. Unknown how the firmware encodes longpass
      # filters in ex/em slots -- no LP filter available to test. The type byte
      # (0x80/0x81) indicates slot category, not filter type.
      bw_raw = int.from_bytes(payload[9:11], "big")
      if bw_raw == 0:
        return None  # empty position
      center_raw = int.from_bytes(payload[7:9], "big")
      center = round(center_raw / 10)
      bandwidth = round(bw_raw / 10)
      return OpticalFilter(
        slot=slot,
        name=f"BP {center}/{bandwidth}",
        center_wavelength=center,
        bandwidth=bandwidth,
      )

    if type_byte == 0x83:
      # Dichroic (long-pass) -- cut-on at bytes 11-12
      cut_on_raw = int.from_bytes(payload[11:13], "big")
      if cut_on_raw == 0:
        return None  # empty position
      cut_on = round(cut_on_raw / 10)
      return DichroicFilter(
        slot=slot,
        name=f"DM {cut_on}",
        cut_on_wavelength=cut_on,
      )

    return None

  async def detect_all_filters(self) -> Dict[str, list]:
    """Scan all 11 filter positions and auto-populate filter slide registries.

    Performs the same "Detect all filters" routine as the OEM software.
    Each position is scanned spectroscopically; the firmware characterizes
    the filter and returns center wavelength, bandwidth, and band edges.

    Detected filters are registered into ``excitation_filter_slide``,
    ``emission_filter_slide``, and ``dichroic_filter_slide``.

    Returns:
      Dict with keys ``"excitation"``, ``"emission"``, ``"dichroic"``,
      each mapping to a positional list (index = slot - 1).  Occupied
      positions contain ``OpticalFilter`` or ``DichroicFilter`` objects; empty
      positions are ``None``.

    Raises:
      TimeoutError: If a scan does not complete within ``read_timeout``.
    """
    CF = self.CommandFamily
    Cmd = self.Command

    n_ex = self.excitation_filter_slide._max_slots or 4
    n_em = self.emission_filter_slide._max_slots or 4
    n_di = self.dichroic_filter_slide._max_slots or 3
    result: Dict[str, list] = {
      "excitation": [None] * n_ex,
      "emission": [None] * n_em,
      "dichroic": [None] * n_di,
    }

    for scan_mode, motor_idx, motor_val, label, category, slot in self._FILTER_SCAN_TABLE:
      # Map scan_mode to the correct FILTER_SCAN sub-command
      scan_cmd = {
        0x20: Cmd.FILTER_SCAN_EXCITATION,
        0x21: Cmd.FILTER_SCAN_EMISSION,
        0x23: Cmd.FILTER_SCAN_DICHROIC,
      }[scan_mode]

      params = self._build_filter_scan_payload(scan_mode, motor_idx, motor_val)

      # 1. Send FILTER_SCAN -- moves slide motor and performs spectral scan
      logger.debug("detect_all_filters: scanning %s (motor %d → %d)", label, motor_idx, motor_val)
      await self.send_command(
        command_family=CF.FILTER_SCAN,
        command=scan_cmd,
        parameters=params,
        wait=True,
        read_timeout=self.read_timeout,
      )

      # 2. Drain spectral data buffer (0x11) -- firmware expects this read
      await self.send_command(
        command_family=CF.REQUEST,
        command=Cmd.SPECTRAL_DATA,
        parameters=b"\x00\x00\x00\x00\x00",
      )

      # 3. Read filter characterization result (0x1b)
      filter_payload = await self.send_command(
        command_family=CF.REQUEST,
        command=Cmd.FILTER_RESULT,
        parameters=b"\x00\x00\x00\x00\x00",
      )

      # 4. Parse and register
      detected = self._parse_filter_result(filter_payload, slot, category)
      result[category][slot - 1] = detected
      if detected is not None:
        if category == "excitation":
          self.excitation_filter_slide.register(detected)
        elif category == "emission":
          self.emission_filter_slide.register(detected)
        elif category == "dichroic":
          self.dichroic_filter_slide.register(detected)
        logger.info("detect_all_filters: %s → %s", label, detected)
      else:
        logger.debug("detect_all_filters: %s → empty", label)

    return result

