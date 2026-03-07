"""CLARIOstar Plus absorbance measurement mixin (discrete + spectrum)."""

import logging
import math
import time
from typing import Dict, List, Literal, Optional, Tuple

from pylabrobot.resources.plate import Plate
from pylabrobot.resources.well import Well

from ._protocol import (
  FrameError,
  _CORE_REFERENCE,
  _PRE_REFERENCE,
  _REFERENCE_BLOCK,
  _SEPARATOR,
  _TRAILER,
)

logger = logging.getLogger("pylabrobot")


class _AbsorbanceMixin:
  """Discrete absorbance and absorbance spectrum measurement methods."""

  # --------------------------------------------------------------------------
  # Feature: Absorbance Measurement
  # --------------------------------------------------------------------------

  def _build_absorbance_payload(
    self,
    plate: Plate,
    wells: List[Well],
    wavelengths: List[int],
    flashes: int = 5,
    well_scan: Literal["point", "orbital", "spiral", "matrix"] = "point",
    scan_diameter_mm: int = 3,
    matrix_size: int = 0,
    bidirectional: bool = True,
    vertical: bool = True,
    corner: Literal["TL", "TR", "BL", "BR"] = "TL",
    shake_pattern: Optional[Literal["orbital", "linear", "double_orbital", "meander"]] = None,
    shake_rpm: int = 0,
    shake_duration_s: int = 0,
    settling_time_s: float = 0.0,
    pause_time: Optional[int] = None,
  ) -> bytes:
    """Build the payload for a MEASUREMENT_RUN absorbance command.

    These parameters are passed to send_command(CommandFamily.RUN, parameters=...),
    which prepends the 0x04 command family byte to produce the full frame payload.

    Args:
      settling_time_s: Wait time after shaking (0.0-1.0 s). Encoded as the
        pause_time byte via ``int(settling_time_s * 50)``. Verified for 0.1 s → 5
        and 0.5 s → 25 (capture F01, G01). TODO: confirm with M-series captures.
      pause_time: Override the pause_time byte directly (for hardware-verified ground truth
        tests). When None (default), computed from settling_time_s.

    Returns:
      Payload bytes (135 for point/1wl, 140 for orbital/1wl, +2 per extra wl).
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
      "matrix": self.WellScanMode.MATRIX,
    }
    wsm = scan_mode_map[well_scan]
    pre_sep = self._pre_separator_block(
      detection_mode=self.DetectionMode.ABSORBANCE,
      well_scan_mode=wsm,
      shake_pattern=shake_pattern,
      shake_rpm=shake_rpm,
      shake_duration_s=shake_duration_s,
    )

    # 4. Separator (4 bytes)
    sep = _SEPARATOR

    # 5. Well scan field (0 or 5 bytes)
    well_0 = plate.get_all_items()[0]
    well_diam_100 = int(round(min(well_0.get_size_x(), well_0.get_size_y()) * 100))
    wsf = self._well_scan_field(
      wsm, self.DetectionMode.ABSORBANCE, scan_diameter_mm, well_diam_100, matrix_size
    )

    # 6. Pause time (1 byte)
    # OEM encodes settling delay as pause_time = int(settling_s * 50).
    # Verified: 0.1s→0x05 (F01), 0.5s→0x19 (G01). G02 (1.0s) anomalous.
    # TODO: confirm formula with M-series captures.
    if pause_time is None:
      pause_time = max(int(settling_time_s * 50), 1) if settling_time_s > 0 else 0x05
    pause = bytes([pause_time])

    # 7. Num wavelengths (1 byte) + wavelength data (2 bytes × N, nm×10 u16 BE)
    num_wl = bytes([len(wavelengths)])
    wl_data = b""
    for wl in wavelengths:
      wl_data += (wl * 10).to_bytes(2, "big")

    # 8. Reference block (13 bytes)
    ref = _REFERENCE_BLOCK

    # 9. Settling fields (1 + 2 bytes): always 0x00 in all OEM captures.
    # Actual settling is encoded via pause_time (step 6 above).
    settling_flag = b"\x00"
    settling_time = b"\x00\x00"

    # 10. Trailer (11 bytes)
    trailer = _TRAILER

    # 11. Flashes (2 bytes u16 BE)
    flash_bytes = flashes.to_bytes(2, "big")

    # 12. Final bytes
    final = b"\x00\x01\x00"

    payload = (
      plate_bytes
      + scan_byte
      + pre_sep
      + sep
      + wsf
      + pause
      + num_wl
      + wl_data
      + ref
      + settling_flag
      + settling_time
      + trailer
      + flash_bytes
      + final
    )

    return payload

  def _build_absorbance_spectrum_payload(
    self,
    plate: Plate,
    wells: List[Well],
    start_wavelength: int,
    end_wavelength: int,
    step_size: int,
    flashes: int = 5,
    well_scan: Literal["point", "orbital", "spiral", "matrix"] = "point",
    scan_diameter_mm: int = 3,
    matrix_size: int = 0,
    bidirectional: bool = True,
    vertical: bool = True,
    corner: Literal["TL", "TR", "BL", "BR"] = "TL",
    shake_pattern: Optional[Literal["orbital", "linear", "double_orbital", "meander"]] = None,
    shake_rpm: int = 0,
    shake_duration_s: int = 0,
    settling_time_s: float = 0.0,
    pause_time: Optional[int] = None,
  ) -> bytes:
    """Build the payload for a MEASUREMENT_RUN absorbance spectrum command.

    Mirrors ``_build_absorbance_payload`` but encodes spectrum parameters:
    ``num_wl=0x00`` signals spectrum mode, followed by start/end/step as
    u16 BE (nm x 10). Only ``_CORE_REFERENCE`` (9 bytes) is included --
    ``_PRE_REFERENCE`` is not used because its 4 bytes are replaced by the
    end + step fields in the wavelength encoding.

    Verified byte-for-byte against H01/H02/H03/H04/H05 USB captures.

    Args:
      start_wavelength: Start wavelength in nm (220-1000).
      end_wavelength: End wavelength in nm (220-1000), must be > start_wavelength.
      step_size: Step size in nm (1, 2, 5, 10, etc.).
      pause_time: Override the pause_time byte directly (for hardware-verified ground truth
        tests). When None (default), computed from settling_time_s.

    Returns:
      Payload bytes (same size as discrete for point scan: 135 bytes).
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
      "matrix": self.WellScanMode.MATRIX,
    }
    wsm = scan_mode_map[well_scan]
    pre_sep = self._pre_separator_block(
      detection_mode=self.DetectionMode.ABSORBANCE,
      well_scan_mode=wsm,
      shake_pattern=shake_pattern,
      shake_rpm=shake_rpm,
      shake_duration_s=shake_duration_s,
    )

    # 4. Separator (4 bytes)
    sep = _SEPARATOR

    # 5. Well scan field (0 or 5 bytes)
    well_0 = plate.get_all_items()[0]
    well_diam_100 = int(round(min(well_0.get_size_x(), well_0.get_size_y()) * 100))
    wsf = self._well_scan_field(
      wsm, self.DetectionMode.ABSORBANCE, scan_diameter_mm, well_diam_100, matrix_size
    )

    # 6. Pause time (1 byte)
    if pause_time is None:
      pause_time = max(int(settling_time_s * 50), 1) if settling_time_s > 0 else 0x05
    pause = bytes([pause_time])

    # 7. Spectrum mode: num_wl=0x00, then start/end/step as u16 BE (nm × 10)
    num_wl = b"\x00"
    start_field = (start_wavelength * 10).to_bytes(2, "big")
    end_field = (end_wavelength * 10).to_bytes(2, "big")
    step_field = (step_size * 10).to_bytes(2, "big")

    # 8. Reference block: _CORE_REFERENCE only (9 bytes)
    # In discrete mode, _PRE_REFERENCE (4 bytes) + _CORE_REFERENCE (9 bytes) = 13 bytes.
    # In spectrum mode, the 4 PRE_REFERENCE bytes are replaced by end+step fields above,
    # so only _CORE_REFERENCE is appended here.
    ref = _CORE_REFERENCE

    # 9. Settling fields (1 + 2 bytes)
    settling_flag = b"\x00"
    settling_time = b"\x00\x00"

    # 10. Trailer (11 bytes)
    trailer = _TRAILER

    # 11. Flashes (2 bytes u16 BE)
    flash_bytes = flashes.to_bytes(2, "big")

    # 12. Final bytes
    final = b"\x00\x01\x00"

    payload = (
      plate_bytes
      + scan_byte
      + pre_sep
      + sep
      + wsf
      + pause
      + num_wl
      + start_field
      + end_field
      + step_field
      + ref
      + settling_flag
      + settling_time
      + trailer
      + flash_bytes
      + final
    )

    return payload

  # -- Absorbance response parsing (decomposed into 4 steps) ----------------

  @staticmethod
  def _parse_response_header(
    payload: bytes,
  ) -> Tuple[int, int, int, int, Optional[float]]:
    """Extract metadata from the 36-byte absorbance response header.

    Returns:
      (schema, num_wl_resp, num_wells, n_positions, temperature).
      n_positions is the number of measurement positions per well (>1 for
      matrix scan). For schema 0xA9: payload[23:25] = n_positions (u16 BE).
      For schema 0x29: those bytes are temperature, so n_positions defaults to 1.
      temperature is None when the raw sensor value is ≤ 1 (inactive).
    """
    if len(payload) < 36:
      raise FrameError(f"Absorbance response too short: {len(payload)} bytes")

    schema = payload[6]
    num_wl_resp = int.from_bytes(payload[18:20], "big")
    num_wells = int.from_bytes(payload[20:22], "big")

    temp: Optional[float] = None
    n_positions = 1
    if schema == 0x29:
      raw_temp = int.from_bytes(payload[23:25], "big")
      if raw_temp > 1:
        temp = raw_temp / 10.0
    elif schema == 0xA9:
      n_positions = int.from_bytes(payload[23:25], "big") if len(payload) >= 25 else 1
      n_positions = max(n_positions, 1)
      raw_temp = int.from_bytes(payload[34:36], "big")
      if raw_temp > 1:
        temp = raw_temp / 10.0

    return schema, num_wl_resp, num_wells, n_positions, temp

  @staticmethod
  def _detect_group_layout(payload_len: int, num_wells: int, num_wl_resp: int) -> int:
    """Determine how many extra groups follow group 0 in the data section.

    Layout: [header 36B] [group0] [N extra groups] [(1+N) × 8B cal] [0-1 trail]

    Solves for N from payload size::

      bytes_after_group0 = N × (wells×4) + (1+N) × 8 + trailing
                         = N × (wells×4 + 8) + 8 + trailing
      N = (bytes_after_group0 - 8 - trailing) / (wells×4 + 8)

    General pattern for W wavelengths: W + 2 extra groups (W + 3 total),
    W + 3 cal pairs. Reference is always the last group with the last
    cal pair.

    Returns:
      Number of extra groups (0 if detection fails).
    """
    group0_size = num_wells * num_wl_resp * 4
    bytes_after_group0 = payload_len - 36 - group0_size
    w4 = num_wells * 4
    if w4 <= 0:
      return 0
    for trailing in (1, 0):
      n_float = (bytes_after_group0 - 8 - trailing) / (w4 + 8)
      if n_float >= 0 and abs(n_float - round(n_float)) < 0.01:
        return int(round(n_float))
    return 0

  @staticmethod
  def _extract_groups(
    payload: bytes,
    num_wells: int,
    num_wl_resp: int,
    extra_groups: int,
  ) -> Tuple[List[int], List[List[int]], List[Tuple[int, int]]]:
    """Read group 0, extra groups, and calibration pairs from the data section.

    Returns:
      (group0, extras, cal_pairs) where group0 is a flat list of u32 values,
      extras is a list of per-group u32 lists, and cal_pairs is a list of
      (hi, lo) tuples.
    """
    offset = 36

    def _read_u32s(count: int) -> List[int]:
      nonlocal offset
      end = offset + count * 4
      if end > len(payload):
        raise ValueError(
          f"payload too short: need {end} bytes for {count} u32s at offset {offset}, "
          f"but payload is {len(payload)} bytes"
        )
      values = []
      for _ in range(count):
        values.append(int.from_bytes(payload[offset : offset + 4], "big"))
        offset += 4
      return values

    group0 = _read_u32s(num_wells * num_wl_resp)
    extras = [_read_u32s(num_wells) for _ in range(extra_groups)]

    num_cal_pairs = 1 + extra_groups
    cal_pairs: List[Tuple[int, int]] = []
    for _ in range(num_cal_pairs):
      hi = int.from_bytes(payload[offset : offset + 4], "big")
      offset += 4
      lo = int.from_bytes(payload[offset : offset + 4], "big")
      offset += 4
      cal_pairs.append((hi, lo))

    return group0, extras, cal_pairs

  def _compute_results(
    self,
    group0: List[int],
    extras: List[List[int]],
    cal_pairs: List[Tuple[int, int]],
    num_wells: int,
    n_positions: int,
    temp: Optional[float],
    plate: Plate,
    wells: List[Well],
    wavelengths: List[int],
    report: Literal["optical_density", "transmittance", "raw"],
  ) -> List[Dict]:
    """Convert extracted groups into per-wavelength result dicts.

    TODO: Add detailed documentation for the calibration math (chrom2/chrom3
    role, dark-subtraction assumptions, multi-wavelength group mapping). The
    current docstring covers the formula but not the full data-flow from raw
    u32 firmware values through group extraction to final OD/T/raw.

    Assigns groups by position:
      Single WL (3 extras): chrom2, chrom3, ref
      Dual WL   (4 extras): WL2, chrom2, chrom3, ref
      Triple WL (5 extras): WL2, WL3, chrom2, chrom3, ref

    When n_positions > 1 (matrix scan), each well has n_positions consecutive
    values. These are averaged per well before computing OD/transmittance.

    Transmittance formula (no dark subtraction)::

      T = (sample / c_hi) × (r_hi / ref)
      T% = T × 100
      OD = -log10(T)
    """
    effective = num_wells * n_positions

    def _avg_positions(flat: List, n_wells: int, n_pos: int) -> List:
      """Average n_pos consecutive values per well."""
      if n_pos <= 1:
        return flat
      return [sum(flat[w * n_pos:(w + 1) * n_pos]) / n_pos for w in range(n_wells)]

    num_extra_wl = max(0, len(extras) - 3)

    # Concatenate all WL sample values: group0 + extra WL groups
    samples = list(group0)
    for wl_extra_idx in range(num_extra_wl):
      samples.extend(extras[wl_extra_idx])

    # Reference is always the LAST extra group
    refs_raw = extras[-1] if extras else [0] * effective
    refs = _avg_positions(refs_raw, num_wells, n_positions)

    # Reference calibration is always the LAST cal pair
    ref_cal = cal_pairs[-1] if len(cal_pairs) >= 2 else (0, 0)
    r_hi = ref_cal[0]
    now = time.time()

    results: List[Dict] = []
    for wl_idx, wl_nm in enumerate(wavelengths):
      wl_cal = cal_pairs[wl_idx] if wl_idx < len(cal_pairs) else cal_pairs[0]
      c_hi = wl_cal[0]

      # Extract this wavelength's slice and average positions
      wl_slice = samples[wl_idx * effective:(wl_idx + 1) * effective]
      wl_averaged = _avg_positions(wl_slice, num_wells, n_positions)

      if report == "raw":
        raw_flat: List[float] = [float(v) for v in wl_averaged]
        grid = self._map_readings_to_plate_grid(raw_flat, wells, plate)
        results.append(
          {
            "wavelength": wl_nm,
            "time": now,
            "temperature": temp,
            "data": grid,
            "references": [float(v) for v in refs],
            "chromatic_cal": wl_cal,
            "reference_cal": ref_cal,
          }
        )
      else:
        values: List[float] = []
        for i in range(num_wells):
          sample_val = wl_averaged[i]
          ref_val = refs[i]
          if c_hi > 0 and ref_val > 0:
            t = (sample_val / c_hi) * (r_hi / ref_val)
          else:
            t = 0.0
          if report == "transmittance":
            values.append(t * 100)
          else:
            values.append(-math.log10(t) if t > 0 else float("inf"))

        grid = self._map_readings_to_plate_grid(values, wells, plate)
        results.append(
          {
            "wavelength": wl_nm,
            "time": now,
            "temperature": temp,
            "data": grid,
          }
        )

    return results

  def _parse_absorbance_response(
    self,
    payload: bytes,
    plate: Plate,
    wells: List[Well],
    wavelengths: List[int],
    report: Literal["optical_density", "transmittance", "raw"] = "optical_density",
  ) -> List[Dict]:
    """Parse an ABS_DATA_RESPONSE payload into per-wavelength result dicts.

    Delegates to four steps:
      1. ``_parse_response_header`` -- validate & extract metadata
      2. ``_detect_group_layout`` -- determine extra group count from payload size
      3. ``_extract_groups`` -- read u32 arrays and calibration pairs
      4. ``_compute_results`` -- apply OD/transmittance/raw formula per wavelength

    See ``_detect_group_layout`` for the dynamic group layout documentation.
    """
    schema, num_wl_resp, num_wells, n_positions, temp = self._parse_response_header(payload)
    effective = num_wells * n_positions
    extra_groups = self._detect_group_layout(len(payload), effective, num_wl_resp)
    if extra_groups == 0 and len(payload) > 36 + effective * num_wl_resp * 4 + 8 + 1:
      logger.warning(
        "Could not determine group layout for %d-byte response (%d wells, %d wl_resp); "
        "results may be invalid (all-zero references produce OD=inf)",
        len(payload),
        effective,
        num_wl_resp,
      )
    group0, extras, cal_pairs = self._extract_groups(payload, effective, num_wl_resp, extra_groups)
    return self._compute_results(
      group0, extras, cal_pairs, num_wells, n_positions, temp, plate, wells, wavelengths, report
    )

  async def request_absorbance_results(
    self,
    plate: Plate,
    wells: List[Well],
    wavelengths: List[int],
    report: Literal["optical_density", "transmittance", "raw"] = "optical_density",
  ) -> List[Dict]:
    """Retrieve and parse completed absorbance data from the device buffer.

    Combines ``_request_measurement_data()`` (wire-level MEM-READ) with
    ``_parse_absorbance_response()`` (binary parsing + OD/T%/raw conversion)
    into a single public call.

    This method exists for the ``wait=False`` workflow: after
    ``read_absorbance(..., wait=False)`` fires the measurement, call this
    once the device is no longer busy to collect the parsed results.
    ``read_absorbance(..., wait=True)`` calls this internally after its
    polling loop completes.

    Args:
      plate: The plate used for the measurement.
      wells: Wells that were measured.
      wavelengths: Wavelengths (nm) that were measured.
      report: Output format -- see ``read_absorbance`` docstring.

    Returns:
      List of result dicts, one per wavelength (same format as
      ``read_absorbance``).
    """
    response = await self._request_measurement_data(progressive=False)
    return self._parse_absorbance_response(response, plate, wells, wavelengths, report=report)

  async def read_absorbance(
    self,
    plate: Plate,
    wells: List[Well],
    wavelength: int,
    *,
    # --- wavelength & output ---
    # TODO: ask community to abolish wavelength: int for wavelengths: List[int]
    #   expected behaviour: execute [wfl_0, wfl_1, ..., wfl_n] / well if possible
    #   (e.g. CLARIOstar, Tecan Spark) else sequentially (e.g. Byonoy A96A)
    wavelengths: Optional[List[int]] = None,  # wire protocol encodes nm×10 (u16 BE),
    # so 0.1nm precision is possible -- may need changing to float if fractional nm
    # are confirmed on hardware.
    report: Literal["optical_density", "transmittance", "raw"] = "optical_density",
    # --- optics ---
    flashes: int = 10,
    well_scan: Literal["point", "orbital", "spiral", "matrix"] = "point",
    scan_diameter_mm: int = 3,
    matrix_size: Optional[int] = None,
    # --- scan direction ---
    bidirectional: bool = True,
    vertical: bool = True,
    corner: Literal["TL", "TR", "BL", "BR"] = "TL",
    # --- shaking ---
    shake_pattern: Optional[Literal["orbital", "linear", "double_orbital", "meander"]] = None,
    shake_rpm: Optional[int] = None,
    shake_duration_s: Optional[int] = None,
    settling_time_s: Optional[float] = None,
    # --- execution ---
    read_timeout: Optional[float] = 7200,
    wait: bool = True,
  ) -> List[Dict]:
    """Measure discrete absorbance at one or more wavelengths.

    This is the top-level orchestrator. It builds the measurement payload,
    sends the RUN command, optionally polls for completion, and returns
    parsed results. It delegates to ``_build_absorbance_payload``,
    ``_request_measurement_data``, ``_measurement_progress``, and
    ``request_absorbance_results`` -- all defined above.

    Two modes of operation:

    **wait=True** (default): Sends the RUN command, then polls
    ``_request_measurement_data(progressive=True)`` in a loop until all
    values are collected (``values_written >= values_expected``). Status queries
    are interleaved between data polls, matching the Voyager protocol.
    Returns parsed results in the format specified by ``report``.

    **wait=False**: Sends the RUN command only and returns an empty list
    immediately. The measurement runs asynchronously on the device. Use
    ``request_absorbance_results()`` to retrieve and parse results once
    the device is no longer busy.

    Args:
      plate: The plate to measure.
      wells: Wells to measure.
      wavelength: Single wavelength in nm. Provide this or *wavelengths*.
      wavelengths: List of wavelengths in nm (1-8). Provide this or *wavelength*.
      report: Output format for the measurement data:

        - ``"optical_density"`` (default): OD = -log10(T), where
          T = (sample / c_hi) * (r_hi / ref). Verified ±0.001 OD vs OEM software.
        - ``"transmittance"``: Percent transmittance T% = T * 100.
        - ``"raw"``: Unprocessed detector counts. Each result dict includes
          extra keys ``"references"``, ``"chromatic_cal"``, and
          ``"reference_cal"`` alongside the per-well sample counts in
          ``"data"``.
      flashes: Flashes per well (default 10). Limits depend on well_scan mode:
        point 1-200, orbital 1-44, spiral 1-127, matrix 1-200.
      well_scan: ``"point"``, ``"orbital"``, ``"spiral"``, or ``"matrix"``
        (matrix not yet implemented).
      scan_diameter_mm: Scan diameter in mm for orbital/spiral modes.
      bidirectional: If True (default), serpentine "snake-line" scanning. If False,
        unidirectional scanning (same direction each pass, slower).
      vertical: If True, scan columns first (top→bottom). If False, scan
        rows first (left→right).
      corner: Starting corner: ``"TL"``, ``"TR"``, ``"BL"``, or ``"BR"``.
      shake_pattern: Shake plate before reading. ``None`` (default) = no shake,
        ``"orbital"``, ``"linear"``, ``"double_orbital"``, or ``"meander"``.
        When set, requires ``shake_rpm``, ``shake_duration_s``, and
        ``settling_time_s``.
      shake_rpm: Shake speed in RPM (multiples of 100, 100-700; meander
        max 300). Required when ``shake_pattern`` is set.
      shake_duration_s: Shake duration in seconds (> 0). Required when
        ``shake_pattern`` is set.
      settling_time_s: Wait time in seconds after shaking before reading
        (0.0-1.0). Required when ``shake_pattern`` is set.
      read_timeout: Safety timeout in seconds for the measurement polling
        loop.  Default 7200 (2 hours), which is sufficient for any single
        measurement run.  Set to ``None`` to poll indefinitely.  The
        coroutine can always be cancelled externally (``Ctrl+C`` /
        ``asyncio.CancelledError``).
      wait: If True, poll until measurement completes and return results.
        If False, fire the measurement and return an empty list immediately.

    Returns:
      List of dicts when wait=True, one per wavelength. Each dict has keys:
        "wavelength": int (nm),
        "time": float (epoch seconds),
        "temperature": Optional[float] (°C or None),
        "data": List[List[Optional[float]]] (2D grid, rows×cols, None for unread wells)
      When report="raw", each dict also includes:
        "references": List[int] (per-well reference detector counts),
        "chromatic_cal": Tuple[int, int] (hi, lo calibration for this wavelength),
        "reference_cal": Tuple[int, int] (hi, lo reference calibration)
      Empty list when wait=False.
    """
    # --- input validation ---
    # When both are provided, wavelengths takes priority (the PlateReader frontend
    # always passes wavelength as a required positional, so both arrive together).
    wls = wavelengths if wavelengths is not None else [wavelength]

    if not 1 <= len(wls) <= 8:
      raise ValueError(f"wavelengths must contain 1-8 entries, got {len(wls)}.")
    lo, hi = self._ABS_WAVELENGTH_RANGE
    for wl in wls:
      self._validate_wavelength(wl, "Wavelength", lo, hi)

    well_scan = self._validate_well_scan_params(
      well_scan, flashes, scan_diameter_mm, matrix_size)
    corner = self._normalize_corner(corner)

    if report not in self._VALID_ABSORBANCE_REPORTS:
      raise ValueError(
        f"report must be one of {self._VALID_ABSORBANCE_REPORTS}, got '{report}'.")

    self._validate_shake_params(
      shake_pattern, shake_rpm, shake_duration_s, settling_time_s,
      require_settling=True,
    )

    if read_timeout is not None and read_timeout <= 0:
      raise ValueError(f"read_timeout must be > 0, got {read_timeout}.")

    _shake_rpm = shake_rpm or 0
    _shake_duration_s = shake_duration_s or 0
    _settling_time_s = settling_time_s or 0.0

    # 1. Build and send measurement parameters via send_command(RUN)
    measurement_params = self._build_absorbance_payload(
      plate,
      wells,
      wls,
      flashes=flashes,
      well_scan=well_scan,
      scan_diameter_mm=scan_diameter_mm,
      matrix_size=matrix_size if matrix_size is not None else 0,
      bidirectional=bidirectional,
      vertical=vertical,
      corner=corner,
      shake_pattern=shake_pattern,
      shake_rpm=_shake_rpm,
      shake_duration_s=_shake_duration_s,
      settling_time_s=_settling_time_s,
    )
    await self.send_command(
      command_family=self.CommandFamily.RUN,
      parameters=measurement_params,
    )

    if not wait:
      return []

    # Store resume context so resume_measurement_and_collect_data() can
    # re-enter the correct polling loop and parse the final data.
    if self.pause_on_interrupt:
      self._resume_context = {
        "poll_mode": "progressive",
        "log_prefix": "ABS measurement",
        "read_timeout": read_timeout,
        "collect_fn": lambda resp, prog_complete: (
          self._parse_absorbance_response(resp, plate, wells, wls, report=report)
          if prog_complete else None
        ),
        "fallback_collect_fn": lambda: self.request_absorbance_results(
          plate, wells, wls, report=report
        ),
      }

    # 2. Progressive data + interleaved status polling (Voyager pattern).
    response, progressive_complete = await self._poll_progressive(
      read_timeout, log_prefix="ABS measurement")
    self._resume_context = None

    # 3. Retrieve final results.
    if progressive_complete:
      return self._parse_absorbance_response(response, plate, wells, wls, report=report)
    else:
      return await self.request_absorbance_results(plate, wells, wls, report=report)

  # --------------------------------------------------------------------------
  # Feature: Absorbance Spectrum Measurement
  # --------------------------------------------------------------------------
  #
  # Spectrum mode differs from discrete absorbance in three key ways:
  #   1. Payload: num_wl=0x00 signals spectrum mode; wavelength field encodes
  #      start/end/step instead of discrete values.
  #   2. Polling: Status-only polling during measurement (no progressive GET_DATA).
  #   3. Data retrieval: Paginated -- repeated standard GET_DATA calls, each
  #      returning a page of u32 data values (capacity varies by scan mode).
  #
  # Pages are concatenated (stripping 36-byte headers from pages 2+) to form
  # a virtual payload identical in layout to a discrete response, then parsed
  # by the same _parse_absorbance_response pipeline.

  async def read_absorbance_spectrum(
    self,
    plate: Plate,
    wells: List[Well],
    start_wavelength: int,
    end_wavelength: int,
    step_size: int,
    *,
    report: Literal["optical_density", "transmittance", "raw"] = "optical_density",
    flashes: int = 5,
    well_scan: Literal["point", "orbital", "spiral", "matrix"] = "point",
    scan_diameter_mm: int = 3,
    matrix_size: Optional[int] = None,
    bidirectional: bool = True,
    vertical: bool = True,
    corner: Literal["TL", "TR", "BL", "BR"] = "TL",
    shake_pattern: Optional[Literal["orbital", "linear", "double_orbital", "meander"]] = None,
    shake_rpm: Optional[int] = None,
    shake_duration_s: Optional[int] = None,
    settling_time_s: Optional[float] = None,
    read_timeout: Optional[float] = 7200,
    wait: bool = True,
  ) -> List[Dict]:
    """Measure absorbance spectrum across a wavelength range.

    Scans all wells at each wavelength from ``start_wavelength`` to
    ``end_wavelength`` in increments of ``step_size``. Returns one result
    dict per wavelength.

    Protocol differences from ``read_absorbance`` (discrete):
      - Payload encodes start/end/step instead of discrete wavelength list.
      - No progressive data polling during measurement -- status-only polling.
      - Data retrieval is paginated: multiple GET_DATA calls, each returning
        data for ~156 wavelengths.

    Args:
      plate: The plate to measure.
      wells: Wells to measure.
      start_wavelength: Start of scan range in nm (220-1000).
      end_wavelength: End of scan range in nm (220-1000), must be > start.
      step_size: Wavelength increment in nm. OEM-verified values: 1, 5.
      report: Output format -- ``"optical_density"`` (default), ``"transmittance"``,
        or ``"raw"``.
      flashes: Flashes per well per wavelength (default 5). OEM captures use 5.
      well_scan: ``"point"`` (default), ``"orbital"``, or ``"spiral"``.
      scan_diameter_mm: Scan diameter in mm for orbital/spiral modes.
      bidirectional: If True (default), serpentine scanning. If False, unidirectional.
      vertical: If True, scan columns first (top to bottom).
      corner: Starting corner: ``"TL"``, ``"TR"``, ``"BL"``, or ``"BR"``.
      shake_pattern: Shake plate before reading. None = no shake,
        ``"orbital"``, ``"linear"``, ``"double_orbital"``, or ``"meander"``.
      shake_rpm: Shake speed in RPM (multiples of 100, 100-700; meander
        max 300).
      shake_duration_s: Shake duration in seconds.
      settling_time_s: Wait time after shaking (0.0-1.0 s).
      read_timeout: Safety timeout in seconds (default 7200 = 2 hours).
        Spectrum measurements can take significantly longer than discrete.
      wait: If True, poll until complete and return results. If False, fire
        measurement and return empty list.

    Returns:
      List of result dicts when wait=True, one per wavelength. Each dict has:
        ``"wavelength"``: int (nm),
        ``"time"``: float (epoch seconds),
        ``"temperature"``: Optional[float] (°C or None),
        ``"data"``: List[List[Optional[float]]] (2D grid, rows x cols)
      When report="raw", each dict also includes:
        ``"references"``: List[int] (per-well reference detector counts),
        ``"chromatic_cal"``: Tuple[int, int] (hi, lo calibration),
        ``"reference_cal"``: Tuple[int, int] (hi, lo reference calibration)
      Empty list when wait=False.
    """
    # --- input validation ---
    lo, hi = self._ABS_WAVELENGTH_RANGE
    self._validate_wavelength(start_wavelength, "start_wavelength", lo, hi)
    self._validate_wavelength(end_wavelength, "end_wavelength", lo, hi)
    if end_wavelength <= start_wavelength:
      raise ValueError(
        f"end_wavelength ({end_wavelength}) must be > start_wavelength ({start_wavelength})."
      )
    if step_size < 1:
      raise ValueError(f"step_size must be >= 1 nm, got {step_size}.")
    if (end_wavelength - start_wavelength) % step_size != 0:
      raise ValueError(
        f"step_size ({step_size}) must evenly divide the range "
        f"({end_wavelength} - {start_wavelength} = {end_wavelength - start_wavelength} nm)."
      )

    well_scan = self._validate_well_scan_params(
      well_scan, flashes, scan_diameter_mm, matrix_size)
    corner = self._normalize_corner(corner)

    if report not in self._VALID_ABSORBANCE_REPORTS:
      raise ValueError(
        f"report must be one of {self._VALID_ABSORBANCE_REPORTS}, got '{report}'.")

    self._validate_shake_params(
      shake_pattern, shake_rpm, shake_duration_s, settling_time_s,
      require_settling=True,
    )

    if read_timeout is not None and read_timeout <= 0:
      raise ValueError(f"read_timeout must be > 0, got {read_timeout}.")

    _shake_rpm = shake_rpm or 0
    _shake_duration_s = shake_duration_s or 0
    _settling_time_s = settling_time_s or 0.0

    # 1. Build and send measurement payload
    num_wavelengths = (end_wavelength - start_wavelength) // step_size + 1
    measurement_params = self._build_absorbance_spectrum_payload(
      plate,
      wells,
      start_wavelength,
      end_wavelength,
      step_size,
      flashes=flashes,
      well_scan=well_scan,
      scan_diameter_mm=scan_diameter_mm,
      matrix_size=matrix_size if matrix_size is not None else 0,
      bidirectional=bidirectional,
      vertical=vertical,
      corner=corner,
      shake_pattern=shake_pattern,
      shake_rpm=_shake_rpm,
      shake_duration_s=_shake_duration_s,
      settling_time_s=_settling_time_s,
    )
    await self.send_command(
      command_family=self.CommandFamily.RUN,
      parameters=measurement_params,
    )

    if not wait:
      return []

    # Store resume context for spectrum polling path.
    num_wells = len(wells)
    expected_total_values = (num_wavelengths + 3) * (num_wells + 2)
    wavelengths = [start_wavelength + i * step_size for i in range(num_wavelengths)]
    if self.pause_on_interrupt:
      self._resume_context = {
        "poll_mode": "status_only",
        "log_prefix": "ABS spectrum",
        "read_timeout": read_timeout,
        "collect_fn": lambda: self._collect_abs_spectrum(
          expected_total_values, plate, wells, wavelengths, report
        ),
      }

    # 2. Status-only polling (no progressive GET_DATA for spectrum).
    await self._poll_status_only(read_timeout, log_prefix="ABS spectrum")
    self._resume_context = None

    # 3. Retrieve paginated spectrum data
    # Total u32 values = (num_wl + 3) × (num_wells + 2), matching the discrete
    # absorbance formula. The "+3" accounts for chrom2, chrom3, and reference
    # groups; the "+2" accounts for calibration pairs per group.
    pages = await self._retrieve_abs_spectrum_pages(expected_total_values)

    if not pages:
      logger.warning("spectrum: no data pages retrieved")
      return []

    # 4. Parse pages into per-wavelength results
    return self._parse_abs_spectrum_pages(pages, plate, wells, wavelengths, report=report)

