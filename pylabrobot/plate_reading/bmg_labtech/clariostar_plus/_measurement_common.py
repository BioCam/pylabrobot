"""CLARIOstar Plus shared measurement helpers: plate encoding, polling, validation, shaking."""

import asyncio
import logging
import math
import time
from typing import Dict, List, Literal, Optional, Tuple

from pylabrobot.resources.plate import Plate
from pylabrobot.resources.well import Well

from ._protocol import (
  FrameError,
  MeasurementInterrupted,
  _SEPARATOR,
  _TRAILER,
  _wrap_payload,
)

logger = logging.getLogger("pylabrobot")


class _MeasurementCommonMixin:
  """Plate encoding, scan direction, pre-separator, well scan, validation, polling, shaking."""

  # --------------------------------------------------------------------------
  # Common Reading Preparations
  # --------------------------------------------------------------------------

  def _plate_field(self, plate: Plate, wells: List[Well]) -> bytes:
    """Encode plate geometry + well mask as 63 bytes for the MEASUREMENT_RUN payload.

    The leading CommandFamily.RUN (0x04) byte is added by send_command, so this
    method returns only the plate data that follows it.

    Byte layout (all multi-byte values big-endian u16, mm×100):
      [0:2]     plate_length (size_x)
      [2:4]     plate_width (size_y)
      [4:6]     well_A1_center_x
      [6:8]     well_A1_center_y  (Y inverted: plate_width - absolute_y)
      [8:10]    last_well_center_x (plate_length - A1_x)
      [10:12]   last_well_center_y (plate_width - A1_y)
      [12]      num_cols
      [13]      num_rows
      [14]      0x00  (extra byte, constant across all 38 captures)
      [15:63]   48-byte well mask (384 bits, row-major, MSB first)

    NOTE: The 48-byte mask covers up to 384 wells. The operating manual (0430B0006B,
    p.4, dated 2019-04-01) lists 1536-well support -- predating our firmware v1.35
    (Nov 2020). 1536 wells would require 192 bytes (1536 bits), so the command format
    likely differs for 1536 plates (larger payload, or byte [14] signals an extended
    mask, or per-well selection is unavailable). All 38 USB captures used 96-well
    plates. TODO: capture a 1536-well protocol via OEM software to determine encoding.
    """
    all_wells = plate.get_all_items()
    if not all_wells:
      raise ValueError("Plate has no wells")

    num_cols = plate.num_items_x
    num_rows = plate.num_items_y
    plate_length = plate.get_size_x()
    plate_width = plate.get_size_y()

    # A1 is at index 0 in column-major order
    well_0 = all_wells[0]
    loc = well_0.location
    assert loc is not None, f"Well {well_0.name} has no location"
    a1_x = loc.x + well_0.center().x
    a1_y = plate_width - (loc.y + well_0.center().y)

    last_well_x = plate_length - a1_x
    last_well_y = plate_width - a1_y

    buf = bytearray(self._PLATE_FIELD_SIZE)
    buf[0:2] = int(round(plate_length * 100)).to_bytes(2, "big")
    buf[2:4] = int(round(plate_width * 100)).to_bytes(2, "big")
    buf[4:6] = int(round(a1_x * 100)).to_bytes(2, "big")
    buf[6:8] = int(round(a1_y * 100)).to_bytes(2, "big")
    buf[8:10] = int(round(last_well_x * 100)).to_bytes(2, "big")
    buf[10:12] = int(round(last_well_y * 100)).to_bytes(2, "big")
    buf[12] = num_cols
    buf[13] = num_rows
    buf[14] = 0x00

    # Well mask: _WELL_MASK_BYTES bytes. Bit index = row * num_cols + col.
    # get_all_items returns column-major: A1,B1,...,H1,A2,...,H12
    # so index i maps to row=i%num_rows, col=i//num_rows
    well_set = set(id(w) for w in wells)
    mask = bytearray(self._WELL_MASK_BYTES)
    for i, w in enumerate(all_wells):
      if id(w) in well_set:
        row = i % num_rows
        col = i // num_rows
        idx = row * num_cols + col
        mask[idx // 8] |= 1 << (7 - (idx % 8))
    buf[15:self._PLATE_FIELD_SIZE] = mask

    return bytes(buf)

  @staticmethod
  def _scan_direction_byte(
    bidirectional: bool = True,
    vertical: bool = True,
    corner: Literal["TL", "TR", "BL", "BR"] = "TL",
    flying: bool = False,
  ) -> int:
    """Encode the scan direction byte.

    Bit layout: | uni(7) | corner(6:5) | 0(4) | vert(3) | fly(2) | always_set(1) | 0(0) |

    Ground truth values verified across all 38+29 captures:
      0x8A: uni=1, TL, vert=1    0x0A: uni=0, TL, vert=1
      0x2A: TR                   0x4A: BL
      0x6A: BR                   0x02: horizontal (vert=0)
      0x0E: flying (TL, vert)   0x1E: flying (TL explicit, vert)
    """
    corner_map = {"TL": 0, "TR": 1, "BL": 2, "BR": 3}
    b = 0
    if not bidirectional:
      b |= 1 << 7
    b |= corner_map[corner] << 5
    if vertical:
      b |= 1 << 3
    if flying:
      b |= 1 << 2
    b |= 1 << 1  # always set
    return b

  @staticmethod
  def _pre_separator_block(
    detection_mode: "CLARIOstarPlusBackend.DetectionMode",
    well_scan_mode: "CLARIOstarPlusBackend.WellScanMode",
    shake_pattern: Optional[Literal["orbital", "linear", "double_orbital", "meander"]] = None,
    shake_rpm: int = 0,
    shake_duration_s: int = 0,
    optic_position: Optional["CLARIOstarPlusBackend.OpticPosition"] = None,
    edr: bool = False,
  ) -> bytes:
    """Build the 31-byte block between scan direction byte and separator.

    Args:
      detection_mode: Detection mode (ABSORBANCE, FLUORESCENCE).
      well_scan_mode: Well scan mode (POINT, ORBITAL, SPIRAL, MATRIX).
      shake_pattern: None, "orbital", "linear", "double_orbital", or "meander".
      shake_rpm: Shake speed in RPM (100-700, multiples of 100; meander max 300).
      shake_duration_s: Shake duration in seconds.
      optic_position: Optic position (TOP, BOTTOM). Fluorescence only.
      edr: Enhanced Dynamic Range. Sets byte[1] = 0x40. Fluorescence only.
    """
    optic_config = int(detection_mode) | int(well_scan_mode)
    if optic_position is not None:
      optic_config |= int(optic_position)

    buf = bytearray(31)
    buf[0] = optic_config
    if edr:
      buf[1] = 0x40

    if shake_pattern is not None and shake_duration_s > 0:
      buf[12] = 0x02  # mixer_action
      shake_pattern_map = {"orbital": 0, "linear": 1, "double_orbital": 2, "meander": 3}
      buf[17] = shake_pattern_map[shake_pattern]
      buf[18] = (shake_rpm // 100) - 1  # speed index
      buf[20:22] = shake_duration_s.to_bytes(2, "little")

    return bytes(buf)

  @staticmethod
  def _well_scan_field(
    well_scan_mode: "CLARIOstarPlusBackend.WellScanMode",
    detection_mode: "CLARIOstarPlusBackend.DetectionMode",
    scan_diameter_mm: int,
    well_diameter_mm_100: int,
    matrix_size: int = 0,
  ) -> bytes:
    """Build 0 or 5 bytes for non-point well scan modes.

    For point scans, returns empty bytes.
    For orbital/spiral: [meas_code, scan_width_mm, well_diam_hi, well_diam_lo, 0x00]
    For matrix: [N, scan_width_mm, well_diam_hi, well_diam_lo, 0x00]

    The measurement code byte (buf[0]) differs by detection mode:
      ABS = 0x02, FL = 0x03.
    For matrix mode, buf[0] is the grid side dimension N instead.
    Verified across all 38 ABS + 29 FL USB captures.
    """
    # WellScanMode.POINT = 0x00
    if well_scan_mode == 0x00:
      return b""
    # DetectionMode → well-scan code byte
    _WELL_SCAN_CODE = {
      0x02: 0x02,  # ABSORBANCE
      0x00: 0x03,  # FLUORESCENCE
    }
    buf = bytearray(5)
    # WellScanMode.MATRIX = 0x10
    if well_scan_mode == 0x10:
      buf[0] = matrix_size
    else:
      buf[0] = _WELL_SCAN_CODE[detection_mode]
    buf[1] = scan_diameter_mm
    buf[2:4] = well_diameter_mm_100.to_bytes(2, "big")
    buf[4] = 0x00
    return bytes(buf)

  @staticmethod
  def _map_readings_to_plate_grid(
    readings: List[float],
    wells: List[Well],
    plate: Plate,
  ) -> List[List[Optional[float]]]:
    """Map flat readings (row-major firmware order) to a 2D grid [rows][cols].

    For all wells (96 on a 96-well plate): simple reshape.
    For partial wells: sort by (row, col), place each reading at its grid position.
    Unread wells are None.
    """
    num_cols = plate.num_items_x
    num_rows = plate.num_items_y
    all_wells = plate.get_all_items()

    grid: List[List[Optional[float]]] = [[None] * num_cols for _ in range(num_rows)]

    # Build a lookup from well id to (row, col) using column-major indexing
    well_index_map = {}
    for i, w in enumerate(all_wells):
      row = i % num_rows
      col = i // num_rows
      well_index_map[id(w)] = (row, col)

    if len(wells) == len(all_wells):
      # All wells: firmware sends row-major (A1, A2, ..., A12, B1, ...)
      for i, val in enumerate(readings):
        row = i // num_cols
        col = i % num_cols
        grid[row][col] = val
    else:
      # Partial: sort wells by row-major index to match firmware order
      well_positions = []
      for w in wells:
        rc = well_index_map[id(w)]
        well_positions.append(rc)
      well_positions.sort(key=lambda rc: rc[0] * num_cols + rc[1])
      for i, (row, col) in enumerate(well_positions):
        if i < len(readings):
          grid[row][col] = readings[i]

    return grid

  @staticmethod
  def _validate_shake_params(
    shake_pattern: Optional[str],
    shake_rpm: Optional[int],
    shake_duration_s: Optional[int],
    settling_time_s: Optional[float] = None,
    *,
    require_settling: bool = False,
  ) -> None:
    """Validate shake parameters shared across all measurement methods.

    Args:
      require_settling: If True, ``settling_time_s`` is treated as part of the
        shake parameter group (required when shake is on, must be None when off).
        Used by absorbance methods. Fluorescence methods manage settling
        independently, so they pass ``require_settling=False`` (default).
    """
    valid_shake_patterns = (None, "orbital", "linear", "double_orbital", "meander")
    if shake_pattern not in valid_shake_patterns:
      raise ValueError(f"shake_pattern must be one of {valid_shake_patterns}, got '{shake_pattern}'.")
    if shake_pattern is not None:
      if shake_rpm is None:
        raise ValueError("shake_rpm is required when shake_pattern is set.")
      if shake_duration_s is None:
        raise ValueError("shake_duration_s is required when shake_pattern is set.")
      if require_settling and settling_time_s is None:
        raise ValueError("settling_time_s is required when shake_pattern is set.")
      max_rpm = 300 if shake_pattern == "meander" else 700
      if shake_rpm < 100 or shake_rpm > max_rpm or shake_rpm % 100 != 0:
        raise ValueError(
          f"shake_rpm must be a multiple of 100 in range 100-{max_rpm}, "
          f"got {shake_rpm}."
        )
      if not 0 < shake_duration_s <= 65535:
        raise ValueError(
          f"shake_duration_s must be 1-65535 when shake_pattern is set, got {shake_duration_s}."
        )
      if require_settling and settling_time_s is not None:
        if not 0 <= settling_time_s <= 1:
          raise ValueError(
            f"settling_time_s must be 0-1 (OEM software range 0.0-1.0 s), got {settling_time_s}."
          )
    else:
      if shake_rpm is not None:
        raise ValueError("shake_rpm must be None when shake_pattern is None.")
      if shake_duration_s is not None:
        raise ValueError("shake_duration_s must be None when shake_pattern is None.")
      if require_settling and settling_time_s is not None:
        raise ValueError("settling_time_s must be None when shake_pattern is None.")

  async def _poll_progressive(
    self,
    read_timeout: Optional[float],
    log_prefix: str = "measurement",
  ) -> Tuple[bytes, bool]:
    """Progressive data polling loop shared by discrete ABS and FL.

    Alternates progressive GET_DATA with interleaved status queries until the
    firmware signals completion (written >= expected) or the device is no longer
    busy.

    If the user interrupts (Ctrl+C / Jupyter stop), the device is stopped
    (or paused when ``pause_on_interrupt`` is True) and
    :class:`MeasurementInterrupted` is raised with any partial data collected.

    Returns:
      ``(response, progressive_complete)`` -- the last progressive response and
      whether it contained the complete data (True) or the loop exited via the
      busy-flag path (False, meaning a final standard GET_DATA is needed).

    Raises:
      TimeoutError: If ``read_timeout`` is exceeded.
      MeasurementInterrupted: If the user interrupts the measurement.
    """
    t0 = time.time()
    response = b""
    progressive_complete = False
    while True:
      try:
        if read_timeout is not None and time.time() - t0 > read_timeout:
          raise TimeoutError(
            f"{log_prefix} not complete after {read_timeout:.1f}s. "
            f"Pass read_timeout=None to wait indefinitely, or increase the value."
          )

        try:
          response = await self._request_measurement_data(progressive=True)
        except FrameError as e:
          logger.warning("%s data poll: bad frame (%s), retrying", log_prefix, e)
          if self.measurement_poll_interval > 0:
            await asyncio.sleep(self.measurement_poll_interval)
          continue

        written, expected = self._measurement_progress(response)
        if logger.isEnabledFor(logging.INFO):
          logger.info("%s progress: %d/%d", log_prefix, written, expected)

        if expected > 0 and written >= expected:
          progressive_complete = True
          break

        try:
          status = await self.request_machine_status()
          if not status["busy"]:
            logger.info("%s complete (device no longer busy)", log_prefix)
            break
        except FrameError as e:
          logger.debug("%s interleaved status poll: bad frame (%s), ignoring",
                       log_prefix, e)

        if self.measurement_poll_interval > 0:
          await asyncio.sleep(self.measurement_poll_interval)

      except (KeyboardInterrupt, asyncio.CancelledError):
        action = "pausing" if self.pause_on_interrupt else "stopping"
        logger.info("%s interrupted by user, %s device", log_prefix, action)
        await self._safe_interrupt()
        if self.pause_on_interrupt:
          msg = (f"{log_prefix} interrupted by user. Device is paused. "
                 "Call resume_measurement_and_collect_data() to continue "
                 "or stop_measurement() to end.")
        else:
          self._resume_context = None
          msg = f"{log_prefix} interrupted by user. Device has been stopped."
        raise MeasurementInterrupted(
          msg,
          partial_data=response if response else None,
        )

    return response, progressive_complete

  async def _poll_status_only(
    self,
    read_timeout: Optional[float],
    log_prefix: str = "measurement",
  ) -> None:
    """Status-only polling loop shared by spectrum measurements.

    Polls ``request_machine_status`` until the device is no longer busy.
    Used by spectrum modes where progressive GET_DATA is not available.

    If the user interrupts (Ctrl+C / Jupyter stop), the device is stopped
    (or paused when ``pause_on_interrupt`` is True) and
    :class:`MeasurementInterrupted` is raised.

    Raises:
      TimeoutError: If ``read_timeout`` is exceeded.
      MeasurementInterrupted: If the user interrupts the measurement.
    """
    t0 = time.time()
    while True:
      try:
        if read_timeout is not None and time.time() - t0 > read_timeout:
          raise TimeoutError(
            f"{log_prefix} not complete after {read_timeout:.1f}s. "
            f"Pass read_timeout=None to wait indefinitely, or increase the value."
          )

        try:
          status = await self.request_machine_status()
          if not status["busy"]:
            logger.info("%s complete (device no longer busy)", log_prefix)
            break
        except FrameError as e:
          logger.warning("%s status poll: bad frame (%s), retrying", log_prefix, e)

        if self.measurement_poll_interval > 0:
          await asyncio.sleep(self.measurement_poll_interval)

      except (KeyboardInterrupt, asyncio.CancelledError):
        action = "pausing" if self.pause_on_interrupt else "stopping"
        logger.info("%s interrupted by user, %s device", log_prefix, action)
        await self._safe_interrupt()
        if self.pause_on_interrupt:
          msg = (f"{log_prefix} interrupted by user. Device is paused. "
                 "Call resume_measurement_and_collect_data() to continue "
                 "or stop_measurement() to end.")
        else:
          self._resume_context = None
          msg = f"{log_prefix} interrupted by user. Device has been stopped."
        raise MeasurementInterrupted(
          msg,
          partial_data=None,
        )

  async def _request_measurement_data(self, progressive: bool = False) -> bytes:
    """Retrieve measurement data from the device buffer (internal).

    Sends REQUEST/DATA (0x05 0x02) and returns the raw response payload.
    Used internally by all measurement types (absorbance, fluorescence,
    luminescence). Users should call the typed collection methods instead
    (e.g. ``request_absorbance_results``).

    Two parameter variants exist (observed in Voyager USB captures):
      - **Standard** (``00 00 00 00 00``): used after the measurement has
        finished (``busy`` flag cleared). Returns the final complete dataset.
      - **Progressive** (``ff ff ff ff 00``): used *during* the measurement
        while the device is still busy. The response contains partially-filled
        data with ``values_written < values_expected`` in the header at
        response payload offsets [7:9] and [9:11] (u16 BE).

    Args:
      progressive: If True, use the progressive parameter variant. Default False
        (standard variant).

    Returns:
      Raw response payload bytes. Parse with ``_parse_absorbance_response``
      (or future fluorescence/luminescence parsers).
    """
    params = b"\xff\xff\xff\xff\x00" if progressive else b"\x00\x00\x00\x00\x00"
    return await self.send_command(
      command_family=self.CommandFamily.REQUEST,
      command=self.Command.DATA,
      parameters=params,
      # Progressive polls happen during active measurement where the device may
      # be busy scanning and not respond immediately.  Use retries=1 so each
      # poll iteration takes at most ~1s (one _PACKET_READ_TIMEOUT) instead of
      # ~3s (3 retries), leaving the full timeout budget for the measurement
      # itself.  The polling loop in read_absorbance already handles FrameError.
      retries=1 if progressive else 3,
    )

  async def _retrieve_abs_spectrum_pages(self, expected_total_values: int) -> List[bytes]:
    """Retrieve all pages of spectrum data via repeated standard GET_DATA calls.

    Spectrum measurements return paginated data: each standard GET_DATA call
    returns one page containing u32 data values after a 36-byte header. Pages
    are collected until the total number of u32 values meets or exceeds
    ``expected_total_values``.

    Page capacity varies by scan mode (~134 wl/page for point scan, ~156 for
    spiral), so value-count-based termination is used instead of a fixed page
    count.

    Args:
      expected_total_values: Total u32 values expected across all pages,
        calculated as ``(num_wavelengths + 3) * (num_wells + 2)``.

    Returns:
      List of raw response payload bytes, one per page.
    """
    pages: List[bytes] = []
    collected_values = 0
    page_num = 0
    while collected_values < expected_total_values:
      page_num += 1
      try:
        page = await self._request_measurement_data(progressive=False)
      except FrameError as e:
        logger.warning("spectrum page %d: frame error (%s), stopping", page_num, e)
        break
      if not page or len(page) < 36:
        logger.warning("spectrum page %d: response too short (%d bytes), stopping",
                       page_num, len(page) if page else 0)
        break
      pages.append(page)
      page_values = (len(page) - 36) // 4
      collected_values += page_values
      if logger.isEnabledFor(logging.INFO):
        logger.info("spectrum page %d: %d values (%d/%d total)",
                    page_num, page_values, collected_values, expected_total_values)
    return pages

  def _parse_abs_spectrum_pages(
    self,
    pages: List[bytes],
    plate: Plate,
    wells: List[Well],
    wavelengths: List[int],
    report: Literal["optical_density", "transmittance", "raw"] = "optical_density",
  ) -> List[Dict]:
    """Parse paginated spectrum response into per-wavelength result dicts.

    Spectrum data spans multiple pages, each with a 36-byte header followed
    by u32 data values. This method:

    1. Keeps page 1's header (36 bytes) as the virtual header.
    2. Strips the 36-byte header from each subsequent page and concatenates
       the data sections.
    3. Delegates to ``_parse_absorbance_response`` for group detection,
       extraction, and OD/transmittance/raw computation.

    The concatenated layout is identical to a single discrete response with
    ``num_wl_resp=1`` and ``(num_wl + 3) × (num_wells + 2)`` total u32
    values, which the existing parser handles directly.

    Args:
      pages: List of raw response payloads from ``_retrieve_abs_spectrum_pages``.
      plate: The plate used for the measurement.
      wells: Wells that were measured.
      wavelengths: List of wavelengths in nm (one per spectrum step).
      report: Output format.

    Returns:
      List of result dicts, one per wavelength.
    """
    if not pages:
      raise ValueError("No spectrum pages to parse.")

    # Build virtual payload: full page 1 + data sections from remaining pages
    virtual_payload = pages[0] + b"".join(page[36:] for page in pages[1:])
    return self._parse_absorbance_response(virtual_payload, plate, wells, wavelengths, report=report)

  async def _collect_abs_spectrum(
    self,
    expected_total_values: int,
    plate: Plate,
    wells: List[Well],
    wavelengths: List[int],
    report: Literal["optical_density", "transmittance", "raw"] = "optical_density",
  ) -> List[Dict]:
    """Retrieve and parse absorbance spectrum pages (used by resume context)."""
    pages = await self._retrieve_abs_spectrum_pages(expected_total_values)
    if not pages:
      logger.warning("spectrum: no data pages retrieved")
      return []
    return self._parse_abs_spectrum_pages(pages, plate, wells, wavelengths, report=report)

  async def _collect_fl_discrete(
    self,
    plate: Plate,
    wells: List[Well],
    chromatic_wavelengths: list,
  ) -> List[Dict]:
    """Retrieve and parse fluorescence discrete data via standard GET_DATA (used by resume context)."""
    final = await self._request_measurement_data(progressive=False)
    return self._parse_fluorescence_response(final, plate, wells, chromatic_wavelengths)

  async def _collect_fl_spectrum(
    self,
    num_wells: int,
    plate: Plate,
    wells: List[Well],
    wavelengths: List[int],
    scan: str,
    fixed_wavelength: int,
  ) -> List[Dict]:
    """Retrieve and parse fluorescence spectrum pages (used by resume context)."""
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
      if len(page) >= 2 and not (page[1] & 0x20):
        logger.info("FL spectrum: final page reached at page %d", page_num)
        break
    if not pages:
      logger.warning("FL spectrum: no data pages retrieved")
      return []
    return self._parse_fl_spectrum_pages(pages, plate, wells, wavelengths, scan, fixed_wavelength)

  @staticmethod
  def _measurement_progress(payload: bytes) -> Tuple[int, int]:
    """Extract (values_written, values_expected) from a DATA response header.

    During a measurement, the firmware fills u32 entries (raw 4-byte detector
    counts and calibration integers) into its data buffer one at a time.
    This method reads two counters from the response header:

    - ``values_expected`` (payload bytes [7:9], u16 BE): total number of u32
      entries the device will produce when the measurement is complete.
    - ``values_written`` (payload bytes [9:11], u16 BE): how many u32 entries
      have been written so far.

    The measurement is complete when ``values_written >= values_expected``.

    ``values_expected`` counts *every* u32 in the response -- 4 data groups
    (sample, chrom2, chrom3, reference) × wells each, plus 4 calibration
    pairs × 2 u32s each:

    - **Single wavelength:**
      ``values_expected = wells × 4 + 8``
    - **Multi-wavelength (W > 1):**
      ``values_expected = wells × 4 + 8 + (W − 1) × (wells + 2)``
      (each extra wavelength adds one group of ``wells`` values + 1 cal pair)

    Examples from real USB captures (values_expected / values_written):
      - A05 (1 well, 1 WL):  expected = 1×4 + 8 = 12;   written = 0→12
      - A03 (8 wells, 1 WL): expected = 8×4 + 8 = 40;   written = 0→40
      - A01 (96 wells, 1 WL): expected = 96×4 + 8 = 392; written = 0→392
      - D02 (96 wells, 2 WL): expected = 96×4 + 8 + 1×(96+2) = 490
      - D03 (96 wells, 3 WL): expected = 96×4 + 8 + 2×(96+2) = 588

    Returns:
      (values_written, values_expected) tuple.

    Raises:
      FrameError: If the payload is too short to contain the header fields.
    """
    if len(payload) < 11:
      raise FrameError(f"DATA response too short for progress header: {len(payload)} bytes")
    values_expected = int.from_bytes(payload[7:9], "big")
    values_written = int.from_bytes(payload[9:11], "big")
    return values_written, values_expected

  # --------------------------------------------------------------------------
  # Measurement Control: Pause / Resume / Abandon
  # --------------------------------------------------------------------------

  async def pause_measurement(self) -> None:
    """Pause a running measurement after the current well completes.

    The device finishes scanning the active well, then halts. Partial results
    collected so far can be retrieved with GET_DATA while paused. Use
    :meth:`resume_measurement_and_collect_data` to continue or :meth:`stop_measurement` to
    terminate the run.

    Status flags after pause:
      - ``busy`` stays set (measurement context alive)
      - ``reading_wells`` stays set (key indicator: paused, not ended)
      - ``unread_data`` toggles as partial data is retrieved via GET_DATA

    Wire: ``0x0D ff ff 00 00``
    """
    await self.send_command(
      command_family=self.CommandFamily.PAUSE_RESUME,
      parameters=b"\xff\xff\x00\x00",
    )

  async def resume_measurement_and_collect_data(self) -> List[Dict]:
    """Resume a paused measurement and collect the remaining data.

    Sends the PAUSE_RESUME(0x00 0x00) command, re-enters the appropriate
    polling loop, retrieves the final data, and returns parsed results in the
    same format as the original measurement call.

    Must be called after a ``MeasurementInterrupted`` was raised with
    ``pause_on_interrupt=True``. Raises ``RuntimeError`` if no resume context
    is available (e.g. measurement was stopped, not paused).

    Returns:
      Parsed measurement results -- same format as the original
      ``read_absorbance`` / ``read_fluorescence`` / etc. call.
    """
    if self._resume_context is None:
      raise RuntimeError(
        "No paused measurement to resume. resume_measurement_and_collect_data() "
        "can only be called after a MeasurementInterrupted with pause_on_interrupt=True."
      )

    ctx = self._resume_context

    # Send resume command
    await self.send_command(
      command_family=self.CommandFamily.PAUSE_RESUME,
      parameters=b"\x00\x00\x00\x00",
    )

    # Re-enter the appropriate polling loop
    if ctx["poll_mode"] == "progressive":
      response, progressive_complete = await self._poll_progressive(
        ctx["read_timeout"], log_prefix=ctx["log_prefix"])
      if progressive_complete:
        result = ctx["collect_fn"](response, True)
      else:
        result = await ctx["fallback_collect_fn"]()
    else:  # status_only
      await self._poll_status_only(ctx["read_timeout"], log_prefix=ctx["log_prefix"])
      result = await ctx["collect_fn"]()

    self._resume_context = None
    return result

  async def stop_measurement(self) -> None:
    """Stop a running or paused measurement.

    Terminates the current run and transitions the device to idle over ~5 s.
    Retrieve any partial data with GET_DATA *before* calling this -- no further
    data will be produced after the stop command.

    Can be sent at any point: mid-run, while paused, or after natural
    completion.

    Status flags after stop:
      - ``reading_wells`` clears immediately (measurement context destroyed)
      - ``busy`` and ``initialized`` clear ~5 s later (device fully idle)

    Wire: ``0x0B 00``
    """
    self._resume_context = None
    await self.send_command(
      command_family=self.CommandFamily.STOP,
      parameters=b"\x00",
    )

  async def _send_cmd_0x0e(self) -> None:
    """Send the unknown CMD_0x0E observed in OEM software startup sequences.

    Purpose is not fully understood. Observed in USB captures of OEM software startup:

    - Sent after INITIALIZE + EEPROM read (REQUEST/0x07) during normal boot
    - Also sent when recovering a device stuck in ``running`` state
    - Sometimes skipped by OEM software during normal startup (conditional logic unknown)
    - The last parameter byte equals EEPROM byte[25] (boot counter) + 1

    Hardware-verified ground truth::

      Recovery capture:  0x0E 0x0B 0x12 0x00 0x00 0x04 0x18
      Normal boot (A):   0x0E 0x0B 0x12 0x00 0x00 0x04 0x19
      Normal boot (B):   not sent

    The first parameter byte (0x0B) matches the STOP command family.

    Wire: ``0x0E 0B 12 00 00 04 <counter+1>``
    """
    # EEPROM byte[25] is a boot counter; the command uses counter + 1.
    # For now we hardcode the observed static prefix -- the counter byte may
    # need to be read from request_eeprom_data() once we understand it better.
    await self.send_command(
      command_family=self.CommandFamily.CMD_0x0E,
      parameters=b"\x0b\x12\x00\x00\x04\x19",
    )

  async def _safe_interrupt(self) -> None:
    """Best-effort pause or stop on interrupt -- swallows errors since we're already handling one.

    When ``pause_on_interrupt`` is True, pauses the device (measurement can be
    resumed). Otherwise stops the measurement (default).
    """
    try:
      if self.pause_on_interrupt:
        await self.pause_measurement()
      else:
        await self.stop_measurement()
    except Exception:
      logger.warning("Failed to send %s command during interrupt",
                     "pause" if self.pause_on_interrupt else "stop", exc_info=True)

  # --------------------------------------------------------------------------
  # Shared validation helpers
  # --------------------------------------------------------------------------

  def _validate_well_scan_params(
    self,
    well_scan: str,
    flashes: Optional[int],
    scan_diameter_mm: int,
    matrix_size: Optional[int],
    *,
    allow_matrix: bool = True,
  ) -> str:
    """Validate well scan parameters. Returns (possibly updated) well_scan."""
    if matrix_size is not None:
      well_scan = "matrix"
    valid = tuple(self._FLASH_LIMITS) if allow_matrix else ("point", "orbital", "spiral")
    if well_scan not in valid:
      raise ValueError(f"well_scan must be one of {valid}, got '{well_scan}'.")
    if well_scan == "matrix":
      lo, hi = self._MATRIX_SIZE_RANGE
      if matrix_size is None:
        raise ValueError("matrix_size is required when well_scan='matrix'.")
      if not lo <= matrix_size <= hi:
        raise ValueError(f"matrix_size must be {lo}-{hi}, got {matrix_size}.")
    if flashes is not None:
      lo, hi = self._FLASH_LIMITS[well_scan]
      if not lo <= flashes <= hi:
        raise ValueError(f"flashes must be {lo}-{hi} for {well_scan} mode, got {flashes}.")
    if well_scan not in ("point", "matrix"):
      lo, hi = self._SCAN_DIAMETER_RANGE
      if not lo <= scan_diameter_mm <= hi:
        raise ValueError(
          f"scan_diameter_mm must be {lo}-{hi} for {well_scan} mode, got {scan_diameter_mm}."
        )
    return well_scan

  def _normalize_corner(self, corner: str) -> str:
    """Normalize corner to canonical form (TL/TR/BL/BR).

    Accepts: "TL", "tl", "top_left", "TOP_LEFT" (and similarly for TR, BL, BR).
    """
    canonical = self._CORNER_ALIASES.get(corner)
    if canonical is None:
      raise ValueError(
        f"corner must be one of {list(self._CORNER_ALIASES.keys())}, got '{corner}'."
      )
    return canonical

  @staticmethod
  def _validate_wavelength(value: int, name: str, lo: int, hi: int) -> None:
    if not lo <= value <= hi:
      raise ValueError(f"{name} must be {lo}-{hi} nm, got {value}.")

  def _validate_focal_height(self, value: float) -> None:
    lo, hi = self._FOCAL_HEIGHT_RANGE
    if not lo <= value <= hi:
      raise ValueError(f"focal_height must be {lo}-{hi} mm, got {value}.")

  def _validate_gain(self, value: int) -> None:
    lo, hi = self._PMT_GAIN_RANGE
    if not lo <= value <= hi:
      raise ValueError(f"gain must be {lo}-{hi}, got {value}.")

