"""CLARIOstar Plus plate mapping mixin: 2D XY raster scan of corner wells.

Plate mapping performs a 2D raster scan around each corner well (A1 and last
well, e.g. H12) to determine their calibrated XY positions. The device
physically moves the optic across a 31×31 grid (~961 points) at each corner,
measuring intensity at every position. Firmware-side peak detection locates
the well centers from the resulting heatmaps.

This is used by MARS to compensate for plate misalignment. The 0x07
PLATE_MAP_SCAN command triggers the entire operation — no separate
MEASUREMENT_RUN (0x04) is needed.

Protocol (6 USB captures: 4 FL + 2 ABS across 96/384-well plates):
  1. (Optional) focus_well() for FL-based mapping
  2. PLATE_MAP_SCAN (0x07): 40-byte parameters, starts raster scan
  3. REQUEST/PLATE_MAP_CONFIG (0x05 0x0D): metadata (grid_size, n_points)
  4. Poll STATUS until ``unread_data`` goes HIGH → REQUEST/DATA for corner 1
  5. Poll STATUS until ``unread_data`` goes HIGH → REQUEST/DATA for corner 2
  6. Poll STATUS until ``busy`` clears
  7. REQUEST/PLATE_MAP_XY (0x05 0x04): calibrated corner well positions

Parameters layout (40 bytes, same frame size for both ABS and FI):
  [0]      = 0x02 (sub-command constant across all captures)
  [1:3]    = plate_length (u16 BE, mm×100)
  [3:5]    = plate_width (u16 BE, mm×100)
  [5:7]    = A1_center_x (u16 BE, mm×100)
  [7:9]    = A1_center_y (u16 BE, mm×100, Y-inverted)
  [9:11]   = last_well_center_x (u16 BE, mm×100)
  [11:13]  = last_well_center_y (u16 BE, mm×100, Y-inverted)
  [13]     = num_cols
  [14]     = num_rows
  [15]     = detection_mode (0x00=FL top, 0x01=FL bottom, 0x02=ABS)

  ABS-specific [16:40]:
    [16:38] = zeros (22 bytes)
    [38:40] = wavelength (u16 BE, nm×10)

  FL-specific [16:40]:
    [16:19] = zeros (3 bytes)
    [19]    = 0x0C constant
    [20:22] = ex_hi (u16 BE, nm×10)
    [22:24] = ex_lo (u16 BE, nm×10)
    [24:26] = dichroic (u16 BE, nm×10)
    [26:28] = em_hi (u16 BE, nm×10)
    [28:30] = em_lo (u16 BE, nm×10)
    [30:32] = slit_a (u16 BE, 0x0004=mono, varies for filter)
    [32:34] = slit_b (u16 BE, 0x0003=mono, varies for filter)
    [34:36] = focal_height (u16 BE, mm×100)
    [36:38] = gain (u16 BE)
    [38:40] = zeros (2 bytes)

DATA response payload (REQUEST/DATA, 3878 bytes per corner):
  Header (31 bytes):
    [6]      = schema (0xa0=FL, 0xa8=ABS)
    [7:9]    = n_points (u16 BE, 961 = 31×31)
    [9:11]   = values_written (u16 BE, 961 when complete)
    [12:15]  = saturation_value (u24 BE, FL=259936, ABS=983025)
    [24]     = well_col (1-indexed: 1=A1, 12=H12/24=P24 col)
    [26]     = well_row (1-indexed: 1=A1, 8=H12/16=P24 row)
  Raster data (961 × 4 bytes):
    Each point: 3-byte BE intensity + 0x00 padding.
    Values range 0 to saturation_value (260000).
    Arranged as 31×31 grid (row-major) around the well center.

XY response payload (REQUEST/PLATE_MAP_XY, 16 bytes):
  [0]      = 0x04 (response type echoing command)
  [1:5]    = status bytes
  [5:8]    = 0x000202 (constant)
  [8:10]   = X1 (u16 BE, mm×100) — first corner well
  [10:12]  = Y1 (u16 BE, mm×100)
  [12:14]  = Xn (u16 BE, mm×100) — last corner well
  [14:16]  = Yn (u16 BE, mm×100)
  All zeros if scan failed (observed in ABS capture).

Config response payload (REQUEST/PLATE_MAP_CONFIG, 13 bytes):
  [0]      = 0x10 (response type)
  [6]      = grid_size (0x1f = 31)
  [7:9]    = n_points (u16 BE, 0x03c1 = 961 = 31×31)
  [9:11]   = field_9_10 (u16 BE, scales with well spacing: 330 for 96-well/9mm, 165 for 384-well/4.5mm)
"""

import asyncio
import logging
import time
from typing import Dict, List, Optional, Tuple, Union

from pylabrobot.resources.plate import Plate

logger = logging.getLogger("pylabrobot")

# Raster data header size (bytes before the intensity values in a DATA response).
_RASTER_HEADER_SIZE = 31


class _PlateMappingMixin:
  """Plate mapping: 2D XY raster scan of corner wells."""

  # --------------------------------------------------------------------------
  # Payload builder
  # --------------------------------------------------------------------------

  def _build_plate_map_payload(
    self,
    plate: Plate,
    *,
    mode: str = "fluorescence",
    optic_position: str = "top",
    wavelength: int = 600,
    excitation_wavelength: int = 488,
    emission_wavelength: int = 535,
    excitation_bandwidth: int = 14,
    emission_bandwidth: int = 30,
    dichroic_split_wavelength: Optional[float] = None,
    focal_height_mm: float = 15.0,
    gain: int = 2239,
  ) -> bytes:
    """Build the 40-byte parameters for PLATE_MAP_SCAN (0x07).

    Args:
      plate: Plate resource for geometry encoding.
      mode: ``"fluorescence"`` or ``"absorbance"``.
      optic_position: ``"top"`` or ``"bottom"`` (FL only). Detection mode:
        0x00=FL top, 0x01=FL bottom, 0x02=ABS.
      wavelength: ABS wavelength in nm (only used when mode="absorbance").
      excitation_wavelength: FL excitation center wavelength in nm.
      emission_wavelength: FL emission center wavelength in nm.
      excitation_bandwidth: FL excitation full bandwidth in nm.
      emission_bandwidth: FL emission full bandwidth in nm.
      dichroic_split_wavelength: LVDM split wavelength in nm, or None for
        auto-calculation from ``(ex_upper + em_lower) / 2``.
      focal_height_mm: FL focal height in mm (default 15.0).
      gain: FL PMT gain (default 2239).

    Returns:
      40-byte parameters (command family 0x07 is prepended by send_command).
    """
    mode = mode.lower()
    if mode not in ("fluorescence", "absorbance"):
      raise ValueError(f"mode must be 'fluorescence' or 'absorbance', got {mode!r}")

    # --- Plate geometry (same encoding as _plate_field but without well mask) ---
    all_wells = plate.get_all_items()
    if not all_wells:
      raise ValueError("Plate has no wells")

    num_cols = plate.num_items_x
    num_rows = plate.num_items_y
    plate_length = plate.get_size_x()
    plate_width = plate.get_size_y()

    well_0 = all_wells[0]
    loc = well_0.location
    assert loc is not None, f"Well {well_0.name} has no location"
    a1_x = loc.x + well_0.center().x
    a1_y = plate_width - (loc.y + well_0.center().y)
    last_well_x = plate_length - a1_x
    last_well_y = plate_width - a1_y

    buf = bytearray(40)

    # [0] sub-command constant
    buf[0] = 0x02

    # [1:13] plate geometry (6× u16 BE, mm×100)
    buf[1:3] = int(round(plate_length * 100)).to_bytes(2, "big")
    buf[3:5] = int(round(plate_width * 100)).to_bytes(2, "big")
    buf[5:7] = int(round(a1_x * 100)).to_bytes(2, "big")
    buf[7:9] = int(round(a1_y * 100)).to_bytes(2, "big")
    buf[9:11] = int(round(last_well_x * 100)).to_bytes(2, "big")
    buf[11:13] = int(round(last_well_y * 100)).to_bytes(2, "big")

    # [13:15] plate dimensions
    buf[13] = num_cols
    buf[14] = num_rows

    if mode == "absorbance":
      buf[15] = 0x02  # DetectionMode.ABSORBANCE
      # [16:38] = zeros (already zero)
      # [38:40] = wavelength (nm×10)
      wl_raw = wavelength * 10
      buf[38:40] = wl_raw.to_bytes(2, "big")

    else:  # fluorescence
      if optic_position.lower() == "bottom":
        buf[15] = 0x01  # DetectionMode.FL_BOTTOM
      else:
        buf[15] = 0x00  # DetectionMode.FL_TOP
      # [16:19] = zeros (already zero)
      buf[19] = 0x0C  # constant (all captures)

      # Wavelength edges (nm×10)
      ex_hi = int((excitation_wavelength + excitation_bandwidth / 2) * 10)
      ex_lo = int((excitation_wavelength - excitation_bandwidth / 2) * 10)
      em_hi = int((emission_wavelength + emission_bandwidth / 2) * 10)
      em_lo = int((emission_wavelength - emission_bandwidth / 2) * 10)

      if dichroic_split_wavelength is not None:
        dich = int(dichroic_split_wavelength * 10)
      else:
        dich = (ex_hi + em_lo) // 2

      buf[20:22] = ex_hi.to_bytes(2, "big")
      buf[22:24] = ex_lo.to_bytes(2, "big")
      buf[24:26] = dich.to_bytes(2, "big")
      buf[26:28] = em_hi.to_bytes(2, "big")
      buf[28:30] = em_lo.to_bytes(2, "big")

      # Slit config (monochromator defaults)
      buf[30:32] = (0x0004).to_bytes(2, "big")
      buf[32:34] = (0x0003).to_bytes(2, "big")

      # Focal height (mm×100) and gain
      buf[34:36] = int(round(focal_height_mm * 100)).to_bytes(2, "big")
      buf[36:38] = gain.to_bytes(2, "big")
      # [38:40] = zeros (already zero)

    return bytes(buf)

  # --------------------------------------------------------------------------
  # Response parsers
  # --------------------------------------------------------------------------

  @staticmethod
  def _parse_plate_map_xy(payload: bytes) -> Dict[str, float]:
    """Parse a PLATE_MAP_XY response (REQUEST 0x05 / 0x04).

    Args:
      payload: Validated response payload (16 bytes).

    Returns:
      Dict with keys ``x1_mm``, ``y1_mm``, ``xn_mm``, ``yn_mm`` (floats,
      mm with 0.01mm resolution). All zeros if the scan failed to locate
      corner wells (observed in ABS capture).
    """
    if len(payload) < 16:
      raise ValueError(f"PLATE_MAP_XY response too short: {len(payload)} bytes (need >=16)")

    x1 = int.from_bytes(payload[8:10], "big") / 100.0
    y1 = int.from_bytes(payload[10:12], "big") / 100.0
    xn = int.from_bytes(payload[12:14], "big") / 100.0
    yn = int.from_bytes(payload[14:16], "big") / 100.0

    return {"x1_mm": x1, "y1_mm": y1, "xn_mm": xn, "yn_mm": yn}

  @staticmethod
  def _parse_plate_map_config(payload: bytes) -> Dict[str, int]:
    """Parse a PLATE_MAP_CONFIG response (REQUEST 0x05 / 0x0D).

    The config response uses response_type 0x10 (13-byte payload).

    Args:
      payload: Validated response payload (13 bytes).

    Returns:
      Dict with keys:
        ``response_type`` - always 0x10
        ``grid_size`` - raster grid dimension (31 in all captures)
        ``n_points`` - total raster points (961 = 31×31 in all captures)
        ``field_9_10`` - u16 BE at offset 9 (scales with well spacing: 330 for 96-well, 165 for 384-well)
    """
    if len(payload) < 13:
      raise ValueError(f"PLATE_MAP_CONFIG response too short: {len(payload)} bytes (need >=13)")

    return {
      "response_type": payload[0],
      "grid_size": payload[6],
      "n_points": int.from_bytes(payload[7:9], "big"),
      "field_9_10": int.from_bytes(payload[9:11], "big"),
    }

  @staticmethod
  def _parse_plate_map_raster(payload: bytes) -> dict:
    """Parse a DATA response containing a 2D raster heatmap for one corner well.

    The DATA response has a 31-byte header followed by 961 × 4-byte intensity
    values (3-byte BE + 0x00 padding), forming a 31×31 grid.

    Args:
      payload: Validated response payload (3878 bytes for 31×31 grid).

    Returns:
      Dict with keys:
        ``well_col`` - 1-indexed column of the scanned corner (1 or num_cols).
        ``well_row`` - 1-indexed row of the scanned corner (1 or num_rows).
        ``n_points`` - number of raster points (961).
        ``values_written`` - number of values written by firmware (961 when done).
        ``saturation`` - saturation/clipping value (260000).
        ``grid_size`` - grid dimension (31, inferred from sqrt(n_points)).
        ``intensities`` - flat list of intensity values (length n_points).
    """
    if len(payload) < _RASTER_HEADER_SIZE + 4:
      raise ValueError(
        f"Raster DATA response too short: {len(payload)} bytes "
        f"(need >= {_RASTER_HEADER_SIZE + 4})")

    n_points = int.from_bytes(payload[7:9], "big")
    values_written = int.from_bytes(payload[9:11], "big")
    saturation = (payload[12] << 16) | (payload[13] << 8) | payload[14]
    well_col = payload[24]
    well_row = payload[26]

    # Extract intensity values: 4 bytes each (3-byte BE + 0x00 padding)
    intensities: List[int] = []
    offset = _RASTER_HEADER_SIZE
    for _ in range(n_points):
      if offset + 4 > len(payload):
        break
      val = (payload[offset] << 16) | (payload[offset + 1] << 8) | payload[offset + 2]
      intensities.append(val)
      offset += 4

    # Infer grid dimension
    grid_size = int(round(n_points ** 0.5))

    return {
      "well_col": well_col,
      "well_row": well_row,
      "n_points": n_points,
      "values_written": values_written,
      "saturation": saturation,
      "grid_size": grid_size,
      "intensities": intensities,
    }

  # --------------------------------------------------------------------------
  # Request helpers
  # --------------------------------------------------------------------------

  async def _request_plate_map_data(self) -> bytes:
    """Retrieve raster data for one corner well (REQUEST/DATA = 0x05 0x02).

    Returns the raw response payload. Same command as measurement data
    retrieval, but the response contains a 31×31 raster heatmap instead of
    per-well OD/FL values.
    """
    return await self.send_command(
      command_family=self.CommandFamily.REQUEST,
      command=self.Command.DATA,
      parameters=b"\x00\x00\x00\x00\x00",
    )

  async def request_plate_map_xy(self) -> Dict[str, float]:
    """Retrieve calibrated XY positions from the last plate mapping scan.

    Sends REQUEST/PLATE_MAP_XY (0x05 0x04) and parses the response.

    Returns:
      Dict with ``x1_mm``, ``y1_mm``, ``xn_mm``, ``yn_mm``. All zeros if
      the scan failed to locate corner wells.
    """
    payload = await self.send_command(
      command_family=self.CommandFamily.REQUEST,
      command=self.Command.PLATE_MAP_XY,
      parameters=b"\x00\x00\x00\x00\x00",
    )
    return self._parse_plate_map_xy(payload)

  async def request_plate_map_config(self) -> Dict[str, int]:
    """Retrieve plate mapping config/metadata from the device.

    Sends REQUEST/PLATE_MAP_CONFIG (0x05 0x0D) and parses the response.

    Returns:
      Dict with ``grid_size``, ``n_points``, ``field_9_10``.
    """
    payload = await self.send_command(
      command_family=self.CommandFamily.REQUEST,
      command=self.Command.PLATE_MAP_CONFIG,
      parameters=b"\x00\x00\x00\x00\x00",
    )
    return self._parse_plate_map_config(payload)

  # --------------------------------------------------------------------------
  # Public API
  # --------------------------------------------------------------------------

  async def scan_plate_mapping(
    self,
    plate: Plate,
    *,
    mode: str = "fluorescence",
    optic_position: str = "top",
    wavelength: int = 600,
    excitation_wavelength: int = 488,
    emission_wavelength: int = 535,
    excitation_bandwidth: int = 14,
    emission_bandwidth: int = 30,
    dichroic_split_wavelength: Optional[float] = None,
    focal_height_mm: float = 15.0,
    gain: int = 2239,
    scan_timeout: float = 300.0,
  ) -> dict:
    """Run a 2D plate mapping scan and return raster heatmaps + calibrated XY.

    The 0x07 PLATE_MAP_SCAN command raster-scans a 31×31 grid around each
    corner well (A1 and last well), measuring intensity at every point. The
    firmware then determines the well centers from the heatmaps. The scan
    takes ~100-150 seconds.

    The scan produces two data blocks (one per corner), retrieved automatically
    when the ``unread_data`` status flag goes HIGH. After both corners are
    scanned, the calibrated XY positions are retrieved.

    Requires liquid in the two corner wells (A1 and last well) for the scan
    to detect them. FL mode additionally requires a prior focus scan.

    Args:
      plate: Plate resource.
      mode: ``"fluorescence"`` or ``"absorbance"``.
      optic_position: ``"top"`` or ``"bottom"`` (FL only).
      wavelength: ABS wavelength in nm (only used when mode="absorbance").
      excitation_wavelength: FL excitation center wavelength in nm.
      emission_wavelength: FL emission center wavelength in nm.
      excitation_bandwidth: FL excitation full bandwidth in nm.
      emission_bandwidth: FL emission full bandwidth in nm.
      dichroic_split_wavelength: LVDM split wavelength in nm, or None for
        auto-calculation.
      focal_height_mm: FL focal height in mm (default 15.0).
      gain: FL PMT gain (default 2239).
      scan_timeout: Maximum seconds to wait for the scan (default 300).

    Returns:
      Dict with keys:
        ``xy`` - calibrated XY positions (dict with ``x1_mm``, ``y1_mm``,
        ``xn_mm``, ``yn_mm``). All zeros if scan failed.
        ``config`` - plate mapping config (dict with ``grid_size``, ``n_points``).
        ``rasters`` - list of 2 raster dicts (one per corner), each with
        ``well_col``, ``well_row``, ``grid_size``, ``intensities`` (flat list
        of grid_size² values), ``saturation``.

    Raises:
      ValueError: If mode or parameters are invalid.
      TimeoutError: If the scan doesn't complete within scan_timeout.
    """
    params = self._build_plate_map_payload(
      plate,
      mode=mode,
      optic_position=optic_position,
      wavelength=wavelength,
      excitation_wavelength=excitation_wavelength,
      emission_wavelength=emission_wavelength,
      excitation_bandwidth=excitation_bandwidth,
      emission_bandwidth=emission_bandwidth,
      dichroic_split_wavelength=dichroic_split_wavelength,
      focal_height_mm=focal_height_mm,
      gain=gain,
    )

    # Send the scan command
    await self.send_command(
      command_family=self.CommandFamily.PLATE_MAP_SCAN,
      parameters=params,
    )

    # Retrieve config immediately (device responds while scanning)
    config = await self.request_plate_map_config()
    logger.info("Plate mapping config: grid_size=%d, n_points=%d",
                config["grid_size"], config["n_points"])

    # Collect raster data for 2 corners (A1 + last well).
    # Each corner's data becomes available when ``unread_data`` goes HIGH
    # while the device is still busy scanning.
    rasters: List[dict] = []
    deadline = time.time() + scan_timeout
    prev_unread = False

    while time.time() < deadline:
      status = await self.request_machine_status()
      unread = status.get("unread_data", False)
      busy = status.get("busy", False)

      # When unread_data transitions to HIGH, retrieve the raster block
      if unread and not prev_unread:
        payload = await self._request_plate_map_data()
        raster = self._parse_plate_map_raster(payload)
        rasters.append(raster)
        logger.info("Plate mapping raster %d: well=(%d,%d), %d points, "
                     "saturation=%d",
                     len(rasters), raster["well_col"], raster["well_row"],
                     len(raster["intensities"]), raster["saturation"])

        if len(rasters) >= 2:
          # Both corners collected; wait for busy to clear
          while time.time() < deadline:
            status = await self.request_machine_status()
            if not status.get("busy", False):
              break
            await asyncio.sleep(self.measurement_poll_interval)
          break

      prev_unread = unread

      if not busy and len(rasters) >= 2:
        break
      if not busy and not unread:
        # Device finished without us catching unread_data transitions.
        # This can happen if polling interval is too slow. Try retrieving
        # whatever data is available.
        logger.warning("Plate mapping: busy cleared with only %d raster(s) "
                       "collected (expected 2). Polling may have been too slow.",
                       len(rasters))
        break

      await asyncio.sleep(self.measurement_poll_interval)
    else:
      raise TimeoutError(
        f"Plate mapping scan did not complete within {scan_timeout}s")

    # Retrieve calibrated XY positions
    xy = await self.request_plate_map_xy()

    return {
      "xy": xy,
      "config": config,
      "rasters": rasters,
    }

  # --------------------------------------------------------------------------
  # Arbitrary position scanning
  # --------------------------------------------------------------------------

  def _build_arbitrary_plate_map_payload(
    self,
    positions: List[Tuple[float, float]],
    *,
    plate_size: Tuple[float, float] = (127.76, 85.48),
    mode: str = "fluorescence",
    optic_position: str = "top",
    wavelength: int = 600,
    excitation_wavelength: int = 488,
    emission_wavelength: int = 535,
    excitation_bandwidth: int = 14,
    emission_bandwidth: int = 30,
    dichroic_split_wavelength: Optional[float] = None,
    focal_height_mm: float = 15.0,
    gain: int = 2239,
  ) -> bytes:
    """Build a PLATE_MAP_SCAN payload targeting arbitrary XY positions.

    Instead of deriving geometry from a Plate resource, this method accepts
    raw XY coordinates (in mm) and encodes them directly into the 0x07
    payload. The device will raster-scan a 31×31 grid around each of the
    two corner positions.

    The CLARIOstar coordinate system has origin at the top-left of the plate
    carrier, with X increasing rightward and Y increasing downward (Y is
    inverted relative to pylabrobot's convention where Y=0 is the bottom).

    Args:
      positions: List of 1 or 2 (x_mm, y_mm) tuples in CLARIOstar device
        coordinates. If 1 position is given, both corners are set to the
        same point (single-point scan). If 2, they define the two diagonal
        corners.
      plate_size: (length_mm, width_mm) of the carrier area. Defaults to
        SBS standard (127.76, 85.48).
      mode: ``"fluorescence"`` or ``"absorbance"``.
      optic_position: ``"top"`` or ``"bottom"`` (FL only).
      wavelength: ABS wavelength in nm (only used when mode="absorbance").
      excitation_wavelength: FL excitation center wavelength in nm.
      emission_wavelength: FL emission center wavelength in nm.
      excitation_bandwidth: FL excitation full bandwidth in nm.
      emission_bandwidth: FL emission full bandwidth in nm.
      dichroic_split_wavelength: LVDM split wavelength in nm, or None for
        auto-calculation.
      focal_height_mm: FL focal height in mm.
      gain: FL PMT gain.

    Returns:
      40-byte parameters for PLATE_MAP_SCAN (0x07).
    """
    mode = mode.lower()
    if mode not in ("fluorescence", "absorbance"):
      raise ValueError(f"mode must be 'fluorescence' or 'absorbance', got {mode!r}")
    if not positions or len(positions) > 2:
      raise ValueError(f"positions must have 1 or 2 entries, got {len(positions)}")

    plate_length, plate_width = plate_size
    x1, y1 = positions[0]
    if len(positions) == 2:
      x2, y2 = positions[1]
    else:
      x2, y2 = x1, y1

    # Encode as 1×1 (single point) or 1×2 (two points) virtual plate.
    # For a single point, cols=1, rows=1, A1 = last well = the target.
    # For two points, cols=2, rows=1, A1 = pos[0], last = pos[1].
    if len(positions) == 1:
      num_cols, num_rows = 1, 1
    else:
      num_cols, num_rows = 2, 1

    buf = bytearray(40)
    buf[0] = 0x02  # sub-command constant

    buf[1:3] = int(round(plate_length * 100)).to_bytes(2, "big")
    buf[3:5] = int(round(plate_width * 100)).to_bytes(2, "big")
    buf[5:7] = int(round(x1 * 100)).to_bytes(2, "big")
    buf[7:9] = int(round(y1 * 100)).to_bytes(2, "big")
    buf[9:11] = int(round(x2 * 100)).to_bytes(2, "big")
    buf[11:13] = int(round(y2 * 100)).to_bytes(2, "big")
    buf[13] = num_cols
    buf[14] = num_rows

    if mode == "absorbance":
      buf[15] = 0x02
      wl_raw = wavelength * 10
      buf[38:40] = wl_raw.to_bytes(2, "big")
    else:
      if optic_position.lower() == "bottom":
        buf[15] = 0x01  # DetectionMode.FL_BOTTOM
      else:
        buf[15] = 0x00  # DetectionMode.FL_TOP
      buf[19] = 0x0C  # constant (all captures)

      ex_hi = int((excitation_wavelength + excitation_bandwidth / 2) * 10)
      ex_lo = int((excitation_wavelength - excitation_bandwidth / 2) * 10)
      em_hi = int((emission_wavelength + emission_bandwidth / 2) * 10)
      em_lo = int((emission_wavelength - emission_bandwidth / 2) * 10)

      if dichroic_split_wavelength is not None:
        dich = int(dichroic_split_wavelength * 10)
      else:
        dich = (ex_hi + em_lo) // 2

      buf[20:22] = ex_hi.to_bytes(2, "big")
      buf[22:24] = ex_lo.to_bytes(2, "big")
      buf[24:26] = dich.to_bytes(2, "big")
      buf[26:28] = em_hi.to_bytes(2, "big")
      buf[28:30] = em_lo.to_bytes(2, "big")

      buf[30:32] = (0x0004).to_bytes(2, "big")
      buf[32:34] = (0x0003).to_bytes(2, "big")

      buf[34:36] = int(round(focal_height_mm * 100)).to_bytes(2, "big")
      buf[36:38] = gain.to_bytes(2, "big")

    return bytes(buf)

  async def raster_scan_positions(
    self,
    positions: List[Tuple[float, float]],
    *,
    plate_size: Tuple[float, float] = (127.76, 85.48),
    mode: str = "fluorescence",
    optic_position: str = "top",
    wavelength: int = 600,
    excitation_wavelength: int = 488,
    emission_wavelength: int = 535,
    excitation_bandwidth: int = 14,
    emission_bandwidth: int = 30,
    dichroic_split_wavelength: Optional[float] = None,
    focal_height_mm: float = 15.0,
    gain: int = 2239,
    scan_timeout: float = 300.0,
  ) -> dict:
    """Raster-scan arbitrary XY positions on the plate carrier.

    Sends a PLATE_MAP_SCAN (0x07) command with custom geometry targeting
    the given positions. The device performs a 31×31 raster intensity scan
    around each position (~100-150s total).

    This bypasses normal plate well layout and allows scanning any point
    in the carrier's XY coordinate space.

    Coordinate system:
      - Origin: top-left corner of the plate carrier
      - X: increases rightward (0 to plate_length mm)
      - Y: increases downward (0 to plate_width mm)
      - For a standard 96-well plate, A1 is near (14.3, 11.2) mm

    Args:
      positions: 1 or 2 (x_mm, y_mm) tuples. If 1, a single-point scan.
        If 2, two diagonal corners are scanned (like standard plate mapping).
      plate_size: (length_mm, width_mm) of the carrier. Default SBS standard.
      mode: ``"fluorescence"`` or ``"absorbance"``.
      wavelength: ABS wavelength in nm (mode="absorbance" only).
      excitation_wavelength: FL excitation center wavelength in nm.
      emission_wavelength: FL emission center wavelength in nm.
      excitation_bandwidth: FL excitation full bandwidth in nm.
      emission_bandwidth: FL emission full bandwidth in nm.
      dichroic_split_wavelength: LVDM split wavelength in nm, or None.
      focal_height_mm: FL focal height in mm.
      gain: FL PMT gain.
      scan_timeout: Maximum seconds to wait for the scan.

    Returns:
      Dict with keys:
        ``xy`` - calibrated XY positions (dict with ``x1_mm``, ``y1_mm``,
        ``xn_mm``, ``yn_mm``). All zeros if scan failed.
        ``config`` - scan config (``grid_size``, ``n_points``).
        ``rasters`` - list of raster dicts (1 or 2), each with
        ``well_col``, ``well_row``, ``grid_size``, ``intensities``,
        ``saturation``.
    """
    n_corners = len(positions)
    if n_corners not in (1, 2):
      raise ValueError(f"positions must have 1 or 2 entries, got {n_corners}")

    params = self._build_arbitrary_plate_map_payload(
      positions,
      plate_size=plate_size,
      mode=mode,
      optic_position=optic_position,
      wavelength=wavelength,
      excitation_wavelength=excitation_wavelength,
      emission_wavelength=emission_wavelength,
      excitation_bandwidth=excitation_bandwidth,
      emission_bandwidth=emission_bandwidth,
      dichroic_split_wavelength=dichroic_split_wavelength,
      focal_height_mm=focal_height_mm,
      gain=gain,
    )

    logger.info("Raster scan: %d position(s) at %s, mode=%s",
                n_corners, positions, mode)

    await self.send_command(
      command_family=self.CommandFamily.PLATE_MAP_SCAN,
      parameters=params,
    )

    config = await self.request_plate_map_config()
    logger.info("Raster scan config: grid_size=%d, n_points=%d",
                config["grid_size"], config["n_points"])

    # Collect raster data. For 1 position → 1 raster expected (but device
    # may still produce 2 if it scans both "corners" at the same point).
    # For 2 positions → 2 rasters.
    rasters: List[dict] = []
    deadline = time.time() + scan_timeout
    prev_unread = False
    expected_rasters = n_corners

    while time.time() < deadline:
      status = await self.request_machine_status()
      unread = status.get("unread_data", False)
      busy = status.get("busy", False)

      if unread and not prev_unread:
        payload = await self._request_plate_map_data()
        raster = self._parse_plate_map_raster(payload)
        rasters.append(raster)
        logger.info("Raster %d: pos=(%d,%d), %d points, saturation=%d",
                     len(rasters), raster["well_col"], raster["well_row"],
                     len(raster["intensities"]), raster["saturation"])

        if len(rasters) >= expected_rasters:
          while time.time() < deadline:
            status = await self.request_machine_status()
            if not status.get("busy", False):
              break
            await asyncio.sleep(self.measurement_poll_interval)
          break

      prev_unread = unread

      if not busy and len(rasters) >= expected_rasters:
        break
      if not busy and not unread:
        logger.warning("Raster scan: busy cleared with only %d raster(s) "
                       "collected (expected %d).",
                       len(rasters), expected_rasters)
        break

      await asyncio.sleep(self.measurement_poll_interval)
    else:
      raise TimeoutError(
        f"Raster scan did not complete within {scan_timeout}s")

    xy = await self.request_plate_map_xy()

    return {
      "xy": xy,
      "config": config,
      "rasters": rasters,
    }
