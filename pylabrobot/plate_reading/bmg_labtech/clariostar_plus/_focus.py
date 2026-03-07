"""CLARIOstar Plus focus mixin: focus_well (Z-scan) and auto-focus (deprecated)."""

import asyncio
import logging
import time
import warnings
from typing import Dict, List, Optional, Union

from pylabrobot.resources.plate import Plate
from pylabrobot.resources.well import Well

from ._protocol import _SEPARATOR, _TRAILER
from ..optical_elements import OpticalFilter, DichroicFilter

logger = logging.getLogger("pylabrobot")


class _FocusMixin:
  """Focus well (Z-scan) and auto-focus (deprecated)."""

  # --------------------------------------------------------------------------
  # Auto-Focus
  # --------------------------------------------------------------------------

  def _build_autofocus_payload(
    self,
    plate: Plate,
    wells: List[Well],
    excitation_wavelength: int,
    emission_wavelength: int,
    *,
    excitation_bandwidth: int = 15,
    emission_bandwidth: int = 20,
    dichroic_split_wavelength: Optional[float] = None,
    max_focal_height_mm: float = 15.0,
    flashes_per_position: int = 10,
    excitation_filter: Optional["CLARIOstarPlusBackend.OpticalFilter"] = None,
    emission_filter: Optional["CLARIOstarPlusBackend.OpticalFilter"] = None,
    dichroic_filter: Optional["CLARIOstarPlusBackend.DichroicFilter"] = None,
  ) -> bytes:
    """Build the 0x0c AUTO_FOCUS_SCAN payload (88 bytes, excluding command byte).

    The auto-focus command uses a simplified layout compared to MEASUREMENT_RUN:
      plate_block(63) + config(1) + max_focal(2) + zero(1) + flashes(1) +
      zeros(5) + multi_marker(1) + ExHi(2) + ExLo(2) + Dich(2) + EmHi(2) +
      EmLo(2) + slit(4) = 88 bytes

    The leading 0x0c command byte is prepended by send_command.
    """
    # --- Derive mode from filter presence ---
    excitation_mode = "filter" if excitation_filter is not None else "monochromator"
    emission_mode = "filter" if emission_filter is not None else "monochromator"
    dichroic_mode = "filter" if dichroic_filter is not None else "lvdm"
    ex_filter_slot = excitation_filter.slot if excitation_filter is not None else 1
    em_filter_slot = emission_filter.slot if emission_filter is not None else 1

    # 1. Plate block (63 bytes) -- same geometry as measurement run
    #    but with plate_extra=0xFF and extended well mask
    plate_bytes = bytearray(self._plate_field(plate, wells))
    plate_bytes[14] = 0xFF  # auto-focus uses 0xFF for plate_extra

    # 2. Config byte (purpose not fully determined; echoed in response)
    config = bytes([0x08])

    # 3. Max focal height (u16 BE, mm×100)
    max_focal_raw = int(round(max_focal_height_mm * 100))
    max_focal = max_focal_raw.to_bytes(2, "big")

    # 4. Zero + flashes per Z position
    flash_byte = bytes([0x00, flashes_per_position])

    # 5. Zeros (5 bytes)
    zeros = b"\x00\x00\x00\x00\x00"

    # 6. Multi marker
    multi_marker = bytes([0x0C])

    # 7. Wavelength edges (same encoding as FL chromatic blocks)
    if excitation_mode == "filter":
      ex_hi = 0x0002
      ex_lo = ex_filter_slot
    else:
      ex_hi = int((excitation_wavelength + excitation_bandwidth / 2) * 10)
      ex_lo = int((excitation_wavelength - excitation_bandwidth / 2) * 10)

    if emission_mode == "filter":
      em_hi = em_filter_slot
      em_lo = 0x0002
    else:
      em_hi = int((emission_wavelength + emission_bandwidth / 2) * 10)
      em_lo = int((emission_wavelength - emission_bandwidth / 2) * 10)

    if dichroic_mode == "filter" or excitation_mode == "filter" or emission_mode == "filter":
      dich_raw = 0x0002
    elif dichroic_split_wavelength is not None:
      dich_raw = int(dichroic_split_wavelength * 10)
    else:
      dich_raw = (ex_hi + em_lo) // 2

    wl_bytes = (
      ex_hi.to_bytes(2, "big")
      + ex_lo.to_bytes(2, "big")
      + dich_raw.to_bytes(2, "big")
      + em_hi.to_bytes(2, "big")
      + em_lo.to_bytes(2, "big")
    )

    # 8. Slit config (4 bytes -- no trailing 0x00 unlike measurement run's 5-byte slit)
    slit = bytearray(4)
    slit[1] = 0x01 if emission_mode == "filter" else 0x04
    slit[3] = 0x01 if excitation_mode == "filter" else 0x03

    payload = (
      bytes(plate_bytes)
      + config
      + max_focal
      + flash_byte
      + zeros
      + multi_marker
      + wl_bytes
      + bytes(slit)
    )
    return payload

  def _parse_focus_result(self, payload: bytes) -> dict:
    """Parse a FOCUS_RESULT response (0x05/0x05).

    Two response formats observed in USB captures:

    **Full response (>=27 bytes, capture F-Q02, F-04, F-05):**
      Header layout (capture-verified):
        [7-8]    calculated gain (u16 BE, 0 if no gain adjustment)
        [15]     winner well column (1-indexed)
        [16]     winner well row (1-indexed)
        [21-22]  peak signal (u16 BE)
        [23-24]  Z-position count (u16 BE, typically 144)
      Z-scan records from offset 27: 8 bytes each
        [0-1] Z height (u16 BE, mm×100)
        [2-3] padding
        [4-5] signal (u16 BE)
        [6-7] padding

    **Short response (17 bytes, observed on real hardware with wrong payload):**
      Summary-only.  Best focal height at payload[10:12] (u16 BE, mm×100).
      No Z-profile data.

    Returns:
      Dict with keys:
        ``best_focal_mm`` - firmware-determined optimal focal height (float).
        ``z_profile`` - list of dicts, each with ``z_mm`` (float), ``signal`` (int),
        ``pass_flag`` (int), in descending Z order.  Empty for short responses.
        ``gain`` - calculated gain (int), 0 if no gain adjustment.
        ``peak_signal`` - highest signal in the profile (int).
    """
    if len(payload) < 12:
      raise ValueError(f"Focus result payload too short: {len(payload)} bytes (need >=12)")

    if len(payload) < 27:
      # Short (17-byte) summary response -- no Z-profile data.
      best_focal_raw = int.from_bytes(payload[10:12], "big")
      best_focal_mm = best_focal_raw / 100.0
      logger.info("Focus result short response (%d bytes): best focal = %.2f mm",
                  len(payload), best_focal_mm)
      return {"best_focal_mm": best_focal_mm, "z_profile": [], "gain": 0, "peak_signal": 0}

    # Full response header (capture-verified: F-Q02, F-04, F-05)
    gain = int.from_bytes(payload[7:9], "big")
    best_focal_raw = int.from_bytes(payload[17:19], "big")
    best_focal_mm = best_focal_raw / 100.0
    peak_signal = int.from_bytes(payload[21:23], "big")

    # Z-scan profile: 8-byte records from offset 27
    z_profile: List[dict] = []
    i = 27
    while i + 8 <= len(payload):
      z_raw = int.from_bytes(payload[i:i + 2], "big")
      pass_flag = int.from_bytes(payload[i + 2:i + 4], "big")
      signal = int.from_bytes(payload[i + 4:i + 6], "big")
      # payload[i+6:i+8] is padding (always 0x0000)
      if z_raw == 0:
        break
      z_profile.append({"z_mm": z_raw / 100.0, "signal": signal, "pass_flag": pass_flag})
      i += 8

    logger.info("Focus result: %d Z-positions, gain=%d, peak_signal=%d, best_focal=%.2fmm",
                len(z_profile), gain, peak_signal, best_focal_mm)

    return {
      "best_focal_mm": best_focal_mm,
      "z_profile": z_profile,
      "gain": gain,
      "peak_signal": peak_signal,
    }

  async def _request_focus_result(self) -> bytes:
    """Retrieve focus scan result from the device (REQUEST/FOCUS_RESULT = 0x05 0x05)."""
    return await self.send_command(
      command_family=self.CommandFamily.REQUEST,
      command=self.Command.FOCUS_RESULT,
      parameters=b"\x00\x00\x00\x00\x00",
    )

  async def auto_focus(
    self,
    plate: Plate,
    wells: List[Well],
    excitation_wavelength: int,
    emission_wavelength: int,
    *,
    excitation_bandwidth: int = 15,
    emission_bandwidth: int = 20,
    dichroic_split_wavelength: Optional[float] = None,
    max_focal_height_mm: float = 15.0,
    flashes_per_position: int = 10,
    excitation_filter: Optional["OpticalFilter"] = None,
    emission_filter: Optional["OpticalFilter"] = None,
    dichroic_filter: Optional["DichroicFilter"] = None,
    scan_timeout: float = 120.0,
  ) -> dict:
    """Run a Z-scan auto-focus and return the optimal focal height.

    .. deprecated::
      This method uses command 0x0C with a **broken payload** (88 bytes instead
      of the correct 91 -- missing gain_target field, wrong well mask offset, and
      4-byte slit instead of 5). It produces only a 17-byte short response with
      no Z-profile data. Use :meth:`focus_well` instead, which sends the correct
      0x09 FOCUS_WELL command and returns the full 144-point Z-profile.

    Args:
      plate: Plate resource.
      wells: Wells to use for the focus scan.
      excitation_wavelength: Center excitation wavelength in nm.
      emission_wavelength: Center emission wavelength in nm.
      excitation_bandwidth: Full excitation bandwidth in nm (default 15).
      emission_bandwidth: Full emission bandwidth in nm (default 20).
      dichroic_split_wavelength: LVDM split wavelength in nm, or None for
        auto-calculation from ``(ex_upper + em_lower) / 2``.
      max_focal_height_mm: Upper Z-scan limit in mm (default 15.0).
      flashes_per_position: Number of FL flashes per Z step (default 10).
      excitation_filter: An ``OpticalFilter`` object. ``None`` = monochromator.
      emission_filter: An ``OpticalFilter`` object. ``None`` = monochromator.
      dichroic_filter: A ``DichroicFilter`` object. ``None`` = LVDM.
      scan_timeout: Maximum seconds to wait for the Z-scan (default 120).

    Returns:
      Dict with keys:
        ``best_focal_mm`` - firmware-determined optimal focal height (float).
        ``z_profile`` - list of dicts, each with ``z_mm`` (float), ``signal`` (int),
        ``pass_flag`` (int), in descending Z order.

    Raises:
      ValueError: If wavelength or parameter ranges are invalid.
      TimeoutError: If the Z-scan doesn't complete within scan_timeout.
    """
    import warnings
    warnings.warn(
      "auto_focus() uses a broken 0x0C payload (88 bytes vs correct 91) and only "
      "returns a 17-byte short response with no Z-profile. Use focus_well() instead.",
      DeprecationWarning,
      stacklevel=2,
    )
    # Filter slot validation (EEPROM-based)
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

    # Input validation
    if not 320 <= excitation_wavelength <= 840:
      raise ValueError(
        f"excitation_wavelength must be 320-840 nm, got {excitation_wavelength}")
    if not 320 <= emission_wavelength <= 840:
      raise ValueError(
        f"emission_wavelength must be 320-840 nm, got {emission_wavelength}")
    if not 0.1 <= max_focal_height_mm <= 25.0:
      raise ValueError(
        f"max_focal_height_mm must be 0.1-25.0, got {max_focal_height_mm}")
    if not 1 <= flashes_per_position <= 200:
      raise ValueError(
        f"flashes_per_position must be 1-200, got {flashes_per_position}")

    # Build and send the auto-focus scan command
    af_payload = self._build_autofocus_payload(
      plate, wells,
      excitation_wavelength, emission_wavelength,
      excitation_bandwidth=excitation_bandwidth,
      emission_bandwidth=emission_bandwidth,
      dichroic_split_wavelength=dichroic_split_wavelength,
      max_focal_height_mm=max_focal_height_mm,
      flashes_per_position=flashes_per_position,
      excitation_filter=excitation_filter,
      emission_filter=emission_filter,
      dichroic_filter=dichroic_filter,
    )
    await self.send_command(
      command_family=self.CommandFamily.AUTO_FOCUS,
      parameters=af_payload,
    )

    # Poll until the Z-scan completes.  The auto-focus scan sets only the
    # ``busy`` flag (not ``running``), matching the OEM software behaviour observed
    # in USB capture F-Q01: OEM software polls STATUS_QUERY until busy clears (~28 s).
    deadline = time.time() + scan_timeout
    while time.time() < deadline:
      status = await self.request_machine_status()
      if not status.get("busy", False):
        break
      await asyncio.sleep(0.3)
    else:
      raise TimeoutError(
        f"Auto-focus Z-scan did not complete within {scan_timeout}s")

    # Retrieve and parse the focus result.
    # The firmware may return a full Z-profile (1177 bytes, seen in USB capture F-Q01)
    # or a 17-byte summary with just the focal height.  _parse_focus_result
    # handles both formats.
    result_payload = await self._request_focus_result()
    return self._parse_focus_result(result_payload)

  # --------------------------------------------------------------------------
  # Focus Well (0x09) -- single-well Z-scan
  # --------------------------------------------------------------------------

  def _build_focus_well_payload(
    self,
    plate: Plate,
    well: Well,
    excitation_wavelength: int,
    emission_wavelength: int,
    *,
    excitation_bandwidth: int = 15,
    emission_bandwidth: int = 20,
    dichroic_split_wavelength: Optional[float] = None,
    max_focal_height_mm: float = 15.0,
    flashes_per_position: int = 10,
    gain_target_pct: int = 0,
    excitation_filter: Optional["CLARIOstarPlusBackend.OpticalFilter"] = None,
    emission_filter: Optional["CLARIOstarPlusBackend.OpticalFilter"] = None,
    dichroic_filter: Optional["CLARIOstarPlusBackend.DichroicFilter"] = None,
  ) -> bytes:
    """Build the 0x09 FOCUS_WELL payload (44 bytes, excluding command byte).

    Capture-verified layout (F-Q02 well A1, F-04 well D6):
      [0-11]  plate_geometry (6× u16 BE, mm×100)
      [12]    num_cols
      [13]    num_rows
      [14]    well_col (1-indexed)
      [15]    well_row (1-indexed)
      [16]    detection_mode (0x04 = fluorescence top)
      [17]    num_rows echo
      [18]    padding (0x00)
      [19]    flashes_per_z_pos
      [20-21] max_focal_height (u16 BE, mm×100)
      [22-23] gain_target (u16 BE, %×100, 0=none)
      [24-26] padding (3×0x00)
      [27]    separator (num_cols)
      [28-29] ExHi (u16 BE, nm×10)
      [30-31] ExLo (u16 BE, nm×10)
      [32-33] Dichroic (u16 BE, nm×10)
      [34-35] EmHi (u16 BE, nm×10)
      [36-37] EmLo (u16 BE, nm×10)
      [38-42] slit_config (5 bytes)
      [43]    tail (0x06=focus-only, 0x07=gain+focus)
    """
    # --- Plate geometry (14 bytes) ---
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

    buf = bytearray(44)
    buf[0:2] = int(round(plate_length * 100)).to_bytes(2, "big")
    buf[2:4] = int(round(plate_width * 100)).to_bytes(2, "big")
    buf[4:6] = int(round(a1_x * 100)).to_bytes(2, "big")
    buf[6:8] = int(round(a1_y * 100)).to_bytes(2, "big")
    buf[8:10] = int(round(last_well_x * 100)).to_bytes(2, "big")
    buf[10:12] = int(round(last_well_y * 100)).to_bytes(2, "big")
    buf[12] = num_cols
    buf[13] = num_rows

    # --- Well coordinates (1-indexed) ---
    well_idx = next(
      (i for i, w in enumerate(all_wells) if id(w) == id(well)),
      None,
    )
    if well_idx is None:
      raise ValueError(f"Well {well.name} not found in plate {plate.name}")
    well_col = well_idx // num_rows + 1  # 1-indexed
    well_row = well_idx % num_rows + 1   # 1-indexed
    buf[14] = well_col
    buf[15] = well_row

    # --- Focus config ---
    buf[16] = 0x04              # detection_mode (fluorescence top)
    buf[17] = num_rows          # num_rows echo
    buf[18] = 0x00              # padding
    buf[19] = flashes_per_position
    buf[20:22] = int(round(max_focal_height_mm * 100)).to_bytes(2, "big")
    buf[22:24] = int(round(gain_target_pct * 100)).to_bytes(2, "big")
    buf[24:27] = b"\x00\x00\x00"

    # --- Chromatic block ---
    buf[27] = num_cols          # separator

    # Wavelength edges (same encoding as FL measurement)
    excitation_mode = "filter" if excitation_filter is not None else "monochromator"
    emission_mode = "filter" if emission_filter is not None else "monochromator"

    if excitation_mode == "filter":
      ex_hi = 0x0002
      ex_lo = excitation_filter.slot  # type: ignore[union-attr]
    else:
      ex_hi = int((excitation_wavelength + excitation_bandwidth / 2) * 10)
      ex_lo = int((excitation_wavelength - excitation_bandwidth / 2) * 10)

    if emission_mode == "filter":
      em_hi = emission_filter.slot  # type: ignore[union-attr]
      em_lo = 0x0002
    else:
      em_hi = int((emission_wavelength + emission_bandwidth / 2) * 10)
      em_lo = int((emission_wavelength - emission_bandwidth / 2) * 10)

    if (excitation_mode == "filter" or emission_mode == "filter"
        or dichroic_filter is not None):
      dich_raw = 0x0002
    elif dichroic_split_wavelength is not None:
      dich_raw = int(dichroic_split_wavelength * 10)
    else:
      dich_raw = (ex_hi + em_lo) // 2

    buf[28:30] = ex_hi.to_bytes(2, "big")
    buf[30:32] = ex_lo.to_bytes(2, "big")
    buf[32:34] = dich_raw.to_bytes(2, "big")
    buf[34:36] = em_hi.to_bytes(2, "big")
    buf[36:38] = em_lo.to_bytes(2, "big")

    # Slit config (5 bytes)
    buf[38] = 0x00
    buf[39] = 0x01 if emission_mode == "filter" else 0x04
    buf[40] = 0x00
    buf[41] = 0x01 if excitation_mode == "filter" else 0x03
    buf[42] = 0x00

    # Tail byte
    buf[43] = 0x07 if gain_target_pct > 0 else 0x06

    return bytes(buf)

  async def focus_well(
    self,
    plate: Plate,
    wells: Union[Well, List[Well]],
    excitation_wavelength: int,
    emission_wavelength: int,
    *,
    excitation_bandwidth: int = 15,
    emission_bandwidth: int = 20,
    dichroic_split_wavelength: Optional[float] = None,
    max_focal_height_mm: float = 15.0,
    flashes_per_position: int = 10,
    gain_target_pct: int = 0,
    excitation_filter: Optional["OpticalFilter"] = None,
    emission_filter: Optional["OpticalFilter"] = None,
    dichroic_filter: Optional["DichroicFilter"] = None,
    scan_timeout: float = 120.0,
  ) -> List[dict]:
    """Z-scan one or more wells and return the full focal-height profile for each.

    Sends command 0x09 (FOCUS_WELL) for each well, which sweeps the Z-axis
    from 0.7 mm to ``max_focal_height_mm`` in 0.1 mm steps, measuring
    fluorescence intensity at each position. Returns the complete 144-point
    Z-profile so the caller can apply their own peak-finding algorithm.

    Optionally adjusts gain (set ``gain_target_pct`` to e.g. 90 for 90%).

    Args:
      plate: Plate resource.
      wells: Single well or list of wells to Z-scan (scanned sequentially).
      excitation_wavelength: Center excitation wavelength in nm.
      emission_wavelength: Center emission wavelength in nm.
      excitation_bandwidth: Full excitation bandwidth in nm (default 15).
      emission_bandwidth: Full emission bandwidth in nm (default 20).
      dichroic_split_wavelength: LVDM split wavelength in nm, or None for
        auto-calculation.
      max_focal_height_mm: Upper Z-scan limit in mm (default 15.0).
      flashes_per_position: Number of FL flashes per Z step (default 10).
      gain_target_pct: Gain adjustment target as percentage (0-100). 0 = no
        gain adjustment (default).
      excitation_filter: An ``OpticalFilter`` object. ``None`` = monochromator.
      emission_filter: An ``OpticalFilter`` object. ``None`` = monochromator.
      dichroic_filter: A ``DichroicFilter`` object. ``None`` = LVDM.
      scan_timeout: Maximum seconds to wait per well (default 120).

    Returns:
      List of dicts (one per well), each with keys:
        ``well`` - well name (str).
        ``z_profile`` - list of dicts with ``z_mm``, ``signal``, ``pass_flag``.
        ``gain`` - calculated gain (int), 0 if no gain adjustment.
        ``peak_signal`` - highest signal in the profile (int).
        ``best_focal_mm`` - firmware-determined optimal focal height (float).
    """
    # Normalize to list
    well_list: List[Well] = [wells] if isinstance(wells, Well) else list(wells)

    # Input validation
    if not well_list:
      raise ValueError("No wells provided")
    if not 320 <= excitation_wavelength <= 840:
      raise ValueError(
        f"excitation_wavelength must be 320-840 nm, got {excitation_wavelength}")
    if not 320 <= emission_wavelength <= 840:
      raise ValueError(
        f"emission_wavelength must be 320-840 nm, got {emission_wavelength}")
    if not 0.1 <= max_focal_height_mm <= 25.0:
      raise ValueError(
        f"max_focal_height_mm must be 0.1-25.0, got {max_focal_height_mm}")
    if not 1 <= flashes_per_position <= 200:
      raise ValueError(
        f"flashes_per_position must be 1-200, got {flashes_per_position}")
    if not 0 <= gain_target_pct <= 100:
      raise ValueError(
        f"gain_target_pct must be 0-100, got {gain_target_pct}")

    results: List[dict] = []
    for well in well_list:
      logger.info("Focus well: scanning %s", well.name)
      payload = self._build_focus_well_payload(
        plate, well,
        excitation_wavelength, emission_wavelength,
        excitation_bandwidth=excitation_bandwidth,
        emission_bandwidth=emission_bandwidth,
        dichroic_split_wavelength=dichroic_split_wavelength,
        max_focal_height_mm=max_focal_height_mm,
        flashes_per_position=flashes_per_position,
        gain_target_pct=gain_target_pct,
        excitation_filter=excitation_filter,
        emission_filter=emission_filter,
        dichroic_filter=dichroic_filter,
      )
      await self.send_command(
        command_family=self.CommandFamily.FOCUS_WELL,
        parameters=payload,
      )

      # Poll until Z-scan completes
      deadline = time.time() + scan_timeout
      while time.time() < deadline:
        status = await self.request_machine_status()
        if not status.get("busy", False):
          break
        await asyncio.sleep(0.3)
      else:
        raise TimeoutError(
          f"Focus well Z-scan on {well.name} did not complete within {scan_timeout}s")

      # Retrieve and parse the focus result (0x05/0x05)
      result_payload = await self._request_focus_result()
      result = self._parse_focus_result(result_payload)
      result["well"] = well.name
      results.append(result)

    return results

