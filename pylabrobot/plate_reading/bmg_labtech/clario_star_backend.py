import asyncio
import enum
import logging
import math
import struct
import sys
import time
from typing import Dict, List, Optional, Set, Tuple, Union

from pylabrobot import utils
from pylabrobot.io.ftdi import FTDI
from pylabrobot.resources.plate import Plate
from pylabrobot.resources.well import Well

from ..backend import PlateReaderBackend

if sys.version_info >= (3, 8):
  from typing import Literal
else:
  from typing_extensions import Literal

logger = logging.getLogger("pylabrobot")


class StatusFlag(enum.Enum):
  """Named status flags parsed from the CLARIOstar 5-byte status field."""

  STANDBY = "STANDBY"
  VALID = "VALID"
  BUSY = "BUSY"
  RUNNING = "RUNNING"
  UNREAD_DATA = "UNREAD_DATA"
  INITIALIZED = "INITIALIZED"
  LID_OPEN = "LID_OPEN"
  OPEN = "OPEN"
  PLATE_DETECTED = "PLATE_DETECTED"
  Z_PROBED = "Z_PROBED"
  ACTIVE = "ACTIVE"
  FILTER_COVER_OPEN = "FILTER_COVER_OPEN"


# (byte_index_in_status, bitmask) — status field is bytes 0-4 of the unframed payload
_STATUS_DEFS: List[Tuple[StatusFlag, int, int]] = [
  (StatusFlag.STANDBY, 0, 1 << 1),
  (StatusFlag.VALID, 1, 1 << 0),
  (StatusFlag.BUSY, 1, 1 << 5),
  (StatusFlag.RUNNING, 1, 1 << 4),
  (StatusFlag.UNREAD_DATA, 2, 1),
  (StatusFlag.INITIALIZED, 3, 1 << 5),
  (StatusFlag.LID_OPEN, 3, 1 << 6),
  (StatusFlag.OPEN, 3, 1),
  (StatusFlag.PLATE_DETECTED, 3, 1 << 1),
  (StatusFlag.Z_PROBED, 3, 1 << 2),
  (StatusFlag.ACTIVE, 3, 1 << 3),
  (StatusFlag.FILTER_COVER_OPEN, 4, 1 << 6),
]


def _parse_status(status_bytes: bytes) -> Set[StatusFlag]:
  """Parse 5 status bytes into a set of raised flags.

  Args:
    status_bytes: The 5-byte status field from the unframed response payload.
  """
  flags: Set[StatusFlag] = set()
  for flag, byte_idx, mask in _STATUS_DEFS:
    if byte_idx < len(status_bytes) and status_bytes[byte_idx] & mask:
      flags.add(flag)
  return flags


class FrameError(Exception):
  """Raised when a response frame is malformed."""


class ChecksumError(FrameError):
  """Raised when a response frame checksum is invalid."""


def _frame(payload: bytes) -> bytes:
  """Frame a payload according to the BMG serial protocol.

  Format: STX(0x02) | size(uint16 BE) | NP(0x0c) | payload | checksum(uint16 BE) | CR(0x0d)

  The size field is len(payload) + 7 (accounts for STX + size + NP + checksum + CR).
  """
  size = len(payload) + 7
  buf = bytearray([0x02]) + size.to_bytes(2, "big") + b"\x0c" + payload
  checksum = sum(buf) & 0xFFFF
  buf += checksum.to_bytes(2, "big")
  buf += b"\x0d"
  return bytes(buf)


def _unframe(data: bytes) -> bytes:
  """Validate and strip framing from a response, returning the payload.

  Raises FrameError/ChecksumError on malformed responses.
  """
  if len(data) < 7:
    raise FrameError(f"Response too short ({len(data)} bytes)")
  if data[0] != 0x02:
    raise FrameError(f"Expected STX (0x02), got 0x{data[0]:02x}")
  if data[-1] != 0x0D:
    raise FrameError(f"Expected CR (0x0d), got 0x{data[-1]:02x}")

  # Validate checksum: sum of all bytes except the last 3 (checksum + CR)
  expected_cs = sum(data[:-3]) & 0xFFFF
  actual_cs = int.from_bytes(data[-3:-1], "big")
  if expected_cs != actual_cs:
    raise ChecksumError(f"Checksum mismatch: expected 0x{expected_cs:04x}, got 0x{actual_cs:04x}")

  # Return payload (strip STX + size + NP header and checksum + CR trailer)
  return data[4:-3]


class CLARIOstarBackend(PlateReaderBackend):
  """A plate reader backend for the CLARIOstar.

  Implements luminescence and absorbance reads with structured protocol framing,
  status flag parsing, and partial well selection.
  """

  def __init__(self, device_id: Optional[str] = None):
    self.io = FTDI(device_id=device_id, vid=0x0403, pid=0xBB68)

  async def setup(self):
    await self.io.setup()
    await self.io.set_baudrate(125000)
    await self.io.set_line_property(8, 0, 0)  # 8N1
    await self.io.set_latency_timer(2)

    await self.initialize()
    await self.request_eeprom_data()

  async def stop(self):
    await self.io.stop()

  async def get_stat(self):
    stat = await self.io.poll_modem_status()
    return hex(stat)

  async def read_resp(self, timeout=20) -> bytes:
    """Read a response from the plate reader. If the timeout is reached, return the data that has
    been read so far."""

    d = b""
    last_read = b""
    end_byte_found = False
    t = time.time()

    # Commands are terminated with 0x0d, but this value may also occur as a part of the response.
    # Therefore, we read until we read a 0x0d, but if that's the last byte we read in a full packet,
    # we keep reading for at least one more cycle. We only check the timeout if the last read was
    # unsuccessful (i.e. keep reading if we are still getting data).
    while True:
      last_read = await self.io.read(25)  # 25 is max length observed in pcap
      if len(last_read) > 0:
        d += last_read
        end_byte_found = d[-1] == 0x0D
        if (
          len(last_read) < 25 and end_byte_found
        ):  # if we read less than 25 bytes, we're at the end
          break
      else:
        # If we didn't read any data, check if the last read ended in an end byte. If so, done
        if end_byte_found:
          break

        # Check if we've timed out.
        if time.time() - t > timeout:
          logger.warning("timed out reading response")
          break

        # If we read data, we don't wait and immediately try to read more.
        await asyncio.sleep(0.0001)

    logger.debug("read %s", d.hex())

    return d

  async def send(self, payload: Union[bytearray, bytes], read_timeout=20) -> bytes:
    """Frame a payload and send it to the plate reader, returning the raw response."""

    cmd = _frame(payload)

    logger.debug("sending %s", cmd.hex())

    w = await self.io.write(cmd)

    logger.debug("wrote %s bytes", w)

    assert w == len(cmd)

    resp = await self.read_resp(timeout=read_timeout)
    return resp

  # --- Status ---

  def _parse_status_response(self, response: bytes) -> Set[StatusFlag]:
    """Extract and parse status flags from a framed status response.

    The unframed payload starts with a schema byte, then 5 status bytes at positions 0-4.
    For the status command, the unframed payload is the status data itself.
    """
    try:
      payload = _unframe(response)
    except FrameError:
      logger.warning("Could not unframe status response: %s", response.hex())
      # Fall back to extracting bytes 4-9 from the raw framed response
      if len(response) >= 9:
        return _parse_status(response[4:9])
      return set()
    # The first byte of the payload is a schema/command byte, then status bytes follow
    if len(payload) >= 5:
      return _parse_status(payload[:5])
    return set()

  async def _wait_for_ready_and_return(self, ret, timeout=150):
    """Wait for the plate reader to be ready (BUSY flag cleared) and return the response."""
    last_status_hex = None
    t = time.time()
    while time.time() - t < timeout:
      await asyncio.sleep(0.1)

      command_status = await self.read_command_status()

      status_hex = command_status.hex()
      if status_hex != last_status_hex:
        last_status_hex = status_hex
        flags = self._parse_status_response(command_status)
        logger.info("status changed: %s flags=%s", status_hex, flags)
        if StatusFlag.BUSY not in flags:
          logger.debug("status is ready (BUSY flag cleared)")
          return ret

  async def get_status(self) -> Set[StatusFlag]:
    """Request the current status flags from the plate reader."""
    response = await self.read_command_status()
    return self._parse_status_response(response)

  async def read_command_status(self) -> bytes:
    return await self.send(b"\x80\x00")

  async def initialize(self):
    command_response = await self.send(b"\x01\x00\x00\x10\x02\x00")
    return await self._wait_for_ready_and_return(command_response)

  async def request_eeprom_data(self):
    eeprom_response = await self.send(b"\x05\x07\x00\x00\x00\x00\x00\x00")
    return await self._wait_for_ready_and_return(eeprom_response)

  async def open(self):
    open_response = await self.send(b"\x03\x01\x00\x00\x00\x00\x00")
    return await self._wait_for_ready_and_return(open_response)

  async def close(self, plate: Optional[Plate] = None):
    close_response = await self.send(b"\x03\x00\x00\x00\x00\x00\x00")
    return await self._wait_for_ready_and_return(close_response)

  async def _mp_and_focus_height_value(self):
    mp_and_focus_height_value_response = await self.send(b"\x05\x0f\x00\x00\x00\x00\x00\x00")
    return await self._wait_for_ready_and_return(mp_and_focus_height_value_response)

  def _plate_bytes(self, plate: Plate, wells: Optional[List[Well]] = None) -> bytes:
    """Encode the plate geometry and well selection into the binary format the CLARIOstar expects.

    The 0x04 command prefix is included. Returns a 63-byte sequence:
    command(1) + plate dimensions(12) + col/row counts(2) + 384-bit well mask(48).

    Args:
      plate: The plate resource.
      wells: Optional list of wells to read. If None, all wells are read.
    """

    def float_to_bytes(f: float) -> bytes:
      return round(f * 100).to_bytes(2, byteorder="big")

    plate_length = plate.get_absolute_size_x()
    plate_width = plate.get_absolute_size_y()

    well_0 = plate.get_well(0)
    assert well_0.location is not None, "Well 0 must be assigned to a plate"
    plate_x1 = well_0.location.x + well_0.center().x
    plate_y1 = plate_width - (well_0.location.y + well_0.center().y)
    plate_xn = plate_length - plate_x1
    plate_yn = plate_width - plate_y1

    plate_cols = plate.num_items_x
    plate_rows = plate.num_items_y

    if wells is None or set(wells) == set(plate.get_all_items()):
      # All wells: set first num_items bits
      all_bits = ([1] * plate.num_items) + ([0] * (384 - plate.num_items))
      well_mask_int: int = sum(b << i for i, b in enumerate(all_bits[::-1]))
      wells_bytes = well_mask_int.to_bytes(48, "big")
    else:
      # Selective wells: encode specific well indices into the bitmask
      mask = bytearray(48)
      for well in wells:
        idx = self._well_to_index(plate, well)
        mask[idx // 8] |= 1 << (7 - idx % 8)
      wells_bytes = bytes(mask)

    return (
      b"\x04"
      + float_to_bytes(plate_length)
      + float_to_bytes(plate_width)
      + float_to_bytes(plate_x1)
      + float_to_bytes(plate_y1)
      + float_to_bytes(plate_xn)
      + float_to_bytes(plate_yn)
      + plate_cols.to_bytes(1, byteorder="big")
      + plate_rows.to_bytes(1, byteorder="big")
      + wells_bytes
    )

  @staticmethod
  def _well_to_index(plate: Plate, well: Well) -> int:
    """Convert a well to its row-major index in the plate."""
    for idx, w in enumerate(plate.get_all_items()):
      if w is well:
        return idx
    raise ValueError(f"Well {well.name} not found in plate {plate.name}")

  # --- Run commands ---

  async def _run_luminescence(
    self,
    focal_height: float,
    plate: Plate,
    wells: Optional[List[Well]] = None,
  ):
    """Run a plate reader luminescence run."""

    assert 0 <= focal_height <= 25, "focal height must be between 0 and 25 mm"

    focal_height_data = int(focal_height * 100).to_bytes(2, byteorder="big")
    plate_and_wells = self._plate_bytes(plate, wells)

    payload = (
      plate_and_wells + b"\x02\x01\x00\x00\x00\x00\x00\x00\x00\x20\x04\x00\x1e\x27"
      b"\x0f\x27\x0f\x01" + focal_height_data + b"\x00\x00\x01\x00\x00\x0e\x10\x00\x01\x00\x01\x00"
      b"\x01\x00\x01\x00\x01\x00\x06\x00\x00\x00\x00\x00\x00\x00\x00\x00\x02\x00\x00\x00\x00\x01"
      b"\x00\x00\x00\x01\x00\x64\x00\x20\x00\x00"
    )
    run_response = await self.send(payload)
    return await self._wait_for_ready_and_return(run_response)

  async def _run_absorbance(
    self,
    wavelength: float,
    plate: Plate,
    wells: Optional[List[Well]] = None,
  ):
    """Run a plate reader absorbance run."""
    wavelength_data = int(wavelength * 10).to_bytes(2, byteorder="big")
    plate_and_wells = self._plate_bytes(plate, wells)

    payload = (
      plate_and_wells + b"\x82\x02\x00\x00\x00\x00\x00\x00\x00\x20\x04\x00\x1e\x27\x0f\x27"
      b"\x0f\x19\x01" + wavelength_data + b"\x00\x00\x00\x64\x00\x00\x00\x00\x00\x00\x00\x64\x00"
      b"\x00\x00\x00\x00\x02\x00\x00\x00\x00\x01\x00\x00\x00\x01\x00\x16\x00\x01\x00\x00"
    )
    run_response = await self.send(payload)
    return await self._wait_for_ready_and_return(run_response)

  async def _read_order_values(self):
    return await self.send(b"\x05\x1d\x00\x00\x00\x00\x00\x00")

  async def _status_hw(self):
    status_hw_response = await self.send(b"\x81\x00")
    return await self._wait_for_ready_and_return(status_hw_response)

  async def _get_measurement_values(self):
    return await self.send(b"\x05\x02\x00\x00\x00\x00\x00\x00")

  async def read_luminescence(
    self, plate: Plate, wells: List[Well], focal_height: float = 13, **backend_kwargs
  ) -> List[Dict]:
    """Read luminescence values from the plate reader.

    Supports partial well selection. Unread wells are filled with None.
    """
    all_wells = wells == plate.get_all_items() or set(wells) == set(plate.get_all_items())

    await self._mp_and_focus_height_value()

    await self._run_luminescence(
      focal_height=focal_height,
      plate=plate,
      wells=None if all_wells else wells,
    )

    await self._read_order_values()

    await self._status_hw()

    vals = await self._get_measurement_values()

    # All values are 32 bit integers. The header is variable length, so we need to find the
    # start of the data. In the future, when we understand the protocol better, this can be
    # replaced with a more robust solution.
    num_read = len(wells)
    start_idx = vals.index(b"\x00\x00\x00\x00\x00\x00") + len(b"\x00\x00\x00\x00\x00\x00")
    data = list(vals)[start_idx : start_idx + num_read * 4]

    # group bytes by 4
    int_bytes = [data[i : i + 4] for i in range(0, len(data), 4)]

    # convert to int
    ints = [struct.unpack(">i", bytes(int_data))[0] for int_data in int_bytes]

    readings = [float(i) for i in ints]

    # Map readings back to plate grid
    if all_wells:
      floats: List[List[Optional[float]]] = utils.reshape_2d(
        readings, (plate.num_items_y, plate.num_items_x)
      )
    else:
      grid: List[Optional[float]] = [None] * plate.num_items
      all_items = plate.get_all_items()
      for reading, well in zip(readings, wells):
        idx = all_items.index(well)
        grid[idx] = reading
      floats = utils.reshape_2d(grid, (plate.num_items_y, plate.num_items_x))

    return [
      {
        "data": floats,
        "temperature": float("nan"),  # Temperature not available
        "time": time.time(),
      }
    ]

  async def read_absorbance(
    self,
    plate: Plate,
    wells: List[Well],
    wavelength: int,
    report: Literal["OD", "transmittance"] = "OD",
    **backend_kwargs,
  ) -> List[Dict]:
    """Read absorbance values from the device.

    Args:
      wavelength: wavelength to read absorbance at, in nanometers.
      report: whether to report absorbance as optical depth (OD) or transmittance. Transmittance is
        used interchangeably with "transmission" in the CLARIOStar software and documentation.

    Returns:
      A list containing a single dictionary, where the key is (wavelength, 0) and the value is
      another dictionary containing the data, temperature, and time.
    """
    all_wells = wells == plate.get_all_items() or set(wells) == set(plate.get_all_items())

    await self._mp_and_focus_height_value()

    await self._run_absorbance(
      wavelength=wavelength,
      plate=plate,
      wells=None if all_wells else wells,
    )

    await self._read_order_values()

    await self._status_hw()

    vals = await self._get_measurement_values()
    num_wells = len(wells)
    div = b"\x00" * 6
    start_idx = vals.index(div) + len(div)
    chromatic_data = vals[start_idx : start_idx + num_wells * 4]
    ref_data = vals[start_idx + num_wells * 4 : start_idx + (num_wells * 2) * 4]
    chromatic_bytes = [bytes(chromatic_data[i : i + 4]) for i in range(0, len(chromatic_data), 4)]
    ref_bytes = [bytes(ref_data[i : i + 4]) for i in range(0, len(ref_data), 4)]
    chromatic_reading = [struct.unpack(">i", x)[0] for x in chromatic_bytes]
    reference_reading = [struct.unpack(">i", x)[0] for x in ref_bytes]

    # c100 is the value of the chromatic at 100% intensity
    # c0 is the value of the chromatic at 0% intensity (black reading)
    # r100 is the value of the reference at 100% intensity
    # r0 is the value of the reference at 0% intensity (black reading)
    after_values_idx = start_idx + (num_wells * 2) * 4
    c100, c0, r100, r0 = struct.unpack(">iiii", vals[after_values_idx : after_values_idx + 4 * 4])

    # a bit much, but numpy should not be a dependency
    real_chromatic_reading = []
    for cr in chromatic_reading:
      real_chromatic_reading.append((cr - c0) / c100)
    real_reference_reading = []
    for rr in reference_reading:
      real_reference_reading.append((rr - r0) / r100)

    transmittance: List[Optional[float]] = []
    for rcr, rrr in zip(real_chromatic_reading, real_reference_reading):
      transmittance.append(rcr / rrr * 100)

    data: List[List[Optional[float]]]
    if report == "OD":
      od: List[Optional[float]] = []
      for t in transmittance:
        od.append(math.log10(100 / t) if t is not None and t > 0 else None)
      if all_wells:
        data = utils.reshape_2d(od, (plate.num_items_y, plate.num_items_x))
      else:
        grid: List[Optional[float]] = [None] * plate.num_items
        all_items = plate.get_all_items()
        for i, well in enumerate(wells):
          idx = all_items.index(well)
          grid[idx] = od[i]
        data = utils.reshape_2d(grid, (plate.num_items_y, plate.num_items_x))
    elif report == "transmittance":
      if all_wells:
        data = utils.reshape_2d(transmittance, (plate.num_items_y, plate.num_items_x))
      else:
        grid2: List[Optional[float]] = [None] * plate.num_items
        all_items2 = plate.get_all_items()
        for i, well in enumerate(wells):
          idx = all_items2.index(well)
          grid2[idx] = transmittance[i]
        data = utils.reshape_2d(grid2, (plate.num_items_y, plate.num_items_x))
    else:
      raise ValueError(f"Invalid report type: {report}")

    return [
      {
        "wavelength": wavelength,
        "data": data,
        "temperature": float("nan"),  # Temperature not available
        "time": time.time(),
      }
    ]

  async def read_fluorescence(
    self,
    plate: Plate,
    wells: List[Well],
    excitation_wavelength: int,
    emission_wavelength: int,
    focal_height: float,
  ) -> List[Dict[Tuple[int, int], Dict]]:
    raise NotImplementedError("Not implemented yet")


# Deprecated alias with warning # TODO: remove mid May 2025 (giving people 1 month to update)
# https://github.com/PyLabRobot/pylabrobot/issues/466


class CLARIOStar:
  def __init__(self, *args, **kwargs):
    raise RuntimeError("`CLARIOStar` is deprecated. Please use `CLARIOStarBackend` instead.")


class CLARIOStarBackend:
  def __init__(self, *args, **kwargs):
    raise RuntimeError(
      "`CLARIOStarBackend` (capital 'S') is deprecated. Please use `CLARIOstarBackend` instead."
    )
