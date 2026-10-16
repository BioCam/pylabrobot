"""CLARIOstar driver: the connection, the command layer, and the device's features.

The command layer speaks logical payloads and is the same for both interfaces; only the
framing differs (see ``framing.py``), and it is chosen once, from ``interface``.
"""

import asyncio
import logging
import time
from typing import Any, Callable, Dict, Literal, Optional, Tuple, Union, cast

from pylabrobot.io.ftdi import FTDI
from pylabrobot.io.usb import USB

from .commands import (
  NO_COMMAND_FAMILIES,
  Command,
  CommandFamily,
  parse_quit_codes,
  parse_status,
  parse_temperatures,
  parse_warning_codes,
)
from .errors import CommandRefusedError, FrameError, describe_quit_codes
from .features.drawer import Drawer
from .framing import (
  FTDI_CR,
  FTDI_STX,
  USB_ACK,
  USB_CONTINUATION,
  USB_FIRST,
  USB_HEADER_SIZE,
  USB_HOST_ACK,
  USB_PACKET_SIZE,
  USB_SINGLE,
  ftdi_extract_payload,
  ftdi_validate_frame,
  ftdi_wrap_payload,
  usb_packet_type,
  usb_total_length,
  usb_wrap_payload,
)

logger = logging.getLogger(__name__)

Interface = Literal["ftdi", "usb"]

# Firmware versions checked on hardware, mapped to their build year.
CONFIRMED_FIRMWARE_VERSIONS: Dict[str, int] = {"1.35": 2020}


def _configure_usb_device(dev: Any) -> None:
  """Free interface 0 from the kernel driver (Linux), then select the first configuration."""
  try:
    if dev.is_kernel_driver_active(0):
      dev.detach_kernel_driver(0)
  except NotImplementedError:  # libusb on Windows and macOS has no kernel-driver query
    pass
  dev.set_configuration()


class CLARIOstarDriver:
  """Owns the CLARIOstar connection, the command layer, and the device's features.

  Features are reached as attributes, e.g. ``driver.drawer``.
  """

  _FTDI_READ_CHUNK = 25  # bytes per read; a shorter read marks the end of a burst
  _PACKET_READ_TIMEOUT = 1.0  # seconds to wait for the start of an FTDI reply
  _MAX_FRAME_SIZE = 60_000  # a larger size field is corruption
  # Seconds without new bytes before abandoning a started frame. The longest pause measured
  # inside a reply, over about 26,000 replies including measurement data, was 0.44 s.
  _FRAME_STALL_TIMEOUT = 2.0
  _FRAME_HARD_CAP = 60.0  # seconds; ceiling on reading one FTDI frame
  _USB_PACKET_TIMEOUT = 5  # seconds to wait for one USB packet
  _RETRY_SETTLE = 0.08  # seconds between send_command attempts
  _DEFAULT_WAIT_TIMEOUT = 150.0  # seconds a wait=True command may stay busy

  def __init__(
    self,
    interface: Optional[Interface] = None,
    device_id: Optional[str] = None,
    io: Optional[Union[FTDI, USB]] = None,
  ):
    """
    Args:
      interface: ``"ftdi"`` for readers with the FTDI serial bridge (VID 0x0403 / PID 0xBB68),
        ``"usb"`` for readers with native USB (VID 0x0483 / PID 0xA29A). None takes it from
        ``io``, or ``"ftdi"`` when no ``io`` is given.
      device_id: the FTDI device id, or the USB serial number. None uses the first reader
        found.
      io: an already-built ``FTDI`` or ``USB`` (or a validator of either), used instead of
        building one from the arguments above. Its type sets the interface.

    Raises:
      TypeError: if ``io`` is neither an ``FTDI`` nor a ``USB``.
      ValueError: if ``interface`` is not ``"ftdi"`` or ``"usb"``, or disagrees with ``io``.
    """
    if interface is not None and interface not in ("ftdi", "usb"):
      raise ValueError(f"interface must be 'ftdi' or 'usb', got {interface!r}")
    if io is not None:
      if isinstance(io, FTDI):
        io_interface: Interface = "ftdi"
      elif isinstance(io, USB):
        io_interface = "usb"
      else:
        raise TypeError(f"io must be an FTDI or a USB, got {type(io).__name__}")
      if interface is not None and interface != io_interface:
        raise ValueError(f"interface is {interface!r} but io is {type(io).__name__}")
      interface = io_interface
    self.interface: Interface = interface or "ftdi"
    if io is None:
      if self.interface == "ftdi":
        io = FTDI(
          human_readable_device_name="BMG CLARIOstar",
          device_id=device_id,
          vid=0x0403,
          pid=0xBB68,
        )
      else:
        io = USB(
          id_vendor=0x0483,
          id_product=0xA29A,
          human_readable_device_name="BMG CLARIOstar",
          serial_number=device_id,
          read_endpoint_address=0x81,
          write_endpoint_address=0x01,
          configuration_callback=_configure_usb_device,
        )
    self.io = io
    self._lock = asyncio.Lock()
    self._last_warning: Optional[Tuple[int, int, int, int, int]] = None
    self.drawer = Drawer(self)

  # -- FTDI interface --------------------------------------------------------

  @property
  def _ftdi(self) -> FTDI:
    """The io, as an FTDI."""
    return cast(FTDI, self.io)

  async def _ftdi_setup(self) -> None:
    """Open the FTDI port at 125000 baud, 8N1, latency 2 ms."""
    await self._ftdi.setup()
    await self._ftdi.set_baudrate(125000)
    await self._ftdi.set_line_property(8, 0, 0)  # 8N1
    await self._ftdi.set_latency_timer(2)

  async def _ftdi_write(self, frame: bytes) -> None:
    """Write a whole frame; raise OSError on a short write."""
    written = await self._ftdi.write(frame)
    if written != len(frame):
      raise OSError(f"Short write: sent {written} of {len(frame)} bytes")

  async def _ftdi_read_frame(self) -> bytes:
    """Read one FTDI reply frame.

    CR (0x0D) also occurs inside payloads, so once the header is in, the size field decides
    when the frame is complete. Bytes before an STX are dropped to resync. Before the header,
    ``_PACKET_READ_TIMEOUT`` bounds the wait; after it, only a silence of
    ``_FRAME_STALL_TIMEOUT`` or the ``_FRAME_HARD_CAP`` ends the read, as long replies
    stream in bursts.

    Returns:
      The frame, possibly short of its size field on a stall; the caller validates it.
    """
    data = b""
    expected_size: Optional[int] = None
    end_byte_found = False
    start = time.time()
    last_data_time = start

    while True:
      chunk = await self._ftdi.read(self._FTDI_READ_CHUNK)
      if chunk:
        data += chunk
        last_data_time = time.time()

        if expected_size is None and data[0] != FTDI_STX:
          index = data.find(FTDI_STX)
          data = data[index:] if index != -1 else b""

        end_byte_found = bool(data) and data[-1] == FTDI_CR

        if expected_size is None and len(data) >= 3:
          expected_size = int.from_bytes(data[1:3], "big")
          if expected_size > self._MAX_FRAME_SIZE:
            break
          start = time.time()

        if len(chunk) < self._FTDI_READ_CHUNK and end_byte_found:
          if expected_size is None or len(data) >= expected_size:
            break
        if expected_size is not None and len(data) >= expected_size:
          break

        # The size is known, so ask for exactly the rest of the frame.
        if expected_size is not None:
          remainder = await self._ftdi.read(expected_size - len(data))
          if remainder:
            data += remainder
            end_byte_found = data[-1] == FTDI_CR
            if len(data) >= expected_size:
              break
      else:
        if end_byte_found and (expected_size is None or len(data) >= expected_size):
          break
        now = time.time()
        if expected_size is None:
          timed_out = now - start > self._PACKET_READ_TIMEOUT
        else:
          timed_out = (
            now - last_data_time > self._FRAME_STALL_TIMEOUT or now - start > self._FRAME_HARD_CAP
          )
        if timed_out:
          if expected_size is not None and 0 < len(data) < expected_size:
            data += await self._ftdi.read(expected_size - len(data))
          break
        await asyncio.sleep(0.0001)

    if expected_size is not None and len(data) >= expected_size:
      return data[:expected_size]
    return data

  async def _ftdi_exchange(self, payload: bytes) -> bytes:
    """Send one payload over FTDI and return the validated reply payload."""
    await self._ftdi_write(ftdi_wrap_payload(payload))
    frame = await self._ftdi_read_frame()
    ftdi_validate_frame(frame)
    return ftdi_extract_payload(frame)

  # -- USB interface ---------------------------------------------------------

  @property
  def _usb(self) -> USB:
    """The io, as a USB."""
    return cast(USB, self.io)

  async def _usb_setup(self) -> None:
    """Open the device, then send the two vendor requests it needs before bulk traffic."""
    await self._usb.setup()
    # USB.ctrl_transfer types its data as int (a read length); pyusb also takes bytes to send.
    self._usb.ctrl_transfer(0x22, 0x8B, 0, 0, b"\x01")  # type: ignore[arg-type]  # bulk protocol on
    now = int(time.time()).to_bytes(4, "big")
    self._usb.ctrl_transfer(0x22, 0x88, 0, 0, b"\x00\x00\x00\x00" + now)  # type: ignore[arg-type]

  async def _usb_read_packet(self) -> bytes:
    """Read one USB packet; raise FrameError if none arrives in time."""
    try:
      return await self._usb.read(timeout=self._USB_PACKET_TIMEOUT, size=USB_PACKET_SIZE)
    except TimeoutError as e:
      raise FrameError(f"No USB packet within {self._USB_PACKET_TIMEOUT} s") from e

  async def _usb_exchange(self, payload: bytes) -> bytes:
    """Send one payload and return the reply payload, reassembled from its packets.

    A message longer than one packet waits for the device's acknowledgement before its
    continuation packets; a long reply is acknowledged by the host before its continuations.
    """
    packets = usb_wrap_payload(payload)
    await self._usb.write(packets[0])
    if len(packets) > 1:
      ack = await self._usb_read_packet()
      if usb_packet_type(ack) != USB_ACK:
        raise FrameError(f"Expected a USB acknowledgement, got {ack.hex()}")
      for packet in packets[1:]:
        await self._usb.write(packet)

    first = await self._usb_read_packet()
    packet_type = usb_packet_type(first)
    if packet_type == USB_SINGLE:
      return bytes(first[USB_HEADER_SIZE:])
    if packet_type != USB_FIRST:
      raise FrameError(f"Unexpected USB packet type 0x{packet_type:02x}: {first.hex()}")

    total = usb_total_length(first)
    reply = bytearray(first[USB_HEADER_SIZE:])
    await self._usb.write(USB_HOST_ACK)
    while len(reply) < total:
      packet = await self._usb_read_packet()
      if usb_packet_type(packet) != USB_CONTINUATION:
        raise FrameError(f"Expected a USB continuation packet, got {packet.hex()}")
      reply += packet[USB_HEADER_SIZE:]
    return bytes(reply[:total])

  # -- command layer ---------------------------------------------------------

  async def _purge_rx(self) -> None:
    """Discard unread reply bytes."""
    if self.interface == "ftdi":
      await self._ftdi.usb_purge_rx_buffer()
    else:
      await self._usb.drain()

  async def exchange(self, payload: bytes) -> bytes:
    """Send one logical payload and return the reply payload.

    Raises:
      FrameError: if the reply is missing or malformed.
    """
    async with self._lock:
      if self.interface == "ftdi":
        return await self._ftdi_exchange(payload)
      return await self._usb_exchange(payload)

  async def _exchange_with_retries(self, payload: bytes, retries: int) -> bytes:
    """Exchange a payload, retrying on a missing or malformed reply.

    Raises:
      ValueError: if ``retries`` is below 1.
      FrameError: if every attempt gets a missing or malformed reply.
    """
    if retries < 1:
      raise ValueError(f"retries must be at least 1, got {retries}")
    for attempt in range(1, retries + 1):
      try:
        return await self.exchange(payload)
      except FrameError as e:
        logger.warning(
          "CLARIOstar reply to %s failed (attempt %d/%d): %s",
          payload.hex(),
          attempt,
          retries,
          e,
        )
        if attempt == retries:
          raise
        await self._purge_rx()
        await asyncio.sleep(self._RETRY_SETTLE)
    raise AssertionError("unreachable")

  def _check_reply(self, payload: bytes, reply: bytes) -> None:
    """Raise if the reader refused `payload`; log a device warning once per change of codes.

    Raises:
      CommandRefusedError: if the reply carries the refused bit.
    """
    quit_codes = parse_quit_codes(reply)
    if quit_codes is not None:
      raise CommandRefusedError(payload, quit_codes)
    warning = parse_warning_codes(reply)
    if warning is not None and warning != self._last_warning:
      logger.warning("CLARIOstar device warning: %s", describe_quit_codes(warning))
    self._last_warning = warning

  async def _wait_until_ready(
    self,
    timeout: Optional[float],
    poll_interval: float,
    until: Optional[Callable[[Dict[str, bool]], bool]] = None,
  ) -> None:
    """Poll status until the device is not busy, or until ``until`` holds.

    Args:
      timeout: seconds to wait; None waits indefinitely.
      poll_interval: seconds between status polls.
      until: the condition on the status flags to wait for; None waits for not busy.

    Raises:
      TimeoutError: if the condition does not hold after ``timeout`` seconds.
      CommandRefusedError: if the reader refuses the status query (e.g. before INIT).
    """
    status_payload = bytes([CommandFamily.STATUS])
    start = time.time()
    while True:
      reply = await self._exchange_with_retries(status_payload, retries=5)
      self._check_reply(status_payload, reply)
      status = parse_status(reply)
      if until(status) if until is not None else not status["busy"]:
        return
      if timeout is not None and time.time() - start >= timeout:
        raise TimeoutError(f"CLARIOstar status still {status} after {timeout} s")
      if poll_interval:
        await asyncio.sleep(poll_interval)

  async def send_command(
    self,
    command_family: CommandFamily,
    command: Optional[int] = None,
    *,
    parameters: bytes = b"",
    wait: bool = False,
    timeout: Optional[float] = None,
    poll_interval: float = 0.0,
    retries: int = 3,
    when_idle: bool = True,
  ) -> bytes:
    """Build a logical payload, exchange it, and return the reply payload.

    Args:
      command_family: the family byte.
      command: the command byte; None for families that take none.
      parameters: bytes appended after the family and command bytes.
      wait: poll status until the device is no longer busy, for commands that move it.
      timeout: seconds ``wait`` may last; None uses ``_DEFAULT_WAIT_TIMEOUT``.
      poll_interval: seconds between status polls while waiting.
      retries: attempts on a missing or malformed reply, purging unread bytes in between.
      when_idle: first poll status until the device is not busy, as a busy device refuses
        most commands. False for commands meant for a busy device. STATUS never waits.

    Raises:
      ValueError: if ``command`` is given for a family without one, or missing otherwise.
      FrameError: if every attempt gets a missing or malformed reply.
      CommandRefusedError: if the reader refused the command.
    """
    if command_family in NO_COMMAND_FAMILIES:
      if command is not None:
        raise ValueError(f"{command_family.name} takes no command byte")
      payload = bytes([command_family]) + parameters
    else:
      if command is None:
        raise ValueError(f"{command_family.name} requires a command byte")
      payload = bytes([command_family, command]) + parameters

    if when_idle and command_family != CommandFamily.STATUS:
      await self._wait_until_ready(timeout=self._DEFAULT_WAIT_TIMEOUT, poll_interval=0.1)
    reply = await self._exchange_with_retries(payload, retries)
    self._check_reply(payload, reply)

    if wait:
      await self._wait_until_ready(
        timeout=self._DEFAULT_WAIT_TIMEOUT if timeout is None else timeout,
        poll_interval=poll_interval,
      )
    return reply

  async def request_status(self, retries: int = 5) -> Dict[str, bool]:
    """Request the status flags (see ``parse_status``)."""
    return parse_status(await self.send_command(CommandFamily.STATUS, retries=retries))

  async def request_temperatures(self) -> Dict[str, Optional[float]]:
    """Request the incubator temperatures (see ``parse_temperatures``)."""
    return parse_temperatures(await self.send_command(CommandFamily.STATUS, retries=5))

  async def is_ready(self) -> bool:
    """Return True if the device is not busy."""
    return not (await self.request_status())["busy"]

  async def initialize(self) -> None:
    """Run the hardware initialization (homes the axes, about 13 s) and wait until ready.

    INIT is sent once, without waiting for the reader to be idle first: it is always allowed, and
    an uninitialized reader refuses even STATUS (quit code 201). A malformed reply does not mean
    the reader missed the command, and sending it again would restart a homing already under
    way, so the reply is discarded and status decides when the reader is ready.
    """
    try:
      await self.send_command(
        CommandFamily.INITIALIZE,
        Command.INIT,
        parameters=b"\x00\x10\x03",
        retries=1,
        when_idle=False,
      )
    except FrameError as e:
      logger.warning("CLARIOstar INIT reply malformed (%s); waiting on status instead", e)
      await self._purge_rx()
    await self._wait_until_ready(timeout=self._DEFAULT_WAIT_TIMEOUT, poll_interval=0.1)

  async def request_firmware_info(self) -> Dict[str, str]:
    """Request the firmware version and build timestamp.

    Returns:
      ``firmware_version`` (e.g. ``"1.35"``) and ``firmware_build_timestamp``; both empty
      when the reply is too short to hold them.
    """
    payload = await self.send_command(
      CommandFamily.REQUEST, Command.FIRMWARE_INFO, parameters=b"\x00\x00\x00\x00\x00"
    )
    if len(payload) < 28:
      return {"firmware_version": "", "firmware_build_timestamp": ""}
    version = f"{int.from_bytes(payload[6:8], 'big') / 1000:.2f}"
    build_date = payload[8:20].split(b"\x00", 1)[0].decode("ascii", errors="replace")
    build_time = payload[20:28].split(b"\x00", 1)[0].decode("ascii", errors="replace")
    return {
      "firmware_version": version,
      "firmware_build_timestamp": f"{build_date} {build_time}".strip(),
    }

  async def check_firmware_compatibility(self) -> str:
    """Log a warning if the firmware version has not been checked on hardware.

    Returns:
      The firmware version, empty if the device did not report one.
    """
    version = (await self.request_firmware_info())["firmware_version"]
    if version and version not in CONFIRMED_FIRMWARE_VERSIONS:
      logger.warning(
        "CLARIOstar firmware %s has not been tested with this driver (tested: %s). "
        "Please report how it works.",
        version,
        ", ".join(sorted(CONFIRMED_FIRMWARE_VERSIONS)),
      )
    return version

  # -- lifecycle -------------------------------------------------------------

  async def setup(self) -> None:
    """Connect, initialize the device (about 13 s), and check the firmware version."""
    if self.interface == "ftdi":
      await self._ftdi_setup()
    else:
      logger.warning(
        "The CLARIOstar USB interface has not been tested on hardware with this driver. "
        "Please report how it works."
      )
      await self._usb_setup()
    await self._purge_rx()

    await self.initialize()

    version = await self.check_firmware_compatibility()
    logger.info("CLARIOstar connected over %s, firmware %s", self.interface, version or "unknown")

  async def stop(self) -> None:
    """Close the connection."""
    await self.io.stop()
