"""Driver tests over a fake io. Replies are frames recorded from a CLARIOstar Plus over FTDI."""

import unittest
from typing import List
from unittest.mock import AsyncMock, MagicMock, patch

from pylabrobot.bmg_labtech.clariostar.driver import driver as driver_module
from pylabrobot.bmg_labtech.clariostar.driver.commands import (
  CommandFamily,
  parse_quit_codes,
  parse_status,
  parse_temperatures,
)
from pylabrobot.bmg_labtech.clariostar.driver.driver import (
  CLARIOstarDriver,
)
from pylabrobot.bmg_labtech.clariostar.driver.errors import CommandRefusedError, FrameError
from pylabrobot.bmg_labtech.clariostar.driver.framing import (
  ftdi_extract_payload,
)
from pylabrobot.bmg_labtech.clariostar.driver.recordings import (
  load_exchanges,
)
from pylabrobot.io.ftdi import FTDI
from pylabrobot.io.usb import USB

V1 = load_exchanges("clariostar_plus_ftdi_2020_v1_driver.json")
REFUSED = load_exchanges("clariostar_plus_ftdi_2020_oem_software_refused.json")
PREVIOUS = load_exchanges("clariostar_plus_ftdi_2020_previous_driver.json")
STATUS_NOT_INITIALIZED = PREVIOUS["refused_status_not_initialized"][1]
STATUS_WARNING = PREVIOUS["status_warning_motor"][1]

STATUS_QUERY_FRAME, STATUS_IDLE = V1["status_idle"]
STATUS_BUSY = V1["status_busy"][1]
STATUS_DRAWER_OPEN = V1["status_drawer_open"][1]
STATUS_PLATE_DETECTED = V1["status_plate_detected"][1]
STATUS_TEMPERATURES = V1["status_temperatures"][1]
STATUS_TRUNCATED = V1["status_truncated"][1]  # bytes lost on the line
FIRMWARE_INFO_FRAME, FIRMWARE_INFO_REPLY = V1["firmware_info"]
INIT_FRAME, INIT_REPLY = V1["initialize"]  # a 476-byte reply with 0x0D inside the payload


class FakeFTDI(FTDI):
  """Records writes and answers each write with the next queued frame, in reads of ``chunk``.

  Subclasses ``FTDI`` so the driver takes it as one, without opening a device.
  """

  # No super().__init__(): FTDI.__init__ checks for the FTDI libraries.
  def __init__(self, chunk: int = 25) -> None:
    self.written: List[bytes] = []
    self.replies: List[bytes] = []
    self.purges = 0
    self._pending = b""
    self._chunk = chunk

  async def setup(self) -> None: ...

  async def set_baudrate(self, baudrate: int) -> None: ...

  async def set_line_property(self, bits: int, stopbits: int, parity: int) -> None: ...

  async def set_latency_timer(self, latency: int) -> None: ...

  async def stop(self) -> None: ...

  async def usb_purge_rx_buffer(self) -> None:
    self.purges += 1
    self._pending = b""

  async def write(self, data: bytes) -> int:
    self.written.append(bytes(data))
    if self.replies:
      self._pending += self.replies.pop(0)
    return len(data)

  async def read(self, num_bytes: int = 1) -> bytes:
    size = min(num_bytes, self._chunk)
    data, self._pending = self._pending[:size], self._pending[size:]
    return data


def make_driver(io: FakeFTDI) -> CLARIOstarDriver:
  driver = CLARIOstarDriver(io=io)
  driver._PACKET_READ_TIMEOUT = 0.01
  driver._FRAME_STALL_TIMEOUT = 0.05
  driver._RETRY_SETTLE = 0
  return driver


class InterfaceTests(unittest.TestCase):
  def test_io_type_sets_interface(self):
    self.assertEqual(CLARIOstarDriver(io=FakeFTDI()).interface, "ftdi")
    self.assertEqual(CLARIOstarDriver(io=MagicMock(spec=USB)).interface, "usb")

  def test_matching_interface_and_io_accepted(self):
    self.assertEqual(CLARIOstarDriver(interface="usb", io=MagicMock(spec=USB)).interface, "usb")

  def test_mismatched_interface_and_io_rejected(self):
    with self.assertRaises(ValueError):
      CLARIOstarDriver(interface="usb", io=FakeFTDI())
    with self.assertRaises(ValueError):
      CLARIOstarDriver(interface="ftdi", io=MagicMock(spec=USB))

  def test_other_io_rejected(self):
    with self.assertRaises(TypeError):
      CLARIOstarDriver(io=MagicMock())  # type: ignore[arg-type]

  def test_unknown_interface_rejected(self):
    with self.assertRaises(ValueError):
      CLARIOstarDriver(interface="serial", io=FakeFTDI())  # type: ignore[arg-type]


class StatusTests(unittest.TestCase):
  def test_flags_from_recorded_replies(self):
    busy = parse_status(ftdi_extract_payload(STATUS_BUSY))
    self.assertTrue(busy["busy"])
    self.assertFalse(busy["drawer_open"])

    idle = parse_status(ftdi_extract_payload(STATUS_IDLE))
    self.assertFalse(idle["busy"])

    plate = parse_status(ftdi_extract_payload(STATUS_PLATE_DETECTED))
    self.assertTrue(plate["plate_detected"])

    drawer_open = parse_status(ftdi_extract_payload(STATUS_DRAWER_OPEN))
    self.assertTrue(drawer_open["drawer_open"])
    self.assertFalse(drawer_open["busy"])


class ExchangeTests(unittest.IsolatedAsyncioTestCase):
  async def test_status_round_trip(self):
    io = FakeFTDI()
    io.replies = [STATUS_IDLE]
    status = await make_driver(io).request_status()
    self.assertEqual(io.written, [STATUS_QUERY_FRAME])
    self.assertFalse(status["busy"])

  async def test_reply_split_into_single_bytes(self):
    io = FakeFTDI(chunk=1)
    io.replies = [STATUS_PLATE_DETECTED]
    status = await make_driver(io).request_status()
    self.assertTrue(status["plate_detected"])

  async def test_leading_garbage_is_dropped(self):
    io = FakeFTDI()
    io.replies = [b"\x0d\x00" + STATUS_IDLE]
    status = await make_driver(io).request_status()
    self.assertFalse(status["busy"])

  async def test_truncated_reply_is_retried_after_purge(self):
    io = FakeFTDI()
    io.replies = [STATUS_TRUNCATED, STATUS_IDLE]
    status = await make_driver(io).request_status()
    self.assertEqual(io.written, [STATUS_QUERY_FRAME, STATUS_QUERY_FRAME])
    self.assertEqual(io.purges, 1)
    self.assertFalse(status["busy"])

  async def test_no_reply_raises_after_retries(self):
    io = FakeFTDI()
    with self.assertRaises(FrameError):
      await make_driver(io).request_status(retries=2)
    self.assertEqual(len(io.written), 2)

  async def test_command_byte_rules(self):
    driver = make_driver(FakeFTDI())
    with self.assertRaises(ValueError):
      await driver.send_command(CommandFamily.STATUS, 0x00)
    with self.assertRaises(ValueError):
      await driver.send_command(CommandFamily.DRAWER)


class FirmwareTests(unittest.IsolatedAsyncioTestCase):
  async def test_firmware_info_from_recorded_reply(self):
    io = FakeFTDI()
    io.replies = [STATUS_IDLE, FIRMWARE_INFO_REPLY]
    info = await make_driver(io).request_firmware_info()
    self.assertEqual(io.written, [STATUS_QUERY_FRAME, FIRMWARE_INFO_FRAME])
    self.assertEqual(
      info, {"firmware_version": "1.35", "firmware_build_timestamp": "Nov 20 2020 11:51:21"}
    )

  async def test_confirmed_firmware_does_not_warn(self):
    io = FakeFTDI()
    io.replies = [STATUS_IDLE, FIRMWARE_INFO_REPLY]
    with patch.object(driver_module.logger, "warning") as warning:
      self.assertEqual(await make_driver(io).check_firmware_compatibility(), "1.35")
    warning.assert_not_called()


class TemperatureTests(unittest.TestCase):
  def test_temperatures_from_recorded_replies(self):
    self.assertEqual(
      parse_temperatures(ftdi_extract_payload(STATUS_TEMPERATURES)), {"bottom": 23.1, "top": 24.0}
    )
    self.assertEqual(
      parse_temperatures(ftdi_extract_payload(STATUS_IDLE)), {"bottom": None, "top": None}
    )


class WhenIdleTests(unittest.IsolatedAsyncioTestCase):
  async def test_command_waits_until_the_device_is_idle(self):
    io = FakeFTDI()
    io.replies = [STATUS_BUSY, STATUS_BUSY, STATUS_IDLE, FIRMWARE_INFO_REPLY]
    driver = make_driver(io)
    await driver.request_firmware_info()
    self.assertEqual(io.written, [STATUS_QUERY_FRAME] * 3 + [FIRMWARE_INFO_FRAME])

  async def test_when_idle_false_sends_at_once(self):
    io = FakeFTDI()
    io.replies = [FIRMWARE_INFO_REPLY]
    payload = ftdi_extract_payload(FIRMWARE_INFO_FRAME)
    await make_driver(io).send_command(
      CommandFamily(payload[0]), payload[1], parameters=payload[2:], when_idle=False
    )
    self.assertEqual(io.written, [FIRMWARE_INFO_FRAME])


class RefusedTests(unittest.IsolatedAsyncioTestCase):
  def test_quit_codes_from_recorded_refusals(self):
    expected = {
      "refused_busy": 202,
      "refused_no_results": 213,
      "refused_no_active_run": 214,
      "refused_cycle_time": 65,
    }
    refused_temperature = parse_quit_codes(ftdi_extract_payload(V1["refused_temperature"][1]))
    assert refused_temperature is not None
    self.assertEqual(refused_temperature[0], 110)
    for name, code in expected.items():
      quit_codes = parse_quit_codes(ftdi_extract_payload(REFUSED[name][1]))
      assert quit_codes is not None, name
      self.assertEqual(quit_codes[0], code, name)

  def test_accepted_replies_have_no_quit_codes(self):
    for reply in (STATUS_IDLE, STATUS_BUSY, STATUS_DRAWER_OPEN, FIRMWARE_INFO_REPLY, INIT_REPLY):
      self.assertIsNone(parse_quit_codes(ftdi_extract_payload(reply)))

  async def test_refused_command_raises_with_quit_codes(self):
    sent, received = REFUSED["refused_no_results"]
    payload = ftdi_extract_payload(sent)
    io = FakeFTDI()
    io.replies = [STATUS_IDLE, received]
    with self.assertRaises(CommandRefusedError) as ctx:
      await make_driver(io).send_command(
        CommandFamily(payload[0]), payload[1], parameters=payload[2:]
      )
    self.assertEqual(io.written, [STATUS_QUERY_FRAME, sent])
    self.assertEqual(ctx.exception.quit_codes, (213, 0, 0, 0, 0))
    self.assertIn("quit code 213", str(ctx.exception))


class StatusRefusalAndWarningTests(unittest.IsolatedAsyncioTestCase):
  async def test_refused_status_raises(self):
    io = FakeFTDI()
    io.replies = [STATUS_NOT_INITIALIZED]
    with self.assertRaises(CommandRefusedError) as ctx:
      await make_driver(io).request_status()
    self.assertEqual(ctx.exception.quit_codes[0], 201)
    self.assertIn("not initialized", str(ctx.exception))

  async def test_refused_status_while_polling_raises(self):
    io = FakeFTDI()
    io.replies = [STATUS_NOT_INITIALIZED]
    with self.assertRaises(CommandRefusedError):
      await make_driver(io).request_firmware_info()

  async def test_uninitialized_reader_still_takes_init(self):
    io = FakeFTDI()
    io.replies = [INIT_REPLY, STATUS_BUSY, STATUS_IDLE]
    await make_driver(io).initialize()
    self.assertEqual(io.written[0], INIT_FRAME)

  async def test_warning_is_logged_once_and_not_raised(self):
    io = FakeFTDI()
    io.replies = [STATUS_WARNING, STATUS_WARNING, STATUS_IDLE, FIRMWARE_INFO_REPLY]
    driver = make_driver(io)
    with self.assertLogs(driver_module.logger, "WARNING") as logs:
      await driver.request_firmware_info()
    warnings = [r for r in logs.output if "device warning" in r]
    self.assertEqual(len(warnings), 1)
    self.assertIn("quit code 250", warnings[0])

  def test_line_error_codes_are_named(self):
    for code in (1, 2, 3):
      error = CommandRefusedError(b"\x80", (code, 0, 0, 0, 0))
      self.assertIn("the reader received a frame", str(error))


class SetupTests(unittest.IsolatedAsyncioTestCase):
  async def test_setup_always_initializes(self):
    io = FakeFTDI()
    io.replies = [INIT_REPLY, STATUS_BUSY, STATUS_IDLE]
    driver = make_driver(io)
    driver.check_firmware_compatibility = AsyncMock(return_value="1.35")  # type: ignore
    await driver.setup()
    self.assertEqual(io.written, [INIT_FRAME] + [STATUS_QUERY_FRAME] * 2)
    self.assertEqual(io.purges, 1)

  async def test_malformed_init_reply_is_not_resent(self):
    io = FakeFTDI()
    io.replies = [INIT_REPLY[:100], STATUS_BUSY, STATUS_IDLE]
    await make_driver(io).initialize()
    self.assertEqual(io.written, [INIT_FRAME] + [STATUS_QUERY_FRAME] * 2)
    self.assertEqual(io.purges, 1)


class USBTests(unittest.IsolatedAsyncioTestCase):
  def make_usb_driver(self) -> "tuple[CLARIOstarDriver, MagicMock]":
    io = MagicMock(spec=USB)
    io.setup = AsyncMock()
    io.write = AsyncMock()
    io.read = AsyncMock(side_effect=TimeoutError)
    io.drain = AsyncMock()
    driver = CLARIOstarDriver(interface="usb", io=io)
    driver._RETRY_SETTLE = 0
    return driver, io

  async def test_setup_enables_bulk_protocol_and_sets_clock(self):
    driver, io = self.make_usb_driver()
    await driver._usb_setup()
    enable, clock = io.ctrl_transfer.call_args_list
    self.assertEqual(enable.args, (0x22, 0x8B, 0, 0, b"\x01"))
    self.assertEqual(clock.args[:4], (0x22, 0x88, 0, 0))
    self.assertEqual(clock.args[4][:4], b"\x00\x00\x00\x00")
    self.assertEqual(len(clock.args[4]), 8)

  async def test_status_query_packet_and_retry_on_silence(self):
    driver, io = self.make_usb_driver()
    with self.assertRaises(FrameError):
      await driver.request_status(retries=2)
    sent = [call.args[0] for call in io.write.call_args_list]
    self.assertEqual(sent, [bytes.fromhex("000c010000000180")] * 2)
    io.drain.assert_awaited_once()


if __name__ == "__main__":
  unittest.main()
