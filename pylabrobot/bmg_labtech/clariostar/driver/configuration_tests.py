"""Configuration tests: the INIT reply recorded from a CLARIOstar Plus, decoded and declared."""

import json
import os
import tempfile
import unittest
from typing import Dict, List, Optional, Tuple
from unittest.mock import patch

from pylabrobot.bmg_labtech.clariostar.driver import configuration as configuration_module
from pylabrobot.bmg_labtech.clariostar.driver import master as master_module
from pylabrobot.bmg_labtech.clariostar.driver.configuration import (
  DeviceConfiguration,
  _parse_monochromator_slides,
  compute_recording_name,
  configuration_to_json,
  read_configuration,
)
from pylabrobot.bmg_labtech.clariostar.driver.errors import CommandRefusedError
from pylabrobot.bmg_labtech.clariostar.driver.framing import FTDI_HEADER
from pylabrobot.bmg_labtech.clariostar.driver.master import CLARIOstarDriver
from pylabrobot.bmg_labtech.clariostar.driver.master_tests import (
  FIRMWARE_INFO_REPLY,
  INIT_REPLY,
  PARAMETERS_FRAME,
  PARAMETERS_REPLY,
  STATUS_IDLE,
  STATUS_QUERY_FRAME,
  FakeFTDI,
  make_driver,
)
from pylabrobot.bmg_labtech.clariostar.driver.parameter_table import (
  PARAMETER_TABLE,
  REPLY_OFFSET,
  REPLY_OFFSET_FIRMWARE_2,
  SERIAL_NUMBER_ADDRESSES,
  SIGNED_PARAMETERS,
)
from pylabrobot.bmg_labtech.protocol.framing import ftdi_extract_payload, ftdi_wrap_payload

INIT_PAYLOAD = ftdi_extract_payload(INIT_REPLY)

# A CLARIOstar Plus on firmware 2.11: INIT, stored parameters and firmware info payloads. Serials
# zeroed: the text in block 02, the last 4 bytes of blocks 20 and 2E, parameter bytes 165-168.
INIT_PAYLOAD_2_11 = bytes.fromhex(
  "13250024000002001f083e000102010100d8000010303030302d303030303030000200090027425f0900010d0d0002"
  "08000e0004850202010f0002000011000300000012000200001f000b01012e0a98041a008d00032000080bf4700100"
  "0000002e00097f0be04001000000002f01e945585f53503a313d6f70656e2c323d46696c74657220312c333d46696c"
  "74657220322c4c565f52616e67653a383530302e2e32303235300d0a45585f4c503a313d6f70656e2c323d46696c74"
  "657220312c333d46696c74657220322c4c565f52616e67653a383530302e2e32303235300d0a4253503a313d6f7065"
  "6e2c323d46696c74657220312c333d46696c74657220322c343d46696c74657220332c4c565f52616e67653a313032"
  "35302e2e32323235300d0a454d5f53503a313d6f70656e2c323d46696c74657220312c333d46696c74657220322c4c"
  "565f52616e67653a383530302e2e32303235300d0a454d5f4c503a313d6f70656e2c323d46696c74657220312c333d"
  "46696c74657220322c4c565f52616e67653a383530302e2e32303235300d0a454d5f534c49543a313d6f70656e2c32"
  "3d536c697420302e382c333d536c697420312e322c343d536c697420322e302c353d536c697420332e302c373d4650"
  "207061722c383d4650207065722c363d4c554d206c656e73650d0a45585f534c49543a313d6f70656e2c323d536c69"
  "7420302e362c333d536c697420312e302c343d536c697420312e362c353d536c697420322e332c383d465020537464"
  "72642c373d46502055562c393d4142532c363d462d436865636b0d0a000f0102030405060731000700000000000000"
  "3d00030107d05400050104560000"
)
PARAMETERS_PAYLOAD_2_11 = bytes.fromhex(
  "07050024000000000004200100000a0101010100000100000000000f00000000000000000003040000010000010200"
  "0000000000000000003200006affc40900008c006f0000000000000000006b00660000000000000065000001dc0500"
  "01000000000000e5012703ba04080760092709ac0d0000000000000000000000000000000000000000000000000100"
  "000001010000000000000101010000000000000017028e06000000003e08e5010c00560c00000000a40058ff7e0336"
  "0660ff6211fe0b62115c1b17028d065dff8e0665042703e114ba04080791009001463228460a0046071e0000000000"
  "000000001d03bb0628002c01900146001e00000000002709ac0d600900000000000000000000000009000000000000"
  "00000000000000000000000000000000000000000000005f4227000000434c4152494f7374617220506c7573000000"
  "0000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000"
  "000000000000000000000000000000000000000000000000000000000000000000000068f60600d0010000f0000000"
  "1f0100000e8a00000a0000000a0000000a0000000a0000000000000000000000000000000000000000000000000000"
  "0000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000"
  "0000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000"
  "0000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000"
  "312d00000000000000000000000000000000000000002d000000000000000000000000000000000000000000000000"
  "00000000000000002d0000000000000000000000000000000000000000312d00000000000000000000000000000000"
  "000000002d00000000000000000000000000000000000000000000000000000000000000002d000000000000000000"
  "0000000000000000000000312d00000000000000000000000000000000000000002d00000000000000000000000000"
  "000000000000000000000000000000000000002d0000000000000000000000000000000000000000312d0000000000"
  "0000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000"
  "002d000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000"
  "0000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000"
  "0000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000"
  "000000000000000000000000000000000000000000000000000000000000000000"
)
FIRMWARE_INFO_PAYLOAD_2_11 = bytes.fromhex(
  "0a0500240000041a53657020313120323032340031343a31393a333700083e4d617920203920323032350031303a34"
  "393a3135007365766572616c20736d616c6c20627567666978657320726567617264696e67206761696e2061646a75"
  "73746d656e742070726f636564757265733b2062756766697820726567617264696e67205859206f66667365742073"
  "63616e20696e20666c79696e67206d6f64653b2062756766697820726567617264696e672063616c63756c6174696f"
  "6e206f66206368726f6d6174696320737769746368696e672074696d653b000001"
)
# Replies of the same reader to STATUS, to REQUEST `07` with 5 parameter bytes (refused, wrong
# length) and to TEMPERATURE_CONTROLLER `06 00 01 00 00` (accepted).
STATUS_IDLE_2_11 = bytes.fromhex("0105002400000500000000000007000000000000000000")
STATUS_PLATE_2_11 = bytes.fromhex("0105002600000500000000000007000000000000000000")
STATUS_BUSY_2_11 = bytes.fromhex("0125002600000524000000000007000000000000000000")
REFUSED_REQUEST_2_11 = bytes.fromhex("0115002400000503000700080007000000000000000000")
MONITORING_STARTED_2_11 = bytes.fromhex("0105002400000500000000000007000000000000000000")
RECORDING_2_11 = os.path.join(
  os.path.dirname(__file__), "recordings", "clariostar_plus_2_11_temperature_controller_1536.json"
)


def decoded() -> DeviceConfiguration:
  configuration = DeviceConfiguration()
  configuration.update_from_init_reply(INIT_PAYLOAD)
  return configuration


class DecodeTests(unittest.TestCase):
  def test_real_reply(self):
    c = decoded()
    self.assertEqual(
      (c.model, c.mainboard_revision, c.firmware_version), ("CLARIOstarPlus", 2, "1.35")
    )
    self.assertTrue(c.extended_red_photomultiplier_tube)
    self.assertTrue(c.dual_photomultiplier_tubes)
    self.assertFalse(c.photomultiplier_tube_crossover)
    self.assertEqual(c.excitation_slide_positions, 4)
    self.assertTrue(c.spectrometer)
    self.assertTrue(c.linear_variable_filters)
    self.assertTrue(c.temperature_controller)
    self.assertEqual(c.temperature_controller_channels, 2)
    self.assertEqual(c.pumps, (None, None, None))
    self.assertFalse(c.stacker_connected)
    self.assertEqual(c.barcode_readers, {})
    self.assertFalse(c.atmospheric_control_unit_connected)

  def test_monochromator_slides(self):
    slides = decoded().monochromator_slides
    assert slides is not None
    self.assertEqual(
      list(slides), ["EX_SP", "EX_LP", "BSP", "EM_SP", "EM_LP", "EM_SLIT", "EX_SLIT"]
    )
    self.assertEqual(slides["BSP"], {1: "open", 2: "Filter 1", 3: "Filter 2", 4: "Filter 3"})
    self.assertEqual(slides["EM_SLIT"][6], "LUM lense")

  def test_undecoded_firmware_fills_only_the_main_board(self):
    # Not a reader's reply: the recorded one with its firmware field set to 1.29, and to 2.11, the
    # line with native USB; no reader with either has answered.
    for firmware, version in ((1290, "1.29"), (2110, "2.11")):
      payload = bytearray(INIT_PAYLOAD)
      payload[9:11] = firmware.to_bytes(2, "big")
      configuration = DeviceConfiguration()
      with self.assertRaises(ValueError):
        configuration.update_from_init_reply(bytes(payload))
      self.assertEqual(
        (configuration.model, configuration.firmware_version), ("CLARIOstarPlus", version)
      )
      self.assertIsNone(configuration.spectrometer)

  def test_a_missing_block_leaves_only_its_fields_unknown(self):
    # Not a reader's reply: the recorded one without its block `2F`, the slides.
    payload, offset = bytearray(INIT_PAYLOAD), 6
    while payload[offset] != 0x2F:
      offset += 3 + int.from_bytes(payload[offset + 1 : offset + 3], "big")
    del payload[offset : offset + 3 + int.from_bytes(payload[offset + 1 : offset + 3], "big")]
    configuration = DeviceConfiguration()
    with patch.object(configuration_module.logger, "warning") as warning:
      configuration.update_from_init_reply(bytes(payload))
    self.assertIn("0x2f", warning.call_args.args[1].args[0])
    self.assertIsNone(configuration.monochromator_slides)
    self.assertIsNone(configuration.linear_variable_filters)
    complete = decoded()
    for field in ("spectrometer", "temperature_controller", "pumps", "barcode_readers"):
      self.assertEqual(getattr(configuration, field), getattr(complete, field), field)
    self.assertTrue(configuration.temperature_controller)

  def test_an_unreadable_slide_position_is_left_out(self):
    slides = _parse_monochromator_slides("BSP:1=open,x=Filter 1,3=Filter 2\nEM_SP:1=open")
    self.assertEqual(slides, {"BSP": {1: "open", 3: "Filter 2"}, "EM_SP": {1: "open"}})

  def test_not_an_init_reply(self):
    with self.assertRaises(ValueError):
      DeviceConfiguration().update_from_init_reply(ftdi_extract_payload(STATUS_IDLE))

  def test_cut_short_reply(self):
    with self.assertRaises(ValueError):
      DeviceConfiguration().update_from_init_reply(INIT_PAYLOAD[:-5])


class DriverTests(unittest.IsolatedAsyncioTestCase):
  async def test_initialize_reads_the_configuration(self):
    io = FakeFTDI()
    io.replies = [INIT_REPLY, STATUS_IDLE]
    driver = make_driver(io)
    await driver.initialize()
    self.assertEqual(driver.configuration.model, "CLARIOstarPlus")

  async def test_parameters_agreeing_with_init_do_not_warn(self):
    io = FakeFTDI()
    io.replies = [STATUS_IDLE, PARAMETERS_REPLY, STATUS_IDLE, FIRMWARE_INFO_REPLY]
    driver = make_driver(io)
    driver.configuration = decoded()
    with patch.object(master_module.logger, "warning") as warning:
      await driver.discover()
    warning.assert_not_called()

  async def test_parameters_disagreeing_with_init_warn(self):
    io = FakeFTDI()
    io.replies = [STATUS_IDLE, PARAMETERS_REPLY, STATUS_IDLE, FIRMWARE_INFO_REPLY]
    driver = make_driver(io)
    driver.configuration.firmware_version = "1.34"
    with self.assertLogs(master_module.logger, "WARNING") as logs:
      await driver.discover()
    self.assertIn(
      "firmware versions disagree: INIT reply 1.34, stored parameters 1.35",
      logs.output[0],
    )


class ParametersTests(unittest.IsolatedAsyncioTestCase):
  def make_driver(self, replies_of_parameters: int = 1):
    io = FakeFTDI()
    io.replies = [STATUS_IDLE, PARAMETERS_REPLY] * replies_of_parameters
    return make_driver(io), io

  def test_the_parameter_table_keys_and_addresses(self):
    keys = [key for key, _, _ in PARAMETER_TABLE]
    self.assertEqual(len(keys), len(set(keys)))
    owners: Dict[int, List[str]] = {}
    for key, address, size in PARAMETER_TABLE:
      self.assertLessEqual(address + size, 256, key)
      for byte in range(address, address + size):
        owners.setdefault(byte, []).append(key)
    for address in SERIAL_NUMBER_ADDRESSES:
      self.assertNotIn(address, owners)
    self.assertEqual([byte for byte, owner in owners.items() if len(owner) > 1], [])
    self.assertLessEqual(set(SIGNED_PARAMETERS), set(keys))

  async def test_request_parameters_from_real_reply(self):
    driver, io = self.make_driver()
    parameters = await driver.request_parameters()
    self.assertEqual(io.written, [STATUS_QUERY_FRAME, PARAMETERS_FRAME])
    self.assertEqual(parameters["firmware_version"], 1350)
    self.assertEqual(parameters["fluorescence_measurement_channel_count"], 1)
    self.assertEqual(parameters["fluorescence_auto_gain_level_1_photomultiplier_tube_1"], 494)
    self.assertEqual(parameters["top_bottom_slide_offset"], -5)
    self.assertEqual(parameters["x_transport_lock_position"], -168)
    self.assertEqual(parameters["temperature_sensor_1_offset"], 20)
    self.assertNotIn("serial_number", parameters)
    self.assertNotIn("project_number", parameters)

  async def test_convenience_methods(self):
    driver, _ = self.make_driver(replies_of_parameters=4)
    self.assertTrue(await driver.request_absorbance_available())
    self.assertEqual(await driver.request_time_resolved_fluorescence_channels(), 1)
    self.assertFalse(await driver.request_extended_temperature_range())
    self.assertFalse(await driver.request_well_1536_plates_supported())

  async def test_configuration_from_parameters(self):
    driver, _ = self.make_driver()
    c = DeviceConfiguration()
    c.update_from_parameters(await driver.request_parameters())
    self.assertEqual((c.fluorescence_channels, c.luminescence_channels), (1, 1))
    self.assertEqual(c.time_resolved_fluorescence_channels, 1)
    self.assertTrue(c.absorbance_available)
    self.assertTrue(c.bottom_measurement_available)
    self.assertFalse(c.alpha_screen_available)
    self.assertFalse(c.fluorescence_polarization_available)
    self.assertFalse(c.fluorescence_polarization_ultraviolet_available)
    self.assertFalse(c.extended_temperature_range)
    self.assertFalse(c.high_speed_shaking_allowed)
    self.assertFalse(c.well_1536_plates_supported)

  async def test_discover_reads_the_serial_number_and_checks_the_link(self):
    # Not a reader's reply: the recorded one, its serial cleaned to zeros, given made-up ones.
    def reply_with_serial(first: int, second: int) -> bytes:
      payload = bytearray(ftdi_extract_payload(PARAMETERS_REPLY))
      for address, value in zip(SERIAL_NUMBER_ADDRESSES, (first, second)):
        payload[address + REPLY_OFFSET : address + REPLY_OFFSET + 2] = value.to_bytes(2, "little")
      return ftdi_wrap_payload(bytes(payload), header=FTDI_HEADER)

    cases: List[Tuple[Tuple[int, int], Dict[str, Optional[str]], str, bool]] = [
      ((123, 4567), {"device_id": None}, "123-4567", False),
      ((123, 4567), {"device_id": "123-4567"}, "123-4567", False),
      ((123, 4567), {"device_id": "999-0001"}, "123-4567", True),
      ((12, 345), {"device_id": "012-0345"}, "012-0345", False),  # padded as the link has it
      ((123, 4567), {"device_id": "1:4", "usb_address": "1:4"}, "123-4567", False),  # by address
    ]
    for serial, link, expected, warns in cases:
      io = FakeFTDI()
      io.replies = [STATUS_IDLE, reply_with_serial(*serial), STATUS_IDLE, FIRMWARE_INFO_REPLY]
      driver = make_driver(io)
      driver.configuration = decoded()
      with (
        self.subTest(link=link),
        patch.object(io, "serialize", return_value={"vid": 0x0403, "pid": 0xBB68, **link}),
        patch.object(master_module.logger, "warning") as warning,
      ):
        await driver.discover()
        self.assertEqual(driver.configuration.serial_number, expected)
        mismatch = any("serial number" in str(call.args[0]) for call in warning.call_args_list)
        self.assertEqual(mismatch, warns)

  async def test_other_reply_is_not_decoded(self):
    io = FakeFTDI()
    io.replies = [STATUS_IDLE, FIRMWARE_INFO_REPLY]
    with self.assertRaises(ValueError):
      await make_driver(io).request_parameters()


def read_2_11() -> DeviceConfiguration:
  """The configuration setup reads from the 2.11 reader's INIT and stored parameters replies."""
  configuration = DeviceConfiguration()
  configuration.update_from_init_reply(payload=INIT_PAYLOAD_2_11)
  configuration.update_from_parameters(
    parameters=CLARIOstarDriver._decode_parameters(
      payload=PARAMETERS_PAYLOAD_2_11, offset=REPLY_OFFSET_FIRMWARE_2
    )
  )
  return configuration


def frame(payload: bytes) -> bytes:
  return ftdi_wrap_payload(payload=payload, header=FTDI_HEADER)


class Firmware211Tests(unittest.TestCase):
  def test_main_board_comes_from_block_02(self):
    configuration = DeviceConfiguration()
    with patch.object(configuration_module.logger, "warning") as warning:
      configuration.update_from_init_reply(payload=INIT_PAYLOAD_2_11)
    warning.assert_not_called()
    self.assertEqual(
      (
        configuration.model,
        configuration.mainboard_revision,
        configuration.firmware_version,
        configuration.firmware_build,
      ),
      ("CLARIOstarPlus", 2, "2.11", 0),
    )
    self.assertTrue(configuration.dual_photomultiplier_tubes)
    self.assertEqual(configuration.excitation_slide_positions, 4)
    self.assertTrue(configuration.temperature_controller)
    self.assertIsNone(configuration.temperature_controller_channels)
    self.assertEqual(configuration.pumps, (None, None, None))
    self.assertEqual(configuration.monochromator_slides, decoded().monochromator_slides)

  def test_stored_parameters_start_four_bytes_later(self):
    parameters = CLARIOstarDriver._decode_parameters(
      payload=PARAMETERS_PAYLOAD_2_11, offset=REPLY_OFFSET_FIRMWARE_2
    )
    self.assertEqual(parameters["firmware_version"], 2110)
    self.assertEqual(parameters["well_1536_measurements_enabled"], 1)
    serial_number = CLARIOstarDriver._decode_serial_number(
      payload=PARAMETERS_PAYLOAD_2_11, offset=REPLY_OFFSET_FIRMWARE_2
    )
    self.assertEqual(serial_number, "000-0000")
    with self.assertRaises(ValueError):  # at the 1.x offset the firmware reads 0
      CLARIOstarDriver._decode_parameters(payload=PARAMETERS_PAYLOAD_2_11)

  def test_build_date_is_the_firmware_entry(self):
    decode = CLARIOstarDriver._decode_firmware_build_date
    self.assertEqual(
      decode(payload=FIRMWARE_INFO_PAYLOAD_2_11, firmware_version="2.11"), "2025-05-09"
    )
    with self.assertLogs(master_module.logger, "WARNING"):
      decode(payload=FIRMWARE_INFO_PAYLOAD_2_11, firmware_version="2.12")
    firmware_info_1_35 = ftdi_extract_payload(FIRMWARE_INFO_REPLY)
    self.assertEqual(
      decode(payload=firmware_info_1_35, firmware_version="1.35"),
      decode(payload=firmware_info_1_35),
    )

  def test_recording_is_what_setup_reads(self):
    configuration = read_2_11()
    self.assertEqual(
      compute_recording_name(configuration=configuration), os.path.basename(RECORDING_2_11)
    )
    saved = read_configuration(path=RECORDING_2_11)["device"]
    self.assertEqual(saved, configuration_to_json(configuration=configuration))

  def test_status_flags_and_no_temperatures(self):
    idle, plate, busy = (
      CLARIOstarDriver._parse_status(payload=payload, temperature_indices=None)
      for payload in (STATUS_IDLE_2_11, STATUS_PLATE_2_11, STATUS_BUSY_2_11)
    )
    self.assertEqual((idle.busy, idle.plate_detected, idle.motors_enabled), (False, False, True))
    self.assertEqual((plate.plate_detected, plate.drawer_open), (True, False))
    self.assertTrue(busy.busy)
    self.assertEqual((idle.temperature_bottom, idle.temperature_top), (None, None))


# The driver's asyncio.Lock needs an event loop on Python 3.9: build drivers inside one.
class Firmware211CommandTests(unittest.IsolatedAsyncioTestCase):
  async def make_2_11_driver(self, replies: List[bytes]) -> Tuple[CLARIOstarDriver, FakeFTDI]:
    """A driver that read the 2.11 INIT reply through `initialize`, then answers `replies`."""
    io = FakeFTDI()
    io.replies = [frame(payload=reply) for reply in [INIT_PAYLOAD_2_11, STATUS_IDLE_2_11, *replies]]
    driver = make_driver(io)
    await driver.initialize()
    io.written.clear()
    return driver, io

  async def test_firmware_generation_follows_the_init_reply(self):
    driver, io = await self.make_2_11_driver([])
    self.assertEqual(
      (
        driver._reply_offset,
        driver._quit_codes_offset,
        driver._parameter_padding,
        driver._running_family_index,
        driver._status_temperature_indices,
      ),
      (
        11,
        7,
        {driver.CommandFamily.REQUEST: 1, driver.CommandFamily.TEMPERATURE_CONTROLLER: 2},
        7,
        None,
      ),
    )
    io.replies = [INIT_REPLY, STATUS_IDLE]
    await driver.initialize()  # the 1.35 reader's reply sets every value back
    self.assertEqual(
      (
        driver._reply_offset,
        driver._quit_codes_offset,
        driver._parameter_padding,
        driver._running_family_index,
        driver._status_temperature_indices,
      ),
      (7, 6, {}, 6, (11, 13)),
    )

  async def test_discover_requests_with_six_parameter_bytes(self):
    driver, io = await self.make_2_11_driver(
      [
        STATUS_IDLE_2_11,
        PARAMETERS_PAYLOAD_2_11,
        STATUS_IDLE_2_11,
        FIRMWARE_INFO_PAYLOAD_2_11,
      ]
    )
    await driver.discover()
    sent = [ftdi_extract_payload(written) for written in io.written]
    self.assertEqual(sent[1], bytes.fromhex("0507000000000000"))
    self.assertEqual(sent[3], bytes.fromhex("0509000000000000"))
    self.assertEqual(driver.configuration.firmware_build_date, "2025-05-09")
    self.assertTrue(driver.configuration.well_1536_plates_supported)

  async def test_monitoring_starts_with_five_bytes(self):
    driver, io = await self.make_2_11_driver(
      [STATUS_IDLE_2_11, STATUS_IDLE_2_11, MONITORING_STARTED_2_11]
    )
    driver._discover_features()
    assert driver.temperature_controller is not None
    await driver.temperature_controller.start_monitoring()
    self.assertEqual(ftdi_extract_payload(io.written[-1]), bytes.fromhex("0600010000"))

  async def test_stop_switches_the_sensors_off(self):
    # The accepted reply is the reader's to `06 00 01 00 00`; none to `06 00 00 00 00` exists yet.
    driver, io = await self.make_2_11_driver(
      [STATUS_IDLE_2_11, STATUS_IDLE_2_11, STATUS_IDLE_2_11, MONITORING_STARTED_2_11]
      + [STATUS_IDLE_2_11]
    )
    driver._discover_features()
    await driver._shut_down(accept_plate_left_in_device=True)
    sent = [ftdi_extract_payload(written) for written in io.written]
    self.assertIn(bytes.fromhex("0600000000"), sent)

  async def test_temperatures_are_refused_until_known(self):
    driver, io = await self.make_2_11_driver([])
    driver._discover_features()
    assert driver.temperature_controller is not None
    with self.assertRaises(NotImplementedError):
      await driver.temperature_controller.measure_temperature()
    self.assertEqual(io.written, [])

  async def test_refusal_codes_start_one_byte_later(self):
    driver, _ = await self.make_2_11_driver([STATUS_IDLE_2_11, REFUSED_REQUEST_2_11])
    with self.assertRaises(CommandRefusedError) as refused:
      await driver.send_command(
        driver.CommandFamily.REQUEST, driver.Command.PARAMETERS, parameters=bytes(5), retries=1
      )
    self.assertEqual(refused.exception.quit_codes, (3, 0, 7, 0, 8))


# The driver's asyncio.Lock needs an event loop on Python 3.9: build drivers inside one.
class DeclaredConfigurationTests(unittest.IsolatedAsyncioTestCase):
  def setUp(self):
    self.directory = tempfile.TemporaryDirectory()
    self.path = os.path.join(self.directory.name, "clariostar.json")
    driver = make_driver(FakeFTDI())
    driver.configuration = decoded()
    driver.save_configuration(self.path)

  def tearDown(self):
    self.directory.cleanup()

  def declared_driver(self):
    driver = make_driver(FakeFTDI())
    driver.declared_configuration_json = self.path
    driver.configuration = decoded()
    return driver

  def test_matching_reader_passes(self):
    self.declared_driver()._check_declared_configuration()

  def test_differing_firmware_passes(self):
    driver = self.declared_driver()
    driver.configuration.firmware_version = "2.11"
    driver._check_declared_configuration()

  def test_differently_fitted_reader_is_refused(self):
    with open(self.path) as f:
      saved = json.load(f)
    saved["device"]["stacker_connected"] = True
    with open(self.path, "w") as f:
      json.dump(saved, f)
    with self.assertRaises(RuntimeError) as ctx:
      self.declared_driver()._check_declared_configuration()
    self.assertIn("stacker_connected: declared True, reader False", str(ctx.exception))

  def test_nothing_read_cannot_be_saved(self):
    with self.assertRaises(RuntimeError):
      make_driver(FakeFTDI()).save_configuration(self.path)


if __name__ == "__main__":
  unittest.main()
