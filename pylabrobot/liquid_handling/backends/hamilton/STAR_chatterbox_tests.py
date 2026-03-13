import unittest

from pylabrobot.io.validation_utils import LOG_LEVEL_IO
from pylabrobot.liquid_handling import LiquidHandler
from pylabrobot.resources import (
  Coordinate,
  Resource,
  TIP_CAR_480_A00,
  hamilton_96_tiprack_1000uL,
)
from pylabrobot.resources.hamilton import STARLetDeck

from .STAR_chatterbox import STARChatterboxBackend


class TestSTARChatterboxBackend(unittest.IsolatedAsyncioTestCase):
  async def asyncSetUp(self):
    self.backend = STARChatterboxBackend()
    self.deck = STARLetDeck()
    self.lh = LiquidHandler(backend=self.backend, deck=self.deck)
    await self.lh.setup()

  async def asyncTearDown(self):
    await self.lh.stop()

  async def test_commands_logged_at_io_level(self):
    """Verify that firmware commands are emitted at LOG_LEVEL_IO, same as the real backend."""
    tip_car = TIP_CAR_480_A00(name="tip_carrier")
    tip_car[0] = tiprack = hamilton_96_tiprack_1000uL(name="tips")
    self.deck.assign_child_resource(tip_car, rails=1)

    with self.assertLogs("pylabrobot", level=LOG_LEVEL_IO) as cm:
      await self.lh.pick_up_tips(tiprack["A1"])

    io_messages = [m for m in cm.output if "write:" in m or "read:" in m]
    self.assertGreater(len(io_messages), 0)

    await self.lh.drop_tips(tiprack["A1"])
    self.deck.unassign_child_resource(tip_car)

  async def test_write_and_read_returns_valid_response(self):
    """Verify _write_and_read_command returns a well-formed success response."""
    resp = await self.backend._write_and_read_command(id_=42, cmd="C0ASid0042 ...")
    self.assertIn("er00/00", resp)
    self.assertIn("id0042", resp)

  async def test_write_and_read_none_id(self):
    resp = await self.backend._write_and_read_command(id_=None, cmd="C0ASid0000 ...")
    self.assertIn("id0000", resp)

  async def test_head96_request_tip_presence(self):
    result = await self.backend.head96_request_tip_presence(simulated_value=0)
    self.assertEqual(result, 0)

  async def test_park_iswap(self):
    self.backend._iswap_parked = False
    await self.backend.park_iswap()
    self.assertTrue(self.backend._iswap_parked)

  async def test_return_core_gripper_tools(self):
    self.backend._core_parked = False
    await self.backend.return_core_gripper_tools()
    self.assertTrue(self.backend._core_parked)

  async def test_core_check_resource_exists(self):
    result = await self.backend.core_check_resource_exists_at_location_center(
      location=Coordinate(100, 200, 300),
      resource=Resource(name="test", size_x=10, size_y=10, size_z=10),
      simulated_value=True,
    )
    self.assertTrue(result)

  async def test_request_presence_of_carriers(self):
    self.assertEqual(
      await self.backend.request_presence_of_carriers_on_loading_tray(simulated_value=[]), []
    )
    self.assertEqual(
      await self.backend.request_presence_of_carriers_on_deck(), []
    )

  async def test_send_raw_command_logged_at_io_level(self):
    with self.assertLogs("pylabrobot", level=LOG_LEVEL_IO) as cm:
      await self.backend.send_raw_command("C0RVid0001")
    self.assertTrue(any("C0RVid0001" in msg for msg in cm.output))

  # --- @simulated_value decorator tests ---

  async def test_simulated_value_omitted_returns_zero_default(self):
    """Omitting simulated_value= in simulation returns zeroed default from _parse_response."""
    result = await self.backend.head96_request_tip_presence()
    self.assertEqual(result, 0)

  async def test_simulated_value_returns_provided_value(self):
    """simulated_value= returns the caller-provided value."""
    self.assertEqual(
      await self.backend.head96_request_tip_presence(simulated_value=0), 0
    )
    self.assertEqual(
      await self.backend.request_presence_of_carriers_on_loading_tray(
        simulated_value=[1, 3]
      ),
      [1, 3],
    )

  async def test_simulated_value_generates_firmware_log(self):
    """@simulated_value methods still generate firmware commands in the log."""
    with self.assertLogs("pylabrobot", level=LOG_LEVEL_IO) as cm:
      result = await self.backend.request_presence_of_carriers_on_loading_tray(
        simulated_value=[]
      )
    self.assertEqual(result, [])
    io_messages = [m for m in cm.output if "write:" in m]
    self.assertGreater(len(io_messages), 0)


if __name__ == "__main__":
  unittest.main()
