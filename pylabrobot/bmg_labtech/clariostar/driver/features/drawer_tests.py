"""Drawer tests over a fake io, with replies recorded from a CLARIOstar Plus."""

import unittest

from pylabrobot.bmg_labtech.clariostar.driver.driver_tests import (
  STATUS_BUSY,
  STATUS_DRAWER_OPEN,
  STATUS_IDLE,
  STATUS_PLATE_DETECTED,
  STATUS_QUERY_FRAME,
  V1,
  FakeFTDI,
  make_driver,
)
from pylabrobot.bmg_labtech.clariostar.driver.errors import CommandRefusedError, FrameError
from pylabrobot.bmg_labtech.clariostar.driver.recordings import load_exchanges
from pylabrobot.resources import Coordinate, PlateHolder

OPEN_DRAWER_FRAME, OPEN_DRAWER_REPLY = V1["open_drawer"]
CLOSE_DRAWER_FRAME, CLOSE_DRAWER_REPLY = V1["close_drawer"]
REFUSED_OPEN_DRAWER_BUSY = load_exchanges("clariostar_plus_ftdi_2020_previous_driver.json")[
  "refused_open_drawer_busy"
][1]

# Made-up locations: the real ones are not measured yet.
LOCATION_IN = Coordinate(10, 20, 30)
LOCATION_OUT = Coordinate(10, -200, 30)


def make_plate_holder() -> PlateHolder:
  return PlateHolder(
    name="plate_holder",
    size_x=127.76,
    size_y=85.48,
    size_z=0,
    pedestal_size_z=0,
    child_location=Coordinate.zero(),
  )


class DrawerTests(unittest.IsolatedAsyncioTestCase):
  def setUp(self):
    self.io = FakeFTDI()
    self.driver = make_driver(self.io)
    self.plate_holder = make_plate_holder()
    self.plate_holder.location = Coordinate.zero()
    drawer = self.driver.drawer
    drawer.plate_holder = self.plate_holder
    drawer.location_in = LOCATION_IN
    drawer.location_out = LOCATION_OUT

  async def test_open_waits_for_idle_and_open_then_records_out(self):
    self.io.replies = [
      STATUS_IDLE,  # idle before the command is sent
      OPEN_DRAWER_REPLY,
      STATUS_BUSY,
      STATUS_DRAWER_OPEN,  # idle and open: done
      STATUS_DRAWER_OPEN,  # read for the model
    ]
    await self.driver.drawer.open()
    self.assertEqual(
      self.io.written, [STATUS_QUERY_FRAME, OPEN_DRAWER_FRAME] + [STATUS_QUERY_FRAME] * 3
    )
    self.assertEqual(self.plate_holder.location, LOCATION_OUT)

  async def test_close_records_in(self):
    self.plate_holder.location = LOCATION_OUT
    self.io.replies = [STATUS_DRAWER_OPEN, CLOSE_DRAWER_REPLY, STATUS_IDLE, STATUS_IDLE]
    await self.driver.drawer.close()
    self.assertEqual(
      self.io.written, [STATUS_QUERY_FRAME, CLOSE_DRAWER_FRAME] + [STATUS_QUERY_FRAME] * 2
    )
    self.assertEqual(self.plate_holder.location, LOCATION_IN)

  async def test_idle_but_not_open_times_out(self):
    self.driver.drawer._MOVE_TIMEOUT = 0
    self.io.replies = [STATUS_IDLE, OPEN_DRAWER_REPLY, STATUS_IDLE, STATUS_IDLE]
    with self.assertRaises(TimeoutError):
      await self.driver.drawer.open()
    self.assertEqual(self.plate_holder.location, LOCATION_IN)

  async def test_refused_open_raises_and_records_where_the_drawer_is(self):
    self.io.replies = [STATUS_IDLE, REFUSED_OPEN_DRAWER_BUSY, STATUS_IDLE]
    with self.assertRaises(CommandRefusedError) as ctx:
      await self.driver.drawer.open()
    self.assertEqual(ctx.exception.quit_codes[0], 202)
    self.assertEqual(self.plate_holder.location, LOCATION_IN)

  async def test_failed_move_still_records_where_the_drawer_is(self):
    truncated = CLOSE_DRAWER_REPLY[:10]
    self.io.replies = [STATUS_DRAWER_OPEN, truncated, truncated, truncated, STATUS_DRAWER_OPEN]
    with self.assertRaises(FrameError):
      await self.driver.drawer.close()
    self.assertEqual(
      self.io.written, [STATUS_QUERY_FRAME] + [CLOSE_DRAWER_FRAME] * 3 + [STATUS_QUERY_FRAME]
    )
    self.assertEqual(self.plate_holder.location, LOCATION_OUT)

  async def test_failed_read_after_failed_move_keeps_the_move_error(self):
    self.io.replies = [STATUS_DRAWER_OPEN] + [CLOSE_DRAWER_REPLY[:10]] * 3
    with self.assertRaises(FrameError):
      await self.driver.drawer.close()
    self.assertEqual(self.plate_holder.location, Coordinate.zero())

  async def test_without_locations_the_model_is_left_alone(self):
    self.driver.drawer.location_out = None
    self.io.replies = [STATUS_DRAWER_OPEN]
    self.assertTrue(await self.driver.drawer.request_open())
    self.assertEqual(self.plate_holder.location, Coordinate.zero())

  async def test_plate_detected(self):
    self.io.replies = [STATUS_PLATE_DETECTED]
    self.assertTrue(await self.driver.drawer.request_plate_detected())
