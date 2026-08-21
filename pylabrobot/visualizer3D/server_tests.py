"""The state channel: what a client is told, and what it is deliberately not told again."""

import asyncio
import json
import unittest

import websockets

from pylabrobot.resources import set_volume_tracking
from pylabrobot.resources.coordinate import Coordinate
from pylabrobot.resources.corning import cor_96_wellplate_360uL_Fb
from pylabrobot.visualizer3D.facility import Facility
from pylabrobot.visualizer3D.server import Viewer3D

# Away from the defaults, so a viewer someone left open does not answer these.
FS_PORT, WS_PORT = 8731, 8732


class StateChannelTests(unittest.IsolatedAsyncioTestCase):
  async def asyncSetUp(self):
    set_volume_tracking(True)
    self.facility = Facility(name="facility", size_x=1000, size_y=1000, size_z=500)
    self.plate = cor_96_wellplate_360uL_Fb(name="plate")
    self.facility.assign_child_resource(self.plate, location=Coordinate(10, 10, 0))
    self.viewer = Viewer3D(
      self.facility, open_browser=False, fs_port=FS_PORT, ws_port=WS_PORT, name="tests"
    )
    await self.viewer.start()

  async def asyncTearDown(self):
    await self.viewer.stop()

  async def connect(self):
    """Open a client and take the scene and the snapshot it is greeted with."""
    ws = await websockets.connect(f"ws://127.0.0.1:{self.viewer.ws_port}", max_size=None)
    scene = json.loads(await ws.recv())["data"]
    snapshot = json.loads(await ws.recv())["data"]
    return ws, scene, snapshot

  async def next_state(self, ws, timeout: float = 2.0):
    """The next state message, or None if the server stayed quiet."""
    try:
      while True:
        message = json.loads(await asyncio.wait_for(ws.recv(), timeout))
        if message["event"] == "state":
          return message["data"]
    except asyncio.TimeoutError:
      return None

  async def test_snapshot_names_every_publishing_resource(self):
    ws, scene, snapshot = await self.connect()
    try:
      self.assertIn("plate_well_A1", snapshot["of"])
      self.assertEqual(len(snapshot["of"]), 96)  # the wells; the plate itself publishes nothing
      self.assertIn("plate_well_A1", scene["instances"]["names"])
    finally:
      await ws.close()

  async def test_snapshot_leaves_out_locations(self):
    """The scene sent immediately before already places everything, and a position is unique to one
    resource, so carrying it here would give every resource a state of its own."""
    ws, _, snapshot = await self.connect()
    try:
      for state in snapshot["states"]:
        self.assertNotIn("location", state)
      self.assertLessEqual(len(snapshot["states"]), 2)
    finally:
      await ws.close()

  async def test_a_change_names_only_what_changed(self):
    ws, _, _ = await self.connect()
    try:
      self.plate.get_item("A1").tracker.set_volume(150.0)
      update = await self.next_state(ws)
      self.assertIsNotNone(update)
      self.assertEqual(list(update["of"]), ["plate_well_A1"])
    finally:
      await ws.close()

  async def test_an_unchanged_value_is_not_sent_again(self):
    ws, _, _ = await self.connect()
    try:
      self.plate.get_item("A1").tracker.set_volume(150.0)
      self.assertIsNotNone(await self.next_state(ws))
      self.plate.get_item("A1").tracker.set_volume(150.0)
      self.assertIsNone(await self.next_state(ws, timeout=1.0))
    finally:
      await ws.close()

  async def test_a_change_too_small_to_see_is_not_sent(self):
    """State is rounded to what a viewer can show, so a hundredth of a microlitre is not news."""
    ws, _, _ = await self.connect()
    try:
      self.plate.get_item("A1").tracker.set_volume(150.0)
      self.assertIsNotNone(await self.next_state(ws))
      self.plate.get_item("A1").tracker.set_volume(150.04)
      self.assertIsNone(await self.next_state(ws, timeout=1.0))
    finally:
      await ws.close()

  async def test_a_second_client_is_told_everything(self):
    """Suppression is about what one client has seen. A client that has seen nothing gets it all,
    however much the others have already been told."""
    first, _, _ = await self.connect()
    try:
      self.plate.get_item("A1").tracker.set_volume(150.0)
      await self.next_state(first)
      second, _, snapshot = await self.connect()
      try:
        self.assertEqual(len(snapshot["of"]), 96)
      finally:
        await second.close()
    finally:
      await first.close()

  async def test_a_moved_resource_publishes_its_new_position(self):
    """Position reaches a subscriber the same way rotation always has."""
    ws, _, _ = await self.connect()
    try:
      self.plate.location = Coordinate(400, 300, 0)
      update = await self.next_state(ws)
      self.assertIsNotNone(update)
      self.assertIn("plate", update["of"])
      moved = update["states"][update["of"]["plate"]]
      self.assertEqual(moved["location"]["x"], 400)
    finally:
      await ws.close()


if __name__ == "__main__":
  unittest.main()
