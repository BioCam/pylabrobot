"""The state channel: what a client is told, and what it is deliberately not told again."""

import asyncio
import contextlib
import io
import json
import os
import socket
import unittest
import urllib.error
import urllib.request
from typing import Any, Dict, List, Optional

import websockets
from websockets.typing import Origin

from pylabrobot.resources import does_volume_tracking, set_volume_tracking
from pylabrobot.resources.coordinate import Coordinate
from pylabrobot.resources.corning import cor_96_wellplate_360uL_Fb
from pylabrobot.resources.hamilton import hamilton_96_tiprack_1000uL
from pylabrobot.resources.resource import Resource
from pylabrobot.visualizer3D.facility import Facility
from pylabrobot.visualizer3D.server import Viewer3D

# Away from the defaults, so a viewer someone left open does not answer these.
FS_PORT, WS_PORT = 8731, 8732
# Any model file shipped with the package: what it draws does not matter, that it registers does.
MESH_FILE = os.path.join(
  os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
  "hamilton",
  "star",
  "resource_model",
  "starlet_base.glb",
)


class StateChannelTests(unittest.IsolatedAsyncioTestCase):
  async def asyncSetUp(self):
    # Volume tracking is global, so remember what it was and put it back: leaving it on breaks
    # every other suite that aspirates from a well it never filled.
    self._volume_tracking = does_volume_tracking()
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
    set_volume_tracking(self._volume_tracking)

  async def connect(self):
    """Open a client and take the scene and the snapshot it is greeted with."""
    ws = await websockets.connect(self.viewer.ws_url, max_size=None)
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

  async def test_full_tip_spots_share_one_state(self):
    """A spot's state embeds its tip, and the tip names the spot. That is identity, not state: a
    rack of the same tip is one state on the wire, not ninety-six."""
    rack = hamilton_96_tiprack_1000uL(name="rack", with_tips=True)
    self.facility.assign_child_resource(rack, location=Coordinate(300, 10, 0))
    ws, _, snapshot = await self.connect()
    try:
      spots = [spot.name for spot in rack.get_all_items()]
      self.assertEqual(len({snapshot["of"][name] for name in spots}), 1)
      self.assertLessEqual(len(snapshot["states"]), 3)
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

  async def test_a_resource_moved_under_another_parent_is_moved_not_rebuilt(self):
    """The same names are the same instances: a change of parent is a move, a parent index and six
    floats, applied to the scene the client has. Its new location travels in the move and in no
    state before it, which would be read against the old parent."""
    holder = Resource(name="holder", size_x=200, size_y=200, size_z=50)
    self.facility.assign_child_resource(holder, location=Coordinate(500, 500, 0))
    # The holder is in the scene a client is greeted with, and the flush its assignment scheduled
    # finds nothing moved since, so it sends nothing: a rebuild was the old behaviour there too.
    ws, _, _ = await self.connect()
    try:
      self.plate.unassign()
      holder.assign_child_resource(self.plate, location=Coordinate(5, 5, 50))
      states, moves = await self.next_of(ws, "moves")
      for state in states:
        index = state["of"].get("plate")
        self.assertTrue(index is None or "location" not in state["states"][index], state)
      moved = {move["name"]: move for move in moves["moves"]}
      self.assertIn("plate", moved)
      self.assertEqual(moved["plate"]["parent"], "holder")
      self.assertEqual(moved["plate"]["location"], {"x": 5.0, "y": 5.0, "z": 50.0})
      self.assertEqual(self.viewer.rebuilds, 0)
    finally:
      await ws.close()

  async def test_a_client_arriving_after_a_move_sees_it_in_the_scene(self):
    """The kept scene is moved along with the clients', so a late client is handed it as it stands."""
    holder = Resource(name="holder", size_x=200, size_y=200, size_z=50)
    self.facility.assign_child_resource(holder, location=Coordinate(500, 500, 0))
    first, _, _ = await self.connect()
    try:
      self.plate.unassign()
      holder.assign_child_resource(self.plate, location=Coordinate(5, 5, 50))
      await self.next_of(first, "moves")
      second, scene, _ = await self.connect()
      try:
        names = scene["instances"]["names"]
        self.assertEqual(names[scene["instances"]["parent"][names.index("plate")]], "holder")
      finally:
        await second.close()
    finally:
      await first.close()

  async def next_of(self, ws, event: str, timeout: float = 2.0):
    """The state messages that arrive before the next message of `event`, and that message."""
    states: List[Dict[str, Any]] = []
    while True:
      message = json.loads(await asyncio.wait_for(ws.recv(), timeout))
      if message["event"] == event:
        return states, message["data"]
      if message["event"] == "state":
        states.append(message["data"])


class FileServerTests(unittest.IsolatedAsyncioTestCase):
  """The file server keeps quiet about what is not its fault."""

  async def asyncSetUp(self):
    self.facility = Facility(name="facility", size_x=1000, size_y=1000, size_z=500)
    self.viewer = Viewer3D(self.facility, open_browser=False, fs_port=FS_PORT, ws_port=WS_PORT)
    await self.viewer.start()

  async def asyncTearDown(self):
    await self.viewer.stop()

  async def test_a_download_abandoned_by_the_browser_prints_no_traceback(self):
    """A page left mid-download closes its end of the socket, which the threaded server used to
    report as an exception in the request thread, a full traceback on every reload."""
    captured = io.StringIO()

    def abandon() -> None:
      with socket.create_connection(("127.0.0.1", self.viewer.fs_port)) as sock:
        sock.sendall(b"GET /vendor/three.webgpu.min.js HTTP/1.1\r\nHost: 127.0.0.1\r\n\r\n")
        sock.recv(1024)  # the start of the body, then gone

    with contextlib.redirect_stderr(captured):
      await asyncio.to_thread(abandon)
      await asyncio.sleep(0.5)  # the request thread notices the closed socket
    self.assertEqual(captured.getvalue(), "")


class LifecycleTests(unittest.IsolatedAsyncioTestCase):
  """A stopped viewer gives its ports back."""

  async def test_a_viewer_started_after_another_stopped_binds_the_same_ports(self):
    """`stop` used to close the file server and leave the websocket server listening, so the next
    viewer in the same process found its port taken and moved up: the ports drifted by one on
    every restart, and a page served by the earlier viewer kept its stale token forever."""
    facility = Facility(name="facility", size_x=1000, size_y=1000, size_z=500)
    first = Viewer3D(facility, open_browser=False, fs_port=FS_PORT, ws_port=WS_PORT)
    await first.start()
    self.assertEqual((first.fs_port, first.ws_port), (FS_PORT, WS_PORT))
    await first.stop()
    second = Viewer3D(facility, open_browser=False, fs_port=FS_PORT, ws_port=WS_PORT)
    await second.start()
    try:
      self.assertEqual((second.fs_port, second.ws_port), (FS_PORT, WS_PORT))
    finally:
      await second.stop()


class RebuildTests(unittest.IsolatedAsyncioTestCase):
  """A scene rebuilt from reused models is the scene it was."""

  async def test_a_model_given_a_mesh_does_not_split_on_the_next_build(self):
    """Registering meshes used to write into the interned model dicts, so on the next build the
    one carrying a mesh no longer matched the twins the scene had kept, and every rebuild grew the
    model table: fifty-three models became sixty-seven on the demo facility."""
    facility = Facility(name="facility", size_x=1000, size_y=1000, size_z=500)
    for i in range(3):
      part = Resource(name=f"part_{i}", size_x=10, size_y=10, size_z=10, model="part")
      # Declared the way a resource module declares it: a field the base class does not know.
      setattr(part, "mesh", {"path": MESH_FILE, "units": "m", "up": "Z"})
      facility.assign_child_resource(part, location=Coordinate(100 * i, 0, 0))
    viewer = Viewer3D(facility, open_browser=False)
    first = viewer._scene_message(rebuild=True)
    second = viewer._scene_message(rebuild=True)
    self.assertEqual(len(first["models"]), 2)  # the facility and the one part they all share
    self.assertEqual(second["models"], first["models"])


class AccessTests(unittest.IsolatedAsyncioTestCase):
  """Only the page this viewer served, reached by a name this machine answers to, may watch."""

  async def asyncSetUp(self):
    self.facility = Facility(name="facility", size_x=1000, size_y=1000, size_z=500)
    self.viewer = Viewer3D(
      self.facility, open_browser=False, fs_port=FS_PORT, ws_port=WS_PORT, name="tests"
    )
    await self.viewer.start()

  async def asyncTearDown(self):
    await self.viewer.stop()

  def ws(self, token: Optional[str]) -> str:
    query = "" if token is None else f"?token={token}"
    return f"ws://127.0.0.1:{self.viewer.ws_port}/{query}"

  async def assert_refused(self, url: str, **kwargs):
    with self.assertRaises(websockets.InvalidStatus) as refused:
      await websockets.connect(url, **kwargs)
    self.assertEqual(refused.exception.response.status_code, 403)

  async def test_a_websocket_without_the_token_is_refused(self):
    await self.assert_refused(self.ws(None))
    await self.assert_refused(self.ws("not-the-token"))

  async def test_a_page_from_another_site_is_refused_even_with_the_token(self):
    await self.assert_refused(self.ws(self.viewer.token), origin="https://example.com")

  async def test_the_served_page_and_a_tunnel_are_let_in(self):
    for origin in (
      f"http://127.0.0.1:{self.viewer.fs_port}",
      "http://localhost:9000",
      f"http://{socket.gethostname()}.local:{self.viewer.fs_port}",
      "http://10.60.2.36:1338",
    ):
      ws = await websockets.connect(
        self.ws(self.viewer.token), origin=Origin(origin), max_size=None
      )
      self.assertEqual(json.loads(await ws.recv())["event"], "scene")
      await ws.close()

  def get(self, host: str) -> int:
    request = urllib.request.Request(
      f"http://127.0.0.1:{self.viewer.fs_port}/", headers={"Host": host}
    )
    try:
      with urllib.request.urlopen(request) as response:
        return int(response.status)
    except urllib.error.HTTPError as error:
      return error.code

  async def test_the_page_is_not_served_to_a_rebound_name(self):
    """DNS rebinding points a hostile name at 127.0.0.1, which would make its page same-origin
    with ours and let it read the token out of the HTML."""
    self.assertEqual(await asyncio.to_thread(self.get, "attacker.example:1338"), 403)

  async def test_the_page_carries_the_token_for_a_known_name(self):
    for host in ("127.0.0.1:1338", "localhost:1338", "[::1]:1338"):
      self.assertEqual(await asyncio.to_thread(self.get, host), 200, host)
    page = await asyncio.to_thread(
      lambda: urllib.request.urlopen(f"http://127.0.0.1:{self.viewer.fs_port}/").read().decode()
    )
    self.assertIn(self.viewer.token, page)
    self.assertNotIn("{{ ws_token }}", page)

  async def test_every_run_has_its_own_token(self):
    other = Viewer3D(self.facility, open_browser=False)
    self.assertNotEqual(other.token, self.viewer.token)


if __name__ == "__main__":
  unittest.main()
