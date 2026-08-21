"""The whole chain, in a real browser: a resource moves, and the picture follows.

Everything else here is tested without a renderer, which is why the failures this catches were the
ones that survived longest: the model was right, the message was right, and nothing was drawn. It
loads the page in headless Chrome, moves a resource, and reads back where the viewer thinks things
are - including a child, which follows only because its parent's world transform was recomputed.

Skipped where there is no Chrome to drive, so it is a no-op on a machine or a runner without one.
"""

import asyncio
import json
import os
import shutil
import subprocess
import tempfile
import time
import unittest
import urllib.request
from typing import Any, Optional

import websockets

from pylabrobot.resources.coordinate import Coordinate
from pylabrobot.resources.resource import Resource
from pylabrobot.visualizer3D.facility import Facility
from pylabrobot.visualizer3D.server import Viewer3D

CHROME = "/Applications/Google Chrome.app/Contents/MacOS/Google Chrome"
FS_PORT, WS_PORT, CDP_PORT = 8741, 8742, 8743


class Browser:
  """Headless Chrome, driven over the devtools protocol. Enough of it to load a page and ask it
  questions."""

  def __init__(self, cdp_port: int):
    self._cdp_port = cdp_port
    self._profile = tempfile.mkdtemp()
    self._chrome: Optional[subprocess.Popen] = None
    self._socket: Any = None
    self._id = 0

  async def __aenter__(self) -> "Browser":
    self._chrome = subprocess.Popen(
      [
        CHROME,
        "--headless=new",
        f"--remote-debugging-port={self._cdp_port}",
        f"--user-data-dir={self._profile}",
        "--enable-unsafe-webgpu",
        "--use-angle=metal",
        "--window-size=1200,800",
        "--no-first-run",
        "about:blank",
      ],
      stdout=subprocess.DEVNULL,
      stderr=subprocess.DEVNULL,
    )
    for _ in range(120):
      try:
        tabs = json.load(urllib.request.urlopen(f"http://127.0.0.1:{self._cdp_port}/json"))
        url = next(t["webSocketDebuggerUrl"] for t in tabs if t["type"] == "page")
        self._socket = await websockets.connect(url, max_size=None)
        return self
      except Exception:
        await asyncio.sleep(0.25)
    raise RuntimeError("could not attach to a headless browser")

  async def __aexit__(self, *_: Any) -> None:
    if self._socket is not None:
      await self._socket.close()
    if self._chrome is not None:
      self._chrome.kill()
    shutil.rmtree(self._profile, ignore_errors=True)

  async def _call(self, method: str, params: Optional[dict] = None, timeout: float = 20.0) -> Any:
    """Send one command and wait for its reply, stepping over the notifications in between.

    Bounded on purpose: a page busy enough not to answer is a failure worth reporting, not a reason
    for the suite to hang.
    """
    self._id += 1
    await self._socket.send(json.dumps({"id": self._id, "method": method, "params": params or {}}))
    async with asyncio.timeout(timeout):
      while True:
        message = json.loads(await self._socket.recv())
        if message.get("id") == self._id:
          return message

  async def open(self, url: str) -> None:
    await self._call("Page.enable")
    await self._call("Page.navigate", {"url": url})

  async def evaluate(self, expression: str) -> Any:
    reply = await self._call("Runtime.evaluate", {"expression": expression, "returnByValue": True})
    if reply["result"].get("exceptionDetails"):
      raise RuntimeError(json.dumps(reply["result"]["exceptionDetails"])[:300])
    return reply["result"]["result"].get("value")

  async def settle(self, expression: str, seconds: float = 25.0) -> Any:
    """Wait for an expression to answer something truthy, then answer with it.

    Bounded by the clock rather than by a number of tries, so a slow answer cannot multiply into a
    suite that never finishes.
    """
    deadline = time.monotonic() + seconds
    while time.monotonic() < deadline:
      await asyncio.sleep(0.25)
      try:
        value = await self.evaluate(expression)
      except (RuntimeError, TimeoutError):
        continue
      if value:
        return value
    raise AssertionError(f"the page never answered within {seconds:.0f}s: {expression}")


@unittest.skipUnless(os.path.isfile(CHROME), "no headless browser to drive")
class BrowserTests(unittest.IsolatedAsyncioTestCase):
  async def asyncSetUp(self):
    self.facility = Facility(name="facility", size_x=2000, size_y=1000, size_z=500)
    self.carrier = Resource(name="carrier", size_x=200, size_y=100, size_z=50)
    self.rider = Resource(name="rider", size_x=40, size_y=40, size_z=20)
    self.facility.assign_child_resource(self.carrier, location=Coordinate(100, 100, 0))
    self.carrier.assign_child_resource(self.rider, location=Coordinate(20, 20, 50))
    self.viewer = Viewer3D(
      self.facility, open_browser=False, fs_port=FS_PORT, ws_port=WS_PORT, name="tests"
    )
    await self.viewer.start()

  async def asyncTearDown(self):
    await self.viewer.stop()

  async def world_x(self, browser: Browser, name: str) -> float:
    """Where the viewer draws a resource, read off the scene it holds."""
    return float(await browser.evaluate(f"window.plrViewer.worldOf({name!r})[0]"))

  async def test_a_move_reaches_the_picture_and_carries_its_children(self):
    async with Browser(CDP_PORT) as browser:
      await browser.open(f"http://127.0.0.1:{self.viewer.fs_port}/")
      await browser.settle("window.plrViewer && window.plrViewer.resources().length > 0")

      self.assertEqual(await self.world_x(browser, "carrier"), 100)
      self.assertEqual(await self.world_x(browser, "rider"), 120)

      self.carrier.location = Coordinate(700, 100, 0)
      await browser.settle("window.plrViewer.worldOf('carrier')[0] === 700")

      # The rider never moved in the model: it follows because its parent's world transform was
      # worked out again. Forgetting that is what left a 96-head standing still while its arm swept.
      self.assertEqual(await self.world_x(browser, "rider"), 720)


if __name__ == "__main__":
  unittest.main()
