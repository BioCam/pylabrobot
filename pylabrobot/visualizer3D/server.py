"""Serve a flattened resource tree to the browser and keep it current.

Same two servers as the existing visualizer, a static file server and a websocket, because that
part of the design was never the problem: it is what lets the viewer sit on a laptop while the
protocol runs on the instrument host. What changed is the payload.
"""

import asyncio
import http.server
import json
import logging
import math
import os
import threading
import webbrowser
from typing import Any, Dict, Optional

import websockets

from pylabrobot.resources.resource import Resource

from .scene import build_scene, collect_state

logger = logging.getLogger(__name__)


def _finite(obj: Any) -> Any:
  """Replace non-finite floats with strings.

  `json.dumps` writes bare `Infinity` and `NaN`, which are not JSON and make `JSON.parse` throw in
  the browser. A trough's max volume is genuinely infinite, so this is reached on an ordinary deck.
  """
  if isinstance(obj, float) and not math.isfinite(obj):
    if math.isnan(obj):
      return "NaN"
    return "Infinity" if obj > 0 else "-Infinity"
  if isinstance(obj, dict):
    return {k: _finite(v) for k, v in obj.items()}
  if isinstance(obj, (list, tuple)):
    return [_finite(v) for v in obj]
  return obj


STATIC_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "static")


class Viewer3D:
  """A parallel visualizer that takes any resource as its world.

  Args:
    root: the resource that is the world. Every descendant is placed in its cartesian space.
    telemetry: optional device state readers, polled while the viewer is connected.
    host: interface to bind both servers to.
    fs_port: static file server port.
    ws_port: websocket port.
    telemetry_hz: how often to poll the telemetry readers, in Hz.
    open_browser: whether to open a browser window on start.
    name: what to show in the header, as the existing visualizer shows the calling script.
  """

  def __init__(
    self,
    root: Resource,
    telemetry: Optional[list] = None,
    host: str = "127.0.0.1",
    fs_port: int = 1338,
    ws_port: int = 2122,
    telemetry_hz: float = 5.0,
    open_browser: bool = True,
    name: str = "workcell",
  ):
    self.root = root
    self.telemetry = telemetry or []
    self.host = host
    self.fs_port = fs_port
    self.ws_port = ws_port
    self.telemetry_period = 1.0 / telemetry_hz
    self.open_browser = open_browser
    self.name = name

    self._clients: set = set()
    self._httpd: Optional[http.server.HTTPServer] = None
    self._pending: Dict[str, dict] = {}
    self._flush_scheduled = False
    self._loop: Optional[asyncio.AbstractEventLoop] = None
    self._stats: Dict[str, Any] = {}
    self._legacy_bytes: Optional[int] = None  # measured once; it costs a full extra serialization
    self._scene_dirty = False
    self._scene_timer: Optional[asyncio.TimerHandle] = None
    self.rebuilds = 0  # how many scene rebuilds a run actually cost

    self._subscribe(root)
    # A newly assigned resource has to start publishing too, or its state never reaches the viewer.
    root.register_did_assign_resource_callback(self._on_assign)
    root.register_did_unassign_resource_callback(lambda _r: self._resend())

  # -- wiring ----------------------------------------------------------------

  def _on_assign(self, resource: Resource) -> None:
    self._subscribe(resource)
    self._resend()

  def _subscribe(self, resource: Resource) -> None:
    def on_update(_state: dict, r: Resource = resource) -> None:
      self._on_state_update(r)

    resource.register_state_update_callback(on_update)
    for child in resource.children:
      self._subscribe(child)

  def _on_state_update(self, resource: Resource) -> None:
    """Batch state updates so a 96-channel operation is one message, not ninety-six."""
    if self._loop is None:
      return
    self._loop.call_soon_threadsafe(self._enqueue, resource.name, resource.serialize_state())

  def _enqueue(self, name: str, state: dict) -> None:
    self._pending[name] = state
    if self._loop is not None and not self._flush_scheduled:
      self._flush_scheduled = True
      self._loop.call_soon(lambda: asyncio.ensure_future(self._flush()))

  async def _flush(self) -> None:
    payload, self._pending = self._pending, {}
    self._flush_scheduled = False
    if payload:
      await self._broadcast("state", payload)

  # A structural change costs a whole scene, so a burst of them must not cost a scene each. Picking
  # up ninety-six tips is one operation to a user and a hundred and ninety-two callbacks here; they
  # coalesce into a single rebuild on a short timer. The proper answer is to send the moved
  # instances rather than the scene, since a move is a parent index and six floats, but coalescing
  # is what stops the current shape being quadratic in a burst.
  SCENE_DEBOUNCE_S = 0.05

  def _resend(self) -> None:
    """The tree changed shape, so the flattening is stale. Schedule one rebuild for the burst."""
    if self._loop is None:
      return
    self._loop.call_soon_threadsafe(self._mark_scene_dirty)

  def _mark_scene_dirty(self) -> None:
    self._scene_dirty = True
    if self._scene_timer is not None:
      self._scene_timer.cancel()
    if self._loop is None:
      return
    self._scene_timer = self._loop.call_later(
      self.SCENE_DEBOUNCE_S, lambda: asyncio.ensure_future(self._flush_scene())
    )

  async def _flush_scene(self) -> None:
    self._scene_timer = None
    if not self._scene_dirty:
      return
    self._scene_dirty = False
    self.rebuilds += 1
    await self._send_scene_to_all()

  # -- transport -------------------------------------------------------------

  async def _broadcast(self, event: str, data: Any) -> None:
    if not self._clients:
      return
    message = json.dumps(_finite({"event": event, "data": data}))
    for client in list(self._clients):
      try:
        await client.send(message)
      except Exception:
        self._clients.discard(client)

  def _scene_message(self) -> Dict[str, Any]:
    """The scene, its measurements, and any workcell groups the root records.

    Groups are read by duck typing rather than by importing `Facility`, so any root that records
    workcells is served, and a plain resource simply has none.
    """
    # The comparison against the old payload shape is measured on the first build only: it costs
    # a second full serialization of the tree and never changes for a given scene.
    scene = build_scene(self.root, measure_legacy=self._legacy_bytes is None)
    if self._legacy_bytes is None:
      self._legacy_bytes = scene.legacy_bytes
    scene.legacy_bytes = self._legacy_bytes

    payload = scene.serialize()
    self._stats = scene.stats(scene_bytes=len(json.dumps(payload)))
    serialize_workcells = getattr(self.root, "serialize_workcells", None)
    return {
      **payload,
      "stats": self._stats,
      "workcells": serialize_workcells() if callable(serialize_workcells) else [],
    }

  async def _send_scene_to_all(self) -> None:
    await self._broadcast("scene", self._scene_message())
    await self._broadcast("state", collect_state(self.root))

  async def _handler(self, websocket) -> None:
    self._clients.add(websocket)
    await websocket.send(json.dumps(_finite({"event": "scene", "data": self._scene_message()})))
    await websocket.send(json.dumps(_finite({"event": "state", "data": collect_state(self.root)})))
    try:
      async for _ in websocket:
        pass
    except Exception:
      pass
    finally:
      self._clients.discard(websocket)

  async def _telemetry_loop(self) -> None:
    while True:
      if self._clients and self.telemetry:
        readings = []
        for reader in self.telemetry:
          try:
            readings.append((await reader.read()).serialize())
          except Exception as e:
            logger.warning("telemetry read failed: %s", e)
        if readings:
          await self._broadcast("telemetry", readings)
      await asyncio.sleep(self.telemetry_period)

  # -- static files ----------------------------------------------------------

  def _start_file_server(self) -> None:
    directory = STATIC_DIR
    ws_port = self.ws_port
    name = self.name

    class Handler(http.server.SimpleHTTPRequestHandler):
      def __init__(self, *args, **kwargs):
        super().__init__(*args, directory=directory, **kwargs)

      def log_message(self, fmt, *args):
        pass

      def end_headers(self):
        self.send_header("Cache-Control", "no-store")
        super().end_headers()

      def do_GET(self):
        # Match on the path alone: a link may carry a query string (`/?view=top`), and serving the
        # template unsubstituted in that case leaves the page with no websocket port.
        path = self.path.split("?", 1)[0].split("#", 1)[0]
        if path in ("/", "/index.html"):
          with open(os.path.join(directory, "index.html"), "r", encoding="utf-8") as f:
            content = f.read().replace("{{ ws_port }}", str(ws_port))
            content = content.replace("{{ source_filename }}", name)
          body = content.encode("utf-8")
          self.send_response(200)
          self.send_header("Content-type", "text/html; charset=utf-8")
          self.send_header("Content-Length", str(len(body)))
          self.end_headers()
          self.wfile.write(body)
          return
        return super().do_GET()

    while True:
      try:
        self._httpd = http.server.HTTPServer((self.host, self.fs_port), Handler)
        break
      except OSError:
        self.fs_port += 1

    thread = threading.Thread(target=self._httpd.serve_forever, daemon=True, name="viz3d_fs")
    thread.start()

  # -- lifecycle -------------------------------------------------------------

  async def start(self) -> None:
    self._loop = asyncio.get_running_loop()
    self._start_file_server()

    while True:
      try:
        self._ws_server = await websockets.serve(self._handler, self.host, self.ws_port)
        break
      except OSError:
        self.ws_port += 1

    url = f"http://{self.host}:{self.fs_port}"
    print(f"viewer on {url}  (websocket {self.ws_port})")
    if self.open_browser:
      webbrowser.open(url)

    asyncio.ensure_future(self._telemetry_loop())

  async def stop(self) -> None:
    if self._httpd is not None:
      self._httpd.shutdown()
      self._httpd.server_close()
      self._httpd = None
