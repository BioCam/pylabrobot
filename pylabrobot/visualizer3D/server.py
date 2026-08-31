"""Serve a flattened resource tree to the browser and keep it current.

Same two servers as the existing visualizer, a static file server and a websocket, because that
part of the design was never the problem: it is what lets the viewer sit on a laptop while the
protocol runs on the instrument host. What changed is the payload.
"""

import asyncio
import hashlib
import http.server
import json
import logging
import math
import os
import threading
import webbrowser
from typing import Any, Dict, List, Optional

import websockets

from pylabrobot.resources.resource import Resource

from .scene import build_scene, collect_state, pack_state, state_signature

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
    host: interface to bind both servers to.
    fs_port: static file server port.
    models_root: directory that every `Resource.reference_glb` is relative to. Without one,
      resources that declare a model are drawn as boxes, and say so once each.
    ws_port: websocket port.
    open_browser: whether to open a browser window on start.
    name: what to show in the header, as the existing visualizer shows the calling script.
  """

  def __init__(
    self,
    root: Resource,
    host: str = "127.0.0.1",
    fs_port: int = 1338,
    ws_port: int = 2122,
    open_browser: bool = True,
    name: str = "facility",
    models_root: Optional[str] = None,
  ):
    self.root = root
    self.host = host
    self.fs_port = fs_port
    self.ws_port = ws_port
    self.open_browser = open_browser
    self.name = name
    # Where a resource's `reference_glb` is resolved from. One root for the whole scene, so a
    # resource names its model the same way wherever the tree is built and whoever runs it.
    self.models_root = os.path.abspath(os.path.expanduser(models_root)) if models_root else None

    self._clients: set = set()
    self._httpd: Optional[http.server.HTTPServer] = None
    self._pending: Dict[str, dict] = {}
    self._flush_scheduled = False
    self._loop: Optional[asyncio.AbstractEventLoop] = None
    self._stats: Dict[str, Any] = {}
    self._legacy_bytes: Optional[int] = None  # measured once; it costs a full extra serialization
    # Files a resource declared as its own geometry, by the id the page fetches them under. Only a
    # path that a resource named is ever served, so this doubles as the whitelist.
    self._mesh_files: Dict[str, str] = {}
    # Which scene the indices below belong to, and the index of every resource in it. State is
    # addressed by index rather than by name, so both have to be current before any is sent.
    self._epoch = 0
    self._index_of: Dict[str, int] = {}
    # What each resource last looked like on the wire. A resource that publishes a change too small
    # to see produces the same signature and is not sent again.
    self._published: Dict[str, str] = {}
    # Models derived by the last flatten, by resource name, and the set of names that flatten saw.
    # Reusing a model is only sound while the tree holds the same names: a model can carry a
    # reference to another resource, and whether a string counts as such a reference depends on
    # which names exist. Same names, same answer. A name appearing or disappearing throws the lot
    # away and pays for one full flatten, which is the case that was going to be expensive anyway.
    self._known_models: Dict[str, Dict[str, Any]] = {}
    self._known_names: frozenset = frozenset()
    # The scene as last built. A client arriving is not a change to the scene, so it is handed this
    # rather than causing a fresh one: rebuilding would renumber everything and hand every client
    # already watching an epoch their indices no longer match.
    self._scene_payload: Optional[Dict[str, Any]] = None
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
      message = self._state_message(payload)
      # Everything in the batch may have been a change nobody could see.
      if message["of"]:
        await self._broadcast("state", message)

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

  def _scene_message(self, rebuild: bool = False) -> Dict[str, Any]:
    """The scene and its measurements."""
    if self._scene_payload is not None and not rebuild:
      return self._scene_payload

    # The comparison against the old payload shape is measured on the first build only: it costs
    # a second full serialization of the tree and never changes for a given scene.
    scene = build_scene(
      self.root,
      measure_legacy=self._legacy_bytes is None,
      known=self._known_models,
      known_names=self._known_names,
    )
    self._known_names = frozenset(scene.names)
    self._known_models = scene.derived
    if self._legacy_bytes is None:
      self._legacy_bytes = scene.legacy_bytes
    scene.legacy_bytes = self._legacy_bytes

    payload = scene.serialize()
    self._register_meshes(payload["models"])

    # A new scene renumbers everything, so the indices change and the client knows nothing about
    # what any resource looks like. Both have to be reset together with the epoch that names them.
    self._epoch += 1
    self._index_of = {name: i for i, name in enumerate(payload["instances"]["names"])}
    self._published = {}
    self._stats = scene.stats(scene_bytes=len(json.dumps(payload)))
    self._scene_payload = {
      **payload,
      "epoch": self._epoch,
      "stats": self._stats,
    }
    return self._scene_payload

  def _state_message(self, states: Dict[str, Dict[str, Any]], full: bool = False) -> Dict[str, Any]:
    """Pack state for the wire.

    A broadcast goes to clients that have been following along, so anything that still looks the way
    it last did is left out. A snapshot goes to a client that knows nothing yet and must carry
    everything, whatever the others have already been told - suppression is about what a given
    client has seen, and a new one has seen none of it.

    A snapshot leaves out `location`, alone among the fields. The scene sent immediately before it
    already places every resource, so repeating that here says nothing new - and because a position
    is unique to one resource, carrying it would give every resource a state of its own and undo
    the sharing the rest of this message depends on. A position still travels the moment it
    changes; it just is not announced twice at the start.
    """
    fresh = {}
    for name, published in states.items():
      _, signature = state_signature(published)
      if not full and self._published.get(name) == signature:
        continue
      self._published[name] = signature
      if not full:
        fresh[name] = published
        continue
      # In a snapshot, a resource with nothing left to say is left out entirely: absent already
      # means default to a client that has just arrived. In a delta it is kept, because there it
      # means "no longer what I last told you".
      without_location = {k: v for k, v in published.items() if k != "location"}
      cleaned, _ = state_signature(without_location)
      if cleaned:
        fresh[name] = without_location
    return pack_state(fresh, self._epoch)

  # What `reference_glb` promises: the file is in the resource's own frame, metres, Z up. Stated
  # once here rather than per resource, which is the point of having a convention.
  REFERENCE_GLB_UNITS = "m"
  REFERENCE_GLB_UP = "Z"

  def _register_meshes(self, models: List[Dict[str, Any]]) -> None:
    """Turn each declared model into a URL the page can fetch, and remember what to serve.

    A resource declares its geometry one of two ways. `reference_glb` is a path relative to
    `models_root`, in a fixed convention, and is what most resources should use. `mesh` is the
    long form, carrying its own absolute path, units, up axis and joint map, for a rigged model or
    one that does not fit the convention.

    Both end up in the same place, because the page only knows one way to draw a model. The page
    cannot read a filesystem path and the file is often far too large to inline, so each is given a
    stable id and served from this viewer; the path itself never reaches the browser.
    """
    for model in models:
      reference = model.pop("reference_glb", None)
      if reference is not None and "mesh" not in model:
        if self.models_root is None:
          logger.warning(
            "%s declares reference_glb=%r but the viewer was given no models_root, "
            "so it is drawn as a box",
            model.get("model") or model.get("type"),
            reference,
          )
        else:
          model["mesh"] = {
            "path": os.path.join(self.models_root, reference),
            "units": self.REFERENCE_GLB_UNITS,
            "up": self.REFERENCE_GLB_UP,
          }

    for model in models:
      mesh = model.get("mesh")
      if not isinstance(mesh, dict) or "path" not in mesh:
        continue
      path = os.path.abspath(os.path.expanduser(str(mesh["path"])))
      if not os.path.isfile(path):
        logger.warning("declared mesh not found, drawing the box instead: %s", path)
        model.pop("mesh")
        continue
      mesh_id = hashlib.sha1(path.encode("utf-8")).hexdigest()[:16] + os.path.splitext(path)[1]
      self._mesh_files[mesh_id] = path
      model["mesh"] = {k: v for k, v in mesh.items() if k != "path"}
      model["mesh"]["url"] = f"mesh/{mesh_id}"

  async def _send_scene_to_all(self) -> None:
    await self._broadcast("scene", self._scene_message(rebuild=True))
    await self._broadcast("state", self._state_message(collect_state(self.root), full=True))

  async def _handler(self, websocket) -> None:
    self._clients.add(websocket)
    await websocket.send(json.dumps(_finite({"event": "scene", "data": self._scene_message()})))
    await websocket.send(
      json.dumps(
        _finite(
          {"event": "state", "data": self._state_message(collect_state(self.root), full=True)}
        )
      )
    )
    try:
      async for _ in websocket:
        pass
    except Exception:
      pass
    finally:
      self._clients.discard(websocket)

  # -- static files ----------------------------------------------------------

  def _start_file_server(self) -> None:
    directory = STATIC_DIR
    ws_port = self.ws_port
    name = self.name
    mesh_files = self._mesh_files

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
        if path.startswith("/mesh/"):
          source = mesh_files.get(path[len("/mesh/") :])
          if source is None:
            self.send_error(404)
            return
          with open(source, "rb") as f:
            body = f.read()
          self.send_response(200)
          self.send_header("Content-type", "model/gltf-binary")
          self.send_header("Content-Length", str(len(body)))
          self.end_headers()
          self.wfile.write(body)
          return
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

    # The websocket first, because the page has to be told which port to call back on and the file
    # server bakes that number into what it serves. Started the other way round, a viewer whose
    # preferred port is already taken serves a page pointing at the viewer that took it, and then
    # quietly shows someone else's facility.
    while True:
      try:
        self._ws_server = await websockets.serve(self._handler, self.host, self.ws_port)
        break
      except OSError:
        self.ws_port += 1

    self._start_file_server()

    url = f"http://{self.host}:{self.fs_port}"
    print(f"viewer on {url}  (websocket {self.ws_port})")
    if self.open_browser:
      webbrowser.open(url)

  async def stop(self) -> None:
    if self._httpd is not None:
      self._httpd.shutdown()
      self._httpd.server_close()
      self._httpd = None
