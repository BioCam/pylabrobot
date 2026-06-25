"""Persistent client for the PreciseVision engine - the second server behind a camera-gripper arm.

The vision engine runs on a different host from the TCS controller and speaks a credential-free text
property protocol on :1450 (``property get/set <name> [args]``, reply ``0 <value>`` or a negative
code) and pushes JPEG image results on :1500. The OEM GUI holds one connection per port for a whole
session and triggers each frame with ``property set system.cameraacquire <N>``; this driver mirrors
that - ``setup()`` opens and holds both, ``capture_image()`` triggers a frame and reads it off
the held image stream. The connect "handshake" is just informational property reads (no auth).

Engine protocol confirmed from the 2026-06-22 captures (per-frame trigger = ``cameraacquire``, framing
below). Open hardware item: whether a freshly-opened :1500 socket receives the pushed frame the way
the GUI's held-from-connect socket does - hence both connections are held from ``setup()``.
"""

import io
import logging
import re
from typing import Dict, List, Optional, Tuple

from pylabrobot.capabilities.capability import BackendParams
from pylabrobot.device import Driver
from pylabrobot.io.socket import Socket

try:
  import numpy as np
except ImportError:
  np = None  # type: ignore[assignment]

try:
  from PIL import Image as PILImage
except ImportError:
  PILImage = None  # type: ignore[assignment]

logger = logging.getLogger(__name__)

ENGINE_PROPERTY_PORT = 1450  # text command/query protocol
ENGINE_IMAGE_PORT = 1500  # binary stream carrying the pushed "Primary Image [n]" JPEG results

# Image-result framing on :1500 (confirmed live, 2026-06-22): a binary header carrying a LE-uint32
# JPEG length and the result name ("Primary Image [n]"), then the JPEG itself (FFD8...FFD9). The frame
# is located by the JPEG SOI/EOI; the result name in the header bytes before the SOI gives the camera.
# (Within JPEG entropy data every FF is byte-stuffed as FF00, so a bare FFD9 only marks the real EOI.)
_JPEG_SOI = b"\xff\xd8\xff"
_JPEG_EOI = b"\xff\xd9"
_MAX_IMAGE_BYTES = 16 * 1024 * 1024  # safety cap so a malformed reply cannot read forever


def parse_engine_reply(reply: str) -> Optional[str]:
  """The data of a ``0 <value>`` success reply, or ``None`` for a negative error code (e.g. ``-4017``)."""
  code, _, rest = reply.partition(" ")
  return rest if code == "0" else None


def _split_names(value: str) -> List[str]:
  """Split an engine name list on commas and/or whitespace (listtools is space-, listprocesses comma-)."""
  return [name for name in re.split(r"[,\s]+", value.strip()) if name]


def _drain_named_image(buf: bytearray) -> Optional[Tuple[bytes, bytes]]:
  """Pop the next complete ``(header, jpeg)`` image result from a buffer, consuming it.

  ``header`` is the bytes preceding the JPEG (the binary header + the ``Primary Image [n]`` result
  name); ``jpeg`` is ``FFD8…FFD9``. The frame is located by the JPEG SOI/EOI - the engine prefixes a
  binary header rather than a fixed marker. Returns ``None`` while bytes are still arriving.
  """
  soi = buf.find(_JPEG_SOI)
  if soi < 0:
    return None
  eoi = buf.find(_JPEG_EOI, soi)
  if eoi < 0:
    return None
  header = bytes(buf[:soi])
  jpeg = bytes(buf[soi : eoi + 2])
  del buf[: eoi + 2]
  return header, jpeg


def _decode_jpeg(jpeg: bytes) -> "np.ndarray":
  """Decode an engine JPEG frame to an RGB ``numpy`` array (height x width x 3, ``uint8``)."""
  if np is None or PILImage is None:
    raise ImportError(
      "Pillow and numpy are required to decode camera images; install them with "
      '`pip install "PyLabRobot[precise-flex-vision]"`.'
    )
  return np.asarray(PILImage.open(io.BytesIO(jpeg)))


class PreciseVisionDriver(Driver):
  """Persistent client for the PreciseVision engine (property ``:1450`` + image stream ``:1500``).

  Separate from the arm's ``PreciseFlexDriver`` - a different host and protocol. Holds both
  connections open for the session, mirroring the OEM GUI; ``capture_image`` triggers a frame
  with ``cameraacquire`` and reads it off the held image stream.
  """

  def __init__(
    self,
    host: str,
    *,
    property_port: int = ENGINE_PROPERTY_PORT,
    image_port: int = ENGINE_IMAGE_PORT,
    timeout: float = 5.0,
  ) -> None:
    super().__init__()
    self.io_property = Socket(
      human_readable_device_name="PreciseVision engine (property)", host=host, port=property_port
    )
    self.io_image = Socket(
      human_readable_device_name="PreciseVision engine (image)", host=host, port=image_port
    )
    self.timeout = timeout

  async def setup(self, backend_params: Optional[BackendParams] = None) -> None:
    """Open and hold both engine connections (property + image stream)."""
    await self.io_property.setup()
    await self.io_image.setup()
    logger.info(
      "[PreciseVision %s] connected: property=%s image=%s",
      self.io_property._host,
      self.io_property._port,
      self.io_image._port,
    )

  async def stop(self) -> None:
    """Close both engine connections."""
    await self.io_image.stop()
    await self.io_property.stop()

  # -- low-level property protocol (:1450) ---------------------------------

  async def query(self, command: str) -> Optional[str]:
    """Send a ``property ...`` command and return the success value (``None`` on a negative reply)."""
    await self.io_property.write(command.encode("utf-8") + b"\r\n")
    reply = (await self.io_property.readline()).decode("utf-8", "replace").strip()
    return parse_engine_reply(reply)

  async def property_get(self, name: str) -> Optional[str]:
    return await self.query(f"property get {name}")

  async def property_set(self, name: str, value: object) -> Optional[str]:
    return await self.query(f"property set {name} {value}")

  # -- engine session & discovery ------------------------------------------

  async def request_vision_version(self) -> Optional[str]:
    return await self.property_get("system.engineversion")

  async def request_camera_count(self) -> int:
    value = await self.property_get("system.cameracount")
    return int(value) if value is not None and value.isdigit() else 0

  async def request_projects(self) -> List[str]:
    """List all projects on the engine (``system.listprojects``); the active one is request_project_name."""
    value = await self.property_get("system.listprojects")
    return _split_names(value) if value is not None else []

  async def request_project_name(self) -> Optional[str]:
    """Return the active project's name (``system.projectname``)."""
    return await self.property_get("system.projectname")

  async def request_processes(self) -> List[str]:
    """List all process names in the active project (``system.listprocesses``)."""
    value = await self.property_get("system.listprocesses")
    return _split_names(value) if value is not None else []

  async def request_vision_tools(self) -> List[str]:
    """List all tool names in the active project (``system.listtools``)."""
    value = await self.property_get("system.listtools")
    return _split_names(value) if value is not None else []

  async def request_is_licensed(self) -> bool:
    """Return whether the engine reports a valid license (``system.islicensed``)."""
    return (await self.property_get("system.islicensed")) == "True"

  async def enumerate_project(self) -> Optional[Dict[str, List[str]]]:
    """List the loaded project's processes and tools (``system.listprocesses`` / ``listtools``)."""
    processes = await self.property_get("system.listprocesses")
    tools = await self.property_get("system.listtools")
    if processes is None or tools is None:
      return None
    return {
      "processes": sorted(_split_names(processes)),
      "vision_tools": sorted(_split_names(tools)),
    }

  # -- vision tools --------------------------------------------------------

  async def request_vision_tool_property(self, tool: str, property_name: str) -> Optional[str]:
    """Read one tool property value (``property get <tool>.<property>``)."""
    return await self.property_get(f"{tool}.{property_name}")

  async def request_vision_tool_properties(self, tool: str) -> List[str]:
    """List the property names of one tool (``system.toolproperties <tool>``)."""
    value = await self.property_get(f"system.toolproperties {tool}")
    return _split_names(value) if value is not None else []

  async def request_vision_tool_property_info(self, tool: str, property_name: str) -> Optional[str]:
    """Return the type / enum / range metadata for one tool property (``system.toolpropertyinfo``)."""
    return await self.property_get(f"system.toolpropertyinfo {tool} {property_name}")

  async def request_vision_tool_type(self, tool: str) -> Optional[str]:
    """Return the tool's type/class, e.g. ``Acquire`` or ``FiducialLocator`` (``system.tooltype``)."""
    return await self.property_get(f"system.tooltype {tool}")

  async def request_vision_tool_types(self) -> List[str]:
    """List all tool types the engine can instantiate (``system.tooltypes``) - the fixed palette."""
    value = await self.property_get("system.tooltypes")
    return _split_names(value) if value is not None else []

  async def set_vision_tool_property(
    self, tool: str, property_name: str, value: object, *, apply: bool = True
  ) -> None:
    """Write one tool property and, by default, run the tool so the change reaches the device.

    Writes ``<tool>.<property>`` then, when ``apply`` (the default), runs the tool via
    ``run_vision_tool`` so the new value is applied (e.g. an acquire tool pushes it to the camera).
    Pass ``apply=False`` to stage several writes and apply them with one later ``run_vision_tool``.
    """
    await self.property_set(f"{tool}.{property_name}", value)
    if apply:
      await self.run_vision_tool(tool)

  async def run_vision_tool(self, tool: str) -> None:
    """Run a single vision tool (``property set system.runtool <tool>``).

    Executes just this one tool: for an acquire tool it pushes the tool's stored settings down to the
    camera and grabs a frame. This is the lightweight "apply" path - a bare property write only
    stores a value, and running the tool is what makes it take effect on the device.
    """
    await self.property_set("system.runtool", tool)

  # -- camera info ---------------------------------------------------------

  async def request_camera_name(self, camera: int = 1) -> Optional[str]:
    """Return a camera's friendly name, e.g. ``Cam1`` (``system.cameraname <camera>``)."""
    return await self.property_get(f"system.cameraname {camera}")

  async def request_camera_type(self, camera: int = 1) -> Optional[str]:
    """Return a camera's capture backend, e.g. ``DirectShow`` (``system.cameratype <camera>``)."""
    return await self.property_get(f"system.cameratype {camera}")

  async def request_camera_width(self, camera: int = 1) -> Optional[int]:
    """Return a camera's native frame width in px (``system.cameraframewidth <camera>``)."""
    value = await self.property_get(f"system.cameraframewidth {camera}")
    return int(value) if value is not None and value.isdigit() else None

  async def request_camera_height(self, camera: int = 1) -> Optional[int]:
    """Return a camera's native frame height in px (``system.cameraframeheight <camera>``)."""
    value = await self.property_get(f"system.cameraframeheight {camera}")
    return int(value) if value is not None and value.isdigit() else None

  async def request_camera_resolutions(self, camera: int = 1) -> List[str]:
    """Return a camera's supported resolution modes (``system.cameraresolutions <camera>``)."""
    value = await self.property_get(f"system.cameraresolutions {camera}")
    return _split_names(value) if value is not None else []

  # -- image stream (:1500) ------------------------------------------------

  async def capture_image(self, camera: int = 1) -> "np.ndarray":
    """Trigger a frame for ``camera`` and return it as a decoded RGB array off the held image stream.

    Sends ``property set system.cameraacquire <camera>`` on :1450 (the confirmed per-frame trigger),
    then reads the next complete ``Primary Image [camera]`` result off :1500 and decodes its JPEG to an
    RGB ``numpy`` array (height x width x 3, ``uint8``).

    This grabs the camera's current hardware state; it does NOT apply pending acquire-tool settings.
    After changing a setting, run the acquire tool first (``set_vision_tool_property(..., apply=True)`` or
    ``run_vision_tool``) for the change to show up in the returned frame.

    Raises:
      TimeoutError: if no matching frame arrives within ``self.timeout``.
      RuntimeError: if the image stream ends before the requested frame is seen.
    """
    want = f"Primary Image [{camera}]".encode("ascii")
    await self.property_set("system.cameraacquire", camera)
    buf = bytearray()
    while len(buf) < _MAX_IMAGE_BYTES:
      try:
        chunk = await self.io_image.read(65536, timeout=self.timeout)
      except TimeoutError as e:
        raise TimeoutError(
          f"no 'Primary Image [{camera}]' frame arrived within {self.timeout}s"
        ) from e
      if not chunk:
        break
      buf += chunk
      while True:
        framed = _drain_named_image(buf)
        if framed is None:
          break
        header, jpeg = framed
        if want in header:
          return _decode_jpeg(jpeg)
    raise RuntimeError(f"engine image stream ended without a 'Primary Image [{camera}]' frame")
