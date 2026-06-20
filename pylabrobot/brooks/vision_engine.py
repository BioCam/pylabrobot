"""Password-free client for the PreciseVision engine property protocol (default TCP port 1450).

The vision engine on the vision-server host speaks a plain-text line protocol - ``property get/set
<tool>.<property> [args]``, reply ``0 <value>`` (a negative code + message on error) - that needs **no
credentials**, unlike the FTP path. It enumerates the loaded project (``system.listprocesses`` /
``system.listtools``) and can read camera/calibration/tool data the controller TCS does not expose.

Best-effort, mirroring ``vision_introspection``: every entry point returns ``None`` rather than raising,
so a missing or unreachable engine simply skips the pre-check and the device's own ``-4012``/``-4015``
vision errors remain the runtime backstop. Distinct from the FTP enumeration in that it carries no
credentials - prefer it, and fall back to FTP only where the engine port is not reachable.
"""

import logging
import re
import socket
from typing import Dict, List, Optional

logger = logging.getLogger(__name__)

ENGINE_PROPERTY_PORT = 1450  # text command/query protocol
ENGINE_IMAGE_PORT = 1500  # binary stream carrying the pushed "Primary Image [n]" JPEG results

# Engine result framing for a pushed image (from the 2026-06-19 captures): a 3-byte marker, a
# header (carrying a little-endian uint32 JPEG length) and the result name (e.g.
# "Primary Image [1]"), then the JPEG bytes. The images flow on ENGINE_IMAGE_PORT; the command
# port only carries the cameraacquire trigger and its reply.
_IMAGE_RESULT_MARKER = b"\x10\x02\x01"
_JPEG_SOI = b"\xff\xd8\xff"
_JPEG_EOI = b"\xff\xd9"
_MAX_IMAGE_BYTES = 16 * 1024 * 1024  # safety cap so a malformed reply cannot read forever


def _query(host: str, port: int, timeout: float, commands: List[str]) -> List[str]:
  """Open one connection, send each command (CRLF-terminated), return one reply line per command."""
  replies: List[str] = []
  sock = socket.create_connection((host, port), timeout=timeout)
  try:
    sock.settimeout(timeout)
    stream = sock.makefile("rwb")
    try:
      for command in commands:
        stream.write((command + "\r\n").encode("utf-8"))
        stream.flush()
        replies.append(stream.readline().decode("utf-8", "replace").strip())
    finally:
      stream.close()
  finally:
    sock.close()
  return replies


def parse_engine_reply(reply: str) -> Optional[str]:
  """The data of a ``0 <value>`` success reply, or ``None`` for a negative error code (e.g. ``-4017``)."""
  code, _, rest = reply.partition(" ")
  return rest if code == "0" else None


def _split_names(value: str) -> List[str]:
  """Split an engine name list on commas and/or whitespace.

  ``system.listtools`` is space-separated and ``system.listprocesses`` comma-separated, so accept both.
  """
  return [name for name in re.split(r"[,\s]+", value.strip()) if name]


def enumerate_vision_project_via_engine(
  host: Optional[str], *, port: int = ENGINE_PROPERTY_PORT, timeout: float = 5.0
) -> Optional[Dict[str, List[str]]]:
  """List the loaded project's processes and tools over the engine property protocol - no credentials.

  Returns ``{"processes": [...], "tools": [...]}`` (the same shape as the FTP enumeration), or ``None``
  if the host is missing/unreachable or the engine rejects the queries. Never raises.

  Args:
    host: the vision-engine host (a different host from the controller). ``None`` -> skip.
    port: the engine property-protocol port (default 1450).
    timeout: per-connection socket timeout in seconds.
  """
  if not host:
    return None
  try:
    processes_reply, tools_reply = _query(
      host,
      port,
      timeout,
      ["property get system.listprocesses", "property get system.listtools"],
    )
  except Exception as exc:  # noqa: BLE001
    logger.debug("engine enumeration failed (%s:%s): %s", host, port, exc)
    return None
  processes = parse_engine_reply(processes_reply)
  tools = parse_engine_reply(tools_reply)
  if processes is None or tools is None:
    return None
  return {"processes": sorted(_split_names(processes)), "tools": sorted(_split_names(tools))}


def parse_camera_image_result(buf: bytes) -> Optional[bytes]:
  """Extract the JPEG from an engine image-result buffer, or ``None`` if not yet complete.

  The result is framed as ``\\x10\\x02\\x01 <len: LE u32> <name> <JPEG>`` (e.g. name
  ``"Primary Image [1]"``). The length is the JPEG byte count; trust it when it lands exactly on
  the ``FFD9`` end-of-image, otherwise fall back to scanning ``FFD8..FFD9``. Returns the complete
  JPEG (``FFD8…FFD9``) or ``None`` while bytes are still arriving / the marker is absent.
  """
  marker = buf.find(_IMAGE_RESULT_MARKER)
  if marker < 0 or marker + 7 > len(buf):
    return None
  declared_len = int.from_bytes(buf[marker + 3 : marker + 7], "little")
  soi = buf.find(_JPEG_SOI, marker + 7)
  if soi < 0:
    return None
  # Preferred: the declared length, when it terminates on the JPEG EOI.
  if (
    soi + declared_len <= len(buf) and buf[soi + declared_len - 2 : soi + declared_len] == _JPEG_EOI
  ):
    return buf[soi : soi + declared_len]
  # Fallback: scan for the EOI (covers a length that excludes/includes the name differently).
  eoi = buf.find(_JPEG_EOI, soi)
  return buf[soi : eoi + 2] if eoi > 0 else None


def _drain_named_image(buf: bytearray) -> Optional[tuple]:
  """Pop the next complete ``(header, jpeg)`` image result from a buffer, consuming it.

  ``header`` is the marker-to-SOI bytes (it carries the ``Primary Image [n]`` result name);
  ``jpeg`` is ``FFD8…FFD9``. Returns ``None`` while bytes are still arriving.
  """
  marker = buf.find(_IMAGE_RESULT_MARKER)
  if marker < 0:
    return None
  soi = buf.find(_JPEG_SOI, marker)
  if soi < 0:
    return None
  eoi = buf.find(_JPEG_EOI, soi)
  if eoi < 0:
    return None
  header = bytes(buf[marker:soi])
  jpeg = bytes(buf[soi : eoi + 2])
  del buf[: eoi + 2]
  return header, jpeg


def _trigger_acquire(host: str, camera: int, port: int, timeout: float) -> None:
  """Best-effort ``cameraacquire`` on the command port to push a fresh frame (ignores failure)."""
  try:
    sock = socket.create_connection((host, port), timeout=timeout)
    try:
      sock.settimeout(timeout)
      sock.sendall(f"property set system.cameraacquire {camera}\r\n".encode("utf-8"))
      sock.recv(256)  # drain the "0"/ok reply
    finally:
      sock.close()
  except Exception as exc:  # noqa: BLE001
    logger.debug("cameraacquire trigger failed (%s:%s cam %s): %s", host, port, camera, exc)


def request_camera_image_via_engine(
  host: Optional[str],
  camera: int = 1,
  *,
  image_port: int = ENGINE_IMAGE_PORT,
  command_port: int = ENGINE_PROPERTY_PORT,
  timeout: float = 5.0,
  trigger: bool = True,
) -> Optional[bytes]:
  """Fetch one JPEG frame for ``camera`` from the engine image stream - **no credentials**.

  The engine pushes named ``Primary Image [n]`` JPEG results on the image stream
  (``image_port`` 1500); the text command port (1450) carries only the ``cameraacquire`` trigger
  and its reply. Connects to the image port, optionally triggers a fresh capture with
  ``property set system.cameraacquire <camera>`` on the command port, and returns the JPEG bytes
  for the matching camera (full 2592x1944; ``camera`` 1 = front, 2 = downward). Decode with
  PIL/cv2/numpy at the call site.

  Best-effort, mirroring the other engine helpers: returns ``None`` if the host is
  missing/unreachable or no matching frame arrives - never raises.

  Protocol derived from the 2026-06-19 captures; needs live confirmation that the stream flows on
  a bare connection (the GDS client may first enable the live feed) before being relied upon.
  """
  if not host:
    return None
  want = f"Primary Image [{camera}]".encode("ascii")
  try:
    sock = socket.create_connection((host, image_port), timeout=timeout)
    try:
      sock.settimeout(timeout)
      if trigger:
        _trigger_acquire(host, camera, command_port, timeout)
      buf = bytearray()
      while len(buf) < _MAX_IMAGE_BYTES:
        chunk = sock.recv(65536)
        if not chunk:
          break
        buf += chunk
        while True:
          framed = _drain_named_image(buf)
          if framed is None:
            break
          header, jpeg = framed
          if want in header:
            return jpeg
    finally:
      sock.close()
  except Exception as exc:  # noqa: BLE001
    logger.debug("camera image fetch failed (%s:%s cam %s): %s", host, image_port, camera, exc)
  return None
