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

ENGINE_PROPERTY_PORT = 1450


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
