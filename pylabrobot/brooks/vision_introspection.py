"""Vision-project introspection for the IntelliGuide vision server.

TCS exposes no way to enumerate the tools/processes of the loaded PreciseVision project, so this
reads them out-of-band over the vision server's FTP at setup. Best-effort: every entry point
returns ``None`` rather than raising, so a missing or unreachable FTP simply skips the pre-check
and the device's own ``-4012``/``-4015`` errors remain the runtime backstop.
"""

import ftplib
import io
import logging
from typing import Dict, List, Optional

logger = logging.getLogger(__name__)


def parse_project_member_name(text: str) -> Optional[str]:
  """The authoritative name of a vision ``.tool``/``.process`` file: its INI ``[Name] Value=`` field.

  The filename stem usually matches but is not guaranteed, so prefer the ``Name`` field. Returns
  ``None`` if the file has no ``[Name]`` section.
  """
  lines = text.splitlines()
  for i, line in enumerate(lines):
    if line.strip() == "[Name]":
      for follow in lines[i + 1 : i + 4]:
        stripped = follow.strip()
        if stripped.startswith("Value="):
          return stripped[len("Value=") :] or None
  return None


def assemble_available(files: Dict[str, str]) -> Dict[str, List[str]]:
  """Build ``{"processes": [...], "tools": [...]}`` from ``{filename: file_text}`` for one project.

  Names come from each file's ``[Name]`` field, falling back to the filename stem; non
  ``.process``/``.tool`` files (calibrations, images) are ignored.
  """
  processes: List[str] = []
  tools: List[str] = []
  for filename, text in files.items():
    if filename.endswith(".process"):
      processes.append(parse_project_member_name(text) or filename[: -len(".process")])
    elif filename.endswith(".tool"):
      tools.append(parse_project_member_name(text) or filename[: -len(".tool")])
  return {"processes": sorted(processes), "tools": sorted(tools)}


def enumerate_vision_project(
  host: Optional[str],
  user: Optional[str],
  password: Optional[str],
  project_name: Optional[str],
  *,
  port: int = 21,
  timeout: float = 8.0,
) -> Optional[Dict[str, List[str]]]:
  """List a loaded vision project's processes and tools over the vision server's FTP.

  Returns ``{"processes": [...], "tools": [...]}``, or ``None`` if credentials/target are missing
  or any FTP step fails (unreachable, auth, missing project). Never raises - it is a best-effort
  setup pre-check, with the device's own vision errors as the runtime backstop.

  Args:
    host: the vision server's address (the controller is a different host). ``None`` -> skip.
    user/password: vision-server FTP credentials. ``user`` ``None`` -> skip.
    project_name: the loaded project (from ``System.ProjectName``). ``None`` -> skip.
  """
  if not (host and user and project_name):
    return None
  base = f"/Project Data/{project_name}"
  files: Dict[str, str] = {}
  ftp = ftplib.FTP()
  try:
    ftp.connect(host, port, timeout=timeout)
    ftp.login(user, password or "")
    for entry in ftp.nlst(base):
      name = entry.rsplit("/", 1)[-1]
      if not (name.endswith(".process") or name.endswith(".tool")):
        continue
      buf = io.BytesIO()
      ftp.retrbinary(f"RETR {base}/{name}", buf.write)
      files[name] = buf.getvalue().decode("utf-8", "replace")
  except Exception as exc:  # noqa: BLE001
    logger.debug("vision-project enumeration failed (%s on %s): %s", project_name, host, exc)
    return None
  finally:
    try:
      ftp.close()  # always release the control connection, including on the error paths
    except Exception:  # noqa: BLE001
      pass
  return assemble_available(files)
