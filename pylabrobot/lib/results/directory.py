"""Measurement results written to a directory as they arrive: append-only JSON Lines.

- `rows.jsonl`: the rows of `table.get_table`, one JSON object per line.
- `replies.jsonl`: each data reply's payload, as hex, with its run's first read and its page.
- `manifest.jsonl`: a line each time a writer starts on the directory.
- `.lock`: the process id of the one writer at a time.

The only change ever made to bytes already written is removing an incomplete last line (a crash
mid-write) when a writer starts.

Each batch (a read, a page, a grid) is one `os.write` of whole lines into the operating system's
cache, at once: it outlives a crash of the process. `fsync`, against power loss, runs in one
background thread, in the order written. A failed write is logged and stops the writing; the
measurement still returns its results, and the next `start_writing` on the directory raises it.
"""

import json
import logging
import os
import sys
import threading
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timezone
from typing import Any, Dict, Optional, Sequence, Tuple

from pylabrobot.__version__ import __version__
from pylabrobot.resources import Plate

from .table import get_table

logger = logging.getLogger(__name__)

ROWS = "rows.jsonl"
REPLIES = "replies.jsonl"
MANIFEST = "manifest.jsonl"
LOCK = ".lock"
SCHEMA_VERSION = 1

# fsync opens without O_CREAT: a file deleted meanwhile is an error, not a new empty file.
if sys.platform == "win32":  # binary: no newline translation
  _FSYNC_FLAGS = os.O_WRONLY | os.O_APPEND | os.O_BINARY
else:
  _FSYNC_FLAGS = os.O_WRONLY | os.O_APPEND
_APPEND_FLAGS = _FSYNC_FLAGS | os.O_CREAT
# Bytes read at a time from a file's end, to find its last whole line.
_TAIL_CHUNK = 4096

_ENCODER = json.JSONEncoder(separators=(",", ":"))
# One thread: fsyncs run one at a time, in the order the writes were made.
_FSYNC_EXECUTOR = ThreadPoolExecutor(max_workers=1, thread_name_prefix="results-fsync")
# The files open for appending, by directory and name, from `start_writing` to `stop_writing`.
_OPEN_FILES: Dict[Tuple[str, str], int] = {}
# The first failed write or fsync of each directory, until `start_writing` raises it.
_ERRORS: Dict[str, BaseException] = {}
_ERRORS_LOCK = threading.Lock()


# ----------------------------------------
# Errors and the directory
# ----------------------------------------


def _set_error(directory: str, error: BaseException) -> None:
  """Log `error` and keep the first of `directory`, stopping its writing."""
  logger.error("results not written to %s: %s", directory, error, exc_info=error)
  with _ERRORS_LOCK:
    _ERRORS.setdefault(directory, error)


def _has_error(directory: str) -> bool:
  """Whether a write or fsync to `directory` failed since its writing started."""
  with _ERRORS_LOCK:
    return directory in _ERRORS


def _pop_error(directory: str) -> Optional[BaseException]:
  """The failed write or fsync of `directory` not raised yet, cleared; None if none."""
  with _ERRORS_LOCK:
    return _ERRORS.pop(directory, None)


def check_directory(directory: str) -> str:
  """Create `directory` with its parents if missing, check it is writable; its absolute path.

  Raises:
    ValueError: if it cannot be created, is not a directory, or is not writable.
  """
  path = os.path.abspath(directory)
  try:
    os.makedirs(path, exist_ok=True)
  except OSError as error:
    raise ValueError(f"results directory {directory!r} cannot be created: {error}") from error
  if not os.access(path, os.W_OK | os.X_OK):
    raise ValueError(f"results directory {directory!r} is not writable")
  return path


# ----------------------------------------
# Appending
# ----------------------------------------


def _fsync(directory: str, path: str) -> None:
  """Flush `path` to the disk; a failure is kept as `directory`'s error."""
  try:
    fd = os.open(path, _FSYNC_FLAGS)
    try:
      os.fsync(fd)
    finally:
      os.close(fd)
  except OSError as error:
    _set_error(directory, error)


def _open_file(directory: str, name: str) -> int:
  """File `name` of `directory` open for appending, created if missing; open until `stop_writing`.

  Opening a file can cost milliseconds, a write to an open one microseconds.
  """
  fd = _OPEN_FILES.get((directory, name))
  if fd is None:
    fd = _OPEN_FILES[directory, name] = os.open(os.path.join(directory, name), _APPEND_FLAGS, 0o644)
  return fd


def _append(directory: str, name: str, data: bytes) -> None:
  """Append `data` to file `name` of `directory` in one write, and queue its fsync.

  Raises:
    OSError: if the file cannot be opened or written.
  """
  path = os.path.join(directory, name)
  fd = _open_file(directory, name)
  view = memoryview(data)
  while view:  # a regular file takes it all at once, but for a full disk
    view = view[os.write(fd, view) :]
  _FSYNC_EXECUTOR.submit(_fsync, directory, path)


def _close_files(directory: str) -> None:
  """Close the files of `directory` open for appending."""
  for key in [key for key in _OPEN_FILES if key[0] == directory]:
    try:
      os.close(_OPEN_FILES.pop(key))
    except OSError as error:
      _set_error(directory, error)


def _encode_lines(objects: Sequence[Dict[str, Any]]) -> bytes:
  """`objects` as JSON Lines: one compact object per line, each ending in a newline."""
  if not objects:
    return b""
  return ("\n".join(map(_ENCODER.encode, objects)) + "\n").encode()


def _get_utc_now() -> str:
  """Now, ISO 8601 in UTC."""
  return datetime.now(timezone.utc).isoformat()


def append_reply(directory: str, *, read: int, page: int, reply: bytes) -> None:
  """Append a data reply to `replies.jsonl` of `directory`; a failure is logged, not raised.

  Args:
    directory: the absolute path `start_writing` was given.
    read: the first read of the run the reply belongs to.
    page: the reply's place in the run, from 1.
    reply: the reply's payload.
  """
  if _has_error(directory):
    return
  try:
    line = {"read": read, "page": page, "time": _get_utc_now(), "reply": reply.hex()}
    _append(directory, REPLIES, _encode_lines([line]))
  except Exception as error:  # never lose the measurement to its copy on disk
    _set_error(directory, error)


def append_results(
  directory: str,
  results: Sequence[Any],
  *,
  plate: Optional[Plate] = None,
  first_read: int,
  ceiling: Optional[float] = None,
) -> None:
  """Append the rows of `results` to `rows.jsonl` of `directory`; a failure is logged, not raised.

  Args:
    directory: the absolute path `start_writing` was given.
    results, plate, first_read, ceiling: as `table.get_table`.
  """
  if _has_error(directory):
    return
  try:
    rows = get_table(results, plate=plate, first_read=first_read, ceiling=ceiling)
    timestamps: Dict[datetime, str] = {}
    for row in rows:  # results share a few timestamps: each is formatted once
      for key in ("start_timestamp", "end_timestamp"):
        timestamp = row[key]
        text = timestamps.get(timestamp)
        if text is None:
          text = timestamps[timestamp] = timestamp.isoformat()
        row[key] = text
    _append(directory, ROWS, _encode_lines(rows))
  except Exception as error:  # never lose the measurement to its copy on disk
    _set_error(directory, error)


# ----------------------------------------
# The lock
# ----------------------------------------


def _is_process_alive(pid: int) -> bool:
  """Whether process `pid` is running."""
  if sys.platform == "win32":  # os.kill would end it
    import ctypes

    kernel32 = ctypes.windll.kernel32
    handle = kernel32.OpenProcess(0x1000, False, pid)  # PROCESS_QUERY_LIMITED_INFORMATION
    if not handle:
      return kernel32.GetLastError() == 5  # ERROR_ACCESS_DENIED: running, not ours
    code = ctypes.c_ulong()
    kernel32.GetExitCodeProcess(handle, ctypes.byref(code))
    kernel32.CloseHandle(handle)
    return code.value == 259  # STILL_ACTIVE
  try:
    os.kill(pid, 0)
  except ProcessLookupError:
    return False
  except PermissionError:  # running, as another user
    return True
  return True


def _acquire_lock(directory: str) -> None:
  """Create `.lock` of `directory` holding this process id; take over a dead process's lock.

  Raises:
    RuntimeError: if a running process holds it, or it holds no process id.
  """
  path = os.path.join(directory, LOCK)
  for _ in range(2):
    try:
      fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o644)
    except FileExistsError:
      try:
        with open(path, encoding="utf-8") as f:
          text = f.read().strip()
      except FileNotFoundError:  # released meanwhile
        continue
      if not text.isdigit():
        raise RuntimeError(f"{path} holds no process id; delete it if no process writes there")
      if _is_process_alive(int(text)):
        raise RuntimeError(f"results directory {directory} is written by process {text}")
      logger.warning("taking over %s of process %s, which is not running", path, text)
      try:
        os.remove(path)
      except FileNotFoundError:
        pass
      continue
    try:
      os.write(fd, str(os.getpid()).encode())
    finally:
      os.close(fd)
    return
  raise RuntimeError(f"results directory {directory} is being taken by another process")


def _release_lock(directory: str) -> None:
  """Remove `.lock` of `directory` if this process holds it."""
  path = os.path.join(directory, LOCK)
  try:
    with open(path, encoding="utf-8") as f:
      held = f.read().strip() == str(os.getpid())
    if held:
      os.remove(path)
  except OSError as error:
    logger.warning("%s not released: %s", path, error)


# ----------------------------------------
# Starting and stopping
# ----------------------------------------


def _get_last_line(path: str) -> Tuple[Optional[bytes], int, int]:
  """The last whole line of `path`, read from its end, the size of its whole lines, its size.

  The line is None, and the sizes 0, if the file is missing or has no whole line.
  """
  try:
    f = open(path, "rb")
  except FileNotFoundError:
    return None, 0, 0
  with f:
    size = f.seek(0, os.SEEK_END)
    position = size
    tail = b""
    while position > 0:
      step = min(_TAIL_CHUNK, position)
      position -= step
      f.seek(position)
      tail = f.read(step) + tail
      last = tail.rfind(b"\n")
      if last < 0:
        continue
      start = tail.rfind(b"\n", 0, last)
      if start >= 0 or position == 0:
        return tail[start + 1 : last], position + last + 1, size
    return None, 0, size


def _get_whole_last_line(directory: str, name: str) -> Optional[bytes]:
  """The last whole line of file `name`; a cut line after it, left by a crash, is cut off."""
  path = os.path.join(directory, name)
  line, whole, size = _get_last_line(path)
  if whole < size:
    logger.warning("%s ends in a cut line of %d bytes; it is removed", path, size - whole)
    os.truncate(path, whole)
  return line


def start_writing(directory: str, *, device: Dict[str, Optional[str]]) -> Tuple[str, int]:
  """Start writing to `directory`: lock it, append its manifest line, number the next read.

  The directory and its files are created if missing; a cut last line of a file is removed.
  Reads continue the numbering of `rows.jsonl`, found from its last line.

  Args:
    directory: any path; created with its parents if missing.
    device: the device's model, serial number and firmware, as known.

  Returns:
    the directory's absolute path, for the appends, and the next read's number.

  Raises:
    ValueError: if the directory cannot be created or is not writable.
    RuntimeError: if another running process writes to it, or a write to it since the last
      `start_writing` failed (raised once).
    OSError: if its files cannot be read or written.
  """
  path = check_directory(directory)
  error = _pop_error(path)
  if error is not None:
    raise RuntimeError(f"results were not all written to {path}: {error}") from error
  _acquire_lock(path)
  try:
    for name in (REPLIES, MANIFEST):
      _get_whole_last_line(path, name)
    last = _get_whole_last_line(path, ROWS)
    read = 0 if last is None else int(json.loads(last)["read"]) + 1
    manifest = {
      "schema_version": SCHEMA_VERSION,
      "time": _get_utc_now(),
      "pylabrobot_version": __version__,
      "device": device,
    }
    _append(path, MANIFEST, _encode_lines([manifest]))
    for name in (REPLIES, ROWS):  # opened before the measurement, not on its path
      _open_file(path, name)
  except BaseException:
    _close_files(path)
    _release_lock(path)
    raise
  return path, read


def stop_writing(directory: str) -> None:
  """Close `directory`'s files and release its lock; its queued fsyncs still run.

  Args:
    directory: the absolute path `start_writing` returned.
  """
  _close_files(directory)
  _release_lock(directory)


def wait_for_fsync() -> None:
  """Wait until every write queued so far is flushed to the disk."""
  _FSYNC_EXECUTOR.submit(lambda: None).result()
