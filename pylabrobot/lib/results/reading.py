"""Reading a measurement results directory, also while its writer appends to it.

Readers never lock and never write: the directory's one writer is never slowed down.
"""

import json
import os
import time
from typing import Any, Callable, Dict, Iterator, List, Optional, Sequence, Tuple, Union

_ROWS = "rows.jsonl"  # as `directory.ROWS`, without importing the writer and its dependencies

_COLUMN_TYPES: Dict[str, str] = {
  "read": "Int64",
  "mode": "string",
  "start_timestamp": "datetime",
  "end_timestamp": "datetime",
  "well": "string",
  "row": "string",
  "column": "Int64",
  "row_index": "Int64",
  "column_index": "Int64",
  "wavelength": "float64",
  "excitation_wavelength": "float64",
  "excitation_bandwidth": "float64",
  "emission_wavelength": "float64",
  "emission_bandwidth": "float64",
  "scanned": "string",
  "point": "Int64",
  "x": "float64",
  "y": "float64",
  "focal_height": "float64",
  "optic_position": "string",
  "gain": "Int64",
  "temperature": "float64",
  "quantity": "string",
  "value": "float64",
  "saturated": "bool",
}


def _parse_lines(lines: Sequence[bytes], first_line_number: int) -> List[Dict[str, Any]]:
  """Parse complete JSON Lines lines into rows.

  Args:
    lines: complete lines, without their newline.
    first_line_number: the 1-based line number of `lines[0]` in the file, for errors.
  """
  try:
    rows: List[Dict[str, Any]] = json.loads(b"[" + b",".join(lines) + b"]")
    if len(rows) == len(lines) and all(isinstance(row, dict) for row in rows):
      return rows
  except ValueError:
    pass
  rows = []
  for line_number, line in enumerate(lines, start=first_line_number):
    try:
      row = json.loads(line)
    except ValueError as error:
      raise ValueError(f"{_ROWS} line {line_number} is not valid JSON: {error}") from None
    if not isinstance(row, dict):
      raise ValueError(f"{_ROWS} line {line_number} is not a JSON object")
    rows.append(row)
  return rows


def load_rows(directory: Union[str, os.PathLike]) -> List[Dict[str, Any]]:
  """Load every complete row of a results directory's `rows.jsonl`.

  A cut last line (one without its newline, being written or left by a crash) is skipped. A missing
  file gives no rows. Standard library only.

  Args:
    directory: the results directory.

  Raises:
    ValueError: a complete line is not a JSON object; the message names its line number.
  """
  try:
    with open(os.path.join(directory, _ROWS), "rb") as file:
      data = file.read()
  except FileNotFoundError:
    return []
  whole = data[: data.rfind(b"\n") + 1]
  if not whole:
    return []
  return _parse_lines(whole[:-1].split(b"\n"), first_line_number=1)


def follow_rows(
  directory: Union[str, os.PathLike],
  *,
  poll_interval: float = 0.5,
  idle_timeout: Optional[float] = None,
  sleep: Callable[[float], Any] = time.sleep,
) -> Iterator[List[Dict[str, Any]]]:
  """Yield each batch of new complete rows as the writer appends them to `rows.jsonl`.

  Starts at the beginning of the file, so the first batch holds every row written so far. Reads
  only from the end of the last whole line; a poll without change costs one `os.stat`. A line
  without its newline waits for it; a writer starting again may cut it off. The file may not exist
  yet.

  Args:
    directory: the results directory.
    poll_interval: seconds between polls.
    idle_timeout: stop once polls have seen no change for this many seconds; None follows forever.
    sleep: called with `poll_interval` between polls, e.g. `matplotlib.pyplot.pause` to keep a
      figure responsive.

  Raises:
    ValueError: a complete line is not a JSON object, or whole lines already yielded were removed,
      or the file was replaced.
  """
  path = os.path.join(directory, _ROWS)
  line_start = 0  # the first byte after the last whole line
  lines_read = 0
  seen: Optional[Tuple[int, int]] = None  # size and modification time when last read
  inode: Optional[int] = None
  last_change = time.monotonic()
  while True:
    try:
      status: Optional[os.stat_result] = os.stat(path)
    except FileNotFoundError:
      status = None
    if status is None and line_start > 0:
      raise ValueError(f"{path} was removed: it is no longer append-only")
    if status is not None and (status.st_size, status.st_mtime_ns) != seen:
      if status.st_size < line_start or (inode is not None and status.st_ino != inode):
        raise ValueError(f"{path} lost whole lines or was replaced: it is no longer append-only")
      inode = status.st_ino
      seen = (status.st_size, status.st_mtime_ns)
      with open(path, "rb") as file:
        file.seek(line_start)
        data = file.read()
      last_change = time.monotonic()
      end = data.rfind(b"\n")
      if end >= 0:
        lines = data[:end].split(b"\n")
        rows = _parse_lines(lines, first_line_number=lines_read + 1)
        line_start += end + 1
        lines_read += len(lines)
        yield rows
        last_change = time.monotonic()
        continue
    elif idle_timeout is not None and time.monotonic() - last_change >= idle_timeout:
      return
    sleep(poll_interval)


def get_dataframe(rows: Union[str, os.PathLike, Sequence[Dict[str, Any]]]) -> Any:
  """Get rows as a pandas DataFrame with the rows' column types.

  Timestamps are UTC datetimes, integer columns pandas' nullable `Int64`, text columns `string`.
  Every column of the format is present, also for no rows; other columns follow unchanged.

  Args:
    rows: a results directory (loaded with `load_rows`), or rows already loaded.
  """
  try:
    import pandas as pd  # type: ignore[import-not-found,import-untyped]
  except ImportError as error:
    raise ImportError("get_dataframe needs pandas; install it with `pip install pandas`") from error
  if isinstance(rows, (str, os.PathLike)):
    rows = load_rows(rows)
  frame = pd.DataFrame(list(rows))
  extra_columns = [column for column in frame.columns if column not in _COLUMN_TYPES]
  frame = frame.reindex(columns=list(_COLUMN_TYPES) + extra_columns)
  for column, column_type in _COLUMN_TYPES.items():
    if column_type == "datetime":
      frame[column] = pd.to_datetime(frame[column], utc=True, format="ISO8601")
    elif column_type == "bool" and frame[column].hasnans:
      frame[column] = frame[column].astype("boolean")
    else:
      frame[column] = frame[column].astype(column_type)
  return frame
