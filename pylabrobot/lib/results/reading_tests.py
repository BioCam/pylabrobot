import builtins
import datetime
import importlib.util
import json
import os
import subprocess
import sys
import tempfile
import textwrap
import threading
import time
import unittest
from typing import Any, Dict, List
from unittest import mock

from pylabrobot.lib.results.reading import _COLUMN_TYPES, follow_rows, get_dataframe, load_rows

HAS_PANDAS = importlib.util.find_spec("pandas") is not None


def make_row(read: int, index: int) -> Dict[str, Any]:
  """A row of the rows.jsonl format, its well and value derived from `index`."""
  return {
    "read": read,
    "mode": "fluorescence",
    "start_timestamp": "2000-01-01T00:00:00+00:00",
    "end_timestamp": "2000-01-01T00:00:01.500000+01:00",
    "well": "ABCDEFGH"[index % 8] + str(index // 8 + 1),
    "row": "ABCDEFGH"[index % 8],
    "column": index // 8 + 1,
    "row_index": index % 8,
    "column_index": index // 8,
    "wavelength": None,
    "excitation_wavelength": 485.0,
    "excitation_bandwidth": 15.0,
    "emission_wavelength": 528.0,
    "emission_bandwidth": 20.0,
    "scanned": None,
    "point": None,
    "x": None,
    "y": None,
    "focal_height": 8.5,
    "optic_position": "top",
    "gain": 1000,
    "temperature": 25.1,
    "quantity": "counts",
    "value": float(index),
    "saturated": False,
  }


def encode_rows(rows: List[Dict[str, Any]]) -> bytes:
  return "".join(json.dumps(row) + "\n" for row in rows).encode()


class LoadRowsTests(unittest.TestCase):
  def setUp(self):
    self.directory = tempfile.mkdtemp()
    self.path = os.path.join(self.directory, "rows.jsonl")

  def test_missing_file_gives_no_rows(self):
    self.assertEqual(load_rows(self.directory), [])
    self.assertEqual(load_rows(os.path.join(self.directory, "not_started")), [])

  def test_cut_last_line_is_skipped(self):
    rows = [make_row(0, index) for index in range(3)]
    with open(self.path, "wb") as file:
      file.write(encode_rows(rows) + json.dumps(make_row(0, 3)).encode()[:40])
    self.assertEqual(load_rows(self.directory), rows)

  def test_only_a_cut_line_gives_no_rows(self):
    with open(self.path, "wb") as file:
      file.write(b'{"read": 0, "mo')
    self.assertEqual(load_rows(self.directory), [])

  def test_malformed_complete_line_raises_with_its_line_number(self):
    with open(self.path, "wb") as file:
      file.write(encode_rows([make_row(0, 0)]) + b'{"read": 0,\n' + encode_rows([make_row(0, 1)]))
    with self.assertRaisesRegex(ValueError, "line 2"):
      load_rows(self.directory)

  def test_lines_that_only_form_json_together_raise(self):
    with open(self.path, "wb") as file:
      file.write(b'{"value": [1,\n2]}\n')
    with self.assertRaisesRegex(ValueError, "line 1"):
      load_rows(self.directory)

  def test_non_object_line_raises(self):
    with open(self.path, "wb") as file:
      file.write(encode_rows([make_row(0, 0)]) + b"[1, 2]\n")
    with self.assertRaisesRegex(ValueError, "line 2 is not a JSON object"):
      load_rows(self.directory)


class FollowRowsTests(unittest.TestCase):
  def setUp(self):
    self.directory = tempfile.mkdtemp()
    self.path = os.path.join(self.directory, "rows.jsonl")

  def append(self, data: bytes):
    fd = os.open(self.path, os.O_WRONLY | os.O_APPEND | os.O_CREAT, 0o644)
    os.write(fd, data)
    os.close(fd)

  def test_rows_from_a_separate_writer_process_arrive_once_and_in_order(self):
    pages, rows_per_page = 6, 50
    expected = [make_row(index // rows_per_page, index) for index in range(pages * rows_per_page)]
    page_ends = [len(encode_rows(expected[: (page + 1) * rows_per_page])) for page in range(pages)]
    page_ends.insert(2, page_ends[1] + 1234)  # cuts the third page inside a line
    source = os.path.join(self.directory, "source")
    with open(source, "wb") as file:
      file.write(encode_rows(expected))
    writer = textwrap.dedent(
      f"""
      import os, time
      with open({source!r}, "rb") as file:
        data = file.read()
      start = 0
      for end in {page_ends!r}:
        fd = os.open({self.path!r}, os.O_WRONLY | os.O_APPEND | os.O_CREAT, 0o644)
        os.write(fd, data[start:end])
        os.close(fd)
        start = end
        time.sleep(0.03)
      """
    )
    process = subprocess.Popen([sys.executable, "-c", writer])
    try:
      followed: List[Dict[str, Any]] = []
      for batch in follow_rows(self.directory, poll_interval=0.005, idle_timeout=10):
        followed.extend(batch)
        if len(followed) >= pages * rows_per_page:
          break
    finally:
      self.assertEqual(process.wait(timeout=10), 0)
    self.assertEqual(followed, expected)
    self.assertEqual(load_rows(self.directory), expected)

  def test_partial_line_waits_for_its_newline(self):
    data = encode_rows([make_row(0, 0), make_row(0, 1)])
    self.append(data[:-10])

    def finish_line(seconds: float):
      self.append(data[-10:])

    batches = follow_rows(self.directory, poll_interval=0, sleep=finish_line)
    self.assertEqual(next(batches), [make_row(0, 0)])
    self.assertEqual(next(batches), [make_row(0, 1)])

  def test_file_created_after_following_starts(self):
    def create_file(seconds: float):
      self.append(encode_rows([make_row(0, 0)]))

    batches = follow_rows(self.directory, poll_interval=0, sleep=create_file)
    self.assertEqual(next(batches), [make_row(0, 0)])

  def test_idle_timeout_stops_following(self):
    self.append(encode_rows([make_row(0, 0)]))
    batches = list(follow_rows(self.directory, poll_interval=0.001, idle_timeout=0.02))
    self.assertEqual(batches, [[make_row(0, 0)]])

  def test_idle_polls_only_stat(self):
    self.append(encode_rows([make_row(0, 0)]))
    idle_polls = []

    def append_after_five_polls(seconds: float):
      idle_polls.append(seconds)
      if len(idle_polls) == 5:
        self.append(encode_rows([make_row(0, 1)]))

    batches = follow_rows(self.directory, poll_interval=0, sleep=append_after_five_polls)
    self.assertEqual(next(batches), [make_row(0, 0)])
    with (
      mock.patch.object(builtins, "open", wraps=builtins.open) as opened,
      mock.patch.object(os, "stat", wraps=os.stat) as stated,
    ):
      self.assertEqual(next(batches), [make_row(0, 1)])
    self.assertEqual(opened.call_count, 1)
    self.assertEqual(stated.call_count, 6)

  def test_shrunk_file_raises(self):
    self.append(encode_rows([make_row(0, 0), make_row(0, 1)]))
    batches = follow_rows(self.directory, poll_interval=0)
    next(batches)
    with open(self.path, "wb") as file:
      file.write(encode_rows([make_row(0, 0)]))
    with self.assertRaisesRegex(ValueError, "no longer append-only"):
      next(batches)

  def test_cut_line_removed_by_a_writer_starting_again(self):
    whole = encode_rows([make_row(0, 0)])
    self.append(whole + encode_rows([make_row(0, 1)])[:50])
    batches = follow_rows(self.directory, poll_interval=0)
    self.assertEqual(next(batches), [make_row(0, 0)])
    os.truncate(self.path, len(whole))
    self.append(encode_rows([make_row(1, 2)]))
    self.assertEqual(next(batches), [make_row(1, 2)])

  def test_removed_file_raises(self):
    self.append(encode_rows([make_row(0, 0)]))
    batches = follow_rows(self.directory, poll_interval=0)
    next(batches)
    os.remove(self.path)
    with self.assertRaisesRegex(ValueError, "no longer append-only"):
      next(batches)

  def test_replaced_file_raises(self):
    self.append(encode_rows([make_row(0, 0)]))
    batches = follow_rows(self.directory, poll_interval=0)
    next(batches)
    replacement = os.path.join(self.directory, "replacement")
    with open(replacement, "wb") as file:
      file.write(encode_rows([make_row(0, 0), make_row(0, 1)]))
    os.replace(replacement, self.path)
    with self.assertRaisesRegex(ValueError, "no longer append-only"):
      next(batches)

  def test_malformed_line_raises_with_its_line_number(self):
    self.append(encode_rows([make_row(0, 0), make_row(0, 1)]))
    batches = follow_rows(self.directory, poll_interval=0)
    next(batches)
    self.append(b"not json\n")
    with self.assertRaisesRegex(ValueError, "line 3"):
      next(batches)


@unittest.skipUnless(HAS_PANDAS, "pandas is not installed")
class GetDataframeTests(unittest.TestCase):
  def test_column_types(self):
    import pandas as pd  # type: ignore[import-not-found,import-untyped]

    absorbance = dict(make_row(1, 0), mode="absorbance", wavelength=600.0, gain=None)
    absorbance.update(excitation_wavelength=None, quantity="optical_density", saturated=True)
    frame = get_dataframe([make_row(0, 0), absorbance])

    self.assertEqual(str(frame["start_timestamp"].dt.tz), "UTC")
    self.assertEqual(frame["end_timestamp"][0], pd.Timestamp("1999-12-31T23:00:01.5", tz="UTC"))
    for column in ("read", "gain", "point", "column", "row_index", "column_index"):
      self.assertEqual(str(frame[column].dtype), "Int64", column)
    self.assertTrue(pd.isna(frame["gain"][1]))
    self.assertEqual(frame["saturated"].dtype, bool)
    self.assertEqual(frame["saturated"].tolist(), [False, True])
    for column in ("mode", "well", "row", "scanned", "optic_position", "quantity"):
      self.assertIsInstance(frame[column].dtype, pd.StringDtype, column)
    self.assertEqual(frame["wavelength"].dtype, float)

  def test_directory_and_no_rows(self):
    directory = tempfile.mkdtemp()
    frame = get_dataframe(directory)
    self.assertEqual(len(frame), 0)
    self.assertIn("value", frame.columns)
    with open(os.path.join(directory, "rows.jsonl"), "wb") as file:
      file.write(encode_rows([make_row(0, 0)]))
    self.assertEqual(get_dataframe(directory)["well"].tolist(), ["A1"])


class WriterIntegrationTests(unittest.TestCase):
  def test_follow_what_the_writer_appends(self):
    from pylabrobot.lib.absorbance.results import AbsorbanceResult
    from pylabrobot.lib.results import directory as results_directory
    from pylabrobot.lib.results.table import COLUMNS, get_table

    self.assertEqual(tuple(_COLUMN_TYPES), COLUMNS)
    directory = tempfile.mkdtemp()
    results = [
      AbsorbanceResult(
        data={"A1": 0.1 * read, "B1": 0.2 * read},
        wavelength=600,
        temperature=None,
        start_timestamp=datetime.datetime(2000, 1, 1, read, tzinfo=datetime.timezone.utc),
        end_timestamp=datetime.datetime(2000, 1, 1, read, 1, tzinfo=datetime.timezone.utc),
      )
      for read in range(4)
    ]
    with open(os.path.join(directory, "rows.jsonl"), "wb") as file:
      file.write(b'{"read": 0, "mode"')  # left by a writer that crashed

    def write():
      path, first_read = results_directory.start_writing(directory, device={})
      for read, result in enumerate(results, first_read):
        results_directory.append_results(path, [result], first_read=read)
        time.sleep(0.02)
      results_directory.stop_writing(path)

    writer = threading.Thread(target=write)

    def start_writer_once_the_cut_line_is_seen(seconds: float):
      if writer.ident is None:
        writer.start()
      time.sleep(seconds)

    followed: List[Dict[str, Any]] = []
    for batch in follow_rows(
      directory, poll_interval=0.005, idle_timeout=5, sleep=start_writer_once_the_cut_line_is_seen
    ):
      followed.extend(batch)
      if len(followed) >= 8:
        break
    writer.join()
    expected = get_table(results)
    for row in expected:
      row.update(
        start_timestamp=row["start_timestamp"].isoformat(),
        end_timestamp=row["end_timestamp"].isoformat(),
      )
    self.assertEqual(followed, expected)


class GetDataframeWithoutPandasTests(unittest.TestCase):
  def test_install_hint(self):
    with mock.patch.dict(sys.modules, {"pandas": None}):
      with self.assertRaisesRegex(ImportError, "pip install pandas"):
        get_dataframe([])


if __name__ == "__main__":
  unittest.main()
