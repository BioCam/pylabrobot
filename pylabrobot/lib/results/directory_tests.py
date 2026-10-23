"""Results-directory tests: files created and appended to, whole lines, read numbering, the lock."""

import json
import os
import subprocess
import sys
import tempfile
import unittest
from datetime import datetime
from typing import Any, Dict, List
from unittest.mock import patch

from pylabrobot.lib.absorbance.results import AbsorbanceResult
from pylabrobot.lib.results import directory
from pylabrobot.lib.results.directory import (
  LOCK,
  MANIFEST,
  REPLIES,
  ROWS,
  append_reply,
  append_results,
  check_directory,
  start_writing,
  stop_writing,
  wait_for_fsync,
)
from pylabrobot.lib.results.table import COLUMNS

DEVICE: Dict[str, Any] = {
  "model": "CLARIOstarPlus",
  "serial_number": None,
  "firmware_version": None,
}


def read_lines(path: str) -> List[Dict[str, Any]]:
  """The JSON objects of a JSON Lines file."""
  with open(path, encoding="utf-8") as f:
    return [json.loads(line) for line in f.read().splitlines()]


def make_result(wells: int = 3) -> AbsorbanceResult:
  """An absorbance result of `wells` wells of column 1."""
  now = datetime.now()
  data = {f"{'ABCDEFGH'[i]}1": 0.1 * i for i in range(wells)}
  return AbsorbanceResult(
    data=data, wavelength=600, temperature=None, start_timestamp=now, end_timestamp=now
  )


def get_dead_pid() -> int:
  """The id of a process that has ended."""
  process = subprocess.Popen([sys.executable, "-c", "pass"])
  process.wait()
  return process.pid


class DirectoryTests(unittest.TestCase):
  def setUp(self):
    self.temporary = tempfile.TemporaryDirectory()
    self.addCleanup(self.temporary.cleanup)
    self.addCleanup(wait_for_fsync)  # before the files go
    self.root = self.temporary.name

  def write_read(self, path: str, results: List[Any]) -> int:
    """One writer session appending `results`; the first read it numbered."""
    absolute, read = start_writing(path, device=DEVICE)
    append_results(absolute, results, first_read=read)
    stop_writing(absolute)
    return read

  def test_missing_directories_are_created_and_files_appended_to(self):
    path = os.path.join(self.root, "a", "b")
    self.assertEqual(self.write_read(path, [make_result()]), 0)
    self.assertEqual(self.write_read(path, [make_result(), make_result(2)]), 1)
    rows = read_lines(os.path.join(path, ROWS))
    self.assertEqual([row["read"] for row in rows], [0, 0, 0, 1, 1, 1, 2, 2])
    self.assertEqual(list(rows[0]), list(COLUMNS))
    self.assertTrue(rows[0]["start_timestamp"].endswith("+00:00"))
    manifests = read_lines(os.path.join(path, MANIFEST))
    self.assertEqual(len(manifests), 2)
    self.assertEqual(manifests[0]["schema_version"], 1)
    self.assertEqual(manifests[0]["device"], DEVICE)
    self.assertFalse(os.path.exists(os.path.join(path, LOCK)))

  def test_numbering_continues_from_a_last_line_longer_than_a_tail_chunk(self):
    path = os.path.join(self.root, "run")
    os.makedirs(path)
    long_row = {"read": 41, "padding": "x" * (3 * directory._TAIL_CHUNK)}
    with open(os.path.join(path, ROWS), "w", encoding="utf-8") as f:
      f.write(json.dumps({"read": 40}) + "\n" + json.dumps(long_row) + "\n")
    self.assertEqual(self.write_read(path, [make_result()]), 42)

  def test_a_cut_last_line_is_removed_and_whole_lines_follow(self):
    path = os.path.join(self.root, "run")
    self.write_read(path, [make_result()])
    rows_path = os.path.join(path, ROWS)
    with open(rows_path, "a", encoding="utf-8") as f:
      f.write('{"read": 1, "mode": "absorb')  # a crash mid-write
    self.assertEqual(self.write_read(path, [make_result()]), 1)
    with open(rows_path, "rb") as f:
      data = f.read()
    self.assertTrue(data.endswith(b"\n"))
    self.assertEqual([row["read"] for row in read_lines(rows_path)], [0, 0, 0, 1, 1, 1])

  def test_replies_are_appended_as_hex(self):
    path, read = start_writing(os.path.join(self.root, "run"), device=DEVICE)
    append_reply(path, read=read, page=1, reply=b"\x02\x05")
    append_reply(path, read=read, page=2, reply=b"\xff")
    stop_writing(path)
    replies = read_lines(os.path.join(path, REPLIES))
    self.assertEqual(
      [(r["read"], r["page"], r["reply"]) for r in replies], [(0, 1, "0205"), (0, 2, "ff")]
    )

  def test_a_dead_writers_lock_is_taken_over_and_a_live_ones_refused(self):
    path = check_directory(os.path.join(self.root, "run"))
    lock = os.path.join(path, LOCK)
    with open(lock, "w", encoding="utf-8") as f:
      f.write(str(get_dead_pid()))
    with self.assertLogs(directory.logger, "WARNING"):
      self.write_read(path, [make_result()])
    with open(lock, "w", encoding="utf-8") as f:
      f.write(str(os.getpid()))
    with self.assertRaisesRegex(RuntimeError, "is written by process"):
      start_writing(path, device=DEVICE)
    os.remove(lock)

  def test_a_failed_write_is_logged_stops_the_writing_and_is_raised_once_at_the_next_start(self):
    path, read = start_writing(os.path.join(self.root, "run"), device=DEVICE)
    with (
      patch.object(directory.os, "write", side_effect=OSError(28, "No space left on device")),
      self.assertLogs(directory.logger, "ERROR"),
    ):
      append_results(path, [make_result()], first_read=read)
    append_results(path, [make_result()], first_read=read + 1)  # stopped: nothing written
    stop_writing(path)
    self.assertEqual(os.path.getsize(os.path.join(path, ROWS)), 0)
    with self.assertRaisesRegex(RuntimeError, "not all written"):
      start_writing(path, device=DEVICE)
    self.assertEqual(self.write_read(path, [make_result()]), 0)

  def test_an_unwritable_directory_is_refused(self):
    blocker = os.path.join(self.root, "file")
    with open(blocker, "w", encoding="utf-8"):
      pass
    with self.assertRaises(ValueError):
      check_directory(os.path.join(blocker, "run"))

  def test_writes_are_flushed_to_the_disk_in_the_background(self):
    path, read = start_writing(os.path.join(self.root, "run"), device=DEVICE)
    wait_for_fsync()  # the manifest's
    with patch.object(directory.os, "fsync") as fsync:
      append_results(path, [make_result()], first_read=read)
      wait_for_fsync()
    stop_writing(path)
    fsync.assert_called_once()

  def test_a_file_deleted_before_its_fsync_is_an_error_not_a_new_empty_file(self):
    path = check_directory(os.path.join(self.root, "run"))
    with self.assertLogs(directory.logger, "ERROR"):
      directory._fsync(path, os.path.join(path, ROWS))
    self.assertFalse(os.path.exists(os.path.join(path, ROWS)))
    with self.assertRaisesRegex(RuntimeError, "not all written"):
      start_writing(path, device=DEVICE)


if __name__ == "__main__":
  unittest.main()
