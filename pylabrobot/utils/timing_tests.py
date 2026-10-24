import asyncio
import unittest
from datetime import timedelta
from typing import Any, Dict, List

from pylabrobot.utils.timing import get_current_cycle, run_cycles, sleep_until

NO_CYCLE = {"run_start_timestamp": None, "cycle": None, "due_timestamp": None}


class SleepUntilTests(unittest.IsolatedAsyncioTestCase):
  async def test_returns_at_due_and_not_before(self):
    loop = asyncio.get_running_loop()
    due = loop.time() + 0.05
    await sleep_until(due)
    self.assertGreaterEqual(loop.time(), due)
    self.assertLess(loop.time() - due, 0.1)

  async def test_a_past_due_returns_at_once(self):
    loop = asyncio.get_running_loop()
    start = loop.time()
    await sleep_until(start - 10)
    self.assertLess(loop.time() - start, 0.1)

  async def test_other_tasks_run_while_waiting(self):
    loop = asyncio.get_running_loop()
    ran: List[bool] = []

    async def other():
      ran.append(True)

    task = asyncio.create_task(other())
    await sleep_until(loop.time() + 0.02)
    self.assertEqual(ran, [True])
    await task


class RunCyclesTests(unittest.IsolatedAsyncioTestCase):
  async def test_cycles_start_on_time_whatever_they_take(self):
    loop = asyncio.get_running_loop()
    first = loop.time()
    starts: List[float] = []

    async def cycle_function(cycle: int):
      starts.append(loop.time() - first)
      await asyncio.sleep(0.1)  # half the cycle time

    await run_cycles(cycle_function, cycle_time=0.2, cycles=4)
    for cycle, start in enumerate(starts):
      self.assertGreaterEqual(start, cycle * 0.2)  # never early
      self.assertLess(start, cycle * 0.2 + 0.08)  # not the 0.1 s each cycle takes, added up

  async def test_a_late_cycle_starts_at_once_with_a_warning_and_the_next_ones_keep_their_times(
    self,
  ):
    loop = asyncio.get_running_loop()
    first = loop.time()
    starts: List[float] = []

    async def cycle_function(cycle: int):
      starts.append(loop.time() - first)
      await asyncio.sleep(0.45 if cycle == 1 else 0.01)

    # Cycle 1 (due 0.2 s) ends at 0.65 s, past cycles 2 and 3 (0.4, 0.6 s); cycle 4 is due at 0.8 s.
    with self.assertLogs("pylabrobot.utils.timing", level="WARNING") as logs:
      await run_cycles(cycle_function, cycle_time=0.2, cycles=5)
    self.assertEqual(len(logs.records), 2)
    self.assertIn("cycle 2 of 5 starts", logs.output[0])
    self.assertIn("cycle 3 of 5 starts", logs.output[1])
    self.assertGreaterEqual(starts[2], starts[1] + 0.45)  # at once after cycle 1
    self.assertLess(starts[2], starts[1] + 0.45 + 0.08)
    self.assertGreaterEqual(starts[4], 0.8)  # on its time again
    self.assertLess(starts[4], 0.8 + 0.08)

  async def test_late_skip_leaves_out_a_late_cycle_and_keeps_the_next_ones_times(self):
    loop = asyncio.get_running_loop()
    first = loop.time()
    starts: Dict[int, float] = {}

    async def cycle_function(cycle: int):
      starts[cycle] = loop.time() - first
      await asyncio.sleep(0.45 if cycle == 1 else 0.01)

    # Cycle 1 (due 0.2 s) ends at 0.65 s, past cycles 2 and 3 (0.4, 0.6 s); cycle 4 is due at 0.8 s.
    with self.assertLogs("pylabrobot.utils.timing", level="WARNING") as logs:
      await run_cycles(cycle_function, cycle_time=0.2, cycles=5, late="skip")
    self.assertEqual(list(starts), [0, 1, 4])
    self.assertEqual(len(logs.records), 2)
    self.assertIn("cycle 2 of 5 skipped,", logs.output[0])
    self.assertIn("cycle 3 of 5 skipped,", logs.output[1])
    self.assertGreaterEqual(starts[4], 0.8)
    self.assertLess(starts[4], 0.8 + 0.08)

  async def test_no_warning_on_time(self):
    async def cycle_function(cycle: int):
      pass

    with self.assertNoLogs("pylabrobot.utils.timing", level="WARNING"):
      await run_cycles(cycle_function, cycle_time=0.1, cycles=3)

  async def test_the_current_cycle_while_a_cycle_runs(self):
    seen: List[Dict[str, Any]] = []

    async def cycle_function(cycle: int):
      seen.append(get_current_cycle())

    await run_cycles(cycle_function, cycle_time=0.02, cycles=3)
    self.assertEqual([current["cycle"] for current in seen], [0, 1, 2])
    run_start = seen[0]["run_start_timestamp"]
    self.assertIsNotNone(run_start.tzinfo)
    self.assertEqual(run_start.utcoffset(), timedelta(0))
    for cycle, current in enumerate(seen):
      self.assertEqual(current["run_start_timestamp"], run_start)
      self.assertEqual(current["due_timestamp"], run_start + timedelta(seconds=cycle * 0.02))

  async def test_no_current_cycle_outside_a_run(self):
    self.assertEqual(get_current_cycle(), NO_CYCLE)

    async def cycle_function(cycle: int):
      pass

    await run_cycles(cycle_function, cycle_time=0.01, cycles=2)
    self.assertEqual(get_current_cycle(), NO_CYCLE)

  async def test_an_exception_in_a_cycle_ends_the_run_and_clears_the_current_cycle(self):
    cycles: List[int] = []

    async def cycle_function(cycle: int):
      cycles.append(cycle)
      if cycle == 1:
        raise RuntimeError("stop")

    with self.assertRaises(RuntimeError):
      await run_cycles(cycle_function, cycle_time=0.01, cycles=5)
    self.assertEqual(cycles, [0, 1])
    self.assertEqual(get_current_cycle(), NO_CYCLE)

  async def test_cancelling_ends_the_run_and_clears_the_current_cycle(self):
    async def cycle_function(cycle: int):
      await asyncio.sleep(10)

    task = asyncio.create_task(run_cycles(cycle_function, cycle_time=1, cycles=3))
    await asyncio.sleep(0.01)
    task.cancel()
    with self.assertRaises(asyncio.CancelledError):
      await task
    self.assertEqual(get_current_cycle(), NO_CYCLE)

  async def test_runs_side_by_side_each_see_their_own_cycle(self):
    seen: Dict[str, List[Any]] = {"a": [], "b": []}

    def cycle_function_for(name: str, cycle_time: float):
      async def cycle_function(cycle: int):
        await asyncio.sleep(cycle_time / 2)  # the other run's cycles happen meanwhile
        seen[name].append(get_current_cycle()["cycle"])

      return cycle_function

    await asyncio.gather(
      run_cycles(cycle_function_for("a", 0.02), cycle_time=0.02, cycles=4),
      run_cycles(cycle_function_for("b", 0.03), cycle_time=0.03, cycles=3),
    )
    self.assertEqual(seen, {"a": [0, 1, 2, 3], "b": [0, 1, 2]})

  async def test_a_run_inside_a_cycle_is_the_current_cycle_and_restores_the_outer_one(self):
    seen: List[Any] = []

    async def inner(cycle: int):
      seen.append(("inner", get_current_cycle()["cycle"]))

    async def outer(cycle: int):
      await run_cycles(inner, cycle_time=0.01, cycles=2)
      seen.append(("outer", get_current_cycle()["cycle"]))

    await run_cycles(outer, cycle_time=0.05, cycles=2)
    self.assertEqual(
      seen,
      [("inner", 0), ("inner", 1), ("outer", 0), ("inner", 0), ("inner", 1), ("outer", 1)],
    )

  async def test_invalid_arguments_raise(self):
    async def cycle_function(cycle: int):
      pass

    for cycle_time in (0, -1, float("inf"), float("nan")):
      with self.assertRaisesRegex(ValueError, "cycle_time"):
        await run_cycles(cycle_function, cycle_time=cycle_time, cycles=1)
    for cycles in (0, -1, True):
      with self.assertRaisesRegex(ValueError, "cycles"):
        await run_cycles(cycle_function, cycle_time=1, cycles=cycles)
    late: Any = "catch up"
    with self.assertRaisesRegex(ValueError, "late"):
      await run_cycles(cycle_function, cycle_time=1, cycles=1, late=late)


if __name__ == "__main__":
  unittest.main()
