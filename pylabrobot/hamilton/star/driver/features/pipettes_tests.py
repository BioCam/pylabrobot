import unittest
from typing import Any, List, Optional, Tuple

from pylabrobot.hamilton.protocol.text.framing import assemble_command
from pylabrobot.hamilton.star.driver.features.pipettes import Pipettes
from pylabrobot.hamilton.star.driver.simulator import STARSimulationDriver
from pylabrobot.resources.hamilton import STARDeck


async def channels(width: float, positions: List[float]) -> Tuple[Pipettes, List[str]]:
  """The channels of a simulated machine, of one width and at known Y positions.

  Both are what the tests vary: the width decides the minimum spacing a pair must keep, and the
  positions are what the machine answers `C0 RY` with. Everything else is the driver's own.

  Args:
    width: what every channel reports its width to be, in mm.
    positions: where each channel is along Y, in mm, back to front.

  Returns:
    The feature, and the list its commands are recorded in.
  """
  driver = STARSimulationDriver(deck=STARDeck())
  await driver.setup()
  pipettes = driver.pipettes
  assert pipettes is not None

  for channel in pipettes.configuration.channels:
    channel.width = width

  sent: List[str] = []
  answer = driver.send_command

  async def recorded(
    module: str,
    command: str,
    fmt: Optional[Any] = None,
    subsystem: Optional[str] = None,
    **kwargs: Any,
  ):
    # `fmt` and `subsystem` are the driver's own, not firmware parameters: taken exactly as
    # `send_command` takes them, so they never reach the assembler.
    sent.append(assemble_command(module=module, command=command, id_=None, **kwargs))
    return await answer(module=module, command=command, fmt=fmt, subsystem=subsystem, **kwargs)

  async def reported_positions() -> List[float]:
    return list(positions)

  driver.send_command = recorded  # type: ignore[assignment]
  # The simulated channels answer this from their own model rather than from the wire, so the
  # starting positions are set here, as legacy sets them on its backend.
  pipettes.request_y_positions = reported_positions  # type: ignore[assignment]
  return pipettes, sent


def jy(yp: str) -> str:
  """The Y positioning command carrying `yp`."""
  return assemble_command(module="C0", command="JY", id_=None, yp=yp)


# The two extremes of 160 distinct `C0 JY` payloads recorded across three years of runs: the
# tightest adjacent gap ever commanded, and the frontmost a channel has ever been sent. Both sit
# exactly on a limit the driver enforces, and nothing recorded goes past either.
TIGHTEST_GAP = [529.8, 520.8, 511.8, 502.8, 493.8, 484.8, 459.0, 338.0]
FRONTMOST = [130.0, 100.0, 91.0, 82.0, 73.0, 64.0, 15.0, 6.0]

# What a channel reports its width to be, in mm: `PxVY` answers 194 increments. Not a round
# number, so the rounding up to 0.1 mm is exercised rather than assumed.
REPORTED_WIDTH = 8.9826


class TestPositionInYDirection(unittest.IsolatedAsyncioTestCase):
  """What the channels' minimum spacing does to a Y positioning command."""

  async def test_the_limits_accept_what_the_machine_has_been_commanded(self):
    """The driver's minimum spacing and front limit against the extremes of real runs.

    A minimum wider than 9.0 mm fails on the first, a front limit behind 6.0 mm on the second.
    """
    for payload in (TIGHTEST_GAP, FRONTMOST):
      pipettes, sent = await channels(width=REPORTED_WIDTH, positions=payload)
      await pipettes.move_to_y_positions(dict(enumerate(payload)), make_space=False)
      self.assertEqual(sent[-1], jy(" ".join(f"{round(y * 10):04}" for y in payload)))

  async def test_a_gap_that_is_wide_enough_at_9mm_is_refused_at_18mm(self):
    spread = [100.0, 91.0, 82.0, 73.0, 64.0, 55.0, 46.0, 37.0]

    at_9, sent_9 = await channels(width=9.0, positions=spread)
    await at_9.move_to_y_positions(dict(enumerate(spread)), make_space=False)
    self.assertEqual(sent_9[-1], jy("1000 0910 0820 0730 0640 0550 0460 0370"))

    at_18, _ = await channels(width=18.0, positions=spread)
    with self.assertRaises(ValueError):
      await at_18.move_to_y_positions(dict(enumerate(spread)), make_space=False)

  async def test_make_space_moves_the_channel_in_front_by_the_minimum(self):
    # Already 18mm apart, so the reading needs no conforming and only make_space moves anything.
    current = [400.0, 300.0, 200.0, 160.0, 142.0, 124.0, 106.0, 88.0]

    at_9, sent_9 = await channels(width=9.0, positions=current)
    await at_9.move_to_y_positions({3: 150.0}, make_space=True)
    self.assertEqual(sent_9[-1], jy("4000 3000 2000 1500 1410 1240 1060 0880"))

    at_18, sent_18 = await channels(width=18.0, positions=current)
    await at_18.move_to_y_positions({3: 150.0}, make_space=True)
    self.assertEqual(sent_18[-1], jy("4000 3000 2000 1500 1320 1140 0960 0780"))
