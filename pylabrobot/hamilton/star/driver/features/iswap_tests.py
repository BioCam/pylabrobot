import unittest
from typing import Any, List, Optional, Tuple

from pylabrobot.hamilton.protocol.text.framing import assemble_command
from pylabrobot.hamilton.star.device import RECORDING_STAR
from pylabrobot.hamilton.star.driver.features.iswap import iSWAP
from pylabrobot.hamilton.star.driver.simulator import STARSimulationDriver
from pylabrobot.resources.hamilton import STARDeck


async def gripper() -> Tuple[iSWAP, List[str]]:
  """The iSWAP of a simulated device, and the list its commands are recorded in.

  Returns:
    The feature, and every command it sends from here on.
  """
  driver = STARSimulationDriver(deck=STARDeck(), declared_configuration_json=RECORDING_STAR)
  await driver.setup()
  iswap = driver.iswap
  assert iswap is not None

  sent: List[str] = []
  answer = driver.send_command

  async def recorded(
    module: str,
    command: str,
    fmt: Optional[Any] = None,
    subsystem: Optional[str] = None,
    **kwargs: Any,
  ):
    # `fmt` and `subsystem` are the driver's own rather than firmware parameters, so they are taken
    # as `send_command` takes them and never reach the assembler.
    sent.append(assemble_command(module=module, command=command, id_=None, **kwargs))
    return await answer(module=module, command=command, fmt=fmt, subsystem=subsystem, **kwargs)

  driver.send_command = recorded  # type: ignore[assignment]
  return iswap, sent


def jaw_moves(sent: List[str]) -> List[str]:
  """Every jaw move in what was sent."""
  return [command for command in sent if command.startswith("R0GA")]


class TestJawMoves(unittest.IsolatedAsyncioTestCase):
  """What a jaw move puts on the wire."""

  async def test_a_jaw_move_carries_the_width_it_was_asked_for(self):
    """The width reaches the drive as the position it is driven to. Asserted on the payload rather
    than on the model, because the two are set from different values: the model is told the width
    the caller asked for whatever the drive was sent, so a target lost between them shows up here
    and nowhere else. Both ends of the travel, so a move carrying a constant would fail one."""
    iswap, sent = await gripper()
    c = iswap.configuration

    await iswap.gripper_open()
    await iswap.gripper_close()

    opening, closing = jaw_moves(sent)
    self.assertIn(f"ga{c.gripper_range_increments[1]:05}", opening)
    self.assertIn(f"ga{c.gripper_range_increments[0]:05}", closing)

  async def test_a_close_the_caller_did_not_time_runs_at_half_speed(self):
    """A close carries half the configured default when the caller names no speed, since this
    command feels nothing and meets whatever is there at whatever it was driven at. An opening move
    carries the whole default, which is what separates the two."""
    iswap, sent = await gripper()
    c = iswap.configuration

    await iswap.gripper_open()
    await iswap.gripper_close()

    opening, closing = jaw_moves(sent)
    self.assertIn(f"gv{c.gripper_speed_default_increments:04}", opening)
    self.assertIn(f"gv{c.gripper_speed_default_increments // 2:04}", closing)


if __name__ == "__main__":
  unittest.main()
