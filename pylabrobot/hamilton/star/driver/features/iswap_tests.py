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


def moves(sent: List[str]) -> List[str]:
  """Every command in what was sent that puts something somewhere."""
  return [
    command
    for command in sent
    if command[:4] in ("R0YA", "R0ZA", "R0PA", "R0GA") or command[:4] in ("C0JY", "C0JZ")
  ]


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


class TestYMoves(unittest.IsolatedAsyncioTestCase):
  """What a Y move does before it is sure it can run."""

  async def test_a_refused_y_move_leaves_the_deck_alone(self):
    """Making space moves the channels, so every argument is checked before it runs: a speed the
    drive will not take has to be refused with nothing moved, rather than with the deck rearranged
    for a command that never went out. Driven with a target the channels are in the way of, since
    one they already clear makes space without moving anything and would pass either way."""
    iswap, sent = await gripper()
    pipettes = iswap.arm.pipettes
    assert pipettes is not None
    before = (await pipettes.request_y_positions())[0]

    with self.assertRaises(ValueError):
      await iswap.rotation_drive_move_to_y_position(460.0, make_space=True, speed=500.0)

    self.assertEqual((await pipettes.request_y_positions())[0], before)
    self.assertEqual(moves(sent), [])


class TestPosesAgainstTheRail(unittest.IsolatedAsyncioTestCase):
  """What the X-arm at the back of the deck lets the arm reach."""

  async def test_a_carriage_on_its_own_back_stop_may_still_turn_sideways(self):
    """Parked at the back, the arm lying along the deck reaches nothing behind the carriage, so the
    pose stands. It used to be refused: the limit came from a conversion rounded to two places and
    the position from one rounded again to a single place, leaving the carriage a hundredth of a
    millimetre past its own maximum."""
    iswap, _ = await gripper()
    c = iswap.configuration
    assert c.rotation_drive_predefined_increments is not None
    assert c.wrist_drive_predefined_increments is not None

    self.assertEqual(await iswap.rotation_drive_request_y_position(), c.rotation_drive_y_max)
    for stop in ("left", "right"):
      angle = c.rotation_drive_increments_to_angle(c.rotation_drive_predefined_increments[stop])
      straight = c.wrist_increments_to_deg(c.wrist_drive_predefined_increments["straight"])
      iswap._check_pose_reachable(angle, straight)

  async def test_a_pose_that_reaches_behind_the_rail_is_still_refused(self):
    """The slack is half an increment, not a licence: link 2 folded square backwards puts the grip
    centre 137.7 mm behind the carriage, where the X-arm is."""
    iswap, _ = await gripper()
    c = iswap.configuration
    assert c.rotation_drive_predefined_increments is not None
    assert c.wrist_drive_predefined_increments is not None

    angle = c.rotation_drive_increments_to_angle(c.rotation_drive_predefined_increments["right"])
    wrist = c.wrist_increments_to_deg(c.wrist_drive_predefined_increments["left"])
    with self.assertRaises(ValueError):
      iswap._check_pose_reachable(angle, wrist)


if __name__ == "__main__":
  unittest.main()
