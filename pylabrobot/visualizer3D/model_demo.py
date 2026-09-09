"""A STARlet drawn from the models it ships with, rather than as boxes.

Run it:

    python -m pylabrobot.visualizer3D.model_demo

Nothing here declares a path and nothing is passed a models root. A resource carries a model name,
a file under the package is named after that model, and the viewer draws it - so geometry travels
with the code that describes the part, and a machine picks up its own appearance by being itself.

What is drawn as a model and what is still a box is printed on startup, because that is the whole
of what this demonstrates and it is worth being able to read rather than infer from the picture.
A part keeps its box until two things are true: it has a model name, and a file is named after it
in its own resource's frame - the origin at the resource's own corner, in metres, Z up.

The arm turns and the jaws open and close while it runs, so the models can be watched following
their joints rather than sitting where the boxes used to be. Nothing here moves geometry: the
drives move resources, and a model is drawn wherever its resource is.
"""

import asyncio
import logging
from typing import Dict, List, Tuple

from pylabrobot.hamilton.star.device import STARDevice, STARLet
from pylabrobot.resources.coordinate import Coordinate
from pylabrobot.resources.resource import Resource

from .facility import Facility
from .server import PACKAGE_ROOT, Viewer3D, _models_on_disk

logging.disable(logging.WARNING)


def build_facility() -> Facility:
  """A facility holding one simulated STARlet, and nothing else to look at.

  As it comes: the left extension housing on and the side panel off. A file exists for both, but a
  device has one or the other - the housing stands where the panel would be - so only one of them
  can ever be drawn. Pass `left_side_panel_installed=True` to see the other.
  """
  facility = Facility(name="facility", size_x=2000, size_y=1200, size_z=1000)
  facility.assign_child_resource(STARLet(simulation=True), location=Coordinate(0, 0, 0))
  return facility


def star_of(facility: Resource) -> STARDevice:
  """The STARlet in it."""
  star = facility.children[0]
  if not isinstance(star, STARDevice):
    raise TypeError(f"expected a STAR device in the facility, found {type(star).__name__}")
  return star


def what_is_drawn(root: Resource) -> Tuple[List[str], List[str], List[str]]:
  """Every model in the tree, split by why it is or is not drawn from a file.

  Three answers, not two. A resource with no model name cannot be looked up at all, which is a
  different thing from one that was looked up and found nothing - the first needs a name, the
  second needs a file.
  """
  on_disk = _models_on_disk(PACKAGE_ROOT)
  drawn: Dict[str, None] = {}
  missing: Dict[str, None] = {}
  unnamed: Dict[str, None] = {}

  def walk(resource: Resource) -> None:
    model = getattr(resource, "model", None)
    if not model:
      unnamed.setdefault(f"{type(resource).__name__} ({resource.category})", None)
    elif model in on_disk:
      drawn.setdefault(model, None)
    else:
      missing.setdefault(model, None)
    for child in resource.children:
      walk(child)

  walk(root)
  return sorted(drawn), sorted(missing), sorted(unnamed)


def report(root: Resource) -> None:
  """Print what the viewer will draw from a file and what it will not."""
  drawn, missing, unnamed = what_is_drawn(root)
  print(f"\n  drawn from a model file ({len(drawn)})")
  for model in drawn:
    print(f"    {model}")
  print(f"\n  named, but no file is under that name ({len(missing)})")
  for model in missing:
    print(f"    {model}")
  print(f"\n  no model name, so nothing to look up ({len(unnamed)})")
  for kind in unnamed:
    print(f"    {kind}")
  print()


# How far forward to bring the rotation drive before turning it, in mm. Parked at the back of its
# travel the arm cannot turn at all: a quarter turn puts the wrist joint further back than the
# drive itself reaches, and the guard refuses it. Clearing more than link 1's length leaves room
# for the whole swing.
ROOM_TO_TURN = 200.0


# How long each pose is held, in seconds, so a move can be followed rather than glimpsed.
HELD_FOR = 2.5


async def turn_the_arm(star: STARDevice) -> None:
  """Swing the iSWAP between its stops, so a model can be watched following its joint."""
  iswap = star.iswap
  if iswap is None:
    return

  # Cleared once, up front, rather than asked for on each move. A rotation cannot clear the deck
  # for itself - `make_space=True` on one is refused rather than sweeping the arm while the caller
  # believes the way is clear - so the channels and the head are put out of the way first and stay
  # there for the run.
  await iswap.make_space()

  parked = await iswap.rotation_drive_request_y_position()
  try:
    await iswap.rotation_drive_move_to_y_position(parked - ROOM_TO_TURN)
  except ValueError as refused:
    print(f"  the drive stays where it is, so the arm will not turn far: {refused}")

  for step in range(10_000):
    where = ("front", "left", "front", "right")[step % 4]
    try:
      await iswap.rotate_to_angles(
        rotation_absolute_angle=where, gripper_absolute_angle="front", make_space=False
      )
    except ValueError as refused:
      # The guards stand between the arm and the channels, and a demo is not a reason to talk past
      # them: what they refuse is what a real caller would be refused.
      print(f"  the arm may not go to {where}: {refused}")
    await asyncio.sleep(HELD_FOR)


async def work_the_jaws(star: STARDevice) -> None:
  """Open and close the gripper, so the fingers and their pads can be watched moving.

  The two fingers are one model mounted twice, and the width between them is what the drive
  carries: there is no second mesh to keep in step, and nothing here touches the geometry. Moving
  the drive moves the resources, and the models follow because they are drawn where those are.

  The stops are the drive's own travel rather than round numbers, so what is drawn is the whole of
  what the jaws can do.
  """
  iswap = star.iswap
  if iswap is None:
    return

  c = iswap.configuration
  # Widest first: the arm comes up holding whatever it homed at, and opening from there reads as a
  # move where closing onto an already-closed gripper would not.
  closed, opened = (c.gripper_increments_to_mm(end) for end in c.gripper_range_increments)
  # Offset against the arm's own cycle, so the two are not seen only ever moving together.
  await asyncio.sleep(HELD_FOR / 2)

  for step in range(10_000):
    width = (opened, closed)[step % 2]
    try:
      await iswap.gripper_move_to_jaw_position(width)
    except ValueError as refused:
      print(f"  the jaws may not go to {width:.1f} mm: {refused}")
    await asyncio.sleep(HELD_FOR)


async def main() -> None:
  facility = build_facility()
  star = star_of(facility)
  await star.setup()
  report(facility)

  viewer = Viewer3D(facility, name="model_demo.py")
  await viewer.start()
  if star.iswap is None:
    print("  this STARlet has no iSWAP, so nothing moves")
    return
  # The arm turns and the jaws work at the same time, as they do on the machine: one drive does not
  # wait on the other.
  await asyncio.gather(turn_the_arm(star), work_the_jaws(star))


if __name__ == "__main__":
  try:
    asyncio.run(main())
  except KeyboardInterrupt:
    pass
