"""End-effectors: what an arm carries at its wrist, and the parts they are made of.

A mechanical gripper takes hold by closing onto a resource and lets go by opening. It is a link,
because that is what it is on an arm: it spans the joint it turns on to the point it grips at,
which is its tool centre point.
"""

from typing import Optional, Tuple, cast

from pylabrobot.resources.coordinate import Coordinate
from pylabrobot.resources.manipulator import Link, bolt_on
from pylabrobot.resources.resource import Resource


class Jaw(Resource):
  """One of the two parts a gripper drives together, carrying the finger that touches the resource.

  The jaw is the gripper's own: it is what the mechanism moves, and what a width read off the
  device describes. What is bolted to its end is the finger, which is tooling - changed for what is
  being gripped, and not something a gripper can report.
  """

  def __init__(
    self,
    name: str,
    size_x: float,
    size_y: float,
    size_z: float,
    category: str = "jaw",
    model: Optional[str] = None,
  ):
    super().__init__(
      name=name, size_x=size_x, size_y=size_y, size_z=size_z, category=category, model=model
    )
    self.finger: Optional[Resource] = None
    """The tooling on this jaw's end, when it has any bolted to it."""


class Finger(Resource):
  """What meets the resource: the tooling bolted to a jaw.

  Two things it will carry once there is something to read them from: which of its faces makes
  contact, so a grip can be stated against the surface that holds rather than against the finger's
  own corner, and what it senses, since a gripper that reports force reports it per finger.
  """

  def __init__(
    self,
    name: str,
    size_x: float,
    size_y: float,
    size_z: float,
    category: str = "finger",
    model: Optional[str] = None,
  ):
    super().__init__(
      name=name, size_x=size_x, size_y=size_y, size_z=size_z, category=category, model=model
    )


class MechanicalGripper(Link):
  """A gripper that holds by closing two jaws on what it takes.

  A link, because on an arm that is what it is: it spans the joint it turns on to the point it
  grips at, which is `tool_center_point`. Its body, its two jaws and the finger on each are
  material bolted to that span. How far apart the jaws stand is state rather than shape, so
  `jaw_width` moves them.

  The jaws are the gripper's own and the fingers are tooling: a device reports how far it has
  opened, and nothing reports what is bolted to the ends.
  """

  def __init__(
    self,
    name: str,
    length: float,
    body: Tuple[float, float, float, float, float],
    jaw: Tuple[float, float, float, float, float],
    finger: Tuple[float, float, float, float, float],
    jaw_range: Tuple[float, float],
    jaw_width: Optional[float] = None,
    category: str = "mechanical_gripper",
    model: Optional[str] = None,
  ):
    """
    Args:
      name: what to call this one.
      length: the joint it turns on to the grip centre, in mm.
      body: the body's size, how far along the link it starts, and how far above it stands, in mm.
      jaw: the same for one jaw. There are two, either side of the span.
      finger: the same for the finger on a jaw's end, measured from the joint as the rest are.
      jaw_range: how far apart the jaws stand, closed and open, in mm.
      jaw_width: how far apart they stand to begin with, in mm. Where a gripper is known to come
        up at a particular width - the one it homes at, say - that is what to build it at, so the
        model does not start out claiming a width nothing has read. Open, when not given.
    """
    super().__init__(name=name, length=length, category=category, model=model)
    self.jaw_range = jaw_range
    self._jaw_width = jaw_range[1] if jaw_width is None else jaw_width
    low, high = jaw_range
    if not low <= self._jaw_width <= high:
      raise ValueError(f"the jaws open {low} to {high} mm, so cannot start at {self._jaw_width}")

    self.body = bolt_on(self, "body", body)
    self.jaws = [cast(Jaw, bolt_on(self, f"jaw_{side}", jaw, of=Jaw)) for side in ("left", "right")]
    for on in self.jaws:
      on.finger = bolt_on(
        on,
        "finger",
        (finger[0], finger[1], finger[2], finger[3] - jaw[3], finger[4] - jaw[4]),
        of=Finger,
      )
      # A finger is fixed to its jaw, centred in the jaw's thickness, so it sits the same way on
      # both of them. `bolt_on` centres material across a link, and a jaw is not a link: its own
      # origin is a corner, so centring there leaves one finger inside the jaws and the other
      # outside them.
      where = cast(Coordinate, on.finger.location)
      on.finger.location = Coordinate(where.x, (jaw[1] - finger[1]) / 2, where.z)
    self.fingers = [cast(Resource, on.finger) for on in self.jaws]
    self._place_the_jaws()

  @property
  def tool_center_point(self) -> Coordinate:
    """The tool center point: where this tool is programmed against, as an offset from where it is
    mounted.

    A gripper's far joint carries nothing, so what sits there is the point it grips at.

    In PyLabRobot a tool center point is always this offset - a property of the tool, which changes
    when a different one is fitted and not when the arm moves. Robot controllers also use the term
    for where that point currently is in the robot's frame; here that is a location, and something
    an arm answers rather than a tool.

    Returns:
      The grip centre, from the joint this gripper turns on.
    """
    return self.far_joint

  @property
  def jaw_width(self) -> float:
    """How far apart the jaws stand, in mm."""
    return self._jaw_width

  @jaw_width.setter
  def jaw_width(self, width: float) -> None:
    low, high = self.jaw_range
    if not low <= width <= high:
      raise ValueError(f"the jaws open {low} to {high} mm, not {width}")
    self._jaw_width = width
    self._place_the_jaws()

  def _place_the_jaws(self) -> None:
    """Stand the jaws either side of the span, as far apart as they are open."""
    for jaw, side in zip(self.jaws, (1.0, -1.0)):
      here = cast(Coordinate, jaw.location)
      jaw.location = Coordinate(
        here.x, side * self._jaw_width / 2.0 - jaw.get_size_y() / 2.0, here.z
      )

  def serialize(self) -> dict:
    return {**super().serialize(), "jaw_range": list(self.jaw_range)}
