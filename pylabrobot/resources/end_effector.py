"""End-effectors: what an arm carries at its wrist, and the parts they are made of.

A mechanical gripper takes hold by closing onto a resource and lets go by opening. It is a link,
because that is what it is on an arm: it spans the joint it turns on to the point it grips at,
which is its tool centre point.
"""

from typing import Optional, Tuple, cast

from pylabrobot.resources.coordinate import Coordinate
from pylabrobot.resources.manipulator import Link, bolt_on


class MechanicalGripper(Link):
  """A gripper that holds by closing two fingers on what it takes.

  A link, because on an arm that is what it is: it spans the joint it turns on to the point it
  grips at, which is `tool_centre_point`. Its body, its two fingers and the pad on each are material
  bolted to that span. How far apart the fingers stand is state rather than shape, so `jaw_width`
  moves them.
  """

  def __init__(
    self,
    name: str,
    length: float,
    body: Tuple[float, float, float, float],
    finger: Tuple[float, float, float, float],
    pad: Tuple[float, float, float, float],
    jaw_range: Tuple[float, float],
    category: str = "mechanical_gripper",
    model: Optional[str] = None,
  ):
    """
    Args:
      name: what to call this one.
      length: the joint it turns on to the grip centre, in mm.
      body: the body's size and how far along the link it starts, in mm.
      finger: the same for one finger. There are two, either side of the span.
      pad: the same for the pad on a finger's end, measured from the joint as the rest are.
      jaw_range: how far apart the fingers stand, closed and open, in mm.
    """
    super().__init__(name=name, length=length, category=category, model=model)
    self.jaw_range = jaw_range
    self._jaw_width = jaw_range[1]

    self.body = bolt_on(self, "body", body)
    self.fingers = [bolt_on(self, f"finger_{side}", finger) for side in ("left", "right")]
    self.pads = [
      bolt_on(on, "pad", (pad[0], pad[1], pad[2], pad[3] - finger[3])) for on in self.fingers
    ]
    self._place_the_fingers()

  @property
  def tool_centre_point(self) -> Coordinate:
    """The tool centre point: the point between the fingers a move is programmed against.

    A gripper's far joint carries nothing, so what sits there is the point it grips at. Stated as
    an offset from the joint the gripper turns on, as a tool centre point is.

    Returns:
      The grip centre, from the joint this gripper turns on.
    """
    return self.far_joint

  @property
  def jaw_width(self) -> float:
    """How far apart the fingers stand, in mm."""
    return self._jaw_width

  @jaw_width.setter
  def jaw_width(self, width: float) -> None:
    low, high = self.jaw_range
    if not low <= width <= high:
      raise ValueError(f"the jaws open {low} to {high} mm, not {width}")
    self._jaw_width = width
    self._place_the_fingers()

  def _place_the_fingers(self) -> None:
    """Stand the fingers either side of the span, as far apart as the jaws are open."""
    for finger, side in zip(self.fingers, (1.0, -1.0)):
      here = cast(Coordinate, finger.location)
      finger.location = Coordinate(
        here.x, side * self._jaw_width / 2.0 - finger.get_size_y() / 2.0, here.z
      )

  def serialize(self) -> dict:
    return {**super().serialize(), "jaw_range": list(self.jaw_range)}
