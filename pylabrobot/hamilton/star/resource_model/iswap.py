"""The iSWAP channel: the carriage its arm turns on."""

from typing import Optional

from pylabrobot.resources.coordinate import Coordinate
from pylabrobot.resources.resource import Resource


class iSWAPChannel(Resource):
  """The carriage the iSWAP's arm is mounted on.

  A channel in the sense the pipetting channels are: a body that rides the arm and carries its own
  Y and Z drives.

  The drives position this, not the gripper: `reference_point` is the point they report, and where
  the gripper ends up follows from it through the two links and the joint angles. A resource is
  located by its left front bottom corner, so the drives' readings are offset by this point before
  being recorded.

  It carries no children. What the arm holds hangs off the gripper, which is not modelled: where
  the gripper is depends on the joint state rather than on where this sits, so it does not follow
  this resource in the way a tip follows a mounting shaft.
  """

  def __init__(
    self,
    name: str,
    size_x: float,
    size_y: float,
    size_z: float,
    reference_point: Coordinate,
    category: str = "iswap_channel",
    model: Optional[str] = None,
  ):
    """
    Args:
      name: what to call this one.
      size_x: how wide the drive is, in mm.
      size_y: how deep it is, in mm.
      size_z: how tall it is, in mm.
      reference_point: the point the drives report, from the left front bottom corner.
      category: what kind of resource this is.
      model: which drive this is.
    """
    super().__init__(
      name=name, size_x=size_x, size_y=size_y, size_z=size_z, category=category, model=model
    )
    self.reference_point = reference_point

  def serialize(self) -> dict:
    return {**super().serialize(), "reference_point": self.reference_point.serialize()}


def iswap_channel(
  name: str,
  diameter: float,
  size_z: float,
) -> iSWAPChannel:
  """The channel, modelled as the cylinder the rotation drive sweeps around.

  Square in plan, spanning the drive's diameter, because a resource is a box. The drives report its
  centre in X and Y and its bottom in Z, which is what `reference_point` states.

  Args:
    name: what to call this one.
    diameter: how wide the drive is, in mm.
    size_z: how tall to model it, in mm.

  Returns:
    The drive.
  """
  return iSWAPChannel(
    name=name,
    size_x=diameter,
    size_y=diameter,
    size_z=size_z,
    reference_point=Coordinate(diameter / 2, diameter / 2, 0.0),
    model="hamilton_star_iswap_channel",
  )
