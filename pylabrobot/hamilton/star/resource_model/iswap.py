"""The iSWAP: the carriage its arm turns on, and the links that arm is made of."""

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


class iSWAPLinkage(Resource):
  """One link of the iSWAP's arm.

  A cuboid, turning about the joint at its proximal end: link 1 about the rotation drive, carrying
  the wrist joint at its far end. `reference_point` is that proximal joint, from the left front
  bottom corner, so the link is placed by the joint it turns on rather than by a corner of the box.

  Unrotated it lies along +X, which is where `rotation_drive_angle - 90` puts it at the front stop
  plus ninety degrees. Its length is the distance between the two joints, which is what
  `iSWAPConfiguration.link_1_length` holds - read off the arm, and per unit.

  It carries no children. What the arm holds hangs off the gripper, which is not modelled.
  """

  def __init__(
    self,
    name: str,
    size_x: float,
    size_y: float,
    size_z: float,
    reference_point: Coordinate,
    category: str = "iswap_linkage",
    model: Optional[str] = None,
  ):
    """
    Args:
      name: what to call this one.
      size_x: how long the link is, joint to joint, in mm.
      size_y: how wide it is, in mm.
      size_z: how deep it is, in mm.
      reference_point: the joint it turns on, from the left front bottom corner.
      category: what kind of resource this is.
      model: which link this is.
    """
    super().__init__(
      name=name, size_x=size_x, size_y=size_y, size_z=size_z, category=category, model=model
    )
    self.reference_point = reference_point

  def serialize(self) -> dict:
    return {**super().serialize(), "reference_point": self.reference_point.serialize()}


def iswap_linkage_1(
  name: str,
  length: float = 138.0,
  width: float = 30.5,
  height: float = 15.0,
) -> iSWAPLinkage:
  """The first link: the rotation joint to the wrist joint.

  The joint it turns on sits at the middle of its proximal end, which is what `reference_point`
  states, so turning it about the rotation drive turns it about that point rather than about a
  corner.

  Its underside is the arm's lowest point, which stands
  `iSWAPConfiguration.rotation_drive_z_offset_above_finger` above the gripper finger plane the Z
  drive reports - so a link placed by its own bottom sits that far above what `R0 RZ` answers.

  Args:
    name: what to call this one.
    length: joint to joint, in mm. Only this one is read back: an arm reports its own through
      `iSWAPConfiguration.link_1_length`, which is what to pass when it is known.
    width: how wide the link is, in mm, measured on the arm.
    height: how deep the link is, in mm, measured on the arm. Not the distance it stands above the
      grip centre, which is a gap between two things rather than the size of one.

  Returns:
    The link.
  """
  return iSWAPLinkage(
    name=name,
    size_x=length,
    size_y=width,
    size_z=height,
    reference_point=Coordinate(0.0, width / 2, 0.0),
    model="hamilton_star_iswap_linkage_1",
  )
