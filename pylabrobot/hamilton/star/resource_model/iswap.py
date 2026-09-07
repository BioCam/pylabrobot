"""The iSWAP: the carriage its arm turns on, and the links that arm is made of."""

from typing import Optional, Tuple

from pylabrobot.resources.coordinate import Coordinate
from pylabrobot.resources.end_effector import MechanicalGripper
from pylabrobot.resources.manipulator import Link, bolt_on
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
    self.rotation_drive_angle: Optional[float] = None
    self.wrist_drive_angle: Optional[float] = None
    """Which way the rotation drive reports the arm points, in degrees, or None until it is read.

    Kept in the drive's own terms, as it reports them. `rotation` carries the same fact rendered
    for the deck, which is neither the same reference nor the same axis: degrees there are the
    deck angle link 1 lies along, and a resource turns about its own corner while the arm turns
    about `reference_point`. Anything needing the angle a drive would report reads this rather
    than converting `rotation` back."""

  def serialize(self) -> dict:
    return {
      **super().serialize(),
      "reference_point": self.reference_point.serialize(),
      "rotation_drive_angle": self.rotation_drive_angle,
      "wrist_drive_angle": self.wrist_drive_angle,
    }


# The material each part of the arm carries, measured on the manufacturer's own model: its size,
# how far along the link it starts from the joint the link turns on, and how high it stands. A
# part may start behind its joint, which is why the offset is stated rather than assumed to be
# zero.
#
# The heights are what makes the arm an arm rather than a flat plate: it steps down from the drive
# to the plate it holds. They are measured against the height the Z drive reports, which is the
# same plane `rotation_drive_z_offset_above_finger` is measured from - and the model agrees with
# it independently, since the pads' underside comes out exactly that far below.
LINK_1_BODY = (163.4, 25.5, 15.3, -12.7, 19.0)
GRIPPER_BODY = (59.0, 90.0, 20.3, -13.0, -1.3)
GRIPPER_FINGER = (135.0, 7.0, 8.0, 6.5, 4.0)
GRIPPER_PAD = (37.0, 4.0, 17.0, 115.5, -13.0)

# How far the rotation drive's own column stands above the height the Z drive reports, in mm. The
# arm hangs below that: the drive reports where the material it carries is, not where its column
# begins. The column stands on link 1 with nothing between them, so this follows link 1's own top
# rather than being stated again - the two cannot drift apart.
ROTATION_DRIVE_COLUMN_ABOVE_REPORTED_Z = LINK_1_BODY[4] + LINK_1_BODY[2]


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
    # The Z drive reports a point below the column's own base - the arm it carries hangs there -
    # so the reference point states that, and the resource lands that far above what is read.
    reference_point=Coordinate(diameter / 2, diameter / 2, -ROTATION_DRIVE_COLUMN_ABOVE_REPORTED_Z),
    model="hamilton_star_iswap_channel",
  )


def iswap_gripper(
  name: str, length: float, jaw_range: Tuple[float, float], jaw_width: Optional[float] = None
) -> MechanicalGripper:
  """The iSWAP's hand: the wrist joint to the centre the clamps hold a rack at.

  Args:
    name: what to call this one.
    length: the wrist joint to the grip centre, in mm, as `iSWAPConfiguration.link_2_length`
      reports it.
    jaw_range: how far apart the jaws stand, closed and open, in mm, as the gripper drive's own
      travel gives it.
    jaw_width: how far apart they stand to begin with, in mm. The width the drive homes and parks
      at, where the stored table has been read.

  Returns:
    The gripper.
  """
  return MechanicalGripper(
    name=name,
    length=length,
    body=GRIPPER_BODY,
    finger=GRIPPER_FINGER,
    pad=GRIPPER_PAD,
    jaw_range=jaw_range,
    jaw_width=jaw_width,
    model="hamilton_star_iswap_gripper",
  )


def iswap_link_1(name: str, length: float) -> Link:
  """The first link: the rotation joint to the wrist joint, with the arm bolted to it.

  Args:
    name: what to call this one.
    length: joint to joint, in mm, as `iSWAPConfiguration.link_1_length` reports it.

  Returns:
    The link.
  """
  link = Link(name=name, length=length, category="iswap_link", model="hamilton_star_iswap_link_1")
  bolt_on(link, "body", LINK_1_BODY)
  return link
