"""The PreciseFlex 400's end-effector: the gripper its wrist joint turns.

The gripper is a cuboid in its own frame, located by its left front bottom corner, in mm, lying
along its x from the wrist joint to the point it grips at. Sizes are measured off the
manufacturer's model; how far it reaches and how far its jaws open are what the controller reports.
"""

from typing import Optional, Tuple

from pylabrobot.resources.coordinate import Coordinate
from pylabrobot.resources.end_effector import MechanicalGripper
from pylabrobot.resources.resource import Resource

GRIPPER_BODY_SIZE = (127.0, 134.0, 55.4)
# The wrist joint within the gripper: centred across it, in the flange plane just above its body.
GRIPPER_JOINT = Coordinate(34.4, GRIPPER_BODY_SIZE[1] / 2, 56.4)

# The body seen from above, in its own frame: it narrows towards the wrist joint.
GRIPPER_BODY_OUTLINE = (
  (8.6, 44.1),
  (13.6, 39.5),
  (66.3, 0.2),
  (125.0, 0.1),
  (126.8, 1.2),
  (126.8, 133.0),
  (125.0, 134.1),
  (64.4, 133.3),
  (4.2, 83.6),
  (0.0, 67.1),
)

GRIPPER_FINGER_SIZE = (107.8, 11.5, 22.6)
# Where a finger starts along the gripper and how far it hangs below the body. Y is the jaws'.
GRIPPER_FINGER_LOCATION = Coordinate(93.7, 0.0, -1.2)

# How far below the flange plane the fingers grip: at the middle of their height.
GRIPPER_TOOL_CENTER_POINT_Z = -46.3


def gripper(
  name: str,
  tool_length: float,
  jaw_range: Tuple[float, float],
  jaw_width: Optional[float] = None,
) -> MechanicalGripper:
  """The gripper: the wrist joint to the centre the fingers hold a plate at.

  Args:
    name: what to call this one.
    tool_length: the wrist joint to the grip centre, in mm, as the controller reports it.
    jaw_range: how far apart the fingers stand, closed and open, in mm.
    jaw_width: how far apart they stand to begin with, in mm. Open, when not given.

  Returns:
    The gripper.
  """
  model = "brooks_pf400_gripper"
  fingers = tuple(
    Resource(
      name=f"{name}_finger_{side}",
      size_x=GRIPPER_FINGER_SIZE[0],
      size_y=GRIPPER_FINGER_SIZE[1],
      size_z=GRIPPER_FINGER_SIZE[2],
      category="finger",
      model=f"{model}_finger",
    )
    for side in ("left", "right")
  )
  return MechanicalGripper(
    name=name,
    proximal_joint=GRIPPER_JOINT,
    tool_center_point=Coordinate(tool_length, 0.0, GRIPPER_TOOL_CENTER_POINT_Z),
    body=Resource(
      name=f"{name}_body",
      size_x=GRIPPER_BODY_SIZE[0],
      size_y=GRIPPER_BODY_SIZE[1],
      size_z=GRIPPER_BODY_SIZE[2],
      category="body",
      model=f"{model}_body",
    ),
    body_location=Coordinate.zero(),
    fingers=fingers,
    finger_location=GRIPPER_FINGER_LOCATION,
    jaw_range=jaw_range,
    jaw_width=jaw_width,
    model=model,
  )
