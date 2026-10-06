"""The PreciseFlex 400's end-effector: the gripper its wrist joint turns.

The gripper is a cuboid in its own frame, located by its left front bottom corner, in mm, lying
along its x from the wrist joint to the point it grips at. Its drive moves two jaws, and a finger
is bolted to each. Sizes are measured off the manufacturer's model; how far it reaches and how far
its fingers open are what the controller reports.
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

GRIPPER_JAW_SIZE = (22.0, 43.2, 37.2)
# Where a jaw starts along the gripper and above its underside. Across it is wherever the drive is.
GRIPPER_JAW_LOCATION = Coordinate(92.0, 0.0, 15.7)

GRIPPER_FINGER_SIZE = (107.8, 11.5, 22.6)
# Where the first finger is bolted on its jaw: its rear set into the jaw's outer end, from below.
GRIPPER_FINGER_LOCATION = Coordinate(1.7, 32.2, -16.9)

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
  # The two sides are mirror images, so each has its own mesh.
  jaws, fingers = (
    tuple(
      Resource(
        name=f"{name}_{part}_{side}",
        size_x=size[0],
        size_y=size[1],
        size_z=size[2],
        category=part,
        model=f"{model}_{part}_{side}",
      )
      for side in ("left", "right")
    )
    for part, size in (("jaw", GRIPPER_JAW_SIZE), ("finger", GRIPPER_FINGER_SIZE))
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
    jaws=jaws,
    jaw_location=GRIPPER_JAW_LOCATION,
    jaw_range=jaw_range,
    jaw_width=jaw_width,
    model=model,
  )
