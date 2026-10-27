"""The PreciseFlex 400's manipulator: the two links its shoulder, elbow and wrist joints join.

Each link is a cuboid in its own frame, located by its left front bottom corner, in mm, lying along
its x from the joint it turns on to the joint the next member turns on. Cross-sections and hubs are
measured off the manufacturer's model, and are the same on both reaches; the length between a
link's joints is what the controller reports.
"""

from pylabrobot.brooks.precise_flex.kinematics import ARM_LINKS_EXTENDED, ARM_LINKS_STANDARD
from pylabrobot.resources.coordinate import Coordinate
from pylabrobot.resources.manipulator import LinkBody

# Link 1, shoulder to elbow: how wide and how tall it is, and how far its round hub reaches past the
# joint at each end.
LINK_1_SIZE_YZ = (114.0, 73.4)
LINK_1_HUB_OVERHANG = 57.0

# Link 2, elbow to wrist: a full hub at the elbow and a smaller one at the wrist.
LINK_2_SIZE_YZ = (112.0, 39.2)
LINK_2_HUB_PROXIMAL = 56.0
LINK_2_HUB_DISTAL = 36.0

# How far link 1's underside stands above the flange plane, which link 2's underside lies in.
# Less than link 2 is tall: at the elbow the two hubs nest.
LINK_1_ABOVE_FLANGE_PLANE = 31.5


def _reach(link: int, length: float) -> str:
  """The reach whose link `link` (0 or 1) is nearest `length`: "standard" or "extended"."""
  reaches = {"standard": ARM_LINKS_STANDARD[link], "extended": ARM_LINKS_EXTENDED[link]}
  return min(reaches, key=lambda reach: abs(reaches[reach] - length))


def _link(
  name: str, length: float, size_yz: tuple, hub_proximal: float, hub_distal: float, model: str
) -> LinkBody:
  """A link `length` between its joints, reaching a hub past each."""
  # The joints lie along the bottom face, centred across the link.
  proximal_joint = Coordinate(hub_proximal, size_yz[0] / 2, 0.0)
  return LinkBody(
    name=name,
    size_x=hub_proximal + length + hub_distal,
    size_y=size_yz[0],
    size_z=size_yz[1],
    proximal_joint=proximal_joint,
    distal_joint=proximal_joint + Coordinate(length, 0.0, 0.0),
    model=model,
  )


def link_1(name: str, length: float) -> LinkBody:
  """The first link: the shoulder joint to the elbow joint, drawn as the nearest reach's.

  Args:
    name: what to call this one.
    length: joint to joint, in mm, as the controller reports it.

  Returns:
    The link.
  """
  model = f"brooks_pf400_link_1_{_reach(0, length)}"
  return _link(name, length, LINK_1_SIZE_YZ, LINK_1_HUB_OVERHANG, LINK_1_HUB_OVERHANG, model)


def link_2(name: str, length: float) -> LinkBody:
  """The second link: the elbow joint to the wrist joint, drawn as the nearest reach's.

  Args:
    name: what to call this one.
    length: joint to joint, in mm, as the controller reports it.

  Returns:
    The link.
  """
  model = f"brooks_pf400_link_2_{_reach(1, length)}"
  return _link(name, length, LINK_2_SIZE_YZ, LINK_2_HUB_PROXIMAL, LINK_2_HUB_DISTAL, model)
