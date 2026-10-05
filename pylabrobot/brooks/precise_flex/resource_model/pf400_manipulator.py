"""The PreciseFlex 400's manipulator: the two links its shoulder, elbow and wrist joints join.

Each link is a cuboid in its own frame, located by its left front bottom corner, in mm, lying along
its x from the joint it turns on to the joint the next member turns on. Cross-sections and hubs are
measured off the manufacturer's model, and are the same on both reaches; the length between a
link's joints is what the controller reports.
"""

from pylabrobot.resources.coordinate import Coordinate
from pylabrobot.resources.manipulator import LinkBody
from pylabrobot.resources.resource import Resource

# Link 1, shoulder to elbow: how wide and how tall it is, and how far its round hub reaches past the
# joint at each end.
LINK_1_SIZE_YZ = (114.0, 77.7)
LINK_1_HUB_OVERHANG = 57.0

# Link 2, elbow to wrist: a full hub at the elbow and a smaller one at the wrist.
LINK_2_SIZE_YZ = (112.0, 39.2)
LINK_2_HUB_PROXIMAL = 56.0
LINK_2_HUB_DISTAL = 36.0

# Link 2 turns underneath link 1, and link 1 underneath the carriage, this far apart.
LINK_Z_GAP = 1.0


def _link(
  name: str, length: float, size_yz: tuple, hub_proximal: float, hub_distal: float, model: str
) -> LinkBody:
  """A link `length` between its joints, with its body as a child for a mesh to bind to."""
  size_x = hub_proximal + length + hub_distal
  # The joints lie along the bottom face, centred across the link.
  proximal_joint = Coordinate(hub_proximal, size_yz[0] / 2, 0.0)
  link = LinkBody(
    name=name,
    size_x=size_x,
    size_y=size_yz[0],
    size_z=size_yz[1],
    proximal_joint=proximal_joint,
    distal_joint=proximal_joint + Coordinate(length, 0.0, 0.0),
    model=model,
  )
  body = Resource(
    name=f"{name}_body",
    size_x=size_x,
    size_y=size_yz[0],
    size_z=size_yz[1],
    category="body",
    model=f"{model}_body",
  )
  link.assign_child_resource(body, location=Coordinate.zero())
  return link


def link_1(name: str, length: float) -> LinkBody:
  """The first link: the shoulder joint to the elbow joint.

  Args:
    name: what to call this one.
    length: joint to joint, in mm, as the controller reports it.

  Returns:
    The link.
  """
  return _link(
    name, length, LINK_1_SIZE_YZ, LINK_1_HUB_OVERHANG, LINK_1_HUB_OVERHANG, "brooks_pf400_link_1"
  )


def link_2(name: str, length: float) -> LinkBody:
  """The second link: the elbow joint to the wrist joint.

  Args:
    name: what to call this one.
    length: joint to joint, in mm, as the controller reports it.

  Returns:
    The link.
  """
  return _link(
    name, length, LINK_2_SIZE_YZ, LINK_2_HUB_PROXIMAL, LINK_2_HUB_DISTAL, "brooks_pf400_link_2"
  )
