"""The PreciseFlex 400's optional linear rail: the rail, and the carriage the arm stands on.

Each part is a cuboid in its own frame, located by its left front bottom corner, in mm, with the
rail lying along its x. Sizes are measured off the manufacturer's model.
"""

from typing import Optional

from pylabrobot.resources.resource import Resource

LINEAR_RAIL_SIZE_YZ = (206.0, 104.6)
# How much longer the rail is than the carriage travels on it: the carriage itself and both ends.
LINEAR_RAIL_BEYOND_TRAVEL = 390.8
# The travels the rail is built in, in mm, and what each one's model is called.
LINEAR_RAIL_TRAVELS = {1000.0: "1m", 1500.0: "1_5m", 2000.0: "2m"}

LINEAR_RAIL_CARRIAGE_SIZE = (234.0, 234.0, 90.2)
# Where the carriage rides across and above the rail. Along it is wherever the drive reports.
LINEAR_RAIL_CARRIAGE_LOCATION_YZ = (-14.0, 36.0)
# How the arm is mounted on the carriage, in degrees as the controller holds it, and what each
# one's model is called: at 0 the arm's y lies along the rail, at -90 its x.
LINEAR_RAIL_CARRIAGE_MOUNTINGS = {0.0: "0deg", -90.0: "90deg"}


def linear_rail(name: str, travel: float) -> Resource:
  """The rail, as long as the travel its carriage has.

  Args:
    name: what to call this one.
    travel: how far its carriage travels, in mm. A travel the rail is not built in gets no mesh.

  Returns:
    The rail.
  """
  built = LINEAR_RAIL_TRAVELS.get(travel)
  return Resource(
    name=name,
    size_x=travel + LINEAR_RAIL_BEYOND_TRAVEL,
    size_y=LINEAR_RAIL_SIZE_YZ[0],
    size_z=LINEAR_RAIL_SIZE_YZ[1],
    category="linear_rail",
    model=None if built is None else f"brooks_pf400_linear_rail_{built}",
  )


def linear_rail_carriage(name: str, mounting: float) -> Resource:
  """The carriage that rides the rail, with the plate the arm is mounted on.

  Args:
    name: what to call this one.
    mounting: how the arm is mounted on it, in degrees: 0 or -90.

  Returns:
    The carriage.

  Raises:
    ValueError: If the arm is not mounted either way.
  """
  mounted: Optional[str] = LINEAR_RAIL_CARRIAGE_MOUNTINGS.get(mounting)
  if mounted is None:
    raise ValueError(f"the arm is mounted at 0 or -90 degrees on its rail, not {mounting}")
  return Resource(
    name=name,
    size_x=LINEAR_RAIL_CARRIAGE_SIZE[0],
    size_y=LINEAR_RAIL_CARRIAGE_SIZE[1],
    size_z=LINEAR_RAIL_CARRIAGE_SIZE[2],
    category="linear_rail_carriage",
    model=f"brooks_pf400_linear_rail_carriage_{mounted}",
  )
