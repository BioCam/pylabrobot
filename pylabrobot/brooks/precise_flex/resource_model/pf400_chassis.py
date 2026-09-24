"""The PreciseFlex 400's chassis: the plate it stands on and the column its carriage rides.

Each part is a cuboid in its own frame, located by its left front bottom corner, in mm. Sizes are
the extended-reach arm's, measured off the manufacturer's model.
"""

from typing import Optional

from pylabrobot.resources.coordinate import Coordinate
from pylabrobot.resources.resource import Resource

BASE_PLATE_SIZE = (200.8, 235.1, 9.6)

# The J2 shoulder axis within the base plate: at its front face, centred across it, this far above
# the surface the plate stands on. Every position the controller reports is measured from here.
SHOULDER_AXIS = Coordinate(BASE_PLATE_SIZE[0], BASE_PLATE_SIZE[1] / 2, 62.0)

Z_COLUMN_SIZE_XY = (123.5, 181.0)
# Where the column stands on the plate's top face, centred across it.
Z_COLUMN_LOCATION = Coordinate(
  5.0, (BASE_PLATE_SIZE[1] - Z_COLUMN_SIZE_XY[1]) / 2, BASE_PLATE_SIZE[2]
)
# How far the column reaches above the flange plane once the carriage is at the top of its travel.
Z_COLUMN_HEADROOM = 250.0


def z_column_height(z_travel: float) -> float:
  """How tall the column is on an arm whose carriage travels `z_travel` mm.

  Measured from the plate's top face, where the column stands, to its own top.

  Args:
    z_travel: how far the carriage travels, in mm.

  Returns:
    The height, in mm.
  """
  return SHOULDER_AXIS.z + z_travel + Z_COLUMN_HEADROOM - Z_COLUMN_LOCATION.z


def base_plate(name: str = "pf400_base_plate") -> Resource:
  """The plate the arm stands on.

  Args:
    name: what to call this one.

  Returns:
    The plate.
  """
  return Resource(
    name=name,
    size_x=BASE_PLATE_SIZE[0],
    size_y=BASE_PLATE_SIZE[1],
    size_z=BASE_PLATE_SIZE[2],
    category="base_plate",
    model="brooks_pf400_base_plate",
  )


def z_column(name: str = "pf400_z_column", height: Optional[float] = None) -> Resource:
  """The column the carriage rides.

  Args:
    name: what to call this one.
    height: how tall it is, in mm, as `z_column_height` gives it. Zero until the travel is read.

  Returns:
    The column.
  """
  return Resource(
    name=name,
    size_x=Z_COLUMN_SIZE_XY[0],
    size_y=Z_COLUMN_SIZE_XY[1],
    size_z=0.0 if height is None else height,
    category="z_column",
    model="brooks_pf400_z_column",
  )
