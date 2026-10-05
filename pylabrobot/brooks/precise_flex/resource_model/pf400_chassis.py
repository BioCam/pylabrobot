"""The PreciseFlex 400's chassis: the plate it stands on, the column it rides, the carriage on it.

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

# The carriage the J1 drive rides up the column: the housing the arm turns in, which is what the
# drive carries and what is seen of it.
Z_CARRIAGE_SIZE = (122.8, 110.0, 58.1)
# Where it rides: at the column's front face, centred across it. Z is whatever the drive reports.
Z_CARRIAGE_LOCATION_XY = (Z_COLUMN_SIZE_XY[0], (Z_COLUMN_SIZE_XY[1] - Z_CARRIAGE_SIZE[1]) / 2)
# How far the carriage's underside stands above the flange plane the drive reports: the arm hangs
# between the two. Less than the links stacked, as link 1's hub nests into it.
Z_CARRIAGE_ABOVE_FLANGE_PLANE = 104.2
# The point the drive reports, within the carriage: the shoulder axis, at the flange plane below it.
Z_CARRIAGE_REFERENCE_POINT = Coordinate(
  SHOULDER_AXIS.x - Z_COLUMN_LOCATION.x - Z_CARRIAGE_LOCATION_XY[0],
  Z_CARRIAGE_SIZE[1] / 2,
  -Z_CARRIAGE_ABOVE_FLANGE_PLANE,
)


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


def z_carriage_location(z: float) -> Coordinate:
  """Where the carriage stands on the column when the J1 drive reports `z`.

  A resource is located by its corner, so the reported point is taken out of the reading.

  Args:
    z: where the drive reports the flange plane is, in mm above where it is with the drive at 0.

  Returns:
    The location, on the column.
  """
  return Coordinate(
    Z_CARRIAGE_LOCATION_XY[0],
    Z_CARRIAGE_LOCATION_XY[1],
    SHOULDER_AXIS.z + z - Z_COLUMN_LOCATION.z - Z_CARRIAGE_REFERENCE_POINT.z,
  )


def z_carriage(name: str = "pf400_z_carriage") -> Resource:
  """The carriage the J1 drive rides up the column, and the arm turns in.

  Args:
    name: what to call this one.

  Returns:
    The carriage.
  """
  return Resource(
    name=name,
    size_x=Z_CARRIAGE_SIZE[0],
    size_y=Z_CARRIAGE_SIZE[1],
    size_z=Z_CARRIAGE_SIZE[2],
    category="z_carriage",
    model="brooks_pf400_z_carriage",
  )
