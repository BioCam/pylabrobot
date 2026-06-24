"""PreciseFlex 400 physical resource model (chassis: base_plate, z_column, shoulder, linkages).

Built up in the World/device frame: origin = the J2 shoulder axis at the J1-low tool-flange plane,
+x forward (reach), +y left, +z up. Dimensions are the measured ground truth for the extended-reach
(XR) PF400.
"""

from pylabrobot.brooks.precise_flex.kinematics import ARM_LINKS_EXTENDED
from pylabrobot.resources.coordinate import Coordinate
from pylabrobot.resources.resource import Resource

BASE_PLATE_X, BASE_PLATE_Y, BASE_PLATE_Z = 200.8, 235.1, 9.0
BASE_PLATE_BOTTOM_OFFSET = 62.0  # base_plate bottom this far below the World origin (J1-low flange plane)

Z_COLUMN_X, Z_COLUMN_Y = 123.5, 181.0


def base_plate(name: str = "pf400_base_plate") -> Resource:
  """PreciseFlex 400 base plate - a cuboid, 200.8 (x) x 235.1 (y) x 9 (z) mm."""
  return Resource(
    name=name,
    size_x=BASE_PLATE_X,
    size_y=BASE_PLATE_Y,
    size_z=BASE_PLATE_Z,
    category="base_plate",
    model="PreciseFlex 400",
  )


def build_pf400(total_height: float = 0.0) -> Resource:
  """Assemble the PF400 in the World/device frame (origin = J2 axis at the J1-low tool-flange plane;
  +x forward, +y left, +z up). Returns the root resource (the base_plate).

  `total_height` is the whole chassis height (base_plate bottom -> z_column top); the column sits on
  the plate top, so its size_z = `total_height - BASE_PLATE_Z`."""
  bp = base_plate()
  bp.location = Coordinate(-BASE_PLATE_X, -BASE_PLATE_Y / 2, -BASE_PLATE_BOTTOM_OFFSET)
  zc = z_column(height=total_height - BASE_PLATE_Z)
  bp.assign_child_resource(zc, location=Coordinate(COLUMN_DX, COLUMN_DY, BASE_PLATE_Z))
  zc.assign_child_resource(shoulder(), location=Coordinate(SHOULDER_DX, SHOULDER_DY, SHOULDER_DZ))
  return bp


# z_column placement on the base_plate (child location, relative to base_plate corner origin):
COLUMN_DX = 5.0
COLUMN_DY = (BASE_PLATE_Y - Z_COLUMN_Y) / 2  # = 27.05 -> centred in y on the base_plate

# shoulder placement on the z_column (child location, relative to z_column corner origin):
SHOULDER_X = BASE_PLATE_X - Z_COLUMN_X - COLUMN_DX  # = 72.3, spans the column front face to the J2 axis
SHOULDER_Y = 0.5 * Z_COLUMN_Y  # = 90.5
SHOULDER_Z = 40.0
SHOULDER_DX = Z_COLUMN_X  # = 123.5 -> starts at the column front (+x) face
SHOULDER_DY = (Z_COLUMN_Y - SHOULDER_Y) / 2  # = 45.25 -> centred in y on the column
SHOULDER_DZ = BASE_PLATE_BOTTOM_OFFSET - BASE_PLATE_Z  # = 53 -> shoulder bottom at z = 0


def z_column(name: str = "pf400_z_column", height: float = 0.0) -> Resource:
  """PreciseFlex 400 Z column - a cuboid, 123.5 (x) x 181.0 (y) x `height` (z) mm. (height TBD)"""
  return Resource(
    name=name,
    size_x=Z_COLUMN_X,
    size_y=Z_COLUMN_Y,
    size_z=height,
    category="z_column",
    model="PreciseFlex 400",
  )


def shoulder(name: str = "pf400_shoulder") -> Resource:
  """PreciseFlex 400 shoulder - a cuboid bridging the z_column front face to the J2 axis (origin).

  size: SHOULDER_X (x) x SHOULDER_Y (y) x SHOULDER_Z (z)."""
  return Resource(
    name=name,
    size_x=SHOULDER_X,
    size_y=SHOULDER_Y,
    size_z=SHOULDER_Z,
    category="shoulder",
    model="PreciseFlex 400",
  )


def linkage_1(name: str = "pf400_linkage_1") -> Resource:
  """PreciseFlex 400 linkage 1 (inner link, shoulder -> elbow).

  Modelled as a length-only segment - length `ARM_LINKS_EXTENDED[0]`, cross-section TBD.
  Corner origin = the link start; it extends along +x to the end."""
  return Resource(
    name=name,
    size_x=ARM_LINKS_EXTENDED[0],
    size_y=0.0,
    size_z=0.0,
    category="linkage",
    model="PreciseFlex 400",
  )


def linkage_2(name: str = "pf400_linkage_2") -> Resource:
  """PreciseFlex 400 linkage 2 (outer link, elbow -> wrist).

  Modelled as a length-only segment - length `ARM_LINKS_EXTENDED[1]`, cross-section TBD.
  Corner origin = the link start; it extends along +x to the end."""
  return Resource(
    name=name,
    size_x=ARM_LINKS_EXTENDED[1],
    size_y=0.0,
    size_z=0.0,
    category="linkage",
    model="PreciseFlex 400",
  )
