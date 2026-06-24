"""PreciseFlex 400 physical resource model: base_plate, z_column, shoulder, linkages.

Built up in the World/device frame: origin = the J2 shoulder axis at the J1-low tool-flange plane,
+x forward (reach), +y left, +z up. Dimensions are the measured ground truth for the extended-reach
(XR) PF400.
"""

from pylabrobot.brooks.precise_flex.kinematics import ARM_LINKS_EXTENDED
from pylabrobot.resources.coordinate import Coordinate
from pylabrobot.resources.resource import Resource

BASE_PLATE_X, BASE_PLATE_Y, BASE_PLATE_Z = 200.8, 235.1, 9.6
BASE_PLATE_BOTTOM_OFFSET = 62.0  # base_plate bottom this far below the World origin (J1-low flange plane)

Z_COLUMN_X, Z_COLUMN_Y = 123.5, 181.0

# linkage physical envelopes: CAD-measured cross-section (width Y, height Z) plus a length (X) =
# the extended kinematic length + a hub overhang at each end (the round joint end-bosses).
LINKAGE_1_HUB_OVERHANG = 57.0  # inner link, both ends (= half-width, full hubs: shoulder + elbow)
# outer link is asymmetric: a full hub at the elbow, a smaller tapered end at the wrist.
LINKAGE_2_HUB_PROXIMAL = 56.0  # outer link, elbow end (= half-width, full hub)
LINKAGE_2_HUB_DISTAL = 36.0  # outer link, wrist end (smaller; tapers to the gripper mount)
LINKAGE_1_ENVELOPE_Y, LINKAGE_1_ENVELOPE_Z = 114.0, 77.7  # inner width, height
LINKAGE_2_ENVELOPE_Y, LINKAGE_2_ENVELOPE_Z = 112.0, 39.2  # outer width, height
LINKAGE_1_ENVELOPE_X = ARM_LINKS_EXTENDED[0] + 2 * LINKAGE_1_HUB_OVERHANG  # 416
LINKAGE_2_ENVELOPE_X = ARM_LINKS_EXTENDED[1] + LINKAGE_2_HUB_PROXIMAL + LINKAGE_2_HUB_DISTAL  # 381
# z-clearance between stacked arm bodies:
LINK_Z_GAP = 1.0


def base_plate(name: str = "pf400_base_plate") -> Resource:
  """PreciseFlex 400 base plate - a cuboid, 200.8 (x) x 235.1 (y) x 9.6 (z) mm."""
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

  `total_height` is the whole structure height (base_plate bottom -> z_column top); the column sits on
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

# shoulder body dimensions, measured from the CAD (extended-reach PF400 shoulder housing):
SHOULDER_X = 122.8  # reach (depth)
SHOULDER_Y = 110.0  # width
SHOULDER_Z = 56.25  # height
# shoulder placement on the z_column (child location, relative to z_column corner origin):
SHOULDER_DX = Z_COLUMN_X  # starts at the column front (+x) face
SHOULDER_DY = (Z_COLUMN_Y - SHOULDER_Y) / 2  # centred in y on the column
SHOULDER_DZ = (
  BASE_PLATE_BOTTOM_OFFSET
  - BASE_PLATE_Z
  + LINK_Z_GAP
  + LINKAGE_1_ENVELOPE_Z
  + LINK_Z_GAP
  + LINKAGE_2_ENVELOPE_Z
)  # shoulder bottom raised to z = 118.9, above the stacked inner + outer link envelopes


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
  """PreciseFlex 400 shoulder - the J2 rotary housing, a cuboid of the CAD-measured body size.

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
  """PreciseFlex 400 linkage 1 (inner link, shoulder -> elbow) - full physical envelope.

  A cuboid LINKAGE_1_ENVELOPE_X (length) x _Y (width) x _Z (height). The kinematic length
  `ARM_LINKS_EXTENDED[0]` runs along the bottom (z = 0) face, centred in width and inset by
  LINKAGE_1_HUB_OVERHANG at each end; the body rises from the kinematic line to +z."""
  return Resource(
    name=name,
    size_x=LINKAGE_1_ENVELOPE_X,
    size_y=LINKAGE_1_ENVELOPE_Y,
    size_z=LINKAGE_1_ENVELOPE_Z,
    category="linkage",
    model="PreciseFlex 400",
  )


def linkage_2(name: str = "pf400_linkage_2") -> Resource:
  """PreciseFlex 400 linkage 2 (outer link, elbow -> wrist) - full physical envelope.

  A cuboid LINKAGE_2_ENVELOPE_X (length) x _Y (width) x _Z (height). The kinematic length
  `ARM_LINKS_EXTENDED[1]` runs along the bottom (z = 0) face, centred in width, inset by
  LINKAGE_2_HUB_PROXIMAL at the elbow and LINKAGE_2_HUB_DISTAL at the wrist (asymmetric - the wrist
  sits closer to the front edge); the body rises from the kinematic line to +z."""
  return Resource(
    name=name,
    size_x=LINKAGE_2_ENVELOPE_X,
    size_y=LINKAGE_2_ENVELOPE_Y,
    size_z=LINKAGE_2_ENVELOPE_Z,
    category="linkage",
    model="PreciseFlex 400",
  )
