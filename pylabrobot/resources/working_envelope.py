"""A robot arm's reachable workspace, modelled as a Resource (the arm's analog of a Deck).

Design rationale: a `Deck` bundles {device root frame} + {child registry} + {bounded region}; for an
arm the bounded region is not a flat rectangle but the reachable annular cylinder swept by the links
over the Z travel, optionally extruded along a linear rail. `WorkingEnvelope` is that bundle for an
arm. The intended end-state is a shared `Workspace(Resource)` super-class with `Deck` and
`WorkingEnvelope` as the rectangular and annular concretes.
"""

import math
from typing import Literal, Optional

from pylabrobot.resources.coordinate import Coordinate
from pylabrobot.resources.resource import Resource

RailAxis = Literal["x", "y"]


class WorkingEnvelope(Resource):
  """A robot arm's reachable workspace.

  The arm analog of a `Deck`: the device's root coordinate frame *and* the bound on where the arm can
  operate. The origin is the arm's base frame - for a SCARA, the shoulder (J2) axis, which is the
  device ``x=0, y=0`` on every unit. The reachable region is an annular cylinder: planar radius in
  ``[inner_radius, outer_radius]`` over ``[z_min, z_max]``. With a linear rail it extrudes along
  ``rail_axis`` (``"x"`` or ``"y"`` - a model parameter, since PLR owns the client-side kinematics)
  by ``rail_travel`` into a capsule.

  Two deliberate deviations from a typical Resource, both documented in the design note:
  - the origin is the **centre** of the reachable disk (the device frame), so the bounding box is
    centred on the origin in x/y rather than corner-anchored;
  - the cuboid ``size_x/y/z`` is only a conservative bound - reachability is :meth:`is_reachable`,
    which uses the true annular geometry, never the box.
  """

  def __init__(
    self,
    name: str,
    inner_radius: float,
    outer_radius: float,
    z_min: float,
    z_max: float,
    rail_axis: Optional[RailAxis] = None,
    rail_travel: float = 0.0,
    category: str = "working_envelope",
    model: Optional[str] = None,
  ):
    if not 0 <= inner_radius < outer_radius:
      raise ValueError(f"require 0 <= inner_radius < outer_radius, got {inner_radius}, {outer_radius}")
    if z_max <= z_min:
      raise ValueError(f"require z_min < z_max, got {z_min}, {z_max}")
    if rail_travel < 0:
      raise ValueError(f"rail_travel must be >= 0, got {rail_travel}")
    if rail_axis is None and rail_travel != 0.0:
      raise ValueError("rail_travel set without a rail_axis")

    self.inner_radius = inner_radius
    self.outer_radius = outer_radius
    self.z_min = z_min
    self.z_max = z_max
    self.rail_axis: Optional[RailAxis] = rail_axis
    self.rail_travel = rail_travel

    # Bounding cuboid: the disk spans 2*outer in each planar axis; the rail lengthens one of them by L.
    super().__init__(
      name=name,
      size_x=2 * outer_radius + (rail_travel if rail_axis == "x" else 0.0),
      size_y=2 * outer_radius + (rail_travel if rail_axis == "y" else 0.0),
      size_z=z_max - z_min,
      category=category,
      model=model,
    )

  @property
  def bounds(self) -> tuple:
    """``(xmin, xmax, ymin, ymax, zmin, zmax)`` of the bounding box *relative to the origin* (the
    shoulder axis). Asymmetric when railed: the rail extends the +axis only (``0 -> L`` from the
    controller home end), so the origin is not the box centre - design choice (a)."""
    return (
      -self.outer_radius,
      self.outer_radius + (self.rail_travel if self.rail_axis == "x" else 0.0),
      -self.outer_radius,
      self.outer_radius + (self.rail_travel if self.rail_axis == "y" else 0.0),
      self.z_min,
      self.z_max,
    )

  def is_reachable(self, coordinate: Coordinate) -> bool:
    """Whether ``coordinate`` (in this envelope's frame, origin = the arm base axis) is reachable.

    The rail sweeps the annulus centre along the rail axis over ``[0, rail_travel]``. A point is in
    the swept ring iff some offset ``s`` puts it between the inner and outer radius - equivalently the
    nearest centre is within ``outer_radius`` *and* the farthest centre is at least ``inner_radius``
    (so the point is not inside every inner hole). With no rail this collapses to a plain annulus.
    """
    if not (self.z_min <= coordinate.z <= self.z_max):
      return False
    # Put the rail axis on the first coordinate (hypot is symmetric, so swapping is exact).
    a, b = (coordinate.x, coordinate.y) if self.rail_axis != "y" else (coordinate.y, coordinate.x)
    travel = self.rail_travel
    nearest = math.hypot(a - min(max(a, 0.0), travel), b)
    farthest = max(math.hypot(a, b), math.hypot(a - travel, b))
    return nearest <= self.outer_radius and farthest >= self.inner_radius
