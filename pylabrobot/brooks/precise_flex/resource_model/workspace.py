"""An arm's workspace: the region its tool point can reach, as a resource.

An arm has no deck. What stands in a deck's place is its workspace: where the resources it moves
are positioned, and the frame its positions are stated in.
"""

import math
from typing import Optional

from pylabrobot.resources.coordinate import Coordinate
from pylabrobot.resources.resource import Resource


class Workspace(Resource):
  """The reachable workspace of an arm: a ring about the shoulder axis, over the Z travel.

  Located by its corner, as any resource is. The frame the controller reports in has its origin at
  `reference_point` within it: on the shoulder axis, at the flange plane with the Z drive at 0. The
  cuboid is only the ring's bounding box; `is_reachable` uses the ring.
  """

  def __init__(
    self,
    name: str,
    inner_radius: float,
    outer_radius: float,
    z_min: float,
    z_max: float,
    category: str = "workspace",
    model: Optional[str] = None,
  ):
    """
    Args:
      name: what to call this one.
      inner_radius: how near the shoulder axis the tool point can come, in mm.
      outer_radius: how far from the shoulder axis the tool point can reach, in mm.
      z_min: the lowest the tool point can go, in mm above the reference point.
      z_max: the highest the tool point can go, in mm above the reference point.
      category: what kind of resource this is.
      model: which workspace this is.

    Raises:
      ValueError: If the radii or the heights are not in order.
    """
    if not 0 <= inner_radius < outer_radius:
      raise ValueError(f"inner_radius {inner_radius} must be in [0, outer_radius {outer_radius})")
    if not z_min < z_max:
      raise ValueError(f"z_min {z_min} must be below z_max {z_max}")
    super().__init__(
      name=name,
      size_x=2 * outer_radius,
      size_y=2 * outer_radius,
      size_z=z_max - z_min,
      category=category,
      model=model,
    )
    self.inner_radius = inner_radius
    self.outer_radius = outer_radius
    self.z_min = z_min
    self.z_max = z_max

  @property
  def reference_point(self) -> Coordinate:
    """Where the controller's origin sits within it: on its axis, `z_min` below its floor."""
    return Coordinate(self.outer_radius, self.outer_radius, -self.z_min)

  def is_reachable(self, coordinate: Coordinate) -> bool:
    """Whether `coordinate` lies in the ring the tool point can reach.

    A point outside the ring is out of reach. A point inside it may still be: the ring is swept
    over the joints' limits, and does not say which headings a limit leaves out.

    Args:
      coordinate: the point, stated from `reference_point`, as the controller states positions.
    """
    if not self.z_min <= coordinate.z <= self.z_max:
      return False
    return self.inner_radius <= math.hypot(coordinate.x, coordinate.y) <= self.outer_radius

  def serialize(self) -> dict:
    return {
      **super().serialize(),
      "inner_radius": self.inner_radius,
      "outer_radius": self.outer_radius,
      "z_min": self.z_min,
      "z_max": self.z_max,
    }

  @classmethod
  def deserialize(cls, data: dict, allow_marshal: bool = False) -> "Workspace":
    # The sizes follow from the radii and the heights, so `__init__` takes those and not the sizes.
    derived = ("size_x", "size_y", "size_z")
    return super().deserialize(
      {key: value for key, value in data.items() if key not in derived}, allow_marshal=allow_marshal
    )
