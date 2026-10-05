"""An arm's workspace: the region its tool point can reach, as a resource.

An arm has no deck. What stands in a deck's place is its workspace: where the resources it moves
are positioned, and the frame its positions are stated in.
"""

from typing import List, Optional, Sequence, Tuple

from pylabrobot.resources.coordinate import Coordinate
from pylabrobot.resources.resource import Resource


class Workspace(Resource):
  """The reachable workspace of an arm: the region within its boundary, over the Z travel.

  Located by its corner, as any resource is. The frame the controller reports in has its origin at
  `reference_point` within it: on the shoulder axis, at the flange plane with the Z drive at 0. The
  cuboid is only the boundary's bounding box; `is_reachable` uses the boundary.
  """

  def __init__(
    self,
    name: str,
    boundary: Sequence[Tuple[float, float]],
    z_min: float,
    z_max: float,
    category: str = "workspace",
    model: Optional[str] = None,
  ):
    """
    Args:
      name: what to call this one.
      boundary: the points (x, y) the tool point reaches out to, from the shoulder axis, in mm, in
        order round it.
      z_min: the lowest the tool point can go, in mm above the reference point.
      z_max: the highest the tool point can go, in mm above the reference point.
      category: what kind of resource this is.
      model: which workspace this is.

    Raises:
      ValueError: If the boundary encloses nothing or the heights are not in order.
    """
    if len(boundary) < 3:
      raise ValueError(f"a boundary takes at least 3 points, not {len(boundary)}")
    if not z_min < z_max:
      raise ValueError(f"z_min {z_min} must be below z_max {z_max}")
    self.boundary: List[Tuple[float, float]] = [(float(x), float(y)) for x, y in boundary]
    self._x_min = min(x for x, _ in self.boundary)
    self._y_min = min(y for _, y in self.boundary)
    super().__init__(
      name=name,
      size_x=max(x for x, _ in self.boundary) - self._x_min,
      size_y=max(y for _, y in self.boundary) - self._y_min,
      size_z=z_max - z_min,
      category=category,
      model=model,
    )
    self.z_min = z_min
    self.z_max = z_max

  @property
  def reference_point(self) -> Coordinate:
    """Where the controller's origin sits within it: on its axis, `z_min` below its floor."""
    return Coordinate(-self._x_min, -self._y_min, -self.z_min)

  def is_reachable(self, coordinate: Coordinate) -> bool:
    """Whether `coordinate` lies within the boundary the tool point can reach.

    A point outside it is out of reach. A point inside it may still be: the boundary is swept over
    the joints' limits, and does not know what the arm would hit on the way.

    Args:
      coordinate: the point, stated from `reference_point`, as the controller states positions.
    """
    if not self.z_min <= coordinate.z <= self.z_max:
      return False
    inside = False
    for (x_1, y_1), (x_2, y_2) in zip(self.boundary, self.boundary[1:] + self.boundary[:1]):
      # Count the edges a line drawn from the point along +x crosses: an odd count is inside.
      if (y_1 > coordinate.y) != (y_2 > coordinate.y):
        if coordinate.x < x_1 + (coordinate.y - y_1) * (x_2 - x_1) / (y_2 - y_1):
          inside = not inside
    return inside

  def serialize(self) -> dict:
    return {
      **super().serialize(),
      "boundary": [list(point) for point in self.boundary],
      "z_min": self.z_min,
      "z_max": self.z_max,
    }

  @classmethod
  def deserialize(cls, data: dict, allow_marshal: bool = False) -> "Workspace":
    # The sizes follow from the boundary and the heights, so `__init__` takes those, not the sizes.
    derived = ("size_x", "size_y", "size_z")
    return super().deserialize(
      {key: value for key, value in data.items() if key not in derived}, allow_marshal=allow_marshal
    )
