"""The space a site's automation stands in.

A `Facility` is a `Resource`, because it is a real cartesian space and everything in it resolves
against its frame. Nothing else is needed above a device: the tree is the only structure, and a
machine, a shuttle between machines and a bench that is not automated at all all stand in it the
same way.
"""

from pylabrobot.resources.coordinate import Coordinate
from pylabrobot.resources.resource import Resource


class Facility(Resource):
  """The space a site's automation stands in, and the frame everything in it resolves against.

  Its children are whatever is on the floor: a machine, a shuttle between machines, a bench that is
  not automated at all.
  """

  def __init__(
    self,
    name: str = "facility",
    size_x: float = 10_000.0,
    size_y: float = 10_000.0,
    size_z: float = 3_000.0,
  ):
    """
    Args:
      name: what to call this facility.
      size_x: how wide the space is, in mm.
      size_y: how deep it is, in mm.
      size_z: how tall it is, in mm.
    """
    super().__init__(name=name, size_x=size_x, size_y=size_y, size_z=size_z, category="facility")
    # A facility is the frame everything else resolves against, so it sits at its own origin.
    # Without this every absolute lookup below it raises, since the root has nothing to resolve to.
    self.location = Coordinate.zero()
