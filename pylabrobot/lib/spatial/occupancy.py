"""Where resources are in the tree's space: which one a point falls into."""

from typing import Collection, Optional

from pylabrobot.resources.coordinate import Coordinate
from pylabrobot.resources.resource import Resource


def get_resource_at_location(
  location: Coordinate,
  reference_frame: Resource,
  exclude: Collection[Resource] = (),
) -> Optional[Resource]:
  """The deepest resource under `reference_frame` whose box `location` falls into, in all three axes.

  A point inside a plate on a carrier site is the plate; inside the carrier beside it, the carrier
  or its site. A point on a top face is in nothing, so one on the deck, or resting on top of
  something, is free.

  Args:
    location: the point, in mm, in `reference_frame`'s frame.
    reference_frame: the resource `location` is measured from, whose subtree is searched, e.g. a
      deck.
    exclude: resources to leave out, with everything under them, e.g. what a moving arm carries.

  Returns:
    The resource, or None if the point falls into none.
  """

  def count_parents_between(resource: Resource, ancestor: Resource) -> int:
    """How many parents lie between `resource` and `ancestor`: 0 for a child of `ancestor`."""
    count, current = 0, resource.parent
    while current is not None and current is not ancestor:
      count, current = count + 1, current.parent
    return count

  found: Optional[Resource] = None
  found_parents = -1
  for resource in reference_frame.get_all_children():
    if any(resource.is_in_subtree_of(excluded) for excluded in exclude):
      continue
    lfb = resource.get_location_wrt(reference_frame, "l", "f", "b")
    inside = (
      lfb.x <= location.x < lfb.x + resource.get_absolute_size_x()
      and lfb.y <= location.y < lfb.y + resource.get_absolute_size_y()
      and lfb.z <= location.z < lfb.z + resource.get_absolute_size_z()
    )
    if not inside:
      continue
    parents = count_parents_between(resource, reference_frame)
    if parents > found_parents:
      found, found_parents = resource, parents
  return found
