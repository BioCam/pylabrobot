"""The two concepts above a device: the space they stand in, and the sets they are driven in.

A `Facility` is a `Resource`, because it is a real cartesian space and everything in it resolves
against its frame. A `Workcell` is deliberately not one. In lab automation a workcell is the set of
instruments one scheduler drives, which is a membership rather than a volume: its extent is only
ever the union of what belongs to it, and nobody surveys an origin for it. Making it a transform
parent would put a derived box in the middle of every coordinate chain for no gain.

The consequence worth having is that a workcell is optional. A shuttle moving between two of them
belongs to neither, and sits directly in the facility's frame with everything else, rather than
forcing a workcell to be invented to hold it.
"""

import logging
from typing import Any, Dict, Iterable, List, Optional

from pylabrobot.resources.coordinate import Coordinate
from pylabrobot.resources.resource import Resource

logger = logging.getLogger(__name__)


class Workcell:
  """A set of resources driven together. A grouping, not a place.

  Args:
    name: what to call the group.
    members: the resources that belong to it. They keep whatever parent they already have; joining
      a workcell does not move anything.
  """

  def __init__(self, name: str, members: Iterable[Resource] = ()):
    self.name = name
    self.members: List[Resource] = []
    self.add(*members)

  def add(self, *resources: Resource) -> "Workcell":
    """Add resources to the group. Returns self, so calls chain."""
    for resource in resources:
      if resource in self.members:
        continue
      self.members.append(resource)
    return self

  def remove(self, resource: Resource) -> None:
    """Take a resource out of the group. It stays exactly where it is."""
    if resource in self.members:
      self.members.remove(resource)

  def __contains__(self, resource: Resource) -> bool:
    return resource in self.members

  def __len__(self) -> int:
    return len(self.members)

  def __repr__(self) -> str:
    return f"Workcell({self.name!r}, {len(self.members)} members)"

  def serialize(self) -> Dict[str, Any]:
    """Names only. The extent is derived from the members wherever it is needed."""
    return {"name": self.name, "members": [member.name for member in self.members]}


class Facility(Resource):
  """The space a site's automation stands in, and the frame everything in it resolves against.

  Its children are whatever is on the floor: workcell members, a shuttle between them, a bench that
  is not automated at all. Grouping is recorded separately, in :attr:`workcells`, so nothing has to
  belong to a workcell to have a place here.
  """

  def __init__(
    self,
    name: str = "facility",
    size_x: float = 10_000.0,
    size_y: float = 10_000.0,
    size_z: float = 3_000.0,
    workcells: Optional[Iterable[Workcell]] = None,
  ):
    """
    Args:
      name: what to call this facility.
      size_x: how wide the space is, in mm.
      size_y: how deep it is, in mm.
      size_z: how tall it is, in mm.
      workcells: groups to start with. More can be added with :meth:`add_workcell`.
    """
    super().__init__(name=name, size_x=size_x, size_y=size_y, size_z=size_z, category="facility")
    # A facility is the frame everything else resolves against, so it sits at its own origin.
    # Without this every absolute lookup below it raises, since the root has nothing to resolve to.
    self.location = Coordinate.zero()
    self.workcells: List[Workcell] = list(workcells or [])

  def add_workcell(self, workcell: Workcell) -> Workcell:
    """Record a group of resources as a workcell.

    Nothing moves: members keep their place in the tree. A member that is not in this facility is
    still recorded, but warned about, since its extent would then be measured against a frame this
    facility does not own.

    Returns:
      The workcell, so it can be kept and added to later.
    """
    for member in workcell.members:
      if not self._contains_descendant(member):
        logger.warning(
          "%s is in workcell %s but not in facility %s", member.name, workcell.name, self.name
        )
    self.workcells.append(workcell)
    return workcell

  def workcell_of(self, resource: Resource) -> Optional[Workcell]:
    """The workcell this resource or an ancestor of it belongs to, if any."""
    node: Optional[Resource] = resource
    while node is not None:
      for workcell in self.workcells:
        if node in workcell:
          return workcell
      node = node.parent
    return None

  def _contains_descendant(self, resource: Resource) -> bool:
    node: Optional[Resource] = resource
    while node is not None:
      if node is self:
        return True
      node = node.parent
    return False

  def serialize_workcells(self) -> List[Dict[str, Any]]:
    return [workcell.serialize() for workcell in self.workcells]
