"""
ContainerRack: Corrected - Remove unnecessary _assign_to_holder helper
=======================================================================

PROBLEM:
The _assign_to_holder() helper was:
1. Duplicating ResourceHolder.assign_child_resource() logic
2. Silently removing existing containers (hiding errors)
3. Adding implicit behavior that should be explicit

SOLUTION:
Just use ResourceHolder.assign_child_resource() directly with reassign parameter.
"""

from string import ascii_uppercase as LETTERS
from typing import Dict, List, Optional, Sequence, Union, cast

from pylabrobot.resources.coordinate import Coordinate
from pylabrobot.resources.itemized_resource import ItemizedResource
from pylabrobot.resources.resource import Resource
from pylabrobot.resources.resource_holder import ResourceHolder
from pylabrobot.resources.utils import create_ordered_items_2d


class ContainerRack(ItemizedResource[ResourceHolder]):
  """A movable rack for containers with SLAS-compatible footprint.

  Examples:
      >>> # Create rack
      >>> holders = create_ordered_items_2d(...)
      >>> rack = ContainerRack(name="tubes", size_x=127.76, size_y=85.48,
      ...                      size_z=45.0, ordered_items=holders)
      >>>
      >>> # Assignment
      >>> rack["A1"] = my_tube
      >>> rack["A1:A3"] = [tube1, tube2, tube3]
      >>>
      >>> # Access
      >>> tube = rack.get_container("A1")
      >>> has_tube = rack.has_container("A1")
  """

  def __init__(
    self,
    name: str,
    size_x: float,
    size_y: float,
    size_z: float,
    ordered_items: Optional[Dict[str, ResourceHolder]] = None,
    category: str = "container_rack",
    model: Optional[str] = None,
  ):
    """Initialize a ContainerRack."""
    if ordered_items is None or len(ordered_items) == 0:
      raise ValueError("ordered_items must be provided and non-empty")

    # Validate Excel notation
    for identifier in ordered_items.keys():
      if not identifier or identifier[0] not in LETTERS or not identifier[1:].isdigit():
        raise ValueError(
          f"Invalid identifier '{identifier}'. Must be Excel notation like 'A1', 'B2'."
        )

    super().__init__(
      name=name,
      size_x=size_x,
      size_y=size_y,
      size_z=size_z,
      ordered_items=ordered_items,
      category=category,
      model=model,
    )

  def __repr__(self) -> str:
    """String representation."""
    return (
      f"{self.__class__.__name__}(name={self.name!r}, "
      f"size_x={self._size_x}, size_y={self._size_y}, size_z={self._size_z}, "
      f"location={self.location})"
    )

  # =========================================================================
  # CONTAINER ACCESS
  # =========================================================================

  def get_container(self, identifier: Union[str, int]) -> Optional[Resource]:
    """Get the container at a position, or None if empty."""
    holder = self.get_item(identifier)
    return holder.resource if hasattr(holder, "resource") else None

  def get_containers(
    self, identifiers: Union[str, Sequence[int], Sequence[str]]
  ) -> List[Optional[Resource]]:
    """Get containers at multiple positions."""
    holders = self.get_items(identifiers)
    return [holder.resource if hasattr(holder, "resource") else None for holder in holders]

  def has_container(self, identifier: Union[str, int]) -> bool:
    """Check if a position has a container."""
    return self.get_container(identifier) is not None

  def row_containers(self, row: Union[int, str]) -> List[Optional[Resource]]:
    """Get all containers in a row."""
    holders = self.row(row)
    return [holder.resource if hasattr(holder, "resource") else None for holder in holders]

  def column_containers(self, col: int) -> List[Optional[Resource]]:
    """Get all containers in a column."""
    holders = self.column(col)
    return [holder.resource if hasattr(holder, "resource") else None for holder in holders]

  def get_all_containers(self) -> List[Optional[Resource]]:
    """Get all containers in order."""
    all_items = self.get_all_items()
    return [holder.resource if hasattr(holder, "resource") else None for holder in all_items]

  def get_occupied_containers(self) -> List[Resource]:
    """Get all non-empty containers."""
    all_items = self.get_all_items()
    return [
      holder.resource
      for holder in all_items
      if hasattr(holder, "resource") and holder.resource is not None
    ]

  # =========================================================================
  # ASSIGNMENT - CORRECTED (no helper method, use ResourceHolder API directly)
  # =========================================================================

  def __setitem__(
    self,
    identifier: Union[str, int, slice],
    value: Union[Resource, List[Resource], Sequence[Resource]],
  ) -> None:
    """Assign container(s) to position(s).

    By default, replaces existing containers (reassign=True).
    If you want to fail when position is occupied, use holder.assign_child_resource() directly.

    Args:
        identifier: Position(s) to assign to.
        value: Container(s) to assign.

    Examples:
        >>> rack["A1"] = tube                    # Replaces if occupied
        >>> rack["A1:A3"] = [tube1, tube2, tube3]
    """
    # Handle range/slice assignment
    if isinstance(identifier, slice) or (isinstance(identifier, str) and ":" in identifier):
      holders = self[identifier]  # Returns List[ResourceHolder]

      if not isinstance(value, (list, tuple)):
        raise ValueError(
          f"When assigning to a range, value must be a list or tuple, "
          f"not {type(value).__name__}"
        )

      if len(holders) != len(value):
        raise ValueError(
          f"Number of containers ({len(value)}) must match " f"number of positions ({len(holders)})"
        )

      # Assign each container using ResourceHolder's API
      for holder, container in zip(holders, value):
        holder.assign_child_resource(container, reassign=True)

    # Handle single assignment
    else:
      if isinstance(value, (list, tuple)):
        raise ValueError(
          f"Cannot assign list to single position '{identifier}'. "
          f"Use a range like 'A1:A3' for batch assignment."
        )

      holder = self.get_item(identifier)
      # Use ResourceHolder's assign_child_resource directly
      # reassign=True means it will replace existing container
      holder.assign_child_resource(value, reassign=True)

  def __delitem__(self, identifier: Union[str, int, slice]) -> None:
    """Remove container(s) from position(s).

    Examples:
        >>> del rack["A1"]
        >>> del rack["A1:A3"]
    """
    if isinstance(identifier, slice) or (isinstance(identifier, str) and ":" in identifier):
      holders = self[identifier]
      for holder in holders:
        if holder.resource is not None:
          holder.unassign_child_resource(holder.resource)
    else:
      holder = self.get_item(identifier)
      if holder.resource is not None:
        holder.unassign_child_resource(holder.resource)

  # =========================================================================
  # STATE MANAGEMENT
  # =========================================================================

  def empty(self) -> None:
    """Remove all containers from the rack."""
    for holder in self.get_all_items():
      if holder.resource is not None:
        holder.unassign_child_resource(holder.resource)

  @staticmethod
  def _occupied_func(item: ResourceHolder) -> str:
    """Get occupation status for summary display."""
    return "O" if hasattr(item, "resource") and item.resource is not None else "-"
