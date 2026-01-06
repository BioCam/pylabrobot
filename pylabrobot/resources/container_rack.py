"""A movable rack for containers (with SLAS-compatible footprint)."""

from string import ascii_uppercase as LETTERS
from typing import Dict, List, Optional, Sequence, Union

from pylabrobot.resources.itemized_resource import ItemizedResource
from pylabrobot.resources.resource import Resource
from pylabrobot.resources.resource_holder import ResourceHolder


class ContainerRack(ItemizedResource[ResourceHolder]):
  """A movable rack for containers (with SLAS-compatible footprint).

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
      >>> # Access (raises error if empty)
      >>> tube = rack.get_container("A1")
      >>>
      >>> # Check first
      >>> if rack.has_container("A1"):
      ...     tube = rack.get_container("A1")
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

  def get_container(self, identifier: Union[str, int]) -> Resource:
    """Get the container at a position.

    Raises error if position is empty. Use has_container() to check first.

    Args:
        identifier: Position identifier ("A1" or 0).

    Returns:
        The container at that position.

    Raises:
        ValueError: If position is empty.

    Examples:
        >>> # Check first
        >>> if rack.has_container("A1"):
        ...     tube = rack.get_container("A1")
        >>>
        >>> # Or handle the error
        >>> try:
        ...     tube = rack.get_container("A1")
        ... except ValueError:
        ...     print("Position A1 is empty")
    """
    holder = self.get_item(identifier)
    if holder.resource is None:
      raise ValueError(
        f"No container at position {identifier} in rack '{self.name}'. "
        f"Use has_container() to check first."
      )
    return holder.resource

  def get_containers(self, identifiers: Union[str, Sequence[int], Sequence[str]]) -> List[Resource]:
    """Get containers at multiple positions.

    All positions must have containers, otherwise raises error.

    Args:
        identifiers: Position identifiers.

    Returns:
        List of containers.

    Raises:
        ValueError: If any position is empty.

    Examples:
        >>> tubes = rack.get_containers("A1:A4")
        >>> tubes = rack.get_containers([0, 1, 2, 3])
    """
    holders = self.get_items(identifiers)
    containers = []
    for i, holder in enumerate(holders):
      if holder.resource is None:
        # Try to get identifier for better error message
        try:
          ident = self.get_child_identifier(holder)
        except (ValueError, AttributeError):
          ident = f"index {i}"
        raise ValueError(f"No container at position {ident} in rack '{self.name}'. ")
      containers.append(holder.resource)
    return containers

  def has_container(self, identifier: Union[str, int]) -> bool:
    """Check if a position has a container.

    Args:
        identifier: Position identifier ("A1" or 0).

    Returns:
        True if position has a container, False if empty.

    Examples:
        >>> if rack.has_container("A1"):
        ...     tube = rack.get_container("A1")
    """
    holder = self.get_item(identifier)
    return holder.resource is not None

  def row_containers(self, row: Union[int, str]) -> List[Resource]:
    """Get all containers in a row.

    All positions in the row must have containers.

    Raises:
        ValueError: If any position in the row is empty.
    """
    holders = self.row(row)
    containers = []
    for holder in holders:
      if holder.resource is None:
        ident = self.get_child_identifier(holder)
        raise ValueError(f"No container at position {ident} in rack '{self.name}'. ")
      containers.append(holder.resource)
    return containers

  def column_containers(self, col: int) -> List[Resource]:
    """Get all containers in a column.

    All positions in the column must have containers.

    Raises:
        ValueError: If any position in the column is empty.
    """
    holders = self.column(col)
    containers = []
    for holder in holders:
      if holder.resource is None:
        ident = self.get_child_identifier(holder)
        raise ValueError(f"No container at position {ident} in rack '{self.name}'. ")
      containers.append(holder.resource)
    return containers

  def get_all_containers(self) -> List[Resource]:
    """Get all containers in order.

    All positions must have containers.

    Raises:
        ValueError: If any position is empty.
    """
    all_items = self.get_all_items()
    containers = []
    for holder in all_items:
      if holder.resource is None:
        ident = self.get_child_identifier(holder)
        raise ValueError(
          f"No container at position {ident} in rack '{self.name}'. "
          f"Use get_all_containers_if_present() for optional access."
        )
      containers.append(holder.resource)
    return containers

  def get_occupied_containers(self) -> List[Resource]:
    """Get all non-empty containers (only occupied positions)."""
    all_items = self.get_all_items()
    return [holder.resource for holder in all_items if holder.resource is not None]

  # =========================================================================
  # ASSIGNMENT
  # =========================================================================

  def __setitem__(
    self,
    identifier: Union[str, int, slice],
    value: Union[Resource, List[Resource], Sequence[Resource]],
  ) -> None:
    """Assign container(s) to position(s).

    By default, replaces existing containers (reassign=True).

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
          f"Number of containers ({len(value)}) must match number of positions ({len(holders)})"
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
      holder.assign_child_resource(value, reassign=True)

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
    return "O" if item.resource is not None else "-"
