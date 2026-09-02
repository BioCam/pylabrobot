from __future__ import annotations

import logging
import warnings
from abc import ABCMeta, abstractmethod
from typing import Literal, Optional, cast

from pylabrobot.resources.carrier import Carrier, ResourceHolder
from pylabrobot.resources.coordinate import Coordinate
from pylabrobot.resources.deck import Deck
from pylabrobot.resources.errors import NoLocationError
from pylabrobot.resources.hamilton.core_grippers import HamiltonCoreGrippers
from pylabrobot.resources.resource import Resource
from pylabrobot.resources.trash import Trash

logger = logging.getLogger(__name__)

STARLET_NUM_TRACKS = 30
STAR_NUM_TRACKS = 54
STARPLUS_NUM_TRACKS = 76


_TRACK_WIDTH = 22.5  # space between rails (mm)

# Where a carrier's own front edge sits on any Hamilton deck, in mm.
_CARRIER_Y = 63.0

# Parts of the MACHINE that happen to hang off the deck, as opposed to things placed ON it. They are
# fitted where the instrument puts them, not assigned to rails, so they cannot occupy a rail and
# must not be treated as though they do - a fitted autoload otherwise makes rail 1 unassignable,
# because the sled's box reaches over the deck's front edge and up past a carrier's height.
_MACHINE_PARTS = frozenset({"autoload_sled", "autoload_loading_tray"})


def track_for_x_coordinate(x: float) -> int:
  """Which track an x coordinate falls on.

  Args:
    x: the coordinate, in this deck's own frame.

  Returns:
    The track, counted from 1.
  """
  return int((x - 100.0) / _TRACK_WIDTH) + 1


def rails_for_x_coordinate(x: float) -> int:
  """Deprecated. Use `track_for_x_coordinate`.

  Args:
    x: the coordinate, in this deck's own frame.

  Returns:
    What `track_for_x_coordinate` returns for it.
  """
  warnings.warn(
    "`rails_for_x_coordinate` is deprecated, use `track_for_x_coordinate`: a track is the part of"
    " the deck, and a rail is part of a carrier.",
    DeprecationWarning,
    stacklevel=2,
  )
  return track_for_x_coordinate(x)


def _tracks_from(num_tracks: Optional[int], num_rails: Optional[int]) -> int:
  """The track count, from whichever argument carried it.

  Args:
    num_tracks: the count.
    num_rails: the same count under its old name.

  Returns:
    The count.

  Raises:
    TypeError: If neither was given.
  """
  if num_tracks is not None:
    return num_tracks
  if num_rails is None:
    raise TypeError("num_tracks is required")
  warnings.warn(
    "`num_rails` is deprecated, use `num_tracks`: a track is the part of the deck, and a rail is"
    " part of a carrier.",
    DeprecationWarning,
    stacklevel=3,
  )
  return num_rails


class HamiltonDeck(Deck, metaclass=ABCMeta):
  """Hamilton decks. Currently only STARLet, STAR and Vantage are supported."""

  def __init__(
    self,
    size_x: float,
    size_y: float,
    size_z: float,
    num_tracks: Optional[int] = None,
    name: str = "deck",
    category: str = "deck",
    origin: Coordinate = Coordinate.zero(),
    num_rails: Optional[int] = None,
  ):
    super().__init__(
      name=name,
      size_x=size_x,
      size_y=size_y,
      size_z=size_z,
      category=category,
      origin=origin,
    )
    self.num_tracks = _tracks_from(num_tracks, num_rails)

    self.register_did_assign_resource_callback(self._check_safe_z_height)

  @abstractmethod
  def track_to_location(self, track: int) -> Coordinate:
    """Where a track starts on this deck.

    Args:
      track: the track, counted from 1.

    Returns:
      Its position, in this deck's own frame.
    """

  def rails_to_location(self, rails: int) -> Coordinate:
    """Deprecated. Use `track_to_location`.

    Args:
      rails: the track, counted from 1.

    Returns:
      What `track_to_location` returns for it.
    """
    warnings.warn(
      "`rails_to_location` is deprecated, use `track_to_location`: a track is the part of the deck,"
      " and a rail is part of a carrier.",
      DeprecationWarning,
      stacklevel=2,
    )
    return self.track_to_location(rails)

  def compute_right_track_of_carrier(self, carrier: Carrier) -> int:
    """The last track a carrier covers, from where it sits on this deck.

    Args:
      carrier: the carrier, which must be on this deck.

    Returns:
      The track, counted from 1.
    """
    end_x = carrier.get_location_wrt(self).x + carrier.get_absolute_size_x()
    return track_for_x_coordinate(end_x) - 1

  def get_carrier_at_track(self, track: int) -> Carrier:
    """The carrier covering a track, from where the carriers sit on this deck.

    A carrier covers every track from the one it is placed at to
    `compute_right_track_of_carrier`, so a six-track carrier at track 15 answers for 15 to 20. This
    finds it from any of them, which is what lets a caller name a carrier by the track it was put
    at while the autoload addresses it by its rightmost.

    Args:
      track: any track the carrier covers, counted from 1.

    Returns:
      The carrier there.

    Raises:
      ValueError: If no carrier on this deck covers that track.
    """
    for child in self.children:
      if not isinstance(child, Carrier):
        continue
      left = track_for_x_coordinate(child.get_location_wrt(self).x)
      if left <= track <= self.compute_right_track_of_carrier(child):
        return child
    raise ValueError(f"no carrier on this deck covers track {track}")

  def get_or_create_x_arm(
    self,
    name: str,
    x: float,
    width: float,
    model: str,
    reference_anchor: Literal["l", "c", "r"],
  ) -> Resource:
    """Get, or create once, the deck-owned X-arm resource called `name`.

    The deck owns it: created as a child the first time and reused thereafter, so repeated setups
    do not duplicate it. It is placed so its reference point sits at the arm's current x.

    Args:
      name: what to call it, e.g. "left_x_arm".
      x: where the arm is now, in mm, at its reference point.
      width: how wide the arm is, in mm, as the machine reports it.
      model: which arm this is.
      reference_anchor: where along the width `x` refers to, as an anchor: `"c"` for a dual-rail
        arm, `"r"` for a single-rail one.

    Returns:
      The arm resource, whether it was just created or already there.
    """
    if self.has_resource(name):
      return self.get_resource(name)
    # The arm rides at the channel stop-disk safety height, level with the raised stop discs so it
    # clears them as it travels.
    arm_z, size_z, size_y = 334.7, 140.0, 712.0
    x_arm = Resource(
      name=name,
      size_x=width,
      size_y=size_y,
      size_z=size_z,
      category="x_arm",
      model=model,
    )
    # Place it so its reference point lands at the arm's current x, and so its back edge lines up
    # with the back of the deck. Being deeper than the deck, it reaches in front of the deck's front
    # edge, which is why y is negative. The arm sits above the deck plane, so it does not count as
    # occupying the footprint of the carriers beneath it.
    anchor = x_arm.get_anchor(x=reference_anchor)
    y = self.get_absolute_size_y() - size_y
    self.assign_child_resource(x_arm, location=Coordinate(x - anchor.x, y, arm_z))
    return x_arm

  def get_or_create_autoload_sled(
    self, name: str, x: float, reference_point_from_left: float
  ) -> Resource:
    """Get, or create once, the deck-owned autoload sled.

    The deck owns it: created as a child the first time and reused thereafter, so repeated setups
    do not duplicate it.

    Args:
      name: where the carrier-handling wheel is, in mm, on this deck. The wheel is the point the
        drive reports, so the sled is placed around it.
      x: where the wheel is, in mm, on this deck.
      reference_point_from_left: how far the point the drive reports - the carrier-handling
        wheel - sits from the sled's left edge, in mm.

    Returns:
      The sled resource, whether it was just created or already there.
    """
    if self.has_resource(name):
      return self.get_resource(name)
    # The whole part, transport and barcode reader, off the manufacturer's model. Its left edge is
    # a thin tab reaching 40 mm further left than the body, so a distance measured into this box
    # starts at the tab.
    size_x, size_y, size_z = 316.2, 109.5, 215.3
    # Against a carrier's own front edge, and the deck's work surface.
    ahead_of_carrier_y, above_deck_z = 92.7, 0.5
    sled = Resource(
      name=name,
      size_x=size_x,
      size_y=size_y,
      size_z=size_z,
      category="autoload_sled",
      model="hamilton_star_autoload_sled",
    )
    # What the drive's x actually refers to. The sled is placed around the carrier-handling wheel,
    # so its own origin is not what the machine reports - saying where the wheel sits within it is
    # what lets anything reading this resource put the two together, a viewer included.
    sled.reference_point = {  # type: ignore[attr-defined]
      "x": reference_point_from_left
    }
    self.assign_child_resource(
      sled,
      location=Coordinate(
        x - reference_point_from_left,
        _CARRIER_Y - ahead_of_carrier_y,
        above_deck_z,
      ),
    )
    return sled

  def get_or_create_autoload_loading_tray(self, name: str) -> Resource:
    """Get, or create once, the deck-owned loading tray the autoload draws carriers from.

    It is placed against the deck features it lines up with: its left edge sits 104 mm left of the
    first carrier, and its front edge 380 mm in front of a carrier's. It reaches the same 104 mm
    short of the deck's right edge, so its width follows from the deck. Created as a child the
    first time and reused thereafter, so repeated setups do not duplicate it.

    Its own track markings line up with the deck's, so a carrier put on the tray at a track goes to
    that same track on the deck.

    Args:
      name: what to call it.

    Returns:
      The tray resource, whether it was just created or already there.
    """
    if self.has_resource(name):
      return self.get_resource(name)
    # Measured against the two things on the deck it lines up with: where the first carrier starts,
    # and a carrier's front edge. It insets the same amount from the deck's right edge as from its
    # left, which is what sizes it.
    from_first_carrier_x, front_ahead_y, back_ahead_y, size_z = 104.0, 380.0, 132.0, 92.0
    left = self.track_to_location(1).x - from_first_carrier_x
    tray = Resource(
      name=name,
      size_x=self.get_absolute_size_x() - from_first_carrier_x - left,
      size_y=front_ahead_y - back_ahead_y,
      size_z=size_z,
      category="autoload_loading_tray",
      model="hamilton_star_autoload_loading_tray",
    )
    self.assign_child_resource(tray, location=Coordinate(left, _CARRIER_Y - front_ahead_y, 0.0))
    return tray

  def serialize(self) -> dict:
    """Serialize this deck."""
    return {
      **super().serialize(),
      "num_tracks": self.num_tracks,
      "with_trash": False,  # data encoded as child. (not very pretty to have this key though...)
      "with_trash96": False,
      "core_grippers": None,  # data encoded as child. (not very pretty to have this key though...)
    }

  def _check_safe_z_height(self, resource: Resource):
    """Check for this resource, and all its children, that the z location is not too high."""

    # TODO: maybe these are parameters per HamiltonDeck that we can take as attributes.
    Z_MOVEMENT_LIMIT = 245
    Z_GRAB_LIMIT = 285

    def check_z_height(resource: Resource):
      # What the machine carries belongs up there: it rides above the deck by design, and nothing
      # traverses or grabs it, so the warnings below say nothing about it.
      if resource.category in ("x_arm", "head96"):
        return

      try:
        z_top = resource.get_location_wrt(self, z="top").z
      except NoLocationError:
        # if a resource has no location, we cannot check its z height
        # this is fine, because it's a convenience feature and not critical
        return

      if z_top > Z_MOVEMENT_LIMIT:
        logger.warning(
          "Resource '%s' is very high on the deck: %s mm. Be careful when traversing the deck.",
          resource.name,
          z_top,
        )

      if z_top > Z_GRAB_LIMIT:
        logger.warning(
          "Resource '%s' is very high on the deck: %s mm. Be careful when grabbing this resource.",
          resource.name,
          z_top,
        )

      for child in resource.children:
        check_z_height(child)

    check_z_height(resource)

  def assign_child_resource(
    self,
    resource: Resource,
    location: Optional[Coordinate] = None,
    reassign: bool = False,
    track: Optional[int] = None,
    rails: Optional[int] = None,
    replace=False,
    ignore_collision=False,
  ):
    """Assign a new deck resource.

    The identifier will be the Resource.name, which must be unique amongst previously assigned
    resources.

    Note that some resources, such as tips on a tip carrier or plates on a plate carrier must
    be assigned directly to the tip or plate carrier respectively. See TipCarrier and PlateCarrier
    for details.

    Given a track, the absolute (x, y, z) coordinates are computed from it.

    Args:
      resource: A Resource to assign to this liquid handler.
      location: Where to put it, relative to this deck. Either this or `track`, not both.
      reassign: If True, reassign the resource if it is already assigned. If False, raise a
        `ValueError` if the resource is already assigned.
      track: The leftmost track the resource covers, counted from 1 as the markings on the machine
        are, and down to -4 for the supports left of the first one. Either this or `location`, not
        both.
      rails: Deprecated, use `track`.
      replace: Replace the resource with the same name that was previously assigned, if it exists.
        If a resource is assigned with the same name and replace is False, a ValueError
        will be raised.
      ignore_collision: If True, ignore collision detection.

    Raises:
      ValueError: If a resource is assigned with the same name and replace is `False`.
    """

    # TODO: many things here should be moved to Resource and Deck, instead of just STARLetDeck

    if rails is not None:
      if track is not None:
        raise ValueError("pass track, not both track and rails")
      warnings.warn(
        "`rails` is deprecated, use `track`: a track is the part of the deck, and a rail is part"
        " of a carrier.",
        DeprecationWarning,
        stacklevel=2,
      )
      track = rails

    if track is not None and not -4 <= track <= self.num_tracks:
      raise ValueError(f"Track must be between -4 and {self.num_tracks}.")

    # Check if resource exists.
    if self.has_resource(resource.name):
      if replace:
        # unassign first, so we don't have problems with location checking later.
        cast(Resource, self.get_resource(resource.name)).unassign()
      else:
        raise ValueError(f"Resource with name '{resource.name}' already defined.")

    if track is not None:
      resource_location = self.track_to_location(track)
    elif location is not None:
      resource_location = location
    else:
      raise ValueError("Either track or location must be provided.")

    def should_check_collision(res: Resource) -> bool:
      """Determine if collision detection should be performed for this resource."""
      if isinstance(res, (HamiltonCoreGrippers, Trash)):
        return False
      return True

    if not ignore_collision and should_check_collision(resource):
      if resource_location is not None:  # collision detection
        if (
          resource_location.x + resource.get_absolute_size_x()
          > self.track_to_location(self.num_tracks + 1).x
          and track is not None
        ):
          raise ValueError(
            f"Resource with width {resource.get_absolute_size_x()} does not fit at track {track}."
          )

        # Check if there is space for this new resource.
        for og_resource in self.children:
          if og_resource.category in _MACHINE_PARTS:
            continue
          og_x = cast(Coordinate, og_resource.location).x
          og_y = cast(Coordinate, og_resource.location).y
          og_z = cast(Coordinate, og_resource.location).z

          # A resource is not allowed to overlap with another resource. Resources overlap when
          # their bounding boxes intersect on all three axes. The z axis is included so a resource
          # above the deck plane does not block placement beneath it.
          x_overlap = any(
            [
              og_x <= resource_location.x < og_x + og_resource.get_absolute_size_x(),
              og_x
              < resource_location.x + resource.get_absolute_size_x()
              < og_x + og_resource.get_absolute_size_x(),
            ]
          )
          y_overlap = any(
            [
              og_y <= resource_location.y < og_y + og_resource.get_absolute_size_y(),
              og_y
              < resource_location.y + resource.get_absolute_size_y()
              < og_y + og_resource.get_absolute_size_y(),
            ]
          )
          z_overlap = (
            og_z < resource_location.z + resource.get_absolute_size_z()
            and resource_location.z < og_z + og_resource.get_absolute_size_z()
          )
          if x_overlap and y_overlap and z_overlap:
            raise ValueError(
              f"Location {resource_location} is already occupied by resource '{og_resource.name}'."
            )

    return super().assign_child_resource(resource, location=resource_location, reassign=reassign)

  def summary(self) -> str:
    """Return a summary of the deck.

    Example:
      Printing a summary of the deck layout:

      >>> print(deck.summary())
      Rail     Resource                   Type                Coordinates (mm)
      =============================================================================================
      (1)  ├── tip_car                    TIP_CAR_480_A00     (x: 100.000, y: 240.800, z: 164.450)
           │   ├── tip_rack_01            STF                 (x: 117.900, y: 240.000, z: 100.000)
    """

    if len(self.get_all_resources()) == 0:
      raise ValueError(
        "This liquid editor does not have any resources yet. "
        "Build a layout first by calling `assign_child_resource()`. "
      )

    # don't print these
    exclude_categories = {
      "well",
      "tube",
      "tip_spot",
      "resource_holder",
      "plate_holder",
    }

    def find_longest_child_name(resource: Resource, depth=0, depth_weight=4):
      """DFS to find longest child name, and depth of that child, excluding excluded categories"""
      longest, longest_depth = (
        (len(resource.name), depth) if resource.category not in exclude_categories else (0, 0)
      )
      new_depth = depth + 1 if resource.category not in exclude_categories else depth
      return max(
        [(longest + longest_depth * depth_weight)]
        + [find_longest_child_name(c, new_depth) for c in resource.children]
      )

    def find_longest_type_name(resource: Resource):
      """DFS to find the longest type name"""
      longest = (
        len(resource.__class__.__name__) if resource.category not in exclude_categories else 0
      )
      return max([longest] + [find_longest_type_name(child) for child in resource.children])

    # Calculate the maximum lengths of the resource name and type for proper alignment
    max_name_length = find_longest_child_name(self)
    max_type_length = find_longest_type_name(self)

    # Find column lengths
    rail_column_length = 6
    name_column_length = max(
      max_name_length + 4, 30
    )  # 4 per depth (by find_longest_child), 4 extra
    type_column_length = max_type_length + 1
    location_column_length = 30

    # Print header
    summary_ = (
      "Rail".ljust(rail_column_length)
      + "Resource".ljust(name_column_length)
      + "Type".ljust(type_column_length)
      + "Coordinates (mm)".ljust(location_column_length)
      + "\n"
    )
    total_length = (
      rail_column_length + name_column_length + type_column_length + location_column_length
    )
    summary_ += "=" * total_length + "\n"

    def make_tree_part(depth: int) -> str:
      tree_part = "├── "
      for _ in range(depth):
        tree_part = "│   " + tree_part
      return tree_part

    def print_empty_spot_line(depth=0) -> str:
      r_summary = " " * rail_column_length
      tree_part = make_tree_part(depth)
      r_summary += (tree_part + "<empty>").ljust(name_column_length)
      return r_summary

    def print_resource_line(resource: Resource, depth=0) -> str:
      r_summary = ""

      # Print rail
      if depth == 0:
        rails = track_for_x_coordinate(resource.get_location_wrt(self).x)
        r_summary += f"({rails})".ljust(rail_column_length)
      else:
        r_summary += " " * rail_column_length

      # Print resource name
      tree_part = make_tree_part(depth)
      r_summary += (tree_part + resource.name).ljust(name_column_length)

      # Print resource type
      r_summary += resource.__class__.__name__.ljust(type_column_length)

      # Print resource location
      try:
        x, y, z = resource.get_location_wrt(self)
        location = f"({x:07.3f}, {y:07.3f}, {z:07.3f})"
      except NoLocationError:
        location = "Undefined"
      r_summary += location.ljust(location_column_length)

      return r_summary

    def print_tree(resource: Resource, depth=0):
      r_summary = print_resource_line(resource, depth=depth)

      for child in resource.children:
        if isinstance(child, ResourceHolder):
          r_summary += "\n"
          if child.resource is not None:
            r_summary += print_tree(child.resource, depth=depth + 1)
          else:
            r_summary += print_empty_spot_line(depth=depth + 1)
        elif child.category not in exclude_categories:
          r_summary += "\n"
          r_summary += print_tree(child, depth=depth + 1)

      return r_summary

    # Sort resources by rails, left to right in reality.
    sorted_resources = sorted(self.children, key=lambda r: r.get_location_wrt(self).x)

    # Print table body.
    summary_ += print_tree(sorted_resources[0]) + "\n"
    for resource in sorted_resources[1:]:
      summary_ += "      │\n"
      summary_ += print_tree(resource)
      summary_ += "\n"

    # Truncate trailing whitespace from each line
    summary_ = "\n".join([line.rstrip() for line in summary_.split("\n")])

    return summary_
