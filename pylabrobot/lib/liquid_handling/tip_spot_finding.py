"""Select tip spots from tracked tip inventory without changing trackers."""

from itertools import groupby
from typing import List, Optional, Tuple

from pylabrobot.resources import Resource, TipRack, TipSpot


def _matches_tip_filters(
  tip_spot: TipSpot,
  has_tip: Optional[bool],
  volume: Optional[float],
  has_filter: Optional[bool],
) -> bool:
  """Whether a tip spot passes the presence, volume and filter checks.

  Volume and filter are read from the configured tip (make_tip) when has_tip is False, and from
  the present tip otherwise, so an empty spot never matches them unless has_tip is False.
  """
  if has_tip is not None and tip_spot.has_tip() != has_tip:
    return False
  if volume is None and has_filter is None:
    return True
  if has_tip is False:
    tip = tip_spot.make_tip()
  elif tip_spot.has_tip():
    tip = tip_spot.get_tip()
  else:
    return False
  if volume is not None and tip.nominal_volume != volume:
    return False
  return has_filter is None or tip.has_filter == has_filter


def _get_centred_spots(
  tip_rack: TipRack, spots: List[TipSpot]
) -> List[Tuple[TipSpot, float, float]]:
  """Each spot with its absolute centre x (rounded to 0.001 mm) and y.

  The rack's origin and rotation are resolved once and applied to each spot's rack-local centre,
  instead of walking the resource tree per spot. A spot with its own rotation is resolved alone.
  """
  origin = tip_rack.get_absolute_location()
  matrix = tip_rack.get_absolute_rotation().get_rotation_matrix()
  centred: List[Tuple[TipSpot, float, float]] = []
  for spot in spots:
    if spot.rotation.x or spot.rotation.y or spot.rotation.z or spot.location is None:
      centre = spot.get_absolute_location(x="c", y="c")
      x, y = centre.x, centre.y
    else:
      local_x = spot.location.x + spot.get_size_x() / 2
      local_y = spot.location.y + spot.get_size_y() / 2
      local_z = spot.location.z
      x = origin.x + matrix[0][0] * local_x + matrix[0][1] * local_y + matrix[0][2] * local_z
      y = origin.y + matrix[1][0] * local_x + matrix[1][1] * local_y + matrix[1][2] * local_z
    centred.append((spot, round(x, 3), y))
  return centred


def _get_tip_racks(root: Resource) -> List[TipRack]:
  """Tip racks in the tree under root, root included, depth first; racks are not descended into."""
  if isinstance(root, TipRack):
    return [root]
  return [rack for child in root.children for rack in _get_tip_racks(child)]


def find_tip_spots(
  root: Resource,
  has_tip: Optional[bool] = None,
  volume: Optional[float] = None,
  has_filter: Optional[bool] = None,
  count: Optional[int] = None,
  x_aligned: bool = False,
) -> List[TipSpot]:
  """Find tip spots in consumption order.

  Searches every tip rack in the tree under root, root included: a deck, a carrier, a bench
  resource holding several racks, a whole facility, or a single rack. Racks with a missing tip
  come first, then the remaining racks in tree order (depth first). Within a rack, spots run
  column by column, each column back to front (descending y), so an untouched rack is opened at
  its first column. This suits channels on one X arm that cannot pass each other.

  Args:
    root: Resource whose tree is searched for tip racks. Racks need a location, as positions
      are compared in the frame of the tree's topmost resource.
    has_tip: True for spots holding a tip, False for empty spots, None for both.
    volume: Tip nominal volume in uL. Read from the present tip, or from the configured tip when
      has_tip is False; with has_tip None, only spots holding a tip match.
    has_filter: Tip filter state, matched like volume.
    count: Return exactly this many spots, sorted back to front, or an empty list if fewer
      match. None returns every match.
    x_aligned: Return spots from a single rack column: the first column in consumption order
      holding at least count spots. A shorter column is skipped. Falls back to the unaligned
      batch when no column can serve count. Without count, returns the first column.

  Returns:
    Matching tip spots.

  Raises:
    ValueError: If count is not positive.
  """
  if count is not None and count <= 0:
    raise ValueError(f"count must be positive, got {count}")

  tip_racks = _get_tip_racks(root)

  started = [any(not spot.has_tip() for spot in rack.get_all_items()) for rack in tip_racks]
  rack_order = sorted(range(len(tip_racks)), key=lambda index: (not started[index], index))

  # Racks are visited in consumption order, so a batch is complete as soon as it is found.
  batch: List[Tuple[TipSpot, float, float]] = []
  for rack_index in rack_order:
    rack = tip_racks[rack_index]
    matching = [
      s for s in rack.get_all_items() if _matches_tip_filters(s, has_tip, volume, has_filter)
    ]
    centred = sorted(_get_centred_spots(rack, matching), key=lambda item: (item[1], -item[2]))

    if x_aligned:
      for _, column_items in groupby(centred, key=lambda item: item[1]):
        column = [spot for spot, _, _ in column_items]
        if count is None:
          return column
        if len(column) >= count:
          return column[:count]

    batch.extend(centred)
    if count is not None and len(batch) >= count and not x_aligned:
      break

  if count is None:
    return [spot for spot, _, _ in batch]
  if len(batch) < count:
    return []
  # A batch crossing from one rack's last column into the next rack's first is not back to front.
  return [spot for spot, _, _ in sorted(batch[:count], key=lambda item: item[2], reverse=True)]
