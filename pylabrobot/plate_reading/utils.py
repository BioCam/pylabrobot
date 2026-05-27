from typing import Any, Dict, Iterable, List, Sequence, Tuple

from pylabrobot.resources import Plate, Well


def _non_overlapping_rectangles(
  points: Iterable[Tuple[int, int]],
) -> List[Tuple[int, int, int, int]]:
  """Find non-overlapping rectangles that cover all given points.

  Example:
    >>> points = [
    >>>   (1, 1),
    >>>   (2, 2), (2, 3), (2, 4),
    >>>   (3, 2), (3, 3), (3, 4),
    >>>   (4, 2), (4, 3), (4, 4), (4, 5),
    >>>   (5, 2), (5, 3), (5, 4), (5, 5),
    >>>   (6, 2), (6, 3), (6, 4), (6, 5),
    >>>   (7, 2), (7, 3), (7, 4),
    >>> ]
    >>> non_overlapping_rectangles(points)
    [
      (1, 1, 1, 1),
      (2, 2, 7, 4),
      (4, 5, 6, 5),
    ]
  """

  pts = set(points)
  rects = []

  while pts:
    # start a rectangle from one arbitrary point
    r0, c0 = min(pts)
    # expand right
    c1 = c0
    while (r0, c1 + 1) in pts:
      c1 += 1
    # expand downward as long as entire row segment is filled
    r1 = r0
    while all((r1 + 1, c) in pts for c in range(c0, c1 + 1)):
      r1 += 1

    rects.append((r0, c0, r1, c1))
    # remove covered points
    for r in range(r0, r1 + 1):
      for c in range(c0, c1 + 1):
        pts.discard((r, c))

  rects.sort()
  return rects


def _get_min_max_row_col_tuples(wells: List[Well], plate: Plate) -> List[Tuple[int, int, int, int]]:
  """Get a list of (min_row, min_col, max_row, max_col) tuples for the given wells."""
  plates = set(well.parent for well in wells)
  if len(plates) != 1 or plates.pop() != plate:
    raise ValueError("All wells must be in the specified plate")
  return _non_overlapping_rectangles((well.get_row(), well.get_column()) for well in wells)


def grid_to_wells_dict(
  grid: Sequence[Sequence[Any]],
  wells: List[Well],
  plate: Plate,
) -> Dict[str, Any]:
  """Read measured values out of a row-major plate grid, keyed by well id.

  Maps each ``Well`` in ``wells`` to its short-form well id ("A1", "H12", ...)
  derived from the (row, col) position on ``plate``, and pulls the value at
  ``grid[row][col]``. Wells whose grid cell is ``None`` (not measured) are
  omitted from the result.

  This is the inverse view of the row-major grid returned by plate-reader
  backends: the same numeric values, exposed as a sparse, name-keyed dict for
  data-science workflows (DataFrame ``.map()``, dict merges, JSON dumps).

  Args:
    grid: 2D sequence indexed by ``[row][col]``, as returned in the ``"data"``
      field of plate-reader read results.
    wells: The wells that were measured. Each must belong to ``plate``.
    plate: The plate the wells live on.

  Returns:
    Dict mapping well ids to their measured values. Only wells whose grid
    cell is not ``None`` are included.
  """
  result: Dict[str, Any] = {}
  for well in wells:
    row = well.get_row()
    col = well.get_column()
    if row >= len(grid) or col >= len(grid[row]):
      continue
    value = grid[row][col]
    if value is None:
      continue
    well_id = f"{chr(ord('A') + row)}{col + 1}"
    result[well_id] = value
  return result
