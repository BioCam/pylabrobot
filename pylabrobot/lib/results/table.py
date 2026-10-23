"""Plate-reader results as one tidy table: one row per observed value, every setting a column.

Rows are plain dicts with the keys of `COLUMNS`, in that order; a column that does not apply to a
row is None. Timestamps are timezone-aware, in UTC.
"""

import re
from datetime import timezone
from typing import Any, Dict, List, Optional, Sequence, Tuple

from pylabrobot.lib.absorbance.results import AbsorbanceResult, AbsorbanceSpectrumResult
from pylabrobot.lib.fluorescence.results import FluorescenceResult, FluorescenceSpectrumResult
from pylabrobot.lib.luminescence.results import LuminescenceResult
from pylabrobot.resources import Plate

COLUMNS = (
  "read",
  "mode",
  "start_timestamp",
  "end_timestamp",
  "well",
  "row",
  "column",
  "row_index",
  "column_index",
  "wavelength",
  "excitation_wavelength",
  "excitation_bandwidth",
  "emission_wavelength",
  "emission_bandwidth",
  "scanned",
  "point",
  "x",
  "y",
  "focal_height",
  "optic_position",
  "gain",
  "temperature",
  "quantity",
  "value",
  "saturated",
)

_IDENTIFIER = re.compile(r"([A-Z]+)([0-9]+)")

# Well columns: the identifier's, keyed by identifier.
_WellColumns = Dict[str, Dict[str, Any]]


def _compute_row_index(row: str) -> int:
  """The 0-based index of a row label: A 0, Z 25, AA 26, AF 31."""
  index = 0
  for letter in row:
    index = index * 26 + ord(letter) - ord("A") + 1
  return index - 1


def _get_plate_positions(plate: Plate) -> Dict[str, Tuple[int, int]]:
  """Each well identifier of `plate` with its 0-based row and column index."""
  rows = plate.num_items_y
  return {
    plate.get_child_identifier(well): (index % rows, index // rows)  # items are column by column
    for index, well in enumerate(plate.get_all_items())
  }


def _get_well_columns(
  identifier: str, positions: Optional[Dict[str, Tuple[int, int]]]
) -> Dict[str, Any]:
  """The well columns of `identifier`: its indices from `positions` if given, else parsed.

  Raises:
    ValueError: if `identifier` is not a row label and a column number, or not in `positions`.
  """
  match = _IDENTIFIER.fullmatch(identifier)
  if match is None:
    raise ValueError(f"{identifier!r} is not a well identifier such as 'B3'")
  row = match.group(1)
  if positions is None:
    row_index, column_index = _compute_row_index(row), int(match.group(2)) - 1
  elif identifier in positions:
    row_index, column_index = positions[identifier]
  else:
    raise ValueError(f"the plate has no well {identifier}")
  return {
    "well": identifier,
    "row": row,
    "column": column_index + 1,
    "row_index": row_index,
    "column_index": column_index,
  }


def _get_cached_well_columns(
  identifier: str, positions: Optional[Dict[str, Tuple[int, int]]], cache: _WellColumns
) -> Dict[str, Any]:
  """`_get_well_columns`, computed once per identifier in `cache`."""
  columns = cache.get(identifier)
  if columns is None:
    columns = cache[identifier] = _get_well_columns(identifier, positions)
  return columns


def _get_base(read: int, mode: str, result: Any, **columns: Any) -> Dict[str, Any]:
  """A row of every column, None but `read`, `mode`, `result`'s timestamps in UTC and `columns`."""
  base: Dict[str, Any] = dict.fromkeys(COLUMNS)
  base.update(
    read=read,
    mode=mode,
    start_timestamp=result.start_timestamp.astimezone(timezone.utc),
    end_timestamp=result.end_timestamp.astimezone(timezone.utc),
    saturated=False,
    **columns,
  )
  return base


def _get_row(
  base: Dict[str, Any], well_columns: Dict[str, Any], value: float, ceiling: Optional[float]
) -> Dict[str, Any]:
  """A copy of `base` with `well_columns`, `value` and whether it reads at `ceiling`."""
  row = base.copy()
  row.update(well_columns)
  row["value"] = value
  if ceiling is not None:
    row["saturated"] = value >= ceiling
  return row


def _get_well_rows(
  base: Dict[str, Any],
  data: Dict[str, float],
  positions: Optional[Dict[str, Tuple[int, int]]],
  cache: _WellColumns,
  ceiling: Optional[float],
) -> List[Dict[str, Any]]:
  """One row per well of `data`."""
  return [
    _get_row(base, _get_cached_well_columns(identifier, positions, cache), value, ceiling)
    for identifier, value in data.items()
  ]


def _get_grid_rows(
  base: Dict[str, Any], counts: List[List[int]], spacing: float, ceiling: Optional[float]
) -> List[Dict[str, Any]]:
  """One row per point of a grid: its index, and x and y in mm from the grid's centre.

  x runs along a row of `counts`, y down its rows; which way they run on the plate is not verified.
  """
  rows: List[Dict[str, Any]] = []
  side = len(counts)
  middle = (side - 1) / 2
  for i, line in enumerate(counts):
    for j, count in enumerate(line):
      row = base.copy()
      # Spacing is decoded in um: 3 decimals hold every x and y exactly.
      row.update(
        point=i * side + j,
        x=round((j - middle) * spacing, 3),
        y=round((i - middle) * spacing, 3),
        value=count,
        saturated=ceiling is not None and count >= ceiling,
      )
      rows.append(row)
  return rows


def get_table(
  results: Sequence[Any],
  *,
  plate: Optional[Plate] = None,
  first_read: int = 0,
  ceiling: Optional[float] = None,
) -> List[Dict[str, Any]]:
  """The rows of `results`: one per observed value, each result one read.

  - A read: one row per well. A matrix scan adds one per well and point (`matrix_points`).
  - A spectrum: one row per well and wavelength.
  - A grid (a result with `counts` and `spacing`): one row per point, with x and y.
  - A device's fields beyond the shared types are read by name when a result has them: `gain`,
    `focal_height`, `optic_position`, `matrix_points`, and `references` (raw absorbance counts, with
    `reference_counts` rows).

  Args:
    results: absorbance, fluorescence and luminescence results and spectra, and grids.
    plate: the plate the wells' rows and columns are taken from; None parses the identifiers.
    first_read: the `read` of the first result; each next result counts up by one.
    ceiling: the detector's ceiling in counts: counts at or above it are saturated; None for none.

  Raises:
    TypeError: if a result is of no type above.
    ValueError: if a well is not on `plate`, or not a well identifier.
  """
  positions = None if plate is None else _get_plate_positions(plate)
  cache: _WellColumns = {}
  rows: List[Dict[str, Any]] = []
  for read, result in enumerate(results, first_read):
    settings = {
      name: getattr(result, name)
      for name in ("gain", "focal_height", "optic_position")
      if getattr(result, name, None) is not None
    }
    if hasattr(result, "counts") and hasattr(result, "spacing"):
      well = {} if result.well is None else _get_well_columns(result.well, positions)
      base = _get_base(
        read,
        "fluorescence_grid",
        result,
        temperature=getattr(result, "temperature", None),
        quantity="counts",
        **settings,
        **well,
      )
      rows += _get_grid_rows(base, result.counts, result.spacing, ceiling)
    elif isinstance(result, AbsorbanceResult):
      raw = hasattr(result, "references")
      references = getattr(result, "references", None)
      base = _get_base(
        read,
        "absorbance",
        result,
        wavelength=result.wavelength,
        temperature=result.temperature,
        quantity="counts" if raw else "optical_density",
      )
      rows += _get_well_rows(base, result.data, positions, cache, ceiling if raw else None)
      if references:
        base = {**base, "quantity": "reference_counts"}
        rows += _get_well_rows(base, references, positions, cache, ceiling)
    elif isinstance(result, AbsorbanceSpectrumResult):
      raw = hasattr(result, "references")
      references = getattr(result, "references", None)
      base = _get_base(
        read,
        "absorbance_spectrum",
        result,
        temperature=result.temperature,
        quantity="counts" if raw else "optical_density",
      )
      for identifier, spectrum in result.data.items():
        well = _get_cached_well_columns(identifier, positions, cache)
        for wavelength, value in spectrum.items():
          row = _get_row(base, well, value, ceiling if raw else None)
          row["wavelength"] = wavelength
          rows.append(row)
      if references:
        base = {**base, "quantity": "reference_counts"}
        rows += _get_well_rows(base, references, positions, cache, ceiling)
    elif isinstance(result, FluorescenceResult):
      base = _get_base(
        read,
        "fluorescence",
        result,
        excitation_wavelength=result.excitation_wavelength,
        excitation_bandwidth=result.excitation_bandwidth,
        emission_wavelength=result.emission_wavelength,
        emission_bandwidth=result.emission_bandwidth,
        temperature=result.temperature,
        quantity="counts",
        **settings,
      )
      rows += _get_well_rows(base, result.data, positions, cache, ceiling)
      for identifier, points in (getattr(result, "matrix_points", None) or {}).items():
        well = _get_cached_well_columns(identifier, positions, cache)
        for point, value in enumerate(points):
          row = _get_row(base, well, value, ceiling)
          row["point"] = point
          rows.append(row)
    elif isinstance(result, FluorescenceSpectrumResult):
      scanned = "excitation" if result.excitation_wavelength is None else "emission"
      base = _get_base(
        read,
        "fluorescence_spectrum",
        result,
        excitation_wavelength=result.excitation_wavelength,
        excitation_bandwidth=result.excitation_bandwidth,
        emission_wavelength=result.emission_wavelength,
        emission_bandwidth=result.emission_bandwidth,
        scanned=scanned,
        temperature=result.temperature,
        quantity="counts",
        **settings,
      )
      wavelength_column = f"{scanned}_wavelength"
      for identifier, spectrum in result.data.items():
        well = _get_cached_well_columns(identifier, positions, cache)
        for wavelength, value in spectrum.items():
          row = _get_row(base, well, value, ceiling)
          row[wavelength_column] = wavelength
          rows.append(row)
    elif isinstance(result, LuminescenceResult):
      base = _get_base(
        read,
        "luminescence",
        result,
        emission_wavelength=result.emission_wavelength,
        emission_bandwidth=result.emission_bandwidth,
        temperature=result.temperature,
        quantity="counts",
        **settings,
      )
      rows += _get_well_rows(base, result.data, positions, cache, ceiling)
    else:
      raise TypeError(f"no table for a {type(result).__name__}")
  return rows
