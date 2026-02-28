"""Container classes for plate reader measurement results.

Provides a base :class:`PlateReaderResult` and three measurement-specific subclasses:

- :class:`AbsorbanceResult` — single-wavelength ``"wavelength"`` key per entry
- :class:`FluorescenceResult` — ``"ex_wavelength"`` / ``"em_wavelength"`` keys per entry
- :class:`LuminescenceResult` — no wavelength metadata, just intensity grids

All classes implement ``collections.abc.Sequence`` so they are backwards-compatible
with ``List[Dict]`` indexing.
"""

from __future__ import annotations

import collections.abc
import re
from typing import Any, Dict, List, Optional, Tuple, Union, overload


# ---------------------------------------------------------------------------
# Well name utilities
# ---------------------------------------------------------------------------


def _parse_well_name(name: str) -> Tuple[int, int]:
  """Parse a well name like ``'A1'`` or ``'AA12'`` into ``(row, col)`` zero-indexed.

  Supports single-letter rows A-Z (0-25) and double-letter rows AA-AZ, BA-BZ, etc.
  Columns are 1-based in the name, returned as 0-based.

  Raises:
    ValueError: If the well name is not a valid format.
  """

  m = re.fullmatch(r"([A-Z]{1,2})(\d+)", name)
  if m is None:
    raise ValueError(f"Invalid well name: {name!r}")

  letters, digits = m.group(1), m.group(2)
  if len(letters) == 1:
    row = ord(letters) - ord("A")
  else:
    # AA=26, AB=27, ..., AZ=51, BA=52, ...
    row = (ord(letters[0]) - ord("A") + 1) * 26 + (ord(letters[1]) - ord("A"))

  col = int(digits) - 1
  if col < 0:
    raise ValueError(f"Column must be >= 1, got {digits!r} in well name {name!r}")
  return (row, col)


def _row_label(row: int) -> str:
  """Convert a zero-indexed row to a letter label: 0->``'A'``, 25->``'Z'``, 26->``'AA'``, etc."""
  if row < 26:
    return chr(ord("A") + row)
  return chr(ord("A") + row // 26 - 1) + chr(ord("A") + row % 26)


# ---------------------------------------------------------------------------
# Base class
# ---------------------------------------------------------------------------


class PlateReaderResult(collections.abc.Sequence):
  """Immutable container for plate reader measurement results.

  Wraps the ``List[Dict]`` returned by plate reader backends with convenient
  access patterns while remaining fully backwards-compatible with list indexing.

  Indexing convention:
    - ``result[i]`` (int) — list index (backwards-compatible)
    - ``result["A1"]`` (str) — well values across all entries
    - ``result.grid(0)`` — 2D data grid at list index 0

  This is the base class. Use :class:`AbsorbanceResult`, :class:`FluorescenceResult`,
  or :class:`LuminescenceResult` for measurement-specific functionality.
  """

  __slots__ = ("_data", "_num_rows", "_num_cols")

  def __init__(
    self,
    data: List[Dict],
    num_rows: Optional[int] = None,
    num_cols: Optional[int] = None,
  ):
    self._data: List[Dict] = list(data)  # defensive copy

    # Infer grid dimensions from first entry if not provided
    if num_rows is not None and num_cols is not None:
      self._num_rows: int = num_rows
      self._num_cols: int = num_cols
    elif len(self._data) > 0 and "data" in self._data[0]:
      grid = self._data[0]["data"]
      self._num_rows = len(grid)
      self._num_cols = len(grid[0]) if self._num_rows > 0 else 0
    else:
      self._num_rows = 0
      self._num_cols = 0

  # ---------------------------------------------------------------------------
  # Sequence protocol
  # ---------------------------------------------------------------------------

  @overload
  def __getitem__(self, index: int) -> Dict: ...

  @overload
  def __getitem__(self, index: slice) -> "PlateReaderResult": ...

  @overload
  def __getitem__(self, index: str) -> List[Optional[float]]: ...

  def __getitem__(
    self, index: Union[int, slice, str]
  ) -> Union[Dict, "PlateReaderResult", List[Optional[float]]]:
    if isinstance(index, str):
      return self.well(index)
    if isinstance(index, slice):
      return self._slice(index)
    return self._data[index]

  def _slice(self, s: slice) -> "PlateReaderResult":
    """Return a sliced copy. Subclasses override to return their own type."""
    return PlateReaderResult(
      self._data[s],
      num_rows=self._num_rows,
      num_cols=self._num_cols,
    )

  def __len__(self) -> int:
    return len(self._data)

  def __iter__(self):
    return iter(self._data)

  def __contains__(self, item: object) -> bool:
    return item in self._data

  def __bool__(self) -> bool:
    return len(self._data) > 0

  def __eq__(self, other: object) -> bool:
    if isinstance(other, PlateReaderResult):
      return self._data == other._data
    if isinstance(other, list):
      return self._data == other
    return NotImplemented

  def __repr__(self) -> str:
    n = len(self._data)
    entry_word = "entry" if n == 1 else "entries"
    parts = [f"{n} {entry_word}"]
    if self._num_rows > 0 and self._num_cols > 0:
      parts.append(f"{self._num_rows}x{self._num_cols} grid")
    extra = self._repr_extra()
    if extra:
      parts.append(extra)
    return f"{type(self).__name__}({', '.join(parts)})"

  def _repr_extra(self) -> Optional[str]:
    """Subclasses override to add type-specific repr info."""
    return None

  # ---------------------------------------------------------------------------
  # Properties
  # ---------------------------------------------------------------------------

  @property
  def temperatures(self) -> List[Optional[float]]:
    """List of temperature values from each entry, in order."""
    return [entry.get("temperature") for entry in self._data]

  @property
  def times(self) -> List[Optional[float]]:
    """List of time values from each entry, in order."""
    return [entry.get("time") for entry in self._data]

  @property
  def num_rows(self) -> int:
    """Number of rows in the measurement grid."""
    return self._num_rows

  @property
  def num_cols(self) -> int:
    """Number of columns in the measurement grid."""
    return self._num_cols

  @property
  def raw(self) -> List[Dict]:
    """The underlying list of dictionaries."""
    return self._data

  # ---------------------------------------------------------------------------
  # Well access
  # ---------------------------------------------------------------------------

  def well(self, name: str) -> List[Optional[float]]:
    """Get values for a well across all entries.

    Args:
      name: Well name, e.g. ``"A1"``, ``"H12"``.

    Returns:
      List of values (one per entry), in the same order as the entries.

    Raises:
      ValueError: If the well name is invalid.
      IndexError: If the well position is outside the grid dimensions.
    """

    row, col = _parse_well_name(name)
    if row >= self._num_rows or col >= self._num_cols:
      raise IndexError(
        f"Well {name!r} (row={row}, col={col}) is outside the "
        f"{self._num_rows}x{self._num_cols} grid."
      )
    values: List[Optional[float]] = []
    for entry in self._data:
      grid = entry.get("data")
      if grid is None:
        values.append(None)
      else:
        values.append(grid[row][col])
    return values

  def well_names(self) -> List[str]:
    """List of all well names in row-major order.

    Returns:
      e.g. ``["A1", "A2", ..., "A12", "B1", ..., "H12"]`` for a 96-well plate.
    """
    names: List[str] = []
    for r in range(self._num_rows):
      label = _row_label(r)
      for c in range(self._num_cols):
        names.append(f"{label}{c + 1}")
    return names

  # ---------------------------------------------------------------------------
  # Grid access
  # ---------------------------------------------------------------------------

  def grid(self, index: int) -> List[List[Any]]:
    """Get the 2D data grid at a specific list index.

    Args:
      index: List index (supports negative indexing).

    Returns:
      The 2D grid from the entry at that index.
    """

    return self._data[index]["data"]

  # ---------------------------------------------------------------------------
  # Conversion methods
  # ---------------------------------------------------------------------------

  def to_list(self) -> List[Dict]:
    """Return the underlying data as a plain list of dictionaries.

    Same as ``.raw``.
    """
    return self._data

  def to_dataframe(self) -> Any:
    """Convert to a pandas DataFrame.

    Columns are well names (``A1``, ``A2``, ...) plus metadata columns
    (``temperature``, ``time``, and measurement-specific keys) when present.
    The index depends on the subclass (e.g. ``wavelength`` for absorbance).

    Returns:
      ``pandas.DataFrame``

    Raises:
      ImportError: If pandas is not installed.
    """

    try:
      import pandas as pd  # pylint: disable=import-outside-toplevel
    except ImportError as e:
      raise ImportError(
        "pandas is required for to_dataframe(). Install it with: pip install pandas"
      ) from e

    records: List[Dict] = []
    names = self.well_names()
    index_col = self._dataframe_index_col()

    for entry in self._data:
      row_dict: Dict[str, Any] = {}

      # Metadata columns — subclass controls which keys
      for key in self._metadata_keys():
        if key in entry:
          row_dict[key] = entry[key]

      # Well columns
      grid = entry.get("data")
      if grid is not None:
        for r in range(self._num_rows):
          for c in range(self._num_cols):
            well_idx = r * self._num_cols + c
            if well_idx < len(names):
              row_dict[names[well_idx]] = grid[r][c]

      records.append(row_dict)

    df = pd.DataFrame(records)

    if index_col and index_col in df.columns:
      df = df.set_index(index_col)

    return df

  def _metadata_keys(self) -> List[str]:
    """Keys to include as metadata columns in to_dataframe(). Override in subclasses."""
    return ["temperature", "time"]

  def _dataframe_index_col(self) -> Optional[str]:
    """Column to use as DataFrame index. Override in subclasses."""
    return None

  def to_numpy(self) -> Any:
    """Convert to a numpy 3D array of shape ``(n_entries, num_rows, num_cols)``.

    ``None`` values are converted to ``numpy.nan``.

    Returns:
      ``numpy.ndarray``

    Raises:
      ImportError: If numpy is not installed.
    """

    try:
      import numpy as np  # pylint: disable=import-outside-toplevel
    except ImportError as e:
      raise ImportError(
        "numpy is required for to_numpy(). Install it with: pip install numpy"
      ) from e

    n = len(self._data)
    arr = np.full((n, self._num_rows, self._num_cols), np.nan)

    for i, entry in enumerate(self._data):
      grid = entry.get("data")
      if grid is not None:
        for r in range(self._num_rows):
          for c in range(self._num_cols):
            val = grid[r][c]
            if val is not None:
              arr[i, r, c] = val

    return arr


# ---------------------------------------------------------------------------
# Absorbance
# ---------------------------------------------------------------------------


class AbsorbanceResult(PlateReaderResult):
  """Result container for absorbance measurements.

  Each entry has a ``"wavelength"`` key (int, nm). Provides wavelength-indexed
  access, spectrum extraction, and wavelength-aware DataFrame conversion.

  Examples:
    >>> r = AbsorbanceResult(data)
    >>> r.at_wavelength(600)             # 2D grid at 600 nm
    >>> plt.plot(*r.spectrum("A1"))      # plot absorbance spectrum
    >>> r["A1"]                          # OD values across all wavelengths
  """

  __slots__ = ("_wl_index",)

  def __init__(
    self,
    data: List[Dict],
    num_rows: Optional[int] = None,
    num_cols: Optional[int] = None,
  ):
    super().__init__(data, num_rows=num_rows, num_cols=num_cols)
    # Build wavelength index for O(1) lookup: {wavelength_nm: list_index}
    self._wl_index: Dict[int, int] = {}
    for i, entry in enumerate(self._data):
      wl = entry.get("wavelength")
      if wl is not None:
        self._wl_index[wl] = i

  def _slice(self, s: slice) -> "AbsorbanceResult":
    return AbsorbanceResult(
      self._data[s],
      num_rows=self._num_rows,
      num_cols=self._num_cols,
    )

  def _repr_extra(self) -> Optional[str]:
    if not self._wl_index:
      return None
    wls = sorted(self._wl_index.keys())
    if len(wls) == 1:
      return f"wavelength={wls[0]}nm"
    return f"wavelengths={wls[0]}-{wls[-1]}nm"

  # -- Properties --

  @property
  def wavelengths(self) -> List[int]:
    """Sorted list of wavelengths (nm) across all entries."""
    return sorted(self._wl_index.keys())

  # -- Wavelength access --

  def at_wavelength(self, wavelength: int) -> List[List[Any]]:
    """Get the 2D data grid for a specific wavelength.

    Args:
      wavelength: Wavelength in nanometers.

    Returns:
      The 2D grid (``List[List[float]]``) from the matching entry.

    Raises:
      KeyError: If the wavelength is not found.
    """

    idx = self._wl_index.get(wavelength)
    if idx is None:
      raise KeyError(
        f"Wavelength {wavelength}nm not found. "
        f"Available: {sorted(self._wl_index.keys())}"
      )
    return self._data[idx]["data"]

  def spectrum(self, well_name: str) -> Tuple[List[int], List[Optional[float]]]:
    """Get ``(wavelengths, values)`` for a well, suitable for plotting.

    Usage::

      plt.plot(*result.spectrum("A1"))

    Args:
      well_name: Well name, e.g. ``"A1"``.

    Returns:
      Tuple of ``(wavelengths, od_values)``, both sorted by wavelength.
    """

    row, col = _parse_well_name(well_name)
    if row >= self._num_rows or col >= self._num_cols:
      raise IndexError(
        f"Well {well_name!r} (row={row}, col={col}) is outside the "
        f"{self._num_rows}x{self._num_cols} grid."
      )

    wls: List[int] = []
    vals: List[Optional[float]] = []
    for wl in sorted(self._wl_index.keys()):
      idx = self._wl_index[wl]
      grid = self._data[idx].get("data")
      wls.append(wl)
      if grid is None:
        vals.append(None)
      else:
        vals.append(grid[row][col])
    return (wls, vals)

  # -- DataFrame --

  def _metadata_keys(self) -> List[str]:
    return ["wavelength", "temperature", "time"]

  def _dataframe_index_col(self) -> Optional[str]:
    return "wavelength"


# ---------------------------------------------------------------------------
# Fluorescence
# ---------------------------------------------------------------------------


class FluorescenceResult(PlateReaderResult):
  """Result container for fluorescence measurements.

  Each entry has ``"ex_wavelength"`` and ``"em_wavelength"`` keys (int, nm).

  Examples:
    >>> r = FluorescenceResult(data)
    >>> r.excitation_wavelengths
    >>> r.emission_wavelengths
    >>> r["A1"]  # intensity values across all entries
  """

  __slots__ = ()

  def _slice(self, s: slice) -> "FluorescenceResult":
    return FluorescenceResult(
      self._data[s],
      num_rows=self._num_rows,
      num_cols=self._num_cols,
    )

  def _repr_extra(self) -> Optional[str]:
    ex = self.excitation_wavelengths
    em = self.emission_wavelengths
    if not ex and not em:
      return None
    parts = []
    if len(ex) == 1:
      parts.append(f"ex={ex[0]}nm")
    elif ex:
      parts.append(f"ex={ex[0]}-{ex[-1]}nm")
    if len(em) == 1:
      parts.append(f"em={em[0]}nm")
    elif em:
      parts.append(f"em={em[0]}-{em[-1]}nm")
    return ", ".join(parts)

  # -- Properties --

  @property
  def excitation_wavelengths(self) -> List[int]:
    """Sorted unique excitation wavelengths (nm) across all entries."""
    return sorted({
      entry["ex_wavelength"]
      for entry in self._data
      if "ex_wavelength" in entry
    })

  @property
  def emission_wavelengths(self) -> List[int]:
    """Sorted unique emission wavelengths (nm) across all entries."""
    return sorted({
      entry["em_wavelength"]
      for entry in self._data
      if "em_wavelength" in entry
    })

  # -- DataFrame --

  def _metadata_keys(self) -> List[str]:
    return ["ex_wavelength", "em_wavelength", "temperature", "time"]

  def _dataframe_index_col(self) -> Optional[str]:
    return None  # no single obvious index for fluorescence


# ---------------------------------------------------------------------------
# Luminescence
# ---------------------------------------------------------------------------


class LuminescenceResult(PlateReaderResult):
  """Result container for luminescence measurements.

  Entries have no wavelength metadata — just ``"time"`` and ``"temperature"``.

  Examples:
    >>> r = LuminescenceResult(data)
    >>> r["A1"]           # intensity values across entries
    >>> r.grid(0)         # 2D intensity grid for first entry
  """

  __slots__ = ()

  def _slice(self, s: slice) -> "LuminescenceResult":
    return LuminescenceResult(
      self._data[s],
      num_rows=self._num_rows,
      num_cols=self._num_cols,
    )

  def _metadata_keys(self) -> List[str]:
    return ["temperature", "time"]

  def _dataframe_index_col(self) -> Optional[str]:
    return None
