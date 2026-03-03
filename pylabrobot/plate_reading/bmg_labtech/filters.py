"""Optical filter and filter slide definitions for the CLARIOstar Plus.

Defines the types of physical optical elements installed in the CLARIOstar
filter slides:

- **Filter** — bandpass filter (excitation and emission slides, positions 1–4).
  Characterized by center wavelength and bandwidth.
- **DichroicFilter** — dichroic mirror / long-pass edge filter (dichroic slide,
  positions A/B/C). Characterized by cut-on wavelength.
- **FilterCube** — a matched set of excitation filter, dichroic mirror, and
  emission filter. Not yet implemented.

``Filter`` and ``DichroicFilter`` share a common ``slot`` field which is the
only thing sent on the wire — all other fields are user-side metadata for
decision-making (e.g. "does this filter cover my fluorophore?").

See ``optics_primer.md`` for background on how these components work together.
"""

import dataclasses
from typing import Dict, Optional


# ---------------------------------------------------------------------------
# Filter dataclasses
# ---------------------------------------------------------------------------

@dataclasses.dataclass(frozen=True)
class _FilterBase:
  """Wire-level identity shared by all filter types.

  The firmware only sees ``slot`` — everything else is metadata.
  """
  slot: int
  name: str = ""


@dataclasses.dataclass(frozen=True)
class Filter(_FilterBase):
  """A bandpass optical filter installed in an excitation or emission slide.

  Selects a narrow wavelength band defined by center ± bandwidth/2.
  Pass to ``excitation_filter`` or ``emission_filter`` to use filter mode
  instead of the monochromator.

  Examples::

      Filter(slot=1, name="BP 480", center_wavelength=480, bandwidth=20)
      Filter(slot=2)  # anonymous, slot number only
  """
  center_wavelength: Optional[int] = None  # nm
  bandwidth: Optional[int] = None  # nm


@dataclasses.dataclass(frozen=True)
class DichroicFilter(_FilterBase):
  """A dichroic mirror installed in the dichroic filter slide (positions A/B/C).

  A long-pass edge filter that reflects wavelengths below the cut-on and
  transmits wavelengths above it, separating excitation from emission light.
  Pass to ``dichroic_filter`` to use a fixed dichroic instead of the LVDM.

  Examples::

      DichroicFilter(slot=1, name="LP 504", cut_on_wavelength=504)
      DichroicFilter(slot=2)  # anonymous, slot number only
  """
  cut_on_wavelength: Optional[int] = None  # nm


@dataclasses.dataclass(frozen=True)
class FilterCube:
  """A matched set of excitation filter, dichroic mirror, and emission filter.

  In fluorescence microscopy and plate readers, the three optical elements
  (excitation bandpass, dichroic beam splitter, emission bandpass) are often
  sold and installed as a coordinated set optimized for a specific fluorophore.

  Not yet wired into the backend — placeholder for future use.

  Examples::

      FilterCube(
          name="GFP",
          excitation=Filter(slot=1, name="BP 480", center_wavelength=480, bandwidth=20),
          dichroic=DichroicFilter(slot=1, name="LP 504", cut_on_wavelength=504),
          emission=Filter(slot=1, name="BP 520", center_wavelength=520, bandwidth=20),
      )
  """
  name: str
  excitation: Optional[Filter] = None
  dichroic: Optional[DichroicFilter] = None
  emission: Optional[Filter] = None


# Backward-compat aliases
FilterSlide = Filter
ExcitationFilter = Filter
EmissionFilter = Filter


# ---------------------------------------------------------------------------
# Filter slide classes (containers)
# ---------------------------------------------------------------------------

class _FilterSlideBase:
  """Base class for filter slide containers.

  Supports ``__getitem__`` indexing by slot number and attribute access
  by sanitised filter name.
  """
  _CATEGORY: str = ""
  _DEFAULT_MAX_SLOTS: int = 0
  _FILTER_CLASS = _FilterBase  # overridden by subclasses

  def __init__(self, max_slots: int = 0):
    self._max_slots = max_slots or self._DEFAULT_MAX_SLOTS
    self._by_name: Dict[str, _FilterBase] = {}
    self._by_slot: Dict[int, _FilterBase] = {}

  def register(self, f: _FilterBase) -> None:
    """Register a filter in this slide.

    The filter becomes accessible as an attribute using a sanitised version
    of ``f.name`` (spaces/punctuation → ``_``, leading digits prefixed).
    """
    if self._max_slots > 0 and not 1 <= f.slot <= self._max_slots:
      raise ValueError(
        f"{self._CATEGORY} filter slot {f.slot} out of range "
        f"(instrument has {self._max_slots} {self._CATEGORY} filter slots)")
    self._by_slot[f.slot] = f
    if f.name:
      attr = f.name.replace(" ", "_").replace("/", "_").replace("-", "_")
      if attr and attr[0].isdigit():
        attr = "_" + attr
      self._by_name[attr] = f

  def __getitem__(self, key: int) -> _FilterBase:
    if key in self._by_slot:
      return self._by_slot[key]
    return self._FILTER_CLASS(slot=key)

  def by_slot(self, n: int) -> _FilterBase:
    """Look up a registered filter by slot number, or create an anonymous one."""
    return self[n]

  def __getattr__(self, name: str) -> _FilterBase:
    if name.startswith("_"):
      raise AttributeError(name)
    by_name = object.__getattribute__(self, "_by_name")
    if name in by_name:
      return by_name[name]
    raise AttributeError(
      f"No {object.__getattribute__(self, '_CATEGORY')} filter registered "
      f"as {name!r}. Registered: {list(by_name)}")

  def _update_max_slots(self, n: int) -> None:
    """Update max slot count (e.g. from EEPROM configuration)."""
    self._max_slots = n

  def __repr__(self) -> str:
    items = [f"{k}=slot {v.slot}" for k, v in self._by_name.items()]
    cat = self._CATEGORY or "filter_slide"
    return f"{type(self).__name__}({cat}, [{', '.join(items)}])"


class ExcitationFilterSlide(_FilterSlideBase):
  """Excitation filter slide (positions 1–4, two physical slides)."""
  _CATEGORY = "excitation"
  _DEFAULT_MAX_SLOTS = 4
  _FILTER_CLASS = Filter


class EmissionFilterSlide(_FilterSlideBase):
  """Emission filter slide (positions 1–4, two physical slides)."""
  _CATEGORY = "emission"
  _DEFAULT_MAX_SLOTS = 4
  _FILTER_CLASS = Filter


class DichroicFilterSlide(_FilterSlideBase):
  """Dichroic filter slide (positions A/B/C, one physical slide)."""
  _CATEGORY = "dichroic"
  _DEFAULT_MAX_SLOTS = 3
  _FILTER_CLASS = DichroicFilter
  _LETTER_MAP = {"A": 1, "B": 2, "C": 3}

  def __getitem__(self, key) -> DichroicFilter:
    if isinstance(key, str):
      upper = key.upper()
      if upper not in self._LETTER_MAP:
        raise KeyError(f"Invalid dichroic position {key!r}. Use 'A', 'B', or 'C'.")
      key = self._LETTER_MAP[upper]
    return super().__getitem__(key)  # type: ignore[return-value]
