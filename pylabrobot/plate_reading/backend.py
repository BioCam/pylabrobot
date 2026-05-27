from __future__ import annotations

from abc import ABCMeta, abstractmethod
from typing import Dict, List, Optional

from pylabrobot.machines.backend import MachineBackend
from pylabrobot.plate_reading.standard import (
  Exposure,
  FocalPosition,
  Gain,
  ImagingMode,
  ImagingResult,
  Objective,
)
from pylabrobot.resources.plate import Plate
from pylabrobot.resources.well import Well


class PlateReaderBackend(MachineBackend, metaclass=ABCMeta):
  """An abstract class for a plate reader. Plate readers are devices that can read luminescence,
  absorbance, or fluorescence from a plate."""

  @abstractmethod
  async def setup(self) -> None:
    """Set up the plate reader. This should be called before any other methods."""

  @abstractmethod
  async def stop(self) -> None:
    """Close all connections to the plate reader and make sure setup() can be called again."""

  @abstractmethod
  async def open(self) -> None:
    """Open the plate reader. Also known as plate out."""

  @abstractmethod
  async def close(self, plate: Optional[Plate]) -> None:
    """Close the plate reader. Also known as plate in."""

  # Common optional fields populated by backends (or synthesised by the
  # :class:`PlateReader` wrapper if absent):
  #
  # - ``"wells"`` (``Dict[str, value]``): sparse, well-id-keyed view of
  #   ``"data"``. Wrapper computes this from the grid via
  #   :func:`grid_to_wells_dict` when the backend doesn't supply it.
  # - ``"mode"`` (``str``): the measurement modality (``"fluorescence"``,
  #   ``"absorbance"``, ``"luminescence"``). Wrapper synthesises this from the
  #   calling method when the backend doesn't supply it.
  # - ``"units"`` (``str``): measurement unit string ("RFU", "OD", "%T",
  #   "counts", "RLU"). Backend-supplied only.
  # - ``"overflow_threshold"`` (``int``): raw detector-count ceiling above
  #   which a reading is saturated. Backend-supplied only. NB: applies to
  #   RAW counts, not post-processed values. For absorbance reads with
  #   ``report="optical_density"`` or ``"transmittance"``, ``"wells"`` holds
  #   the *converted* value, so callers can't naively compare it against
  #   ``"overflow_threshold"``. Backends that surface this field should also
  #   surface the raw counts (e.g. as a separate ``report="raw"`` read) if
  #   per-well overflow detection matters.

  @abstractmethod
  async def read_luminescence(
    self, plate: Plate, wells: List[Well], focal_height: float
  ) -> List[Dict]:
    """Read the luminescence from the plate reader.

    Returns:
      A list of dictionaries, one for each measurement. Each dictionary
      contains the modality-specific fields:
        "time": float,
        "temperature": float,
        "data": List[List[float]]    -- row-major plate grid

      Plus the optional standard fields documented at the class level:
      ``"wells"``, ``"mode"``, ``"units"``, ``"overflow_threshold"``.
    """

  @abstractmethod
  async def read_absorbance(self, plate: Plate, wells: List[Well], wavelength: int) -> List[Dict]:
    """Read the absorbance from the plate reader.

    Returns:
      A list of dictionaries, one for each measurement. Each dictionary
      contains the modality-specific fields:
        "wavelength": int,
        "time": float,
        "temperature": float,
        "data": List[List[float]]    -- row-major plate grid

      Plus the optional standard fields documented at the class level:
      ``"wells"``, ``"mode"``, ``"units"``, ``"overflow_threshold"``.
    """

  @abstractmethod
  async def read_fluorescence(
    self,
    plate: Plate,
    wells: List[Well],
    excitation_wavelength: int,
    emission_wavelength: int,
    focal_height: float,
  ) -> List[Dict]:
    """Read the fluorescence from the plate reader.

    Returns:
      A list of dictionaries, one for each measurement. Each dictionary
      contains the modality-specific fields:
        "ex_wavelength": int,
        "em_wavelength": int,
        "time": float,
        "temperature": float,
        "data": List[List[float]]    -- row-major plate grid

      Plus the optional standard fields documented at the class level:
      ``"wells"``, ``"mode"``, ``"units"``, ``"overflow_threshold"``.
    """


class ImagerBackend(MachineBackend, metaclass=ABCMeta):
  @abstractmethod
  async def capture(
    self,
    row: int,
    column: int,
    mode: ImagingMode,
    objective: Objective,
    exposure_time: Exposure,
    focal_height: FocalPosition,
    gain: Gain,
    plate: Plate,
  ) -> ImagingResult:
    """Capture an image of the plate in the specified mode."""


class ImageReaderBackend(PlateReaderBackend, ImagerBackend):
  pass
