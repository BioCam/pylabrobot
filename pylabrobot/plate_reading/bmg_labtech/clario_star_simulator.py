import datetime
import random
from typing import Dict, List, Optional, Set

from pylabrobot.plate_reading.backend import PlateReaderBackend
from pylabrobot.plate_reading.bmg_labtech.clario_star_backend import StatusFlag
from pylabrobot.resources.plate import Plate
from pylabrobot.resources.well import Well


class CLARIOstarSimulatorBackend(PlateReaderBackend):
  """A simulator backend for the CLARIOstar plate reader.

  Generates realistic random data from configurable mean/CV per modality,
  or accepts explicit mock data passed via ``**backend_kwargs``.

  Return formats match the real ``CLARIOstarBackend`` exactly.
  """

  def __init__(
    self,
    absorbance_mean: float = 0.5,
    absorbance_cv: float = 0.05,
    fluorescence_mean: float = 10000.0,
    fluorescence_cv: float = 0.10,
    luminescence_mean: float = 5000.0,
    luminescence_cv: float = 0.10,
    temperature: float = 26.0,
    seed: Optional[int] = None,
  ):
    self.absorbance_mean = absorbance_mean
    self.absorbance_cv = absorbance_cv
    self.fluorescence_mean = fluorescence_mean
    self.fluorescence_cv = fluorescence_cv
    self.luminescence_mean = luminescence_mean
    self.luminescence_cv = luminescence_cv
    self.temperature = temperature
    self._rng = random.Random(seed)
    self._is_open = False
    self._plate_on_tray = False

  async def setup(self) -> None:
    pass

  async def stop(self) -> None:
    pass

  async def open(self) -> None:
    self._is_open = True

  async def close(self, plate: Optional[Plate] = None) -> None:
    self._is_open = False
    if plate is not None:
      self._plate_on_tray = True

  async def get_status(self) -> Set[StatusFlag]:
    """Return simulated status flags reflecting current simulator state."""
    flags: Set[StatusFlag] = {StatusFlag.VALID, StatusFlag.INITIALIZED}
    if self._is_open:
      flags.add(StatusFlag.OPEN)
    if self._plate_on_tray:
      flags.add(StatusFlag.PLATE_DETECTED)
    return flags

  def get_eeprom_data(self) -> Optional[bytes]:
    """Return None (no physical EEPROM in simulation)."""
    return None

  async def set_temperature(self, temperature: float) -> None:
    """Set the simulated temperature in degrees Celsius.

    Matches the planned CLARIOstarBackend API. Pass 0.0 to switch off.
    """
    self.temperature = temperature

  async def get_temperature(self) -> float:
    """Return the current simulated temperature in degrees Celsius."""
    return self.temperature

  def _generate_grid(self, rows: int, cols: int, mean: float, cv: float) -> List[List[float]]:
    """Generate a rows x cols grid of random values drawn from N(mean, mean*cv)."""
    sigma = mean * cv
    return [[self._rng.gauss(mean, sigma) for _ in range(cols)] for _ in range(rows)]

  def _mask_grid(
    self,
    grid: List[List[float]],
    wells: List[Well],
    plate: Plate,
  ) -> List[List[Optional[float]]]:
    """Mask unselected wells to None, matching CLARIOstarBackend behavior."""
    rows = plate.num_items_y
    cols = plate.num_items_x
    masked: List[List[Optional[float]]] = [[None] * cols for _ in range(rows)]
    for well in wells:
      r, c = well.get_row(), well.get_column()
      if r < rows and c < cols:
        masked[r][c] = grid[r][c]
    return masked

  async def read_absorbance(
    self,
    plate: Plate,
    wells: List[Well],
    wavelength: int,
    **backend_kwargs,
  ) -> List[Dict]:
    wavelengths = backend_kwargs.pop("wavelengths", [wavelength])
    if isinstance(wavelengths, int):
      wavelengths = [wavelengths]
    report = backend_kwargs.pop("report", "OD")
    mock_data = backend_kwargs.pop("mock_data", None)
    mean = backend_kwargs.pop("mean", self.absorbance_mean)
    cv = backend_kwargs.pop("cv", self.absorbance_cv)

    rows, cols = plate.num_items_y, plate.num_items_x
    results = []
    for wl in wavelengths:
      if mock_data is not None:
        data = mock_data
      else:
        full = self._generate_grid(rows, cols, mean, cv)
        data = self._mask_grid(full, wells, plate)
      entry: Dict = {
        "wavelength": wl,
        "data": data,
        "temperature": self.temperature,
        "time": datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
      }
      if report == "raw":
        num_wells = len(wells)
        entry["references"] = [self._rng.gauss(100000, 1000) for _ in range(num_wells)]
        entry["chromatic_cal"] = (100000.0, 0.0)
        entry["reference_cal"] = (200000.0, 0.0)
      results.append(entry)
    return results

  async def read_fluorescence(
    self,
    plate: Plate,
    wells: List[Well],
    excitation_wavelength: int,
    emission_wavelength: int,
    focal_height: float,
    **backend_kwargs,
  ) -> List[Dict]:
    mock_data = backend_kwargs.pop("mock_data", None)
    mean = backend_kwargs.pop("mean", self.fluorescence_mean)
    cv = backend_kwargs.pop("cv", self.fluorescence_cv)

    rows, cols = plate.num_items_y, plate.num_items_x
    if mock_data is not None:
      data = mock_data
    else:
      full = self._generate_grid(rows, cols, mean, cv)
      data = self._mask_grid(full, wells, plate)

    return [{
      "ex_wavelength": excitation_wavelength,
      "em_wavelength": emission_wavelength,
      "data": data,
      "temperature": self.temperature,
      "time": datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
    }]

  async def read_luminescence(
    self,
    plate: Plate,
    wells: List[Well],
    focal_height: float,
    **backend_kwargs,
  ) -> List[Dict]:
    mock_data = backend_kwargs.pop("mock_data", None)
    mean = backend_kwargs.pop("mean", self.luminescence_mean)
    cv = backend_kwargs.pop("cv", self.luminescence_cv)

    rows, cols = plate.num_items_y, plate.num_items_x
    if mock_data is not None:
      data = mock_data
    else:
      full = self._generate_grid(rows, cols, mean, cv)
      data = self._mask_grid(full, wells, plate)

    return [{
      "data": data,
      "temperature": self.temperature,
      "time": datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
    }]
