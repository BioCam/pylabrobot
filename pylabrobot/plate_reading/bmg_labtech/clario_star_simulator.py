import datetime
import random
from typing import Dict, List, Optional, Tuple

from pylabrobot.plate_reading.backend import PlateReaderBackend
from pylabrobot.plate_reading.bmg_labtech.clario_star_backend import CLARIOstarConfig
from pylabrobot.resources.plate import Plate
from pylabrobot.resources.well import Well


class CLARIOstarSimulatorBackend(PlateReaderBackend):
  """A simulator backend for the CLARIOstar plate reader.

  Generates realistic random data from configurable mean/CV per modality,
  or accepts explicit mock data passed via ``**backend_kwargs``.

  Return formats match the real ``CLARIOstarBackend`` exactly.

  Supports ``wait=False`` in read methods (returns None immediately) and
  ``collect_*_measurement()`` for deferred retrieval, mirroring the real backend.
  """

  _AMBIENT_TEMP: float = 21.0

  def __init__(
    self,
    absorbance_mean: float = 0.5,
    absorbance_cv: float = 0.05,
    fluorescence_mean: float = 10000.0,
    fluorescence_cv: float = 0.10,
    luminescence_mean: float = 5000.0,
    luminescence_cv: float = 0.10,
    seed: Optional[int] = None,
  ):
    self.absorbance_mean = absorbance_mean
    self.absorbance_cv = absorbance_cv
    self.fluorescence_mean = fluorescence_mean
    self.fluorescence_cv = fluorescence_cv
    self.luminescence_mean = luminescence_mean
    self.luminescence_cv = luminescence_cv
    self._incubation_target: float = 0.0
    self._rng = random.Random(seed)
    self._is_open = False
    self._plate_in_drawer = False

  @property
  def _current_temperature(self) -> float:
    """The simulated temperature: incubation target if heating, else ambient."""
    if self._incubation_target > 0:
      return self._incubation_target
    return self._AMBIENT_TEMP

  async def setup(self) -> None:
    pass

  async def stop(self) -> None:
    pass

  async def open(self) -> None:
    self._is_open = True

  async def close(self, plate: Optional[Plate] = None) -> None:
    self._is_open = False
    if plate is not None:
      self._plate_in_drawer = True

  async def request_machine_status(self) -> Dict[str, bool]:
    """Return simulated status flags reflecting current simulator state."""
    return {
      "standby": False,
      "valid": True,
      "busy": False,
      "running": False,
      "unread_data": False,
      "initialized": True,
      "lid_open": False,
      "drawer_open": self._is_open,
      "plate_detected": self._plate_in_drawer,
      "z_probed": False,
      "active": False,
      "filter_cover_open": False,
    }

  async def request_drawer_open(self) -> bool:
    """Request whether the drawer is currently open."""
    return (await self.request_machine_status())["drawer_open"]

  async def request_plate_detected(self) -> bool:
    """Request whether a plate is detected in the drawer."""
    return (await self.request_machine_status())["plate_detected"]

  async def request_busy(self) -> bool:
    """Request whether the machine is currently executing a command."""
    return (await self.request_machine_status())["busy"]

  async def request_initialization_status(self) -> bool:
    """Request whether the instrument has been initialized."""
    return (await self.request_machine_status())["initialized"]

  def get_eeprom_data(self) -> Optional[bytes]:
    """Return None (no physical EEPROM in simulation)."""
    return None

  def get_machine_config(self) -> CLARIOstarConfig:
    """Return a synthetic CLARIOstarConfig for the simulated instrument."""
    return CLARIOstarConfig(
      serial_number="SIM-0000",
      firmware_version="1.35",
      firmware_build_timestamp="Jan 01 2025 00:00:00",
      model_name="CLARIOstar Plus (Simulator)",
      machine_type_code=0x0024,
      has_absorbance=True,
      has_fluorescence=True,
      has_luminescence=True,
      has_alpha_technology=False,
      has_pump1=False,
      has_pump2=False,
      has_stacker=False,
      monochromator_range=(220, 1000),
      num_filter_slots=11,
    )

  def dump_eeprom_str(self) -> Optional[str]:
    """Return None (no physical EEPROM in simulation)."""
    return None

  async def request_usage_counters(self) -> Dict[str, int]:
    """Return synthetic usage counters for the simulated instrument."""
    return {
      "flashes": 0, "testruns": 0, "wells": 0, "well_movements": 0,
      "active_time_s": 0, "shake_time_s": 0,
      "pump1_usage": 0, "pump2_usage": 0, "alpha_time": 0,
    }

  async def start_temperature_control(self, temperature: float) -> None:
    """Start active temperature control (simulated incubation)."""
    self._incubation_target = temperature

  async def stop_temperature_control(self) -> None:
    """Switch off the incubator and temperature monitoring."""
    self._incubation_target = 0.0

  async def measure_temperature(self) -> Tuple[float, float]:
    """Activate temperature monitoring and return the current simulated temperature.

    Returns:
      (sensor1_celsius, sensor2_celsius) — in simulation both sensors return the same value.
    """
    return (self._current_temperature, self._current_temperature)

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
  ) -> Optional[List[Dict]]:
    wait = backend_kwargs.pop("wait", True)
    wavelengths = backend_kwargs.pop("wavelengths", [wavelength])
    if isinstance(wavelengths, int):
      wavelengths = [wavelengths]
    report = backend_kwargs.pop("report", "OD")
    mock_data = backend_kwargs.pop("mock_data", None)
    mean = backend_kwargs.pop("mean", self.absorbance_mean)
    cv = backend_kwargs.pop("cv", self.absorbance_cv)

    if not wait:
      # Stash params for deferred collection
      self._pending_absorbance = {
        "plate": plate, "wells": wells, "wavelengths": wavelengths,
        "report": report, "mock_data": mock_data, "mean": mean, "cv": cv,
      }
      return None

    return self._generate_absorbance(plate, wells, wavelengths, report, mock_data, mean, cv)

  def _generate_absorbance(
    self, plate, wells, wavelengths, report, mock_data, mean, cv,
  ) -> List[Dict]:
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
        "temperature": self._current_temperature,
        "time": datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
      }
      if report == "raw":
        num_wells = len(wells)
        entry["references"] = [self._rng.gauss(100000, 1000) for _ in range(num_wells)]
        entry["chromatic_cal"] = (100000.0, 0.0)
        entry["reference_cal"] = (200000.0, 0.0)
      results.append(entry)
    return results

  async def collect_absorbance_measurement(
    self,
    plate: Plate,
    wells: List[Well],
    wavelengths: List[int],
    report: str = "OD",
  ) -> List[Dict]:
    """Retrieve absorbance data after a ``wait=False`` read."""
    pending = getattr(self, "_pending_absorbance", None)
    if pending is not None:
      result = self._generate_absorbance(**pending)
      self._pending_absorbance = None
      return result
    return self._generate_absorbance(
      plate, wells, wavelengths, report, None, self.absorbance_mean, self.absorbance_cv,
    )

  async def read_fluorescence(
    self,
    plate: Plate,
    wells: List[Well],
    excitation_wavelength: int,
    emission_wavelength: int,
    focal_height: float,
    **backend_kwargs,
  ) -> Optional[List[Dict]]:
    wait = backend_kwargs.pop("wait", True)
    mock_data = backend_kwargs.pop("mock_data", None)
    mean = backend_kwargs.pop("mean", self.fluorescence_mean)
    cv = backend_kwargs.pop("cv", self.fluorescence_cv)

    if not wait:
      self._pending_fluorescence = {
        "plate": plate, "wells": wells,
        "excitation_wavelength": excitation_wavelength,
        "emission_wavelength": emission_wavelength,
        "mock_data": mock_data, "mean": mean, "cv": cv,
      }
      return None

    return self._generate_fluorescence(
      plate, wells, excitation_wavelength, emission_wavelength, mock_data, mean, cv,
    )

  def _generate_fluorescence(
    self, plate, wells, excitation_wavelength, emission_wavelength, mock_data, mean, cv,
  ) -> List[Dict]:
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
      "temperature": self._current_temperature,
      "time": datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
    }]

  async def collect_fluorescence_measurement(
    self,
    plate: Plate,
    wells: List[Well],
    excitation_wavelength: int,
    emission_wavelength: int,
  ) -> List[Dict]:
    """Retrieve fluorescence data after a ``wait=False`` read."""
    pending = getattr(self, "_pending_fluorescence", None)
    if pending is not None:
      result = self._generate_fluorescence(**pending)
      self._pending_fluorescence = None
      return result
    return self._generate_fluorescence(
      plate, wells, excitation_wavelength, emission_wavelength,
      None, self.fluorescence_mean, self.fluorescence_cv,
    )

  async def read_luminescence(
    self,
    plate: Plate,
    wells: List[Well],
    focal_height: float,
    **backend_kwargs,
  ) -> Optional[List[Dict]]:
    wait = backend_kwargs.pop("wait", True)
    mock_data = backend_kwargs.pop("mock_data", None)
    mean = backend_kwargs.pop("mean", self.luminescence_mean)
    cv = backend_kwargs.pop("cv", self.luminescence_cv)

    if not wait:
      self._pending_luminescence = {
        "plate": plate, "wells": wells,
        "mock_data": mock_data, "mean": mean, "cv": cv,
      }
      return None

    return self._generate_luminescence(plate, wells, mock_data, mean, cv)

  def _generate_luminescence(self, plate, wells, mock_data, mean, cv) -> List[Dict]:
    rows, cols = plate.num_items_y, plate.num_items_x
    if mock_data is not None:
      data = mock_data
    else:
      full = self._generate_grid(rows, cols, mean, cv)
      data = self._mask_grid(full, wells, plate)

    return [{
      "data": data,
      "temperature": self._current_temperature,
      "time": datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
    }]

  async def collect_luminescence_measurement(
    self,
    plate: Plate,
    wells: List[Well],
  ) -> List[Dict]:
    """Retrieve luminescence data after a ``wait=False`` read."""
    pending = getattr(self, "_pending_luminescence", None)
    if pending is not None:
      result = self._generate_luminescence(**pending)
      self._pending_luminescence = None
      return result
    return self._generate_luminescence(
      plate, wells, None, self.luminescence_mean, self.luminescence_cv,
    )
