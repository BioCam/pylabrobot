import logging
from typing import Dict, List, Optional, cast

from pylabrobot.machines.machine import Machine, need_setup_finished
from pylabrobot.plate_reading.backend import PlateReaderBackend
from pylabrobot.plate_reading.standard import NoPlateError
from pylabrobot.plate_reading.utils import grid_to_wells_dict
from pylabrobot.resources import Coordinate, Plate, Resource, ResourceHolder, Rotation, Well

logger = logging.getLogger(__name__)


class PlateReader(ResourceHolder, Machine):
  """The front end for plate readers. Plate readers are devices that can read luminescence,
  absorbance, or fluorescence from a plate.

  Plate readers are asynchronous, meaning that their methods will return immediately and
  will not block.

  Here's an example of how to use this class in a Jupyter Notebook:

  >>> from pylabrobot.plate_reading.clario_star import CLARIOStarBackend
  >>> pr = PlateReader(backend=CLARIOStarBackend())
  >>> pr.setup()
  >>> await pr.read_luminescence()
  [[value1, value2, value3, ...], [value1, value2, value3, ...], ...
  """

  def __init__(
    self,
    name: str,
    size_x: float,
    size_y: float,
    size_z: float,
    backend: PlateReaderBackend,
    rotation: Optional["Rotation"] = None,
    category: Optional[str] = "plate_reader",
    model: Optional[str] = None,
    child_location: Coordinate = Coordinate.zero(),
    preferred_pickup_location: Optional[Coordinate] = None,
  ) -> None:
    ResourceHolder.__init__(
      self,
      name=name,
      size_x=size_x,
      size_y=size_y,
      size_z=size_z,
      rotation=rotation,
      category=category,
      model=model,
      child_location=child_location,
      preferred_pickup_location=preferred_pickup_location,
    )
    Machine.__init__(self, backend=backend)
    self.backend: PlateReaderBackend = backend  # fix type

  def assign_child_resource(
    self,
    resource: Resource,
    location: Optional[Coordinate] = None,
    reassign: bool = True,
  ):
    if len([c for c in self.children if isinstance(c, Plate)]) >= 1:
      raise ValueError("There already is a plate in the plate reader.")

    super().assign_child_resource(resource, location=location, reassign=reassign)

  def get_plate(self) -> Plate:
    plate_children = [c for c in self.children if isinstance(c, Plate)]
    if len(plate_children) == 0:
      raise NoPlateError("There is no plate in the plate reader.")
    return cast(Plate, plate_children[0])

  @need_setup_finished
  async def open(self, **backend_kwargs) -> None:
    await self.backend.open(**backend_kwargs)

  @need_setup_finished
  async def close(self, **backend_kwargs) -> None:
    plate = self.get_plate() if len(self.children) > 0 else None
    await self.backend.close(plate=plate, **backend_kwargs)

  @need_setup_finished
  async def read_luminescence(
    self,
    focal_height: float,
    wells: Optional[List[Well]] = None,
    use_new_return_type: bool = False,
    **backend_kwargs,
  ) -> List[Dict]:
    """Read the luminescence from the plate reader.

    Args:
      focal_height: The focal height to read the luminescence at, in millimeters.
      use_new_return_type: Whether to return the new return type, which is a list of dictionaries.

    Returns:
      A list of dictionaries, one for each measurement. Each dictionary contains:
        "time": float,
        "temperature": float,
        "data": List[List[float]]
    """

    plate = self.get_plate()
    resolved_wells = wells or plate.get_all_items()
    result = await self.backend.read_luminescence(
      plate=plate,
      wells=resolved_wells,
      focal_height=focal_height,
      **backend_kwargs,
    )

    if not use_new_return_type:
      logger.warning(
        "The return type of read_luminescence will change in a future version. Please set "
        "use_new_return_type=True to use the new return type."
      )
      return result[0]["data"]  # type: ignore[no-any-return]
    return self._enrich_result_shape(result, resolved_wells, plate, mode="luminescence")

  @need_setup_finished
  async def read_absorbance(
    self,
    wavelength: int,
    wells: Optional[List[Well]] = None,
    use_new_return_type: bool = False,
    **backend_kwargs,
  ) -> List[Dict]:
    """Read the absorbance from the plate reader.

    Args:
      wavelength: The wavelength to read the absorbance at, in nanometers.
      use_new_return_type: Whether to return the new return type, which is a list of dictionaries.

    Returns:
      A list of dictionaries, one for each measurement. Each dictionary contains:
        "wavelength": int,
        "time": float,
        "temperature": float,
        "data": List[List[float]]
    """

    plate = self.get_plate()
    resolved_wells = wells or plate.get_all_items()
    result = await self.backend.read_absorbance(
      plate=plate,
      wells=resolved_wells,
      wavelength=wavelength,
      **backend_kwargs,
    )

    if not use_new_return_type:
      logger.warning(
        "The return type of read_absorbance will change in a future version. Please set "
        "use_new_return_type=True to use the new return type."
      )
      return result[0]["data"]  # type: ignore[no-any-return]
    return self._enrich_result_shape(result, resolved_wells, plate, mode="absorbance")

  @need_setup_finished
  async def read_fluorescence(
    self,
    excitation_wavelength: int,
    emission_wavelength: int,
    focal_height: float,
    wells: Optional[List[Well]] = None,
    use_new_return_type: bool = False,
    **backend_kwargs,
  ) -> List[Dict]:
    """Read the fluorescence from the plate reader.

    Args:
      excitation_wavelength: The excitation wavelength to read the fluorescence at, in nanometers.
      emission_wavelength: The emission wavelength to read the fluorescence at, in nanometers.
      focal_height: The focal height to read the fluorescence at, in millimeters.
      use_new_return_type: Whether to return the new return type, which is a list of dictionaries.

    Returns:
      A list of dictionaries, one for each measurement. Each dictionary contains:
        "ex_wavelength": int,
        "em_wavelength": int,
        "time": float,
        "temperature": float,
        "data": List[List[float]]
    """

    if excitation_wavelength > emission_wavelength:
      logger.warning(
        "Excitation wavelength is greater than emission wavelength. This is unusual and may indicate an error."
      )

    plate = self.get_plate()
    resolved_wells = wells or plate.get_all_items()
    result = await self.backend.read_fluorescence(
      plate=plate,
      wells=resolved_wells,
      excitation_wavelength=excitation_wavelength,
      emission_wavelength=emission_wavelength,
      focal_height=focal_height,
      **backend_kwargs,
    )
    if not use_new_return_type:
      logger.warning(
        "The return type of read_fluorescence will change in a future version. Please set "
        "use_new_return_type=True to use the new return type."
      )
      return result[0]["data"]  # type: ignore[no-any-return]
    return self._enrich_result_shape(result, resolved_wells, plate, mode="fluorescence")

  @staticmethod
  def _enrich_result_shape(
    result: List[Dict],
    wells: List[Well],
    plate: Plate,
    *,
    mode: str,
  ) -> List[Dict]:
    """Add standard data-science-friendly fields to each result dict.

    For each entry in ``result``, populate any of the following that the
    backend didn't supply directly:

    - ``"wells"``: sparse ``{well_id: value}`` view of ``"data"``, computed
      via :func:`grid_to_wells_dict`.
    - ``"mode"``: the measurement modality the call originated from
      (``"fluorescence"``, ``"absorbance"``, ``"luminescence"``).

    Backends that populate these fields directly (such as the CLARIOstar
    Plus, which sets ``mode``/``units``/``overflow_threshold`` at the parser
    level) are left untouched. Backends that return only the row-major
    ``"data"`` grid get the well-keyed view and the mode tag for free, so
    downstream callers see a uniform shape across backends.
    """
    for entry in result:
      if "wells" not in entry:
        grid = entry.get("data")
        if grid is not None:
          entry["wells"] = grid_to_wells_dict(grid, wells, plate)
      entry.setdefault("mode", mode)
    return result

  def serialize(self) -> dict:
    return {**Resource.serialize(self), **Machine.serialize(self)}
