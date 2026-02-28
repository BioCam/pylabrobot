import logging
from typing import Dict, List, Optional, Union, cast

from pylabrobot.machines.machine import Machine, need_setup_finished
from pylabrobot.plate_reading.backend import PlateReaderBackend
from pylabrobot.plate_reading.result import AbsorbanceResult, FluorescenceResult, LuminescenceResult
from pylabrobot.plate_reading.standard import NoPlateError
from pylabrobot.resources import Coordinate, Plate, Resource, ResourceHolder, Well

logger = logging.getLogger(__name__)

_VALID_RETURN_TYPES = {"legacy", "dict", "result"}


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

  @staticmethod
  def _resolve_return_type(
    return_type: Optional[str],
    use_new_return_type: bool,
    method_name: str,
  ) -> str:
    """Resolve the effective return type from the two parameters.

    Priority: ``return_type`` wins if given; otherwise fall back to the legacy boolean.
    """

    if return_type is not None:
      if return_type not in _VALID_RETURN_TYPES:
        raise ValueError(
          f"return_type must be one of {_VALID_RETURN_TYPES!r}, got {return_type!r}"
        )
      return return_type

    # Legacy boolean path
    if use_new_return_type:
      return "dict"

    logger.warning(
      "The return type of %s will change in a future version. Please set "
      "return_type='dict' or return_type='result' to silence this warning.",
      method_name,
    )
    return "legacy"

  @need_setup_finished
  async def read_luminescence(
    self,
    focal_height: float,
    wells: Optional[List[Well]] = None,
    use_new_return_type: bool = False,
    return_type: Optional[str] = None,
    **backend_kwargs,
  ) -> Union[LuminescenceResult, List[Dict]]:
    """Read the luminescence from the plate reader.

    Args:
      focal_height: The focal height to read the luminescence at, in millimeters.
      use_new_return_type: Whether to return the ``List[Dict]`` return type (kept for
        backwards compatibility; prefer ``return_type``).
      return_type: ``"legacy"`` returns ``result[0]["data"]``, ``"dict"`` returns
        ``List[Dict]``, ``"result"`` returns a :class:`LuminescenceResult`.

    Returns:
      Depends on *return_type* / *use_new_return_type*.
    """

    rt = self._resolve_return_type(return_type, use_new_return_type, "read_luminescence")

    plate = self.get_plate()
    result = await self.backend.read_luminescence(
      plate=plate,
      wells=wells or plate.get_all_items(),
      focal_height=focal_height,
      **backend_kwargs,
    )

    if rt == "legacy":
      return result[0]["data"]  # type: ignore[no-any-return]
    if rt == "result":
      return LuminescenceResult(result, num_rows=plate.num_items_y, num_cols=plate.num_items_x)
    return result

  @need_setup_finished
  async def read_absorbance(
    self,
    wavelength: int,
    wells: Optional[List[Well]] = None,
    use_new_return_type: bool = False,
    return_type: Optional[str] = None,
    **backend_kwargs,
  ) -> Union[AbsorbanceResult, List[Dict]]:
    """Read the absorbance from the plate reader.

    Args:
      wavelength: The wavelength to read the absorbance at, in nanometers.
      use_new_return_type: Whether to return the ``List[Dict]`` return type (kept for
        backwards compatibility; prefer ``return_type``).
      return_type: ``"legacy"`` returns ``result[0]["data"]``, ``"dict"`` returns
        ``List[Dict]``, ``"result"`` returns an :class:`AbsorbanceResult`.

    Returns:
      Depends on *return_type* / *use_new_return_type*.
    """

    rt = self._resolve_return_type(return_type, use_new_return_type, "read_absorbance")

    plate = self.get_plate()
    result = await self.backend.read_absorbance(
      plate=plate,
      wells=wells or plate.get_all_items(),
      wavelength=wavelength,
      **backend_kwargs,
    )

    if rt == "legacy":
      return result[0]["data"]  # type: ignore[no-any-return]
    if rt == "result":
      return AbsorbanceResult(result, num_rows=plate.num_items_y, num_cols=plate.num_items_x)
    return result

  @need_setup_finished
  async def read_fluorescence(
    self,
    excitation_wavelength: int,
    emission_wavelength: int,
    focal_height: float,
    wells: Optional[List[Well]] = None,
    use_new_return_type: bool = False,
    return_type: Optional[str] = None,
    **backend_kwargs,
  ) -> Union[FluorescenceResult, List[Dict]]:
    """Read the fluorescence from the plate reader.

    Args:
      excitation_wavelength: The excitation wavelength to read the fluorescence at, in nanometers.
      emission_wavelength: The emission wavelength to read the fluorescence at, in nanometers.
      focal_height: The focal height to read the fluorescence at, in millimeters.
      use_new_return_type: Whether to return the ``List[Dict]`` return type (kept for
        backwards compatibility; prefer ``return_type``).
      return_type: ``"legacy"`` returns ``result[0]["data"]``, ``"dict"`` returns
        ``List[Dict]``, ``"result"`` returns a :class:`FluorescenceResult`.

    Returns:
      Depends on *return_type* / *use_new_return_type*.
    """

    if excitation_wavelength > emission_wavelength:
      logger.warning(
        "Excitation wavelength is greater than emission wavelength. This is unusual and may indicate an error."
      )

    rt = self._resolve_return_type(return_type, use_new_return_type, "read_fluorescence")

    plate = self.get_plate()
    result = await self.backend.read_fluorescence(
      plate=plate,
      wells=wells or plate.get_all_items(),
      excitation_wavelength=excitation_wavelength,
      emission_wavelength=emission_wavelength,
      focal_height=focal_height,
      **backend_kwargs,
    )

    if rt == "legacy":
      return result[0]["data"]  # type: ignore[no-any-return]
    if rt == "result":
      return FluorescenceResult(result, num_rows=plate.num_items_y, num_cols=plate.num_items_x)
    return result

  def serialize(self) -> dict:
    return {**Resource.serialize(self), **Machine.serialize(self)}
