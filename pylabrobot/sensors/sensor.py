from typing import Optional

from pylabrobot.machines.machine import Machine
from pylabrobot.resources import Resource, Rotation
from pylabrobot.machines.backend import MachineBackend


class Sensor(Resource, Machine):
  """Generic sensor resource wrapping any MachineBackend."""

  def __init__(
    self,
    name: str,
    size_x: float = 10,  # default values for non-physical sensors
    size_y: float = 10,
    size_z: float = 10,
    backend: MachineBackend = None,
    rotation: Optional[Rotation] = None,
    category: Optional[str] = None,
    model: Optional[str] = None,
  ):
    Machine.__init__(self, backend=backend)
    Resource.__init__(
      self,
      name=name,
      size_x=size_x,
      size_y=size_y,
      size_z=size_z,
      rotation=rotation,
      category=category,
      model=model,
    )
    self.backend = backend  # type: ignore

  def serialize(self) -> dict:
    return {
      "name": self.name,
      "backend": self.backend.serialize() if self.backend else None,
      "category": self.category,
      "model": self.model
    }
