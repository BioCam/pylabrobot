from abc import ABCMeta, abstractmethod
from pylabrobot.machines.backend import MachineBackend

class TemperatureSensorBackend(MachineBackend, metaclass=ABCMeta):
  """Abstract interface for a temperature sensor."""

  @abstractmethod
  async def get_temperature(self) -> float:
    """Get the current temperature in degrees Celsius."""
    ...
