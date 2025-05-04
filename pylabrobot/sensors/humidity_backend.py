from abc import ABCMeta, abstractmethod
from pylabrobot.machines.backend import MachineBackend

class HumiditySensorBackend(MachineBackend, metaclass=ABCMeta):
  """Abstract interface for a humidity sensor."""

  @abstractmethod
  async def get_humidity(self) -> float:
    """Get the current relative humidity in percent."""
    ...
