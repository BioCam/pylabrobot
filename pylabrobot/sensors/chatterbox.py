import random
import asyncio
from .temperature_backend import TemperatureSensorBackend
from .humidity_backend import HumiditySensorBackend

class ChatterboxSensorBackend(TemperatureSensorBackend, HumiditySensorBackend):
  """Dummy backend that simulates temperature and humidity readings."""

  async def setup(self) -> None:
    pass

  async def stop(self) -> None:
    pass

  def serialize(self) -> dict:
    return { "type": "ChatterboxSensorBackend" }

  async def get_temperature(self) -> float:
    await asyncio.sleep(0.1)
    return round(20 + 5 * random.random(), 2)

  async def get_humidity(self) -> float:
    await asyncio.sleep(0.1)
    return round(40 + 20 * random.random(), 2)

  async def get_temperature_and_humidity(self) -> tuple[float, float]:
    return await self.get_temperature(), await self.get_humidity()
