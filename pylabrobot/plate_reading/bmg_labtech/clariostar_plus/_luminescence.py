"""CLARIOstar Plus luminescence measurement mixin (stub)."""

from typing import Dict, List

from pylabrobot.resources.plate import Plate
from pylabrobot.resources.well import Well


class _LuminescenceMixin:
  """Luminescence measurement for the CLARIOstar Plus.

  Not yet implemented — no USB capture data exists for the luminescence
  protocol. The CLARIOstar Plus hardware supports luminescence (confirmed
  via EEPROM capability flags), but the wire-level command encoding has
  not been reverse-engineered.
  """

  async def read_luminescence(
    self, plate: Plate, wells: List[Well], focal_height: float
  ) -> List[Dict]:
    raise NotImplementedError(
      "Luminescence not yet implemented for CLARIOstar Plus. "
      "USB capture data is needed to reverse-engineer the protocol."
    )
