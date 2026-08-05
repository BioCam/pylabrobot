"""Formulatrix Mantis contactless liquid dispenser device."""

from __future__ import annotations

from typing import Dict, Optional

from pylabrobot.capabilities.bulk_dispensers.diaphragm import DiaphragmDispenser
from pylabrobot.device import Device
from pylabrobot.formulatrix.mantis.diaphragm_dispenser_backend import (
  MantisDiaphragmDispenserBackend,
)
from pylabrobot.formulatrix.mantis.driver import MantisDriver


class Mantis(Device):
  """Formulatrix Mantis chip-based contactless liquid dispenser.

  Args:
    serial_number: FTDI serial number of the Mantis device (e.g. ``"M-000438"``).
    generation: instrument generation (``"v3.3"`` / ``"v4"``); selects the arm bring-up
      (v3.3 seeks the arm hard stops, v4 references from the absolute encoder).
    chip_type_map: Mapping from chip number (1-6) to chip type string (key in
      ``PPI_SEQUENCES``). Defaults to chips 3-5 as ``"high_volume"``.
  """

  def __init__(
    self,
    serial_number: Optional[str] = None,
    generation: str = "v3.3",
    chip_type_map: Optional[Dict[int, str]] = None,
    *,
    driver: Optional[MantisDriver] = None,
  ) -> None:
    if driver is None:
      driver = MantisDriver(
        serial_number=serial_number, generation=generation, chip_type_map=chip_type_map
      )
    super().__init__(driver=driver)
    self.driver: MantisDriver = driver
    self.diaphragm_dispenser = DiaphragmDispenser(
      backend=MantisDiaphragmDispenserBackend(driver)
    )
    self._capabilities = [self.diaphragm_dispenser]
