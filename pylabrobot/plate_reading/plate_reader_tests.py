import asyncio
import unittest
from typing import Dict, List

from pylabrobot.plate_reading import PlateReader
from pylabrobot.plate_reading.backend import PlateReaderBackend
from pylabrobot.plate_reading.chatterbox import PlateReaderChatterboxBackend
from pylabrobot.resources import Cor_96_wellplate_360ul_Fb, Plate, Well


class TestPlateReaderResource(unittest.TestCase):
  """Test plate reader as a resource."""

  def setUp(self) -> None:
    super().setUp()
    self.pr = PlateReader(
      name="pr",
      backend=PlateReaderChatterboxBackend(),
      size_x=1,
      size_y=1,
      size_z=1,
    )

  def test_add_plate(self):
    plate = Plate("plate", size_x=1, size_y=1, size_z=1, ordered_items={})
    self.pr.assign_child_resource(plate)

  def test_add_plate_full(self):
    plate = Plate("plate", size_x=1, size_y=1, size_z=1, ordered_items={})
    self.pr.assign_child_resource(plate)

    another_plate = Plate("another_plate", size_x=1, size_y=1, size_z=1, ordered_items={})
    with self.assertRaises(ValueError):
      self.pr.assign_child_resource(another_plate)

  def test_get_plate(self):
    plate = Plate("plate", size_x=1, size_y=1, size_z=1, ordered_items={})
    self.pr.assign_child_resource(plate)

    self.assertEqual(self.pr.get_plate(), plate)


class _StubBackend(PlateReaderBackend):
  """Minimal backend that returns a canned grid for read_* calls.

  Optionally pre-populates the "wells" sibling so we can verify the wrapper
  leaves backend-supplied values alone.
  """

  def __init__(self, supply_wells: bool = False):
    self.supply_wells = supply_wells

  async def setup(self) -> None:
    pass

  async def stop(self) -> None:
    pass

  async def open(self, **_) -> None:
    pass

  async def close(self, plate=None, **_) -> None:
    pass

  def _make_result(self, base: Dict) -> List[Dict]:
    grid: List[List[float]] = [[None] * 12 for _ in range(8)]
    grid[0][0] = 100.0  # A1
    grid[2][3] = 200.0  # C4
    grid[7][11] = 300.0  # H12
    entry = {**base, "data": grid}
    if self.supply_wells:
      entry["wells"] = {"A1": 100.0, "C4": 200.0, "H12": 300.0, "_backend_marker": True}
    return [entry]

  async def read_luminescence(self, plate, wells, focal_height) -> List[Dict]:
    return self._make_result({"time": 0.0, "temperature": 25.0})

  async def read_absorbance(self, plate, wells, wavelength) -> List[Dict]:
    return self._make_result({"wavelength": wavelength, "time": 0.0, "temperature": 25.0})

  async def read_fluorescence(
    self, plate, wells, excitation_wavelength, emission_wavelength, focal_height
  ) -> List[Dict]:
    return self._make_result(
      {
        "ex_wavelength": excitation_wavelength,
        "em_wavelength": emission_wavelength,
        "time": 0.0,
        "temperature": 25.0,
      }
    )


class TestPlateReaderWellsEnrichment(unittest.TestCase):
  """Verify the wrapper populates ``"wells"`` when the backend omits it."""

  def setUp(self) -> None:
    self.plate = Cor_96_wellplate_360ul_Fb(name="plate")
    self.measured_wells: List[Well] = [
      self.plate.get_well("A1"),
      self.plate.get_well("C4"),
      self.plate.get_well("H12"),
    ]

  def _make_pr(self, supply_wells: bool) -> PlateReader:
    pr = PlateReader(
      name="pr",
      backend=_StubBackend(supply_wells=supply_wells),
      size_x=1,
      size_y=1,
      size_z=1,
    )
    pr._setup_finished = True  # bypass setup gate for tests
    pr.assign_child_resource(self.plate)
    return pr

  def test_fluorescence_wrapper_adds_wells_when_missing(self):
    """Backend returns only ``"data"`` -> wrapper computes ``"wells"`` from it."""
    pr = self._make_pr(supply_wells=False)
    result = asyncio.run(
      pr.read_fluorescence(
        excitation_wavelength=640,
        emission_wavelength=670,
        focal_height=8.0,
        wells=self.measured_wells,
        use_new_return_type=True,
      )
    )
    self.assertEqual(len(result), 1)
    self.assertIn("wells", result[0])
    self.assertEqual(result[0]["wells"], {"A1": 100.0, "C4": 200.0, "H12": 300.0})
    # Grid is preserved untouched.
    self.assertEqual(result[0]["data"][0][0], 100.0)
    self.assertEqual(result[0]["data"][7][11], 300.0)

  def test_absorbance_wrapper_adds_wells_when_missing(self):
    pr = self._make_pr(supply_wells=False)
    result = asyncio.run(
      pr.read_absorbance(
        wavelength=600,
        wells=self.measured_wells,
        use_new_return_type=True,
      )
    )
    self.assertEqual(result[0]["wells"], {"A1": 100.0, "C4": 200.0, "H12": 300.0})

  def test_luminescence_wrapper_adds_wells_when_missing(self):
    pr = self._make_pr(supply_wells=False)
    result = asyncio.run(
      pr.read_luminescence(
        focal_height=8.0,
        wells=self.measured_wells,
        use_new_return_type=True,
      )
    )
    self.assertEqual(result[0]["wells"], {"A1": 100.0, "C4": 200.0, "H12": 300.0})

  def test_wrapper_preserves_backend_supplied_wells(self):
    """Backend-supplied ``"wells"`` is not overwritten by the wrapper."""
    pr = self._make_pr(supply_wells=True)
    result = asyncio.run(
      pr.read_fluorescence(
        excitation_wavelength=640,
        emission_wavelength=670,
        focal_height=8.0,
        wells=self.measured_wells,
        use_new_return_type=True,
      )
    )
    # The marker key is unique to the backend's pre-populated dict.
    self.assertTrue(result[0]["wells"].get("_backend_marker"))
