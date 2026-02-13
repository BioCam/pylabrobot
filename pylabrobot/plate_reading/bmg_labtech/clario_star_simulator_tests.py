import statistics
import unittest

from pylabrobot.plate_reading.bmg_labtech.clario_star_backend import StatusFlag
from pylabrobot.plate_reading.bmg_labtech.clario_star_simulator import CLARIOstarSimulatorBackend
from pylabrobot.resources import Cor_96_wellplate_360ul_Fb


class CLARIOstarSimulatorTestBase(unittest.IsolatedAsyncioTestCase):
  async def asyncSetUp(self):
    self.backend = CLARIOstarSimulatorBackend(seed=42)
    await self.backend.setup()
    self.plate = Cor_96_wellplate_360ul_Fb(name="test_plate")
    self.all_wells = self.plate.get_all_items()


class TestAbsorbanceFormat(CLARIOstarSimulatorTestBase):
  async def test_absorbance_returns_correct_format(self):
    results = await self.backend.read_absorbance(
      plate=self.plate, wells=self.all_wells, wavelength=450,
    )
    self.assertEqual(len(results), 1)
    r = results[0]
    self.assertIn("wavelength", r)
    self.assertIn("data", r)
    self.assertIn("temperature", r)
    self.assertIn("time", r)
    self.assertEqual(r["wavelength"], 450)
    self.assertEqual(len(r["data"]), 8)
    self.assertEqual(len(r["data"][0]), 12)

  async def test_multi_wavelength_absorbance(self):
    results = await self.backend.read_absorbance(
      plate=self.plate, wells=self.all_wells, wavelength=450,
      wavelengths=[450, 600],
    )
    self.assertEqual(len(results), 2)
    self.assertEqual(results[0]["wavelength"], 450)
    self.assertEqual(results[1]["wavelength"], 600)


class TestFluorescenceFormat(CLARIOstarSimulatorTestBase):
  async def test_fluorescence_returns_correct_format(self):
    results = await self.backend.read_fluorescence(
      plate=self.plate, wells=self.all_wells,
      excitation_wavelength=485, emission_wavelength=520, focal_height=13.0,
    )
    self.assertEqual(len(results), 1)
    r = results[0]
    self.assertIn("ex_wavelength", r)
    self.assertIn("em_wavelength", r)
    self.assertIn("data", r)
    self.assertIn("temperature", r)
    self.assertIn("time", r)
    self.assertEqual(r["ex_wavelength"], 485)
    self.assertEqual(r["em_wavelength"], 520)
    self.assertEqual(len(r["data"]), 8)
    self.assertEqual(len(r["data"][0]), 12)


class TestLuminescenceFormat(CLARIOstarSimulatorTestBase):
  async def test_luminescence_returns_correct_format(self):
    results = await self.backend.read_luminescence(
      plate=self.plate, wells=self.all_wells, focal_height=13.0,
    )
    self.assertEqual(len(results), 1)
    r = results[0]
    self.assertIn("data", r)
    self.assertIn("temperature", r)
    self.assertIn("time", r)
    self.assertNotIn("wavelength", r)
    self.assertEqual(len(r["data"]), 8)
    self.assertEqual(len(r["data"][0]), 12)


class TestMockData(CLARIOstarSimulatorTestBase):
  async def test_mock_data_used_directly(self):
    mock = [[float(r * 12 + c) for c in range(12)] for r in range(8)]
    results = await self.backend.read_absorbance(
      plate=self.plate, wells=self.all_wells, wavelength=450, mock_data=mock,
    )
    self.assertEqual(results[0]["data"], mock)

  async def test_mock_data_fluorescence(self):
    mock = [[100.0] * 12 for _ in range(8)]
    results = await self.backend.read_fluorescence(
      plate=self.plate, wells=self.all_wells,
      excitation_wavelength=485, emission_wavelength=520, focal_height=13.0,
      mock_data=mock,
    )
    self.assertEqual(results[0]["data"], mock)

  async def test_mock_data_luminescence(self):
    mock = [[999.0] * 12 for _ in range(8)]
    results = await self.backend.read_luminescence(
      plate=self.plate, wells=self.all_wells, focal_height=13.0, mock_data=mock,
    )
    self.assertEqual(results[0]["data"], mock)


class TestRandomGeneration(CLARIOstarSimulatorTestBase):
  async def test_random_generation_within_bounds(self):
    backend = CLARIOstarSimulatorBackend(absorbance_mean=1.0, absorbance_cv=0.05, seed=0)
    all_values = []
    for _ in range(10):
      results = await backend.read_absorbance(
        plate=self.plate, wells=self.all_wells, wavelength=450,
      )
      for row in results[0]["data"]:
        all_values.extend(v for v in row if v is not None)

    sample_mean = statistics.mean(all_values)
    sample_std = statistics.stdev(all_values)
    # With 960 samples, mean should be close to 1.0 and std close to 0.05
    self.assertAlmostEqual(sample_mean, 1.0, delta=0.02)
    self.assertAlmostEqual(sample_std, 0.05, delta=0.02)


class TestPartialWellSelection(CLARIOstarSimulatorTestBase):
  async def test_partial_well_selection(self):
    selected = [self.all_wells[0], self.all_wells[1]]  # A1, B1 (column-major)
    results = await self.backend.read_absorbance(
      plate=self.plate, wells=selected, wavelength=450,
    )
    data = results[0]["data"]
    # A1 (0,0) and B1 (1,0) should have values
    self.assertIsNotNone(data[0][0])
    self.assertIsNotNone(data[1][0])
    # All other wells should be None
    for r in range(8):
      for c in range(12):
        if (r, c) not in [(0, 0), (1, 0)]:
          self.assertIsNone(data[r][c])


class TestPerCallOverride(CLARIOstarSimulatorTestBase):
  async def test_per_call_mean_cv_override(self):
    backend = CLARIOstarSimulatorBackend(absorbance_mean=0.5, absorbance_cv=0.05, seed=0)
    all_values = []
    for _ in range(10):
      results = await backend.read_absorbance(
        plate=self.plate, wells=self.all_wells, wavelength=450,
        mean=2.0, cv=0.01,
      )
      for row in results[0]["data"]:
        all_values.extend(v for v in row if v is not None)

    sample_mean = statistics.mean(all_values)
    # Should be near 2.0, not the constructor default of 0.5
    self.assertAlmostEqual(sample_mean, 2.0, delta=0.05)


class TestSeedReproducibility(CLARIOstarSimulatorTestBase):
  async def test_seed_reproducibility(self):
    b1 = CLARIOstarSimulatorBackend(seed=123)
    b2 = CLARIOstarSimulatorBackend(seed=123)
    r1 = await b1.read_absorbance(plate=self.plate, wells=self.all_wells, wavelength=450)
    r2 = await b2.read_absorbance(plate=self.plate, wells=self.all_wells, wavelength=450)
    self.assertEqual(r1[0]["data"], r2[0]["data"])


class TestTemperature(CLARIOstarSimulatorTestBase):
  async def test_temperature_value(self):
    backend = CLARIOstarSimulatorBackend(temperature=37.0)
    results = await backend.read_absorbance(
      plate=self.plate, wells=self.plate.get_all_items(), wavelength=450,
    )
    self.assertEqual(results[0]["temperature"], 37.0)

  async def test_set_and_get_temperature(self):
    await self.backend.set_temperature(37.0)
    self.assertEqual(await self.backend.get_temperature(), 37.0)
    # Temperature change is reflected in subsequent reads
    results = await self.backend.read_absorbance(
      plate=self.plate, wells=self.all_wells, wavelength=450,
    )
    self.assertEqual(results[0]["temperature"], 37.0)

  async def test_set_temperature_zero_switches_off(self):
    await self.backend.set_temperature(0.0)
    self.assertEqual(await self.backend.get_temperature(), 0.0)


class TestStatus(CLARIOstarSimulatorTestBase):
  async def test_initial_status(self):
    status = await self.backend.get_status()
    self.assertIn(StatusFlag.VALID, status)
    self.assertIn(StatusFlag.INITIALIZED, status)
    self.assertNotIn(StatusFlag.BUSY, status)
    self.assertNotIn(StatusFlag.OPEN, status)

  async def test_open_sets_flag(self):
    await self.backend.open()
    status = await self.backend.get_status()
    self.assertIn(StatusFlag.OPEN, status)

  async def test_close_clears_open_sets_plate_detected(self):
    await self.backend.open()
    await self.backend.close(plate=self.plate)
    status = await self.backend.get_status()
    self.assertNotIn(StatusFlag.OPEN, status)
    self.assertIn(StatusFlag.PLATE_DETECTED, status)


class TestEepromData(CLARIOstarSimulatorTestBase):
  async def test_eeprom_returns_none(self):
    self.assertIsNone(self.backend.get_eeprom_data())


class TestExtraKwargsIgnored(CLARIOstarSimulatorTestBase):
  async def test_absorbance_ignores_extra_kwargs(self):
    results = await self.backend.read_absorbance(
      plate=self.plate, wells=self.all_wells, wavelength=450,
      report="transmittance", flashes=22, settling_time=0,
    )
    self.assertEqual(len(results), 1)

  async def test_fluorescence_ignores_extra_kwargs(self):
    results = await self.backend.read_fluorescence(
      plate=self.plate, wells=self.all_wells,
      excitation_wavelength=485, emission_wavelength=520, focal_height=8.5,
      gain=1500, ex_bandwidth=10, em_bandwidth=20, flashes=150, bottom_optic=True,
    )
    self.assertEqual(len(results), 1)

  async def test_luminescence_ignores_shaker_kwargs(self):
    from pylabrobot.plate_reading.bmg_labtech.clario_star_backend import ShakerType
    results = await self.backend.read_luminescence(
      plate=self.plate, wells=self.all_wells, focal_height=13.0,
      shake_type=ShakerType.ORBITAL, shake_speed_rpm=300, shake_duration_s=5,
    )
    self.assertEqual(len(results), 1)


if __name__ == "__main__":
  unittest.main()
