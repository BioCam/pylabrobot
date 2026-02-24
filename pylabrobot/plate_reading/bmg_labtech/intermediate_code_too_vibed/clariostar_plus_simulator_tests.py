import statistics
import unittest
import warnings

from pylabrobot.plate_reading.bmg_labtech.clariostar_plus_simulator import (
  CLARIOstarPlusSimulatorBackend,
)

from pylabrobot.resources import Cor_96_wellplate_360ul_Fb


class CLARIOstarPlusSimulatorTestBase(unittest.IsolatedAsyncioTestCase):
  async def asyncSetUp(self):
    self.backend = CLARIOstarPlusSimulatorBackend(seed=42)
    await self.backend.setup()
    self.plate = Cor_96_wellplate_360ul_Fb(name="test_plate")
    self.all_wells = self.plate.get_all_items()


class TestAbsorbanceFormat(CLARIOstarPlusSimulatorTestBase):
  async def test_absorbance_returns_correct_format(self):
    results = await self.backend.read_absorbance(
      plate=self.plate,
      wells=self.all_wells,
      wavelength=450,
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
      plate=self.plate,
      wells=self.all_wells,
      wavelength=450,
      wavelengths=[450, 600],
    )
    self.assertEqual(len(results), 2)
    self.assertEqual(results[0]["wavelength"], 450)
    self.assertEqual(results[1]["wavelength"], 600)


class TestFluorescenceFormat(CLARIOstarPlusSimulatorTestBase):
  async def test_fluorescence_returns_correct_format(self):
    results = await self.backend.read_fluorescence(
      plate=self.plate,
      wells=self.all_wells,
      excitation_wavelength=485,
      emission_wavelength=520,
      focal_height=13.0,
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


class TestLuminescenceFormat(CLARIOstarPlusSimulatorTestBase):
  async def test_luminescence_returns_correct_format(self):
    results = await self.backend.read_luminescence(
      plate=self.plate,
      wells=self.all_wells,
      focal_height=13.0,
    )
    self.assertEqual(len(results), 1)
    r = results[0]
    self.assertIn("data", r)
    self.assertIn("temperature", r)
    self.assertIn("time", r)
    self.assertNotIn("wavelength", r)
    self.assertEqual(len(r["data"]), 8)
    self.assertEqual(len(r["data"][0]), 12)


class TestMockData(CLARIOstarPlusSimulatorTestBase):
  async def test_mock_data_used_directly(self):
    mock = [[float(r * 12 + c) for c in range(12)] for r in range(8)]
    results = await self.backend.read_absorbance(
      plate=self.plate,
      wells=self.all_wells,
      wavelength=450,
      mock_data=mock,
    )
    self.assertEqual(results[0]["data"], mock)

  async def test_mock_data_fluorescence(self):
    mock = [[100.0] * 12 for _ in range(8)]
    results = await self.backend.read_fluorescence(
      plate=self.plate,
      wells=self.all_wells,
      excitation_wavelength=485,
      emission_wavelength=520,
      focal_height=13.0,
      mock_data=mock,
    )
    self.assertEqual(results[0]["data"], mock)

  async def test_mock_data_luminescence(self):
    mock = [[999.0] * 12 for _ in range(8)]
    results = await self.backend.read_luminescence(
      plate=self.plate,
      wells=self.all_wells,
      focal_height=13.0,
      mock_data=mock,
    )
    self.assertEqual(results[0]["data"], mock)


class TestRandomGeneration(CLARIOstarPlusSimulatorTestBase):
  async def test_random_generation_within_bounds(self):
    backend = CLARIOstarPlusSimulatorBackend(absorbance_mean=1.0, absorbance_cv=0.05, seed=0)
    all_values = []
    for _ in range(10):
      results = await backend.read_absorbance(
        plate=self.plate,
        wells=self.all_wells,
        wavelength=450,
      )
      for row in results[0]["data"]:
        all_values.extend(v for v in row if v is not None)

    sample_mean = statistics.mean(all_values)
    sample_std = statistics.stdev(all_values)
    # With 960 samples, mean should be close to 1.0 and std close to 0.05
    self.assertAlmostEqual(sample_mean, 1.0, delta=0.02)
    self.assertAlmostEqual(sample_std, 0.05, delta=0.02)


class TestPartialWellSelection(CLARIOstarPlusSimulatorTestBase):
  async def test_partial_well_selection(self):
    selected = [self.all_wells[0], self.all_wells[1]]  # A1, B1 (column-major)
    results = await self.backend.read_absorbance(
      plate=self.plate,
      wells=selected,
      wavelength=450,
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


class TestPerCallOverride(CLARIOstarPlusSimulatorTestBase):
  async def test_per_call_mean_cv_override(self):
    backend = CLARIOstarPlusSimulatorBackend(absorbance_mean=0.5, absorbance_cv=0.05, seed=0)
    all_values = []
    for _ in range(10):
      results = await backend.read_absorbance(
        plate=self.plate,
        wells=self.all_wells,
        wavelength=450,
        mean=2.0,
        cv=0.01,
      )
      for row in results[0]["data"]:
        all_values.extend(v for v in row if v is not None)

    sample_mean = statistics.mean(all_values)
    # Should be near 2.0, not the constructor default of 0.5
    self.assertAlmostEqual(sample_mean, 2.0, delta=0.05)


class TestSeedReproducibility(CLARIOstarPlusSimulatorTestBase):
  async def test_seed_reproducibility(self):
    b1 = CLARIOstarPlusSimulatorBackend(seed=123)
    b2 = CLARIOstarPlusSimulatorBackend(seed=123)
    r1 = await b1.read_absorbance(plate=self.plate, wells=self.all_wells, wavelength=450)
    r2 = await b2.read_absorbance(plate=self.plate, wells=self.all_wells, wavelength=450)
    self.assertEqual(r1[0]["data"], r2[0]["data"])


class TestTemperature(CLARIOstarPlusSimulatorTestBase):
  async def test_ambient_temperature_in_results(self):
    results = await self.backend.read_absorbance(
      plate=self.plate,
      wells=self.all_wells,
      wavelength=450,
    )
    self.assertEqual(results[0]["temperature"], 21.0)

  async def test_incubation_reflected_in_results(self):
    await self.backend.start_temperature_control(37.0)
    results = await self.backend.read_absorbance(
      plate=self.plate,
      wells=self.all_wells,
      wavelength=450,
    )
    self.assertEqual(results[0]["temperature"], 37.0)

  async def test_measure_temperature_ambient(self):
    temp = await self.backend.measure_temperature()
    self.assertEqual(temp, 21.0)

  async def test_measure_temperature_incubating(self):
    await self.backend.start_temperature_control(25.0)
    temp = await self.backend.measure_temperature()
    self.assertEqual(temp, 25.0)

  async def test_measure_temperature_sensor_selection(self):
    await self.backend.start_temperature_control(37.0)
    self.assertEqual(await self.backend.measure_temperature(sensor="bottom"), 37.0)
    self.assertEqual(await self.backend.measure_temperature(sensor="top"), 37.0)
    self.assertEqual(await self.backend.measure_temperature(sensor="mean"), 37.0)

  async def test_stop_returns_to_ambient(self):
    await self.backend.start_temperature_control(37.0)
    await self.backend.stop_temperature_control()
    temp = await self.backend.measure_temperature()
    self.assertEqual(temp, 21.0)

  async def test_temperature_too_high_raises(self):
    with self.assertRaises(ValueError):
      await self.backend.start_temperature_control(50.0)

  async def test_temperature_negative_raises(self):
    with self.assertRaises(ValueError):
      await self.backend.start_temperature_control(-1.0)

  async def test_temperature_below_current_warns(self):
    with warnings.catch_warnings(record=True) as w:
      warnings.simplefilter("always")
      await self.backend.start_temperature_control(10.0)  # below ambient 21.0
      self.assertEqual(len(w), 1)
      self.assertIn("no active cooling", str(w[0].message))

  async def test_temperature_above_current_no_warning(self):
    with warnings.catch_warnings(record=True) as w:
      warnings.simplefilter("always")
      await self.backend.start_temperature_control(37.0)
      self.assertEqual(len(w), 0)


class TestStatus(CLARIOstarPlusSimulatorTestBase):
  async def test_initial_status(self):
    status = await self.backend.request_machine_status()
    self.assertTrue(status["valid"])
    self.assertTrue(status["initialized"])
    self.assertFalse(status["busy"])
    self.assertFalse(status["drawer_open"])
    self.assertEqual(len(status), 12)

  async def test_open_sets_flag(self):
    await self.backend.open()
    self.assertTrue(await self.backend.request_drawer_open())

  async def test_close_clears_open_sets_plate_detected(self):
    await self.backend.open()
    await self.backend.close(plate=self.plate)
    self.assertFalse(await self.backend.request_drawer_open())
    self.assertTrue(await self.backend.request_plate_detected())


class TestEepromData(CLARIOstarPlusSimulatorTestBase):
  async def test_eeprom_returns_none(self):
    self.assertIsNone(self.backend.get_eeprom_data())


class TestExtraKwargsIgnored(CLARIOstarPlusSimulatorTestBase):
  async def test_absorbance_ignores_extra_kwargs(self):
    results = await self.backend.read_absorbance(
      plate=self.plate,
      wells=self.all_wells,
      wavelength=450,
      report="transmittance",
      flashes=22,
      pause_time_per_well=0,
    )
    self.assertEqual(len(results), 1)

  async def test_fluorescence_ignores_extra_kwargs(self):
    results = await self.backend.read_fluorescence(
      plate=self.plate,
      wells=self.all_wells,
      excitation_wavelength=485,
      emission_wavelength=520,
      focal_height=8.5,
      gain=1500,
      ex_bandwidth=10,
      em_bandwidth=20,
      flashes=150,
      bottom_optic=True,
    )
    self.assertEqual(len(results), 1)

  async def test_luminescence_ignores_shaker_kwargs(self):
    from pylabrobot.plate_reading.bmg_labtech.clariostar_plus_backend import ShakerType

    results = await self.backend.read_luminescence(
      plate=self.plate,
      wells=self.all_wells,
      focal_height=13.0,
      shake_type=ShakerType.ORBITAL,
      shake_speed_rpm=300,
      shake_duration_s=5,
    )
    self.assertEqual(len(results), 1)


class TestWaitFalse(CLARIOstarPlusSimulatorTestBase):
  async def test_absorbance_wait_false_returns_none(self):
    result = await self.backend.read_absorbance(
      plate=self.plate,
      wells=self.all_wells,
      wavelength=450,
      wait=False,
    )
    self.assertIsNone(result)

  async def test_absorbance_collect_after_wait_false(self):
    await self.backend.read_absorbance(
      plate=self.plate,
      wells=self.all_wells,
      wavelength=450,
      wait=False,
    )
    results = await self.backend.collect_absorbance_measurement(
      plate=self.plate,
      wells=self.all_wells,
      wavelengths=[450],
    )
    self.assertEqual(len(results), 1)
    self.assertEqual(results[0]["wavelength"], 450)
    self.assertEqual(len(results[0]["data"]), 8)

  async def test_fluorescence_wait_false_returns_none(self):
    result = await self.backend.read_fluorescence(
      plate=self.plate,
      wells=self.all_wells,
      excitation_wavelength=485,
      emission_wavelength=520,
      focal_height=13.0,
      wait=False,
    )
    self.assertIsNone(result)

  async def test_fluorescence_collect_after_wait_false(self):
    await self.backend.read_fluorescence(
      plate=self.plate,
      wells=self.all_wells,
      excitation_wavelength=485,
      emission_wavelength=520,
      focal_height=13.0,
      wait=False,
    )
    results = await self.backend.collect_fluorescence_measurement(
      plate=self.plate,
      wells=self.all_wells,
      excitation_wavelength=485,
      emission_wavelength=520,
    )
    self.assertEqual(len(results), 1)
    self.assertEqual(results[0]["ex_wavelength"], 485)
    self.assertEqual(results[0]["em_wavelength"], 520)

  async def test_luminescence_wait_false_returns_none(self):
    result = await self.backend.read_luminescence(
      plate=self.plate,
      wells=self.all_wells,
      focal_height=13.0,
      wait=False,
    )
    self.assertIsNone(result)

  async def test_luminescence_collect_after_wait_false(self):
    await self.backend.read_luminescence(
      plate=self.plate,
      wells=self.all_wells,
      focal_height=13.0,
      wait=False,
    )
    results = await self.backend.collect_luminescence_measurement(
      plate=self.plate,
      wells=self.all_wells,
    )
    self.assertEqual(len(results), 1)
    self.assertIn("data", results[0])
    self.assertEqual(len(results[0]["data"]), 8)


class TestBuildAbsorbanceResponse(unittest.TestCase):
  """Round-trip tests: build_absorbance_response → _parse_absorbance_response."""

  def test_round_trip_single_wavelength(self):
    """Build a single-wavelength response and parse it back."""
    from pylabrobot.plate_reading.bmg_labtech.clariostar_plus_backend import CLARIOstarPlusBackend

    num_wells = 96
    num_wl = 1
    c_hi = 100000.0
    r_hi = 200000.0
    samples = [50000.0 + i * 100 for i in range(num_wells)]
    refs = [100000.0 + i * 50 for i in range(num_wells)]

    frame = CLARIOstarPlusSimulatorBackend.build_absorbance_response(
      num_wells=num_wells,
      num_wavelengths=num_wl,
      samples=samples,
      references=refs,
      chromatic_cal=[(c_hi, 0.0)],
      reference_cal=(r_hi, 0.0),
      temperature_raw=250,
      schema=0x29,
    )

    transmission, temperature, raw = CLARIOstarPlusBackend._parse_absorbance_response(frame, num_wl)

    self.assertEqual(len(transmission), num_wells)
    self.assertAlmostEqual(temperature, 25.0, places=1)
    self.assertEqual(len(raw["samples"]), num_wells * num_wl)
    self.assertEqual(len(raw["references"]), num_wells)
    # Verify sample values round-trip
    for i in range(num_wells):
      self.assertAlmostEqual(raw["samples"][i], samples[i], places=0)
      self.assertAlmostEqual(raw["references"][i], refs[i], places=0)
    # Verify calibration round-trip
    self.assertAlmostEqual(raw["chromatic_cal"][0][0], c_hi, places=0)
    self.assertAlmostEqual(raw["reference_cal"][0], r_hi, places=0)

  def test_round_trip_multi_wavelength(self):
    """Build a 2-wavelength response and parse it back."""
    from pylabrobot.plate_reading.bmg_labtech.clariostar_plus_backend import CLARIOstarPlusBackend

    num_wells = 96
    num_wl = 2
    samples = [float(40000 + i) for i in range(num_wells * num_wl)]
    refs = [float(100000 + i) for i in range(num_wells)]

    frame = CLARIOstarPlusSimulatorBackend.build_absorbance_response(
      num_wells=num_wells,
      num_wavelengths=num_wl,
      samples=samples,
      references=refs,
      chromatic_cal=[(100000.0, 0.0), (100000.0, 0.0)],
      reference_cal=(200000.0, 0.0),
    )

    transmission, temperature, raw = CLARIOstarPlusBackend._parse_absorbance_response(frame, num_wl)

    self.assertEqual(len(transmission), num_wells)
    self.assertEqual(len(transmission[0]), num_wl)
    self.assertEqual(len(raw["samples"]), num_wells * num_wl)

  def test_incubation_schema_temperature(self):
    """Schema 0xA9 puts temperature at offset 34-35."""
    from pylabrobot.plate_reading.bmg_labtech.clariostar_plus_backend import CLARIOstarPlusBackend

    num_wells = 8
    num_wl = 1
    samples = [50000.0] * num_wells
    refs = [100000.0] * num_wells

    frame = CLARIOstarPlusSimulatorBackend.build_absorbance_response(
      num_wells=num_wells,
      num_wavelengths=num_wl,
      samples=samples,
      references=refs,
      chromatic_cal=[(100000.0, 0.0)],
      reference_cal=(200000.0, 0.0),
      temperature_raw=370,
      schema=0xA9,
    )

    _, temperature, _ = CLARIOstarPlusBackend._parse_absorbance_response(frame, num_wl)
    self.assertAlmostEqual(temperature, 37.0, places=1)

  def test_transmittance_calculation(self):
    """Verify T% = (sample / c_hi) * (r_hi / ref) * 100 round-trips correctly."""
    from pylabrobot.plate_reading.bmg_labtech.clariostar_plus_backend import CLARIOstarPlusBackend

    c_hi = 100000.0
    r_hi = 200000.0
    sample_val = 50000.0
    ref_val = 200000.0
    # Expected T% = (50000/100000) * (200000/200000) * 100 = 50.0

    frame = CLARIOstarPlusSimulatorBackend.build_absorbance_response(
      num_wells=1,
      num_wavelengths=1,
      samples=[sample_val],
      references=[ref_val],
      chromatic_cal=[(c_hi, 0.0)],
      reference_cal=(r_hi, 0.0),
    )

    transmission, _, _ = CLARIOstarPlusBackend._parse_absorbance_response(frame, 1)
    self.assertAlmostEqual(transmission[0][0], 50.0, places=1)


class TestBinaryRoundTripPath(CLARIOstarPlusSimulatorTestBase):
  """Verify the simulator's read path goes through binary build→parse round-trip."""

  async def test_absorbance_od_values_are_plausible(self):
    """OD values from binary round-trip should be close to configured mean."""
    results = await self.backend.read_absorbance(
      plate=self.plate,
      wells=self.all_wells,
      wavelength=450,
    )
    self.assertEqual(len(results), 1)
    r = results[0]
    # All 96 wells should have non-None float values
    for row in r["data"]:
      for val in row:
        self.assertIsNotNone(val)
        self.assertIsInstance(val, float)
    # Mean OD should be close to the configured absorbance_mean (0.5)
    flat = [v for row in r["data"] for v in row]
    mean_od = statistics.mean(flat)
    self.assertAlmostEqual(mean_od, 0.5, delta=0.15)

  async def test_absorbance_raw_report_has_detector_counts(self):
    """report='raw' should return detector counts and calibration from the binary frame."""
    results = await self.backend.read_absorbance(
      plate=self.plate,
      wells=self.all_wells,
      wavelength=600,
      report="raw",
    )
    r = results[0]
    self.assertIn("references", r)
    self.assertIn("chromatic_cal", r)
    self.assertIn("reference_cal", r)
    # references should be a list of floats (detector counts)
    self.assertEqual(len(r["references"]), 96)
    # chromatic_cal should be a (hi, lo) tuple
    self.assertEqual(len(r["chromatic_cal"]), 2)
    self.assertGreater(r["chromatic_cal"][0], 0)

  async def test_absorbance_transmittance_report(self):
    """report='transmittance' should return T% values (positive, typically 10-90%)."""
    results = await self.backend.read_absorbance(
      plate=self.plate,
      wells=self.all_wells,
      wavelength=450,
      report="transmittance",
    )
    r = results[0]
    flat = [v for row in r["data"] for v in row if v is not None]
    self.assertEqual(len(flat), 96)
    for val in flat:
      self.assertGreater(val, 0)
      self.assertLess(val, 200)  # T% should be reasonable

  async def test_multi_wavelength_binary_round_trip(self):
    """Multi-wavelength reads should produce separate results per wavelength."""
    results = await self.backend.read_absorbance(
      plate=self.plate,
      wells=self.all_wells,
      wavelength=450,
      wavelengths=[450, 600],
    )
    self.assertEqual(len(results), 2)
    self.assertEqual(results[0]["wavelength"], 450)
    self.assertEqual(results[1]["wavelength"], 600)
    # Each should have 8x12 grid
    for r in results:
      self.assertEqual(len(r["data"]), 8)
      self.assertEqual(len(r["data"][0]), 12)

  async def test_temperature_embedded_in_binary(self):
    """Temperature should come from the binary frame, not just from _current_temperature."""
    await self.backend.start_temperature_control(37.0)
    results = await self.backend.read_absorbance(
      plate=self.plate,
      wells=self.all_wells,
      wavelength=450,
    )
    self.assertAlmostEqual(results[0]["temperature"], 37.0, places=0)


class TestVerboseMode(CLARIOstarPlusSimulatorTestBase):
  """Test verbose mode controls decoded annotations; hex dump always prints."""

  async def test_always_prints_hex_dump(self):
    """The simulator always prints command hex dumps (like STARChatterboxBackend)."""
    import io
    import sys

    captured = io.StringIO()
    old_stdout = sys.stdout
    sys.stdout = captured
    try:
      await self.backend.read_absorbance(
        plate=self.plate,
        wells=self.all_wells,
        wavelength=450,
      )
    finally:
      sys.stdout = old_stdout
    output = captured.getvalue()
    # Should contain the hex dump even with verbose=False (default)
    self.assertIn("[SIM] WRITE", output)

  async def test_verbose_prints_decoded_annotations(self):
    """When verbose=True, the simulator also prints decoded byte-level annotations."""
    import io
    import sys

    self.backend.set_verbose(True)
    captured = io.StringIO()
    old_stdout = sys.stdout
    sys.stdout = captured
    try:
      await self.backend.read_absorbance(
        plate=self.plate,
        wells=self.all_wells,
        wavelength=450,
      )
    finally:
      sys.stdout = old_stdout
    output = captured.getvalue()
    self.assertIn("[SIM]", output)
    self.assertIn("ABSORBANCE_RESPONSE", output)
    # Should contain decoded annotation columns
    self.assertIn("Offset", output)
    self.assertIn("Hex", output)
    self.assertIn("Decoded", output)

  async def test_verbose_off_no_annotations(self):
    """When verbose=False, decoded annotations are not printed."""
    import io
    import sys

    captured = io.StringIO()
    old_stdout = sys.stdout
    sys.stdout = captured
    try:
      await self.backend.read_absorbance(
        plate=self.plate,
        wells=self.all_wells,
        wavelength=450,
      )
    finally:
      sys.stdout = old_stdout
    output = captured.getvalue()
    # Hex dump is printed, but not the decoded annotation table
    self.assertIn("[SIM] WRITE", output)
    self.assertNotIn("ABSORBANCE_RESPONSE", output)
    self.assertNotIn("Offset", output)


if __name__ == "__main__":
  unittest.main()
