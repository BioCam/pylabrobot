"""Tests for PlateReaderResult and measurement-specific subclasses."""

import collections.abc
import sys
import unittest
from typing import Dict, List
from unittest import mock

from pylabrobot.plate_reading.result import (
  AbsorbanceResult,
  FluorescenceResult,
  LuminescenceResult,
  PlateReaderResult,
  _parse_well_name,
)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _make_entry(
  wavelength=None, ex_wavelength=None, em_wavelength=None,
  temperature=None, time=None, num_rows=8, num_cols=12, fill=None,
) -> Dict:
  """Build a single result entry dict."""
  grid = [
    [fill if fill is not None else (r * num_cols + c + 1) * 0.001 for c in range(num_cols)]
    for r in range(num_rows)
  ]
  entry: Dict = {"data": grid}
  if wavelength is not None:
    entry["wavelength"] = wavelength
  if ex_wavelength is not None:
    entry["ex_wavelength"] = ex_wavelength
  if em_wavelength is not None:
    entry["em_wavelength"] = em_wavelength
  if temperature is not None:
    entry["temperature"] = temperature
  if time is not None:
    entry["time"] = time
  return entry


def _make_absorbance_data(
  start_wl=300, end_wl=700, step=1, num_rows=8, num_cols=12,
) -> List[Dict]:
  """Build entries mimicking an absorbance spectrum scan."""
  data = []
  for wl in range(start_wl, end_wl + 1, step):
    grid = [
      [round(wl * 0.001 + r * 0.01 + c * 0.0001, 4) for c in range(num_cols)]
      for r in range(num_rows)
    ]
    data.append({"wavelength": wl, "data": grid, "temperature": 25.0, "time": wl * 0.1})
  return data


def _make_fluorescence_data(num_rows=8, num_cols=12) -> List[Dict]:
  """Build entries mimicking a fluorescence measurement."""
  return [
    _make_entry(ex_wavelength=485, em_wavelength=528, temperature=25.0, time=1.0,
                num_rows=num_rows, num_cols=num_cols, fill=100.5),
    _make_entry(ex_wavelength=485, em_wavelength=590, temperature=25.1, time=2.0,
                num_rows=num_rows, num_cols=num_cols, fill=42.3),
  ]


def _make_luminescence_data(num_rows=8, num_cols=12) -> List[Dict]:
  """Build entries mimicking a luminescence measurement."""
  return [
    _make_entry(temperature=25.0, time=0.5, num_rows=num_rows, num_cols=num_cols, fill=5000.0),
  ]


# ===========================================================================
# Well name parsing
# ===========================================================================


class TestParseWellName(unittest.TestCase):
  def test_single_letter_rows(self):
    self.assertEqual(_parse_well_name("A1"), (0, 0))
    self.assertEqual(_parse_well_name("A12"), (0, 11))
    self.assertEqual(_parse_well_name("H1"), (7, 0))
    self.assertEqual(_parse_well_name("H12"), (7, 11))
    self.assertEqual(_parse_well_name("Z1"), (25, 0))

  def test_double_letter_rows(self):
    self.assertEqual(_parse_well_name("AA1"), (26, 0))
    self.assertEqual(_parse_well_name("AB1"), (27, 0))
    self.assertEqual(_parse_well_name("AZ1"), (51, 0))
    self.assertEqual(_parse_well_name("BA1"), (52, 0))

  def test_invalid_names(self):
    with self.assertRaises(ValueError):
      _parse_well_name("")
    with self.assertRaises(ValueError):
      _parse_well_name("1A")
    with self.assertRaises(ValueError):
      _parse_well_name("a1")
    with self.assertRaises(ValueError):
      _parse_well_name("A")
    with self.assertRaises(ValueError):
      _parse_well_name("A0")


# ===========================================================================
# Base PlateReaderResult — backwards compatibility
# ===========================================================================


class TestBaseBackwardsCompat(unittest.TestCase):
  def setUp(self):
    self.data = _make_absorbance_data(start_wl=300, end_wl=302, step=1)
    self.result = PlateReaderResult(self.data)

  def test_len(self):
    self.assertEqual(len(self.result), 3)

  def test_int_indexing(self):
    self.assertEqual(self.result[0], self.data[0])
    self.assertEqual(self.result[1], self.data[1])

  def test_negative_indexing(self):
    self.assertEqual(self.result[-1], self.data[-1])

  def test_iteration(self):
    self.assertEqual(list(self.result), self.data)

  def test_contains(self):
    self.assertIn(self.data[0], self.result)

  def test_truthiness(self):
    self.assertTrue(self.result)
    self.assertFalse(PlateReaderResult([]))

  def test_eq_list(self):
    self.assertEqual(self.result, self.data)

  def test_eq_another_result(self):
    self.assertEqual(self.result, PlateReaderResult(self.data))

  def test_is_sequence(self):
    self.assertIsInstance(self.result, collections.abc.Sequence)

  def test_index_out_of_range(self):
    with self.assertRaises(IndexError):
      _ = self.result[100]


# ===========================================================================
# Base — well access
# ===========================================================================


class TestBaseWellAccess(unittest.TestCase):
  def setUp(self):
    self.data = _make_absorbance_data(start_wl=300, end_wl=302, step=1)
    self.result = PlateReaderResult(self.data)

  def test_bracket_str_access(self):
    expected = [entry["data"][0][0] for entry in self.data]
    self.assertEqual(self.result["A1"], expected)

  def test_well_method(self):
    expected = [entry["data"][0][0] for entry in self.data]
    self.assertEqual(self.result.well("A1"), expected)

  def test_last_well(self):
    expected = [entry["data"][7][11] for entry in self.data]
    self.assertEqual(self.result["H12"], expected)

  def test_invalid_well_name(self):
    with self.assertRaises(ValueError):
      self.result["invalid"]

  def test_out_of_bounds_well(self):
    with self.assertRaises(IndexError):
      self.result["Z48"]

  def test_well_names(self):
    names = self.result.well_names()
    self.assertEqual(len(names), 8 * 12)
    self.assertEqual(names[0], "A1")
    self.assertEqual(names[11], "A12")
    self.assertEqual(names[12], "B1")
    self.assertEqual(names[-1], "H12")


# ===========================================================================
# Base — properties
# ===========================================================================


class TestBaseProperties(unittest.TestCase):
  def test_temperatures(self):
    data = _make_absorbance_data(start_wl=300, end_wl=302, step=1)
    result = PlateReaderResult(data)
    self.assertEqual(result.temperatures, [25.0, 25.0, 25.0])

  def test_times(self):
    data = _make_absorbance_data(start_wl=300, end_wl=302, step=1)
    result = PlateReaderResult(data)
    for actual, expected in zip(result.times, [30.0, 30.1, 30.2]):
      self.assertAlmostEqual(actual, expected)

  def test_grid_dimensions(self):
    data = [_make_entry(num_rows=8, num_cols=12)]
    result = PlateReaderResult(data)
    self.assertEqual(result.num_rows, 8)
    self.assertEqual(result.num_cols, 12)

  def test_raw(self):
    data = [_make_entry()]
    result = PlateReaderResult(data)
    self.assertEqual(result.raw, data)

  def test_to_list(self):
    data = [_make_entry()]
    result = PlateReaderResult(data)
    self.assertEqual(result.to_list(), data)


# ===========================================================================
# Base — grid, empty, partial, slice, repr
# ===========================================================================


class TestBaseGrid(unittest.TestCase):
  def test_grid_at_index(self):
    data = _make_absorbance_data(start_wl=300, end_wl=302, step=1)
    result = PlateReaderResult(data)
    self.assertEqual(result.grid(0), data[0]["data"])
    self.assertEqual(result.grid(-1), data[-1]["data"])


class TestBaseEmpty(unittest.TestCase):
  def test_empty_result(self):
    result = PlateReaderResult([])
    self.assertEqual(len(result), 0)
    self.assertFalse(result)
    self.assertEqual(result.temperatures, [])
    self.assertEqual(result.times, [])
    self.assertEqual(result.num_rows, 0)
    self.assertEqual(result.num_cols, 0)
    self.assertEqual(result.well_names(), [])
    self.assertEqual(list(result), [])


class TestBasePartialWells(unittest.TestCase):
  def test_none_propagates(self):
    data = [
      {"wavelength": 300, "data": [[1.0, 2.0], [3.0, None]]},
      {"wavelength": 301, "data": [[5.0, 6.0], [None, 8.0]]},
    ]
    result = PlateReaderResult(data, num_rows=2, num_cols=2)
    self.assertEqual(result["A1"], [1.0, 5.0])
    self.assertEqual(result["B2"], [None, 8.0])
    self.assertEqual(result["B1"], [3.0, None])


class TestBaseSlice(unittest.TestCase):
  def test_slice_returns_same_type(self):
    data = _make_absorbance_data(start_wl=300, end_wl=305, step=1)
    result = PlateReaderResult(data)
    sliced = result[0:3]
    self.assertIsInstance(sliced, PlateReaderResult)
    self.assertEqual(len(sliced), 3)
    self.assertEqual(sliced[0], data[0])


class TestBaseRepr(unittest.TestCase):
  def test_repr(self):
    data = [_make_entry()]
    result = PlateReaderResult(data)
    r = repr(result)
    self.assertIn("1 entry", r)
    self.assertIn("8x12 grid", r)
    self.assertTrue(r.startswith("PlateReaderResult("))

  def test_empty_repr(self):
    result = PlateReaderResult([])
    self.assertEqual(repr(result), "PlateReaderResult(0 entries)")


# ===========================================================================
# Base — dimension inference
# ===========================================================================


class TestBaseDimensionInference(unittest.TestCase):
  def test_infer_from_data(self):
    data = [{"data": [[1, 2, 3], [4, 5, 6]]}]
    result = PlateReaderResult(data)
    self.assertEqual(result.num_rows, 2)
    self.assertEqual(result.num_cols, 3)

  def test_explicit_dims_override(self):
    data = [{"data": [[1, 2, 3], [4, 5, 6]]}]
    result = PlateReaderResult(data, num_rows=4, num_cols=6)
    self.assertEqual(result.num_rows, 4)
    self.assertEqual(result.num_cols, 6)


# ===========================================================================
# AbsorbanceResult
# ===========================================================================


class TestAbsorbanceWavelengths(unittest.TestCase):
  def setUp(self):
    self.data = _make_absorbance_data(start_wl=300, end_wl=305, step=1)
    self.result = AbsorbanceResult(self.data)

  def test_wavelengths_property(self):
    self.assertEqual(self.result.wavelengths, [300, 301, 302, 303, 304, 305])

  def test_at_wavelength(self):
    grid = self.result.at_wavelength(300)
    self.assertEqual(grid, self.data[0]["data"])

  def test_at_wavelength_miss(self):
    with self.assertRaises(KeyError):
      self.result.at_wavelength(999)


class TestAbsorbanceSpectrum(unittest.TestCase):
  def setUp(self):
    self.data = _make_absorbance_data(start_wl=300, end_wl=305, step=1)
    self.result = AbsorbanceResult(self.data)

  def test_spectrum_returns_correct_tuple(self):
    wls, vals = self.result.spectrum("A1")
    self.assertEqual(wls, [300, 301, 302, 303, 304, 305])
    expected_vals = [entry["data"][0][0] for entry in self.data]
    self.assertEqual(vals, expected_vals)

  def test_spectrum_another_well(self):
    wls, vals = self.result.spectrum("B3")
    expected_vals = [entry["data"][1][2] for entry in self.data]
    self.assertEqual(vals, expected_vals)

  def test_spectrum_invalid_well(self):
    with self.assertRaises(IndexError):
      self.result.spectrum("Z48")


class TestAbsorbanceSlice(unittest.TestCase):
  def test_slice_returns_absorbance_result(self):
    data = _make_absorbance_data(start_wl=300, end_wl=305, step=1)
    result = AbsorbanceResult(data)
    sliced = result[0:3]
    self.assertIsInstance(sliced, AbsorbanceResult)
    self.assertEqual(len(sliced), 3)
    self.assertEqual(sliced.wavelengths, [300, 301, 302])

  def test_slice_step(self):
    data = _make_absorbance_data(start_wl=300, end_wl=305, step=1)
    result = AbsorbanceResult(data)
    sliced = result[::2]
    self.assertEqual(len(sliced), 3)
    self.assertEqual(sliced.wavelengths, [300, 302, 304])


class TestAbsorbanceSingleWavelength(unittest.TestCase):
  def test_single_entry(self):
    data = [_make_entry(wavelength=600)]
    result = AbsorbanceResult(data)
    self.assertEqual(len(result), 1)
    self.assertEqual(result.wavelengths, [600])
    self.assertEqual(result.at_wavelength(600), data[0]["data"])


class TestAbsorbanceRepr(unittest.TestCase):
  def test_spectrum_repr(self):
    data = _make_absorbance_data(start_wl=300, end_wl=700, step=1)
    result = AbsorbanceResult(data)
    r = repr(result)
    self.assertIn("401 entries", r)
    self.assertIn("8x12 grid", r)
    self.assertIn("wavelengths=300-700nm", r)
    self.assertTrue(r.startswith("AbsorbanceResult("))

  def test_single_wavelength_repr(self):
    data = [_make_entry(wavelength=600)]
    result = AbsorbanceResult(data)
    r = repr(result)
    self.assertIn("1 entry", r)
    self.assertIn("wavelength=600nm", r)


class TestAbsorbanceDataframe(unittest.TestCase):
  def test_wavelength_as_index(self):
    try:
      import pandas  # noqa: F401
    except ImportError:
      self.skipTest("pandas not installed")

    data = _make_absorbance_data(start_wl=300, end_wl=302, step=1)
    result = AbsorbanceResult(data)
    df = result.to_dataframe()
    self.assertEqual(df.shape[0], 3)
    self.assertIn("A1", df.columns)
    self.assertIn("H12", df.columns)
    self.assertEqual(df.index.name, "wavelength")
    self.assertEqual(list(df.index), [300, 301, 302])

  def test_import_error(self):
    with mock.patch.dict(sys.modules, {"pandas": None}):
      result = AbsorbanceResult([_make_entry(wavelength=300)])
      with self.assertRaises(ImportError):
        result.to_dataframe()


# ===========================================================================
# FluorescenceResult
# ===========================================================================


class TestFluorescenceProperties(unittest.TestCase):
  def setUp(self):
    self.data = _make_fluorescence_data()
    self.result = FluorescenceResult(self.data)

  def test_excitation_wavelengths(self):
    self.assertEqual(self.result.excitation_wavelengths, [485])

  def test_emission_wavelengths(self):
    self.assertEqual(self.result.emission_wavelengths, [528, 590])

  def test_is_sequence(self):
    self.assertIsInstance(self.result, collections.abc.Sequence)
    self.assertIsInstance(self.result, PlateReaderResult)

  def test_well_access(self):
    vals = self.result["A1"]
    self.assertEqual(vals, [100.5, 42.3])


class TestFluorescenceSlice(unittest.TestCase):
  def test_slice_returns_fluorescence_result(self):
    data = _make_fluorescence_data()
    result = FluorescenceResult(data)
    sliced = result[0:1]
    self.assertIsInstance(sliced, FluorescenceResult)
    self.assertEqual(len(sliced), 1)
    self.assertEqual(sliced.excitation_wavelengths, [485])
    self.assertEqual(sliced.emission_wavelengths, [528])


class TestFluorescenceRepr(unittest.TestCase):
  def test_repr(self):
    data = _make_fluorescence_data()
    result = FluorescenceResult(data)
    r = repr(result)
    self.assertTrue(r.startswith("FluorescenceResult("))
    self.assertIn("2 entries", r)
    self.assertIn("ex=485nm", r)
    self.assertIn("em=528-590nm", r)


class TestFluorescenceDataframe(unittest.TestCase):
  def test_includes_ex_em_columns(self):
    try:
      import pandas  # noqa: F401
    except ImportError:
      self.skipTest("pandas not installed")

    data = _make_fluorescence_data()
    result = FluorescenceResult(data)
    df = result.to_dataframe()
    self.assertIn("ex_wavelength", df.columns)
    self.assertIn("em_wavelength", df.columns)
    self.assertIn("A1", df.columns)
    # No wavelength index for fluorescence
    self.assertNotEqual(df.index.name, "wavelength")


# ===========================================================================
# LuminescenceResult
# ===========================================================================


class TestLuminescenceProperties(unittest.TestCase):
  def setUp(self):
    self.data = _make_luminescence_data()
    self.result = LuminescenceResult(self.data)

  def test_no_wavelength_attributes(self):
    # LuminescenceResult should not have wavelength-related methods
    self.assertFalse(hasattr(self.result, "wavelengths"))
    self.assertFalse(hasattr(self.result, "at_wavelength"))
    self.assertFalse(hasattr(self.result, "spectrum"))

  def test_temperatures(self):
    self.assertEqual(self.result.temperatures, [25.0])

  def test_times(self):
    self.assertEqual(self.result.times, [0.5])

  def test_well_access(self):
    self.assertEqual(self.result["A1"], [5000.0])

  def test_is_sequence(self):
    self.assertIsInstance(self.result, collections.abc.Sequence)
    self.assertIsInstance(self.result, PlateReaderResult)


class TestLuminescenceSlice(unittest.TestCase):
  def test_slice_returns_luminescence_result(self):
    data = _make_luminescence_data()
    result = LuminescenceResult(data)
    sliced = result[0:1]
    self.assertIsInstance(sliced, LuminescenceResult)


class TestLuminescenceRepr(unittest.TestCase):
  def test_repr(self):
    data = _make_luminescence_data()
    result = LuminescenceResult(data)
    r = repr(result)
    self.assertTrue(r.startswith("LuminescenceResult("))
    self.assertIn("1 entry", r)
    self.assertIn("8x12 grid", r)
    # No wavelength info
    self.assertNotIn("wavelength", r.lower())


# ===========================================================================
# to_numpy (shared, tested on base)
# ===========================================================================


class TestToNumpy(unittest.TestCase):
  def test_correct_shape(self):
    try:
      import numpy as np
    except ImportError:
      self.skipTest("numpy not installed")

    data = _make_absorbance_data(start_wl=300, end_wl=302, step=1, num_rows=2, num_cols=3)
    result = AbsorbanceResult(data, num_rows=2, num_cols=3)
    arr = result.to_numpy()
    self.assertEqual(arr.shape, (3, 2, 3))
    self.assertAlmostEqual(arr[0, 0, 0], data[0]["data"][0][0])

  def test_none_becomes_nan(self):
    try:
      import numpy as np
    except ImportError:
      self.skipTest("numpy not installed")

    data = [{"data": [[1.0, None], [None, 4.0]]}]
    result = PlateReaderResult(data, num_rows=2, num_cols=2)
    arr = result.to_numpy()
    self.assertAlmostEqual(arr[0, 0, 0], 1.0)
    self.assertTrue(np.isnan(arr[0, 0, 1]))
    self.assertTrue(np.isnan(arr[0, 1, 0]))
    self.assertAlmostEqual(arr[0, 1, 1], 4.0)

  def test_import_error(self):
    with mock.patch.dict(sys.modules, {"numpy": None}):
      result = PlateReaderResult([_make_entry()])
      with self.assertRaises(ImportError):
        result.to_numpy()


# ===========================================================================
# Cross-class equality
# ===========================================================================


class TestCrossClassEquality(unittest.TestCase):
  def test_absorbance_eq_list(self):
    data = _make_absorbance_data(start_wl=300, end_wl=302, step=1)
    result = AbsorbanceResult(data)
    self.assertEqual(result, data)

  def test_luminescence_eq_list(self):
    data = _make_luminescence_data()
    result = LuminescenceResult(data)
    self.assertEqual(result, data)

  def test_fluorescence_eq_list(self):
    data = _make_fluorescence_data()
    result = FluorescenceResult(data)
    self.assertEqual(result, data)


if __name__ == "__main__":
  unittest.main()
