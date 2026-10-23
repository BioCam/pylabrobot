"""Tidy-table tests on results the CLARIOstar decodes from the reader's replies."""

import unittest
from collections import Counter
from datetime import datetime, timezone
from typing import Any, Dict, List

from pylabrobot.bmg_labtech.clariostar.driver.features import fluorescence_tests, luminescence_tests
from pylabrobot.bmg_labtech.clariostar.driver.features.absorbance_tests import (
  RUN_REPLY,
  STATUS_MEASURED,
  STATUS_MEASURING,
  make_absorbance,
)
from pylabrobot.bmg_labtech.clariostar.driver.features.fluorescence_tests import (
  EXCITATION_SPECTRUM,
  MATRIX_DATA_REPLY,
  SPECTRUM_WELLS,
  fluorescence_plate,
  make_fluorescence,
  read_ground_truth,
  scan_ground_truth,
  spectrum_replies,
)
from pylabrobot.bmg_labtech.clariostar.driver.features.measurement import MeasurementSettings
from pylabrobot.bmg_labtech.clariostar.driver.master_tests import (
  STATUS_IDLE,
  FakeFTDI,
  load_session_replies,
)
from pylabrobot.lib.absorbance.results import get_grid
from pylabrobot.lib.results.table import COLUMNS, _get_well_columns, get_table
from pylabrobot.resources import cor_96_wellplate_360uL_Fb

EIGHT_WAVELENGTHS = [260, 280, 350, 450, 530, 600, 700, 750]


async def read_absorbance_session(step: str, **arguments: Any) -> Any:
  """Column 1 as the reader answered step `step` of the session; the plate and the results."""
  session = load_session_replies()
  io = FakeFTDI(chunk=4096)
  io.replies = [STATUS_IDLE, RUN_REPLY, STATUS_MEASURING, STATUS_MEASURED]
  io.replies.append(
    bytes.fromhex(session[f"{step}_reply" if f"{step}_reply" in session else f"{step}_page"])
  )
  plate = cor_96_wellplate_360uL_Fb("plate")
  absorbance = make_absorbance(io, plate)
  wells = plate.get_items("A1:H1")
  if "start_wavelength" in arguments:
    return plate, await absorbance.measure_spectrum(wells=wells, **arguments)
  return plate, await absorbance.measure(wells=wells, **arguments)


def by(rows: List[Dict[str, Any]], column: str) -> Counter:
  """How many rows have each value of `column`."""
  return Counter(row[column] for row in rows)


class ShapeTests(unittest.IsolatedAsyncioTestCase):
  async def test_absorbance_is_one_row_per_well_and_wavelength(self):
    plate, results = await read_absorbance_session(
      "absorbance_8_wavelengths", wavelengths=EIGHT_WAVELENGTHS
    )
    rows = get_table(results, plate=plate, first_read=3)
    self.assertEqual(len(rows), 64)
    self.assertTrue(all(tuple(row) == COLUMNS for row in rows))
    self.assertEqual(by(rows, "read"), Counter({read: 8 for read in range(3, 11)}))
    self.assertEqual(by(rows, "quantity"), Counter(optical_density=64))
    self.assertEqual([row["wavelength"] for row in rows[::8]], EIGHT_WAVELENGTHS)
    first = rows[0]
    self.assertEqual(
      [first[key] for key in ("well", "row", "column", "row_index", "column_index")],
      ["A1", "A", 1, 0, 0],
    )
    self.assertEqual(first["value"], results[0].data["A1"])
    self.assertEqual(first["start_timestamp"].tzinfo, timezone.utc)
    self.assertEqual(first["start_timestamp"], results[0].start_timestamp.astimezone(timezone.utc))
    self.assertIsNone(first["gain"])

  async def test_raw_absorbance_adds_the_reference_counts(self):
    plate, results = await read_absorbance_session(
      "absorbance_600_nm", wavelengths=[600], report="raw"
    )
    rows = get_table(results, plate=plate)
    self.assertEqual(by(rows, "quantity"), Counter(counts=8, reference_counts=8))
    references = [row["value"] for row in rows if row["quantity"] == "reference_counts"]
    self.assertEqual(references, list(results[0].references.values()))

  async def test_a_spectrum_is_one_row_per_well_and_wavelength(self):
    plate, result = await read_absorbance_session(
      "absorbance_spectrum", start_wavelength=300, end_wavelength=700, step_size=1
    )
    rows = get_table([result], plate=plate)
    self.assertEqual(len(rows), 8 * 401)
    self.assertEqual(by(rows, "mode"), Counter(absorbance_spectrum=8 * 401))
    self.assertEqual(rows[401]["well"], "B1")
    self.assertEqual(rows[401]["wavelength"], 300)
    self.assertEqual(rows[401]["value"], result.data["B1"][300])

  async def test_fluorescence_carries_its_settings(self):
    session = load_session_replies()
    io = FakeFTDI()
    io.replies = [STATUS_IDLE, RUN_REPLY, STATUS_MEASURING, STATUS_MEASURED]
    io.replies.append(bytes.fromhex(session["fluorescence_column_1_reply"]))
    plate = cor_96_wellplate_360uL_Fb("plate")
    result = await make_fluorescence(io, plate).measure(
      fluorescence_tests.BASELINE, wells=plate.get_items("A1:H1"), gain=1000, focal_height=8.5
    )
    rows = get_table([result])
    self.assertEqual(
      [row["value"] for row in rows], [68.0, 62.0, 72.0, 64.0, 67.0, 69.0, 67.0, 68.0]
    )
    row = rows[0]
    self.assertEqual(
      [row[key] for key in ("mode", "gain", "focal_height", "optic_position", "quantity")],
      ["fluorescence", 1000, 8.5, "top", "counts"],
    )
    self.assertEqual((row["excitation_wavelength"], row["emission_wavelength"]), (485, 528))
    self.assertEqual((row["excitation_bandwidth"], row["emission_bandwidth"]), (15, 20))

  async def test_a_matrix_adds_a_row_per_point(self):
    plate = fluorescence_plate()
    _, result = await read_ground_truth(
      MATRIX_DATA_REPLY,
      plate=plate,
      wells=[plate.get_well("A1")],
      measurement_settings=MeasurementSettings(
        well_scan="matrix", matrix_size=3, scan_diameter=3, flashes=10
      ),
    )
    rows = get_table([result], plate=plate)
    self.assertEqual([row["point"] for row in rows], [None, *range(9)])
    self.assertEqual(rows[0]["value"], result.data["A1"])
    self.assertEqual([row["value"] for row in rows[1:]], result.matrix_points["A1"])

  async def test_a_fluorescence_spectrum_puts_the_scanned_wavelength_on_its_side(self):
    io = FakeFTDI(chunk=4096)
    io.replies = spectrum_replies("excitation_spectrum")
    plate = fluorescence_plate()
    result = await make_fluorescence(io, plate).measure_spectrum(
      wells=[plate.get_well(well) for well in SPECTRUM_WELLS],
      **{"gain": 1000, "focal_height": 8.5, **EXCITATION_SPECTRUM},
    )
    rows = get_table([result], plate=plate)
    self.assertEqual(len(rows), 4 * 221)
    self.assertEqual(by(rows, "scanned"), Counter(excitation=4 * 221))
    self.assertEqual(by(rows, "emission_wavelength"), Counter({800: 4 * 221}))
    self.assertEqual([row["excitation_wavelength"] for row in rows[:221]], list(range(400, 621)))
    self.assertEqual(rows[0]["value"], 41.0)

  async def test_luminescence_pivots_back_to_the_plate(self):
    result = await luminescence_tests.read(FakeFTDI())
    plate = luminescence_tests.plate()
    rows = get_table([result], plate=plate, ceiling=210_000_000)
    self.assertEqual(len(rows), 96)
    grid: List[List[Any]] = [[None] * 12 for _ in range(8)]
    for row in rows:
      grid[row["row_index"]][row["column_index"]] = row["value"]
    self.assertEqual(grid, get_grid(plate, result.data))
    self.assertEqual(
      grid, [[float(c) for c in line] for line in luminescence_tests.LUMINESCENCE_GROUND_TRUTH]
    )
    self.assertEqual((rows[0]["gain"], rows[0]["focal_height"]), (3500, 8.5))
    self.assertFalse(any(row["saturated"] for row in rows))

  async def test_a_grid_is_961_rows_with_its_points_in_mm(self):
    _, _, results = await scan_ground_truth(focal_height=15.0, gain=2239)
    rows = get_table(results, ceiling=260_000)
    self.assertEqual(by(rows, "read"), Counter({0: 961, 1: 961}))
    self.assertEqual(by(rows, "well"), Counter(A1=961, H12=961))
    first = rows[0]
    self.assertEqual((first["point"], first["x"], first["y"]), (0, -4.95, -4.95))
    self.assertEqual((rows[480]["x"], rows[480]["y"]), (0.0, 0.0))
    self.assertEqual(rows[1]["x"], -4.62)
    self.assertEqual(first["value"], results[0].counts[0][0])
    saturated = [row for row in rows if row["saturated"]]
    self.assertTrue(saturated)
    self.assertTrue(all(row["value"] == 260_000 for row in saturated))
    self.assertIsNone(first["temperature"])


class WellColumnTests(unittest.TestCase):
  def test_identifiers_are_parsed_without_a_plate(self):
    self.assertEqual(
      _get_well_columns("AF48", None),
      {"well": "AF48", "row": "AF", "column": 48, "row_index": 31, "column_index": 47},
    )
    self.assertEqual(_get_well_columns("Z1", None)["row_index"], 25)
    self.assertEqual(_get_well_columns("AA1", None)["row_index"], 26)
    for refused in ("a1", "B", "3"):
      with self.subTest(refused=refused), self.assertRaises(ValueError):
        _get_well_columns(refused, None)

  def test_a_well_not_on_the_plate_is_refused(self):
    from pylabrobot.lib.absorbance.results import AbsorbanceResult

    now = datetime.now()
    result = AbsorbanceResult(
      data={"Q1": 0.1}, wavelength=600, temperature=None, start_timestamp=now, end_timestamp=now
    )
    with self.assertRaises(ValueError):
      get_table([result], plate=cor_96_wellplate_360uL_Fb("plate"))
    with self.assertRaises(TypeError):
      get_table([object()])


if __name__ == "__main__":
  unittest.main()
