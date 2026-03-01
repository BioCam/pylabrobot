"""Tests for pipette_orchestration module."""

import unittest
from unittest.mock import MagicMock, patch

from pylabrobot.liquid_handling.pipette_orchestration import (
  ODD_SPAN_CENTER_AVOIDANCE_OFFSET_MM,
  ChannelBatch,
  _build_spacing_table,
  _min_physical_spacing,
  compute_single_container_offsets,
  plan_batches,
)
from pylabrobot.resources.coordinate import Coordinate


class TestMinPhysicalSpacing(unittest.TestCase):

  def test_uniform(self):
    table = _build_spacing_table([9.0, 9.0, 9.0, 9.0])
    self.assertAlmostEqual(_min_physical_spacing(table, 0, 3), 9.0)

  def test_mixed_takes_max(self):
    table = _build_spacing_table([9.0, 9.0, 18.0, 18.0])
    self.assertAlmostEqual(_min_physical_spacing(table, 0, 3), 18.0)
    self.assertAlmostEqual(_min_physical_spacing(table, 0, 1), 9.0)
    self.assertAlmostEqual(_min_physical_spacing(table, 1, 2), 18.0)

  def test_single_channel(self):
    table = _build_spacing_table([9.0, 18.0])
    self.assertAlmostEqual(_min_physical_spacing(table, 0, 0), 9.0)
    self.assertAlmostEqual(_min_physical_spacing(table, 1, 1), 18.0)


class TestPlanBatchesUniformSpacing(unittest.TestCase):
  """All original tests with scalar min_y_spacing (uniform channels)."""

  S = 9.0

  # --- X grouping ---

  def test_single_x_group(self):
    batches = plan_batches([0, 1, 2], [100.0] * 3, [270.0, 261.0, 252.0], self.S)
    self.assertEqual(len(batches), 1)
    self.assertAlmostEqual(batches[0].x_position, 100.0)

  def test_two_x_groups(self):
    batches = plan_batches(
      [0, 1, 2, 3], [100.0, 100.0, 200.0, 200.0], [270.0, 261.0, 270.0, 261.0], self.S
    )
    x_positions = [b.x_position for b in batches]
    self.assertAlmostEqual(x_positions[0], 100.0)
    self.assertAlmostEqual(x_positions[-1], 200.0)

  def test_x_groups_preserve_first_appearance_order(self):
    batches = plan_batches([0, 1, 2], [300.0, 100.0, 200.0], [270.0] * 3, self.S)
    x_positions = [b.x_position for b in batches]
    self.assertAlmostEqual(x_positions[0], 300.0)
    self.assertAlmostEqual(x_positions[1], 100.0)
    self.assertAlmostEqual(x_positions[2], 200.0)

  def test_x_positions_within_tolerance_grouped(self):
    batches = plan_batches([0, 1], [100.0, 100.05], [270.0, 261.0], self.S)
    self.assertEqual(len(batches), 1)

  def test_x_positions_outside_tolerance_split(self):
    batches = plan_batches([0, 1], [100.0, 100.2], [270.0, 270.0], self.S)
    self.assertEqual(len(batches), 2)

  # --- Y batching ---

  def test_consecutive_channels_single_batch(self):
    batches = plan_batches([0, 1, 2], [100.0] * 3, [270.0, 261.0, 252.0], self.S)
    self.assertEqual(len(batches), 1)
    self.assertEqual(sorted(batches[0].channels), [0, 1, 2])

  def test_same_y_forces_serialization(self):
    batches = plan_batches([0, 1, 2], [100.0] * 3, [200.0] * 3, self.S)
    self.assertEqual(len(batches), 3)

  def test_barely_fitting_spacing(self):
    batches = plan_batches([0, 1], [100.0] * 2, [209.0, 200.0], self.S)
    self.assertEqual(len(batches), 1)

  def test_barely_insufficient_spacing(self):
    batches = plan_batches([0, 1], [100.0] * 2, [208.9, 200.0], self.S)
    self.assertEqual(len(batches), 2)

  def test_reversed_y_order_splits(self):
    batches = plan_batches([0, 1], [100.0] * 2, [200.0, 220.0], self.S)
    self.assertEqual(len(batches), 2)

  # --- Non-consecutive channels ---

  def test_non_consecutive_channels_fit(self):
    batches = plan_batches(
      [0, 1, 2, 5, 6, 7], [100.0] * 6,
      [300.0, 291.0, 282.0, 255.0, 246.0, 237.0], self.S,
    )
    self.assertEqual(len(batches), 1)
    self.assertEqual(sorted(batches[0].channels), [0, 1, 2, 5, 6, 7])

  def test_phantom_channels_interpolated(self):
    batches = plan_batches([0, 3], [100.0] * 2, [300.0, 273.0], self.S)
    self.assertEqual(len(batches), 1)
    y = batches[0].y_positions
    self.assertAlmostEqual(y[0], 300.0)
    self.assertAlmostEqual(y[1], 291.0)
    self.assertAlmostEqual(y[2], 282.0)
    self.assertAlmostEqual(y[3], 273.0)

  def test_phantoms_only_within_batch(self):
    batches = plan_batches([0, 3], [100.0] * 2, [200.0, 250.0], self.S)
    self.assertEqual(len(batches), 2)
    for batch in batches:
      self.assertEqual(len(batch.y_positions), 1)

  # --- Mixed X and Y ---

  def test_mixed_complexity(self):
    batches = plan_batches(
      [0, 1, 2, 3], [100.0, 100.0, 200.0, 200.0], [200.0, 200.0, 270.0, 261.0], self.S,
    )
    x100 = [b for b in batches if abs(b.x_position - 100.0) < 0.01]
    x200 = [b for b in batches if abs(b.x_position - 200.0) < 0.01]
    self.assertEqual(len(x100), 2)
    self.assertEqual(len(x200), 1)

  # --- Validation ---

  def test_mismatched_lengths(self):
    with self.assertRaises(ValueError):
      plan_batches([0, 1], [100.0], [200.0, 200.0], self.S)

  def test_empty(self):
    with self.assertRaises(ValueError):
      plan_batches([], [], [], self.S)

  # --- Index correctness ---

  def test_indices_map_back_correctly(self):
    use_channels = [3, 7, 0]
    batches = plan_batches(use_channels, [100.0] * 3, [261.0, 237.0, 270.0], self.S)
    all_indices = [idx for b in batches for idx in b.indices]
    self.assertEqual(sorted(all_indices), [0, 1, 2])
    for batch in batches:
      for idx, ch in zip(batch.indices, batch.channels):
        self.assertEqual(use_channels[idx], ch)

  # --- Realistic ---

  def test_8_channels_trough(self):
    batches = plan_batches(list(range(8)), [100.0] * 8,
                           [300.0 - i * 9.0 for i in range(8)], self.S)
    self.assertEqual(len(batches), 1)
    self.assertEqual(len(batches[0].channels), 8)

  def test_8_channels_narrow_well(self):
    batches = plan_batches(list(range(8)), [100.0] * 8, [200.0] * 8, self.S)
    self.assertEqual(len(batches), 8)

  def test_channels_0_1_2_5_6_7_phantoms(self):
    batches = plan_batches(
      [0, 1, 2, 5, 6, 7], [100.0] * 6,
      [300.0, 291.0, 282.0, 255.0, 246.0, 237.0], self.S,
    )
    self.assertEqual(len(batches), 1)
    y = batches[0].y_positions
    self.assertIn(3, y)
    self.assertIn(4, y)
    self.assertAlmostEqual(y[3], 282.0 - 9.0)
    self.assertAlmostEqual(y[4], 282.0 - 18.0)


class TestPlanBatchesMixedSpacing(unittest.TestCase):
  """Tests for mixed-channel instruments (e.g. 1mL + 5mL)."""

  # Channels 0,1 are 1mL (8.98mm), channels 2,3 are 5mL (17.96mm)
  SPACINGS = [8.98, 8.98, 17.96, 17.96]

  def test_two_1ml_channels_fit_at_9mm(self):
    """Channels 0,1 (both 1mL) at 8.98mm apart → single batch."""
    batches = plan_batches([0, 1], [100.0] * 2, [208.98, 200.0], self.SPACINGS)
    self.assertEqual(len(batches), 1)

  def test_1ml_and_5ml_need_wider_spacing(self):
    """Channel 1 (1mL) and channel 2 (5mL) at 9mm apart → too close, split."""
    batches = plan_batches([1, 2], [100.0] * 2, [209.0, 200.0], self.SPACINGS)
    # effective spacing = max(8.98, 17.96) = 17.96, need 17.96mm but only have 9mm
    self.assertEqual(len(batches), 2)

  def test_1ml_and_5ml_fit_at_wide_spacing(self):
    """Channel 1 (1mL) and channel 2 (5mL) at 17.96mm apart → fits."""
    batches = plan_batches([1, 2], [100.0] * 2, [217.96, 200.0], self.SPACINGS)
    self.assertEqual(len(batches), 1)

  def test_5ml_channels_fit_at_wide_spacing(self):
    """Channels 2,3 (both 5mL) at 17.96mm apart → single batch."""
    batches = plan_batches([2, 3], [100.0] * 2, [217.96, 200.0], self.SPACINGS)
    self.assertEqual(len(batches), 1)

  def test_5ml_channels_too_close(self):
    """Channels 2,3 (both 5mL) at 9mm apart → split."""
    batches = plan_batches([2, 3], [100.0] * 2, [209.0, 200.0], self.SPACINGS)
    self.assertEqual(len(batches), 2)

  def test_span_across_1ml_and_5ml(self):
    """Channels 0,3 — span includes 5mL channels, so effective spacing is 17.96mm.
    Need (3-0) × 17.96 = 53.88mm gap."""
    # Enough space
    batches = plan_batches([0, 3], [100.0] * 2, [253.88, 200.0], self.SPACINGS)
    self.assertEqual(len(batches), 1)

    # Not enough space
    batches = plan_batches([0, 3], [100.0] * 2, [253.0, 200.0], self.SPACINGS)
    self.assertEqual(len(batches), 2)

  def test_phantom_channels_use_min_physical_spacing(self):
    """Phantoms between channels 0 and 3 should use max spacing (17.96mm)."""
    batches = plan_batches([0, 3], [100.0] * 2, [253.88, 200.0], self.SPACINGS)
    self.assertEqual(len(batches), 1)
    y = batches[0].y_positions
    # Phantoms at effective spacing of 17.96
    self.assertAlmostEqual(y[1], 253.88 - 17.96)
    self.assertAlmostEqual(y[2], 253.88 - 2 * 17.96)

  def test_mixed_all_four_channels_spaced_wide(self):
    """All 4 channels at effective spacing → single batch."""
    s = 17.96  # effective for entire span
    batches = plan_batches(
      [0, 1, 2, 3], [100.0] * 4,
      [300.0, 300.0 - s, 300.0 - 2 * s, 300.0 - 3 * s],
      self.SPACINGS,
    )
    self.assertEqual(len(batches), 1)

  def test_mixed_channels_at_1ml_spacing_forces_serialization(self):
    """All 4 channels at 1mL spacing (9mm) → channels 2,3 can't fit, need multiple batches."""
    batches = plan_batches(
      [0, 1, 2, 3], [100.0] * 4,
      [300.0, 291.0, 282.0, 273.0],  # 9mm gaps
      self.SPACINGS,
    )
    # Channels 0,1 fit together (both 1mL, 9mm apart ≥ 8.98mm).
    # Channel 2 (5mL) can't join: effective_spacing(0,2) = 17.96, need 2×17.96=35.92mm,
    # but 300-282=18mm.
    self.assertGreater(len(batches), 1)


class TestComputeSingleContainerOffsets(unittest.TestCase):

  S = 9.0

  def _mock_container(self, size_y: float):
    c = MagicMock(spec=["get_absolute_size_y"])
    c.get_absolute_size_y.return_value = size_y
    return c

  @patch("pylabrobot.liquid_handling.pipette_orchestration.get_wide_single_resource_liquid_op_offsets")
  def test_even_span_no_center_offset(self, mock_offsets):
    mock_offsets.return_value = [Coordinate(0, 4.5, 0), Coordinate(0, -4.5, 0)]
    result = compute_single_container_offsets(self._mock_container(50.0), [0, 1], self.S)
    self.assertAlmostEqual(result[0].y, 4.5)
    self.assertAlmostEqual(result[1].y, -4.5)

  @patch("pylabrobot.liquid_handling.pipette_orchestration.get_wide_single_resource_liquid_op_offsets")
  def test_single_channel_no_center_offset(self, mock_offsets):
    mock_offsets.return_value = [Coordinate(0, 0.0, 0)]
    result = compute_single_container_offsets(self._mock_container(50.0), [0], self.S)
    self.assertAlmostEqual(result[0].y, 0.0)  # no ODD_SPAN offset for single channel

  @patch("pylabrobot.liquid_handling.pipette_orchestration.get_wide_single_resource_liquid_op_offsets")
  def test_odd_span_applies_center_offset(self, mock_offsets):
    mock_offsets.return_value = [Coordinate(0, 9.0, 0), Coordinate(0, 0.0, 0), Coordinate(0, -9.0, 0)]
    result = compute_single_container_offsets(self._mock_container(50.0), [0, 1, 2], self.S)
    self.assertAlmostEqual(result[0].y, 9.0 + ODD_SPAN_CENTER_AVOIDANCE_OFFSET_MM)
    self.assertAlmostEqual(result[1].y, 0.0 + ODD_SPAN_CENTER_AVOIDANCE_OFFSET_MM)
    self.assertAlmostEqual(result[2].y, -9.0 + ODD_SPAN_CENTER_AVOIDANCE_OFFSET_MM)

  @patch("pylabrobot.liquid_handling.pipette_orchestration.get_wide_single_resource_liquid_op_offsets")
  def test_non_consecutive_selects_correct_offsets(self, mock_offsets):
    mock_offsets.return_value = [Coordinate(0, 10.0, 0), Coordinate(0, 0.0, 0), Coordinate(0, -10.0, 0)]
    result = compute_single_container_offsets(self._mock_container(50.0), [0, 2], self.S)
    self.assertEqual(len(result), 2)
    mock_offsets.assert_called_once_with(resource=unittest.mock.ANY, num_channels=3, min_spacing=self.S)

  def test_container_too_small_returns_none(self):
    self.assertIsNone(compute_single_container_offsets(self._mock_container(10.0), [0, 1], self.S))

  def test_empty_channels(self):
    self.assertEqual(compute_single_container_offsets(self._mock_container(50.0), [], self.S), [])

  @patch("pylabrobot.liquid_handling.pipette_orchestration.get_wide_single_resource_liquid_op_offsets")
  def test_mixed_spacing_uses_effective(self, mock_offsets):
    """With mixed spacings, effective spacing for span is used."""
    mock_offsets.return_value = [Coordinate(0, 18.0, 0), Coordinate(0, 0.0, 0), Coordinate(0, -18.0, 0)]
    spacings = [9.0, 9.0, 18.0]
    result = compute_single_container_offsets(self._mock_container(100.0), [0, 2], spacings)
    self.assertIsNotNone(result)
    # effective spacing = max(9, 9, 18) = 18.0 → num_channels_in_span=3
    mock_offsets.assert_called_once_with(resource=unittest.mock.ANY, num_channels=3, min_spacing=18.0)


if __name__ == "__main__":
  unittest.main()
