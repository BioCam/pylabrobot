import os
import unittest

from pylabrobot.brooks.precise_flex.resource_model import pf400_rail

MODELS = os.path.dirname(pf400_rail.__file__)


class TestTheLinearRail(unittest.TestCase):
  """The rail and its carriage, as resources a mesh is named after."""

  def test_a_rail_is_as_long_as_its_travel_and_what_lies_beyond_it(self):
    for travel, size_x, model in (
      (1000.0, 1390.8, "brooks_pf400_linear_rail_1m"),
      (1500.0, 1890.8, "brooks_pf400_linear_rail_1_5m"),
      (2000.0, 2390.8, "brooks_pf400_linear_rail_2m"),
    ):
      with self.subTest(travel=travel):
        rail = pf400_rail.linear_rail("rail", travel)
        self.assertEqual(
          (rail.get_size_x(), rail.get_size_y(), rail.get_size_z()), (size_x, 206.0, 104.6)
        )
        self.assertEqual((rail.category, rail.model), ("linear_rail", model))

  def test_a_travel_the_rail_is_not_built_in_has_no_mesh(self):
    rail = pf400_rail.linear_rail("rail", 1200.0)
    self.assertEqual(rail.get_size_x(), 1590.8)
    self.assertIsNone(rail.model)

  def test_the_carriage_is_named_for_how_the_arm_is_mounted(self):
    for mounting, model in ((0.0, "0deg"), (-90.0, "90deg")):
      carriage = pf400_rail.linear_rail_carriage("carriage", mounting)
      self.assertEqual(carriage.get_size_z(), 90.2)
      self.assertEqual(carriage.model, f"brooks_pf400_linear_rail_carriage_{model}")
    with self.assertRaises(ValueError):
      pf400_rail.linear_rail_carriage("carriage", 45.0)

  def test_every_model_has_its_mesh(self):
    travels = pf400_rail.LINEAR_RAIL_TRAVELS.values()
    mountings = pf400_rail.LINEAR_RAIL_CARRIAGE_MOUNTINGS.values()
    for name in [f"linear_rail_{t}" for t in travels] + [
      f"linear_rail_carriage_{m}" for m in mountings
    ]:
      self.assertTrue(os.path.exists(os.path.join(MODELS, f"brooks_pf400_{name}.glb")), name)
