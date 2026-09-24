"""The flattener: what it emits, and that reusing derived models changes nothing about it."""

import json
import unittest

from pylabrobot.resources.coordinate import Coordinate
from pylabrobot.resources.corning import cor_96_wellplate_360uL_Fb
from pylabrobot.resources.hamilton import hamilton_96_tiprack_1000uL
from pylabrobot.visualizer3D.facility import Facility
from pylabrobot.visualizer3D.scene import build_scene, pack_state


def facility_with(plates: int) -> Facility:
  """A facility holding `plates` identical plates, side by side."""
  facility = Facility(name="facility", size_x=10_000, size_y=10_000, size_z=500)
  for i in range(plates):
    facility.assign_child_resource(
      cor_96_wellplate_360uL_Fb(name=f"plate_{i}"), location=Coordinate(150 * i, 0, 0)
    )
  return facility


class SceneTests(unittest.TestCase):
  def test_emits_parents_before_children(self):
    """A client resolves world transforms in one forward pass, which only works in this order."""
    scene = build_scene(facility_with(2))
    for index, parent in enumerate(scene.parent_of_instance):
      self.assertLess(parent, index, f"instance {index} is emitted before its parent")

  def test_identical_resources_share_one_model(self):
    """The whole point of the split: geometry is sent once, however many stand on it."""
    one = build_scene(facility_with(1))
    many = build_scene(facility_with(20))
    self.assertEqual(len(many.models), len(one.models))
    self.assertEqual(len(many.names), 1 + 20 * 97)  # facility, then plate and its 96 wells

  def test_reused_models_give_an_identical_scene(self):
    """Skipping the derive must not change a single byte of what is sent."""
    facility = facility_with(3)
    cold = build_scene(facility)
    warm = build_scene(facility, known=cold.derived, known_names=frozenset(cold.names))
    self.assertEqual(
      json.dumps(cold.serialize(), sort_keys=True),
      json.dumps(warm.serialize(), sort_keys=True),
    )

  def test_a_move_is_seen_through_reused_models(self):
    """A model is reused, a position never is: moving something must still show up."""
    facility = facility_with(3)
    first = build_scene(facility)
    names = frozenset(first.names)
    facility.get_resource("plate_0").location = Coordinate(999, 888, 0)
    warm = build_scene(facility, known=first.derived, known_names=names)
    self.assertEqual(
      json.dumps(warm.serialize(), sort_keys=True),
      json.dumps(build_scene(facility).serialize(), sort_keys=True),
    )

  def test_a_racked_tip_hangs_from_its_collar(self):
    """A tip serializes without its location; the scene places it where its spot put it."""
    facility = Facility(name="facility", size_x=1000, size_y=1000, size_z=500)
    rack = hamilton_96_tiprack_1000uL(name="rack", with_tips=True)
    facility.assign_child_resource(rack, location=Coordinate(100, 100, 0))
    tip = rack.get_item("A1").get_tip()
    location = tip.location
    assert location is not None

    scene = build_scene(facility)
    index = scene.names.index(tip.name)
    self.assertEqual(
      tuple(scene.transforms[6 * index : 6 * index + 3]), (location.x, location.y, location.z)
    )

  def test_models_are_not_reused_when_the_names_change(self):
    """Whether a string counts as a reference depends on which names exist, so a changed tree
    invalidates what was derived from the old one."""
    facility = facility_with(2)
    first = build_scene(facility)
    names = frozenset(first.names)
    # A plate's ordering links its wells by name: with A1 out of the tree, that entry is a name.
    plate = facility.get_resource("plate_0")
    plate.unassign_child_resource(facility.get_resource("plate_0_well_A1"))
    warm = build_scene(facility, known=first.derived, known_names=names)
    self.assertNotEqual(
      warm.derived["plate_0"], first.derived["plate_0"], "the model kept its link"
    )
    self.assertEqual(
      json.dumps(warm.serialize(), sort_keys=True),
      json.dumps(build_scene(facility).serialize(), sort_keys=True),
    )


class PackStateTests(unittest.TestCase):
  def test_resources_that_differ_only_in_position_share_one_state(self):
    """A position rode inside the state, so two wells at the same volume were two states, and a
    plate of them that had moved once could never share anything again."""
    at = lambda x: {"x": x, "y": 0.0, "z": 0.0, "type": "Coordinate"}  # noqa: E731
    packed = pack_state(
      {
        "a": {"volume": 100.0, "location": at(1.0)},
        "b": {"volume": 100.0, "location": at(2.0)},
        "c": {"volume": 100.0},
      }
    )
    self.assertEqual(len(packed["states"]), 1)
    self.assertEqual(packed["of"], {"a": 0, "b": 0, "c": 0})
    self.assertEqual(packed["locations"], {"a": at(1.0), "b": at(2.0)})
    self.assertNotIn("location", packed["states"][0])


if __name__ == "__main__":
  unittest.main()
