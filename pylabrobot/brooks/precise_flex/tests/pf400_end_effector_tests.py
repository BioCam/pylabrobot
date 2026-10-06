import unittest

from pylabrobot.brooks.precise_flex.resource_model import pf400_end_effector
from pylabrobot.resources.coordinate import Coordinate
from pylabrobot.resources.end_effector import MechanicalGripper


class TestPF400Gripper(unittest.TestCase):
  """The gripper, reaching as far as the controller reports its tool does."""

  def setUp(self):
    self.gripper = pf400_end_effector.gripper("gripper", 162.0, (60.0, 145.0), jaw_width=120.0)

  def test_it_is_sized_to_its_body_and_turns_on_the_wrist_joint(self):
    self.assertIsInstance(self.gripper, MechanicalGripper)
    self.assertEqual(self.gripper.get_size_x(), 127.0)
    self.assertEqual(self.gripper.proximal_joint, Coordinate(34.4, 67.0, 56.4))

  def test_it_grips_its_tool_length_out_and_below_the_flange_plane(self):
    self.assertEqual(self.gripper.tool_center_point, Coordinate(162.0, 0.0, -46.3))

  def test_the_grip_centre_is_at_the_middle_of_the_fingers_height(self):
    finger = self.gripper.fingers[0]
    middle = finger.get_location_wrt(self.gripper).z + finger.get_size_z() / 2
    grip = self.gripper.proximal_joint.z + self.gripper.tool_center_point.z
    self.assertAlmostEqual(middle, grip)

  def test_the_fingers_stand_the_jaw_width_apart_about_the_wrist_joint(self):
    left, right = (finger.get_location_wrt(self.gripper).y for finger in self.gripper.fingers)
    thickness = self.gripper.fingers[1].get_size_y()
    self.assertAlmostEqual(left - (right + thickness), 120.0)
    self.assertAlmostEqual(left + right + thickness, 2 * 67.0)

  def test_the_drive_moves_two_jaws_and_a_finger_is_bolted_to_each(self):
    self.assertEqual([jaw.parent for jaw in self.gripper.jaws], [self.gripper] * 2)
    self.assertEqual([finger.parent for finger in self.gripper.fingers], self.gripper.jaws)
    self.assertEqual({jaw.category for jaw in self.gripper.jaws}, {"jaw"})

  def test_a_finger_starts_where_its_jaw_does_and_hangs_below_the_body(self):
    for finger in self.gripper.fingers:
      here = finger.get_location_wrt(self.gripper)
      self.assertAlmostEqual(here.x, 93.7)
      self.assertAlmostEqual(here.z, -1.2)

  def test_a_jaws_outer_end_stands_just_inside_its_fingers_outer_face(self):
    for jaw, finger, outer in zip(self.gripper.jaws, self.gripper.fingers, (1.0, -1.0)):
      jaw_y, finger_y = (part.get_location_wrt(self.gripper).y for part in (jaw, finger))
      jaw_end = jaw_y + jaw.get_size_y() if outer > 0 else jaw_y
      finger_end = finger_y + finger.get_size_y() if outer > 0 else finger_y
      self.assertAlmostEqual(outer * (finger_end - jaw_end), 0.5)

  def test_the_parts_are_named_for_a_mesh_each_side_its_own(self):
    self.assertEqual(self.gripper.body.model, "brooks_pf400_gripper_body")
    for part, parts in (("jaw", self.gripper.jaws), ("finger", self.gripper.fingers)):
      self.assertEqual(
        [each.model for each in parts],
        [f"brooks_pf400_gripper_{part}_left", f"brooks_pf400_gripper_{part}_right"],
      )
