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
    middle = finger.location.z + finger.get_size_z() / 2
    grip = self.gripper.proximal_joint.z + self.gripper.tool_center_point.z
    self.assertAlmostEqual(middle, grip)

  def test_the_fingers_stand_the_jaw_width_apart_about_the_wrist_joint(self):
    left, right = self.gripper.fingers
    self.assertAlmostEqual(left.location.y - (right.location.y + right.get_size_y()), 120.0)
    self.assertAlmostEqual(left.location.y + right.location.y + right.get_size_y(), 2 * 67.0)

  def test_the_parts_are_named_for_a_mesh(self):
    self.assertEqual(self.gripper.body.model, "brooks_pf400_gripper_body")
    self.assertEqual({f.model for f in self.gripper.fingers}, {"brooks_pf400_gripper_finger"})
