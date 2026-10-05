import unittest

from pylabrobot.brooks.precise_flex.resource_model import pf400_chassis, pf400_manipulator
from pylabrobot.resources.coordinate import Coordinate
from pylabrobot.resources.manipulator import LinkBody


class TestPF400Links(unittest.TestCase):
  """The two links, sized from the length the controller reports between their joints."""

  def test_link_1_is_its_length_plus_a_hub_at_each_end(self):
    for length, size_x in ((302.0, 416.0), (225.0, 339.0)):  # extended reach, standard reach
      with self.subTest(length=length):
        link = pf400_manipulator.link_1("link_1", length)
        self.assertIsInstance(link, LinkBody)
        self.assertEqual(link.get_size_x(), size_x)
        self.assertEqual((link.get_size_y(), link.get_size_z()), (114.0, 77.7))
        self.assertEqual(link.proximal_joint, Coordinate(57.0, 57.0, 0.0))
        self.assertEqual(link.length, length)

  def test_link_2_has_a_smaller_hub_at_the_wrist(self):
    for length, size_x in ((289.0, 381.0), (210.0, 302.0)):
      with self.subTest(length=length):
        link = pf400_manipulator.link_2("link_2", length)
        self.assertEqual(link.get_size_x(), size_x)
        self.assertEqual((link.get_size_y(), link.get_size_z()), (112.0, 39.2))
        self.assertEqual(link.proximal_joint, Coordinate(56.0, 56.0, 0.0))
        self.assertEqual(link.distal_joint, Coordinate(56.0 + length, 56.0, 0.0))

  def test_each_link_carries_its_body_for_a_mesh(self):
    link = pf400_manipulator.link_1("link_1", 302.0)
    (body,) = link.children
    self.assertEqual((body.name, body.model), ("link_1_body", "brooks_pf400_link_1_body"))
    self.assertEqual(body.get_size_x(), link.get_size_x())

  def test_the_links_and_the_carriage_nest(self):
    link_2_top = pf400_manipulator.LINK_2_SIZE_YZ[1]
    link_1_top = pf400_manipulator.LINK_1_ABOVE_FLANGE_PLANE + pf400_manipulator.LINK_1_SIZE_YZ[1]
    self.assertAlmostEqual(link_2_top - pf400_manipulator.LINK_1_ABOVE_FLANGE_PLANE, 7.7)
    self.assertAlmostEqual(link_1_top - pf400_chassis.Z_CARRIAGE_ABOVE_FLANGE_PLANE, 5.0)
