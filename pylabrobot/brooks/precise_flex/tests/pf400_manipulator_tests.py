import unittest

from pylabrobot.brooks.precise_flex.resource_model import pf400_manipulator
from pylabrobot.resources.coordinate import Coordinate
from pylabrobot.resources.manipulator import LinkBody


class TestTheShoulderAxis(unittest.TestCase):
  """The point the controller reports from stands within the base plate."""

  def test_the_axis_stands_above_the_base_plates_front_edge_centred_across_it(self):
    base_plate = pf400_manipulator.base_plate()
    self.assertEqual(
      pf400_manipulator.SHOULDER_AXIS,
      Coordinate(base_plate.get_size_x(), base_plate.get_size_y() / 2, 77.57),
    )


class TestTheColumn(unittest.TestCase):
  """The column stands on the base plate and reaches the height the arm stands."""

  def test_it_stands_on_the_base_plates_top_face_centred_across_it(self):
    base_plate = pf400_manipulator.base_plate()
    column = pf400_manipulator.z_column("column", 700.0)
    location = pf400_manipulator.Z_COLUMN_LOCATION
    self.assertEqual(location.z, base_plate.get_size_z())
    self.assertEqual(2 * location.y + column.get_size_y(), base_plate.get_size_y())

  def test_a_column_reaches_the_datasheets_robot_height(self):
    # Measured from the base plate's bottom, which is its own frame's zero.
    for z_travel, height in ((400.0, 679.0), (401.5, 679.0), (750.0, 1029.0), (1161.5, 1439.0)):
      column = pf400_manipulator.z_column(
        "column", height=pf400_manipulator.z_column_height(z_travel)
      )
      self.assertEqual(pf400_manipulator.Z_COLUMN_LOCATION.z + column.get_size_z(), height)

  def test_each_column_sold_has_its_own_mesh(self):
    for z_travel, model in ((401.5, "400mm"), (750.0, "750mm"), (1161.5, "1160mm")):
      column = pf400_manipulator.z_column("column", pf400_manipulator.z_column_height(z_travel))
      self.assertEqual(column.model, f"brooks_pf400_z_column_{model}")


class TestTheCarriage(unittest.TestCase):
  """What the J1 drive moves, and where a reading puts it."""

  def test_it_rides_the_columns_front_face_centred_across_it(self):
    column = pf400_manipulator.z_column("column", 700.0)
    carriage = pf400_manipulator.z_carriage()
    location = pf400_manipulator.z_carriage_location(0.0)
    self.assertEqual(location.x, column.get_size_x())
    self.assertEqual(2 * location.y + carriage.get_size_y(), column.get_size_y())

  def test_the_drive_reports_the_shoulder_axis_at_the_flange_plane(self):
    reference = pf400_manipulator.Z_CARRIAGE_REFERENCE_POINT
    self.assertEqual(reference, Coordinate(67.5, 55.0, -88.8))

  def test_a_reading_moves_it_by_what_it_read(self):
    stood = pf400_manipulator.z_carriage_location(0.0)
    raised = pf400_manipulator.z_carriage_location(250.0)
    self.assertEqual(raised - stood, Coordinate(0.0, 0.0, 250.0))


class TestEveryPart(unittest.TestCase):
  """Each part is a cuboid that says what it is."""

  def test_each_part_names_a_category_and_a_model(self):
    parts = (
      pf400_manipulator.base_plate(),
      pf400_manipulator.z_column("column", 700.0),
      pf400_manipulator.z_carriage(),
    )
    self.assertEqual(
      [(part.category, part.model) for part in parts],
      [
        ("base_plate", "brooks_pf400_base_plate"),
        ("z_column", "brooks_pf400_z_column_400mm"),
        ("z_carriage", "brooks_pf400_z_carriage"),
      ],
    )


class TestPF400Links(unittest.TestCase):
  """The two links, sized from the length the controller reports between their joints."""

  def test_link_1_is_its_length_plus_a_hub_at_each_end(self):
    for length, size_x in ((302.0, 416.0), (225.0, 339.0)):  # extended reach, standard reach
      with self.subTest(length=length):
        link = pf400_manipulator.link_1("link_1", length)
        self.assertIsInstance(link, LinkBody)
        self.assertEqual(link.get_size_x(), size_x)
        self.assertEqual((link.get_size_y(), link.get_size_z()), (114.0, 73.4))
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

  def test_each_link_is_named_for_its_reachs_mesh_and_carries_nothing(self):
    # The nearest reach's mesh: an odd length is drawn as the reach it is closer to.
    for l1, l2, reach in (
      (302.0, 289.0, "extended"),
      (225.0, 210.0, "standard"),
      (250.0, 240.0, "standard"),
    ):
      with self.subTest(reach=reach, l1=l1):
        first = pf400_manipulator.link_1("link_1", l1)
        second = pf400_manipulator.link_2("link_2", l2)
        models = (f"brooks_pf400_link_1_{reach}", f"brooks_pf400_link_2_{reach}")
        self.assertEqual((first.model, second.model), models)
        self.assertEqual(first.children + second.children, [])

  def test_the_links_and_the_carriage_nest(self):
    link_2_top = pf400_manipulator.LINK_2_SIZE_YZ[1]
    link_1_top = pf400_manipulator.LINK_1_ABOVE_FLANGE_PLANE + pf400_manipulator.LINK_1_SIZE_YZ[1]
    self.assertAlmostEqual(link_2_top - pf400_manipulator.LINK_1_ABOVE_FLANGE_PLANE, 7.7)
    # Link 1 rises past the carriage's bracket to 0.9 under its housing, 17.0 above the bracket.
    self.assertAlmostEqual(link_1_top - pf400_manipulator.Z_CARRIAGE_ABOVE_FLANGE_PLANE, 16.1)
