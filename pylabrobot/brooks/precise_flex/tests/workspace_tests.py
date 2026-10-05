import unittest

from pylabrobot.brooks.precise_flex.resource_model import Workspace
from pylabrobot.resources.coordinate import Coordinate
from pylabrobot.resources.resource import Resource


class TestWorkspace(unittest.TestCase):
  """The ring an arm's tool point can reach, as a resource located by its corner."""

  def setUp(self):
    self.workspace = Workspace(
      "workspace", inner_radius=100.0, outer_radius=700.0, z_min=1.5, z_max=401.5
    )

  def test_the_cuboid_bounds_the_ring(self):
    self.assertEqual(self.workspace.get_size_x(), 1400.0)
    self.assertEqual(self.workspace.get_size_y(), 1400.0)
    self.assertEqual(self.workspace.get_size_z(), 400.0)

  def test_the_reference_point_is_on_the_axis_at_the_drives_zero(self):
    self.assertEqual(self.workspace.reference_point, Coordinate(700.0, 700.0, -1.5))

  def test_reach_is_the_ring_not_the_box(self):
    for point, reachable in (
      (Coordinate(400.0, 0.0, 200.0), True),
      (Coordinate(0.0, -700.0, 401.5), True),  # on the outer edge, at the top
      (Coordinate(50.0, 0.0, 200.0), False),  # inside the hole about the shoulder axis
      (Coordinate(600.0, 600.0, 200.0), False),  # in the box's corner, past the ring
      (Coordinate(400.0, 0.0, 0.0), False),  # below the Z travel
      (Coordinate(400.0, 0.0, 402.0), False),  # above it
    ):
      with self.subTest(point=point):
        self.assertEqual(self.workspace.is_reachable(point), reachable)

  def test_radii_and_heights_must_be_in_order(self):
    for inner_radius, outer_radius, z_min, z_max in (
      (700.0, 100.0, 0.0, 1.0),
      (-1.0, 100.0, 0.0, 1.0),
      (0.0, 100.0, 1.0, 1.0),
    ):
      with self.subTest(inner_radius=inner_radius, z_min=z_min), self.assertRaises(ValueError):
        Workspace("workspace", inner_radius, outer_radius, z_min, z_max)

  def test_serialization_round_trips(self):
    again = Workspace.deserialize(self.workspace.serialize())
    self.assertEqual(again, self.workspace)
    self.assertEqual(again.serialize()["size_x"], 1400.0)

  def test_it_round_trips_as_a_child(self):
    device = Resource("device", size_x=10.0, size_y=10.0, size_z=10.0)
    device.assign_child_resource(self.workspace, location=Coordinate(1.0, 2.0, 3.0))
    again = Resource.deserialize(device.serialize())
    self.assertIsInstance(again.children[0], Workspace)
    self.assertEqual(again, device)
