import unittest

from pylabrobot.brooks.precise_flex import kinematics
from pylabrobot.brooks.precise_flex.resource_model import Workspace
from pylabrobot.resources.coordinate import Coordinate
from pylabrobot.resources.resource import Resource

# Reaches 700 mm ahead and to both sides, and only 300 mm behind.
BOUNDARY = [(700.0, -700.0), (700.0, 700.0), (-300.0, 700.0), (-300.0, -700.0)]


class TestWorkspace(unittest.TestCase):
  """The region an arm's tool point can reach, as a resource located by its corner."""

  def setUp(self):
    self.workspace = Workspace("workspace", boundary=BOUNDARY, z_min=1.5, z_max=401.5)

  def test_the_cuboid_bounds_the_boundary(self):
    self.assertEqual(self.workspace.get_size_x(), 1000.0)
    self.assertEqual(self.workspace.get_size_y(), 1400.0)
    self.assertEqual(self.workspace.get_size_z(), 400.0)

  def test_the_reference_point_is_on_the_axis_at_the_drives_zero(self):
    self.assertEqual(self.workspace.reference_point, Coordinate(300.0, 700.0, -1.5))

  def test_reach_is_the_boundary_not_a_ring(self):
    for point, reachable in (
      (Coordinate(400.0, 0.0, 200.0), True),
      (Coordinate(-200.0, 0.0, 200.0), True),  # behind, within what the boundary leaves
      (Coordinate(-400.0, 0.0, 200.0), False),  # as far behind as it reaches ahead
      (Coordinate(800.0, 0.0, 200.0), False),
      (Coordinate(400.0, 0.0, 0.0), False),  # below the Z travel
      (Coordinate(400.0, 0.0, 402.0), False),  # above it
    ):
      with self.subTest(point=point):
        self.assertEqual(self.workspace.is_reachable(point), reachable)

  def test_a_boundary_encloses_something_and_heights_are_in_order(self):
    with self.assertRaises(ValueError):
      Workspace("workspace", boundary=BOUNDARY[:2], z_min=0.0, z_max=1.0)
    with self.assertRaises(ValueError):
      Workspace("workspace", boundary=BOUNDARY, z_min=1.0, z_max=1.0)

  def test_before_a_boundary_it_has_no_extent_and_nothing_is_reachable(self):
    unread = Workspace("workspace")
    self.assertEqual(
      (unread.get_size_x(), unread.get_size_y(), unread.get_size_z()), (0.0, 0.0, 0.0)
    )
    self.assertEqual(unread.reference_point, Coordinate.zero())
    self.assertFalse(unread.is_reachable(Coordinate(0.0, 0.0, 0.0)))
    self.assertEqual(Workspace.deserialize(unread.serialize()), unread)

  def test_it_takes_the_boundary_a_configuration_gives(self):
    unread = Workspace("workspace")
    unread.update_boundary(BOUNDARY, z_min=1.5, z_max=401.5)
    self.assertEqual(unread, self.workspace)
    self.assertEqual(unread.get_absolute_size_z(), 400.0)
    with self.assertRaises(ValueError):
      unread.update_boundary(BOUNDARY[:2], z_min=1.5, z_max=401.5)

  def test_serialization_round_trips(self):
    again = Workspace.deserialize(self.workspace.serialize())
    self.assertEqual(again, self.workspace)
    self.assertEqual(again.serialize()["size_x"], 1000.0)

  def test_it_round_trips_as_a_child(self):
    device = Resource("device", size_x=10.0, size_y=10.0, size_z=10.0)
    device.assign_child_resource(self.workspace, location=Coordinate(1.0, 2.0, 3.0))
    again = Resource.deserialize(device.serialize())
    self.assertIsInstance(again.children[0], Workspace)
    self.assertEqual(again, device)


class TestWorkspaceBoundary(unittest.TestCase):
  """The boundary swept from the extended-reach arm's joint ranges."""

  def setUp(self):
    self.boundary = kinematics.compute_workspace_boundary(
      kinematics.PF400Params(), shoulder_range=(-93.0, 93.0), elbow_range=(12.0, 348.0)
    )

  def reach(self, index: int) -> float:
    x, y = self.boundary[index]
    return float((x * x + y * y) ** 0.5)

  def test_it_reaches_furthest_ahead_and_less_behind(self):
    self.assertEqual(len(self.boundary), 120)
    self.assertAlmostEqual(self.reach(60), 749.8, delta=0.5)  # straight ahead
    self.assertAlmostEqual(self.reach(0), 351.1, delta=3.0)  # straight behind

  def test_it_is_the_same_to_both_sides(self):
    for index in range(1, 60):
      with self.subTest(index=index):
        self.assertAlmostEqual(self.reach(60 - index), self.reach(60 + index), delta=0.5)

  def test_a_workspace_built_from_it_leaves_out_what_a_ring_took_in(self):
    workspace = Workspace("workspace", boundary=self.boundary, z_min=0.0, z_max=400.0)
    self.assertTrue(workspace.is_reachable(Coordinate(700.0, 0.0, 200.0)))
    self.assertFalse(workspace.is_reachable(Coordinate(-700.0, 0.0, 200.0)))
