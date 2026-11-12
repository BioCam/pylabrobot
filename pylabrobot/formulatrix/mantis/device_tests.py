"""Mantis device tests: the parts tree, and the arm model following the moves."""

import os
import unittest
from unittest import mock

from pylabrobot.formulatrix.mantis import Mantis, MantisDevice
from pylabrobot.formulatrix.mantis.driver.features.led_bar import LedBar
from pylabrobot.io.ftdi import FTDI
from pylabrobot.resources import Coordinate

RESOURCE_MODEL = os.path.join(os.path.dirname(__file__), "resource_model")


class MantisTests(unittest.TestCase):
  def make_device(self) -> MantisDevice:
    return Mantis(io=mock.create_autospec(FTDI, instance=True))

  def test_every_part_has_its_model_file(self):
    device = self.make_device()
    for resource in (device, device.left_chip_rack, device.right_chip_rack):
      with self.subTest(resource=resource.name):
        self.assertTrue(os.path.isfile(os.path.join(RESOURCE_MODEL, f"{resource.model}.glb")))

  def test_simulation_refuses_a_link(self):
    with self.assertRaises(ValueError):
      Mantis(simulation=True, io=mock.create_autospec(FTDI, instance=True))


class ArmModelTests(unittest.IsolatedAsyncioTestCase):
  async def test_a_move_poses_the_links_and_moves_the_z_column(self):
    device = Mantis(simulation=True)
    with mock.patch.object(LedBar, "_sleep", autospec=True):
      await device.setup()
    self.addAsyncCleanup(device.stop)
    assert device.arm is not None
    column = device.z_column.location
    assert column is not None
    await device.arm.move_to_location(Coordinate(x=15.0, y=60.0, z=-10.0))
    self.assertAlmostEqual(device.z_column.get_absolute_location().z, column.z - 10.0)
    theta_1, theta_2 = await device.arm.request_link_angles()
    idle, posed = Mantis(simulation=True), Mantis(simulation=True)
    posed._update_arm_model(theta_1=theta_1, theta_2=theta_2, z=-10.0)
    for name, link in device.arm_links.items():
      with self.subTest(link=name):
        self.assertAlmostEqual(link.rotation.z, posed.arm_links[name].rotation.z)
        self.assertNotAlmostEqual(link.rotation.z, idle.arm_links[name].rotation.z)


if __name__ == "__main__":
  unittest.main()
