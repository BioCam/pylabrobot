import dataclasses
import unittest

from pylabrobot.hamilton.star.driver.simulator import (
  DEFAULT_STAR_CONFIGURATION,
  STARSimulationDriver,
)


class TestXArm(unittest.IsolatedAsyncioTestCase):
  """`STARDriver.x_arm` is the single-arm shorthand, and its job is which error it raises."""

  async def test_before_setup(self):
    with self.assertRaises(RuntimeError):
      STARSimulationDriver().x_arm

  async def test_one_arm(self):
    star = STARSimulationDriver()
    await star.setup()
    self.assertIs(star.x_arm, star.left_x_arm)

  async def test_two_arms(self):
    both = dataclasses.replace(
      DEFAULT_STAR_CONFIGURATION, right_arm=DEFAULT_STAR_CONFIGURATION.left_arm
    )
    star = STARSimulationDriver(configuration=both)
    await star.setup()
    with self.assertRaises(ValueError):
      star.x_arm

  async def test_no_arms(self):
    neither = dataclasses.replace(DEFAULT_STAR_CONFIGURATION, left_arm=None, right_arm=None)
    star = STARSimulationDriver(configuration=neither)
    await star.setup()
    with self.assertRaises(ValueError):
      star.x_arm
