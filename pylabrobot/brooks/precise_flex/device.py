"""The PreciseFlex arms as resources: the device, and what it knows about its own workspace.

A frame factory builds the base plate the machine stands on. Everything it carries - the column,
the carriage, the arm, the gripper - is hung off it by the driver, from a configuration.
"""

import logging
import os
from typing import Optional

from pylabrobot.brooks.precise_flex.driver.features.arm import PreciseFlexArm
from pylabrobot.brooks.precise_flex.driver.features.gripper import PreciseFlexGripper
from pylabrobot.brooks.precise_flex.driver.features.rail import PreciseFlexRail
from pylabrobot.brooks.precise_flex.driver.features.vision import PreciseFlexVision
from pylabrobot.brooks.precise_flex.driver.master import PreciseFlexDriver
from pylabrobot.brooks.precise_flex.resource_model.pf400_chassis import (
  BASE_PLATE_SIZE,
  base_plate,
)
from pylabrobot.brooks.precise_flex.resource_model.workspace import Workspace
from pylabrobot.resources.coordinate import Coordinate
from pylabrobot.resources.resource import Resource

logger = logging.getLogger(__name__)

_RECORDINGS = os.path.join(os.path.dirname(os.path.abspath(__file__)), "driver", "recordings")
# What an extended-reach PreciseFlex 400 with 400 mm of Z travel reported about itself.
RECORDING_PF400 = os.path.join(_RECORDINGS, "pf400_extended_400mm.json")


class PreciseFlexDevice(Resource):
  """The complete modelling and control interface for a PreciseFlex arm.

  The device is itself a resource and its workspace is its child: one tree, rooted here.
  `device.driver` speaks to the arm in its own terms and stays reachable.
  """

  def __init__(
    self,
    workspace: Workspace,
    driver: PreciseFlexDriver,
    name: str,
    size_x: float,
    size_y: float,
    size_z: float,
    model: Optional[str] = None,
  ):
    """
    Args:
      workspace: the workspace this device reaches. It becomes a child of the device.
      driver: the driver to drive the device through.
      name: what to call this device in the resource tree.
      size_x: how wide the device is, in mm.
      size_y: how deep it is, in mm.
      size_z: how tall it is, in mm.
      model: which device this is. Defaults to the class name.
    """
    super().__init__(
      name=name,
      size_x=size_x,
      size_y=size_y,
      size_z=size_z,
      category="device",
      model=model if model is not None else self.__class__.__name__,
    )
    self.workspace = workspace
    self.driver = driver
    if self.driver.workspace is not None and self.driver.workspace is not workspace:
      logger.warning("the driver was given another workspace; modelling into this device's")
    self.driver.workspace = workspace
    # Where it sits is set once a configuration gives it an extent.
    self.assign_child_resource(workspace, location=Coordinate.zero())

  @property
  def arm(self) -> PreciseFlexArm:
    """The arm, as the driver has it."""
    return self.driver.arm

  @property
  def gripper(self) -> PreciseFlexGripper:
    """The gripper, as the driver has it."""
    return self.driver.gripper

  @property
  def rail(self) -> Optional[PreciseFlexRail]:
    """The rail, if the arm stands on one."""
    return self.driver.rail

  @property
  def vision(self) -> Optional[PreciseFlexVision]:
    """The vision feature, if setup found one."""
    return self.driver.vision

  async def setup(self, skip_home: bool = False, skip_vision: bool = False):
    """Bring the device up.

    Args:
      skip_home: as `PreciseFlexDriver.setup` takes it.
      skip_vision: as `PreciseFlexDriver.setup` takes it.
    """
    await self.driver.setup(skip_home=skip_home, skip_vision=skip_vision)

  async def stop(self):
    """Put the device down."""
    await self.driver.stop()


def PreciseFlex400(driver: PreciseFlexDriver, name: str = "PreciseFlex400") -> PreciseFlexDevice:
  """A PreciseFlex 400: its base plate, and a workspace for the driver to reflect it into.

  Nothing about the arm is declared here. The column, the workspace's extent, the links and the
  gripper are built from a configuration: the one the driver was given as
  `declared_configuration_json`, at once, or else the one the controller answers at setup. Where
  the controller reports from is `pf400_chassis.SHOULDER_AXIS`, within the base plate.

  Args:
    driver: the driver to drive the device through.
    name: what to call this one.

  Returns:
    The machine.
  """
  device = PreciseFlexDevice(
    workspace=Workspace(name=f"{name}_workspace"),
    driver=driver,
    name=name,
    # The device's own cuboid is the base plate it stands on; what it carries reaches above that.
    size_x=BASE_PLATE_SIZE[0],
    size_y=BASE_PLATE_SIZE[1],
    size_z=BASE_PLATE_SIZE[2],
    model=PreciseFlex400.__name__,
  )
  device.assign_child_resource(base_plate(name=f"{name}_base_plate"), location=Coordinate.zero())
  if driver.declared is not None:
    driver._create_feature_resources(driver.declared)
  return device
