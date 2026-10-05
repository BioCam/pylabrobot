"""The PreciseFlex arms as resources: the device, and what it knows about its own workspace.

A frame factory builds the machine. What it carries - the carriage, the arm, the gripper - is hung
off it by the driver at setup, from what the controller reports.
"""

import logging
from typing import Literal, Optional, Tuple

from pylabrobot.brooks.precise_flex import kinematics
from pylabrobot.brooks.precise_flex.driver.features.arm import PreciseFlexArm
from pylabrobot.brooks.precise_flex.driver.features.gripper import PreciseFlexGripper
from pylabrobot.brooks.precise_flex.driver.features.rail import PreciseFlexRail
from pylabrobot.brooks.precise_flex.driver.features.vision import PreciseFlexVision
from pylabrobot.brooks.precise_flex.driver.master import PreciseFlexDriver
from pylabrobot.brooks.precise_flex.resource_model.pf400_chassis import (
  BASE_PLATE_SIZE,
  SHOULDER_AXIS,
  Z_COLUMN_LOCATION,
  base_plate,
  z_column,
  z_column_height,
)
from pylabrobot.brooks.precise_flex.resource_model.workspace import Workspace
from pylabrobot.resources.coordinate import Coordinate
from pylabrobot.resources.resource import Resource

logger = logging.getLogger(__name__)


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
    workspace_location: Optional[Coordinate] = None,
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
      workspace_location: where the workspace sits from the device's origin. Defaults to it.
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
    self.assign_child_resource(
      workspace,
      location=workspace_location if workspace_location is not None else Coordinate.zero(),
    )

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


def PreciseFlex400(
  driver: PreciseFlexDriver,
  name: str = "PreciseFlex400",
  z_travel: float = 400.0,
  reach_class: Literal["standard", "extended"] = "extended",
  shoulder_range: Tuple[float, float] = (-93.0, 93.0),
  elbow_range: Tuple[float, float] = (12.0, 348.0),
) -> PreciseFlexDevice:
  """A PreciseFlex 400, as tall as the travel its carriage was built with.

  The column stands on the plate, so the plate carries it and the machine is one tree. Where the
  controller reports from is `pf400_chassis.SHOULDER_AXIS`, within the plate. What is declared
  here is what the workspace is swept from until the controller has been read.

  Args:
    driver: the driver to drive the device through. Its tool length is the workspace's.
    name: what to call this one.
    z_travel: how far its carriage travels, in mm.
    reach_class: which links it was built with.
    shoulder_range: the shoulder's lowest and highest angle, in degrees.
    elbow_range: the elbow's lowest and highest angle, in degrees.

  Returns:
    The machine.
  """
  link_1_length, link_2_length = (
    kinematics.ARM_LINKS_EXTENDED if reach_class == "extended" else kinematics.ARM_LINKS_STANDARD
  )
  workspace = Workspace(
    name=f"{name}_workspace",
    boundary=kinematics.compute_workspace_boundary(
      kinematics.PF400Params(
        l1=link_1_length,
        l2=link_2_length,
        gripper_length=driver._kinematics_params.gripper_length,
      ),
      shoulder_range=shoulder_range,
      elbow_range=elbow_range,
    ),
    z_min=0.0,
    z_max=z_travel,
  )
  column = z_column(name=f"{name}_z_column", height=z_column_height(z_travel))
  device = PreciseFlexDevice(
    workspace=workspace,
    driver=driver,
    name=name,
    size_x=BASE_PLATE_SIZE[0],
    size_y=BASE_PLATE_SIZE[1],
    size_z=Z_COLUMN_LOCATION.z + column.get_size_z(),
    # The controller reports from the shoulder axis, which the workspace states as its own point.
    workspace_location=SHOULDER_AXIS - workspace.reference_point,
    model=PreciseFlex400.__name__,
  )
  plate = base_plate(name=f"{name}_base_plate")
  device.assign_child_resource(plate, location=Coordinate.zero())
  plate.assign_child_resource(column, location=Z_COLUMN_LOCATION)
  return device
