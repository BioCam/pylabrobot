"""The PreciseFlex arms as resources: the chassis each one stands on, assembled into one tree.

A frame factory builds the machine. What it carries - the carriage, the arm, the gripper - is hung
off it by the driver at setup, from what the controller reports.
"""

from pylabrobot.brooks.precise_flex.resource_model.pf400_chassis import (
  BASE_PLATE_SIZE,
  Z_COLUMN_LOCATION,
  base_plate,
  z_column,
  z_column_height,
)
from pylabrobot.resources.coordinate import Coordinate
from pylabrobot.resources.resource import Resource


def PreciseFlex400(name: str, z_travel: float) -> Resource:
  """A PreciseFlex 400, as tall as the travel its carriage was built with.

  The column stands on the plate, so the plate carries it and the machine is one tree. Where the
  controller reports from is `pf400_chassis.SHOULDER_AXIS`, within the plate.

  Args:
    name: what to call this one.
    z_travel: how far its carriage travels, in mm, as the J1 limits give it.

  Returns:
    The machine.
  """
  column = z_column(name=f"{name}_z_column", height=z_column_height(z_travel))
  device = Resource(
    name=name,
    size_x=BASE_PLATE_SIZE[0],
    size_y=BASE_PLATE_SIZE[1],
    size_z=Z_COLUMN_LOCATION.z + column.get_size_z(),
    category="device",
    model="PreciseFlex400",
  )
  plate = base_plate(name=f"{name}_base_plate")
  device.assign_child_resource(plate, location=Coordinate.zero())
  plate.assign_child_resource(column, location=Z_COLUMN_LOCATION)
  return device
