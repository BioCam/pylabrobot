"""Mantis configuration: what the device reported about itself at setup."""

import dataclasses
import json
import os
from typing import Any, Dict, Literal, Optional, Tuple

from .features.pump import PressureController
from .framing import ABSOLUTE_POSITION_SENSOR_BOARD


@dataclasses.dataclass
class DeviceConfiguration:
  """What the device reported about itself.

  Attributes:
    generation: "v4" if board 11 answered the version read, else "v3"; None until read.
    firmware_versions: each board's firmware version, by board; None for a board that did not
      answer.
    motor_limits: each motor's (lower, upper) limit, by motor, in the device's units.
    feedback_sensor_parameters: each pressure controller's feedback sensor (scale, offset), by
      controller name (``PRESSURE_CONTROLLERS``), not by its index as the motors are; as the
      pressure board holds them, empty without one. Not a fitted field.
  """

  generation: Optional[Literal["v3", "v4"]] = None
  firmware_versions: Dict[int, Optional[str]] = dataclasses.field(default_factory=dict)
  motor_limits: Dict[int, Tuple[float, float]] = dataclasses.field(default_factory=dict)
  feedback_sensor_parameters: Dict[PressureController, Tuple[float, float]] = dataclasses.field(
    default_factory=dict
  )


# One real unit of each generation: its device block and its unit blocks.
RECORDING_MANTIS_V3 = os.path.join(os.path.dirname(__file__), "recordings", "mantis_v3.json")
RECORDING_MANTIS_V4 = os.path.join(os.path.dirname(__file__), "recordings", "mantis_v4.json")
# The blocks a unit's own values fill: from its vendor folder, its declared file or a recording.
UNIT_BLOCKS = ("plate_clamp", "rfid", "led_bar", "arm", "zones", "stations", "stage")
# The blocks that calibrate motion: never taken from a recording; without them motion refuses.
MOTION_CALIBRATION_BLOCKS = ("arm", "zones", "stations", "stage")

# What is fitted: compared between a declared configuration and the device at setup. Firmware is
# not, so a configuration taken off one device still describes another of its build.
FITTED_FIELDS = ("generation", "motor_limits")


def compute_generation(*, firmware_versions: Dict[int, Optional[str]]) -> Literal["v3", "v4"]:
  """The generation from which boards answered the version read: board 11 answers on a v4.

  Args:
    firmware_versions: each board's firmware version, None for a board that did not answer.
  """
  # A v3 is not known to have the absolute position sensor board.
  if firmware_versions.get(ABSOLUTE_POSITION_SENSOR_BOARD) is not None:
    return "v4"
  return "v3"


def configuration_to_json(configuration: DeviceConfiguration) -> Dict[str, Any]:
  """The fields as JSON values, as saved."""
  return dict(json.loads(json.dumps(dataclasses.asdict(configuration))))


def configuration_from_json(fields: Dict[str, Any]) -> DeviceConfiguration:
  """A configuration from saved fields, with JSON's lists and string keys turned back."""
  return DeviceConfiguration(
    generation=fields.get("generation"),
    firmware_versions={
      int(board): version for board, version in fields.get("firmware_versions", {}).items()
    },
    motor_limits={
      int(motor): (float(lower), float(upper))
      for motor, (lower, upper) in fields.get("motor_limits", {}).items()
    },
    feedback_sensor_parameters={
      controller: (float(scale), float(offset))
      for controller, (scale, offset) in fields.get("feedback_sensor_parameters", {}).items()
    },
  )


def read_configuration(path: str) -> Dict[str, Any]:
  """Read a configuration written by ``MantisDriver.save_configuration``."""
  with open(path, encoding="utf-8") as f:
    return dict(json.load(f))
