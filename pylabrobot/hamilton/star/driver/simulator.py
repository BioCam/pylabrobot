"""A STAR that answers commands without being plugged in.

`STARSimulationDriver` subclasses the real driver and replaces only where the reply comes from.
Command assembly, error checking and response parsing all still run, so simulated code exercises
the same paths production code does - a simulator that reimplemented those would drift from them
silently.

`answer()` is the seam. It takes the assembled command string and returns what the machine would
have said, computed from the simulator's own state. Teaching the simulator a new command means
adding a handler to `_HANDLERS` and, where the command changes the machine, state to mutate.
"""

import logging
from typing import Any, Callable, Dict, List, NamedTuple, Optional, Tuple

from pylabrobot.hamilton.protocol.text.framing import assemble_command, parse_fw_string
from pylabrobot.hamilton.star.driver.configuration import DeviceConfiguration
from pylabrobot.hamilton.star.driver.confirmed_firmware_versions import (
  STAR_8_CHANNEL_STACK,
  ConfirmedFirmware,
)
from pylabrobot.hamilton.star.driver.errors import check_fw_string_error
from pylabrobot.hamilton.star.driver.features.x_arm import XArmConfiguration
from pylabrobot.hamilton.star.driver.master import STARDriver
from pylabrobot.io.io import IOBase
from pylabrobot.io.validation_utils import LOG_LEVEL_IO

logger = logging.getLogger(__name__)

# X geometry belongs to the arm, not the instrument: each rail has its own travel, workspace and
# wrap, and `XArmConfiguration` carries all three. These are only the fallback for a simulated arm
# built without them, taken from a real dual-rail arm. Travel is what the drive can move through;
# the workspace is where the arm's reference point can be, so it runs past both ends of the travel
# by roughly half the arm's width.
NOMINAL_X_TRAVEL = (95.0, 1340.2)
NOMINAL_WORKSPACE = (-323.2, 1517.2)
NOMINAL_ARM_WRAP = 595.2

# The x the machine parks the left arm at on every init.
SIMULATED_LEFT_X_ARM_HOME = 362.9

# The firmware stack the simulated instrument reports. Every module's version answer is read off
# it, so the simulator reports one coherent stack rather than a version per module invented
# separately - and reports a stack this driver has actually been validated against.
SIMULATED_FIRMWARE = STAR_8_CHANNEL_STACK

# What the machine reports for an arm that is not fitted: a wrap size of zero, and this position at
# both ends of its travel and workspace.
ARM_ABSENT_POSITION = 3000.0


class _ArmGeometry(NamedTuple):
  """One rail's X geometry, in mm, in the terms the machine reports it."""

  travel: Tuple[float, float]
  workspace: Tuple[float, float]
  wrap: float


# Serial number and installation date the simulated instrument reports. Made up: a simulator must
# never be mistaken for a particular machine.
SIMULATED_SERIAL_NUMBER = "SIM0"
SIMULATED_INSTALLATION_DATE = "2020-01-01"

# Z position a channel reports when parked at its safety height.
CHANNEL_Z_SAFETY = 285.0

# Y/Z drive speed and acceleration registers a 2013-or-later 96-head reports, in mm and mm/s.
HEAD96_Y_SPEED_INCREMENTS = 25_000
HEAD96_Y_ACCELERATION_INCREMENTS = 35_000
HEAD96_Z_SPEED = 85.0
HEAD96_Z_ACCELERATION = 400.0

# What a bare STARSimulationDriver() pretends to be, copied field for field off a real instrument
# so that simulated discovery matches a machine that exists: a full-size STAR, 54 slots wide, with
# eight 1000uL channels, a wide-gripper iSWAP and a 96-head on a dual-rail left arm, autoload
# fitted, no right arm. A STARlet would be the same instrument at 30 slots.
DEFAULT_STAR_CONFIGURATION = DeviceConfiguration(
  pip_type_1000ul=True,
  kb_iswap_installed=True,
  autoload_installed=True,
  num_pip_channels=8,
  left_x_drive_large=True,
  ka_head96_installed=True,
  iswap_gripper_wide=True,
  instrument_size_slots=54,
  autoload_size_slots=54,
  tip_waste_x_position=1340.0,
  left_arm=XArmConfiguration(
    pip_installed=True,
    iswap_installed=True,
    head96_installed=True,
    width=354.0,
    x_range=(95.0, 1340.2),
    workspace_range=(-323.2, 1517.2),
    wrap_size=595.2,
  ),
  right_arm=None,
  min_iswap_collision_free_position=350.0,
  max_iswap_collision_free_position=1140.0,
  left_x_arm_width=354.0,
  right_x_arm_width=370.0,
)


class _UnusedTransport(IOBase):
  """Stands where the transport would be.

  The simulator never reaches the wire. If anything does, that is a defect, and it should be loud
  rather than silently talking to nothing.
  """

  async def setup(self, *args, **kwargs):
    pass

  async def stop(self):
    pass

  async def write(self, data: bytes, *args, **kwargs):
    raise RuntimeError(f"the simulator tried to write to a transport: {data!r}")

  async def read(self, *args, **kwargs) -> bytes:
    raise RuntimeError("the simulator tried to read from a transport")


class STARSimulationDriver(STARDriver):
  """A simulated STAR, driven exactly like the real one."""

  def __init__(
    self,
    configuration: Optional[DeviceConfiguration] = None,
    tips_mounted: Optional[List[bool]] = None,
    firmware: Optional[ConfirmedFirmware] = None,
    serial_number: str = SIMULATED_SERIAL_NUMBER,
    channels_minimum_y_spacing: Optional[List[float]] = None,
    initialized: bool = False,
  ):
    """
    Args:
      configuration: the instrument to pretend to be. Defaults to `DEFAULT_STAR_CONFIGURATION`.
      tips_mounted: one entry per channel, `True` where a tip sits on the channel. Defaults to no
        tips on every channel.
      firmware: the module firmware stack to report. Defaults to `SIMULATED_FIRMWARE`.
      serial_number: what the master reports for an installation-data request.
      channels_minimum_y_spacing: per-channel minimum Y spacing in mm. Defaults to the
        configuration's PIP raster pitch for every channel.
      initialized: whether the machine reports itself already initialized. A machine that has
        just been switched on has not been.

    Raises:
      ValueError: If a per-channel list does not have one entry per channel.
    """
    super().__init__(io=_UnusedTransport())

    self.simulated_configuration = configuration or DEFAULT_STAR_CONFIGURATION
    self.firmware = firmware or SIMULATED_FIRMWARE
    self.serial_number = serial_number

    channels = self.simulated_configuration.num_pip_channels

    if tips_mounted is None:
      tips_mounted = [False] * channels
    if len(tips_mounted) != channels:
      raise ValueError(f"tips_mounted has {len(tips_mounted)} entries, expected {channels}")
    self.tips_mounted = list(tips_mounted)

    if channels_minimum_y_spacing is None:
      channels_minimum_y_spacing = [
        self.simulated_configuration.min_raster_pitch_pip_channels
      ] * channels
    if len(channels_minimum_y_spacing) != channels:
      raise ValueError(
        f"channels_minimum_y_spacing has {len(channels_minimum_y_spacing)} entries, "
        f"expected {channels}"
      )
    self.channels_minimum_y_spacing = list(channels_minimum_y_spacing)

    # Machine state the simulator moves as commands arrive. Nothing reads these yet - the driver
    # cannot issue the commands that would - but they are the state a real STAR carries, and each
    # is what the corresponding handler will mutate and report.
    # Where each arm rests until something moves it: the left at the home the machine parks it to
    # at every init, the right derived from its own reach so its right edge sits at the far end of
    # its travel, clear of the left arm's rest.
    c = self.simulated_configuration
    self.x_arm_positions = {"left": SIMULATED_LEFT_X_ARM_HOME}
    if c.right_arm is not None:
      right_edge = self._geometry(c.right_arm).travel[1]
      self.x_arm_positions["right"] = right_edge - c.right_x_arm_width / 2
    self.channel_z_positions = [CHANNEL_Z_SAFETY] * channels
    self.channel_y_positions = [0.0] * channels
    self.dispensing_drive_positions = [0.0] * channels
    self.iswap_parked = True
    self.head96_tips_mounted = False
    self.initialized = initialized

    # Every command the simulator has been asked, in order. Useful for asserting what a protocol
    # would have sent.
    self.sent: List[str] = []
    self._id = 0

  # -- lifecycle -------------------------------------------------------------

  async def setup(self):
    """Discover the simulated instrument. Opens no link and starts no reader."""
    await self.discover()

  async def stop(self):
    pass

  # -- the seam --------------------------------------------------------------

  async def send_command(
    self,
    module: str,
    command: str,
    auto_id: bool = True,
    tip_pattern: Optional[List[bool]] = None,
    write_timeout: Optional[int] = None,
    read_timeout: Optional[int] = None,
    wait: bool = True,
    fmt: Optional[Any] = None,
    **kwargs,
  ):
    """Assemble the command for real, answer it from state, then parse the reply for real."""
    id_ = self._next_id() if auto_id else None
    cmd = assemble_command(
      module=module,
      command=command,
      id_=id_,
      tip_pattern=tip_pattern,
      num_channels=self._num_channels,
      **kwargs,
    )
    resp = self._exchange(cmd, wait=wait)
    if resp is None:
      return None
    if fmt is not None:
      return self._parse_response(resp, fmt)
    return resp

  async def send_raw_command(
    self,
    command: str,
    write_timeout: Optional[int] = None,
    read_timeout: Optional[int] = None,
    wait: bool = True,
  ) -> Optional[str]:
    """Answer a command string exactly as given."""
    return self._exchange(command, wait=wait)

  def _exchange(self, command: str, wait: bool) -> Optional[str]:
    """Record the command, answer it, and raise on an error reply as the real path would."""
    logger.log(LOG_LEVEL_IO, "simulated STAR write: %s", command)
    self.sent.append(command)
    if not wait:
      return None
    resp = self.answer(command)
    logger.log(LOG_LEVEL_IO, "simulated STAR read: %s", resp)
    check_fw_string_error(resp)
    return resp

  def answer(self, command: str) -> str:
    """Return the reply the machine would send for an assembled command.

    Args:
      command: the assembled command string, exactly as it would go on the wire.

    Returns:
      The reply. A command the simulator does not know is answered the way a machine answers one
      its firmware does not carry.
    """
    module, mnemonic = command[:2], command[2:4]
    id_ = parse_fw_string(command, "id####").get("id")
    prefix = f"{module}{mnemonic}id{id_:04}" if id_ is not None else f"{module}{mnemonic}"

    handler = self._HANDLERS.get(module, {}).get(mnemonic)
    if handler is None:
      if module == "C0":
        return f"{prefix}er01/30"  # master: command syntax error / unknown command
      return f"{prefix}er30"  # module: unknown command

    body = handler(self, command)
    # The master reports two error fields, its own and the module's. The modules we have replies
    # from report none on success, so the body follows the echo directly.
    return f"{prefix}er00/00{body}" if module == "C0" else f"{prefix}{body}"

  def _next_id(self) -> int:
    """continuously generate unique ids 0 <= x < 10000."""
    self._id += 1
    return self._id % 10000

  # -- answers ---------------------------------------------------------------

  def _firmware_version(self, command: str) -> str:
    return f"rf{self.firmware.master_version}"

  def _machine_configuration(self, command: str) -> str:
    c = self.simulated_configuration
    kb = (
      (c.pip_type_1000ul << 0)
      | (c.kb_iswap_installed << 1)
      | (c.main_front_cover_monitoring_installed << 2)
      | (c.autoload_installed << 3)
      | (c.wash_station_1_installed << 4)
      | (c.wash_station_2_installed << 5)
      | (c.temp_controlled_carrier_1_installed << 6)
      | (c.temp_controlled_carrier_2_installed << 7)
    )
    return f"kb{kb:02X}kp{c.num_pip_channels:02} " + " ".join(
      f"{node}0000" for node in self._nodes()
    )

  def _nodes(self) -> List[str]:
    """The modules on the bus, in the order the machine lists them."""
    c = self.simulated_configuration
    nodes = ["C0", "X0"]
    nodes += [f"P{'123456789ABCDEFG'[i]}" for i in range(c.num_pip_channels)]
    if c.autoload_installed:
      nodes.append("I0")
    if c.kb_iswap_installed:
      nodes.append("R0")
    if c.ka_head96_installed:
      nodes.append("H0")
    return nodes

  def _installation_data(self, command: str) -> str:
    return f"si{SIMULATED_INSTALLATION_DATE}sn{self.serial_number}"

  def _extended_configuration(self, command: str) -> str:
    c = self.simulated_configuration
    ka = (
      (c.left_x_drive_large << 0)
      | (c.ka_head96_installed << 1)
      | (c.right_x_drive_large << 2)
      | (c.pump_station_1_installed << 3)
      | (c.pump_station_2_installed << 4)
      | (c.wash_station_1_type_cr << 5)
      | (c.wash_station_2_type_cr << 6)
      | (c.left_cover_installed << 7)
      | (c.right_cover_installed << 8)
      | (c.additional_front_cover_monitoring_installed << 9)
      | (c.pump_station_3_installed << 10)
      | (c.multi_channel_nano_pipettor_installed << 11)
      | (c.dispensing_head_384_installed << 12)
      | (c.xl_channels_installed << 13)
      | (c.tube_gripper_installed << 14)
      | (c.waste_direction_left << 15)
      | (c.iswap_gripper_wide << 16)
      | (c.additional_channel_nano_pipettor_installed << 17)
      | (c.imaging_channel_installed << 18)
      | (c.robotic_channel_installed << 19)
      | (c.channel_order_ox_first << 20)
      | (c.x0_interface_ham_can << 21)
      | (c.park_heads_with_iswap_off << 22)
    )
    # Field order follows the machine, which does not group related fields or match the order the
    # driver asks for them in. Parsing is by field name, so the order is fidelity, not function.
    return (
      f"ka{ka:06X}"
      f"xt{c.instrument_size_slots:02}"
      f"xa{c.autoload_size_slots:02}"
      f"xw{round(c.tip_waste_x_position * 10):05}"
      f"xl{self._arm_modules_byte1(c.left_arm):02X}"
      f"xr{self._arm_modules_byte1(c.right_arm):02X}"
      f"xm{round(c.min_iswap_collision_free_position * 10):05}"
      f"xx{round(c.max_iswap_collision_free_position * 10):05}"
      f"ys{round(c.min_raster_pitch_pip_channels * 10):03}"
      f"xu{round(c.left_x_arm_width * 10):04}"
      f"xv{round(c.right_x_arm_width * 10):04}"
      f"yu{round(c.left_arm_min_y_position * 10):04}"
      f"kl{round(c.min_raster_pitch_xl_channels * 10):03}"
      f"kc{c.num_xl_channels:01}"
      f"yx{round(c.right_arm_min_y_position * 10):04}"
      f"ke{c.configuration_data_3:08X}"
      f"xn{self._arm_modules_byte2(c.left_arm):02X}"
      f"xo{self._arm_modules_byte2(c.right_arm):02X}"
      f"ym{round(c.pip_maximal_y_position * 10):04}"
      f"kr{c.num_robotic_channels:01}"
      f"km{round(c.min_raster_pitch_robotic_channels * 10):03}"
    )

  @staticmethod
  def _arm_modules_byte1(arm: Optional[XArmConfiguration]) -> int:
    if arm is None:
      return 0
    return (
      (arm.pip_installed << 0)
      | (arm.iswap_installed << 1)
      | (arm.head96_installed << 2)
      | (arm.nano_pipettor_installed << 3)
      | (arm.dispensing_head_384_installed << 4)
      | (arm.xl_channels_installed << 5)
      | (arm.tube_gripper_installed << 6)
      | (arm.imaging_channel_installed << 7)
    )

  @staticmethod
  def _arm_modules_byte2(arm: Optional[XArmConfiguration]) -> int:
    return 0 if arm is None else (arm.robotic_channel_installed << 0)

  def _geometry(self, arm: Optional[XArmConfiguration]) -> _ArmGeometry:
    """The X geometry of one rail, as the machine would report it.

    An arm carries its own travel, workspace and wrap; an arm built without them falls back to a
    real dual-rail arm's, and a rail with no arm reports what the machine reports for one.
    """
    if arm is None:
      absent = (ARM_ABSENT_POSITION, ARM_ABSENT_POSITION)
      # A wrap of 0 is how the machine says "this arm is not installed".
      return _ArmGeometry(travel=absent, workspace=absent, wrap=0.0)
    return _ArmGeometry(
      travel=arm.x_range or NOMINAL_X_TRAVEL,
      workspace=arm.workspace_range or NOMINAL_WORKSPACE,
      wrap=NOMINAL_ARM_WRAP if arm.wrap_size is None else arm.wrap_size,
    )

  def _arm_geometry(self) -> List[_ArmGeometry]:
    c = self.simulated_configuration
    return [self._geometry(c.left_arm), self._geometry(c.right_arm)]

  def _x_drive_ranges(self, command: str) -> str:
    values = [v for arm in self._arm_geometry() for v in arm.travel]
    return "ru" + " ".join(f"{round(v * 10):05}" for v in values)

  def _working_envelopes(self, command: str) -> str:
    arms = self._arm_geometry()
    wraps = " ".join(f"{round(arm.wrap * 10):04}" for arm in arms)
    workspaces = " ".join(f"{round(v * 10):+06}" for arm in arms for v in arm.workspace)
    return f"ua{wraps} {workspaces}"

  def _tip_presence(self, command: str) -> str:
    return "rt" + " ".join("1" if mounted else "0" for mounted in self.tips_mounted)

  def _initialization_status(self, command: str) -> str:
    return f"qw{int(self.initialized)}"

  def _pre_initialize(self, command: str) -> str:
    """Home every drive. Leaves the channels at Z safety and the arms at their rest."""
    self.initialized = True
    self.channel_z_positions = [CHANNEL_Z_SAFETY] * len(self.channel_z_positions)
    self.x_arm_positions["left"] = SIMULATED_LEFT_X_ARM_HOME
    return ""

  def _move_all_channels_to_z_safety(self, command: str) -> str:
    self.channel_z_positions = [CHANNEL_Z_SAFETY] * len(self.channel_z_positions)
    return ""

  def _x_arm_firmware_version(self, command: str) -> str:
    version = self.firmware.x_drives_version
    if version is None:
      raise ValueError("the simulated firmware stack records no X-drive version")
    return f"rf{version}"

  def _move_x_arm(self, command: str) -> str:
    """Move the arm and acknowledge. The move is instant; there is nothing to be slow about."""
    self.x_arm_positions["left"] = parse_fw_string(command, "la#####")["la"] / 10
    return ""

  # Module -> command mnemonic -> the method that builds its reply body. Extend this as driver
  # methods land: the legacy chatterbox additionally answered channel Z and Y positions,
  # dispensing-drive positions, per-channel Y spacing, tip length, last LLD height, and the
  # 96-head's firmware version, tip presence and drive speeds.
  _HANDLERS: Dict[str, Dict[str, Callable[["STARSimulationDriver", str], str]]] = {
    "C0": {
      "RF": _firmware_version,
      "RI": _installation_data,
      "RM": _machine_configuration,
      "QM": _extended_configuration,
      "RU": _x_drive_ranges,
      "UA": _working_envelopes,
      "RT": _tip_presence,
      "QW": _initialization_status,
      "VI": _pre_initialize,
      "ZA": _move_all_channels_to_z_safety,
    },
    "X0": {
      "RF": _x_arm_firmware_version,
      "XP": _move_x_arm,
    },
  }
