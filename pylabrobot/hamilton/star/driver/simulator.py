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
from pylabrobot.hamilton.star.driver.features.head96 import Head96Configuration
from pylabrobot.hamilton.star.driver.features.pipettes import PipettesConfiguration
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

# How a channel counts Y, used to report a pipette's width in the units it answers in.
PIPETTE_Y_DRIVE_MM_PER_INCREMENT = PipettesConfiguration().y_drive_mm_per_increment

# What a channel reports for the hardware fitted to it, field by field: an ML_STAR channel on an
# ML_STAR head, a CoRe II stop disc, and a Renesas pressure ADC.
SIMULATED_CHANNEL_HARDWARE = ("0", "0", "1", "0")

# What the 96-head reports about itself, field by field: clot monitoring with cLLD, a CoRe II
# stop disc, and a legacy (not FM-STAR) instrument.
SIMULATED_HEAD96_HARDWARE = ("0", "1", "0", "0", "0", "0", "0", "0", "0", "0")

# Which head is fitted, and where its channel A1 sits relative to the arm carriage, in mm.
SIMULATED_HEAD96_TYPE = 2
SIMULATED_HEAD96_X_OFFSET = 368.2

# What the iSWAP holds in its stored position tables, slot by slot, as read off a real arm. The
# rotation and wrist tables end in the arm length; the Y table is all position.
SIMULATED_ISWAP_ROTATION_SLOTS = (
  13000,
  -29007,
  156,
  29068,
  29500,
  29068,
  29068,
  29068,
  29068,
  1378,
)
SIMULATED_ISWAP_WRIST_SLOTS = (
  -26577,
  -26577,
  -8860,
  9044,
  26858,
  -26577,
  -26577,
  -26577,
  -26577,
  1377,
)
SIMULATED_ISWAP_Y_SLOTS = (9855, 7000, 9000, 13550, 12600, 9855, 9855, 9855, 9855, 9855)

# Where the iSWAP's rotation drive sits relative to the arm carriage, in mm.
SIMULATED_ISWAP_X_OFFSET = 32.8

# Z position a channel reports when parked at its safety height.
CHANNEL_Z_SAFETY = 285.0

# The Y/Z drive registers a 2013-or-later 96-head holds, in the increments it counts in, and how
# it counts Z. The Z safety height is where a retract leaves it.
HEAD96_DRIVE_PARAMETERS = {"yv": 25_000, "yr": 35_000, "zv": 17_000, "zr": 80_000}
HEAD96_Z_DRIVE_MM_PER_INCREMENT = Head96Configuration().z_drive_mm_per_increment
HEAD96_Z_SAFETY = 336.965

# The iSWAP's stored tables, by the name each is asked for by.
ISWAP_TABLES = {
  "pw": SIMULATED_ISWAP_ROTATION_SLOTS,
  "pt": SIMULATED_ISWAP_WRIST_SLOTS,
  "py": SIMULATED_ISWAP_Y_SLOTS,
}

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
    pipette_widths: Optional[List[float]] = None,
    initialized: bool = False,
  ):
    """
    Args:
      configuration: the instrument to pretend to be. Defaults to `DEFAULT_STAR_CONFIGURATION`.
      tips_mounted: one entry per channel, `True` where a tip sits on the channel. Defaults to no
        tips on every channel.
      firmware: the module firmware stack the simulated machine reports. Defaults to
        `SIMULATED_FIRMWARE`. Kept as `simulated_firmware`, beside
        `simulated_configuration`; `firmware` is what the driver read back.
      serial_number: what the master reports for an installation-data request.
      pipette_widths: how wide each pipette is, in mm. Defaults to the
        configuration's PIP raster pitch for every channel.
      initialized: whether the machine reports itself already initialized. A machine that has
        just been switched on has not been.

    Raises:
      ValueError: If a per-channel list does not have one entry per channel.
    """
    super().__init__(io=_UnusedTransport())

    self.simulated_configuration = configuration or DEFAULT_STAR_CONFIGURATION
    self.simulated_firmware = firmware or SIMULATED_FIRMWARE
    self.serial_number = serial_number

    channels = self.simulated_configuration.num_pip_channels

    if tips_mounted is None:
      tips_mounted = [False] * channels
    if len(tips_mounted) != channels:
      raise ValueError(f"tips_mounted has {len(tips_mounted)} entries, expected {channels}")
    self.tips_mounted = list(tips_mounted)

    if pipette_widths is None:
      pipette_widths = [self.simulated_configuration.min_raster_pitch_pip_channels] * channels
    if len(pipette_widths) != channels:
      raise ValueError(f"pipette_widths has {len(pipette_widths)} entries, expected {channels}")
    self.pipette_widths = list(pipette_widths)
    self.channel_hardware = [SIMULATED_CHANNEL_HARDWARE] * channels

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
    self.head96_z_position = HEAD96_Z_SAFETY
    self.head96_initialized = initialized
    self.iswap_initialized = initialized
    self.initialized = initialized

    # Every command the simulator has been asked, in order. Useful for asserting what a protocol
    # would have sent.
    self.sent: List[str] = []
    self._id = 0

  # -- lifecycle -------------------------------------------------------------

  def _describe_link(self) -> str:
    return "simulation (no link)"

  async def _open(self):
    """There is no link to open and no replies to read: they are answered as they are asked."""

  async def _close(self):
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
    # Every pipetting channel runs the same firmware, so they share one handler table.
    table = "Px" if module.startswith("P") and module[1] in "123456789ABCDEFG" else module
    id_ = parse_fw_string(command, "id####").get("id")
    prefix = f"{module}{mnemonic}id{id_:04}" if id_ is not None else f"{module}{mnemonic}"

    handler = self._HANDLERS.get(table, {}).get(mnemonic)
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
    return f"rf{self.simulated_firmware.master_version}"

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
    version = self.simulated_firmware.x_drives_version
    if version is None:
      raise ValueError("the simulated firmware stack records no X-drive version")
    return f"rf{version}"

  def _channel_firmware_version(self, command: str) -> str:
    return f"rf{self.simulated_firmware.channels_version}"

  def _y_drive_parameters(self, command: str) -> str:
    """The channel's Y-drive parameters: init position offset, the distance between the channels
    in the increments the drive counts in, and the drive's turn direction, which alternates
    between odd and even channels."""
    channel = self._channel_index(command)
    distance = round(self.pipette_widths[channel] / PIPETTE_Y_DRIVE_MM_PER_INCREMENT)
    return f"yc000 {distance:03} {channel % 2}"

  def _channel_hardware(self, command: str) -> str:
    return "vw" + " ".join(self.channel_hardware[self._channel_index(command)])

  def _iswap_initialization_status(self, command: str) -> str:
    return f"qw{int(self.iswap_initialized)}"

  def _iswap_firmware_version(self, command: str) -> str:
    version = self.simulated_firmware.iswap_version
    if version is None:
      raise ValueError("the simulated firmware stack records no iSWAP version")
    return f"rf{version}"

  def _iswap_stored_table(self, command: str) -> str:
    """One of the arm's stored position tables, signed and blank-separated as it reports them."""
    table = str(parse_fw_string(command, "ra&&")["ra"])
    slots = ISWAP_TABLES.get(table)
    if slots is None:
      return ""  # a table this simulator does not hold
    return table + " ".join(f"{slot:+06}" for slot in slots)

  def _initialize_iswap(self, command: str) -> str:
    self.iswap_initialized = True
    self.iswap_parked = False
    return ""

  def _park_iswap(self, command: str) -> str:
    self.iswap_parked = True
    return ""

  def _head96_initialization_status(self, command: str) -> str:
    return f"qw{int(self.head96_initialized)}"

  def _head96_firmware_version(self, command: str) -> str:
    version = self.simulated_firmware.head96_version
    if version is None:
      raise ValueError("the simulated firmware stack records no 96-head version")
    return f"rf{version}"

  def _head96_hardware(self, command: str) -> str:
    return "au" + " ".join(SIMULATED_HEAD96_HARDWARE)

  def _head96_type(self, command: str) -> str:
    return f"qg{SIMULATED_HEAD96_TYPE}"

  def _head96_stop_disk_z(self, command: str) -> str:
    """The firmware and hardware counters. A real head reports them a few increments apart; the
    simulator holds one position and reports it for both. The hardware counter is the one read."""
    increments = round(self.head96_z_position / HEAD96_Z_DRIVE_MM_PER_INCREMENT)
    return f"rz+{increments:05} +{increments:05}"

  def _head96_drive_parameter(self, command: str) -> str:
    parameter = parse_fw_string(command, "ra&&")["ra"]
    value = HEAD96_DRIVE_PARAMETERS.get(parameter)
    if value is None:
      return ""  # a parameter this simulator does not hold
    return f"{parameter}{value:05}"

  def _master_parameter(self, command: str) -> str:
    """A parameter held in the master's own memory."""
    parameter = parse_fw_string(command, "ra&&")["ra"]
    if parameter == "kf":  # 96-head x offset
      return f"kf{round(SIMULATED_HEAD96_X_OFFSET * 10):04}"
    if parameter == "kg":  # iSWAP rotation-drive x offset
      return f"kg{round(SIMULATED_ISWAP_X_OFFSET * 10):03}"
    return ""

  def _retract_head96(self, command: str) -> str:
    self.head96_z_position = HEAD96_Z_SAFETY
    return ""

  def _initialize_head96(self, command: str) -> str:
    """Throw off whatever is mounted and leave the head where the command says."""
    self.head96_tips_mounted = False
    ending_at = parse_fw_string(command, "ze####").get("ze")
    if ending_at is not None:
      self.head96_z_position = ending_at / 10
    self.head96_initialized = True
    return ""

  def _initialize_channels(self, command: str) -> str:
    """Throw off whatever is mounted and leave the channels at Z safety."""
    self.tips_mounted = [False] * len(self.tips_mounted)
    self.channel_z_positions = [CHANNEL_Z_SAFETY] * len(self.channel_z_positions)
    return ""

  @staticmethod
  def _channel_index(command: str) -> int:
    """Which channel a `Px` command addresses, 0-indexed from the back."""
    return "123456789ABCDEFG".index(command[1])

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
      "DI": _initialize_channels,
      "EV": _retract_head96,
      "EI": _initialize_head96,
      "RA": _master_parameter,
      "FI": _initialize_iswap,
      "PG": _park_iswap,
    },
    "R0": {
      "RF": _iswap_firmware_version,
      "QW": _iswap_initialization_status,
      "RA": _iswap_stored_table,
    },
    "H0": {
      "RF": _head96_firmware_version,
      "QU": _head96_hardware,
      "QG": _head96_type,
      "QW": _head96_initialization_status,
      "RZ": _head96_stop_disk_z,
      "RA": _head96_drive_parameter,
    },
    "Px": {
      "RF": _channel_firmware_version,
      "VY": _y_drive_parameters,
      "VW": _channel_hardware,
    },
    "X0": {
      "RF": _x_arm_firmware_version,
      "XP": _move_x_arm,
    },
  }
