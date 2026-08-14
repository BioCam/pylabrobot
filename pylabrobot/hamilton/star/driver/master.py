"""The STAR master module, responsible for
- carrying the transport,
- firmware protocol
- orchestrating higher level tasks.
"""

import logging
from typing import Any, Dict, List, Literal, Optional, Tuple, cast

from pylabrobot.hamilton.protocol.text.framing import assemble_command, parse_fw_string
from pylabrobot.hamilton.protocol.text.router import ReplyRouter
from pylabrobot.hamilton.star.driver.configuration import DeviceConfiguration
from pylabrobot.hamilton.star.driver.errors import (
  STAR_MODULE_ID_LENGTH,
  check_fw_string_error,
)
from pylabrobot.hamilton.star.driver.features.pipettes import Pipettes
from pylabrobot.hamilton.star.driver.features.x_arm import XArm, XArmConfiguration
from pylabrobot.io.io import IOBase
from pylabrobot.io.usb import USB

logger = logging.getLogger(__name__)

ID_VENDOR = 0x08AF
ID_PRODUCT = 0x8000

# The instrument initialization procedure homes every drive, which takes minutes.
PRE_INITIALIZE_READ_TIMEOUT = 300


class STARDriver:
  """Interface for the Hamilton STARDriver."""

  PIP_X_MIN_WITH_LEFT_SIDE_PANEL: float = 320.0
  HEAD96_X_MIN_WITH_LEFT_SIDE_PANEL: float = 0.0

  def __init__(
    self,
    device_address: Optional[int] = None,
    serial_number: Optional[str] = None,
    packet_read_timeout: int = 3,
    read_timeout: int = 30,
    write_timeout: int = 30,
    left_side_panel_installed: bool = False,
    io: Optional[IOBase] = None,
  ):
    """Create a new STAR interface.

    Args:
      device_address: the USB device address of the Hamilton STAR. Only useful if using more than
        one Hamilton machine over USB.
      serial_number: the serial number of the Hamilton STAR. Only useful if using more than one
        Hamilton machine over USB.
      packet_read_timeout: timeout in seconds for reading a single packet.
      read_timeout: timeout in seconds for reading a full response.
      write_timeout: timeout in seconds for writing a command.
      left_side_panel_installed: if True, restrict PIP channels to x >= 320mm and
        the 96-head to x >= 0mm to prevent collisions with the left side panel.
      io: an already-built USB handle to use instead of opening one from the arguments above.
    """

    self.io: IOBase = io or USB(
      human_readable_device_name="Hamilton",
      id_vendor=ID_VENDOR,
      id_product=ID_PRODUCT,
      device_address=device_address,
      write_timeout=write_timeout,
      serial_number=serial_number,
    )

    self._replies = ReplyRouter(
      io=self.io,
      module_id_length=STAR_MODULE_ID_LENGTH,
      parse_id=self.get_id_from_fw_response,
      raise_for_error=check_fw_string_error,
      packet_read_timeout=packet_read_timeout,
      read_timeout=read_timeout,
    )

    self._num_channels: Optional[int] = None

    self.left_side_panel_installed = left_side_panel_installed

    self.configuration: Optional[DeviceConfiguration] = None

    # Subsystems. Each reads what it needs off `configuration`, so they are usable once setup has
    # run and raise a clear error before that. A STAR always has a left arm; a right arm is an
    # option, so it appears only if setup finds one installed.
    self.pipettes = Pipettes(self)
    self.left_x_arm = XArm(self, side="left")
    self.right_x_arm: Optional[XArm] = None

  # -- connection ------------------------------------------------------------

  async def setup(self):
    """Open the connection and discover what machine is on the other end."""
    await self.io.setup()
    self._replies.start()
    await self.discover()

  async def discover(self):
    """Read what machine is on the other end, and build the subsystems it turns out to have.

    Read-only: nothing moves. Call `initialize` to bring the machine up.
    """
    self.configuration = await self.request_device_configuration()
    self._num_channels = len(await self.request_tip_presence())

    if self.configuration.right_arm is not None:
      self.right_x_arm = XArm(self, side="right")

  async def initialize(self, force: bool = False):
    """Bring the machine to a known state, ready to be driven.

    This moves the instrument. An uninitialized machine runs its initialization procedure, which
    homes every drive and leaves the channels at Z safety. A machine that is already initialized
    is left where it is, apart from raising the channels to Z safety, which the procedure would
    otherwise have guaranteed - nothing may move laterally while a channel is low.

    Args:
      force: run the initialization procedure even if the machine reports itself initialized.
    """
    if force or not await self.request_initialization_status():
      await self.pre_initialize()
      return

    await self.pipettes.move_all_to_z_safety()
    if self.configuration is not None and self.configuration.ka_head96_installed:
      logger.warning(
        "the 96-head was not raised: this driver cannot move it yet. Raise it before any "
        "lateral move, or call initialize(force=True) to run the full procedure."
      )

  async def request_initialization_status(self, module: str = "C0") -> bool:
    """Whether a module reports itself initialized.

    Every module answers the same query, so this covers the master and each subsystem.

    Args:
      module: the module to ask. Defaults to the master, which reports for the instrument.

    Returns:
      True if the module is initialized.
    """
    resp = await self.send_command(module=module, command="QW", fmt="qw#")
    return cast(int, resp["qw"]) == 1

  async def pre_initialize(self):
    """Run the instrument's initialization procedure.

    Homes every drive and leaves the channels at Z safety. It takes minutes, hence the long read
    timeout.
    """
    return await self.send_command(
      module="C0", command="VI", read_timeout=PRE_INITIALIZE_READ_TIMEOUT
    )

  async def stop(self):
    self._replies.stop()
    await self.io.stop()

  @property
  def num_channels(self) -> int:
    """The number of pipette channels present on the robot."""
    if self._num_channels is None:
      raise RuntimeError("has not loaded num_channels, forgot to call `setup`?")
    return self._num_channels

  # -- sending ---------------------------------------------------------------

  async def send_command(
    self,
    module: str,
    command: str,
    auto_id=True,
    tip_pattern: Optional[List[bool]] = None,
    write_timeout: Optional[int] = None,
    read_timeout: Optional[int] = None,
    wait=True,
    fmt: Optional[Any] = None,
    **kwargs,
  ):
    """Assemble a firmware command, send it, and parse the reply if a format is given."""
    id_ = self._replies.next_id() if auto_id else None
    cmd = assemble_command(
      module=module,
      command=command,
      id_=id_,
      tip_pattern=tip_pattern,
      num_channels=self._num_channels,
      **kwargs,
    )
    resp = await self._replies.send(
      cmd=cmd,
      id_=id_,
      write_timeout=write_timeout,
      read_timeout=read_timeout,
      wait=wait,
    )
    if resp is not None and fmt is not None:
      return self._parse_response(resp, fmt)
    return resp

  async def send_raw_command(
    self,
    command: str,
    write_timeout: Optional[int] = None,
    read_timeout: Optional[int] = None,
    wait: bool = True,
  ) -> Optional[str]:
    """Send a raw command to the machine."""
    return await self._replies.send_raw(
      command=command,
      write_timeout=write_timeout,
      read_timeout=read_timeout,
      wait=wait,
    )

  # -- device queries --------------------------------------------------------

  async def request_tip_presence(self) -> List[bool]:
    """Measure tip presence on all single channels using their sleeve sensors.

    Returns:
      A list of length `num_channels`, `True` where a tip is mounted.
    """
    resp = await self.send_command(module="C0", command="RT", fmt="rt# (n)")
    return [bool(v) for v in cast(List[int], resp.get("rt"))]

  async def request_maximal_ranges_of_x_drives(self) -> Dict[str, Tuple[float, float]]:
    """Request the maximal travel range of each X drive.

    Returns:
      The `(minimum, maximum)` X position in mm each drive can reach, keyed by side:
      `{"left": (min, max), "right": (min, max)}`.
    """
    resp = await self.send_command(module="C0", command="RU")
    values = [int(v) / 10 for v in resp.split("ru")[-1].strip().split()]
    left_min, left_max, right_min, right_max = values
    return {"left": (left_min, left_max), "right": (right_min, right_max)}

  async def request_working_envelopes_per_arm(
    self,
  ) -> Dict[str, Tuple[float, Tuple[float, float]]]:
    """Request the working envelope of each installed arm.

    Returns:
      Per side, `(wrap_size, (workspace_min, workspace_max))` in mm, keyed by side. A
      `wrap_size` of 0 means that arm is not installed.
    """
    resp = await self.send_command(module="C0", command="UA")
    values = [int(v) / 10 for v in resp.split("ua")[-1].strip().split()]
    left_wrap, right_wrap, left_min, left_max, right_min, right_max = values
    return {
      "left": (left_wrap, (left_min, left_max)),
      "right": (right_wrap, (right_min, right_max)),
    }

  async def request_device_configuration(self) -> DeviceConfiguration:
    """Request the instrument's installed hardware and geometry.

    Combines the machine configuration (RM) and the extended configuration (QM). Each installed
    X-drive's geometry is resolved from the X-drive range (RU) and working-envelope (UA) queries;
    `right_arm` is None when no second arm is installed.
    """
    machine = await self.send_command(module="C0", command="RM", fmt="kb**kp##")
    extended = await self.send_command(
      module="C0",
      command="QM",
      fmt="ka******ke********xt##xa##xw#####xl**xn**xr**xo**xm#####xx#####xu####xv####kc#kr#"
      + "ys###kl###km###ym####yu####yx####",
    )

    ranges = await self.request_maximal_ranges_of_x_drives()
    wraps = await self.request_working_envelopes_per_arm()

    def _resolve_arm(
      byte1: int, byte2: int, side: Literal["left", "right"], width: float
    ) -> Optional[XArmConfiguration]:
      wrap, workspace_range = wraps[side]
      if wrap == 0:  # arm not installed
        return None
      return XArmConfiguration(
        pip_installed=bool(byte1 & (1 << 0)),
        iswap_installed=bool(byte1 & (1 << 1)),
        head96_installed=bool(byte1 & (1 << 2)),
        nano_pipettor_installed=bool(byte1 & (1 << 3)),
        dispensing_head_384_installed=bool(byte1 & (1 << 4)),
        xl_channels_installed=bool(byte1 & (1 << 5)),
        tube_gripper_installed=bool(byte1 & (1 << 6)),
        imaging_channel_installed=bool(byte1 & (1 << 7)),
        robotic_channel_installed=bool(byte2 & (1 << 0)),
        width=width,
        x_range=ranges[side],
        workspace_range=workspace_range,
        wrap_size=wrap,
      )

    left_arm = _resolve_arm(extended["xl"], extended["xn"], "left", extended["xu"] / 10)
    if left_arm is None:
      raise RuntimeError("no left X-arm reported; a STAR always has one")

    kb = machine["kb"]
    ka = extended["ka"]
    return DeviceConfiguration(
      pip_type_1000ul=bool(kb & (1 << 0)),
      kb_iswap_installed=bool(kb & (1 << 1)),
      main_front_cover_monitoring_installed=bool(kb & (1 << 2)),
      autoload_installed=bool(kb & (1 << 3)),
      wash_station_1_installed=bool(kb & (1 << 4)),
      wash_station_2_installed=bool(kb & (1 << 5)),
      temp_controlled_carrier_1_installed=bool(kb & (1 << 6)),
      temp_controlled_carrier_2_installed=bool(kb & (1 << 7)),
      num_pip_channels=machine["kp"],
      left_x_drive_large=bool(ka & (1 << 0)),
      ka_head96_installed=bool(ka & (1 << 1)),
      right_x_drive_large=bool(ka & (1 << 2)),
      pump_station_1_installed=bool(ka & (1 << 3)),
      pump_station_2_installed=bool(ka & (1 << 4)),
      wash_station_1_type_cr=bool(ka & (1 << 5)),
      wash_station_2_type_cr=bool(ka & (1 << 6)),
      left_cover_installed=bool(ka & (1 << 7)),
      right_cover_installed=bool(ka & (1 << 8)),
      additional_front_cover_monitoring_installed=bool(ka & (1 << 9)),
      pump_station_3_installed=bool(ka & (1 << 10)),
      multi_channel_nano_pipettor_installed=bool(ka & (1 << 11)),
      dispensing_head_384_installed=bool(ka & (1 << 12)),
      xl_channels_installed=bool(ka & (1 << 13)),
      tube_gripper_installed=bool(ka & (1 << 14)),
      waste_direction_left=bool(ka & (1 << 15)),
      iswap_gripper_wide=bool(ka & (1 << 16)),
      additional_channel_nano_pipettor_installed=bool(ka & (1 << 17)),
      imaging_channel_installed=bool(ka & (1 << 18)),
      robotic_channel_installed=bool(ka & (1 << 19)),
      channel_order_ox_first=bool(ka & (1 << 20)),
      x0_interface_ham_can=bool(ka & (1 << 21)),
      park_heads_with_iswap_off=bool(ka & (1 << 22)),
      configuration_data_3=extended["ke"],
      instrument_size_slots=extended["xt"],
      autoload_size_slots=extended["xa"],
      tip_waste_x_position=extended["xw"] / 10,
      left_arm=left_arm,
      right_arm=_resolve_arm(extended["xr"], extended["xo"], "right", extended["xv"] / 10),
      min_iswap_collision_free_position=extended["xm"] / 10,
      max_iswap_collision_free_position=extended["xx"] / 10,
      left_x_arm_width=extended["xu"] / 10,
      right_x_arm_width=extended["xv"] / 10,
      num_xl_channels=extended["kc"],
      num_robotic_channels=extended["kr"],
      min_raster_pitch_pip_channels=extended["ys"] / 10,
      min_raster_pitch_xl_channels=extended["kl"] / 10,
      min_raster_pitch_robotic_channels=extended["km"] / 10,
      pip_maximal_y_position=extended["ym"] / 10,
      left_arm_min_y_position=extended["yu"] / 10,
      right_arm_min_y_position=extended["yx"] / 10,
    )

  # -- response parsing ------------------------------------------------------

  def get_id_from_fw_response(self, resp: str) -> Optional[int]:
    """Get the id from a firmware response."""
    parsed = parse_fw_string(resp, "id####")
    if "id" in parsed and parsed["id"] is not None:
      return int(parsed["id"])
    return None

  def _parse_response(self, resp: str, fmt: Any) -> Dict[str, Any]:
    """Parse a response from the machine."""
    return parse_fw_string(resp, fmt)
