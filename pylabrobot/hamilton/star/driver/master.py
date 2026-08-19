"""The STAR master module, responsible for
- carrying the transport,
- firmware protocol
- orchestrating higher level tasks.
"""

import asyncio
import datetime
import logging
from typing import Any, Dict, List, Literal, Optional, Tuple, cast

from pylabrobot.events import emit_event
from pylabrobot.hamilton.protocol.text.framing import (
  assemble_command,
  parse_firmware_version_date,
  parse_fw_string,
)
from pylabrobot.hamilton.protocol.text.router import ReplyRouter
from pylabrobot.hamilton.star.driver.configuration import DeviceConfiguration
from pylabrobot.hamilton.star.driver.errors import (
  STAR_MODULE_ID_LENGTH,
  check_fw_string_error,
)
from pylabrobot.hamilton.star.driver.features.autoload import Autoload
from pylabrobot.hamilton.star.driver.features.cover import FrontCover
from pylabrobot.hamilton.star.driver.features.head96 import Head96
from pylabrobot.hamilton.star.driver.features.iswap import iSWAP
from pylabrobot.hamilton.star.driver.features.pipettes import Pipettes
from pylabrobot.hamilton.star.driver.features.x_arm import XArm, XArmConfiguration
from pylabrobot.io.io import IOBase
from pylabrobot.io.usb import USB
from pylabrobot.resources.hamilton.hamilton_decks import HamiltonDeck

logger = logging.getLogger(__name__)

ID_VENDOR = 0x08AF
ID_PRODUCT = 0x8000


def _range(values: Optional[Tuple[float, float]]) -> str:
  """A `(low, high)` range in mm, or a note that it was not resolved."""
  return "unresolved" if values is None else f"{values[0]} to {values[1]} mm"


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
    deck: Optional[HamiltonDeck] = None,
    packet_read_timeout: int = 3,
    write_timeout: int = 30,
    read_timeout: int = 60,
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
      deck: the deck to reflect the machine into. Optional: without one the driver still drives the
        machine, and nothing about where things are is modelled.
    """

    self.io: IOBase = io or USB(
      human_readable_device_name=f"Hamilton {'STAR'}",
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

    # Whether the link is open, and whether a full setup has run behind it. Commands gate on the
    # link: they flow during setup, long before setup is done.
    self._connected = False
    self._setup_done = False

    self.left_side_panel_installed = left_side_panel_installed

    # The deck to reflect the machine into, or None to drive it without a resource model. With one,
    # setup builds a resource per capability as a child of it; without, nothing is modelled.
    self.deck = deck

    self.configuration: Optional[DeviceConfiguration] = None

    # What each capability reported at discovery, keyed as `confirmed_firmware_versions` keys it.
    self.firmware: Dict[str, str] = {}

    # Subsystems. Each reads what it needs off `configuration`, so they are usable once setup has
    # run and raise a clear error before that. Each arm appears only if setup finds one installed.
    self.pipettes: Optional[Pipettes] = None
    self.front_cover: Optional[FrontCover] = None
    self.left_x_arm: Optional[XArm] = None
    self.right_x_arm: Optional[XArm] = None
    self.head96: Optional[Head96] = None
    self.iswap: Optional[iSWAP] = None
    self.autoload: Optional[Autoload] = None

  # -- connection ------------------------------------------------------------

  async def setup(self):
    """Connect to the machine, find out what it is, and bring it up.

    This moves the instrument: everything that can be initialized is. `discover` on its own is
    the read-only half, for connecting and inspecting without anything moving.

    Safe to call again: discovery re-reads the machine and initialization is a no-op on a machine
    that is already up. A setup that fails part way closes the link rather than leaving a claimed
    device and a reader behind.
    """
    logger.debug("Setting up STAR on %s ...", self._describe_link())
    await self._open()
    self._connected = True

    try:
      # 1. What is on the other end, and what does it carry?
      logger.debug("[PHASE 1] Discovery")
      await self.discover()

      # 2. Bring the instrument to a known state.
      logger.debug("[PHASE 2] Instrument initialization")
      already_initialized = await self.initialize()

      # 3. Each capability brings itself up. They sit on different modules, so they run together;
      #    the autoload, iSWAP and 96-head join this gather as they land. The channels only need
      #    it when the instrument procedure did not just run, or when something is still mounted.
      logger.debug("[PHASE 3] Capability bring-up")
      bring_up = [self._bring_up_arm(already_initialized)]
      if self.autoload is not None:
        bring_up.append(self.autoload.initialize())
      await asyncio.gather(*bring_up)

      # 4. What was found, as resources on the deck - when the driver was given one to reflect
      #    into. Each is a child of the deck, so a machine with a deck carries one tree.
      if self.deck is not None:
        logger.debug("[PHASE 4] Capability resources")
        await self._create_x_arm_resources()

    except BaseException:
      await self.stop()
      raise

    self._setup_done = True
    logger.info("%s", self.format_setup_summary())

  async def _open(self):
    """Open the link and start reading replies."""
    await self.io.setup()
    self._replies.start()

  async def _close(self):
    """Stop reading replies and close the link."""
    self._replies.stop()
    await self.io.stop()

  async def discover(self):
    """Read what machine is on the other end, and build the subsystems it turns out to have.

    Read-only: nothing moves. Call `initialize` to bring the machine up.
    """
    self.configuration = await self.request_device_configuration()
    self._num_channels = len(await self.request_tip_presence())

    # Built for what the machine turns out to have, and only if not already there: a caller can
    # hand a capability its configuration before setup, and re-running setup keeps it.
    if self.configuration.left_arm is not None and self.left_x_arm is None:
      self.left_x_arm = XArm(self, side="left")
    if self.configuration.right_arm is not None and self.right_x_arm is None:
      self.right_x_arm = XArm(self, side="right")
    if self.configuration.num_pip_channels > 0 and self.pipettes is None:
      self.pipettes = Pipettes(self)
    if self.configuration.ka_head96_installed and self.head96 is None:
      self.head96 = Head96(self)
    if (
      self.configuration.left_arm is not None
      and self.configuration.left_arm.iswap_installed
      and self.iswap is None
    ):
      self.iswap = iSWAP(self)
    if self.configuration.autoload_installed and self.autoload is None:
      self.autoload = Autoload(self)
    if self.configuration.main_front_cover_monitoring_installed and self.front_cover is None:
      self.front_cover = FrontCover(self)

    # Each capability reads its own modules, and they are different modules, so they read at
    # once. Both arms run off the same X-drive board, so only one of them asks it.
    arms = [arm for arm in (self.left_x_arm, self.right_x_arm) if arm is not None]
    reading = []
    if self.pipettes is not None:
      reading.append(self.pipettes.discover())
    if arms:
      reading.append(arms[0].discover())
    if self.head96 is not None:
      reading.append(self.head96.discover())
    if self.iswap is not None:
      reading.append(self.iswap.discover())
    if self.autoload is not None:
      reading.append(self.autoload.discover())
    await asyncio.gather(*reading)
    for arm in arms[1:]:
      arm.configuration.firmware_version = arms[0].configuration.firmware_version

    master_version, _ = await self.request_firmware_version()
    reported = {
      "master": master_version,
      "pipettes": (
        None if self.pipettes is None else self.pipettes.configuration.channels[0].firmware_version
      ),
      "x_arm": None if not arms else arms[0].configuration.firmware_version,
      "head96": None if self.head96 is None else self.head96.configuration.firmware_version,
      "iswap": None if self.iswap is None else self.iswap.configuration.firmware_version,
      "autoload": None if self.autoload is None else self.autoload.configuration.firmware_version,
    }
    self.firmware = {name: v for name, v in reported.items() if v is not None}

  async def initialize(self, force: bool = False) -> bool:
    """Bring the instrument itself to a known state.

    This moves it. An uninitialized machine runs its initialization procedure, which homes every
    drive and leaves the channels at Z safety. A machine that is already initialized is left where
    it is, apart from raising the channels to Z safety, which the procedure would otherwise have
    guaranteed - nothing may move laterally while a channel is low.

    This is the instrument-level step only. `setup` is what brings up the capabilities behind it.

    Args:
      force: run the initialization procedure even if the machine reports itself initialized.

    Returns:
      Whether the machine reported itself already initialized before this ran.
    """
    already_initialized = await self.request_initialization_status()

    if force or not already_initialized:
      logger.debug(
        "machine reports %s - running the initialization procedure (up to %d s)",
        "initialized, but the run was forced" if already_initialized else "not initialized",
        PRE_INITIALIZE_READ_TIMEOUT,
      )
      await self.pre_initialize()
    else:
      logger.debug("machine reports initialized - raising the channels to Z safety only")
      if self.pipettes is not None:
        await self.pipettes.move_to_z_safety()
      # The head is retracted whatever its own status says: the retract is what keeps it clear of
      # the iSWAP, which shares the left X-drive and moves during capability bring-up.
      if self.head96 is not None:
        self.head96.resolve_z_range(await self.head96.move_to_z_safety())

    return already_initialized

  def _describe_link(self) -> str:
    """How this machine is reached, in whatever terms its transport is addressed by."""
    fields = self.io.serialize()
    link = type(self.io).__name__
    vendor, product = fields.get("id_vendor"), fields.get("id_product")
    if vendor is not None and product is not None:
      link += f" {vendor:#06x}:{product:#06x}"
    named = [
      f"{label} {fields[key]}"
      for label, key in (
        ("address", "device_address"),
        ("serial", "serial_number"),
        ("port", "port"),
      )
      if fields.get(key)
    ]
    return link + (f" ({', '.join(named)})" if named else "")

  def format_setup_summary(self) -> str:
    """One block describing the machine that was found: how it is reached, what firmware every
    module runs, whether an autoload is fitted, how many arms there are, and per arm its
    dimensions, how many channels it carries and whether it carries a 96-head, a 384-head and an
    iSWAP.

    Returns:
      A multi-line summary, or a note that setup has not run.
    """
    c = self.configuration
    if c is None:
      return "[Hamilton STAR] not discovered yet"

    firmware = (
      ", ".join(f"{name} {version}" for name, version in self.firmware.items()) or "unknown"
    )

    fitted = [f"{c.instrument_size_slots} slots"]
    for number, installed in ((1, c.wash_station_1_installed), (2, c.wash_station_2_installed)):
      if installed:
        fitted.append(f"wash station {number}")

    autoload = "none"
    if c.autoload_installed:
      autoload = "installed"
      if self.autoload is not None and self.autoload.configuration.autoload_type is not None:
        autoload = self.autoload.configuration.autoload_type

    arms = [arm for arm in (self.left_x_arm, self.right_x_arm) if arm is not None]
    lines = [
      f"[Hamilton STAR] Connected on {self._describe_link()}",
      f"  Firmware: {firmware}",
      f"  Configuration: {', '.join(fitted)}",
      f"  Autoload: {autoload}",
      f"  Arms: {len(arms)}",
    ]
    for arm in arms:
      a = arm.configuration
      # Read through the capability, not the arm's own bit, so the summary cannot report channels
      # the driver did not build. The two disagree only on a machine whose configuration says both.
      channels = "none"
      if self.pipettes is not None and a.pip_installed:
        channels = f"{c.num_pip_channels} ({'1000uL' if c.pip_type_1000ul else '300uL'})"
      elif self.pipettes is None and a.pip_installed:
        channels = "none, but this arm reports the module installed"
      head96 = "none"
      if a.head96_installed:
        head96 = "installed"
        if self.head96 is not None and self.head96.configuration.head_type is not None:
          head96 = self.head96.configuration.head_type
      iswap = "none"
      if a.iswap_installed:
        iswap = f"{'wide' if c.iswap_gripper_wide else 'small'} gripper"
      lines.append(
        f"    {arm.side}: {a.model}, {a.width} mm wide, "
        f"travel {_range(a.x_range)}, workspace {_range(a.workspace_range)}"
      )
      lines.append(
        f"      channels: {channels} | 96-head: {head96} | "
        f"384-head: {'installed' if a.dispensing_head_384_installed else 'none'} | "
        f"iSWAP: {iswap}"
      )
    if sum(arm.configuration.pip_installed for arm in arms) > 1:
      lines.append("      (the machine reports one channel count for the instrument, not per arm)")
    return "\n".join(lines)

  async def _bring_up_arm(self, already_initialized: bool):
    """Bring up everything the arm carries, one after another.

    The channels, the iSWAP and the 96-head share the arm's X drive, so bringing one up while
    another is moving is refused by the machine. They go in the order the legacy routine uses.

    Args:
      already_initialized: whether the instrument reported itself up before this setup ran.
    """
    if self.pipettes is None:
      logger.debug("channels: none installed - skipped")
    else:
      tips = await self.request_tip_presence()
      if not already_initialized or any(tips):
        logger.debug(
          "channels: %d of %d carrying tips, instrument %s - initializing",
          sum(tips),
          len(tips),
          "was already up" if already_initialized else "has just been homed",
        )
        await self.pipettes.initialize()
      else:
        logger.debug("channels: already up and nothing mounted - skipped")

    if self.iswap is not None:
      if not await self.request_initialization_status("R0"):
        logger.debug("iSWAP reports itself uninitialized - initializing")
        await self.iswap.initialize()
      await self.iswap.park()

    if self.head96 is not None:
      if not await self.request_initialization_status("H0"):
        if self.head96.configuration.initialize_position is None:
          logger.warning(
            "the 96-head reports itself uninitialized, and there is nowhere configured to eject "
            "at. Set head96.configuration.initialize_position, or call head96.initialize(x, y, z)."
          )
        else:
          logger.debug("96-head reports itself uninitialized - initializing")
          await self.head96.initialize()
      # Probing how far this head reaches retracts it, so it doubles as the safety retract and
      # runs on every setup rather than only the first.
      self.head96.resolve_z_range(await self.head96.move_to_z_safety())

  async def _create_x_arm_resources(self) -> None:
    """Put each installed arm on the deck, where it is.

    Read once, at setup: the arm reports where it came to rest, and its resource is seated there.
    An arm already on the deck is reused rather than replaced, so repeated setups do not duplicate
    it.
    """
    if self.deck is None:
      return
    for arm in (self.left_x_arm, self.right_x_arm):
      if arm is None:
        continue
      a = arm.configuration
      if a.width is None:
        logger.warning("the %s X-arm reported no width, so it is not modelled", arm.side)
        continue
      arm.resource = self.deck.get_or_create_x_arm(
        name=f"{arm.side}_x_arm",
        x=await arm.request_position(),
        width=a.width,
        model=a.model,
        reference_point=a.reference_point,
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
    """Close the link. The machine keeps its state; only this driver lets go of it."""
    self._setup_done = False
    self._connected = False
    await self._close()

  @property
  def connected(self) -> bool:
    """Whether the link is open, so commands can be sent."""
    return self._connected

  @property
  def setup_done(self) -> bool:
    """Whether a full setup has run: the machine discovered and initialized."""
    return self._setup_done

  @property
  def num_channels(self) -> int:
    """The number of pipette channels present on the robot."""
    if self._num_channels is None:
      raise RuntimeError("channel count not read; have you called `star.setup()`?")
    return self._num_channels

  @property
  def x_arm(self) -> XArm:
    """The machine's X-arm, on a machine that has only one.

    Most STARs carry a single arm, and naming a side there is noise. A machine with two has no
    single X-arm, so this refuses rather than picking one.

    Raises:
      RuntimeError: If setup has not run, so it is not yet known which arms are installed.
      ValueError: If the machine has no arm, or more than one.
    """
    if self.configuration is None:
      raise RuntimeError("no configuration read; have you called `star.setup()`?")
    installed = {
      name: arm
      for name, arm in (("left_x_arm", self.left_x_arm), ("right_x_arm", self.right_x_arm))
      if arm is not None
    }
    if not installed:
      raise ValueError("this machine reports no X-arm installed.")
    if len(installed) > 1:
      raise ValueError(
        f"this machine has {len(installed)} X-arms ({', '.join(installed)}), so `x_arm` is "
        f"ambiguous. Use the one you mean by name."
      )
    return next(iter(installed.values()))

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
    """Assemble a firmware command, send it, and parse the reply if a format is given.

    Raises:
      RuntimeError: If the link is not open.
    """
    self._require_connection()
    id_ = self._replies.next_id() if auto_id else None
    cmd = assemble_command(
      module=module,
      command=command,
      id_=id_,
      tip_pattern=tip_pattern,
      num_channels=self._num_channels,
      **kwargs,
    )
    event_data = {
      "transport": "hamilton_usb",
      "driver": type(self).__name__,
      "module": module,
      "command": command,
      "command_id": id_,
      "raw_command": cmd,
    }
    emit_event("firmware.command.started", **event_data)
    try:
      resp = await self._replies.send(
        cmd=cmd,
        id_=id_,
        write_timeout=write_timeout,
        read_timeout=read_timeout,
        wait=wait,
      )
      result = self._parse_response(resp, fmt) if resp is not None and fmt is not None else resp
    except BaseException as error:
      emit_event(
        "firmware.command.failed",
        **event_data,
        error_type=type(error).__name__,
        error_message=str(error),
      )
      raise
    emit_event("firmware.command.completed", **event_data, response=resp)
    return result

  async def send_raw_command(
    self,
    command: str,
    write_timeout: Optional[int] = None,
    read_timeout: Optional[int] = None,
    wait: bool = True,
  ) -> Optional[str]:
    """Send a raw command to the machine.

    Raises:
      RuntimeError: If the link is not open.
    """
    self._require_connection()
    return await self._replies.send_raw(
      command=command,
      write_timeout=write_timeout,
      read_timeout=read_timeout,
      wait=wait,
    )

  def _require_connection(self) -> None:
    """Raise unless the link is open, so a command cannot be sent into nothing."""
    if not self._connected:
      raise RuntimeError("not connected to a machine; call `setup` first")

  # -- device queries --------------------------------------------------------

  async def request_firmware_version(self) -> Tuple[str, datetime.date]:
    """Request the master's firmware version and build date.

    Returns:
      The version string and its build date, e.g. `("7.6S", date(2021, 11, 5))`.
    """
    resp = await self.send_command(module="C0", command="RF")
    return resp.split("rf")[-1], parse_firmware_version_date(resp)

  async def request_tip_presence(self) -> List[bool]:
    """Measure tip presence on all single channels using their sleeve sensors.

    Returns:
      A list of length `num_channels`, `True` where a tip is mounted.
    """
    resp = await self.send_command(module="C0", command="RT", fmt="rt# (n)")
    return [bool(v) for v in cast(List[int], resp.get("rt"))]

  async def request_cover_input_status(self) -> Tuple[bool, bool, bool]:
    """Request the three inputs on the cover connector.

    On the master rather than on `front_cover`, because it is the one cover read that stays
    reachable on a machine whose configuration says the cover monitoring is not installed - and
    that machine is exactly the one worth asking.

    Returns:
      Whether each is set: the cover input, the second input - a reserve or the additional cover
      control, depending on the board - and a second reserve. What a set cover input means is not
      stated; `front_cover.request_position` is the one that says open or shut.

    Raises:
      ValueError: If the machine answered with fewer than three inputs.
    """
    resp = await self.send_command(module="C0", command="RW")
    read = resp.split("rw", 1)[-1].strip().strip("'")
    if len(read) < 3:
      raise ValueError(f"expected three inputs in the reply: {resp!r}")
    return read[0] == "1", read[1] == "1", read[2] == "1"

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
      left_arm=_resolve_arm(extended["xl"], extended["xn"], "left", extended["xu"] / 10),
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
