"""A STAR that answers without being plugged in.

Each capability has a small subclass here that overrides the handful of methods which would
otherwise talk to a machine, returning what one would have said. `STARSimulationDriver` swaps
those in, so everything above them - discovery, the bring-up order, the configuration each
capability resolves - runs exactly as it does against hardware.

Nothing reaches the wire. `send_command` raises, which is how a command that has not been
simulated makes itself known: override the method that sends it, on the capability that owns it.
"""

import datetime
import logging
from typing import Any, Dict, List, Optional, Tuple, cast

from pylabrobot.hamilton.protocol.text.framing import parse_firmware_version_date
from pylabrobot.hamilton.star.driver.configuration import DeviceConfiguration
from pylabrobot.hamilton.star.driver.features.autoload import Autoload, AutoloadConfiguration
from pylabrobot.hamilton.star.driver.features.cover import CoverPosition, FrontCover
from pylabrobot.hamilton.star.driver.features.head96 import Head96, HeadType
from pylabrobot.hamilton.star.driver.features.iswap import iSWAP
from pylabrobot.hamilton.star.driver.features.pipettes import PipetteConfiguration, Pipettes
from pylabrobot.hamilton.star.driver.features.x_arm import XArm, XArmConfiguration
from pylabrobot.hamilton.star.driver.master import STARDriver
from pylabrobot.io.io import IOBase
from pylabrobot.io.validation_utils import LOG_LEVEL_IO
from pylabrobot.resources.hamilton.hamilton_decks import HamiltonDeck

logger = logging.getLogger(__name__)

# What each capability reports for its firmware. Read off a real instrument, so a simulated run
# resolves to a machine that exists.
SIMULATED_FIRMWARE = {
  "master": "7.6S 25 2021_11_05 (GRU C0)",
  "pipettes": "4.0S j 2022-03-16",
  "x_arm": "1.4S 2012-04-25",
  "head96": "5.0S i 2021-10-22 (H0 XE167)",
  "iswap": "4.1S 2011-12-19",
}

# Made up, so a simulator is never mistaken for a particular machine.
SIMULATED_SERIAL_NUMBER = "SIM0"

# How wide a pipette is, in mm.
PIPETTE_WIDTH = 8.98

# What each pipetting channel is: an ML_STAR channel on an ML_STAR head, with a CoRe II stop disc
# and a Renesas pressure ADC.
SIMULATED_PIPETTE = PipetteConfiguration(
  channel_type="ML_STAR",
  head_type="ML_STAR",
  stop_disc_type="core_ii",
  pressure_adc="Renesas_X9268",
)

# The 96-head: what it is, what it reports about itself, where its channel A1 sits relative to the
# arm carriage, the Z it rests at, and what its drives are set to. Distances in mm.
SIMULATED_HEAD96_TYPE: HeadType = "96 head II"
SIMULATED_HEAD96_HARDWARE = ["0", "1", "0", "0", "0", "0", "0", "0", "0", "0"]
SIMULATED_HEAD96_X_OFFSET = 368.2
SIMULATED_HEAD96_Z_SAFETY = 336.97
SIMULATED_HEAD96_DRIVE_PARAMETERS = {"yv": 390.62, "yr": 546.88, "zv": 85.0, "zr": 400.0}

# The autoload this machine has. Its device facts are the defaults; what it answers about itself is
# here, and discovery reads it as it would off a real one.
SIMULATED_AUTOLOAD = AutoloadConfiguration(
  firmware_version="3.4S f 2017-01-09",
  autoload_type="1D barcode scanner",
)

# Where its three drives report themselves, in mm. Where they actually are is not modelled: each
# answers from its zero.
SIMULATED_AUTOLOAD_X_POSITION = 0.0
SIMULATED_AUTOLOAD_Y_POSITION = 0.0
SIMULATED_AUTOLOAD_Z_POSITION = 0.0

# Whether the front cover is shut. A simulated machine is not being reached into.
SIMULATED_COVER_POSITION: CoverPosition = "closed"

# The three inputs on the cover connector: the cover input, and two whose meaning is not known.
SIMULATED_COVER_INPUTS = (True, False, False)

# What its scanner reads. A simulated deck holds no carriers, so nothing.
SIMULATED_BARCODE: Optional[str] = None

# The iSWAP's stored position tables, and where its rotation drive sits relative to the carriage.
SIMULATED_ISWAP_TABLES = {
  "pw": [13000, -29007, 156, 29068, 29500, 29068, 29068, 29068, 29068, 1378],
  "pt": [-26577, -26577, -8860, 9044, 26858, -26577, -26577, -26577, -26577, 1377],
  "py": [9855, 7000, 9000, 13550, 12600, 9855, 9855, 9855, 9855, 9855],
}
SIMULATED_ISWAP_X_OFFSET = 32.8

# What a bare STARSimulationDriver() pretends to be, copied field for field off a real instrument:
# a full-size STAR, 54 slots wide, with eight 1000uL channels, a wide-gripper iSWAP and a 96-head
# on a dual-rail left arm, autoload fitted, no right arm. A STARlet would be the same at 30 slots.
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
  """Stands where the transport would be. Nothing should reach it."""

  async def setup(self, *args, **kwargs):
    pass

  async def stop(self):
    pass

  async def write(self, data: bytes, *args, **kwargs):
    raise RuntimeError(f"the simulator tried to write to a transport: {data!r}")

  async def read(self, *args, **kwargs) -> bytes:
    raise RuntimeError("the simulator tried to read from a transport")


class _Simulated:
  """Reaches the machine behind a capability, which for a simulated one is the simulator."""

  _driver: STARDriver

  @property
  def machine(self) -> "STARSimulationDriver":
    return cast("STARSimulationDriver", self._driver)


class SimulatedPipettes(_Simulated, Pipettes):
  """The pipetting channels, answering for themselves."""

  async def request_firmware_version(self, channel: int) -> Tuple[str, datetime.date]:
    return self.machine.reported("pipettes")

  async def request_min_pipette_width(self, channel: int) -> float:
    return PIPETTE_WIDTH

  async def request_pipette_configuration(self, channel: int) -> PipetteConfiguration:
    return PipetteConfiguration(
      channel_type=SIMULATED_PIPETTE.channel_type,
      head_type=SIMULATED_PIPETTE.head_type,
      stop_disc_type=SIMULATED_PIPETTE.stop_disc_type,
      pressure_adc=SIMULATED_PIPETTE.pressure_adc,
    )

  async def initialize(self, *args, **kwargs):
    """Whatever was mounted on the channels comes off."""
    self.machine.tips_mounted = [False] * len(self.machine.tips_mounted)


# Where the left arm reports itself at rest, in mm: far enough along the rail to sit within reach
# of any STAR deck. The right arm rests at the far end of its own travel instead, so the two do
# not overlap on a machine that has both.
SIMULATED_LEFT_X_ARM_POSITION = 362.9


class SimulatedXArm(_Simulated, XArm):
  """An X-arm, answering for itself."""

  async def request_firmware_version(self) -> Tuple[str, datetime.date]:
    return self.machine.reported("x_arm")

  async def request_position(self) -> float:
    # With a deck, where the arm is is what the model says, so a simulated run answers the way a
    # real one does rather than from a remembered value. Without one, it reports where it rests.
    if self.resource is not None and self.resource.location is not None:
      anchor = self.resource.get_anchor(x=self.reference_anchor)
      return self.resource.location.x + anchor.x
    if self.side == "left" or self.configuration.x_range is None:
      return SIMULATED_LEFT_X_ARM_POSITION
    return self.configuration.x_range[1]


class SimulatedHead96(_Simulated, Head96):
  """The 96-head, answering for itself."""

  async def request_firmware_version(self) -> Tuple[str, datetime.date]:
    return self.machine.reported("head96")

  async def request_hardware(self) -> List[str]:
    return list(SIMULATED_HEAD96_HARDWARE)

  async def request_head_type(self) -> HeadType:
    return SIMULATED_HEAD96_TYPE

  async def request_x_offset(self) -> float:
    return SIMULATED_HEAD96_X_OFFSET

  async def request_stop_disk_z(self) -> float:
    return SIMULATED_HEAD96_Z_SAFETY

  async def request_drive_parameter(self, parameter: str) -> float:
    return SIMULATED_HEAD96_DRIVE_PARAMETERS[parameter]

  async def initialize(self, *args, **kwargs):
    """Whatever was mounted on the head comes off, and it reports itself up."""
    self.machine.initialized["H0"] = True


class SimulatedISWAP(_Simulated, iSWAP):
  """The iSWAP, answering for itself."""

  async def request_firmware_version(self) -> str:
    return self.machine.simulated_firmware["iswap"]

  async def request_rotation_drive_x_offset(self) -> float:
    return SIMULATED_ISWAP_X_OFFSET

  async def _request_slots(self, table: str) -> List[int]:
    return list(SIMULATED_ISWAP_TABLES[table])

  async def initialize(self):
    self.machine.initialized["R0"] = True


class SimulatedFrontCover(_Simulated, FrontCover):
  """The front cover, answering for itself: it is shut."""

  async def request_position(self) -> CoverPosition:
    return SIMULATED_COVER_POSITION


class SimulatedAutoload(_Simulated, Autoload):
  """The autoload, answering for itself. Its deck and its loading tray are empty."""

  track = 1
  """Where it last moved to."""

  async def request_firmware_version(self) -> str:
    version = self.machine.simulated_autoload.firmware_version
    if version is None:
      raise RuntimeError(
        "the simulated autoload has no firmware version; set it on its configuration"
      )
    return version

  async def request_autoload_type(self) -> str:
    autoload_type = self.machine.simulated_autoload.autoload_type
    if autoload_type is None:
      raise RuntimeError("the simulated autoload has no type; set it on its configuration")
    return autoload_type

  async def request_initialization_status(self) -> bool:
    return self.machine.initialized["I0"]

  async def request_latest_barcode_read(self) -> Optional[str]:
    return SIMULATED_BARCODE

  async def request_track(self) -> int:
    return self.track

  async def request_x_position(self) -> float:
    return SIMULATED_AUTOLOAD_X_POSITION

  async def request_y_position(self) -> float:
    return SIMULATED_AUTOLOAD_Y_POSITION

  async def request_z_position(self) -> float:
    return SIMULATED_AUTOLOAD_Z_POSITION

  async def sense_carrier_presence_on_deck(self) -> List[int]:
    return []

  async def sense_carrier_presence_on_loading_tray(self) -> List[int]:
    return []

  async def sense_carrier_presence_on_single_loading_tray_track(
    self, track: int, park_after: bool = True
  ) -> bool:
    return False

  async def load_carrier_from_tray_and_scan_carrier_barcode(
    self, track: int, *args, **kwargs
  ) -> Optional[str]:
    return SIMULATED_BARCODE

  async def load_carrier_from_autoload_belt(
    self, barcode_reading: bool = False, *args, **kwargs
  ) -> Dict[int, Optional[str]]:
    """The containers read nothing, and there are as many as were asked for."""
    if not barcode_reading:
      return {}
    containers = kwargs.get("containers_per_carrier", 5)
    return {position: SIMULATED_BARCODE for position in range(containers)}

  async def initialize(self, park_after: bool = True):
    await super().initialize(park_after=park_after)
    self.machine.initialized["I0"] = True

  async def move_to_track(self, track: int, *args, **kwargs):
    await super().move_to_track(track, *args, **kwargs)
    self.track = track

  async def park(self):
    await super().park()
    self.track = self.track_range[-1]


class STARSimulationDriver(STARDriver):
  """A simulated STAR, driven exactly like the real one."""

  def __init__(
    self,
    configuration: Optional[DeviceConfiguration] = None,
    tips_mounted: Optional[List[bool]] = None,
    firmware: Optional[Dict[str, str]] = None,
    autoload: Optional[AutoloadConfiguration] = None,
    deck: Optional[HamiltonDeck] = None,
    serial_number: str = SIMULATED_SERIAL_NUMBER,
    initialized: bool = False,
  ):
    """
    Args:
      configuration: the instrument to pretend to be. Defaults to `DEFAULT_STAR_CONFIGURATION`.
      tips_mounted: one entry per channel, `True` where a tip sits on the channel. Defaults to no
        tips on any of them.
      firmware: what each capability reports, keyed as `confirmed_firmware_versions` keys it.
        Defaults to `SIMULATED_FIRMWARE`.
      autoload: the autoload this machine has, which it answers about itself. Defaults to
        `SIMULATED_AUTOLOAD`. The capability's own configuration is filled by discovery, as on a
        real machine, so this is what it reads rather than what it becomes.
      deck: the deck to reflect this machine into, as on a real one.
      serial_number: what this machine calls itself.
      initialized: whether the machine and its modules report themselves already initialized. One
        that has just been switched on does not.

    Raises:
      ValueError: If `tips_mounted` does not have one entry per channel.
    """
    super().__init__(io=_UnusedTransport(), deck=deck)

    self.simulated_configuration = configuration or DEFAULT_STAR_CONFIGURATION
    self.simulated_firmware = firmware or dict(SIMULATED_FIRMWARE)
    self.simulated_autoload = autoload or SIMULATED_AUTOLOAD
    self.serial_number = serial_number

    channels = self.simulated_configuration.num_pip_channels
    if tips_mounted is None:
      tips_mounted = [False] * channels
    if len(tips_mounted) != channels:
      raise ValueError(f"tips_mounted has {len(tips_mounted)} entries, expected {channels}")
    self.tips_mounted = list(tips_mounted)

    # What each module says when asked whether it is initialized, and where things are.
    self.initialized = {module: initialized for module in ("C0", "I0", "R0", "H0")}

    # The capabilities this machine has, each answering for itself. Discovery builds only the ones
    # that are not already there, so these stand in for the real ones throughout.
    c = self.simulated_configuration
    if c.num_pip_channels > 0:
      self.pipettes = SimulatedPipettes(self)
    if c.main_front_cover_monitoring_installed:
      self.front_cover = SimulatedFrontCover(self)
    if c.left_arm is not None:
      self.left_x_arm = SimulatedXArm(self, side="left")
    if c.right_arm is not None:
      self.right_x_arm = SimulatedXArm(self, side="right")
    if c.ka_head96_installed:
      self.head96 = SimulatedHead96(self)
    if c.left_arm is not None and c.left_arm.iswap_installed:
      self.iswap = SimulatedISWAP(self)
    if c.autoload_installed:
      self.autoload = SimulatedAutoload(self)

  def reported(self, capability: str) -> Tuple[str, datetime.date]:
    """What a capability reports for its firmware, and the date in it."""
    version = self.simulated_firmware[capability]
    return version, parse_firmware_version_date(version)

  # -- the machine itself ----------------------------------------------------

  async def _open(self):
    """There is no link to open, and no replies to read."""

  async def _close(self):
    pass

  async def request_device_configuration(self) -> DeviceConfiguration:
    return self.simulated_configuration

  async def request_cover_input_status(self) -> Tuple[bool, bool, bool]:
    return SIMULATED_COVER_INPUTS

  async def request_tip_presence(self) -> List[bool]:
    return list(self.tips_mounted)

  async def request_firmware_version(self) -> Tuple[str, datetime.date]:
    return self.reported("master")

  async def request_initialization_status(self, module: str = "C0") -> bool:
    return self.initialized.get(module, False)

  async def pre_initialize(self):
    """Home every drive. The modules it de-initializes then need their own."""
    self.initialized["C0"] = True

  def _describe_link(self) -> str:
    return "simulation (no link)"

  async def send_command(self, module: str, command: str, *args: Any, **kwargs: Any) -> None:
    """Say what would have been sent, and answer nothing.

    A command that only moves needs no more than this. One whose answer is read is overridden on
    the capability that reads it, so it never gets here.
    """
    logger.log(LOG_LEVEL_IO, "%s %s %s", module, command, kwargs or "")
    return None

  async def send_raw_command(self, command: str, *args: Any, **kwargs: Any) -> None:
    logger.log(LOG_LEVEL_IO, "%s", command)
    return None
