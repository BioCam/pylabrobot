import copy
import datetime
import logging
import re
import warnings

from pylabrobot.io.validation_utils import LOG_LEVEL_IO
from contextlib import asynccontextmanager
from typing import Dict, List, Literal, Optional, Union

from pylabrobot.liquid_handling.backends import LiquidHandlerBackend
from pylabrobot.liquid_handling.backends.hamilton.STAR_backend import (
  DriveConfiguration,
  ExtendedConfiguration,
  Head96Information,
  MachineConfiguration,
  STARBackend,
)
from pylabrobot.resources import Carrier, Container, Coordinate
from pylabrobot.resources.well import Well

logger = logging.getLogger("pylabrobot")

_DEFAULT_MACHINE_CONFIGURATION = MachineConfiguration(
  pip_type_1000ul=True,
  kb_iswap_installed=True,
  auto_load_installed=True,
  num_pip_channels=8,
)

_DEFAULT_EXTENDED_CONFIGURATION = ExtendedConfiguration(
  left_x_drive_large=True,
  iswap_gripper_wide=True,
  instrument_size_slots=30,
  auto_load_size_slots=30,
  tip_waste_x_position=800.0,
  left_x_drive=DriveConfiguration(iswap_installed=True, core_96_head_installed=True),
  min_iswap_collision_free_position=350.0,
  max_iswap_collision_free_position=600.0,
)


class STARChatterboxBackend(STARBackend):
  """Chatterbox backend for 'STAR'"""

  def __init__(
    self,
    num_channels: int = 8,
    machine_configuration: MachineConfiguration = _DEFAULT_MACHINE_CONFIGURATION,
    extended_configuration: ExtendedConfiguration = _DEFAULT_EXTENDED_CONFIGURATION,
    channels_minimum_y_spacing: Optional[List[float]] = None,
    # deprecated parameters
    core96_head_installed: Optional[bool] = None,
    iswap_installed: Optional[bool] = None,
  ):
    """Initialize a chatter box backend.

    Args:
      num_channels: Number of pipetting channels (default: 8)
      machine_configuration: Machine configuration to return from `request_machine_configuration`.
      extended_configuration: Extended configuration to return from `request_extended_configuration`.
      channels_minimum_y_spacing: Per-channel minimum Y spacing in mm. If None, defaults to
        `extended_configuration.min_raster_pitch_pip_channels` for all channels.
      core96_head_installed: Deprecated. Set `extended_configuration.left_x_drive
        .core_96_head_installed` instead.
      iswap_installed: Deprecated. Set `extended_configuration.left_x_drive
        .iswap_installed` instead.
    """
    super().__init__()
    self._num_channels = num_channels
    self._iswap_parked = True

    if core96_head_installed is not None or iswap_installed is not None:
      extended_configuration = copy.deepcopy(extended_configuration)
      xl = copy.deepcopy(extended_configuration.left_x_drive)
      if core96_head_installed is not None:
        warnings.warn(
          "core96_head_installed is deprecated. Pass an ExtendedConfiguration with "
          "left_x_drive.core_96_head_installed set instead.",
          DeprecationWarning,
          stacklevel=2,
        )
        xl.core_96_head_installed = core96_head_installed
      if iswap_installed is not None:
        warnings.warn(
          "iswap_installed is deprecated. Pass an ExtendedConfiguration with "
          "left_x_drive.iswap_installed set instead.",
          DeprecationWarning,
          stacklevel=2,
        )
        xl.iswap_installed = iswap_installed
      extended_configuration.left_x_drive = xl

    self._machine_configuration = machine_configuration
    self._extended_conf = extended_configuration

    if channels_minimum_y_spacing is not None:
      if len(channels_minimum_y_spacing) != num_channels:
        raise ValueError(
          f"channels_minimum_y_spacing has {len(channels_minimum_y_spacing)} entries, "
          f"expected {num_channels}."
        )
      self._channels_minimum_y_spacing = list(channels_minimum_y_spacing)
    else:
      self._channels_minimum_y_spacing = [
        extended_configuration.min_raster_pitch_pip_channels
      ] * num_channels

  async def setup(
    self,
    skip_instrument_initialization=False,
    skip_pip=False,
    skip_autoload=False,
    skip_iswap=False,
    skip_core96_head=False,
  ):
    """Initialize the chatterbox backend and detect installed modules.

    Args:
      skip_instrument_initialization: If True, skip instrument initialization.
      skip_pip: If True, skip pipetting channel initialization.
      skip_autoload: If True, skip initializing the autoload module, if applicable.
      skip_iswap: If True, skip initializing the iSWAP module, if applicable.
      skip_core96_head: If True, skip initializing the CoRe 96 head module, if applicable.
    """
    await LiquidHandlerBackend.setup(self)

    self.id_ = 0

    # Request machine information
    self._machine_conf = await self.request_machine_configuration()
    self._extended_conf = await self.request_extended_configuration()

    # Mock firmware information for 96-head if installed
    if self.extended_conf.left_x_drive.core_96_head_installed and not skip_core96_head:
      self._head96_information = Head96Information(
        fw_version=datetime.date(2023, 1, 1),
        supports_clot_monitoring_clld=False,
        stop_disc_type="core_ii",
        instrument_type="FM-STAR",
        head_type="96 head II",
      )
    else:
      self._head96_information = None

  async def stop(self):
    await LiquidHandlerBackend.stop(self)
    self._setup_done = False

  # # # # # # # # Simulated values # # # # # # # #

  _SENTINEL = object()

  @asynccontextmanager
  async def simulated_values(self, **overrides):
    """Temporarily override method return values for simulation.

    Within the block, each overridden method still runs its body (assembling
    and logging firmware commands) but returns the declared value instead of
    the parsed response.  On exit, the original methods are restored.

    Usage::

        async with star.simulated_values(head96_request_tip_presence=0):
            q = await star.head96_request_tip_presence()  # returns 0
    """
    saved = {}
    for name, value in overrides.items():
        saved[name] = self.__dict__.get(name, self._SENTINEL)

        # Walk the MRO to find the real method (class-level, not instance-level)
        real_method = None
        for cls in type(self).__mro__:
            if name in cls.__dict__:
                real_method = cls.__dict__[name]
                break
        if real_method is None:
            raise AttributeError(f"{type(self).__name__} has no method {name!r}")

        async def _wrapper(*args, _orig=real_method, _val=value, **kwargs):
            try:
                await _orig(self, *args, **kwargs)
            except Exception:
                pass
            return _val

        self.__dict__[name] = _wrapper
    try:
        yield
    finally:
        for name, orig in saved.items():
            if orig is self._SENTINEL:
                self.__dict__.pop(name, None)
            else:
                self.__dict__[name] = orig

  # # # # # # # # Low-level command sending/receiving # # # # # # # #

  async def _write_and_read_command(
    self,
    id_: Optional[int],
    cmd: str,
    write_timeout: Optional[int] = None,
    read_timeout: Optional[int] = None,
    wait: bool = True,
  ) -> Optional[str]:
    logger.log(LOG_LEVEL_IO, "write: %s", cmd)
    prefix = cmd[:4]
    id_str = f"id{id_:04d}" if id_ is not None else "id0000"
    resp = f"{prefix}{id_str} er00/00"
    logger.log(LOG_LEVEL_IO, "read: %s", resp)
    return resp

  def _parse_response(self, resp: str, fmt: str) -> dict:
    """Return zeroed defaults derived from the format string.

    Instead of parsing the mock response (which has no real parameter data),
    we extract parameter names and types from ``fmt`` and return zero/empty
    values for each.  This allows every ``send_command(..., fmt=...)`` call
    to succeed in simulation without per-method overrides.
    """
    info: dict = {}

    # Split fmt into parameter tokens using the same logic as parse_star_fw_string.
    params: list[str] = []
    current = ""
    prevchar = None
    for char in fmt:
      if char.islower() and prevchar != "(":
        if len(current) > 2:
          params.append(current)
          current = ""
      current += char
      prevchar = char
    if current:
      params.append(current)

    for param in params:
      name, data = param[:2], param[2:]
      if not data:
        continue
      is_list = param.endswith(" (n)")
      type_char = data[0]
      if type_char == "#":
        info[name] = [0] if is_list else 0
      elif type_char == "*":
        info[name] = [0] if is_list else 0
      elif type_char == "&":
        length = len(data.split(" ")[0])
        info[name] = ["\x00" * length] if is_list else "\x00" * length

    # Always include id
    if "id" not in info:
      id_match = re.search(r"id(\d+)", resp)
      info["id"] = int(id_match.group(1)) if id_match else 0

    return info

  async def send_raw_command(
    self,
    command: str,
    write_timeout: Optional[int] = None,
    read_timeout: Optional[int] = None,
    wait: bool = True,
  ) -> Optional[str]:
    logger.log(LOG_LEVEL_IO, "write: %s", command)
    return None

  # # # # # # # # STAR configuration # # # # # # # #

  async def request_machine_configuration(self) -> MachineConfiguration:
    return self._machine_configuration

  async def request_extended_configuration(self) -> ExtendedConfiguration:
    assert self._extended_conf is not None
    return self._extended_conf

  # # # # # # # # 1_000 uL Channel: Basic Commands # # # # # # # #

  async def request_tip_presence(self) -> List[Optional[bool]]:
    """Return mock tip presence based on the tip tracker state.

    Returns:
      A list of length `num_channels` where each element is `True` if a tip is mounted,
      `False` if not, or `None` if unknown.
    """
    return [self.head[ch].has_tip for ch in range(self.num_channels)]

  async def channel_request_y_minimum_spacing(self, channel_idx: int) -> float:
    """Return mock minimum Y spacing for the given channel.

    Returns the value stored in ``_channels_minimum_y_spacing`` (set during
    ``__init__()``) without issuing any hardware commands.
    """
    if not 0 <= channel_idx <= self.num_channels - 1:
      raise ValueError(
        f"channel_idx must be between 0 and {self.num_channels - 1}, got {channel_idx}."
      )
    return self._channels_minimum_y_spacing[channel_idx]

  async def move_channel_y(self, channel: int, y: float):
    logger.info("moving channel %d to y: %s", channel, y)

  async def move_channel_x(self, channel: int, x: float):
    logger.info("moving channel %d to x: %s", channel, x)

  async def move_all_channels_in_z_safety(self):
    logger.info("moving all channels to z safety")

  async def position_channels_in_z_direction(self, zs: Dict[int, float]):
    logger.info("positioning channels in z: %s", zs)

  # # # # # # # # 1_000 uL Channel: Complex Commands # # # # # # # #

  async def step_off_foil(
    self,
    wells: Union[Well, List[Well]],
    front_channel: int,
    back_channel: int,
    move_inwards: float = 2,
    move_height: float = 15,
  ):
    logger.info(
      "stepping off foil | wells: %s | front channel: %s | "
      "back channel: %s | move inwards: %s | move height: %s",
      wells, front_channel, back_channel, move_inwards, move_height,
    )

  async def pierce_foil(
    self,
    wells: Union[Well, List[Well]],
    piercing_channels: List[int],
    hold_down_channels: List[int],
    move_inwards: float,
    spread: Literal["wide", "tight"] = "wide",
    one_by_one: bool = False,
    distance_from_bottom: float = 20.0,
  ):
    logger.info(
      "piercing foil | wells: %s | piercing channels: %s | "
      "hold down channels: %s | move inwards: %s | "
      "spread: %s | one by one: %s | distance from bottom: %s",
      wells, piercing_channels, hold_down_channels, move_inwards,
      spread, one_by_one, distance_from_bottom,
    )

  # # # # # # # # Extension: iSWAP # # # # # # # #

  @property
  def iswap_parked(self) -> bool:
    return self._iswap_parked is True

  async def move_iswap_x(self, x_position: float):
    logger.info("moving iswap x to %s", x_position)

  async def move_iswap_y(self, y_position: float):
    logger.info("moving iswap y to %s", y_position)

  async def move_iswap_z(self, z_position: float):
    logger.info("moving iswap z to %s", z_position)

  @asynccontextmanager
  async def slow_iswap(self, wrist_velocity: int = 20_000, gripper_velocity: int = 20_000):
    """A context manager that sets the iSWAP to slow speed during the context."""
    assert 20 <= gripper_velocity <= 75_000, "Gripper velocity out of range."
    assert 20 <= wrist_velocity <= 65_000, "Wrist velocity out of range."

    messages = ["start slow iswap"]
    try:
      yield
    finally:
      messages.append("end slow iswap")
      logger.info(" | ".join(messages))

  # # # # # # # # Liquid Level Detection (LLD) # # # # # # # #

  async def request_tip_len_on_channel(self, channel_idx: int) -> float:
    """Return tip length from the tip tracker.

    Args:
      channel_idx: Index of the pipetting channel (0-indexed).

    Returns:
      The tip length in mm from the tip tracker.

    Raises:
      NoTipError: If no tip is present on the channel (via tip tracker).
    """
    tip = self.head[channel_idx].get_tip()
    return tip.total_tip_length

  async def position_channels_in_y_direction(self, ys, make_space=True):
    logger.info("positioning channels in y: %s make_space: %s", ys, make_space)

  async def probe_liquid_heights(
    self,
    containers: List[Container],
    use_channels: Optional[List[int]] = None,
    **kwargs,
  ) -> List[float]:
    """Return liquid heights derived from the volume tracker state."""
    return [
      container.compute_height_from_volume(container.tracker.get_used_volume())
      for container in containers
    ]

  # # # # # # # # Carrier presence (no firmware in sim) # # # # # # # #

  async def request_presence_of_carriers_on_deck(self) -> list[int]:
    """Return empty list — carrier presence is not tracked in simulation."""
    return []

  # # # # # # # # Extension: iSWAP (additional) # # # # # # # #

  async def park_iswap(
    self,
    minimum_traverse_height_at_beginning_of_a_command: int = 2840,
  ):
    """Park iSWAP (simulation — sets state only)."""
    self._iswap_parked = True
    logger.info("park_iswap")

  # # # # # # # # Extension: CoRe Gripper # # # # # # # #

  async def return_core_gripper_tools(
    self,
    front_offset: Optional[Coordinate] = None,
    back_offset: Optional[Coordinate] = None,
  ):
    """Return CoRe gripper tools (simulation — sets state only)."""
    self._core_parked = True
    logger.info("return_core_gripper_tools")

  async def take_carrier_out_to_autoload_belt(self, carrier: Carrier):
    """Autoload no-op in simulation."""
    logger.info("take_carrier_out_to_autoload_belt: %s", carrier.name)

  async def unload_carrier(
    self,
    carrier: Carrier,
    park_autoload_after: bool = True,
  ):
    """Autoload no-op in simulation."""
    logger.info("unload_carrier: %s", carrier.name)
