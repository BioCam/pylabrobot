"""Read what a v1 device publishes about itself, and say plainly what it does not.

v0 carried machine state on the liquid handler, which serialized its head. v1 has no liquid
handler and its capabilities are plain subsystems with no state serialization, so there is
currently nothing for a visualizer to subscribe to. This module is the shape that contract could
take, built only from what a `STARDevice` already answers.

Every number carries its provenance. `measured` came off the instrument, `derived` was computed
from something the instrument said plus a documented rule, and `unavailable` means v1 publishes
no way to know. Nothing is guessed and presented as a reading.
"""

import logging
from dataclasses import asdict, dataclass, field
from typing import Any, Dict, List, Literal, Optional

logger = logging.getLogger(__name__)

Provenance = Literal["measured", "derived", "unavailable"]


@dataclass
class Reading:
  """One number, and where it came from."""

  value: Optional[float]
  provenance: Provenance
  note: str = ""

  @staticmethod
  def missing(note: str) -> "Reading":
    return Reading(value=None, provenance="unavailable", note=note)


@dataclass
class ChannelState:
  index: int
  x: Reading
  y: Reading
  z: Reading


@dataclass
class DeviceState:
  """What one device is doing, as far as it will say."""

  device: str
  channels: List[ChannelState] = field(default_factory=list)
  arm_x: Optional[Reading] = None
  iswap_y: Optional[Reading] = None
  cover: Optional[str] = None
  gaps: List[str] = field(default_factory=list)

  def serialize(self) -> Dict[str, Any]:
    return asdict(self)


class STARTelemetry:
  """A state reader for a v1 `STARDevice`.

  Read it with :meth:`read`. It only calls query methods, so it is safe to poll while a protocol
  runs: nothing here moves anything.
  """

  def __init__(self, device):
    self.device = device

  async def read(self) -> DeviceState:
    state = DeviceState(device=self.device.name)

    arm_x_value: Optional[float] = None
    try:
      arm_x_value = await self.device.x_arm.request_position()
      state.arm_x = Reading(arm_x_value, "measured", "X-arm position readout")
    except Exception as e:  # a machine without an arm, or one that is not up yet
      state.arm_x = Reading.missing(f"X-arm position not readable: {e}")

    pipettes = self.device.pipettes
    if pipettes is not None:
      # Y: the initialization spread is the only per-channel Y the capability computes. It is
      # where the channels sit after initialization, not a live readout, so it is derived.
      try:
        y_positions = pipettes.default_initialize_y_positions()
      except Exception:
        y_positions = []
      for channel in range(pipettes.num_channels):
        state.channels.append(
          ChannelState(
            index=channel,
            x=(
              Reading(arm_x_value, "derived", "the arm's X; per-channel X is not published")
              if arm_x_value is not None
              else Reading.missing("no arm position to derive channel X from")
            ),
            y=(
              Reading(y_positions[channel], "derived", "initialization spread, not a live readout")
              if channel < len(y_positions)
              else Reading.missing("no per-channel Y readout")
            ),
            z=Reading.missing("no Z readout; only a move-to-safety command exists"),
          )
        )
      state.gaps.append(
        f"{pipettes.num_channels} channels publish no live X, Y or Z, and no tip-mounted state"
      )
    else:
      state.gaps.append("no pipetting channels on this machine")

    iswap = self.device.iswap
    if iswap is not None:
      try:
        y_positions = await iswap.request_y_positions()
        state.iswap_y = Reading(
          y_positions.get("home"), "measured", "the iSWAP's home Y, not its live position"
        )
      except Exception as e:
        state.iswap_y = Reading.missing(f"iSWAP Y not readable: {e}")
      state.gaps.append("iSWAP publishes named Y constants, not a live pose or its contents")

    if self.device.head96 is not None:
      state.gaps.append("96-head publishes drive windows, not a live position")

    cover = self.device.front_cover
    if cover is not None:
      try:
        state.cover = str(await cover.request_position())
      except Exception:
        state.cover = None
    else:
      state.gaps.append("no front-cover monitoring on this machine")

    return state
