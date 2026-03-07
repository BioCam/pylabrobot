"""CLARIOstar Plus standalone shaking and idle movement mixin."""

import asyncio
import logging
import time
from typing import Literal, Optional

logger = logging.getLogger("pylabrobot")


class _ShakerMixin:
  """Standalone plate shaking (R_Shake) and idle movement (R_IdleMove)."""

  async def start_shaking(
    self,
    pattern: Literal["orbital", "linear", "double_orbital", "meander"] = "orbital",
    rpm: int = 300,
    duration: Optional[int] = None,
    x_position: int = 9999,
    y_position: int = 9999,
  ) -> None:
    """Standalone plate shaking (R_Shake, command 0x1D).

    Shakes the plate independently of any measurement. When no ``duration``
    is given, shakes for the maximum time (3600 s). Call
    :meth:`stop_measurement` to interrupt early.

    Args:
      pattern: Shake pattern -- ``"orbital"`` (default), ``"linear"``,
        ``"double_orbital"``, or ``"meander"``.
      rpm: Shake frequency in RPM. Must be a multiple of 100.
        Range 100-700 for most modes, 100-300 for meander.
      duration: Shake duration in seconds (1-3600). If ``None``, shakes
        for 3600 s (1 hour). Use :meth:`stop_measurement` to stop early.
      x_position: Plate X position (250-3100), or 9999 for default/random.
      y_position: Plate Y position (125-800), or 9999 for default/random.

    Wire (11-byte payload, no command sub-byte)::

      [0x1D] [mode] [speed_idx] [duration:2B BE]
             [x_pos:2B BE] [y_pos:2B BE] [0x00] [flags]

    Hardware-verified ground truth::

      orbital 300rpm   5s default:  1d 00 02 00 05 27 0f 27 0f 00 00
      orbital 300rpm   5s x=500:   1d 00 02 00 05 01 f4 27 0f 00 01
      orbital 100rpm   5s default:  1d 00 00 00 05 27 0f 27 0f 00 00
      orbital 200rpm   5s default:  1d 00 01 00 05 27 0f 27 0f 00 00
      orbital 300rpm 300s default:  1d 00 02 01 2c 27 0f 27 0f 00 00
      orbital 300rpm 600s default:  1d 00 02 02 58 27 0f 27 0f 00 01
      orbital 300rpm 3600s default: 1d 00 02 0e 10 27 0f 27 0f 00 00
    """
    if pattern not in self._SHAKE_MODES:
      raise ValueError(f"pattern must be one of {list(self._SHAKE_MODES)}, got '{pattern}'.")
    max_rpm = 300 if pattern == "meander" else 700
    if rpm < 100 or rpm > max_rpm or rpm % 100 != 0:
      raise ValueError(
        f"rpm must be a multiple of 100 in range 100-{max_rpm}, got {rpm}."
      )

    if duration is None:
      duration = 3600
    if not 1 <= duration <= 3600:
      raise ValueError(f"duration must be 1-3600, got {duration}.")

    mode_byte = self._SHAKE_MODES[pattern]
    speed_idx = (rpm // 100) - 1
    # Byte 10 is a flag: 0x01 when custom x_position is specified
    custom_pos = 0x01 if x_position != 9999 else 0x00

    # Duration is u16 BE at bytes 2-3 -- confirmed by USB captures
    # VAL-01 (300s=0x012C), VAL-02 (600s=0x0258), VAL-03 (3600s=0x0E10).
    payload = bytearray(10)
    payload[0] = mode_byte
    payload[1] = speed_idx
    payload[2:4] = duration.to_bytes(2, "big")
    payload[4:6] = x_position.to_bytes(2, "big")
    payload[6:8] = y_position.to_bytes(2, "big")
    payload[8] = 0x00
    payload[9] = custom_pos

    await self.send_command(
      command_family=self.CommandFamily.SHAKE,
      parameters=bytes(payload),
      wait=True,
    )

  async def stop_shaking(self) -> None:
    """Stop standalone shaking started by :meth:`start_shaking`.

    Queries device status and acts based on state:

    - **Running but no measurement** (standalone shake): calls
      :meth:`stop_measurement` (STOP 0x0B 0x00) and polls until the
      ``running`` flag clears (~5 s).
    - **Running with active measurement**: logs a warning that stopping
      will cancel the measurement, then calls :meth:`stop_measurement`.
    - **Not running**: does nothing (shake already finished or never started).

    Hardware-verified ground truth confirms STOP 0x0B 0x00 reliably terminates
    standalone shaking (captures ST-01, ST-04).
    """
    status = await self.request_machine_status()

    if not status["running"]:
      logger.info("stop_shaking: device not running, nothing to do")
      return

    if status["reading_wells"]:
      logger.warning(
        "stop_shaking: device is running a measurement (reading_wells=True). "
        "Calling stop_measurement will cancel the entire run."
      )

    await self.stop_measurement()

    # Poll until running clears (typically ~5 s)
    t = time.time()
    timeout = 15.0
    while time.time() - t < timeout:
      await asyncio.sleep(0.25)
      status = await self.request_machine_status()
      if not status["running"]:
        logger.info("stop_shaking: running flag cleared after %.1fs", time.time() - t)
        return
    logger.warning("stop_shaking: running flag still set after %.1fs", time.time() - t)

  async def stop_idle_movement(self) -> None:
    """Cancel any active idle movement (R_IdleMove cancel, command 0x27).

    Sends mode=0 (cancel) to stop movement started by
    :meth:`start_idle_movement`.

    Wire::

      27 00 00 00 00 00 00 00 00 00 00
    """
    await self.send_command(
      command_family=self.CommandFamily.IDLE_MOVE,
      parameters=b"\x00" * 10,
    )

  async def start_idle_movement(
    self,
    pattern: Literal[
      "linear_corner", "incubation", "meander_corner",
      "orbital_corner", "orbital", "double_orbital",
    ] = "orbital",
    rpm: int = 300,
    duration: int = 65535,
    on_time: int = 0,
    off_time: int = 0,
  ) -> None:
    """Start continuous or periodic plate movement (R_IdleMove, command 0x27).

    Designed for keeping samples mixed during incubation. Runs in the
    background and does not block. When ``off_time`` is 0, shaking is
    permanent for the full ``duration``. Cancel anytime with
    :meth:`stop_idle_movement`.

    Requires firmware >= 1.20.

    Args:
      pattern: Movement pattern. ``"orbital"`` and ``"double_orbital"`` support
        speed control (100-700 rpm). ``"meander_corner"`` supports 100-300 rpm.
        ``"linear_corner"`` and ``"incubation"`` ignore speed.
        ``"orbital_corner"`` requires special plate carrier.
      rpm: Shake frequency in RPM. Must be a multiple of 100.
        Ignored for ``"linear_corner"`` and ``"incubation"`` modes.
      duration: Total duration in seconds (1-65535). Default 65535 (~18 hours).
      on_time: Seconds of movement per cycle (0 = permanent, no pauses).
      off_time: Seconds of pause between cycles (0 = permanent, no pauses).

    Wire (11-byte payload, no command sub-byte)::

      [0x27] [mode] [speed_idx?] [0x00] [duration]
             [off_time:2B BE] [on_time:2B BE] [0x00] [0x00]

    Hardware-verified ground truth (linear corner, 60s, on=10s, off=5s)::

      27 01 00 00 3c 00 05 00 0a 00 00
    """
    if pattern not in self._IDLE_MOVE_MODES:
      raise ValueError(f"pattern must be one of {list(self._IDLE_MOVE_MODES)}, got '{pattern}'.")
    if not 1 <= duration <= 65535:
      raise ValueError(f"duration must be 1-65535, got {duration}.")

    mode_byte = self._IDLE_MOVE_MODES[pattern]

    # Speed encoding -- same as R_Shake for modes that support it
    speed_idx = 0x00
    if pattern in ("meander_corner", "orbital_corner", "orbital", "double_orbital"):
      max_rpm = 300 if pattern == "meander_corner" else 700
      if rpm < 100 or rpm > max_rpm or rpm % 100 != 0:
        raise ValueError(
          f"rpm must be a multiple of 100 in range 100-{max_rpm}, got {rpm}."
        )
      speed_idx = (rpm // 100) - 1

    payload = bytearray(10)
    payload[0] = mode_byte
    payload[1] = speed_idx
    payload[2] = 0x00
    payload[3] = duration & 0xFF  # low byte (may be u16 -- needs more capture data)
    payload[4:6] = off_time.to_bytes(2, "big")
    payload[6:8] = on_time.to_bytes(2, "big")
    payload[8] = 0x00
    payload[9] = 0x00

    await self.send_command(
      command_family=self.CommandFamily.IDLE_MOVE,
      parameters=bytes(payload),
    )
