"""CLARIOstar Plus temperature control mixin."""

import asyncio
import logging
import time
import warnings
from typing import Literal, Optional

logger = logging.getLogger("pylabrobot")


class _TemperatureControlMixin:
  """Temperature monitoring and heating control.

  Temperature commands use standard framing with a 3-byte payload:
    [0x06, temp_hi, temp_lo]
  where temp_raw = (temp_hi << 8) | temp_lo is the target in 0.1°C units.
    OFF:     temp_raw = 0x0000
    MONITOR: temp_raw = 0x0001
    SET:     temp_raw = target_celsius * 10  (e.g. 30.0°C → 0x012C)

  The device does not send a dedicated temperature response; the regular
  status response (cmd 0x80, 24-byte frame / 16-byte payload) carries
  temperature readings at payload bytes 11-14.

  The set target temperature is fire-and-forget -- it is NOT echoed back
  in the status response. The host must track it locally.

  Heating state tracking: the firmware does not expose a reliable
  "heating active" flag. Byte 15 of the status response takes multiple
  values (0xC0, 0xE0, 0x40, 0x00) but the pattern does not correlate
  clearly with heating state. Therefore, heating state is tracked in
  software via ``_target_temperature``.

  Wire format confirmed in K01 USB capture (monitor -> set 30 degC -> off -> monitor -> off).
  """

  _TEMP_OFF = b"\x00\x00"  # 0x0000: disable sensors + heating
  _TEMP_MONITOR = b"\x00\x01"  # 0x0001: sensors only, no heating

  async def _request_temperature_monitoring_on(self) -> bool:
    """Check whether temperature sensors are currently reporting.

    Returns:
      ``True`` if heating or monitoring is active (status payload bytes
      11-14 carry non-zero temperature values), ``False`` otherwise.
    """
    status = await self.request_machine_status()
    return status["temperature_bottom"] is not None

  def get_target_temperature(self) -> Optional[float]:
    """Return the current heating target in °C, or ``None`` if not heating."""
    return self._target_temperature

  async def _start_temperature_monitoring(self) -> None:
    """Send the MONITOR command to enable temperature readout without heating.

    Warning:
      Sending MONITOR while heating is active will overwrite the active
      setpoint (firmware treats the temperature register as single-state).
      Callers must check ``_request_temperature_monitoring_on()`` first
      and skip this call if sensors are already reporting.
    """
    await self.send_command(
      command_family=self.CommandFamily.TEMPERATURE_CONTROLLER,
      parameters=self._TEMP_MONITOR,
    )

  async def start_temperature_control(self, temperature: float) -> None:
    """Set target temperature and enable heating.

    Args:
      temperature: Target in degrees C (e.g. 37.0). Increments of 0.1°C.

    Raises:
      ValueError: If target exceeds ``max_temperature``.
    """

    max_temp = self.configuration["max_temperature"]
    if not 0 <= temperature <= max_temp:
      raise ValueError(f"Temperature must be between 0 and {max_temp} °C, got {temperature}.")

    current = await self.measure_temperature(sensor="bottom")
    heater_overshoot_tolerance = 0.5
    if temperature < current - heater_overshoot_tolerance:
      warnings.warn(
        f"Target {temperature} °C is below the current bottom plate temperature "
        f"({current} °C). The CLARIOstar has no active cooling and will not reach "
        f"this target unless the ambient temperature drops.",
        stacklevel=2,
      )

    raw = int(round(temperature * 10))
    hi = (raw >> 8) & 0xFF
    lo = raw & 0xFF
    await self.send_command(
      command_family=self.CommandFamily.TEMPERATURE_CONTROLLER,
      parameters=bytes([hi, lo]),
    )
    self._target_temperature = temperature
    # Firmware needs ~200ms to populate temperature sensors after a SET command.
    # Without this, an immediate status poll sees zeros and
    # _start_temperature_monitoring would send MONITOR, overwriting the setpoint.
    await asyncio.sleep(0.3)

  async def stop_temperature_control(self) -> None:
    """Stop heating but keep temperature sensors active.

    Downgrades from SET to MONITOR. Use ``_stop_temperature_monitoring`` to
    turn off everything (sensors + heating).
    """
    await self.send_command(
      command_family=self.CommandFamily.TEMPERATURE_CONTROLLER,
      parameters=self._TEMP_MONITOR,
    )
    self._target_temperature = None
    # Firmware briefly zeros temperature readings during SET -> MONITOR transition.
    # Without this, an immediate status poll sees zeros and reports sensors as inactive.
    await asyncio.sleep(0.3)

  async def _stop_temperature_monitoring(self) -> None:
    """Disable temperature monitoring and heating."""
    logger.warning("_stop_temperature_monitoring sends OFF -- this also disables heating")
    await self.send_command(
      command_family=self.CommandFamily.TEMPERATURE_CONTROLLER,
      parameters=self._TEMP_OFF,
    )
    self._target_temperature = None

  async def measure_temperature(
    self,
    sensor: Literal["bottom", "top", "mean"] = "bottom",
  ) -> float:
    """Return the current incubator temperature, activating sensors if needed.

    Checks ``_request_temperature_monitoring_on`` first and only calls
    ``_start_temperature_monitoring`` when sensors are not yet populated,
    so it will never overwrite an active heating setpoint from
    ``start_temperature_control``.

    Then polls ``request_machine_status`` until both bottom and top plate
    temperatures are reported.

    Args:
      sensor: Which heating plate to read. ``"bottom"`` (below microplate,
        tracks setpoint), ``"top"`` (above microplate, ~0.5 degC above setpoint
        to prevent condensation), or ``"mean"`` (average of both).

    Returns:
      Temperature in degree C.

    Raises:
      TimeoutError: If the sensor does not populate within
        ``_PACKET_READ_TIMEOUT`` (3 s).

    Note:
      Uses ``_PACKET_READ_TIMEOUT`` (3 s) rather than ``read_timeout`` because
      sensor warm-up is bounded by hardware latency (~200 ms), not by command
      processing time.
    """

    valid_sensors = ("bottom", "top", "mean")
    if sensor not in valid_sensors:
      raise ValueError(f"sensor must be one of {valid_sensors}, got '{sensor}'.")

    if not await self._request_temperature_monitoring_on():
      await self._start_temperature_monitoring()

    t = time.time()
    timeout = self._PACKET_READ_TIMEOUT
    while time.time() - t < timeout:
      status = await self.request_machine_status()
      bottom = status["temperature_bottom"]
      top = status["temperature_top"]
      if bottom is not None and top is not None:
        if sensor == "bottom":
          return float(bottom)
        if sensor == "top":
          return float(top)
        return round((float(bottom) + float(top)) / 2, 1)
    raise TimeoutError(f"Temperature sensor did not populate within {timeout}s")
