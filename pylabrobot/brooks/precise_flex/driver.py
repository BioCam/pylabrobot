"""PreciseFlex driver - owns the socket I/O connection and device lifecycle."""

import asyncio
import logging
import time
from dataclasses import dataclass
from typing import TYPE_CHECKING, Dict, Literal, Optional

from pylabrobot.capabilities.capability import BackendParams
from pylabrobot.device import Driver
from pylabrobot.io.socket import Socket

from .data_ids import PowerState
from .errors import PreciseFlexError
from .interrupt import halt_and_resync, halt_on_interrupt

if TYPE_CHECKING:
  from .vision_backend import PreciseFlexVisionBackend

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Driver - owns socket I/O and device lifecycle
# ---------------------------------------------------------------------------


class PreciseFlexDriver(Driver):
  """Driver for PreciseFlex robotic arms.

  Owns the Socket I/O connection and device-level operations (power, attach,
  home, response mode).  Exposes ``send_command`` as the generic wire method.

  Documentation and error codes available at
  https://www2.brooksautomation.com/#Root/Welcome.htm
  """

  def __init__(self, host: str, port: int = 10100, timeout: int = 20) -> None:
    super().__init__()
    self.io = Socket(human_readable_device_name="Precise Flex Arm", host=host, port=port)
    self.timeout = timeout
    # Nullable vision capability, built by the arm backend at setup when a camera gripper is present.
    self.vision: Optional["PreciseFlexVisionBackend"] = None

  # -- communication ---------------------------------------------------------

  async def send_command(self, command: str) -> str:
    await self.io.write(command.encode("utf-8") + b"\n")
    reply = await self.io.readline()
    return self._parse_reply_ensure_successful(reply)

  async def query_raw(self, command: str) -> str:
    """Write a command and return its reply line stripped, without the ``<code> <data>`` parsing.

    For protocols that reply with a bare value - e.g. PreciseVision ``VToolProperty`` reads, which
    are not prefixed with a reply code. The caller interprets the raw line.
    """
    await self.io.write(command.encode("utf-8") + b"\n")
    return (await self.io.readline()).decode("utf-8").strip()

  def _parse_reply_ensure_successful(self, reply: bytes) -> str:
    """Parse reply from Precise Flex.

    Expected format: b'replycode data message\r\n'
    - replycode is an integer at the beginning
    - data is rest of the line (excluding CRLF)
    """
    text = reply.decode().strip()
    if not text:
      raise PreciseFlexError(-1, "Empty reply from device.")
    parts = text.split(" ", 1)
    if len(parts) == 1:
      replycode = int(parts[0])
      data = ""
    else:
      replycode, data = int(parts[0]), parts[1]
    if replycode != 0:
      raise PreciseFlexError(replycode, data)
    return data

  # -- vision tool properties (controller relay) -----------------------------

  async def request_vision_tool_property(self, tool: str, property_name: str) -> str:
    """Read a PreciseVision tool property over the controller (``VToolProperty <tool> <prop>``).

    Named ``vision_`` because this is the general controller where ``tool`` already means the robot's
    tool frame. The controller relays the read to the vision engine and replies with the BARE value
    (no ``<code> <data>`` prefix), so it is read raw; a negative reply is a vision error code and
    raised. The (tool, property) split is needed because VToolProperty's wire form is two tokens;
    direct to the engine the same read is ``PreciseVisionDriver.request_property("<tool>.<property>")``
    (dotted, and ``None`` on error rather than raising).

    Args:
      tool: the vision tool name (e.g. ``led``, ``acq1``, or ``System`` for server properties).
      property_name: the tool property name (e.g. ``Bank``, ``Brightness``, ``CameraCount``).

    Returns:
      The bare property value.

    Raises:
      PreciseFlexError: on a negative reply (a vision error code).
    """
    reply = await self.query_raw(f"VToolProperty {tool} {property_name}")
    if reply.startswith("-") and reply[1:].isdigit():
      raise PreciseFlexError(int(reply), "")
    return reply

  async def _set_vision_tool_property(self, tool: str, property_name: str, value: str) -> str:
    """Write a PreciseVision tool property over the controller (``VToolProperty <tool> <prop> <value>``).

    Private: a write changes device state, so it is reached through the vision backend's vetted
    orchestrations, not called directly (the ``request_`` read sibling is public). Named ``vision_``
    because this is the general controller where ``tool`` already means the robot's tool frame. The
    (tool, property) split is needed because VToolProperty's wire form is two tokens; direct to the
    engine the same write is ``PreciseVisionDriver._set_property("<tool>.<property>", value)``. The
    write only stores the value; run the owning tool/process to apply it. Goes through the normal
    ``<code> <data>`` reply parser.

    Args:
      tool: the vision tool name (e.g. ``led``, ``acq1``).
      property_name: the tool property name (e.g. ``Bank``, ``acquiremode``).
      value: the value to write; must not contain spaces.

    Returns:
      The write reply.
    """
    return await self.send_command(f"VToolProperty {tool} {property_name} {value}")

  # -- lifecycle -------------------------------------------------------------

  @dataclass
  class SetupParams(BackendParams):
    """PreciseFlex-specific parameters for ``setup``.

    Args:
      skip_home: If True, skip the homing step during setup.
    """

    skip_home: bool = False

  async def setup(self, backend_params: Optional[BackendParams] = None):
    """Initialize the PreciseFlex driver.

    Opens the socket connection, sets response mode to PC, powers on the
    robot, attaches it, and (optionally) homes it.
    """
    if not isinstance(backend_params, PreciseFlexDriver.SetupParams):
      backend_params = PreciseFlexDriver.SetupParams()

    await self.io.setup()
    await self.set_response_mode("pc")
    await self.power_on_robot()
    await self.attach(1)
    if not backend_params.skip_home:
      await self.home()
    logger.debug("[PreciseFlex %s] connected: port=%s", self.io._host, self.io._port)

  async def setup_vision(self, vision_host: Optional[str]) -> None:
    """Build the vision capability and connect its PreciseVision engine; best-effort, never raises.

    Called by the arm backend once it has discovered a camera gripper is installed - the driver owns
    the connection, symmetric with how ``stop`` closes it. The controller side of vision always works;
    a set, reachable ``vision_host`` additionally opens the engine for image fetch and discovery. A
    missing or unreachable host leaves ``self.vision`` built but engine-less.

    Args:
      vision_host: address of the PreciseVision engine, or ``None`` for controller-only vision.
    """
    from .vision_backend import PreciseFlexVisionBackend  # local import: breaks the import cycle
    from .vision_driver import PreciseVisionDriver

    vision_driver: Optional[PreciseVisionDriver] = None
    if vision_host:
      vision_driver = PreciseVisionDriver(vision_host)
      try:
        await vision_driver.setup()
      except Exception as exc:  # noqa: BLE001 - a missing/unreachable engine just disables image fetch
        logger.warning(
          "[PreciseFlex %s] vision engine at %s unreachable; direct image acquisition disabled: %s",
          self.io._host,
          vision_host,
          exc,
        )
        vision_driver = None
    self.vision = PreciseFlexVisionBackend(
      self, vision_host=vision_host, vision_driver=vision_driver
    )
    await self.vision.setup()  # discovers, caches, and logs the capability summary (best-effort)

  async def stop(self):
    """Stop the PreciseFlex driver."""
    await self.detach()
    await self.power_off_robot()
    await self.exit()
    if self.vision is not None and self.vision.vision_driver is not None:
      await self.vision.vision_driver.stop()  # close the held PreciseVision engine connection
    await self.io.stop()
    logger.info("[PreciseFlex %s] disconnected: port=%s", self.io._host, self.io._port)

  # -- device-level commands -------------------------------------------------

  async def exit(self) -> None:
    """Close the communications link immediately.

    Note:
      Does not affect any robots that may be active.
    """
    await self.io.write(b"exit\n")

  ResponseMode = Literal["pc", "verbose"]

  async def request_mode(self) -> ResponseMode:
    """Get the current response mode.

    Returns:
      Current mode (0 = PC mode, 1 = verbose mode)
    """
    response = await self.send_command("mode")
    mapping: Dict[int, PreciseFlexDriver.ResponseMode] = {0: "pc", 1: "verbose"}
    return mapping[int(response)]

  async def set_response_mode(self, mode: ResponseMode) -> None:
    """Set the response mode.

    Args:
      mode: Response mode to set.
      0 = Select PC mode
      1 = Select verbose mode

    Note:
      When using serial communications, the mode change does not take effect
      until one additional command has been processed.
    """
    if mode not in ["pc", "verbose"]:
      raise ValueError("Mode must be 'pc' or 'verbose'")
    mapping = {"pc": 0, "verbose": 1}
    await self.send_command(f"mode {mapping[mode]}")

  async def request_system_state(self) -> int:
    """Controller power/system-state word (the ``sysState`` command, == DataID 234).

    See :class:`~pylabrobot.brooks.precise_flex.data_ids.PowerState` for the values;
    ``PowerState.OFF_HARD_ESTOP`` (15) means a hard E-stop is engaged, ``PowerState.ON_ATTACHED``
    (21) is the normal running state. Read-only, so it detects an E-stop without provoking an error.
    """
    return int(await self.send_command("sysState"))

  async def power_on_robot(self):
    """Power on the robot."""
    error: Optional[PreciseFlexError] = None
    for _ in range(3):
      try:
        await self.set_power(True, self.timeout)
      except PreciseFlexError as e:
        logger.warning(f"Error powering on robot, retrying... Attempt {_ + 1}/3. Error: {e}")
        error = e
      else:
        return

    if error:
      raise error
    raise RuntimeError("Failed to power on robot after 3 attempts for unknown reasons.")

  async def recover_from_fault(self) -> None:
    """Recover after a collision / fault that stopped the arm and dropped power, leaving it usable.

    A collision trips an envelope error (``-3100`` hard / ``-3122`` soft, see
    :func:`~pylabrobot.brooks.precise_flex.errors.is_collision`); the servo stops the arm itself and
    high power drops. This re-enables power, re-attaches, and re-homes (which only cycles the gripper
    when the other axes are already homed - absolute encoders retain them - so it does not sweep the
    arm), leaving it ready to move. It does **not** drive the arm to any pose; confirm the obstacle is
    removed before calling.

    The envelope error auto-clears, so no explicit clear is needed; a latched fatal that blocks
    power-on is surfaced by ``power_on_robot`` for the operator to reset (DataID 247) or reboot.

    Raises:
      PreciseFlexError: if a hard E-stop is engaged (release the button first) or power cannot be
        re-enabled.
    """
    if await self.request_system_state() == PowerState.OFF_HARD_ESTOP:
      raise PreciseFlexError(
        -1028, "hard E-Stop engaged - release the E-stop button before recovering"
      )
    await self.power_on_robot()
    await self.attach(1)
    await self.home()

  async def power_off_robot(self):
    """Power off the robot."""
    await self.set_power(False)

  async def set_power(self, enable: bool, timeout: int = 0) -> None:
    """Enable or disable robot high power.

    Args:
      enable: True to enable power, False to disable
      timeout: Wait timeout for power to come on.
        0 or omitted = do not wait for power to come on
        > 0 = wait this many seconds for power to come on
        -1 = wait indefinitely for power to come on

    Raises:
      PreciseFlexError: If power does not come on within the specified timeout.
    """
    power_state = 1 if enable else 0
    if timeout == 0:
      await self.send_command(f"hp {power_state}")
    else:
      await self.send_command(f"hp {power_state} {timeout}")

  async def request_power_state(self) -> int:
    """Get the current robot power state.

    Returns:
      Current power state (0 = disabled, 1 = enabled)
    """
    response = await self.send_command("hp")
    return int(response)

  async def attach(self, attach_state: Optional[int] = None) -> int:
    """Attach or release the robot, or get attachment state.

    Args:
      attach_state: If omitted, returns the attachment state.  0 = release the robot; 1 = attach the robot.

    Returns:
      If attach_state is omitted, returns 0 if robot is not attached, -1 if attached.  Otherwise returns 0 on success.

    Note:
      The robot must be attached to allow motion commands.
    """
    if attach_state is None:
      response = await self.send_command("attach")
      return int(response)
    await self.send_command(f"attach {attach_state}")
    return 0

  async def detach(self):
    """Detach the robot."""
    await self.attach(0)

  async def home(self) -> None:
    """Home the robot associated with this thread.

    Note:
      Requires power to be enabled.
      Requires robot to be attached.
      Waits until the homing is complete.
    """
    await self.send_command("home")

  async def home_all(self) -> None:
    """Home all robots.

    Note:
      Requires power to be enabled.
      Requires that robots not be attached.
    """
    await self.send_command("homeAll")

  async def _wait_for_eom(
    self, poll_interval: float = 0.05, settle: float = 0.02, timeout: float = 60.0
  ) -> None:
    """Wait (non-blocking) until the arm has stopped moving, keeping the connection responsive.

    Polls the live joint position (``wherej``) and returns once it stops changing between samples
    (every axis moving less than ``settle``) - i.e. end of motion. It returns promptly when the arm
    is already stationary, including when it was stopped short of its last commanded target (after a
    halt/interrupt or a hand-move), so it never hangs waiting to reach a target that will not be
    reached.

    This deliberately avoids the firmware ``waitForEom``: that command parks the controller's single
    command interpreter and makes it ignore everything else on the connection - including ``halt`` -
    until the move ends (hardware-verified). Polling instead leaves the connection free between
    samples, so a user interrupt can stop the move mid-flight via ``halt`` and other controller
    commands (status, vision, barcode) can run during motion.

    Raises:
      TimeoutError: if the arm never settles within ``timeout`` seconds.
      OperationInterrupted: on a user interrupt (the arm is halted and the connection kept).
    """

    def _floats(reply: str) -> list[float]:
      return [float(x) for x in reply.split()]

    # On interrupt, `halt` stops the move on the now-free connection and we resync; the connection is
    # kept open. Hardware-verified: a clean halt keeps power, attach, and the link (only a collision
    # trips -3122 and drops power, which needs explicit recovery).
    async with halt_on_interrupt(lambda: halt_and_resync(self.io, b"halt")):
      previous = _floats(await self.send_command("wherej"))
      deadline = time.monotonic() + timeout
      while True:
        await asyncio.sleep(poll_interval)
        current = _floats(await self.send_command("wherej"))
        if all(abs(c - p) < settle for c, p in zip(current, previous)):
          return  # stopped moving
        if time.monotonic() > deadline:
          raise TimeoutError(f"motion did not settle within {timeout:.0f}s (current={current})")
        previous = current

  async def state(self) -> str:
    """Return state of motion.

    This value indicates the state of the currently executing or last completed robot motion.
    For additional information, please see 'Robot.TrajState' in the GPL reference manual.

    Returns:
      str: The current motion state.
    """
    return await self.send_command("state")
