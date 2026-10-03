"""PreciseFlex driver - owns the socket I/O connection and device lifecycle."""

import asyncio
import dataclasses
import logging
import warnings
from typing import (
  ClassVar,
  Dict,
  List,
  Literal,
  NamedTuple,
  Optional,
  Tuple,
)

from pylabrobot.brooks.precise_flex import kinematics
from pylabrobot.brooks.precise_flex.driver.configuration import Axis, PreciseFlexConfiguration
from pylabrobot.brooks.precise_flex.kinematics import JointState
from pylabrobot.events import emit_event, evented_operation
from pylabrobot.io.socket import Socket
from pylabrobot.resources.coordinate import Coordinate
from pylabrobot.resources.rotation import Rotation

from ..confirmed_firmware_versions import (
  SUPPORTED_ROBOT_TYPES,
  is_confirmed,
  is_supported_model,
  suggest_entry,
)
from ..data_ids import DataID, PowerState
from ..kinematics import ElbowOrientation, PreciseFlexCartesianPose, Wrist
from ..tcs_modules import missing_required_modules
from .errors import PreciseFlexError
from .features.arm import PreciseFlexArm, _cartesian_target_reference, _joint_state_reference
from .features.gripper import PreciseFlexGripper
from .features.rail import PreciseFlexRail
from .features.vision import PreciseFlexVision

logger = logging.getLogger(__name__)


# The vision server (Brooks' PreciseVision engine) behind a camera-gripper arm: a text property
# protocol on one port, and the JPEG results it pushes on another.
VISION_SERVER_PROPERTY_PORT = 1450  # text command/query protocol
VISION_SERVER_IMAGE_PORT = (
  1500  # binary stream carrying the pushed "Primary Image [n]" JPEG results
)

# Result framing on :1500 (confirmed live from the 2026-06-22 capture): the engine pushes a sequence
# of length-prefixed records, each a fixed 16-byte header then the result name then the data -
#
#   01 | name_len (u8) | 00 00 00 | data_len (u32 LE) | 00 00 00 00 00 00 00 | <name> | <data>
#
# For a "Primary Image [n]" record the data is the JPEG (FFD8...FFD9) and data_len is its exact byte
# count (verified to land on the EOI for 52/52 frames). The stream interleaves non-image records too
# (e.g. "VisionResults[led]" tool results), framed identically. Parsing by the announced data_len -
# rather than scanning the payload for FFD8/FFD9 - is O(1) per record, demuxes the non-image records,
# and never inspects the JPEG, so an embedded thumbnail or restart marker cannot mis-frame it. The
# parser stays aligned by always consuming exactly one whole record; a freshly held stream starts on a
# record boundary.
_RECORD_HEADER_LEN = 16
_MAX_IMAGE_BYTES = (
  16 * 1024 * 1024
)  # sanity cap: a record this large signals a desync, not a real frame


def parse_vision_server_reply(reply: str) -> str:
  """Parse an engine reply line into its success value, raising on a negative (error) reply.

  Mirrors the controller transport (``PreciseFlex._ensure_successful``): a negative
  reply is a vision error code, surfaced as a ``PreciseFlexError`` whose message looks the code up in
  the shared error table (the vision ``-40xx`` codes are in it), rather than silently swallowed to
  ``None``.

  Args:
    reply: a raw reply line - ``0 <value>`` on success, or a negative code (+ optional message text).

  Returns:
    The ``<value>`` of a success reply (possibly empty).

  Raises:
    PreciseFlexError: on a negative (error) reply, carrying the engine's numeric code and message.
  """
  code, _, rest = reply.partition(" ")
  if code == "0":
    return rest
  try:
    replycode = int(code)
  except ValueError as e:
    raise PreciseFlexError(-1, f"unparseable engine reply: {reply!r}") from e
  raise PreciseFlexError(replycode, rest)


def _drain_named_record(buf: bytearray) -> Optional[Tuple[str, bytes]]:
  """Pop the next complete ``(name, data)`` result record from the front of ``buf``, consuming it.

  Reads the engine's fixed 16-byte record header (see the module comment): the name length, the
  little-endian ``data_len``, then ``name_len`` name bytes and exactly ``data_len`` data bytes. Parsing
  by the announced length never inspects the payload, so a JPEG's internal markers cannot mis-frame it,
  and the same path frames the interleaved non-image records. Assumes ``buf`` begins on a record
  boundary, which a freshly held stream does.

  Args:
    buf: the held read buffer; a complete record is removed from its front in place.

  Returns:
    The next ``(name, data)`` record, or ``None`` while the full record has not arrived yet.

  Raises:
    ValueError: if the header is not a record start (``buf[0] != 0x01``) or declares an implausibly
      large ``data_len`` - both signal a desynchronised stream, which has no safe silent recovery.
  """
  if len(buf) < _RECORD_HEADER_LEN:
    return None
  if buf[0] != 0x01:
    raise ValueError(
      f"PreciseVision image stream desync: record starts with {buf[0]:#04x}, not 0x01"
    )
  name_len = buf[1]
  data_len = int.from_bytes(buf[5:9], "little")
  if data_len > _MAX_IMAGE_BYTES:
    raise ValueError(
      f"PreciseVision record declares an implausible data length of {data_len} bytes"
    )
  end = _RECORD_HEADER_LEN + name_len + data_len
  if len(buf) < end:
    return None
  name = bytes(buf[_RECORD_HEADER_LEN : _RECORD_HEADER_LEN + name_len]).decode("ascii", "replace")
  data = bytes(buf[_RECORD_HEADER_LEN + name_len : end])
  del buf[:end]
  return name, data


class MotionProfile(NamedTuple):
  """A controller motion profile, as reported by ``Profile <n>`` (field order matches the wire)."""

  profile: int
  speed: float
  speed2: float
  acceleration: float
  deceleration: float
  acceleration_ramp: float
  deceleration_ramp: float
  in_range: float  # -1 (BLEND_IN_RANGE) to 100; -1 blends, 0 stops, >0 enforces position accuracy
  straight: bool  # True = straight-line path, False = joint-based path


def _parse_scalar(response: str) -> float:
  """Parse the first numeric field of a DataID reply.

  Some scalar DataIDs come back zero-padded (e.g. robot type as ``12, 0, 0, ...``)
  and Cartesian references carry several components; take the leading value.
  """
  return float(response.split(",")[0])


def _parse_per_axis(response: str) -> Dict[Axis, float]:
  """Parse a comma-separated per-axis DataID reply into an {Axis: value} map."""
  values = [float(v) for v in response.split(",")]
  return {Axis(i + 1): values[i] for i in range(min(len(values), len(Axis)))}


def _zip_axis_ranges(
  low: Dict[Axis, float], high: Dict[Axis, float]
) -> Dict[Axis, tuple[float, float]]:
  """Combine min and max per-axis maps into an {Axis: (min, max)} map."""
  return {axis: (low[axis], high[axis]) for axis in low.keys() & high.keys()}


class PreciseFlex:
  """Driver for PreciseFlex robotic arms.

  Owns the Socket I/O connection and device-level operations (power, attach,
  home, response mode).  Exposes ``send_command`` as the generic wire method.

  Documentation and error codes available at
  https://www2.brooksautomation.com/#Root/Welcome.htm
  """

  # Validated parked orientations: planar folds differing only in which way the arm faces, named for
  # the direction the gripper points (BACK / RIGHT / FRONT). The Z column (Axis.BASE) is omitted on
  # purpose - ``park()`` fills it from the discovered travel (3/4 of it) so one orientation works on
  # any reach; set Axis.BASE yourself to override. The gripper and rail are left untouched so parking
  # never drops a held plate or assumes a rail. Assign one to ``parking_position`` to change the park.
  PARKING_POSITION_BACK: ClassVar[JointState] = {
    Axis.SHOULDER: 90.0,
    Axis.ELBOW: 180.0,
    Axis.WRIST: 90.0,
  }
  PARKING_POSITION_RIGHT: ClassVar[JointState] = {
    Axis.SHOULDER: 0.0,
    Axis.ELBOW: 180.0,
    Axis.WRIST: 180.0,
  }
  PARKING_POSITION_FRONT: ClassVar[JointState] = {
    Axis.SHOULDER: -90.0,
    Axis.ELBOW: 180.0,
    Axis.WRIST: 270.0,
  }

  def __init__(
    self,
    host: str,
    gripper_length: float,
    gripper_z_offset: float,
    closed_gripper_position: float,
    port: int = 10100,
    timeout: int = 20,
    is_dual_gripper: bool = False,
    has_rail: bool = False,
    read_kinematics_from_device: bool = True,
    recover_out_of_range: bool = True,
    parking_position: Optional[JointState] = None,
    vision_host: Optional[str] = None,
  ) -> None:
    """
    Args:
      gripper_length: wrist-axis → TCP distance in mm. Used as the fallback /
        override; when ``read_kinematics_from_device`` is True (the default) the
        link lengths and tool length are read from the controller at setup and
        this value is only used if that read fails.
      gripper_z_offset: vertical offset in mm from the wrist plate to the tool tip.
        Depends on the mounted gripper; the concrete Device wrapper supplies a
        model-appropriate default. Always taken from here (not on the controller).
      read_kinematics_from_device: when True, read l1/l2 and the tool length from
        the controller at setup and use them for kinematics; the constructor's
        ``gripper_length`` then acts only as a fallback. Set False to force the
        constructor values regardless of what the controller reports.
      recover_out_of_range: when True (the default), an out-of-range axis (its current position
        outside its soft limit - a state the controller rejects every commanded move for, -1012) is
        driven back into range once via ``recover_axes_within_limits``, the same way at both moments
        it matters: at setup, and before a commanded move (which then retries). If it is still out of
        range after that, ``OutOfRangeOfMotionError`` propagates (no loop). Set False to forbid this
        autonomous motion - an out-of-range axis then raises instead, carrying recovery instructions.
        Every recovery is logged.
      closed_gripper_position: firmware-unit value (passed to ``GripClosePos`` /
        ``GripOpenPos``) at which the jaws are at the narrow end of
        :attr:`PreciseFlexGripper.jaw_width_range`.
        Depends on the mounted gripper. The conversion mm → firmware units is
        linear with slope 1: ``units = closed_gripper_position + (width_mm -
        jaw_width_range[0])``.
      parking_position: initial value for the public, runtime-settable ``parking_position`` that
        ``park()`` moves to. Leave None (the default) and setup fills the generic default RIGHT pose
        (planar fold, Z column at 3/4 of the discovered travel); reassign it any time to park
        elsewhere. While unset (no configuration), ``park()`` falls back to ``movetosafe``.
      vision_host: address of the PreciseVision engine, a separate machine from the controller (its
        own box with its own IP). Set it to connect to the engine, which powers both image fetch and
        engine-side discovery/introspection (what tool types, tools, processes, and projects exist).
        None leaves the engine unconnected, disabling those; the controller-side execution path
        (running processes/tools, setting properties, lighting, barcodes, stereo locate) is
        unaffected. Only consulted when setup discovers an IntelliGuide vision module.
    """
    super().__init__()
    self.io = Socket(human_readable_device_name="Precise Flex Arm", host=host, port=port)
    self.timeout = timeout
    # Serializes each request->reply exchange over the single shared controller socket; the rationale
    # (and why it is kept though uncontended today) is in _locked_exchange.
    self._io_lock = asyncio.Lock()
    self._vision_host = vision_host
    # The vision server's two connections, held here beside the controller's; None until
    # setup opens them, which it does only for a reachable `vision_host`.
    self._vision_server_io: Optional[Socket] = None
    self._vision_image_io: Optional[Socket] = None
    # The held image stream is read in chunks and a record can span reads, so a read that times out
    # mid-record leaves a partial record here, keeping the next read frame-aligned.
    self._vision_image_buf = bytearray()
    self.vision_server_timeout = 5.0
    # Nullable vision capability, built at setup when a camera gripper is present; its existence is
    # the capability gate.
    self.vision: Optional[PreciseFlexVision] = None
    self.profile_index: int = 1
    self.location_index: int = 1
    self.horizontal_compliance: bool = False
    self.horizontal_compliance_torque: int = 0
    self._has_rail = has_rail
    # Built only on an arm that has a rail; discovery decides at setup.
    self.rail: Optional[PreciseFlexRail] = PreciseFlexRail(self) if has_rail else None
    self.arm = PreciseFlexArm(self)
    self.gripper = PreciseFlexGripper(
      self, closed_gripper_position=closed_gripper_position, is_dual_gripper=is_dual_gripper
    )
    self._kinematics_params = kinematics.PF400Params(
      gripper_length=gripper_length, gripper_z_offset=gripper_z_offset
    )
    self._read_kinematics_from_device = read_kinematics_from_device
    self._recover_out_of_range = recover_out_of_range
    # Device configuration, resolved once at setup; None until then. Set before parking_position so its
    # validating setter can check assignments against the soft limits once they are known.
    self._configuration: Optional[PreciseFlexConfiguration] = None
    # Public and runtime-settable (validated on assignment); setup fills the default RIGHT pose when
    # this is left None.
    self.parking_position = parking_position
    if is_dual_gripper:
      warnings.warn(
        "Dual gripper support is experimental and may not work as expected.", UserWarning
      )

  # -- communication ---------------------------------------------------------

  def _controller_reference(self) -> Dict[str, object]:
    """The controller's identity, as structured execution events name it."""
    return {
      "name": "precise_flex",
      "type": type(self).__name__,
      "host": self.io._host,
      "port": self.io._port,
    }

  async def _locked_exchange(self, command: str) -> str:
    """Write one command and read its single reply line as one atomic, lock-held exchange.

    Why the lock: the controller exposes a single socket (port 10100 refuses a second connection), so
    every caller shares it - arm motion and the controller-relayed vision commands (``VToolProperty``,
    ``Vprocess``, ``StereoLocate``) alike. A request and its reply are correlated only by order on that
    socket, so if two coroutines' write/read pairs interleave, one reads the other's reply line. This
    lock makes each write-and-its-reply atomic, so they cannot interleave.

    No caller is concurrent today (a single async flow drives the arm), so the lock is currently
    uncontended - it is a forward guard, kept because the failure it prevents is silent
    reply-misattribution the moment anyone runs e.g. ``asyncio.gather(arm_op, vision_relay_op)``, and an
    uncontended ``asyncio.Lock`` is near-free. It is held per exchange, not across a whole move-wait, so
    commands issued while a move polls for end-of-motion still slot in between polls (the move-wait's
    emergency halt deliberately bypasses this lock - see ``_wait_for_eom``).

    This is the single choke point both reply grammars share (``send_command`` and the bare
    ``VToolProperty`` read). The trailing newline is added here; the reply line is decoded and stripped.
    """
    async with self._io_lock:
      await self.io.write(command.encode("utf-8") + b"\n")
      return (await self.io.readline()).decode("utf-8").strip()

  async def send_command(self, command: str) -> str:
    """Send a command and return the accepted ``<code> <data>`` payload.

    Writes the command and reads one reply line (as one locked exchange), then applies the standard
    acceptance gate (``_ensure_successful``): a non-zero reply code raises, otherwise the data payload
    is returned. A reply in a different grammar (e.g. PreciseVision's bare ``VToolProperty`` value)
    goes through the same ``_locked_exchange`` and is parsed by the caller instead.

    The exchange is wrapped in the firmware-command events so a command keeps its enclosing
    operation context.
    """
    event_data = {
      "device": self._controller_reference(),
      "command": command,
    }
    emit_event("precise_flex.firmware_command.started", **event_data)
    try:
      result = self._ensure_successful(await self._locked_exchange(command))
    except BaseException as error:
      emit_event(
        "precise_flex.firmware_command.failed",
        **event_data,
        error_type=type(error).__name__,
        error_message=str(error),
      )
      raise
    emit_event("precise_flex.firmware_command.completed", **event_data, response=result)
    return result

  def _ensure_successful(self, reply: str) -> str:
    """Acceptance gate for the standard ``<code> <data>`` reply: raise on a non-zero code, else return the data.

    Verifies the controller accepted the command - the leading integer reply code is ``0`` - and
    strips it, returning the rest of the line as the data payload. This is only the success check;
    interpreting the payload is a separate concern left to the caller.

    Args:
      reply: one decoded, stripped reply line.

    Returns:
      The data payload (the line with its leading reply code removed).

    Raises:
      PreciseFlexError: on an empty reply or a non-zero reply code.
    """
    if not reply:
      raise PreciseFlexError(-1, "Empty reply from device.")
    code, _, data = reply.partition(" ")
    replycode = int(code)
    if replycode != 0:
      raise PreciseFlexError(replycode, data)
    return data

  # -- vision server: the second server's two connections, held here ------------------------------

  @property
  def vision_server_connected(self) -> bool:
    """Whether setup opened the PreciseVision engine's connections."""
    return self._vision_server_io is not None

  async def _open_vision_server(self, host: str) -> None:
    """Open and hold both engine connections (property + image stream)."""
    server_io = Socket(
      human_readable_device_name="PreciseVision engine (property)",
      host=host,
      port=VISION_SERVER_PROPERTY_PORT,
    )
    image_io = Socket(
      human_readable_device_name="PreciseVision engine (image)",
      host=host,
      port=VISION_SERVER_IMAGE_PORT,
    )
    await server_io.setup()
    await image_io.setup()
    self._vision_server_io, self._vision_image_io = server_io, image_io
    self._vision_image_buf.clear()  # a fresh stream; drop anything buffered from a previous session
    logger.info(
      "[PreciseVision %s] connected: property=%s image=%s",
      host,
      VISION_SERVER_PROPERTY_PORT,
      VISION_SERVER_IMAGE_PORT,
    )

  async def _close_vision_server(self) -> None:
    """Close both engine connections, if they are open."""
    if self._vision_image_io is not None:
      await self._vision_image_io.stop()
    if self._vision_server_io is not None:
      await self._vision_server_io.stop()
    self._vision_server_io = self._vision_image_io = None

  async def send_command_to_vision_server(self, command: str) -> str:
    """Write one engine command line and return its success value, raising on an error reply.

    The engine's text protocol, beside ``send_command`` for the controller.

    Args:
      command: the full command line to send (the trailing CRLF is added here).

    Returns:
      The success value of the reply (possibly empty).

    Raises:
      RuntimeError: If the engine is not connected.
      PreciseFlexError: on a negative (error) reply.
    """
    if self._vision_server_io is None:
      raise RuntimeError("the vision server is not connected")
    await self._vision_server_io.write(command.encode("utf-8") + b"\r\n")
    reply = (await self._vision_server_io.readline()).decode("utf-8", "replace").strip()
    return parse_vision_server_reply(reply)

  async def request_vision_server_property(self, name: str) -> str:
    """Read a named engine parameter (``property get <name>``); raises on an error reply.

    Args:
      name: the engine parameter name (e.g. ``system.engineversion``, ``acq1.exposure``). May carry
        trailing positional args (e.g. ``system.cameraname 1``).

    Returns:
      The parameter value (possibly empty).
    """
    return await self.send_command_to_vision_server(f"property get {name}")

  async def _set_vision_server_property(self, name: str, value: object) -> str:
    """Write a named engine parameter (``property set <name> <value>``); raises on an error reply.

    Private: a write changes device state, so it is reached through the vision capability's vetted
    orchestrations. The same namespace carries action triggers (``system.runtool``,
    ``system.cameraacquire``).

    Args:
      name: the engine parameter name (e.g. ``acq1.exposure``, ``system.runtool``).
      value: the value to write; stringified onto the command line.

    Returns:
      The reply value (possibly empty).
    """
    return await self.send_command_to_vision_server(f"property set {name} {value}")

  async def read_next_vision_server_record(
    self, timeout: Optional[float] = None
  ) -> Optional[Tuple[str, bytes]]:
    """Read the next complete ``(name, data)`` result off the held image stream, or None at its end.

    Returns a record already buffered if there is one, otherwise reads until a whole record has
    arrived. Partial bytes from a timed-out read stay buffered, so the next call resumes frame-aligned.

    Args:
      timeout: per-read timeout in seconds; ``vision_server_timeout`` when None.

    Returns:
      The next ``(name, data)`` record, or None if the stream closed before a full record.

    Raises:
      RuntimeError: If the engine is not connected.
      TimeoutError: if no bytes arrive within ``timeout``.
      ValueError: if the stream has desynchronised (see ``_drain_named_record``).
    """
    if self._vision_image_io is None:
      raise RuntimeError("the vision server is not connected")
    buf = self._vision_image_buf
    while True:
      record = _drain_named_record(buf)
      if record is not None:
        return record
      chunk = await self._vision_image_io.read(
        65_536, timeout=self.vision_server_timeout if timeout is None else timeout
      )
      if not chunk:
        return None
      buf += chunk

  # -- lifecycle -------------------------------------------------------------

  @evented_operation(
    "precise_flex.setup",
    lambda self, skip_home=False, skip_vision=False: {
      "device": self._controller_reference(),
      "skip_home": skip_home,
      "skip_vision": skip_vision,
    },
  )
  async def setup(self, skip_home: bool = False, skip_vision: bool = False):
    """Initialize the PreciseFlex driver.

    Opens the socket connection, sets response mode to PC, powers on the
    robot, attaches it, and (optionally) homes it. Configuration discovery then reports the loaded
    TCS modules; when an IntelliGuide vision module is among them the vision capability is built and
    exposed as ``self.vision``.

    Args:
      skip_home: If True, skip the homing step during setup.
      skip_vision: If True, leave ``self.vision`` unset even when a vision module is detected.
        Mirrors STAR's ``skip_*`` setup flags.
    """
    await self.io.setup()
    await self.set_response_mode("pc")
    await self.power_on_robot()
    await self.attach(1)
    if not skip_home:
      await self.home()
    logger.debug("[PreciseFlex %s] connected: port=%s", self.io._host, self.io._port)

    await self.stop_freedrive_mode()
    # Resolve the device configuration once and adopt it as the source of truth;
    # without it the class defaults stay in place.
    try:
      self._configuration = await self._request_configuration()
    except Exception as exc:  # discovery is best-effort
      logger.warning(
        "[PreciseFlex %s] could not read configuration, using defaults: %s",
        self.io._host,
        exc,
      )
      return
    self._adopt_configuration(self._configuration)
    if self.parking_position is None:
      self.parking_position = self.PARKING_POSITION_RIGHT
    self._log_configuration_summary(self._configuration)
    self._assess_configuration(self._configuration)
    await self.arm._handle_out_of_range_axes()
    if not skip_vision and self._configuration.has_vision_module:
      await self._setup_vision(self._vision_host)

  async def _setup_vision(self, vision_host: Optional[str]) -> None:
    """Build the vision capability and connect its PreciseVision engine; best-effort, never raises.

    Called by ``setup`` once discovery has reported a camera gripper is installed - this class owns
    the connection, symmetric with how ``stop`` closes it. The controller side of vision always works;
    a set, reachable ``vision_host`` additionally opens the engine for image fetch and discovery. A
    missing or unreachable host leaves ``self.vision`` built but engine-less.

    Args:
      vision_host: address of the PreciseVision engine, or ``None`` for controller-only vision.
    """
    if vision_host:
      try:
        await self._open_vision_server(vision_host)
      except Exception as exc:  # noqa: BLE001 - a missing/unreachable engine just disables image fetch
        logger.warning(
          "[PreciseFlex %s] vision engine at %s unreachable; direct image acquisition disabled: %s",
          self.io._host,
          vision_host,
          exc,
        )
    self.vision = PreciseFlexVision(self, vision_host=vision_host)
    await self.vision.setup()  # discovers, caches, and logs the capability summary (best-effort)

  @evented_operation(
    "precise_flex.stop",
    lambda self: {"device": self._controller_reference()},
  )
  async def stop(self):
    """Stop the PreciseFlex driver."""
    await self.detach()
    await self.power_off_robot()
    await self._exit()
    await self._close_vision_server()
    await self.io.stop()
    logger.info("[PreciseFlex %s] disconnected: port=%s", self.io._host, self.io._port)

  # -- device-level commands -------------------------------------------------

  async def _exit(self) -> None:
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
    mapping: Dict[int, "PreciseFlex.ResponseMode"] = {0: "pc", 1: "verbose"}
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

  @evented_operation(
    "precise_flex.power_on",
    lambda self: {"device": self._controller_reference()},
  )
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

  @evented_operation(
    "precise_flex.recover_from_fault",
    lambda self: {"device": self._controller_reference()},
  )
  async def recover_from_fault(self) -> None:
    """Recover after a collision / fault that stopped the arm and dropped power, leaving it usable.

    A collision trips an envelope error (``-3100`` hard / ``-3122`` soft, see
    :func:`~pylabrobot.brooks.precise_flex.driver.errors.is_collision`); the servo stops the arm itself and
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

  @evented_operation(
    "precise_flex.power_off",
    lambda self: {"device": self._controller_reference()},
  )
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

  @evented_operation(
    "precise_flex.home",
    lambda self: {"device": self._controller_reference()},
  )
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

  # -- raw parameters -----------------------------------------------------------------------

  async def request_parameter(
    self,
    data_id: int,
    unit_number: Optional[int] = None,
    sub_unit: Optional[int] = None,
    array_index: Optional[int] = None,
  ) -> str:
    """Get the value of a numeric parameter database item.

    Args:
      data_id: DataID of parameter.
      unit_number: Unit number, usually the robot number (1-NROB).
      sub_unit: Sub-unit, usually 0.
      array_index: Array index.

    Returns:
      str: The numeric value of the specified database parameter.
    """
    if unit_number is not None:
      if sub_unit is not None:
        if array_index is not None:
          response = await self.send_command(f"pd {data_id} {unit_number} {sub_unit} {array_index}")
        else:
          response = await self.send_command(f"pd {data_id} {unit_number} {sub_unit}")
      else:
        response = await self.send_command(f"pd {data_id} {unit_number}")
    else:
      response = await self.send_command(f"pd {data_id}")
    return response

  async def set_parameter(
    self,
    data_id: int,
    value,
    unit_number: Optional[int] = None,
    sub_unit: Optional[int] = None,
    array_index: Optional[int] = None,
  ) -> None:
    """Change a value in the controller's parameter database.

    Args:
      data_id: DataID of parameter.
      value: New parameter value. If string, will be quoted automatically.
      unit_number: Unit number, usually the robot number (1 - N_ROB).
      sub_unit: Sub-unit, usually 0.
      array_index: Array index.

    Note:
      Updated values are not saved in flash unless a save-to-flash operation
      is performed (see DataID 901).
    """
    if unit_number is not None and sub_unit is not None and array_index is not None:
      if isinstance(value, str):
        await self.send_command(f'pc {data_id} {unit_number} {sub_unit} {array_index} "{value}"')
      else:
        await self.send_command(f"pc {data_id} {unit_number} {sub_unit} {array_index} {value}")
    else:
      if isinstance(value, str):
        await self.send_command(f'pc {data_id} "{value}"')
      else:
        await self.send_command(f"pc {data_id} {value}")

  async def set_axis_parameter(
    self,
    data_id: int,
    axis: Axis,
    value,
    robot_number: int = 1,
  ) -> None:
    """Change one joint's element of a per-axis parameter array (``pc``).

    Per-axis DataIDs (motor current limits, hard-stop homing envelope, joint limits)
    hold one value per joint; this writes a single joint's element and leaves the rest
    untouched. ``axis`` is the controller's 1-based array index (``Axis.GRIPPER`` -> 5),
    cast to int at the wire boundary; reads of the same DataID come back in this order
    (see ``_parse_per_axis``).

    Args:
      data_id: the per-axis DataID to change.
      axis: which joint's element to write.
      value: the new value for that element.
      robot_number: unit number, the robot (1 - N_ROB).

    Note:
      Volatile until a save-to-flash (DataID 901); a power cycle otherwise restores the
      flashed value.
    """
    await self.set_parameter(
      data_id, value, unit_number=robot_number, sub_unit=0, array_index=int(axis)
    )

  async def nop(self) -> None:
    """No operation command.

    Does nothing except return the standard reply. Can be used to see if the link
    is active or to check for exceptions.
    """
    await self.send_command("nop")

  # -- digital I/O --------------------------------------------------------------------------

  async def request_signal(self, signal_number: int) -> int:
    """Get the value of the specified digital input or output signal.

    Args:
      signal_number: The number of the digital signal to get.

    Returns:
      The current signal value.
    """
    response = await self.send_command(f"sig {signal_number}")
    sig_id, sig_val = response.split()
    return int(sig_val)

  async def set_signal(self, signal_number: int, value: int) -> None:
    """Set the specified digital input or output signal.

    Args:
      signal_number: The number of the digital signal to set.
      value: The signal value to set. 0 = off, non-zero = on.
    """
    await self.send_command(f"sig {signal_number} {value}")

  # -- motion primitives --------------------------------------------------------------------

  # -- speed & motion profiles --------------------------------------------------------------

  async def request_monitor_speed(self) -> int:
    """Get the global system (monitor) speed.

    Returns:
      Current monitor speed as a percentage (0-100)
    """
    response = await self.send_command("mspeed")
    return int(response)

  async def set_monitor_speed(
    self, speed_percent: Optional[int] = None, *, speed_pct: Optional[int] = None
  ) -> None:
    """Set the global system (monitor) speed.

    Args:
      speed_percent: Speed percentage between 0 and 100, where 100 means full speed.
      speed_pct: deprecated, use `speed_percent`.

    Raises:
      ValueError: If speed_percent is not between 0 and 100.
    """
    if speed_pct is not None:
      warnings.warn(
        "`speed_pct` is deprecated, use `speed_percent`.", DeprecationWarning, stacklevel=2
      )
      speed_percent = speed_pct
    if speed_percent is None:
      raise TypeError("set_monitor_speed() missing required argument: 'speed_percent'")
    if not 0 <= speed_percent <= 100:
      raise ValueError(f"speed_percent must be between 0 and 100, got {speed_percent}")
    await self.send_command(f"mspeed {speed_percent}")

  async def request_payload(self) -> int:
    """Get the payload percent value for the current robot.

    Returns:
      Current payload as a percentage of maximum (0-100)
    """
    response = await self.send_command("payload")
    return int(response)

  async def set_payload(
    self, payload_percent: Optional[int] = None, *, payload_pct: Optional[int] = None
  ) -> None:
    """Set the payload percent of maximum for the currently selected or attached robot.

    Args:
      payload_percent: Payload percentage from 0 to 100 indicating the percent of the maximum payload the robot is carrying.
      payload_pct: deprecated, use `payload_percent`.

    Raises:
      ValueError: If payload_percent is not between 0 and 100.

    Note:
      If the robot is moving, waits for the robot to stop before setting a value.
    """
    if payload_pct is not None:
      warnings.warn(
        "`payload_pct` is deprecated, use `payload_percent`.", DeprecationWarning, stacklevel=2
      )
      payload_percent = payload_pct
    if payload_percent is None:
      raise TypeError("set_payload() missing required argument: 'payload_percent'")
    if not (0 <= payload_percent <= 100):
      raise ValueError("Payload percent must be between 0 and 100")
    await self.send_command(f"payload {payload_percent}")

  async def request_profile_speed(self, profile_index: int) -> float:
    """Get the speed property of the specified profile.

    Args:
      profile_index: The profile index to query.

    Returns:
      float: The current speed as a percentage. 100 = full speed.
    """
    response = await self.send_command(f"Speed {profile_index}")
    profile, speed = response.split()
    return float(speed)

  async def set_profile_speed(
    self,
    profile_index: int,
    speed_percent: Optional[float] = None,
    *,
    speed_pct: Optional[float] = None,
  ) -> None:
    """Set the speed property of the specified profile.

    Args:
      profile_index: The profile index to modify.
      speed_percent: The new speed as a percentage (0-100). 100 = full speed.
      speed_pct: deprecated, use `speed_percent`.

    Raises:
      ValueError: If speed_percent is not between 0 and 100.
    """
    if speed_pct is not None:
      warnings.warn(
        "`speed_pct` is deprecated, use `speed_percent`.", DeprecationWarning, stacklevel=2
      )
      speed_percent = speed_pct
    if speed_percent is None:
      raise TypeError("set_profile_speed() missing required argument: 'speed_percent'")
    if not 0 <= speed_percent <= 100:
      raise ValueError(f"speed_percent must be between 0 and 100, got {speed_percent}")
    await self.send_command(f"Speed {profile_index} {speed_percent}")

  async def request_profile_speed2(self, profile_index: int) -> float:
    """Get the speed2 property of the specified profile.

    Args:
      profile_index: The profile index to query.

    Returns:
      float: The current speed2 as a percentage. Used for Cartesian moves.
    """
    response = await self.send_command(f"Speed2 {profile_index}")
    profile, speed2 = response.split()
    return float(speed2)

  async def set_profile_speed2(
    self,
    profile_index: int,
    speed2_percent: Optional[float] = None,
    *,
    speed2_pct: Optional[float] = None,
  ) -> None:
    """Set the speed2 property of the specified profile.

    Args:
      profile_index: The profile index to modify.
      speed2_percent: The new speed2 as a percentage (0-100). 100 = full speed.
        Used for Cartesian moves. Normally set to 0.
      speed2_pct: deprecated, use `speed2_percent`.

    Raises:
      ValueError: If speed2_percent is not between 0 and 100.
    """
    if speed2_pct is not None:
      warnings.warn(
        "`speed2_pct` is deprecated, use `speed2_percent`.", DeprecationWarning, stacklevel=2
      )
      speed2_percent = speed2_pct
    if speed2_percent is None:
      raise TypeError("set_profile_speed2() missing required argument: 'speed2_percent'")
    if not 0 <= speed2_percent <= 100:
      raise ValueError(f"speed2_percent must be between 0 and 100, got {speed2_percent}")
    await self.send_command(f"Speed2 {profile_index} {speed2_percent}")

  async def request_profile_acceleration(self, profile_index: int) -> float:
    """Get the acceleration property of the specified profile.

    Args:
      profile_index: The profile index to query.

    Returns:
      float: The current acceleration as a percentage. 100 = maximum acceleration.
    """
    response = await self.send_command(f"Accel {profile_index}")
    profile, acceleration = response.split()
    return float(acceleration)

  async def set_profile_acceleration(
    self,
    profile_index: int,
    acceleration_percent: Optional[float] = None,
    *,
    acceleration_pct: Optional[float] = None,
  ) -> None:
    """Set the acceleration property of the specified profile.

    Args:
      profile_index: The profile index to modify.
      acceleration_percent: The new acceleration as a percentage (0-100). 100 = maximum acceleration.
      acceleration_pct: deprecated, use `acceleration_percent`.

    Raises:
      ValueError: If acceleration_percent is not between 0 and 100.
    """
    if acceleration_pct is not None:
      warnings.warn(
        "`acceleration_pct` is deprecated, use `acceleration_percent`.",
        DeprecationWarning,
        stacklevel=2,
      )
      acceleration_percent = acceleration_pct
    if acceleration_percent is None:
      raise TypeError(
        "set_profile_acceleration() missing required argument: 'acceleration_percent'"
      )
    if not 0 <= acceleration_percent <= 100:
      raise ValueError(
        f"acceleration_percent must be between 0 and 100, got {acceleration_percent}"
      )
    await self.send_command(f"Accel {profile_index} {acceleration_percent}")

  async def request_profile_acceleration_ramp(self, profile_index: int) -> float:
    """Get the acceleration ramp property of the specified profile.

    Args:
      profile_index: The profile index to query.

    Returns:
      float: The current acceleration ramp time in seconds.
    """
    response = await self.send_command(f"AccRamp {profile_index}")
    profile, acceleration_ramp = response.split()
    return float(acceleration_ramp)

  async def set_profile_acceleration_ramp(
    self, profile_index: int, acceleration_ramp_seconds: float
  ) -> None:
    """Set the acceleration ramp property of the specified profile.

    Args:
      profile_index: The profile index to modify.
      acceleration_ramp_seconds: The new acceleration ramp time in seconds.
    """
    await self.send_command(f"AccRamp {profile_index} {acceleration_ramp_seconds}")

  async def request_profile_deceleration(self, profile_index: int) -> float:
    """Get the deceleration property of the specified profile.

    Args:
      profile_index: The profile index to query.

    Returns:
      float: The current deceleration as a percentage. 100 = maximum deceleration.
    """
    response = await self.send_command(f"Decel {profile_index}")
    profile, deceleration = response.split()
    return float(deceleration)

  async def set_profile_deceleration(
    self,
    profile_index: int,
    deceleration_percent: Optional[float] = None,
    *,
    deceleration_pct: Optional[float] = None,
  ) -> None:
    """Set the deceleration property of the specified profile.

    Args:
      profile_index: The profile index to modify.
      deceleration_percent: The new deceleration as a percentage (0-100). 100 = maximum deceleration.
      deceleration_pct: deprecated, use `deceleration_percent`.

    Raises:
      ValueError: If deceleration_percent is not between 0 and 100.
    """
    if deceleration_pct is not None:
      warnings.warn(
        "`deceleration_pct` is deprecated, use `deceleration_percent`.",
        DeprecationWarning,
        stacklevel=2,
      )
      deceleration_percent = deceleration_pct
    if deceleration_percent is None:
      raise TypeError(
        "set_profile_deceleration() missing required argument: 'deceleration_percent'"
      )
    if not 0 <= deceleration_percent <= 100:
      raise ValueError(
        f"deceleration_percent must be between 0 and 100, got {deceleration_percent}"
      )
    await self.send_command(f"Decel {profile_index} {deceleration_percent}")

  async def request_profile_deceleration_ramp(self, profile_index: int) -> float:
    """Get the deceleration ramp property of the specified profile.

    Args:
      profile_index: The profile index to query.

    Returns:
      float: The current deceleration ramp time in seconds.
    """
    response = await self.send_command(f"DecRamp {profile_index}")
    profile, deceleration_ramp = response.split()
    return float(deceleration_ramp)

  async def set_profile_deceleration_ramp(
    self, profile_index: int, deceleration_ramp_seconds: float
  ) -> None:
    """Set the deceleration ramp property of the specified profile.

    Args:
      profile_index: The profile index to modify.
      deceleration_ramp_seconds: The new deceleration ramp time in seconds.
    """
    await self.send_command(f"DecRamp {profile_index} {deceleration_ramp_seconds}")

  async def request_profile_in_range(self, profile_index: int) -> float:
    """Get the InRange property of the specified profile.

    Args:
      profile_index: The profile index to query.

    Returns:
      float: The current InRange value (-1 to 100).
      -1 = do not stop at end of motion if blending is possible
      0 = always stop but do not check end point error
      > 0 = wait until close to end point (larger numbers mean less position error allowed)
    """
    response = await self.send_command(f"InRange {profile_index}")
    profile, in_range = response.split()
    return float(in_range)

  async def set_profile_in_range(self, profile_index: int, in_range_value: float) -> None:
    """Set the InRange property of the specified profile.

    Args:
      profile_index: The profile index to modify.
      in_range_value: The new InRange value from -1 to 100.
      -1 = do not stop at end of motion if blending is possible
      0 = always stop but do not check end point error
      > 0 = wait until close to end point (larger numbers mean less position error allowed)

    Raises:
      ValueError: If in_range_value is not between -1 and 100.
    """
    if not (-1 <= in_range_value <= 100):
      raise ValueError("InRange value must be between -1 and 100")
    await self.send_command(f"InRange {profile_index} {in_range_value}")

  async def request_profile_straight(self, profile_index: int) -> bool:
    """Get the Straight property of the specified profile.

    Args:
      profile_index: The profile index to query.

    Returns:
      The current Straight property value.
      True = follow a straight-line path
      False = follow a joint-based path (coordinated axes movement)
    """
    response = await self.send_command(f"Straight {profile_index}")
    profile, straight = response.split()
    return straight == "True"

  async def set_profile_straight(self, profile_index: int, straight_mode: bool) -> None:
    """Set the Straight property of the specified profile.

    Args:
      profile_index: The profile index to modify.
      straight_mode: The path type to use.
      True = follow a straight-line path
      False = follow a joint-based path (robot axes move in coordinated manner)

    Raises:
      ValueError: If straight_mode is not True or False.
    """
    straight_int = 1 if straight_mode else 0
    await self.send_command(f"Straight {profile_index} {straight_int}")

  async def request_motion_profile_values(self, profile: int) -> MotionProfile:
    """
    Get the current motion profile values for the specified profile index on the PreciseFlex robot.

    Args:
      profile: Profile index to get values for.

    Returns:
      A :class:`MotionProfile` with the profile's speed, acceleration, ramps, InRange and path mode.
    """
    data = await self.send_command(f"Profile {profile}")
    parts = data.split(" ")
    if len(parts) != 9:
      raise PreciseFlexError(-1, "Unexpected response format from device.")
    return MotionProfile(
      int(parts[0]),
      float(parts[1]),
      float(parts[2]),
      float(parts[3]),
      float(parts[4]),
      float(parts[5]),
      float(parts[6]),
      float(parts[7]),
      int(parts[8]) != 0,
    )

  async def set_motion_profile_values(
    self,
    profile: int,
    speed_percent: Optional[float] = None,
    speed2_percent: Optional[float] = None,
    acceleration_percent: Optional[float] = None,
    deceleration_percent: Optional[float] = None,
    acceleration_ramp: Optional[float] = None,
    deceleration_ramp: Optional[float] = None,
    in_range: Optional[float] = None,
    straight: Optional[bool] = None,
    *,
    speed_pct: Optional[float] = None,
    speed2_pct: Optional[float] = None,
    acceleration_pct: Optional[float] = None,
    deceleration_pct: Optional[float] = None,
  ):
    """
    Set motion profile values for the specified profile index on the PreciseFlex robot.

    Args:
      profile: Profile index to set values for.
      speed_percent: Percentage of maximum speed (0-100). 100 = full speed.
      speed2_percent: Secondary speed setting (0-100), typically for Cartesian moves. Normally 0.
      acceleration_percent: Percentage of maximum acceleration (0-100). 100 = full acceleration.
      deceleration_percent: Percentage of maximum deceleration (0-100). 100 = full deceleration.
      acceleration_ramp: Acceleration ramp time in seconds.
      deceleration_ramp: Deceleration ramp time in seconds.
      in_range: InRange value, from -1 to 100. -1 = allow blending, 0 = stop without checking, >0 = enforce position accuracy.
      straight: If True, follow a straight-line path (-1). If False, follow a joint-based path (0).
      speed_pct: deprecated, use `speed_percent`.
      speed2_pct: deprecated, use `speed2_percent`.
      acceleration_pct: deprecated, use `acceleration_percent`.
      deceleration_pct: deprecated, use `deceleration_percent`.
    """
    if speed_pct is not None:
      warnings.warn(
        "`speed_pct` is deprecated, use `speed_percent`.", DeprecationWarning, stacklevel=2
      )
      speed_percent = speed_pct
    if speed2_pct is not None:
      warnings.warn(
        "`speed2_pct` is deprecated, use `speed2_percent`.", DeprecationWarning, stacklevel=2
      )
      speed2_percent = speed2_pct
    if acceleration_pct is not None:
      warnings.warn(
        "`acceleration_pct` is deprecated, use `acceleration_percent`.",
        DeprecationWarning,
        stacklevel=2,
      )
      acceleration_percent = acceleration_pct
    if deceleration_pct is not None:
      warnings.warn(
        "`deceleration_pct` is deprecated, use `deceleration_percent`.",
        DeprecationWarning,
        stacklevel=2,
      )
      deceleration_percent = deceleration_pct
    if (
      speed_percent is None
      or speed2_percent is None
      or acceleration_percent is None
      or deceleration_percent is None
      or acceleration_ramp is None
      or deceleration_ramp is None
      or in_range is None
      or straight is None
    ):
      arguments = {
        "speed_percent": speed_percent,
        "speed2_percent": speed2_percent,
        "acceleration_percent": acceleration_percent,
        "deceleration_percent": deceleration_percent,
        "acceleration_ramp": acceleration_ramp,
        "deceleration_ramp": deceleration_ramp,
        "in_range": in_range,
        "straight": straight,
      }
      missing = [name for name, value in arguments.items() if value is None]
      raise TypeError(f"set_motion_profile_values() missing required arguments: {missing}")
    if not 0 <= speed_percent <= 100:
      raise ValueError(f"speed_percent must be between 0 and 100, got {speed_percent}")
    if not 0 <= speed2_percent <= 100:
      raise ValueError(f"speed2_percent must be between 0 and 100, got {speed2_percent}")
    if not 0 <= acceleration_percent <= 100:
      raise ValueError(
        f"acceleration_percent must be between 0 and 100, got {acceleration_percent}"
      )
    if not 0 <= deceleration_percent <= 100:
      raise ValueError(
        f"deceleration_percent must be between 0 and 100, got {deceleration_percent}"
      )
    if acceleration_ramp < 0:
      raise ValueError("acceleration_ramp must be >= 0 (seconds).")
    if deceleration_ramp < 0:
      raise ValueError("deceleration_ramp must be >= 0 (seconds).")
    if not (-1 <= in_range <= 100):
      raise ValueError("InRange must be between -1 and 100.")
    straight_int = -1 if straight else 0
    await self.send_command(
      f"Profile {profile} {speed_percent} {speed2_percent} {acceleration_percent} {deceleration_percent} "
      f"{acceleration_ramp} {deceleration_ramp} {in_range} {straight_int}"
    )

  async def _set_speed(self, speed_percent: float):
    """Set the speed percentage of the arm's movement (0-100)."""
    await self.set_profile_speed(self.profile_index, speed_percent)

  async def _request_speed(self) -> float:
    """Get the current speed percentage of the arm's movement."""
    return await self.request_profile_speed(self.profile_index)

  # -- brakes, torque & freedrive -----------------------------------------------------------

  async def release_brake(self, axis: int) -> None:
    """Release the axis brake.

    Overrides the normal operation of the brake. It is important that the brake not be set
    while a motion is being performed. This feature is used to lock an axis to prevent
    motion or jitter.

    Args:
      axis: The number of the axis whose brake should be released.
    """
    await self.send_command(f"releaseBrake {axis}")

  async def set_brake(self, axis: int) -> None:
    """Set the axis brake.

    Overrides the normal operation of the brake. It is important not to set a brake on an
    axis that is moving as it may damage the brake or damage the motor.

    Args:
      axis: The number of the axis whose brake should be set.
    """
    await self.send_command(f"setBrake {axis}")

  async def zero_torque(self, enable: bool, axis_mask: int = 1) -> None:
    """Sets or clears zero torque mode for the selected robot.

    Individual axes may be placed into zero torque mode while the remaining axes are servoing.

    Args:
      enable: If True, enable torque mode for axes specified by axis_mask.  If False, disable torque mode for the entire robot.
      axis_mask: The bit mask specifying the axes to be placed in torque mode when enable is True.  The mask is computed by OR'ing the axis bits: 1 = axis 1, 2 = axis 2, 4 = axis 3, 8 = axis 4, etc.  Ignored when enable is False.

    Raises:
      ValueError: If ``enable`` is True and ``axis_mask`` names no axis.
    """
    if enable:
      if axis_mask <= 0:
        raise ValueError(f"axis_mask must be greater than 0, is {axis_mask}")
      await self.send_command(f"zeroTorque 1 {axis_mask}")
    else:
      await self.send_command("zeroTorque 0")

  @evented_operation(
    "precise_flex.start_freedrive",
    lambda self, free_axes=None: {
      "device": self._controller_reference(),
      "free_axes": [int(axis) for axis in free_axes] if free_axes is not None else None,
    },
  )
  async def start_freedrive_mode(self, free_axes: Optional[List[int]] = None) -> None:
    """Enter freedrive mode, allowing manual movement of the specified joints.

    The robot must be attached to enter free mode.

    Args:
      free_axes: List of joint indices to free. Use [0] for all axes.
    """
    if free_axes is None:
      # Default to the positioning axes that exist; include the rail only when
      # fitted - freemode on an absent axis returns -2800 on a no-rail arm. The
      # cached configuration is the source of truth for the installed axes; fall
      # back to the constructor hint before setup has resolved it.
      has_rail = self._configuration.has_rail if self._configuration is not None else self._has_rail
      free_axes = [Axis.BASE, Axis.SHOULDER, Axis.ELBOW, Axis.WRIST]
      if has_rail:
        free_axes.append(Axis.RAIL)
    for axis in free_axes:
      await self.send_command(f"freemode {axis}")

  @evented_operation(
    "precise_flex.stop_freedrive",
    lambda self: {"device": self._controller_reference()},
  )
  async def stop_freedrive_mode(self) -> None:
    """Exit freedrive mode for all axes."""
    await self.send_command("freemode -1")

  @evented_operation(
    "precise_flex.halt",
    lambda self: {"device": self._controller_reference()},
  )
  async def halt(self):
    """Stops the current robot immediately but leaves power on."""
    await self.send_command("halt")

  # -- gripper primitives -------------------------------------------------------------------

  async def change_config(
    self, grip_mode: int = 0, *, close_gripper_without_force_sensing: bool = False
  ) -> None:
    """Change Robot configuration from Righty to Lefty or vice versa using customizable locations.

    Uses customizable locations to avoid hitting robot during change.
    Does not include checks for collision inside work volume of the robot.
    Can be customized by user for their work cell configuration.

    Args:
      grip_mode: Gripper control mode.
      0 = do not change gripper (default)
      1 = open gripper
      2 = close gripper, which senses no force; refused unless
        ``close_gripper_without_force_sensing``.
      close_gripper_without_force_sensing: allow ``grip_mode=2``.

    Raises:
      ValueError: If ``grip_mode`` is 2 and closing without force sensing was not allowed.
    """
    if grip_mode == 2 and not close_gripper_without_force_sensing:
      raise ValueError(
        "grip_mode=2 closes the gripper without sensing force; close it with "
        "gripper.move_to_jaw_position, or pass close_gripper_without_force_sensing=True"
      )
    await self.send_command(f"ChangeConfig {grip_mode}")

  async def change_config2(
    self, grip_mode: int = 0, *, close_gripper_without_force_sensing: bool = False
  ) -> None:
    """Change Robot configuration from Righty to Lefty or vice versa using algorithm.

    Uses an algorithm to avoid hitting robot during change.
    Does not include checks for collision inside work volume of the robot.
    Can be customized by user for their work cell configuration.

    Args:
      grip_mode: Gripper control mode.
      0 = do not change gripper (default)
      1 = open gripper
      2 = close gripper, which senses no force; refused unless
        ``close_gripper_without_force_sensing``.
      close_gripper_without_force_sensing: allow ``grip_mode=2``.

    Raises:
      ValueError: If ``grip_mode`` is 2 and closing without force sensing was not allowed.
    """
    if grip_mode == 2 and not close_gripper_without_force_sensing:
      raise ValueError(
        "grip_mode=2 closes the gripper without sensing force; close it with "
        "gripper.move_to_jaw_position, or pass close_gripper_without_force_sensing=True"
      )
    await self.send_command(f"ChangeConfig2 {grip_mode}")

  async def _set_grip_detail(self):
    """Configure a default vertical station type for pick/place operations."""
    await self.send_command(f"StationType {self.location_index} 1 0 100 0 10")

  # -- identity & status reads --------------------------------------------------------------

  async def request_manufacturer(self) -> str:
    return (await self.request_parameter(DataID.MANUFACTURER)).strip()

  async def request_controller_model(self) -> str:
    return (await self.request_parameter(DataID.CONTROLLER_MODEL)).strip()

  async def request_hardware_version(self) -> str:
    return (await self.request_parameter(DataID.HARDWARE_VERSION)).strip()

  async def request_gpl_version(self) -> str:
    """Controller firmware/runtime version (distinct from ``request_version``, the TCS app)."""
    return (await self.request_parameter(DataID.GPL_VERSION)).strip()

  async def request_controller_serial(self) -> str:
    return (await self.request_parameter(DataID.CONTROLLER_SERIAL)).strip()

  async def request_robot_name(self) -> str:
    return (await self.request_parameter(DataID.ROBOT_NAME)).strip()

  async def request_robot_type(self) -> int:
    """Built-in kinematic model id (PF400 = 12)."""
    return int(_parse_scalar(await self.request_parameter(DataID.ROBOT_TYPE)))

  async def request_axis_count(self) -> int:
    """Number of servoed axes."""
    return int(_parse_scalar(await self.request_parameter(DataID.NUM_AXES)))

  async def request_extra_axis_count(self) -> int:
    """Number of non-servoed (extra) axes."""
    return int(_parse_scalar(await self.request_parameter(DataID.EXTRA_AXES)))

  async def request_axis_mask(self) -> int:
    """Capability/option bit field (rail, dual gripper, ...)."""
    return int(_parse_scalar(await self.request_parameter(DataID.AXIS_MASK)))

  async def request_version(self) -> str:
    """Get the current version of TCS and any installed plug-ins.

    Returns:
      str: The current version information.
    """
    return await self.send_command("version")

  # -- kinematics & reference limits --------------------------------------------------------

  async def request_joint_limits(self, hard: bool = False) -> Dict[Axis, tuple[float, float]]:
    """Per-axis travel limits as {Axis: (min, max)}.

    Returns the soft limits by default; pass ``hard=True`` for the hard limits.
    """
    min_id = DataID.HARD_LIMIT_MIN if hard else DataID.SOFT_LIMIT_MIN
    max_id = DataID.HARD_LIMIT_MAX if hard else DataID.SOFT_LIMIT_MAX
    return _zip_axis_ranges(
      _parse_per_axis(await self.request_parameter(min_id)),
      _parse_per_axis(await self.request_parameter(max_id)),
    )

  async def request_reference_speed(self) -> Dict[Axis, float]:
    """Per-axis rated speed at 100%; J1/J5 in mm/s, J2-J4 in deg/s."""
    return _parse_per_axis(await self.request_parameter(DataID.REFERENCE_SPEED))

  async def request_reference_acceleration(self) -> Dict[Axis, float]:
    """Per-axis rated acceleration at 100%."""
    return _parse_per_axis(await self.request_parameter(DataID.REFERENCE_ACCEL))

  async def request_link_lengths(self) -> tuple[float, float]:
    """(l1, l2) SCARA link lengths in mm: shoulder->elbow, elbow->wrist."""
    per_axis = _parse_per_axis(await self.request_parameter(DataID.LINK_LENGTHS))
    return per_axis[Axis.SHOULDER], per_axis[Axis.ELBOW]

  async def request_tool_length(self) -> float:
    """Wrist->TCP distance in mm (z of the tool-offset transform)."""
    values = [float(v) for v in (await self.request_parameter(DataID.TOOL_OFFSET)).split(",")]
    return values[2]

  async def request_kinematic_parameters(self) -> "kinematics.PF400Params":
    """Build PF400Params from the controller's stored geometry.

    Link lengths and tool length come from the device; gripper_z_offset is not on
    the controller, so it is carried over from the constructor params.
    """
    l1, l2 = await self.request_link_lengths()
    return dataclasses.replace(
      self._kinematics_params,
      l1=l1,
      l2=l2,
      gripper_length=await self.request_tool_length(),
    )

  async def request_reference_cartesian_speed(self) -> float:
    """Rated Cartesian (translational) speed at 100%, in mm/s."""
    return _parse_scalar(await self.request_parameter(DataID.REFERENCE_CARTESIAN_SPEED))

  async def request_reference_cartesian_acceleration(self) -> float:
    """Rated Cartesian (translational) acceleration at 100%, in mm/s^2."""
    return _parse_scalar(await self.request_parameter(DataID.REFERENCE_CARTESIAN_ACCEL))

  async def request_max_speed_percent(self) -> float:
    """Global cap on the speed percentage (one value, applies to all joints)."""
    return _parse_scalar(await self.request_parameter(DataID.MAX_SPEED_PERCENT))

  async def request_max_acceleration_percent(self) -> float:
    """Global cap on the acceleration percentage (one value, applies to all joints)."""
    return _parse_scalar(await self.request_parameter(DataID.MAX_ACCEL_PERCENT))

  async def request_max_deceleration_percent(self) -> float:
    """Global cap on the deceleration percentage (one value, applies to all joints)."""
    return _parse_scalar(await self.request_parameter(DataID.MAX_DECEL_PERCENT))

  # -- tool & base frame --------------------------------------------------------------------

  async def request_base(self) -> tuple[float, float, float, float]:
    """Get the robot base offset.

    Returns:
      A tuple containing (x_offset, y_offset, z_offset, z_rotation)
    """
    data = await self.send_command("base")
    parts = data.split()
    if len(parts) != 4:
      raise PreciseFlexError(-1, "Unexpected response format from base command.")
    return (float(parts[0]), float(parts[1]), float(parts[2]), float(parts[3]))

  async def set_base(
    self, x_offset: float, y_offset: float, z_offset: float, z_rotation: float
  ) -> None:
    """Set the robot base offset.

    Args:
      x_offset: Base X offset
      y_offset: Base Y offset
      z_offset: Base Z offset
      z_rotation: Base Z rotation

    Note:
      The robot must be attached to set the base.
      Setting the base pauses any robot motion in progress.
    """
    await self.send_command(f"base {x_offset} {y_offset} {z_offset} {z_rotation}")

  async def request_tool_transformation_values(
    self,
  ) -> tuple[float, float, float, float, float, float]:
    """Get the current tool transformation values.

    Returns:
      A tuple containing (X, Y, Z, yaw, pitch, roll) for the tool transformation.
    """
    data = await self.send_command("tool")
    if data.startswith("tool: "):
      data = data[6:]
    parts = data.split()
    if len(parts) != 6:
      raise PreciseFlexError(-1, "Unexpected response format from tool command.")
    x, y, z, yaw, pitch, roll = self.arm._parse_xyz_response(parts)
    return (x, y, z, yaw, pitch, roll)

  async def _set_tool_transformation_values(
    self, x: float, y: float, z: float, yaw: float, pitch: float, roll: float
  ) -> None:
    """Set the robot tool transformation (private).

    Private because the client kinematics read the tool once at setup into the frozen configuration;
    changing it live desyncs `request_gripper_pose` from the controller's `wherec` until the
    configuration is rebuilt. The robot must be attached to set the tool, and setting it pauses any
    robot motion in progress.

    Args:
      x: Tool X coordinate.
      y: Tool Y coordinate.
      z: Tool Z coordinate.
      yaw: Tool yaw rotation.
      pitch: Tool pitch rotation.
      roll: Tool roll rotation.
    """
    await self.send_command(f"tool {x} {y} {z} {yaw} {pitch} {roll}")

  # -- robot selection ----------------------------------------------------------------------

  async def reset(self, robot_number: int) -> None:
    """Reset the threads associated with the specified robot.

    Stops and restarts the threads for the specified robot. Any TCP/IP connections
    made by these threads are broken. This command can only be sent to the status thread.

    Args:
      robot_number: The number of the robot thread to reset, from 1 to N_ROB. Must not be zero.

    Raises:
      ValueError: If robot_number is zero or negative.
    """
    if robot_number <= 0:
      raise ValueError("Robot number must be greater than zero")
    await self.send_command(f"reset {robot_number}")

  async def request_selected_robot(self) -> int:
    """Get the number of the currently selected robot.

    Returns:
      The number of the currently selected robot.
    """
    response = await self.send_command("selectRobot")
    return int(response)

  async def select_robot(self, robot_number: int) -> None:
    """Change the robot associated with this communications link.

    Does not affect the operation or attachment state of the robot. The status thread
    may select any robot or 0. Except for the status thread, a robot may only be
    selected by one thread at a time.

    Args:
      robot_number: The new robot to be connected to this thread (1 to N_ROB) or 0 for none.
    """
    await self.send_command(f"selectRobot {robot_number}")

  # -- configuration discovery & adoption ---------------------------------------------------

  @property
  def configuration(self) -> "PreciseFlexConfiguration":
    """The device configuration resolved at setup. Raises before setup()."""
    if self._configuration is None:
      raise RuntimeError("Configuration is not available until setup() has run.")
    return self._configuration

  async def _request_configuration(self) -> "PreciseFlexConfiguration":
    """Read the controller's identity, axes, limits, kinematics, and envelope.

    Read-only (no motion, no homing required), so it is safe to call at setup.
    Link lengths and tool length are read from the controller; per-arm flags are
    derived from the joint set, the axis mask, and the model name.
    """
    soft_limits = await self.request_joint_limits()
    axis_mask = await self.request_axis_mask()
    robot_name = await self.request_robot_name()
    name_tokens = robot_name.split()
    suffix = name_tokens[-1].upper().lstrip("0123456789") if name_tokens else ""
    # The version command reports the TCS app version then its loaded modules.
    tcs_version, *modules = (seg.strip() for seg in (await self.request_version()).split(","))

    # Combine the per-axis 100% references with the global percent caps into the
    # effective per-joint maxima, so consumers get usable limits, not raw factors.
    reference_speed = await self.request_reference_speed()
    reference_acceleration = await self.request_reference_acceleration()
    speed_percent = await self.request_max_speed_percent()
    acceleration_percent = await self.request_max_acceleration_percent()
    deceleration_percent = await self.request_max_deceleration_percent()

    # Kinematics: read the link/tool geometry from the controller by default, so
    # the driver is correct for whichever 400 variant is plugged in; fall back to
    # the constructor params if the read fails or the override is set.
    kinematics_source: Literal["device", "provided", "default"]
    if self._read_kinematics_from_device:
      try:
        kinematic_params = await self.request_kinematic_parameters()
        kinematics_source = "device"
      except Exception as exc:
        logger.warning(
          "[PreciseFlex %s] could not read kinematics, using constructor params: %s",
          self.io._host,
          exc,
        )
        kinematic_params = self._kinematics_params
        kinematics_source = "default"
    else:
      kinematic_params = self._kinematics_params
      kinematics_source = "provided"
    reach_class = kinematics._classify_pf400_reach((kinematic_params.l1, kinematic_params.l2))
    if reach_class == "unknown":
      logger.warning(
        "[PreciseFlex %s] link lengths l1=%.1f l2=%.1f match neither the standard %s nor "
        "extended %s PF400 arm; the arm's device-stored link lengths may have been changed",
        self.io._host,
        kinematic_params.l1,
        kinematic_params.l2,
        kinematics.ARM_LINKS_STANDARD,
        kinematics.ARM_LINKS_EXTENDED,
      )

    return PreciseFlexConfiguration(
      manufacturer=await self.request_manufacturer(),
      controller_model=await self.request_controller_model(),
      hardware_version=await self.request_hardware_version(),
      gpl_version=await self.request_gpl_version(),
      controller_serial=await self.request_controller_serial(),
      robot_name=robot_name,
      robot_type=await self.request_robot_type(),
      tcs_version=tcs_version,
      modules=tuple(modules),
      num_axes=await self.request_axis_count(),
      extra_axes=await self.request_extra_axis_count(),
      axis_mask=axis_mask,
      soft_limits=soft_limits,
      hard_limits=await self.request_joint_limits(hard=True),
      max_joint_speed={a: v * speed_percent / 100 for a, v in reference_speed.items()},
      max_joint_acceleration={
        a: v * acceleration_percent / 100 for a, v in reference_acceleration.items()
      },
      max_joint_deceleration={
        a: v * deceleration_percent / 100 for a, v in reference_acceleration.items()
      },
      max_cartesian_speed=(await self.request_reference_cartesian_speed()) * speed_percent / 100,
      max_cartesian_acceleration=(await self.request_reference_cartesian_acceleration())
      * acceleration_percent
      / 100,
      power_state=await self.request_system_state(),
      kinematics=kinematic_params,
      kinematics_source=kinematics_source,
      has_rail=Axis.RAIL in soft_limits,
      is_dual_gripper=bool(axis_mask & 0x80),
      is_vision_gripper=suffix[:1] == "V",
      reach_class=reach_class,
    )

  def _adopt_configuration(self, config: "PreciseFlexConfiguration") -> None:
    """Adopt the discovered configuration as the source of truth for later commands.

    The gripper width limits come from the gripper-axis soft limits, IK/FK use the
    device link lengths, and the rail / dual-gripper command paths follow the axes
    the controller actually reports.
    """
    self.gripper._adopt_configuration(config)
    self._kinematics_params = config.kinematics
    self._has_rail = config.has_rail
    self.rail = (self.rail or PreciseFlexRail(self)) if config.has_rail else None

  def _assess_configuration(self, config: "PreciseFlexConfiguration") -> None:
    """Warn about an unsupported model, a missing TCS module, or an untested combo.

    The kinematics is the PreciseFlex 400 geometry, so a different model would get
    wrong joint targets; a missing module (e.g. PARobot) is the usual ``-2805``
    cause; an unlisted full configuration is allowed but flagged for reporting.
    """
    host = self.io._host
    if not is_supported_model(config.robot_type):
      logger.warning(
        "[PreciseFlex %s] robot_type %s is not a model this driver's kinematics "
        "supports (%s); move_to/work_envelope may be wrong.",
        host,
        config.robot_type,
        ", ".join(SUPPORTED_ROBOT_TYPES.values()),
      )
    for module, provides, project in missing_required_modules(config.modules):
      logger.warning(
        "[PreciseFlex %s] the '%s' module (%s) is not loaded; install the '%s' TCS "
        "project (obtain it from Brooks Automation) and restart it.",
        host,
        module,
        provides,
        project,
      )
    if not is_confirmed(config.robot_type, config.gpl_version, config.tcs_version, config.modules):
      logger.info(
        "[PreciseFlex %s] this software stack has not been tested with this driver. "
        "If the arm works correctly, please add the following entry to "
        "CONFIRMED_FIRMWARE_VERSIONS in pylabrobot/brooks/confirmed_firmware_versions.py "
        "and open a pull request so other users benefit:\n%s",
        host,
        suggest_entry(config.robot_type, config.gpl_version, config.tcs_version, config.modules),
      )

  def _log_configuration_summary(self, config: "PreciseFlexConfiguration") -> None:
    """Log a single structured summary of the discovered device: name, connection,
    firmware, this unit's configuration, and the resulting capabilities."""
    io = self.io
    axes = f"{config.num_axes} axes" + (" + rail" if config.has_rail else "")
    grippers = [
      label
      for present, label in (
        (config.is_dual_gripper, "dual gripper"),
        (config.is_vision_gripper, "vision gripper"),
      )
      if present
    ]
    gripper_note = (", " + ", ".join(grippers)) if grippers else ""
    logger.info(
      "[%s] Connected on %s:%s\n"
      "  Firmware: GPL %s, TCS %s\n"
      "  Configuration: %s, robot_type %s, %s%s\n"
      "  Capabilities: %s reach (l1=%.1f, l2=%.1f mm), modules: %s",
      config.robot_name or config.controller_model or "PreciseFlex",
      io._host,
      io._port,
      config.gpl_version,
      config.tcs_version,
      config.controller_model,
      config.robot_type,
      axes,
      gripper_note,
      config.reach_class,
      config.kinematics.l1,
      config.kinematics.l2,
      ", ".join(config.modules),
    )

  # -- homing & range recovery --------------------------------------------------------------

  async def _is_robot_homed(self) -> bool:
    """Whether all axes are homed (DataID 2800).

    Homing is lost on every power cycle (incremental encoders), and until it is redone
    the controller blocks commanded motion (-1021) and reports unreliable positions.
    """
    return _parse_scalar(await self.request_parameter(DataID.ROBOT_HOMED)) == 1.0

  # -- joint-space motion -------------------------------------------------------------------

  # -- cartesian motion ---------------------------------------------------------------------

  # -- pick & place -------------------------------------------------------------------------

  @evented_operation(
    "precise_flex.pick_up_at_joint_position",
    lambda self, position, resource_width, finger_speed_percent=None, grasp_force=None, finger_speed_pct=None: {
      "device": self._controller_reference(),
      "target_joint_position": _joint_state_reference(position),
      "resource_width": float(resource_width),
      "finger_speed_percent": float(
        next(
          value
          for value in (
            finger_speed_pct,
            finger_speed_percent,
            self.gripper.default_finger_speed_percent,
          )
          if value is not None
        )
      ),
      "grasp_force": float(
        self.gripper.default_grasp_force if grasp_force is None else grasp_force
      ),
    },
  )
  async def pick_up_at_joint_position(
    self,
    position: JointState,
    resource_width: float,
    finger_speed_percent: Optional[float] = None,
    grasp_force: Optional[float] = None,
    *,
    finger_speed_pct: Optional[float] = None,
  ) -> None:
    """Pick up at the specified joint position.

    Args:
      position: Joint state to pick from.
      resource_width: Width of the resource to grasp, in mm.
      finger_speed_percent: Finger closing speed as a percentage (0-100).
        ``default_finger_speed_percent`` when None.
      grasp_force: Grasp force in Newtons. ``default_grasp_force`` when None.
      finger_speed_pct: deprecated, use `finger_speed_percent`.
    """
    if finger_speed_pct is not None:
      warnings.warn(
        "`finger_speed_pct` is deprecated, use `finger_speed_percent`.",
        DeprecationWarning,
        stacklevel=3,
      )
      finger_speed_percent = finger_speed_pct
    if finger_speed_percent is None:
      finger_speed_percent = self.gripper.default_finger_speed_percent
    if grasp_force is None:
      grasp_force = self.gripper.default_grasp_force
    logger.info(
      "[PreciseFlex %s] pick_up: joints=%s, resource_width_mm=%s",
      self.io._host,
      position,
      resource_width,
    )
    await self.gripper._set_grasp_data(
      plate_width=resource_width,
      finger_speed_percent=finger_speed_percent,
      grasp_force=grasp_force,
    )
    await self._pick_plate_j(position)

  @evented_operation(
    "precise_flex.drop_at_joint_position",
    lambda self, position, resource_width: {
      "device": self._controller_reference(),
      "target_joint_position": _joint_state_reference(position),
      "resource_width": float(resource_width),
    },
  )
  async def drop_at_joint_position(
    self,
    position: JointState,
    resource_width: float,
  ) -> None:
    """Drop at the specified joint position.

    Args:
      position: Joint state to drop at.
      resource_width: Width of the held resource, in mm.
    """
    logger.info(
      "[PreciseFlex %s] drop: joints=%s, resource_width_mm=%s",
      self.io._host,
      position,
      resource_width,
    )
    await self._place_plate_j(position)

  @evented_operation(
    "precise_flex.pick_up_at_location",
    lambda self, location, direction, resource_width, finger_speed_percent=None, grasp_force=None, orientation=None, wrist=None, rail_position=None, finger_speed_pct=None: {
      "device": self._controller_reference(),
      "target": _cartesian_target_reference(
        location,
        direction,
        orientation=orientation,
        wrist=wrist,
        rail_position=rail_position,
      ),
      "resource_width": float(resource_width),
      "finger_speed_percent": float(
        next(
          value
          for value in (
            finger_speed_pct,
            finger_speed_percent,
            self.gripper.default_finger_speed_percent,
          )
          if value is not None
        )
      ),
      "grasp_force": float(
        self.gripper.default_grasp_force if grasp_force is None else grasp_force
      ),
    },
  )
  async def pick_up_at_location(
    self,
    location: Coordinate,
    direction: float,
    resource_width: float,
    finger_speed_percent: Optional[float] = None,
    grasp_force: Optional[float] = None,
    orientation: Optional[ElbowOrientation] = None,
    wrist: Optional[Wrist] = None,
    rail_position: Optional[float] = None,
    *,
    finger_speed_pct: Optional[float] = None,
  ) -> None:
    """Pick up at the specified Cartesian location.

    Args:
      location: Cartesian location to pick from.
      direction: Approach direction, applied as the pose's z rotation in degrees.
      resource_width: Width of the resource to grasp, in mm.
      finger_speed_percent: Finger closing speed as a percentage (0-100).
        ``default_finger_speed_percent`` when None.
      grasp_force: Grasp force in Newtons. ``default_grasp_force`` when None.
      orientation: Elbow orientation (``"lefty"`` or ``"righty"``). If None, the robot
        picks the closest configuration.
      wrist: Wrist configuration. If None, the robot picks the closest configuration.
      rail_position: Linear rail position in mm. Required when the arm has a rail.
      finger_speed_pct: deprecated, use `finger_speed_percent`.
    """
    if finger_speed_pct is not None:
      warnings.warn(
        "`finger_speed_pct` is deprecated, use `finger_speed_percent`.",
        DeprecationWarning,
        stacklevel=3,
      )
      finger_speed_percent = finger_speed_pct
    if finger_speed_percent is None:
      finger_speed_percent = self.gripper.default_finger_speed_percent
    if grasp_force is None:
      grasp_force = self.gripper.default_grasp_force
    logger.info(
      "[PreciseFlex %s] pick_up: x=%s, y=%s, z=%s, direction=%s, resource_width_mm=%s",
      self.io._host,
      location.x,
      location.y,
      location.z,
      direction,
      resource_width,
    )
    if rail_position is not None:
      await self.arm._require_rail().move_rail(rail_position)
    elif self._has_rail:
      raise ValueError(
        "rail_position must be specified for pick_up_at_location when using a rail-equipped arm."
      )
    coords = PreciseFlexCartesianPose(
      location=location,
      rotation=Rotation(z=direction),
      orientation=orientation,
      wrist=wrist,
    )
    await self.gripper._set_grasp_data(
      plate_width=resource_width,
      finger_speed_percent=finger_speed_percent,
      grasp_force=grasp_force,
    )
    await self._pick_plate_c(cartesian_position=coords)

  @evented_operation(
    "precise_flex.drop_at_location",
    lambda self, location, direction, resource_width, orientation=None, wrist=None, rail_position=None: {
      "device": self._controller_reference(),
      "target": _cartesian_target_reference(
        location,
        direction,
        orientation=orientation,
        wrist=wrist,
        rail_position=rail_position,
      ),
      "resource_width": float(resource_width),
    },
  )
  async def drop_at_location(
    self,
    location: Coordinate,
    direction: float,
    resource_width: float,
    orientation: Optional[ElbowOrientation] = None,
    wrist: Optional[Wrist] = None,
    rail_position: Optional[float] = None,
  ) -> None:
    """Drop at the specified Cartesian location.

    Args:
      location: Cartesian location to drop at.
      direction: Approach direction, applied as the pose's z rotation in degrees.
      resource_width: Width of the held resource, in mm.
      orientation: Elbow orientation (``"lefty"`` or ``"righty"``). If None, the robot
        picks the closest configuration.
      wrist: Wrist configuration. If None, the robot picks the closest configuration.
      rail_position: Linear rail position in mm. Required when the arm has a rail.
    """
    logger.info(
      "[PreciseFlex %s] drop: x=%s, y=%s, z=%s, direction=%s, resource_width_mm=%s",
      self.io._host,
      location.x,
      location.y,
      location.z,
      direction,
      resource_width,
    )
    if rail_position is not None:
      await self.arm._require_rail().move_rail(rail_position)
    elif self._has_rail:
      raise ValueError(
        "rail_position must be specified for drop_at_location when using a rail-equipped arm."
      )
    coords = PreciseFlexCartesianPose(
      location=location,
      rotation=Rotation(z=direction),
      orientation=orientation,
      wrist=wrist,
    )
    await self._place_plate_c(cartesian_position=coords)

  async def _pick_plate_j(self, joint_position: JointState):
    """Pick a plate from the specified position using joint coordinates."""
    await self.arm._set_joint_angles(self.location_index, joint_position)
    await self._set_grip_detail()
    horizontal_compliance_int = 1 if self.horizontal_compliance else 0
    ret_code = await self.send_command(
      f"pickplate {self.location_index} {horizontal_compliance_int} {self.horizontal_compliance_torque}"
    )
    if ret_code == "0":
      raise PreciseFlexError(-1, "the force-controlled gripper detected no plate present.")

  async def _place_plate_j(self, joint_position: JointState):
    """Place a plate at the specified position using joint coordinates."""
    await self.arm._set_joint_angles(self.location_index, joint_position)
    await self._set_grip_detail()
    horizontal_compliance_int = 1 if self.horizontal_compliance else 0
    await self.send_command(
      f"placeplate {self.location_index} {horizontal_compliance_int} {self.horizontal_compliance_torque}"
    )

  async def _pick_plate_c(self, cartesian_position: PreciseFlexCartesianPose):
    """Pick a plate at a Cartesian position via IK + joint-space pickplate."""
    joints = await self.arm._cart_to_joints(cartesian_position)
    await self._pick_plate_j(joints)

  async def _place_plate_c(self, cartesian_position: PreciseFlexCartesianPose):
    """Place a plate at a Cartesian position via IK + joint-space placeplate."""
    joints = await self.arm._cart_to_joints(cartesian_position)
    await self._place_plate_j(joints)

  # -- parking ------------------------------------------------------------------------------

  @property
  def parking_position(self) -> Optional[JointState]:
    """The pose ``park()`` moves to. Assign one of the ``PARKING_POSITION_BACK/RIGHT/FRONT`` class
    constants or any JointState; the assignment is validated (keys must be ``Axis`` members, values must
    be within the soft limits once the configuration is known). None until setup, where it defaults to
    ``PARKING_POSITION_RIGHT``. A pose that omits ``Axis.BASE`` has its Z filled at park time."""
    return self._parking_position

  @parking_position.setter
  def parking_position(self, position: Optional[JointState]) -> None:
    if position is not None:
      self._validate_parking_position(position)
    self._parking_position: Optional[JointState] = dict(position) if position is not None else None

  @evented_operation(
    "precise_flex.park",
    lambda self: {"device": self._controller_reference()},
  )
  async def park(self) -> None:
    """Move to ``self.parking_position``; defaults at setup, reassignable at runtime.

    ``parking_position`` is filled at setup with ``PARKING_POSITION_RIGHT`` (a planar fold facing
    right, Z column at 3/4 of its discovered travel); assign one of the ``PARKING_POSITION_*`` class
    constants or any JointState to park elsewhere. Falls back to the firmware ``movetosafe`` while it is
    unset. No collision checks against 3rd-party obstacles.
    """
    if self.parking_position is not None:
      await self.arm.move_to_joint_position(
        position=self._parking_pose_with_default_z(self.parking_position)
      )
    else:
      await self.send_command("movetosafe")

  def _validate_parking_position(self, position: JointState) -> None:
    """Reject anything that is not a JointState of in-range axes (limits checked once known)."""
    if not isinstance(position, dict) or not position:
      raise ValueError(f"parking_position must be a non-empty JointState, got {position!r}")
    for axis, value in position.items():
      if not isinstance(axis, Axis):
        raise ValueError(f"parking_position keys must be Axis members, got {axis!r}")
      if not isinstance(value, (int, float)):
        raise ValueError(f"parking_position[{axis.name}] must be a number, got {value!r}")
      if self._configuration is not None:
        lo, hi = self._configuration.soft_limits[axis]
        if not lo <= value <= hi:
          raise ValueError(
            f"parking_position[{axis.name}]={value} is outside the soft limits [{lo}, {hi}]"
          )

  def _parking_pose_with_default_z(self, position: JointState) -> JointState:
    """Fill the Z column (``Axis.BASE``) at 3/4 of the discovered travel when the pose omits it."""
    if Axis.BASE in position or self._configuration is None:
      return position
    _, z_max = self._configuration.z_range
    return {Axis.BASE: 0.75 * z_max, **position}
