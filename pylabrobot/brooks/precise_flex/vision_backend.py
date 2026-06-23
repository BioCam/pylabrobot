"""IntelliGuide vision capability for a PreciseFlex with a camera gripper.

Folds the GPL vision wire primitives (``VToolProperty``, ``Vprocess``, ``VresultInfoString``,
``LightControl``) together with the higher-level orchestrations, over the pure-transport
``PreciseFlexDriver``. Intended to be held as the nullable ``driver.vision``, built at setup only
when a camera gripper is present - so its existence is the capability gate (no per-method guards).
Only ``locate_target`` moves the arm.

Password-free engine image retrieval (``request_camera_image``) and vision-project enumeration use
the separate PreciseVision engine protocol rather than the TCS controller, and are added on top of
this module.
"""

import functools
from dataclasses import dataclass, field
from typing import Awaitable, Callable, Dict, List, Literal, Optional, TypeVar, Union, cast

from pylabrobot.resources import Coordinate, Rotation

from .driver import PreciseFlexDriver
from .errors import PreciseFlexError
from .kinematics import PreciseFlexCartesianPose
from .vision_driver import PreciseVisionDriver


@dataclass
class StereoParameters:
  """IntelliGuide stereo-locator configuration for one robot/camera pair.

  Read with ``request_stereo_parameters`` (``StereoParam`` get) and written with
  ``set_stereo_parameters`` (set). The dual-ArUco stereo locator uses these to find a
  target; the fields and their order mirror the controller's ``StereoParam`` reply.
  Requires the IntelliGuide vision module.
  """

  process_name: str
  tool_name: str
  optimum_distance_to_target: float
  optimum_window_scale_factor: float
  wrist_axis_index: int
  aruco1_number: int
  aruco2_number: int
  distance_between_arucos: float
  max_aruco_distance_estimate_error: float
  wait_msecs: int

  @classmethod
  def from_reply(cls, reply: str) -> "StereoParameters":
    """Parse a ``StereoParam`` get reply: 10 space-separated fields in field order.

    The process and tool names are assumed single tokens (no embedded spaces); the
    wire format requires this since the controller space-joins the fields.
    """
    fields = reply.split()
    if len(fields) != 10:
      raise ValueError(f"expected 10 stereo-parameter fields, got {len(fields)}: {reply!r}")
    return cls(
      process_name=fields[0],
      tool_name=fields[1],
      optimum_distance_to_target=float(fields[2]),
      optimum_window_scale_factor=float(fields[3]),
      wrist_axis_index=int(float(fields[4])),
      aruco1_number=int(float(fields[5])),
      aruco2_number=int(float(fields[6])),
      distance_between_arucos=float(fields[7]),
      max_aruco_distance_estimate_error=float(fields[8]),
      wait_msecs=int(float(fields[9])),
    )

  def to_command_args(self) -> str:
    """The 10 fields as the space-separated argument string for ``StereoParam`` set."""
    return (
      f"{self.process_name} {self.tool_name} "
      f"{self.optimum_distance_to_target} {self.optimum_window_scale_factor} "
      f"{self.wrist_axis_index} {self.aruco1_number} {self.aruco2_number} "
      f"{self.distance_between_arucos} {self.max_aruco_distance_estimate_error} "
      f"{self.wait_msecs}"
    )


@dataclass
class CameraInfo:
  """Discovered facts about one engine camera."""

  name: Optional[str] = None
  type: Optional[str] = None
  width: Optional[int] = None
  height: Optional[int] = None
  resolutions: List[str] = field(default_factory=list)


@dataclass
class VisionToolInfo:
  """A discovered tool instance: its name, type (the EntryType class), and property names."""

  name: str
  type: Optional[str]
  properties: List[str] = field(default_factory=list)


@dataclass
class VisionConfiguration:
  """A snapshot of the PreciseVision engine's capabilities, discovered once at setup and cached.

  ``discovered`` is False when no engine was configured (no ``vision_host``), leaving the other
  fields empty. ``tool_types`` is the fixed compiled palette (what the engine can instantiate);
  ``tools`` are the instances in the active project, each with its type and property names. Populated
  by ``PreciseFlexVisionBackend.discover_configuration`` from the engine ``request_*`` reads.
  """

  discovered: bool = False
  vision_version: Optional[str] = None
  licensed: bool = False
  vision_tool_types: List[str] = field(default_factory=list)
  projects: List[str] = field(default_factory=list)
  active_project: Optional[str] = None
  processes: List[str] = field(default_factory=list)
  vision_tools: Dict[str, VisionToolInfo] = field(default_factory=dict)
  cameras: Dict[int, CameraInfo] = field(default_factory=dict)

  def has_vision_tool(self, name: str) -> bool:
    """Whether a tool instance is present in the active project."""
    return name in self.vision_tools

  def has_vision_tool_type(self, tool_type: str) -> bool:
    """Whether the engine can instantiate a tool type (it is in the fixed palette)."""
    return tool_type in self.vision_tool_types

  def to_dict(self) -> Dict[str, object]:
    """Return a plain-dict snapshot for recording/serialising the discovered configuration."""
    return {
      "discovered": self.discovered,
      "vision_version": self.vision_version,
      "licensed": self.licensed,
      "vision_tool_types": list(self.vision_tool_types),
      "projects": list(self.projects),
      "active_project": self.active_project,
      "processes": list(self.processes),
      "vision_tools": {
        n: {"type": t.type, "properties": list(t.properties)} for n, t in self.vision_tools.items()
      },
      "cameras": {cam: vars(info) for cam, info in self.cameras.items()},
    }


F = TypeVar("F", bound=Callable[..., Awaitable[object]])


def requires_vision_tool_type(tool_type: str) -> Callable[[F], F]:
  """Gate a method on the engine providing a compiled tool type (a hard, unfixable requirement).

  When discovery has run (``self.configuration.discovered``) and the type is absent, raise - the type
  is compiled into the engine and cannot be added by PLR. Before discovery (no engine configured) the
  gate is a no-op so the method runs, matching the rest of the capability model.
  """

  def decorator(func: F) -> F:
    @functools.wraps(func)
    async def wrapper(self: "PreciseFlexVisionBackend", *args: object, **kwargs: object) -> object:
      config = self.configuration
      if config.discovered and not config.has_vision_tool_type(tool_type):
        raise RuntimeError(
          f"{func.__name__} requires the '{tool_type}' vision tool type, which this engine does not "
          f"provide (available: {', '.join(config.vision_tool_types) or 'none'})"
        )
      return await func(self, *args, **kwargs)

    return cast(F, wrapper)

  return decorator


def requires_vision_tool(name: str, *, tool_type: Optional[str] = None) -> Callable[[F], F]:
  """Gate a method on a tool instance being present in the active project (a soft requirement).

  When discovery has run and the tool is absent, the outcome depends on its type (the third state
  beyond present/unsupported): if ``tool_type`` is in the engine's palette the gap is provisionable
  and the error says so; otherwise it is unsupported. Before discovery the gate is a no-op.
  """

  def decorator(func: F) -> F:
    @functools.wraps(func)
    async def wrapper(self: "PreciseFlexVisionBackend", *args: object, **kwargs: object) -> object:
      config = self.configuration
      if config.discovered and not config.has_vision_tool(name):
        if tool_type is not None and config.has_vision_tool_type(tool_type):
          raise RuntimeError(
            f"{func.__name__} requires tool '{name}', absent from project "
            f"{config.active_project!r}, but its type '{tool_type}' is available - provision it or "
            f"load a project that defines it"
          )
        detail = f"; type '{tool_type}' is not available on this engine" if tool_type else ""
        raise RuntimeError(f"{func.__name__} requires tool '{name}', not present{detail}")
      return await func(self, *args, **kwargs)

    return cast(F, wrapper)

  return decorator


class PreciseFlexVisionBackend:
  """IntelliGuide vision capability for a PreciseFlex with a camera gripper.

  Built at setup only when a camera gripper is present, so its existence is the capability gate
  (no per-method guards). The wire primitives translate GPL vision commands over the driver's
  transport; the orchestrations compose them. Only ``locate_target`` moves the arm. ``available``
  caches the project enumeration when present (else ``None``).
  """

  def __init__(
    self,
    driver: PreciseFlexDriver,
    available: Optional[Dict[str, List[str]]] = None,
    vision_host: Optional[str] = None,
    vision_driver: Optional[PreciseVisionDriver] = None,
  ):
    self.driver = driver
    self.available = available
    self._vision_host = vision_host
    self.vision_driver = vision_driver
    self.configuration = VisionConfiguration()  # populated by discover_configuration() at setup

  # -- low-level wire primitives -------------------------------------------

  async def vtool_property(self, tool: str, property_name: str, value: Optional[str] = None) -> str:
    """``VToolProperty`` read (no value) or write (value given); no arm motion.

    A read returns the BARE property value (PreciseVision does not prefix it with the usual
    ``<code> <data>``), so it is read raw and a negative reply is raised as a PreciseFlexError.
    A write goes through the normal reply parser. ``value`` must not contain spaces.
    """
    if value is not None:
      return await self.driver.send_command(f"VToolProperty {tool} {property_name} {value}")
    reply = await self.driver.query_raw(f"VToolProperty {tool} {property_name}")
    if reply.startswith("-") and reply[1:].isdigit():
      raise PreciseFlexError(int(reply), "")
    return reply

  async def run_vision_process(self, name: str) -> str:
    """Run a vision process - the whole assembled tool pipeline (``Vprocess <name>``); no arm motion.

    Controller-side (TCS): runs every tool in the named process in order. To run a single tool, use
    the engine's ``run_vision_tool`` instead. Returns the reply.
    """
    return await self.driver.send_command(f"Vprocess {name}")

  async def vresult_info_string(
    self, tool: Optional[str] = None, index: Optional[int] = None
  ) -> str:
    """``VresultInfoString`` - a result's text result (e.g. a decoded barcode), or the last result.

    ``tool`` and 1-based ``index`` are given together or both omitted. The wire pads the value
    with a leading space, which is stripped.
    """
    if (tool is None) != (index is None):
      raise ValueError("tool and index must be given together, or both omitted")
    suffix = f" {tool} {index}" if tool is not None else ""
    return (await self.driver.send_command(f"VresultInfoString{suffix}")).strip()

  def _require_engine(self) -> PreciseVisionDriver:
    """The held engine client, or a clear error if none was configured at setup."""
    if self.vision_driver is None:
      raise RuntimeError(
        "no PreciseVision engine configured - pass vision_host at setup to use this method"
      )
    return self.vision_driver

  # -- engine session & discovery ------------------------------------------

  async def request_camera_count(self) -> int:
    """Number of cameras PreciseVision sees (``System.CameraCount``); read-only, no motion."""
    return int(await self.vtool_property("System", "CameraCount"))

  async def request_projects(self) -> List[str]:
    """List all projects on the engine."""
    return await self._require_engine().request_projects()

  async def request_project_name(self) -> Optional[str]:
    """Return the active project's name."""
    return await self._require_engine().request_project_name()

  async def discover_configuration(self) -> VisionConfiguration:
    """Discover the engine's capabilities once and cache them on ``self.configuration``; no motion.

    Reads the tool-type palette, projects, active project, processes, each tool's type and property
    names, and per-camera info via the engine ``request_*`` calls (all read-only). Returns an
    undiscovered (empty) configuration when no engine was configured at setup.
    """
    engine = self.vision_driver
    if engine is None:
      self.configuration = VisionConfiguration(discovered=False)
      return self.configuration
    tools: Dict[str, VisionToolInfo] = {}
    for name in await engine.request_vision_tools():
      tools[name] = VisionToolInfo(
        name=name,
        type=await engine.request_vision_tool_type(name),
        properties=await engine.request_vision_tool_properties(name),
      )
    cameras: Dict[int, CameraInfo] = {}
    for cam in range(1, await engine.request_camera_count() + 1):
      cameras[cam] = CameraInfo(
        name=await engine.request_camera_name(cam),
        type=await engine.request_camera_type(cam),
        width=await engine.request_camera_width(cam),
        height=await engine.request_camera_height(cam),
        resolutions=await engine.request_camera_resolutions(cam),
      )
    self.configuration = VisionConfiguration(
      discovered=True,
      vision_version=await engine.request_vision_version(),
      licensed=await engine.request_is_licensed(),
      vision_tool_types=await engine.request_vision_tool_types(),
      projects=await engine.request_projects(),
      active_project=await engine.request_project_name(),
      processes=await engine.request_processes(),
      vision_tools=tools,
      cameras=cameras,
    )
    return self.configuration

  # -- vision tools --------------------------------------------------------

  async def request_vision_tool_property(self, tool: str, property_name: str) -> Optional[str]:
    """Read one tool property value off the engine."""
    return await self._require_engine().request_vision_tool_property(tool, property_name)

  async def request_vision_tool_properties(self, tool: str) -> List[str]:
    """List one tool's property names."""
    return await self._require_engine().request_vision_tool_properties(tool)

  async def request_vision_tool_types(self) -> List[str]:
    """List the engine's fixed palette of tool types."""
    return await self._require_engine().request_vision_tool_types()

  async def set_vision_tool_property(
    self, tool: str, property_name: str, value: object, *, apply: bool = True
  ) -> None:
    """Write a tool property and, by default, run the tool so it takes effect on the device."""
    await self._require_engine().set_vision_tool_property(tool, property_name, value, apply=apply)

  async def run_vision_tool(self, tool: str) -> None:
    """Run one vision tool on the engine (applies its settings + acquires); see PreciseVisionDriver."""
    await self._require_engine().run_vision_tool(tool)

  # -- lighting ------------------------------------------------------------

  async def set_lighting(
    self,
    camera: Union[Literal["front", "bottom"], int] = "front",
    *,
    brightness: int = 100,
    delay: Optional[int] = None,
    light_tool: str = "led",
    light_process: str = "LightControl",
  ) -> None:
    """Set the camera LED bank/brightness and apply it; ``brightness=0`` turns the LEDs off."""
    await self.start_led(
      camera,
      brightness=brightness,
      delay=delay,
      light_tool=light_tool,
      light_process=light_process,
    )

  @requires_vision_tool_type("LightControl")
  async def start_led(
    self,
    camera: Union[Literal["front", "bottom"], int] = "front",
    *,
    brightness: int = 100,
    delay: Optional[int] = None,
    light_tool: str = "led",
    light_process: str = "LightControl",
  ) -> None:
    """Turn on the IntelliGuide camera lighting (LightControl vision tool); no arm motion.

    Sets the named LightControl tool's LED bank and brightness, then runs the process that
    contains it to apply the change.

    Args:
      camera: which integrated LED source - ``"front"``/``1`` or ``"bottom"``/``2``. Drives the
        tool's LED Bank (1 = front-facing, 2 = bottom-facing).
      brightness: LED brightness 0-100 (PWM duty); ``0`` turns the LEDs off.
      delay: optional light time delay in milliseconds.
      light_tool: the LightControl tool name in the loaded vision project.
      light_process: the process containing ``light_tool``, run to apply the settings.
    """
    bank = {"front": 1, "bottom": 2, 1: 1, 2: 2}.get(camera)
    if bank is None:
      raise ValueError(f"camera must be 'front'/1 or 'bottom'/2, got {camera!r}")
    if not 0 <= brightness <= 100:
      raise ValueError(f"brightness must be 0-100, got {brightness}")
    await self.vtool_property(light_tool, "Bank", str(bank))
    await self.vtool_property(light_tool, "Brightness", str(brightness))
    if delay is not None:
      await self.vtool_property(light_tool, "Delay", str(delay))
    await self.run_vision_process(light_process)

  # -- camera image --------------------------------------------------------

  @requires_vision_tool_type("Acquire")
  async def set_camera_setting(self, camera: int, setting: str, value: object) -> None:
    """Set one acquire-tool camera knob and apply it to the camera; no arm motion.

    Writes ``acq<camera>.<setting>`` (brightness/hue/gain/exposure/...) and runs the acquire tool so
    the change reaches the DirectShow camera - a bare write only stores it. The live stream then
    reflects it.
    """
    await self._require_engine().set_vision_tool_property(
      f"acq{camera}", setting, value, apply=True
    )

  async def request_camera_image(self, camera: int = 1) -> Optional[bytes]:
    """Fetch one JPEG frame for ``camera`` directly off the PreciseVision engine, no motion.

    Delegates to the held engine client (``engine``); returns ``None`` if no engine was configured
    (no ``vision_host`` at setup). The frame is the full-resolution JPEG; decode at the call
    site. For a saved file instead, use ``capture_image`` (written on the engine host).
    """
    if self.vision_driver is None:
      return None
    return await self.vision_driver.request_camera_image(camera)

  @requires_vision_tool_type("Acquire")
  async def capture_image(
    self,
    process_name: str,
    acquire_tool: str,
    acquire_prefix: Optional[str] = None,
    acquire_path: Optional[str] = None,
  ) -> str:
    """Acquire and save a frame via the acquire tool's ACQUIRE_AND_SAVE mode; no arm motion.

    Camera is fixed by the acquire tool's CameraNumber, so pick it by process/tool pair:
    ``("Camera1", "acq1")`` front, ``("Camera2", "acq2")`` downward. The file is written on the
    vision-engine host; retrieve it over a separate transport. Returns the ``Vprocess`` reply.
    """
    await self.vtool_property(acquire_tool, "acquiremode", "ACQUIRE_AND_SAVE")
    if acquire_path is not None:
      await self.vtool_property(acquire_tool, "acquirepath", acquire_path)
    if acquire_prefix is not None:
      await self.vtool_property(acquire_tool, "acquireprefix", acquire_prefix)
    try:
      return await self.run_vision_process(process_name)
    finally:
      await self.vtool_property(acquire_tool, "acquiremode", "NORMAL_ACQUIRE")

  # -- barcode reading -----------------------------------------------------

  async def set_barcode_symbologies(
    self, tool: str, symbologies: List[str], *, enabled: bool = True
  ) -> None:
    """Enable (or disable) the given barcode symbologies on a BarcodeRead tool; no arm motion.

    Each symbology is an independent boolean property (no master 1D/2D switch), e.g.
    ``["code128", "qrcode"]``. Values are stored and take effect the next time the barcode tool runs
    (``read_barcode``). Pass ``enabled=False`` to turn them off.
    """
    engine = self._require_engine()
    for symbology in symbologies:
      await engine.set_vision_tool_property(tool, symbology, str(enabled).lower(), apply=False)

  @requires_vision_tool_type("BarcodeRead")
  async def read_barcode(
    self, process_name: str, barcode_tool: str = "barcode_read1", index: int = 1
  ) -> str:
    """Run a process containing a BarcodeRead tool and return the decoded type+value; no motion."""
    await self.run_vision_process(process_name)
    return await self.vresult_info_string(barcode_tool, index)

  # -- stereo location -----------------------------------------------------

  async def request_stereo_parameters(
    self, robot_number: int = 1, camera_number: int = 1
  ) -> StereoParameters:
    """Read the IntelliGuide stereo-locator configuration (``StereoParam`` get); no motion."""
    reply = await self.driver.send_command(f"StereoParam {robot_number} {camera_number}")
    return StereoParameters.from_reply(reply)

  async def set_stereo_parameters(
    self, params: StereoParameters, robot_number: int = 1, camera_number: int = 1
  ) -> None:
    """Write the IntelliGuide stereo-locator configuration (``StereoParam`` set)."""
    await self.driver.send_command(
      f"StereoParam {robot_number} {camera_number} {params.to_command_args()}"
    )

  @requires_vision_tool_type("FiducialLocator")
  async def locate_target(
    self, robot_number: int = 1, camera_number: int = 1
  ) -> PreciseFlexCartesianPose:
    """Locate an ArUco target by stereo vision (``StereoLocate``); returns its robot-frame pose.

    ACTION - this MOVES THE ARM: the selected gripper camera builds a stereo view by driving to
    multiple viewpoints. Clear the workspace. Requires a prior stereoscopic calibration and a
    configured locator. Returns x/y/z (mm) + rotation (deg).
    """
    reply = await self.driver.send_command(f"StereoLocate {robot_number} {camera_number}")
    x, y, z, yaw, pitch, roll = (float(v) for v in reply.split())
    return PreciseFlexCartesianPose(
      location=Coordinate(x=x, y=y, z=z),
      rotation=Rotation(x=roll, y=pitch, z=yaw),
    )
