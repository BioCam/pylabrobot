"""IntelliGuide vision capability for a PreciseFlex with a camera gripper.

Folds the GPL vision wire primitives (``VToolProperty``, ``Vprocess``, ``VresultInfoString``,
``LightControl``) together with the higher-level orchestrations, over the pure-transport
``PreciseFlexDriver``. Intended to be held as the nullable ``driver.vision``, built at setup only
when a camera gripper is present - so its existence is the capability gate (no per-method guards).
Only ``locate_target`` moves the arm.

Password-free engine image retrieval (``capture_image``) and vision-project enumeration use
the separate PreciseVision engine protocol rather than the TCS controller, and are added on top of
this module.
"""

import functools
import logging
import re
from dataclasses import dataclass, field
from typing import (
  TYPE_CHECKING,
  Awaitable,
  Callable,
  Dict,
  List,
  Literal,
  Optional,
  TypeVar,
  Union,
  cast,
)

if TYPE_CHECKING:
  import numpy as np

from pylabrobot.resources import Coordinate, Rotation

from .confirmed_firmware_versions import is_confirmed_vision_version
from .driver import PreciseFlexDriver
from .kinematics import PreciseFlexCartesianPose
from .vision_driver import PreciseVisionDriver, decode_jpeg

logger = logging.getLogger(__name__)

_NO_ENGINE = "no PreciseVision engine configured - pass vision_host at setup to use this method"


def _split_names(value: str) -> List[str]:
  """Split an engine name list on commas and/or whitespace.

  Args:
    value: an engine name list (``listtools`` is space-separated, ``listprocesses`` comma-separated).

  Returns:
    The non-empty names, in order.
  """
  return [name for name in re.split(r"[,\s]+", value.strip()) if name]


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

    Args:
      reply: a ``StereoParam`` get reply - 10 space-separated fields in field order.

    Returns:
      The parsed ``StereoParameters``.

    Raises:
      ValueError: if the reply does not have exactly 10 fields.
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
    """Whether a tool instance is present in the active project.

    Args:
      name: the tool instance name to look for (e.g. ``acq1``, ``led``).
    """
    return name in self.vision_tools

  def has_vision_tool_type(self, tool_type: str) -> bool:
    """Whether the engine can instantiate a tool type (it is in the fixed palette).

    Args:
      tool_type: the compiled tool-type name to look for (e.g. ``Acquire``).
    """
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

  Args:
    tool_type: the compiled tool type the gated method needs (e.g. ``Acquire``, ``LightControl``).

  Raises:
    RuntimeError: when the decorated method is called after discovery and the type is unavailable.
  """

  def decorator(func: F) -> F:
    @functools.wraps(func)
    async def wrapper(self: "PreciseFlexVisionBackend", *args: object, **kwargs: object) -> object:
      config = self.configuration
      if not config.discovered:  # nothing discovered to gate against yet - let the method run
        return await func(self, *args, **kwargs)
      if not config.has_vision_tool_type(tool_type):
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

  Args:
    name: the tool instance the gated method needs in the active project (e.g. ``led``, ``aruco1``).
    tool_type: the tool's compiled type, used to tell a provisionable gap from an unsupported one.

  Raises:
    RuntimeError: when the decorated method is called after discovery and the tool is absent.
  """

  def decorator(func: F) -> F:
    @functools.wraps(func)
    async def wrapper(self: "PreciseFlexVisionBackend", *args: object, **kwargs: object) -> object:
      config = self.configuration
      if not config.discovered:  # nothing discovered to gate against yet - let the method run
        return await func(self, *args, **kwargs)
      if not config.has_vision_tool(name):
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

  @staticmethod
  def _camera_index(camera: Union[Literal["front", "bottom"], int]) -> int:
    """Resolve a gripper-camera selector to its engine camera number: ``front``->1, ``bottom``->2.

    Shared by every camera-addressed method (image capture, acquire settings, lighting) so the
    ``front``/``bottom`` alias resolves the same way everywhere.

    Args:
      camera: the gripper camera - ``"front"``/``1`` or ``"bottom"``/``2``.

    Returns:
      The engine camera number (1 or 2).

    Raises:
      ValueError: if ``camera`` is not one of ``"front"``/``"bottom"``/``1``/``2``.
    """
    index = {"front": 1, "bottom": 2, 1: 1, 2: 2}.get(camera)
    if index is None:
      raise ValueError(f"camera must be 'front'/1 or 'bottom'/2, got {camera!r}")
    return index

  # ========================================================================
  # LOW-LEVEL ACCESS
  # ========================================================================

  # -- wire primitives -----------------------------------------------------

  # The vision-tool property reads/writes are transport primitives, so they live on the drivers, not
  # here, and each call site names which of the two drivers (three ports) it touches. The controller
  # relay (``self.driver.request_vision_tool_property`` / ``_set_vision_tool_property``, tool+property
  # split because VToolProperty's wire form is two tokens) is always present; the engine path
  # (``self.vision_driver.request_property`` / ``_set_property`` with the dotted ``<tool>.<property>``
  # key) needs a configured ``vision_host``, so its callers guard on ``self.vision_driver is None``
  # first. The orchestrations below compose either. Reads are public; writes (``_set_*``) are private -
  # reached through these vetted orchestrations, never directly.

  async def _run_vision_process(self, name: str) -> str:
    """Run a vision process - the whole assembled tool pipeline (``Vprocess <name>``); no arm motion.

    Controller-side (TCS): runs every tool in the named process in order. To run a single tool over
    the engine instead, use ``_run_vision_tool``.

    Args:
      name: the process name in the active vision project (e.g. ``Camera1``, ``LightControl``).

    Returns:
      The ``Vprocess`` reply.
    """
    return await self.driver.send_command(f"Vprocess {name}")

  async def _vresult_info_string(
    self, tool: Optional[str] = None, index: Optional[int] = None
  ) -> str:
    """``VresultInfoString`` - a result's text result (e.g. a decoded barcode), or the last result.

    The wire pads the value with a leading space, which is stripped.

    Args:
      tool: the result's tool name; give with ``index``, or omit both for the last result.
      index: the 1-based result index; give with ``tool``, or omit both for the last result.

    Returns:
      The result's text, with the leading-space pad stripped.

    Raises:
      ValueError: if exactly one of ``tool`` / ``index`` is given.
    """
    if (tool is None) != (index is None):
      raise ValueError("tool and index must be given together, or both omitted")
    suffix = f" {tool} {index}" if tool is not None else ""
    return (await self.driver.send_command(f"VresultInfoString{suffix}")).strip()

  # -- engine session & discovery ------------------------------------------

  # Engine (the software running on the vision server that performs the computations)
  # ├─ cameras                ← engine hardware
  # ├─ tool types (palette)   ← engine capability
  # └─ Project (active, of N)
  #    ├─ Processes           ← pipelines
  #    └─ Tools               ← instances (of the palette types)

  async def request_camera_count(self) -> int:
    """Number of cameras PreciseVision sees (``System.CameraCount``); read-only, no motion.

    Goes over the controller (``VToolProperty``), so it works without a configured engine; the
    engine-side per-camera detail is in the ``request_camera_*`` reads.
    """
    return int(await self.driver.request_vision_tool_property("System", "CameraCount"))

  async def request_vision_version(self) -> Optional[str]:
    """The PreciseVision engine version (``system.engineversion``)."""
    if self.vision_driver is None:
      raise RuntimeError(_NO_ENGINE)
    return await self.vision_driver.request_property("system.engineversion")

  async def request_is_licensed(self) -> bool:
    """Whether the engine reports a valid license (``system.islicensed``)."""
    if self.vision_driver is None:
      raise RuntimeError(_NO_ENGINE)
    return (await self.vision_driver.request_property("system.islicensed")) == "True"

  async def request_projects(self) -> List[str]:
    """List all projects on the engine (``system.listprojects``); the active one is request_project_name."""
    if self.vision_driver is None:
      raise RuntimeError(_NO_ENGINE)
    value = await self.vision_driver.request_property("system.listprojects")
    return _split_names(value) if value is not None else []

  async def request_project_name(self) -> Optional[str]:
    """The active project's name (``system.projectname``)."""
    if self.vision_driver is None:
      raise RuntimeError(_NO_ENGINE)
    return await self.vision_driver.request_property("system.projectname")

  async def request_processes(self) -> List[str]:
    """List all process names in the active project (``system.listprocesses``)."""
    if self.vision_driver is None:
      raise RuntimeError(_NO_ENGINE)
    value = await self.vision_driver.request_property("system.listprocesses")
    return _split_names(value) if value is not None else []

  async def request_vision_tools(self) -> List[str]:
    """List all tool names in the active project (``system.listtools``)."""
    if self.vision_driver is None:
      raise RuntimeError(_NO_ENGINE)
    value = await self.vision_driver.request_property("system.listtools")
    return _split_names(value) if value is not None else []

  async def enumerate_project(self) -> Optional[Dict[str, List[str]]]:
    """List the loaded project's processes and tools (``system.listprocesses`` / ``listtools``)."""
    if self.vision_driver is None:
      raise RuntimeError(_NO_ENGINE)
    processes = await self.vision_driver.request_property("system.listprocesses")
    tools = await self.vision_driver.request_property("system.listtools")
    if processes is None or tools is None:
      return None
    return {
      "processes": sorted(_split_names(processes)),
      "vision_tools": sorted(_split_names(tools)),
    }

  async def discover_configuration(self) -> VisionConfiguration:
    """Discover the engine's capabilities once and cache them on ``self.configuration``; no motion.

    Reads the tool-type palette, projects, active project, processes, each tool's type and property
    names, and per-camera info via the engine reads (all read-only). Returns an undiscovered (empty)
    configuration when no engine was configured at setup.
    """
    if self.vision_driver is None:
      self.configuration = VisionConfiguration(discovered=False)
      return self.configuration
    tools: Dict[str, VisionToolInfo] = {}
    for name in await self.request_vision_tools():
      tools[name] = VisionToolInfo(
        name=name,
        type=await self.request_vision_tool_type(name),
        properties=await self.request_vision_tool_properties(name),
      )
    count = await self.vision_driver.request_property("system.cameracount")
    cameras: Dict[int, CameraInfo] = {}
    for cam in range(1, (int(count) if count is not None and count.isdigit() else 0) + 1):
      cameras[cam] = CameraInfo(
        name=await self.request_camera_name(cam),
        type=await self.request_camera_type(cam),
        width=await self.request_camera_width(cam),
        height=await self.request_camera_height(cam),
        resolutions=await self.request_camera_resolutions(cam),
      )
    self.configuration = VisionConfiguration(
      discovered=True,
      vision_version=await self.request_vision_version(),
      licensed=await self.request_is_licensed(),
      vision_tool_types=await self.request_vision_tool_types(),
      projects=await self.request_projects(),
      active_project=await self.request_project_name(),
      processes=await self.request_processes(),
      vision_tools=tools,
      cameras=cameras,
    )
    return self.configuration

  async def setup(self) -> None:
    """Discover the engine's capabilities, cache them, and log a summary; best-effort, no motion.

    Run once after the capability is built. Discovery failures are swallowed (logged), so a missing
    or flaky engine never blocks arm bring-up; an unconfirmed engine version is warned about.
    """
    host = self.driver.io._host
    try:
      config = await self.discover_configuration()
    except Exception as exc:  # discovery is best-effort and never blocks setup
      logger.warning("[PreciseFlex %s] vision capability discovery failed: %s", host, exc)
      return
    if not config.discovered:
      return
    if not is_confirmed_vision_version(config.vision_version):
      logger.warning(
        "[PreciseFlex %s] PreciseVision engine %s is not in the confirmed list; please report it if "
        "the vision capability works so others benefit.",
        host,
        config.vision_version,
      )
    self._log_configuration_summary(config)

  def _log_configuration_summary(self, config: VisionConfiguration) -> None:
    """Log the discovered engine configuration as one hierarchical summary (engine > project > tools).

    Args:
      config: the discovered configuration to log.
    """
    tools = ", ".join(f"{n} ({t.type})" for n, t in config.vision_tools.items()) or "none"
    cameras = (
      ", ".join(
        f"{cam}={info.name or '?'} ({info.type}) {info.width}x{info.height}"
        for cam, info in config.cameras.items()
      )
      or "none"
    )
    logger.info(
      "[PreciseFlex %s] Vision: PreciseVision %s (licensed=%s)\n"
      "  Tool types (%d available): %s\n"
      "  Cameras: %s\n"
      "  Project: %r (of %d: %s)\n"
      "    Processes: %s\n"
      "    Tools: %s",
      self.driver.io._host,
      config.vision_version,
      config.licensed,
      len(config.vision_tool_types),
      ", ".join(config.vision_tool_types) or "none",
      cameras,
      config.active_project,
      len(config.projects),
      ", ".join(config.projects) or "none",
      ", ".join(config.processes) or "none",
      tools,
    )

  # -- camera info ---------------------------------------------------------

  async def request_camera_name(
    self, camera: Union[Literal["front", "bottom"], int] = "front"
  ) -> Optional[str]:
    """A camera's friendly name, e.g. ``Cam1`` (``system.cameraname <camera>``)."""
    if self.vision_driver is None:
      raise RuntimeError(_NO_ENGINE)
    return await self.vision_driver.request_property(
      f"system.cameraname {self._camera_index(camera)}"
    )

  async def request_camera_type(
    self, camera: Union[Literal["front", "bottom"], int] = "front"
  ) -> Optional[str]:
    """A camera's capture backend, e.g. ``DirectShow`` (``system.cameratype <camera>``)."""
    if self.vision_driver is None:
      raise RuntimeError(_NO_ENGINE)
    return await self.vision_driver.request_property(
      f"system.cameratype {self._camera_index(camera)}"
    )

  async def request_camera_width(
    self, camera: Union[Literal["front", "bottom"], int] = "front"
  ) -> Optional[int]:
    """A camera's native frame width in px (``system.cameraframewidth <camera>``)."""
    if self.vision_driver is None:
      raise RuntimeError(_NO_ENGINE)
    value = await self.vision_driver.request_property(
      f"system.cameraframewidth {self._camera_index(camera)}"
    )
    return int(value) if value is not None and value.isdigit() else None

  async def request_camera_height(
    self, camera: Union[Literal["front", "bottom"], int] = "front"
  ) -> Optional[int]:
    """A camera's native frame height in px (``system.cameraframeheight <camera>``)."""
    if self.vision_driver is None:
      raise RuntimeError(_NO_ENGINE)
    value = await self.vision_driver.request_property(
      f"system.cameraframeheight {self._camera_index(camera)}"
    )
    return int(value) if value is not None and value.isdigit() else None

  async def request_camera_resolutions(
    self, camera: Union[Literal["front", "bottom"], int] = "front"
  ) -> List[str]:
    """A camera's supported resolution modes (``system.cameraresolutions <camera>``)."""
    if self.vision_driver is None:
      raise RuntimeError(_NO_ENGINE)
    value = await self.vision_driver.request_property(
      f"system.cameraresolutions {self._camera_index(camera)}"
    )
    return _split_names(value) if value is not None else []

  # ========================================================================
  # VISION TOOLS
  # ========================================================================

  # -- tool properties -----------------------------------------------------

  async def request_vision_tool_property_value(
    self, tool: str, property_name: str
  ) -> Optional[str]:
    """Read one tool property value (``property get <tool>.<property>``)."""
    if self.vision_driver is None:
      raise RuntimeError(_NO_ENGINE)
    return await self.vision_driver.request_property(f"{tool}.{property_name}")

  async def request_vision_tool_properties(self, tool: str) -> List[str]:
    """List the property names of one tool (``system.toolproperties <tool>``)."""
    if self.vision_driver is None:
      raise RuntimeError(_NO_ENGINE)
    value = await self.vision_driver.request_property(f"system.toolproperties {tool}")
    return _split_names(value) if value is not None else []

  async def request_vision_tool_property_info(self, tool: str, property_name: str) -> Optional[str]:
    """The type / enum / range metadata for one tool property (``system.toolpropertyinfo``)."""
    if self.vision_driver is None:
      raise RuntimeError(_NO_ENGINE)
    return await self.vision_driver.request_property(
      f"system.toolpropertyinfo {tool} {property_name}"
    )

  async def request_vision_tool_type(self, tool: str) -> Optional[str]:
    """The tool's type/class, e.g. ``Acquire`` or ``FiducialLocator`` (``system.tooltype``)."""
    if self.vision_driver is None:
      raise RuntimeError(_NO_ENGINE)
    return await self.vision_driver.request_property(f"system.tooltype {tool}")

  async def request_vision_tool_types(self) -> List[str]:
    """List all tool types the engine can instantiate (``system.tooltypes``) - the fixed palette."""
    if self.vision_driver is None:
      raise RuntimeError(_NO_ENGINE)
    value = await self.vision_driver.request_property("system.tooltypes")
    return _split_names(value) if value is not None else []

  async def _run_vision_tool(self, tool: str) -> None:
    """Run a single engine vision tool (``property set system.runtool <tool>``).

    Internal apply primitive: for an acquire tool it pushes the tool's stored settings to the camera
    and grabs a frame. A bare property write only stores a value; running the tool applies it.
    """
    if self.vision_driver is None:
      raise RuntimeError(_NO_ENGINE)
    await self.vision_driver._set_property("system.runtool", tool)

  # -- lighting (LightControl) ---------------------------------------------

  # The IntelliGuide gripper's LightControl tool and the process that applies it. Project-specific
  # names, but fixed for the shipped vision project, so they are internal - not per-call arguments.
  _LIGHT_TOOL = "led"
  _LIGHT_PROCESS = "LightControl"

  @requires_vision_tool_type("LightControl")
  async def start_led(
    self,
    camera: Union[Literal["front", "bottom"], int] = "front",
    brightness: int = 100,
    delay: Optional[int] = None,
  ) -> None:
    """Turn on the IntelliGuide camera lighting (LightControl vision tool); no arm motion.

    Sets the LightControl tool's LED bank and brightness, then runs the process that applies it.
    ``brightness=0`` turns the LEDs off, or use ``stop_led``.

    Args:
      camera: which integrated LED source - ``"front"``/``1`` or ``"bottom"``/``2``. Drives the
        tool's LED Bank (1 = front-facing, 2 = bottom-facing).
      brightness: LED brightness 0-100 (PWM duty); ``0`` turns the LEDs off.
      delay: optional light time delay in milliseconds.
    """
    bank = self._camera_index(camera)  # LED bank 1 = front-facing, 2 = bottom-facing
    if self.configuration.discovered and bank not in self.configuration.cameras:
      raise RuntimeError(
        f"camera {camera!r} (engine camera {bank}) is not among the discovered "
        f"cameras {sorted(self.configuration.cameras)}"
      )
    if not 0 <= brightness <= 100:
      raise ValueError(f"brightness must be 0-100, got {brightness}")
    await self.driver._set_vision_tool_property(self._LIGHT_TOOL, "Bank", str(bank))
    await self.driver._set_vision_tool_property(self._LIGHT_TOOL, "Brightness", str(brightness))
    if delay is not None:
      await self.driver._set_vision_tool_property(self._LIGHT_TOOL, "Delay", str(delay))
    await self._run_vision_process(self._LIGHT_PROCESS)

  async def stop_led(self, camera: Union[Literal["front", "bottom"], int] = "front") -> None:
    """Turn off the IntelliGuide camera lighting (the ``start_led`` counterpart); no arm motion."""
    await self.start_led(camera, 0)

  # -- camera image (Acquire) ----------------------------------------------

  @requires_vision_tool_type("Acquire")
  async def set_camera_setting(
    self, camera: Union[Literal["front", "bottom"], int], setting: str, value: object
  ) -> None:
    """Set one acquire-tool camera knob and apply it to the camera; no arm motion.

    Writes ``acq<n>.<setting>`` (brightness/hue/gain/exposure/...) and runs the acquire tool so the
    change reaches the DirectShow camera - a bare write only stores it. The live stream then reflects
    it.

    Args:
      camera: which gripper camera - ``"front"``/``1`` (front-facing) or ``"bottom"``/``2`` (downward).
      setting: the acquire-tool property name (e.g. ``brightness``, ``exposure``, ``gain``).
      value: the value to write. The camera may clamp it to its own range, so read it back with
        ``request_vision_tool_property_value`` to confirm the effective value.
    """
    if self.vision_driver is None:
      raise RuntimeError(_NO_ENGINE)
    acquire_tool = f"acq{self._camera_index(camera)}"
    await self.vision_driver._set_property(f"{acquire_tool}.{setting}", value)
    await self._run_vision_tool(acquire_tool)  # a bare write only stores; run the tool to apply

  async def capture_image(
    self, camera: Union[Literal["front", "bottom"], int] = "front"
  ) -> "np.ndarray":
    """Fetch one frame for ``camera`` directly off the PreciseVision engine as an array, no motion.

    Triggers a frame with ``system.cameraacquire`` and reads records off the engine's image stream
    until the matching ``Primary Image [n]`` arrives, discarding non-image and other-camera records,
    then decodes its JPEG to an RGB array. Requires a configured engine (raises if none was set up).
    For a saved file on the engine host instead, use ``save_image``.

    This grabs the camera's current hardware state; it does NOT apply pending acquire-tool settings.
    Change one first with ``set_camera_setting`` (which applies it) for it to show in the frame.

    Args:
      camera: which gripper camera - ``"front"``/``1`` (front-facing) or ``"bottom"``/``2`` (downward).

    Returns:
      The full-resolution frame as an RGB ``numpy`` array (height x width x 3, ``uint8``).

    Raises:
      TimeoutError: if no frame arrives off the engine image stream before the read times out.
      RuntimeError: if the image stream ends before the requested frame is seen.
    """
    if self.vision_driver is None:
      raise RuntimeError(_NO_ENGINE)
    index = self._camera_index(camera)
    want = f"Primary Image [{index}]"
    await self.vision_driver._set_property("system.cameraacquire", index)
    while True:
      try:
        record = await self.vision_driver.read_next_record()
      except TimeoutError as e:
        raise TimeoutError(f"no '{want}' frame arrived within {self.vision_driver.timeout}s") from e
      if record is None:
        raise RuntimeError(f"engine image stream ended without a '{want}' record")
      name, data = record
      if name == want:
        return decode_jpeg(data)

  @requires_vision_tool_type("Acquire")
  async def save_image(
    self,
    camera: Union[Literal["front", "bottom"], int] = "front",
    acquire_prefix: Optional[str] = None,
    acquire_path: Optional[str] = None,
  ) -> str:
    """Acquire and save a frame via the acquire tool's ACQUIRE_AND_SAVE mode; no arm motion.

    The file is written on the vision-engine host; retrieve it over a separate transport. Returns
    the ``Vprocess`` reply.

    Args:
      camera: which gripper camera - ``"front"``/``1`` (front-facing) or ``"bottom"``/``2``
        (downward). Selects the acquire tool (``acq<n>``) and the process that runs it
        (``Camera<n>``); the camera itself is fixed by that tool's CameraNumber.
      acquire_prefix: optional filename prefix for the saved frame.
      acquire_path: optional directory on the engine host to write the frame to.
    """
    index = self._camera_index(camera)
    process_name = f"Camera{index}"
    acquire_tool = f"acq{index}"
    await self.driver._set_vision_tool_property(acquire_tool, "acquiremode", "ACQUIRE_AND_SAVE")
    if acquire_path is not None:
      await self.driver._set_vision_tool_property(acquire_tool, "acquirepath", acquire_path)
    if acquire_prefix is not None:
      await self.driver._set_vision_tool_property(acquire_tool, "acquireprefix", acquire_prefix)
    try:
      return await self._run_vision_process(process_name)
    finally:
      await self.driver._set_vision_tool_property(acquire_tool, "acquiremode", "NORMAL_ACQUIRE")

  # -- barcode reading (BarcodeRead) ---------------------------------------

  async def set_barcode_symbologies(
    self, tool: str, symbologies: List[str], *, enabled: bool = True
  ) -> None:
    """Enable (or disable) the given barcode symbologies on a BarcodeRead tool; no arm motion.

    Each symbology is an independent boolean property (no master 1D/2D switch), e.g.
    ``["code128", "qrcode"]``. Values are stored and take effect the next time the barcode tool runs
    (``read_barcode``). Pass ``enabled=False`` to turn them off.
    """
    if self.vision_driver is None:
      raise RuntimeError(_NO_ENGINE)
    for symbology in symbologies:
      # Stored only (no run-tool); the next read_barcode run applies them.
      await self.vision_driver._set_property(f"{tool}.{symbology}", str(enabled).lower())

  @requires_vision_tool_type("BarcodeRead")
  async def read_barcode(
    self, process_name: str, barcode_tool: str = "barcode_read1", index: int = 1
  ) -> str:
    """Run a process containing a BarcodeRead tool and return the decoded type+value; no motion."""
    await self._run_vision_process(process_name)
    return await self._vresult_info_string(barcode_tool, index)

  # -- stereo location (FiducialLocator) -----------------------------------

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
