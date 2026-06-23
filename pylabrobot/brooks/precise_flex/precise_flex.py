"""PreciseFlex device front-ends - the user-facing per-model device classes."""

from typing import Optional

from pylabrobot.capabilities.arms.orientable_arm import OrientableGripperArm
from pylabrobot.capabilities.capability import BackendParams
from pylabrobot.device import Device
from pylabrobot.resources.resource import Resource

from .arm_backend import PreciseFlexArmBackend
from .driver import PreciseFlexDriver
from .vision_backend import PreciseFlexVisionBackend

# -- PreciseFlex 400 -------------------------------------------------------


class PreciseFlex400(Device):
  """Device wrapper for the PreciseFlex 400 robotic arm."""

  def __init__(
    self,
    host: str,
    closed_gripper_position: float,
    port: int = 10100,
    has_rail: bool = False,
    timeout: int = 20,
    gripper_length: float = 162.0,
    gripper_z_offset: float = 0.0,
    recover_out_of_range: bool = True,
    vision_host: Optional[str] = None,
  ) -> None:
    """
    Args:
      closed_gripper_position: firmware-unit value at which the jaws are at the
        backend's :attr:`~PreciseFlexArmBackend.min_gripper_width`. Depends on
        the specific gripper mounted; calibrate before first use.
      gripper_length: wrist-axis → TCP distance in mm. Defaults to 162 mm, which
        matches the stock single gripper on the PF400.
      gripper_z_offset: vertical offset in mm from the wrist plate to the tool tip.
        Defaults to 0 mm.
      recover_out_of_range: when True (the default), an out-of-range axis is driven back into range
        once - at setup and before a commanded move (which then retries). Set False to forbid this
        autonomous motion; an out-of-range axis then raises instead, carrying recovery instructions.
      vision_host: address of the PreciseVision engine, a separate machine from the controller (its
        own box with its own IP). Set it to connect to the engine, which powers both image fetch and
        engine-side discovery/introspection (what projects, tools, and tool types exist). None leaves
        the engine unconnected, disabling those; the controller-side execution path (running
        processes/tools, setting properties, lighting, barcodes, stereo locate) is unaffected.
    """
    driver = PreciseFlexDriver(host=host, port=port, timeout=timeout)
    super().__init__(driver=driver)
    self.driver: PreciseFlexDriver
    backend = PreciseFlexArmBackend(
      driver=driver,
      has_rail=has_rail,
      gripper_length=gripper_length,
      gripper_z_offset=gripper_z_offset,
      closed_gripper_position=closed_gripper_position,
      recover_out_of_range=recover_out_of_range,
      vision_host=vision_host,
    )
    self.reference = Resource(name="PreciseFlex400", size_x=200, size_y=200, size_z=200)
    self.arm = OrientableGripperArm(backend=backend, reference_resource=self.reference)
    self._capabilities = [self.arm]
    self.vision: Optional[PreciseFlexVisionBackend] = None

  async def setup(
    self, backend_params: Optional[BackendParams] = None, *, skip_vision: bool = False
  ) -> None:
    """Set up the arm, then expose the vision capability if a camera gripper is present.

    Args:
      skip_vision: if True, do not expose ``self.vision`` even when a camera gripper is detected
        (``driver.vision`` is still built by the backend). Mirrors STAR's ``skip_*`` setup flags.
    """
    await super().setup(backend_params=backend_params)
    self.vision = (
      self.driver.vision if (self.driver.vision is not None and not skip_vision) else None
    )


# -- PreciseFlex 3400 ------------------------------------------------------


class PreciseFlex3400(Device):
  """Device wrapper for the PreciseFlex 3400 robotic arm.

  Mirrors :class:`PreciseFlex400`. The 3400 is the same two-link SCARA family (its link
  lengths are read from the controller at setup), with a taller reach.
  """

  def __init__(
    self,
    host: str,
    closed_gripper_position: float,
    gripper_length: float,
    port: int = 10100,
    has_rail: bool = False,
    timeout: int = 20,
    gripper_z_offset: float = 0.0,
    recover_out_of_range: bool = True,
    vision_host: Optional[str] = None,
  ) -> None:
    """
    Args:
      closed_gripper_position: firmware-unit value at which the jaws are at the backend's
        :attr:`~PreciseFlexArmBackend.min_gripper_width`. Depends on the mounted gripper;
        calibrate before first use.
      gripper_length: wrist-axis → TCP distance in mm. Required - unlike the PF400 there is
        no stock default, because the 3400 ships with an IntelliGuide gripper whose length
        differs; set it for the gripper actually mounted.
      gripper_z_offset: vertical offset in mm from the wrist plate to the tool tip.
      recover_out_of_range: when True (the default), an out-of-range axis is driven back into range
        once - at setup and before a commanded move (which then retries). Set False to forbid this
        autonomous motion; an out-of-range axis then raises instead, carrying recovery instructions.
      vision_host: address of the PreciseVision engine, a separate machine from the controller (its
        own box with its own IP). Set it to connect to the engine, which powers both image fetch and
        engine-side discovery/introspection (what projects, tools, and tool types exist). None leaves
        the engine unconnected, disabling those; the controller-side execution path (running
        processes/tools, setting properties, lighting, barcodes, stereo locate) is unaffected.
    """
    driver = PreciseFlexDriver(host=host, port=port, timeout=timeout)
    super().__init__(driver=driver)
    self.driver: PreciseFlexDriver
    backend = PreciseFlexArmBackend(
      driver=driver,
      has_rail=has_rail,
      gripper_length=gripper_length,
      gripper_z_offset=gripper_z_offset,
      closed_gripper_position=closed_gripper_position,
      recover_out_of_range=recover_out_of_range,
      vision_host=vision_host,
    )
    self.reference = Resource(name="PreciseFlex3400", size_x=200, size_y=200, size_z=200)
    self.arm = OrientableGripperArm(backend=backend, reference_resource=self.reference)
    self._capabilities = [self.arm]
    self.vision: Optional[PreciseFlexVisionBackend] = None

  async def setup(
    self, backend_params: Optional[BackendParams] = None, *, skip_vision: bool = False
  ) -> None:
    """Set up the arm, then expose the vision capability if a camera gripper is present.

    Args:
      skip_vision: if True, do not expose ``self.vision`` even when a camera gripper is detected
        (``driver.vision`` is still built by the backend). Mirrors STAR's ``skip_*`` setup flags.
    """
    await super().setup(backend_params=backend_params)
    self.vision = (
      self.driver.vision if (self.driver.vision is not None and not skip_vision) else None
    )
