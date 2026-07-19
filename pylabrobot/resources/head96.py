from typing import Any, Dict, Optional, cast

from pylabrobot.resources.coordinate import Coordinate
from pylabrobot.resources.resource import Resource
from pylabrobot.resources.x_arm import XArm
from pylabrobot.resources.x_arm_tracker import XArmTracker


class Head96(Resource):
  """A visual proxy for the 96-head, mounted on the X-arm.

  Two reference conventions meet here. This resource's origin is the front-left-bottom
  corner of the stop-disk array (the PyLabRobot convention, so the bounding box matches the
  drawn footprint). The firmware, by contrast, references the centre-centre-bottom of
  channel A1 inside that array - so the *tracked* reference point is A1's centre, which sits
  at local ``(radius, size_y - radius)`` (see below).

  The head is assigned as a child of the ``XArm`` at ``x_offset`` (from ``Head96Information``)
  beyond the arm's carriage reference, so it rides the arm in x for free - when the arm's
  tracker moves the XArm, this moves with it.

  Its y is independent (the head's own y-drive), so the ``Head96`` owns a tracker holding
  A1's y - the tracker's value is the resource's state, reaching the Visualizer through the
  standard state channel (like ``XArm`` owns its x-tracker). The backend drives it; the
  Visualizer positions the head in y from it.

  The footprint reaches the outer channel edges (``(n-1)*pitch + channel_diameter`` per
  axis). Channels are on a ``pitch`` grid inset by the channel radius: A1 is the back-left
  nozzle, its centre at local ``(radius, size_y - radius)``; columns extend in +x and rows
  A->H toward the front (decreasing y).
  """

  def __init__(
    self,
    name: str,
    num_rows: int = 8,
    num_columns: int = 12,
    pitch: float = 9.0,
    channel_diameter: float = 7.0,
    size_z: float = 20.0,
    category: str = "head96",
    model: Optional[str] = None,
  ):
    self.num_rows = num_rows
    self.num_columns = num_columns
    self.pitch = pitch
    self.channel_diameter = channel_diameter
    super().__init__(
      name=name,
      size_x=(num_columns - 1) * pitch + channel_diameter,
      size_y=(num_rows - 1) * pitch + channel_diameter,
      size_z=size_z,
      category=category,
      model=model,
    )
    # Holds A1's tracked y (mm). XArmTracker is a generic 1-D reference tracker; here its
    # value is a y, not an x.
    self.tracker = XArmTracker(thing=name)
    self.tracker.register_callback(self._state_updated)

  @property
  def x(self) -> float:
    """Live deck x of the resource origin (front-left corner), derived from the XArm
    carriage tracker this head rides - not the fixed ``location.x`` offset. Equals
    ``carriage_x - x_offset - radius``.

    A Head96 is only ever assigned as a child of an XArm (see ``_setup_head96``), so the
    parent and location are taken as given.

    Raises:
      RuntimeError: If the arm's position is unknown (no tracked move has committed yet).
    """
    arm = cast(XArm, self.parent)
    reference_offset = arm.get_size_x() / 2 if arm.reference_point == "center" else arm.get_size_x()
    return arm.tracker.get_x() - reference_offset + cast(Coordinate, self.location).x

  @property
  def a1_x(self) -> float:
    """Live deck x of channel A1's centre - the firmware reference point (``carriage_x -
    x_offset``). Equals ``x`` plus the channel radius."""
    return self.x + self.channel_diameter / 2

  def serialize(self) -> Dict[str, Any]:
    return {
      **super().serialize(),
      "num_rows": self.num_rows,
      "num_columns": self.num_columns,
      "pitch": self.pitch,
      "channel_diameter": self.channel_diameter,
    }

  def serialize_state(self) -> Dict[str, Any]:
    return {**super().serialize_state(), "tracker": self.tracker.serialize()}

  def load_state(self, state: Dict[str, Any]) -> None:
    super().load_state(state)
    if "tracker" in state:
      self.tracker.load_state(state["tracker"])
