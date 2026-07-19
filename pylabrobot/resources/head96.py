from typing import Any, Dict, Optional

from pylabrobot.resources.resource import Resource
from pylabrobot.resources.x_arm_tracker import XArmTracker


class Head96(Resource):
  """A visual proxy for the 96-head, mounted on the X-arm.

  The reference point is the centre of channel A1 (the resource origin). The head is
  assigned as a child of the ``XArm`` at ``x_offset`` (from ``Head96Information``) beyond
  the arm's carriage reference, so it rides the arm in x for free - when the arm's tracker
  moves the XArm, this moves with it.

  Its y is independent (the head's own y-drive), so the ``Head96`` owns a tracker holding
  A1's y - the tracker's value is the resource's state, reaching the Visualizer through the
  standard state channel (like ``XArm`` owns its x-tracker). The backend drives it; the
  Visualizer positions the head in y from it.

  The origin is the front-left corner, so the resource's bounding box matches the drawn
  footprint, which reaches the outer channel edges (``(n-1)*pitch + channel_diameter`` per
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
      size_z=0.0,
      category=category,
      model=model,
    )
    # Holds A1's tracked y (mm). XArmTracker is a generic 1-D reference tracker; here its
    # value is a y, not an x.
    self.tracker = XArmTracker(thing=name)
    self.tracker.register_callback(self._state_updated)

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
