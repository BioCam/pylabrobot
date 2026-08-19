from typing import Any, Dict, Literal

from pylabrobot.resources.resource import Resource


class XArm(Resource):
  """A model of an X-arm carriage, owned by the deck.

  The arm spans the deck and rides above it, so it is a child of the deck like anything else
  standing on it. Where it is along the deck is its location, which is what moving it updates.

  `reference_point` says where along the arm's width its x refers to: the arm centre for a
  dual-rail arm, the right edge for a single-rail arm.
  """

  def __init__(
    self,
    name: str,
    size_x: float,
    size_y: float,
    size_z: float,
    reference_point: Literal["center", "right"] = "center",
    category: str = "x_arm",
    model: str = "hamilton_legacy_star_dual_rail_arm",
  ):
    """
    Args:
      name: what to call this arm in the resource tree.
      size_x: how wide the arm is, in mm.
      size_y: how deep it is, in mm.
      size_z: how tall it is, in mm.
      reference_point: where along the width its x refers to.
      category: the resource category.
      model: which arm this is.
    """
    super().__init__(
      name=name,
      size_x=size_x,
      size_y=size_y,
      size_z=size_z,
      category=category,
      model=model,
    )
    self.reference_point = reference_point

  def serialize(self) -> Dict[str, Any]:
    return {**super().serialize(), "reference_point": self.reference_point}
