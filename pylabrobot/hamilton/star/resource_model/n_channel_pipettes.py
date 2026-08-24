"""Pipetting channels, and the rigid grids some machines carry them in."""

from collections import OrderedDict
from typing import Any, Dict, Literal, Mapping, Optional, get_args

from pylabrobot.resources.coordinate import Coordinate
from pylabrobot.resources.itemized_resource import ItemizedResource
from pylabrobot.resources.resource import Resource
from pylabrobot.resources.utils import create_ordered_items_2d

TipPickupMode = Literal["friction", "core"]
"""How a channel holds onto a tip.

`friction` presses the channel's cone into the tip and relies on the interference fit, so a tip is
seated by pushing down onto it and shed by pushing it off against something. `core` seats the
channel inside the tip and expands a compressed o-ring into its collar, so the grip is made and
released mechanically rather than by force - which is why a pipette that engages this way has a
squeezer drive, and why it can put tips back on a rack rather than only discarding them."""


class PipettingChannel(Resource):
  """A pipetting channel: what a tip goes onto.

  A machine whose channels move independently carries them as these, one each - a channel that is
  its own pipette needs nothing wrapped around it. A machine whose channels move as one carries
  them inside an `NChannelPipette` instead.

  A channel's own diameter is not something an instrument reports, so unless it has been measured
  it is modelled as the point a tip attaches at rather than given an invented footprint. A tip that
  has been collected is a child of the channel carrying it, which is what keeps the two together as
  the channel moves.
  """

  def __init__(
    self,
    name: str,
    tip_pickup_mode: TipPickupMode,
    size_x: float = 0.0,
    size_y: float = 0.0,
    size_z: float = 0.0,
    category: str = "pipetting_channel",
    model: Optional[str] = None,
  ):
    """
    Args:
      name: what to call this one.
      tip_pickup_mode: how it holds onto a tip.
      size_x: how wide it is, in mm. Zero models it as the point a tip attaches at, which is all
        that is known unless someone has measured one.
      size_y: how deep it is, in mm.
      size_z: how far it reaches below whatever carries it, in mm.
      category: what kind of resource this is.
      model: which channel this is.

    Raises:
      ValueError: If the tip pickup mode is not one this models.
    """
    if tip_pickup_mode not in get_args(TipPickupMode):
      raise ValueError(
        f"unknown tip_pickup_mode {tip_pickup_mode!r}, expected one of {get_args(TipPickupMode)}"
      )
    self.tip_pickup_mode = tip_pickup_mode
    super().__init__(
      name=name,
      size_x=size_x,
      size_y=size_y,
      size_z=size_z,
      category=category,
      model=model,
    )

  def serialize(self) -> dict:
    """What its size does not say: how it holds a tip."""
    return {**super().serialize(), "tip_pickup_mode": self.tip_pickup_mode}


class NChannelPipette(ItemizedResource[PipettingChannel]):
  """A rigid grid of pipetting channels that move as one.

  Only for channels that share their drives: where each moves on its own, it is a
  `PipettingChannel` in its own right and there is nothing for this to wrap.

  The channels are the items, so where any one of them is follows from where the pipette is and how
  the grid is spaced - `item_dx` and `item_dy` are that spacing, and `channel_pitch` is the word the
  drivers use for it. Located like any resource, by its left front bottom corner; where the drives
  report it - which need not be a channel at all - is `reference_point`.
  """

  def __init__(
    self,
    name: str,
    size_x: float,
    size_y: float,
    size_z: float,
    reference_point: Coordinate,
    ordered_items: Optional[Dict[str, PipettingChannel]] = None,
    ordering: Optional[OrderedDict[str, str]] = None,
    independent_channel_actuation: bool = False,
    category: str = "n_channel_pipette",
    model: Optional[str] = None,
    metadata: Optional[Mapping[str, Any]] = None,
  ):
    """
    Args:
      name: what to call this one.
      size_x: how wide the pipette is, in mm.
      size_y: how deep it is, in mm.
      size_z: how tall it is, from its lowest fixed feature to its top, in mm.
      reference_point: the point the drives report and commands name, from the left front bottom
        corner. Often the first channel, but a pipette is free to be measured from anywhere.
      ordered_items: its channels, keyed by identifier.
      ordering: the channels it already has, when one is being rebuilt rather than built.
      independent_channel_actuation: whether its channels can be worked one at a time rather than
        only all together. False unless each has its own actuation.
      category: what kind of resource this is.
      model: which pipette this is.
      metadata: anything else worth keeping with it.
    """
    super().__init__(
      name,
      size_x,
      size_y,
      size_z,
      ordered_items=ordered_items,
      ordering=ordering,
      category=category,
      model=model,
      metadata=metadata,
    )
    self.reference_point = reference_point
    self.independent_channel_actuation = independent_channel_actuation

  @property
  def num_channels(self) -> int:
    """How many channels this pipette has."""
    return self.num_items

  @property
  def channel_pitch(self) -> float:
    """The centre-to-centre spacing of the channels, in mm.

    Raises:
      ValueError: If the pipette has a single row or column, which has nothing to be spaced from.
    """
    return self.item_dx if self.num_items_x > 1 else self.item_dy

  @property
  def tip_pickup_mode(self) -> TipPickupMode:
    """How its channels hold onto a tip.

    Read from the channels rather than kept alongside them, so there is nothing to disagree with.

    Raises:
      ValueError: If the pipette has no channels to read it from.
    """
    return self.get_item(0).tip_pickup_mode

  def serialize(self) -> dict:
    """What its size and its channels do not say: where it is measured from, and whether they can
    be worked one at a time."""
    return {
      **super().serialize(),
      "reference_point": self.reference_point.serialize(),
      "independent_channel_actuation": self.independent_channel_actuation,
    }


def _rigid_head(
  name: str,
  columns: int,
  rows: int,
  pitch: float,
  model: str,
  size_x: Optional[float],
  size_y: Optional[float],
  size_z: float,
  dx: float,
  dy: Optional[float],
  dz: float,
) -> NChannelPipette:
  """One of the rigid heads: a grid the instrument knows, in a body it does not.

  What the instrument tells us is the grid - how many channels, at what pitch. Its body is a
  measurement of a particular head, so it is not derived from the pitch and not invented: left
  unmeasured, the resource spans the channel array and nothing more.

  Args:
    name: what to call this one.
    columns: how many channels across.
    rows: how many channels deep.
    pitch: their centre-to-centre spacing, in mm.
    model: which head this is.
    size_x: how wide the head's body is, in mm. None spans the channel array instead.
    size_y: how deep the body is, in mm. None spans the channel array instead.
    size_z: how tall it is, in mm. Zero models it as its channel plane.
    dx: how far channel A1 sits from the body's left edge, in mm.
    dy: how far channel A1 sits from its front edge, in mm. None puts it on the array's back edge.
    dz: how far channel A1 sits above its bottom, in mm.

  Returns:
    The pipette.
  """
  array_x, array_y = (columns - 1) * pitch, (rows - 1) * pitch
  size_x = array_x if size_x is None else size_x
  size_y = array_y if size_y is None else size_y
  dy = array_y if dy is None else dy
  return NChannelPipette(
    name=name,
    size_x=size_x,
    size_y=size_y,
    size_z=size_z,
    reference_point=Coordinate(dx, dy, dz),
    ordered_items=create_ordered_items_2d(
      PipettingChannel,
      num_items_x=columns,
      num_items_y=rows,
      dx=dx,
      dy=dy - array_y,
      dz=dz,
      item_dx=pitch,
      item_dy=pitch,
      tip_pickup_mode="core",
    ),
    category=model,
    model=model,
  )


def head96(
  name: str,
  size_x: Optional[float] = None,
  size_y: Optional[float] = None,
  size_z: float = 0.0,
  dx: float = 0.0,
  dy: Optional[float] = None,
  dz: float = 0.0,
) -> NChannelPipette:
  """The 96-head: 96 channels on a 12 by 8 grid at 9 mm, moving as one.

  The drives report channel A1, so that is what `reference_point` is. The head's body is larger than
  its channel array by an amount nobody here has measured, so by default the resource spans the
  array alone - which understates the head, and is why anything checking what it might collide with
  needs a measured body rather than this default.

  Args:
    name: what to call this one.
    size_x: how wide the head's body is, in mm. None spans the channel array instead.
    size_y: how deep the body is, in mm. None spans the channel array instead.
    size_z: how tall it is, from its stop disk to its top, in mm. Zero leaves it unmodelled.
    dx: how far channel A1 sits from the body's left edge, in mm.
    dy: how far channel A1 sits from its front edge, in mm. None puts it on the array's back edge.
    dz: how far channel A1 sits above its bottom, in mm.

  Returns:
    The pipette.
  """
  return _rigid_head(name, 12, 8, 9.0, "head96", size_x, size_y, size_z, dx, dy, dz)


def head384(
  name: str,
  size_x: Optional[float] = None,
  size_y: Optional[float] = None,
  size_z: float = 0.0,
  dx: float = 0.0,
  dy: Optional[float] = None,
  dz: float = 0.0,
) -> NChannelPipette:
  """The 384-head: 384 channels on a 24 by 16 grid at 4.5 mm, moving as one.

  Measured from channel A1, and unmeasured in its body, for the same reasons as the 96-head.

  Args:
    name: what to call this one.
    size_x: how wide the head's body is, in mm. None spans the channel array instead.
    size_y: how deep the body is, in mm. None spans the channel array instead.
    size_z: how tall it is, from its collar bearing to its top, in mm. Zero leaves it unmodelled.
    dx: how far channel A1 sits from the body's left edge, in mm.
    dy: how far channel A1 sits from its front edge, in mm. None puts it on the array's back edge.
    dz: how far channel A1 sits above its bottom, in mm.

  Returns:
    The pipette.
  """
  return _rigid_head(name, 24, 16, 4.5, "head384", size_x, size_y, size_z, dx, dy, dz)
