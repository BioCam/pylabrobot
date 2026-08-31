"""A facility with a v1 STAR in it, plus a bench that is not a machine at all.

Run it:

    python -m plr_viz3d.demo

The world is a `Facility`. A simulated `STARDevice` is assigned into it at a coordinate, and so is
a bench holding a plate and a tip rack that belong to no instrument. The viewer treats them
identically, because it never asks what anything is.

The STAR is recorded in a `Workcell`; the bench is in none. That is the point of the workcell being
a grouping rather than a place: a thing can stand in the facility without one, which is what a
shuttle moving between workcells would need.

The v1 STAR has no aspirate, dispense or tip-pickup yet, so the run below drives the trackers
directly. That is the same channel the viewer subscribes to either way: a real pipetting command
would move these trackers rather than talk to the viewer.
"""

import asyncio
import logging

from pylabrobot.hamilton.star.device import STARDevice, STARLet
from pylabrobot.resources import set_tip_tracking, set_volume_tracking
from pylabrobot.resources.coordinate import Coordinate
from pylabrobot.resources.corning import cor_96_wellplate_360uL_Fb
from pylabrobot.resources.hamilton import (
  PLT_CAR_L5AC_A00,
  TIP_CAR_480_A00,
  hamilton_96_tiprack_1000uL,
)
from pylabrobot.resources.plate import Plate
from pylabrobot.resources.resource import Resource
from pylabrobot.resources.tip_rack import TipRack

from .facility import Facility, Workcell
from .server import Viewer3D

logging.disable(logging.WARNING)


def star_of(facility: Resource) -> STARDevice:
  """The STAR the demo drives. It is the first thing assigned, and the only device here."""
  star = facility.children[0]
  if not isinstance(star, STARDevice):
    raise TypeError(f"expected a STAR at the front of {facility.name}, found {type(star).__name__}")
  return star


def build_facility() -> Facility:
  """A facility with a STAR in it and a bench beside it."""
  facility = Facility(name="facility", size_x=2600, size_y=1400, size_z=1000)

  star = STARLet(simulation=True)
  facility.assign_child_resource(star, location=Coordinate(0, 0, 0))

  tip_carrier = TIP_CAR_480_A00(name="tip_carrier")
  for slot in range(3):
    tip_carrier[slot] = hamilton_96_tiprack_1000uL(name=f"tips_{slot}")
  star.deck.assign_child_resource(tip_carrier, rails=1)

  plate_carrier = PLT_CAR_L5AC_A00(name="source_carrier")
  for slot in range(5):
    plate_carrier[slot] = cor_96_wellplate_360uL_Fb(name=f"source_{slot}")
  star.deck.assign_child_resource(plate_carrier, rails=8)

  destination_carrier = PLT_CAR_L5AC_A00(name="destination_carrier")
  for slot in range(5):
    destination_carrier[slot] = cor_96_wellplate_360uL_Fb(name=f"destination_{slot}")
  star.deck.assign_child_resource(destination_carrier, rails=14)

  # The deck's own `size_z` is 900 mm, taken from the instrument's configuration file. That is the
  # working envelope, not the deck's extent, and it leaves the deck protruding 75.5 mm through the
  # roof of the machine carrying it while enclosing 665 mm of empty space. The honest height is the
  # top of the X-arm that rides above it: 334.7 mm of channel travel plus the arm's own 140 mm.
  # Applied here rather than upstream, since this viewer does not edit the resource library.
  DECK_HEIGHT = 334.7 + 140.0
  star.deck._size_z = DECK_HEIGHT
  star.deck._local_size_z = DECK_HEIGHT

  # Everything the STAR is driven with is one workcell. Nothing moved to make that true: the
  # grouping is recorded beside the tree, not inserted into it.
  facility.add_workcell(Workcell("star_cell", [star]))

  # A bench is not a machine, has no deck and no driver, belongs to no workcell, and still takes
  # part in the same cartesian space. This is the case the old visualizer had no way to express.
  bench = Resource(name="bench", size_x=900, size_y=600, size_z=880, category="bench")
  facility.assign_child_resource(bench, location=Coordinate(1300, 60, 0))
  bench.assign_child_resource(
    cor_96_wellplate_360uL_Fb(name="bench_plate"), location=Coordinate(60, 60, 880)
  )
  bench.assign_child_resource(
    hamilton_96_tiprack_1000uL(name="bench_tips"), location=Coordinate(60, 240, 880)
  )

  return facility


def declare_channel_access(star) -> None:
  """Record how far the channels reach across the deck, once the arm has been discovered.

  Depths of 465, 393 and 321 mm, concentric: each narrower band is inset by half the difference at
  both ends, so every extra four channels costs 36 mm of reach front and back - four channels at
  the 9 mm pitch. In Y this is the deck's own frame, which is also the frame the instrument is
  commanded in, since the backend derives every firmware coordinate from `get_location_wrt(deck)`.

  In X the bands stop where the channels do. Two things bound that, and neither can be taken at
  face value: the arm's own `x_range` is a STAR's, because `STARSimulationDriver` has no STARlet
  configuration, and the deck edge is further right than the channels ever travel. The waste block
  is the real right-hand limit on this machine - the channels eject into it and go no further - so
  the band stops at its near edge. On a real STARlet the arm would report this itself.

  Declared here because no v1 capability publishes any of it; it belongs on the pipettes
  capability, whose reach it describes, rather than on the deck it is measured across.
  """
  low, high = star.x_arm.configuration.x_range
  x_from = max(0.0, low)
  x_to = min(star.deck.get_absolute_size_x(), high)

  # Where the machine's x refers to, as a point from the arm's own origin: the centre of a dual-rail
  # arm, the right edge of a single-rail one. The driver names it with a word; a resource states it
  # as a coordinate, the way a pipette states the point its drives report. The X-arm tracker branch
  # serializes this on the resource; until that lands it is derived off the configuration here.
  if star.x_arm.resource is not None:
    anchor = star.x_arm.configuration.reference_point
    width = star.x_arm.resource.get_absolute_size_x()
    star.x_arm.resource.reference_point = Coordinate(
      width if anchor == "right" else width / 2, 0, 0
    )

    # The opening through the carriage: 185 mm wide, centred on the arm, which on a 354 mm arm
    # puts it at 84.5 .. 269.5.
    if anchor == "center":
      star.x_arm.resource.window = {"width": 185.0, "inset_y": 20.0}

  waste_block = next((child for child in star.deck.children if child.name == "waste_block"), None)
  if waste_block is not None:
    x_to = min(x_to, waste_block.get_location_wrt(star.deck).x)

  star.deck.access_bands = [
    {"label": label, "from": front, "to": front + depth, "x_from": x_from, "x_to": x_to}
    for label, front, depth in (
      ("4/8", 77.5, 465.0),
      ("12", 113.5, 393.0),
      ("16", 149.5, 321.0),
    )
  ]


def fill(plate: Plate, volume: float) -> None:
  for well in plate.get_all_items():
    well.tracker.set_volume(volume)


async def run(facility: Resource) -> None:
  """Move liquid and tips around so the state channel has something to carry."""
  star = star_of(facility)
  tips = star.deck.get_resource("tips_0")
  source = star.deck.get_resource("source_0")
  destination = star.deck.get_resource("destination_0")
  if (
    not isinstance(tips, TipRack)
    or not isinstance(source, Plate)
    or not isinstance(destination, Plate)
  ):
    raise TypeError("the demo deck no longer holds the rack and plates this run drives")

  fill(source, 300.0)
  await asyncio.sleep(2.0)

  for column in range(12):
    # Eight tips leave the rack, so eight instances lose their tip body in one message.
    for row in "ABCDEFGH":
      spot = tips.get_item(f"{row}{column + 1}")
      if spot.tracker.has_tip:
        spot.tracker.remove_tip()
    await asyncio.sleep(0.35)

    for row in "ABCDEFGH":
      well = f"{row}{column + 1}"
      taken = min(150.0, source.get_item(well).tracker.get_used_volume())
      source.get_item(well).tracker.remove_liquid(taken)
      destination.get_item(well).tracker.add_liquid(volume=taken)
    await asyncio.sleep(0.45)

  print("run complete; the viewer stays up")


async def sweep_arm(star) -> None:
  """Walk the X-arm back and forth, so the viewer has a moving part to follow.

  The arm is the one thing on a v1 STAR that reports a live position, so this is what a viewer
  tracking motion actually has to work from.
  """
  low, high = star.x_arm.configuration.x_range
  span = min(high, star.deck.get_absolute_size_x()) - low
  for step in range(10_000):
    target = low + span * (0.15 if step % 2 else 0.75)
    await star.x_arm.move_x(round(target, 1))
    await asyncio.sleep(3.0)


async def main() -> None:
  set_volume_tracking(True)
  set_tip_tracking(True)

  facility = build_facility()
  star = star_of(facility)
  await star.setup()
  declare_channel_access(star)

  viewer = Viewer3D(facility, name="demo.py")
  await viewer.start()

  await asyncio.sleep(1.5)  # let a browser connect before anything moves
  await run(facility)
  await sweep_arm(star)


if __name__ == "__main__":
  try:
    asyncio.run(main())
  except KeyboardInterrupt:
    pass
