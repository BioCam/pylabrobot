"""Tip handling on a simulated STAR, watched in the 3D viewer.

Run it:

    python -m pylabrobot.visualizer3D.tip_demo

Four tip carriers, one tip size each, four racks apiece: two with tips taken out at random, one
holding only its right half, and one full. The runs below pick up, return, drop and discard from
them, including spots holding different tips in one call - a command names one tip type, so those
go out as one command per kind, in ascending X.

Every public command is printed with the firmware it sent, and a second passes before the next
one, so the viewer can be followed.
"""

import asyncio
import logging
import random
from typing import Any, List, Optional, Sequence

from pylabrobot.hamilton.star.device import STAR, STARDevice
from pylabrobot.resources import set_tip_tracking
from pylabrobot.resources.coordinate import Coordinate
from pylabrobot.resources.errors import HasTipError, NoTipError
from pylabrobot.resources.hamilton import (
  TIP_CAR_480_A00,
  hamilton_96_tiprack_10uL,
  hamilton_96_tiprack_50uL,
  hamilton_96_tiprack_300uL,
  hamilton_96_tiprack_1000uL,
)
from pylabrobot.resources.tip_rack import TipRack

from .server import Viewer3D

logging.disable(logging.WARNING)

# One carrier per tip size, on the tracks each carrier occupies six of.
CARRIERS = (
  ("10uL", hamilton_96_tiprack_10uL, 1),
  ("50uL", hamilton_96_tiprack_50uL, 7),
  ("300uL", hamilton_96_tiprack_300uL, 13),
  ("1000uL", hamilton_96_tiprack_1000uL, 19),
)

# How many of a rack's 96 spots keep their tip when the tips are taken out at random. Seeded, so
# the same spots are empty on every run.
KEPT_AT_RANDOM = 60
SEED = 0

# How long each command is left on screen, in seconds.
HELD_FOR = 1.0


def build_star() -> STARDevice:
  """A simulated STAR with four tip carriers on it, each holding four racks in its own size."""
  star = STAR(simulation=True)
  dice = random.Random(SEED)

  for size, make_rack, track in CARRIERS:
    carrier = TIP_CAR_480_A00(name=f"carrier_{size}")
    for slot in range(4):
      rack = make_rack(name=f"{size}_{slot}")
      carrier[slot] = rack
      wells = [f"{row}{column}" for column in range(1, 13) for row in "ABCDEFGH"]
      if slot < 2:
        # Taken out at random: what a rack looks like part way through a run.
        kept = set(dice.sample(wells, KEPT_AT_RANDOM))
        rack.set_tip_state({well: well in kept for well in wells})
      elif slot == 2:
        # The right half only: columns 7 to 12.
        rack.set_tip_state({well: int(well[1:]) > 6 for well in wells})
    star.deck.assign_child_resource(carrier, track=track)

  return star


def rack_of(star: STARDevice, size: str, slot: int) -> TipRack:
  """The rack in one carrier's slot."""
  rack = star.deck.get_resource(f"{size}_{slot}")
  if not isinstance(rack, TipRack):
    raise TypeError(f"{size}_{slot} is not a tip rack")
  return rack


def spots(rack: TipRack, wells: Sequence[str]) -> List[Any]:
  return [rack.get_item(well) for well in wells]


def holding(rack: TipRack, how_many: int) -> List[Any]:
  """The first `how_many` spots of a rack that still hold a tip, front to back, left to right."""
  with_tips = [spot for spot in rack.get_all_items() if spot.has_tip()]
  return with_tips[:how_many]


class Run:
  """Runs one command at a time, printing what it sent and leaving it on screen."""

  def __init__(self, star: STARDevice) -> None:
    self.star = star
    self.sent: List[str] = []
    driver = star.driver
    log = driver._log_exchange  # type: ignore[attr-defined]

    def recorded(written: str, read: Optional[str]) -> None:
      if written[:4] in ("C0TP", "C0TR"):
        self.sent.append(written)
      log(written, read)

    driver._log_exchange = recorded  # type: ignore[attr-defined]

  async def __call__(self, what: str, command: Any) -> None:
    """Await one public command, print what it sent, and hold the pose."""
    self.sent.clear()
    print(f"\n{what}")
    try:
      await command
    except (NoTipError, HasTipError, ValueError) as refused:
      print(f"  refused: {refused}")
    for firmware in self.sent:
      print(f"  {firmware}")
    if not self.sent:
      print("  (nothing sent)")
    await asyncio.sleep(HELD_FOR)


async def run(star: STARDevice) -> None:
  """Work through the tip handling, one command at a time."""
  arm = star.left_x_arm
  pipettes = arm.pipettes if arm is not None else None
  if pipettes is None:
    raise RuntimeError("this STAR reports no pipetting channels")
  each = Run(star)

  full_300 = rack_of(star, "300uL", 3)
  holed_300 = rack_of(star, "300uL", 0)
  right_half_50 = rack_of(star, "50uL", 2)
  full_10 = rack_of(star, "10uL", 3)
  full_1000 = rack_of(star, "1000uL", 3)
  full_50 = rack_of(star, "50uL", 3)
  holed_1000 = rack_of(star, "1000uL", 1)

  # 1. A full rack, eight channels: what one command looks like.
  await each(
    "1. eight tips from a full 300 uL rack",
    pipettes.pick_up_tips(spots(full_300, [f"{row}1" for row in "ABCDEFGH"])),
  )
  await each("   back where they came from", pipettes.return_tips())

  # 2. A rack with tips taken out at random: the spots that still hold one are not a column.
  await each(
    "2. eight tips from a 300 uL rack with tips taken out at random",
    pipettes.pick_up_tips(holding(holed_300, 8)),
  )
  await each("   back where they came from", pipettes.return_tips())

  # 3. Only the right half of the rack is loaded.
  await each(
    "3. eight tips from the right half of a 50 uL rack",
    pipettes.pick_up_tips(spots(right_half_50, [f"{row}12" for row in "ABCDEFGH"])),
  )
  await each("   back where they came from", pipettes.return_tips())

  # 4. Two sizes in one call: one command per kind, the left-hand carrier first.
  await each(
    "4. four 10 uL and four 1000 uL tips in one call",
    pipettes.pick_up_tips(
      spots(full_10, ["A1", "B1", "C1", "D1"]) + spots(full_1000, ["E1", "F1", "G1", "H1"])
    ),
  )
  await each("   back where they came from", pipettes.return_tips())

  # 5. All four sizes at once, one channel each.
  await each(
    "5. one tip of each size, on channels 0 to 3",
    pipettes.pick_up_tips(
      [
        full_10.get_item("A1"),
        full_50.get_item("B1"),
        full_300.get_item("C1"),
        full_1000.get_item("D1"),
      ],
      use_channels=[0, 1, 2, 3],
    ),
  )
  await each("   back where they came from", pipettes.return_tips())

  # 6. Channels that are not next to each other, two sizes between them.
  await each(
    "6. two sizes on channels 0, 2, 4 and 6",
    pipettes.pick_up_tips(
      spots(full_10, ["A2", "C2"]) + spots(full_1000, ["E2", "G2"]),
      use_channels=[0, 2, 4, 6],
    ),
  )
  await each("   back where they came from", pipettes.return_tips())

  # 7. The same, with each spot's centre offset.
  await each(
    "7. two sizes with offsets",
    pipettes.pick_up_tips(
      spots(full_10, ["A3", "B3"]) + spots(full_1000, ["C3", "D3"]),
      offsets=[
        Coordinate(0.5, 0.5, 0),
        Coordinate(-0.5, 0.5, 0),
        Coordinate(0.5, -0.5, 0),
        Coordinate(0, 0, 0),
      ],
    ),
  )
  await each("   back where they came from", pipettes.return_tips())

  # 8. Dropped into spots other than the ones they came from.
  await each(
    "8. four 300 uL tips, to be dropped elsewhere",
    pipettes.pick_up_tips(spots(full_300, ["A4", "B4", "C4", "D4"])),
  )
  free = [spot for spot in holed_300.get_all_items() if not spot.has_tip()][:4]
  await each("   dropped into the holed rack's empty spots", pipettes.drop_tips(free))

  # 9. Dropped at a place on the deck rather than into a spot.
  await each(
    "9. four 1000 uL tips, to be dropped on the deck",
    pipettes.pick_up_tips(holding(holed_1000, 4)),
  )
  place = full_1000.get_item("A1").get_location_wrt(star.deck, x="c", y="c", z="b")
  # Spread along Y: the channels cannot stand on one another, so a place each.
  await each(
    "   let go 30 mm in front of the rack, one place per channel",
    pipettes.drop_tips([place + Coordinate(0, -30 - 18 * channel, 0) for channel in range(4)]),
  )

  # 10. Discarded into the deck's waste.
  await each(
    "10. eight 50 uL tips, to be discarded",
    pipettes.pick_up_tips(spots(full_50, [f"{row}5" for row in "ABCDEFGH"])),
  )
  await each("    discarded into the waste", pipettes.discard_tips())

  # 11. Some channels discarded, the rest returned.
  await each(
    "11. four 300 uL tips",
    pipettes.pick_up_tips(spots(full_300, ["A6", "B6", "C6", "D6"])),
  )
  await each("    channels 0 and 1 discarded", pipettes.discard_tips(use_channels=[0, 1]))
  await each("    channels 2 and 3 returned", pipettes.return_tips(use_channels=[2, 3]))

  # 12. What the guards refuse.
  empty = next(spot for spot in holed_300.get_all_items() if not spot.has_tip())
  await each(f"12. {empty.name.split('_')[-1]}, which holds no tip", pipettes.pick_up_tips([empty]))
  await each(
    "    two more tips, so a channel is carrying one",
    pipettes.pick_up_tips(spots(full_300, ["A7", "B7"])),
  )
  await each(
    "    picking up on a channel that is already carrying",
    pipettes.pick_up_tips(spots(full_300, ["C7", "D7"]), use_channels=[0, 1]),
  )
  await each("    back where they came from", pipettes.return_tips())

  print("\nruns complete; the viewer stays up")


async def main() -> None:
  set_tip_tracking(True)

  star = build_star()
  await star.setup()

  viewer = Viewer3D(star, name="tip_demo.py")
  await viewer.start()

  await asyncio.sleep(1.5)  # let a browser connect before anything moves
  await run(star)
  while True:  # the viewer stays up until it is stopped
    await asyncio.sleep(1.0)


if __name__ == "__main__":
  try:
    asyncio.run(main())
  except KeyboardInterrupt:
    pass
