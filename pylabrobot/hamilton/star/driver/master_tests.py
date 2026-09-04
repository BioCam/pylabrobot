import contextlib
import dataclasses
import json
import pathlib
import tempfile
import unittest
import unittest.mock
from typing import List, cast

import pylabrobot.hamilton.star.driver.simulator as simulator
from pylabrobot.hamilton.star.driver.configuration import (
  DeviceConfiguration,
  read_configuration,
  to_jsonable,
)
from pylabrobot.hamilton.star.driver.features.head96 import Head96
from pylabrobot.hamilton.star.driver.simulator import (
  BARE_X_ARM,
  RECORDING_STAR,
  STARSimulationDriver,
)
from pylabrobot.resources.coordinate import Coordinate
from pylabrobot.resources.hamilton import STARDeck

# The device this package ships a recording of, read through the one reader there is: tests need a
# device to start from, and this is the one they stand in for.
RECORDED_DEVICE = cast(DeviceConfiguration, read_configuration(RECORDING_STAR)["device"])


def declaring(**parts: object) -> str:
  """The shipped recording with parts swapped out, written where it can be read back.

  A declaration is read from a file and nothing else, so a test that needs a device no recording
  describes writes one. Everything not named here stays as the recorded STAR has it.

  Args:
    parts: `device` for the device itself, or a feature name for something the left arm carries.

  Returns:
    The path it was written to.
  """
  tree = json.loads(pathlib.Path(RECORDING_STAR).read_text())
  for name, part in parts.items():
    if name == "device":
      tree["device"] = to_jsonable(part)
    else:
      tree["arms"]["left"][name] = to_jsonable(part)
  written = pathlib.Path(tempfile.mkdtemp()) / "declared.json"
  written.write_text(json.dumps(tree))
  return str(written)


def declaring_a_device(
  channels: int, head96: bool, head384: bool, iswap: bool, autoload: bool
) -> str:
  """A declaration for a STAR fitted with exactly these, written where it can be read back.

  Built from the shipped recording so every value is one a device answered: only what is fitted
  changes. The bits and the features are set together, since the bits are what the driver builds
  from and the features are what it builds.

  Args:
    channels: how many pipetting channels, 0 for none.
    head96: whether a 96-head is fitted.
    head384: whether a 384-head is fitted.
    iswap: whether an iSWAP is fitted.
    autoload: whether an autoload is fitted.

  Returns:
    The path it was written to.
  """
  tree = json.loads(pathlib.Path(RECORDING_STAR).read_text())
  device, arm, carried = tree["device"], tree["device"]["left_arm"], tree["arms"]["left"]

  device["num_pip_channels"] = channels
  arm["pip_installed"] = channels > 0
  device["ka_head96_installed"] = arm["head96_installed"] = head96
  device["dispensing_head_384_installed"] = arm["head384_installed"] = head384
  device["kb_iswap_installed"] = arm["iswap_installed"] = iswap
  device["autoload_installed"] = autoload

  for name, fitted in (("head96", head96), ("iswap", iswap), ("pipettes", channels > 0)):
    if not fitted:
      carried.pop(name, None)
  if not autoload:
    tree.pop("autoload", None)
  if channels > 0:
    # One recorded channel stands for all of them: they are the same part.
    recorded = carried["pipettes"]["channels"]
    carried["pipettes"]["channels"] = (recorded * channels)[:channels]

  written = pathlib.Path(tempfile.mkdtemp()) / "declared.json"
  written.write_text(json.dumps(tree))
  return str(written)


class TestXArm(unittest.IsolatedAsyncioTestCase):
  """`STARDriver.x_arm` is the single-arm shorthand, and its job is which error it raises."""

  async def test_before_setup(self):
    with self.assertRaises(RuntimeError):
      STARSimulationDriver(deck=STARDeck(), declared_configuration_json=RECORDING_STAR).x_arm

  async def test_one_arm(self):
    star = STARSimulationDriver(deck=STARDeck(), declared_configuration_json=RECORDING_STAR)
    await star.setup()
    self.assertIs(star.x_arm, star.left_x_arm)

  async def test_two_arms(self):
    both = dataclasses.replace(
      RECORDED_DEVICE,
      right_arm=BARE_X_ARM,
    )
    star = STARSimulationDriver(
      deck=STARDeck(),
      declared_configuration_json=declaring(device=both),
    )
    await star.setup()
    with self.assertRaises(ValueError):
      star.x_arm

  async def test_no_arms(self):
    neither = dataclasses.replace(RECORDED_DEVICE, left_arm=None, right_arm=None)
    star = STARSimulationDriver(
      deck=STARDeck(),
      declared_configuration_json=declaring(device=neither),
    )
    await star.setup()
    with self.assertRaises(ValueError):
      star.x_arm


class TestSimulation(unittest.IsolatedAsyncioTestCase):
  """A simulated machine has no firmware to ask, so the resource model is all it can answer from."""

  async def test_simulation_needs_a_deck(self):
    with self.assertRaises(ValueError):
      STARSimulationDriver()


# What each initialization step is called in the sequences below, and where it is defined. The simulated
# classes override some of them, so each is recorded where a simulated run would reach it.
MOVING_STEPS = [
  (simulator.STARSimulationDriver, "pre_initialize", "VI instrument"),
  (simulator.Pipettes, "probe_z_max", "ZA channels to safe Z"),
  (simulator.SimulatedPipettes, "initialize", "DI channels"),
  (simulator.SimulatedISWAP, "initialize", "FI iSWAP"),
  (simulator.iSWAP, "park", "iSWAP park"),
  (simulator._SimulatedHead, "initialize", "EI 96-head"),
  (simulator._SimulatedHead, "probe_z_max", "EV 96-head probe and retract"),
  (simulator.SimulatedAutoload, "initialize", "II autoload"),
  (simulator.SimulatedAutoload, "park", "autoload park"),
]


@contextlib.contextmanager
def recorded_moves():
  """Record every setup step that moves the machine, in the order setup runs them."""
  moves: List[str] = []
  with contextlib.ExitStack() as stack:
    for owner, name, label in MOVING_STEPS:
      real = owner.__dict__[name]

      def wrap(real=real, label=label):
        async def recorded(self, *args, **kwargs):
          moves.append(label)
          return await real(self, *args, **kwargs)

        return recorded

      stack.enter_context(unittest.mock.patch.object(owner, name, wrap()))
    yield moves


class TestSetupSequence(unittest.IsolatedAsyncioTestCase):
  """Setup moves the machine, and the order it moves it in is what keeps the arm's modules from
  driving into each other. It follows the legacy routine: the channels reach Z safety and the head
  retracts before the iSWAP moves on the shared left X-drive, and the head is only initialized once
  its own status has been asked. The 96-head retract runs on every setup, since that retract is
  what keeps it clear."""

  async def run_setup(self, instrument_up: bool, head_up: bool, eject_position: bool) -> List[str]:
    star = simulator.STARSimulationDriver(
      deck=STARDeck(),
      initialized=instrument_up,
      declared_configuration_json=RECORDING_STAR,
    )
    star.initialized["H0"] = head_up
    cast(Head96, star.head96).configuration.tip_discard_location = (
      Coordinate(-263.8, 108.3, 200.0) if eject_position else None
    )
    with recorded_moves() as moves:
      await star.setup()
    return list(moves)

  async def test_everything_already_up(self):
    self.assertEqual(
      await self.run_setup(instrument_up=True, head_up=True, eject_position=True),
      [
        "ZA channels to safe Z",
        "EV 96-head probe and retract",
        "ZA channels to safe Z",
        "iSWAP park",
        "EV 96-head probe and retract",
        "II autoload",
        "autoload park",
      ],
    )

  async def test_head_down_on_an_instrument_that_is_up(self):
    self.assertEqual(
      await self.run_setup(instrument_up=True, head_up=False, eject_position=True),
      [
        "ZA channels to safe Z",
        "EV 96-head probe and retract",
        "ZA channels to safe Z",
        "iSWAP park",
        "EI 96-head",
        "EV 96-head probe and retract",
        "II autoload",
        "autoload park",
      ],
    )

  async def test_head_down_with_nowhere_to_eject(self):
    """It is still retracted, because that is what keeps it clear of the iSWAP; it is just not
    initialized, since initializing throws off whatever is mounted and there is nowhere to drop it."""
    self.assertEqual(
      await self.run_setup(instrument_up=True, head_up=False, eject_position=False),
      [
        "ZA channels to safe Z",
        "EV 96-head probe and retract",
        "ZA channels to safe Z",
        "iSWAP park",
        "EV 96-head probe and retract",
        "II autoload",
        "autoload park",
      ],
    )

  async def test_instrument_not_up(self):
    """The instrument procedure homes every drive, so nothing is raised beforehand. The autoload
    is its own unit, so it comes up alongside the procedure rather than after it."""
    self.assertEqual(
      await self.run_setup(instrument_up=False, head_up=False, eject_position=True),
      [
        "VI instrument",
        "II autoload",
        "autoload park",
        "DI channels",
        "ZA channels to safe Z",
        "FI iSWAP",
        "iSWAP park",
        "EI 96-head",
        "EV 96-head probe and retract",
      ],
    )


class TestEveryConfiguration(unittest.IsolatedAsyncioTestCase):
  """Every combination of what a STAR can be fitted with, and what each one builds.

  What the declaration says is fitted is what the driver has to end up carrying, and nothing else.
  A feature built from a bit that was not set, or missing where one was, is the failure this is
  looking for.
  """

  async def test_each_combination_builds_exactly_what_it_declares(self):
    for channels in (4, 8, 12, 16):
      for head96 in (False, True):
        for head384 in (False, True):
          for iswap in (False, True):
            for autoload in (False, True):
              with self.subTest(
                channels=channels,
                head96=head96,
                head384=head384,
                iswap=iswap,
                autoload=autoload,
              ):
                driver = STARSimulationDriver(
                  deck=STARDeck(),
                  declared_configuration_json=declaring_a_device(
                    channels=channels,
                    head96=head96,
                    head384=head384,
                    iswap=iswap,
                    autoload=autoload,
                  ),
                )
                await driver.setup()
                arm = driver.x_arm
                self.assertEqual(arm.pipettes is not None, channels > 0)
                if channels > 0:
                  self.assertEqual(driver.num_channels, channels)
                self.assertEqual(arm.head96 is not None, head96)
                self.assertEqual(arm.head384 is not None, head384)
                self.assertEqual(arm.iswap is not None, iswap)
                self.assertEqual(driver.autoload is not None, autoload)
