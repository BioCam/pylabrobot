import os

import pytest

from pylabrobot.azenta.xpeel import HAS_SERIAL, XPeel
from pylabrobot.resources import Coordinate, cor_96_wellplate_360uL_Fb

pytestmark = pytest.mark.skipif(not HAS_SERIAL, reason="pyserial is not installed")


def test_models_are_shipped():
  xpeel = XPeel(port="/dev/null")
  model_dir = os.path.join(os.path.dirname(__file__), "resource_model")
  for resource in (xpeel, xpeel.plate_carrier):
    assert os.path.isfile(os.path.join(model_dir, f"{resource.model}.glb"))


def test_plate_seats_on_the_carrier():
  xpeel = XPeel(port="/dev/null")
  plate = cor_96_wellplate_360uL_Fb(name="plate")
  xpeel.plate_carrier.assign_child_resource(plate)
  assert plate.get_location_wrt(xpeel) == Coordinate(31.07, 36.11, 136.65)
