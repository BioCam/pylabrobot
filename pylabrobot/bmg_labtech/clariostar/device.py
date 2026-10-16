"""BMG Labtech CLARIOstar plate reader."""

from typing import Optional, Union

from pylabrobot.io.ftdi import FTDI
from pylabrobot.io.usb import USB
from pylabrobot.resources import Coordinate, PlateHolder, Resource

from .driver.driver import CLARIOstarDriver, Interface
from .driver.features.drawer import Drawer


class CLARIOstar(Resource):
  """BMG Labtech CLARIOstar plate reader.

  ``interface`` picks how the reader is wired: ``"ftdi"`` (the default) for readers with the
  FTDI serial bridge, ``"usb"`` for readers with native USB. Commands are the same on both.
  A given ``io`` sets the interface by its type.
  """

  def __init__(
    self,
    name: str,
    *,
    interface: Optional[Interface] = None,
    device_id: Optional[str] = None,
    io: Optional[Union[FTDI, USB]] = None,
    size_x: float = 0.0,
    size_y: float = 0.0,
    size_z: float = 0.0,
  ):
    """
    Args:
      name: the resource name.
      interface: ``"ftdi"`` or ``"usb"``; None takes it from ``io``, or ``"ftdi"``.
      device_id: the FTDI device id, or the USB serial number. None uses the first reader
        found.
      io: an already-built ``FTDI`` or ``USB``, used instead of building one.
      size_x: footprint in x.
      size_y: footprint in y.
      size_z: height.
    """
    super().__init__(name=name, size_x=size_x, size_y=size_y, size_z=size_z, model="BMG CLARIOstar")
    self.driver = CLARIOstarDriver(interface=interface, device_id=device_id, io=io)
    self.plate_holder = PlateHolder(
      name=f"{name}_plate_holder",
      size_x=127.76,
      size_y=85.48,
      size_z=0,
      pedestal_size_z=0,
      child_location=Coordinate.zero(),
    )
    self.assign_child_resource(self.plate_holder, location=Coordinate.zero())

  @property
  def drawer(self) -> Drawer:
    """The drawer."""
    return self.driver.drawer

  async def setup(self) -> None:
    """Connect and initialize the reader (about 13 s)."""
    await self.driver.setup()

  async def stop(self) -> None:
    """Close the connection."""
    await self.driver.stop()

  async def __aenter__(self) -> "CLARIOstar":
    """Connect, as `setup` does."""
    await self.setup()
    return self

  async def __aexit__(self, *exc) -> None:
    """Close the connection."""
    await self.stop()
