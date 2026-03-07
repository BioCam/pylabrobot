"""CLARIOstar Plus drawer control mixin."""

from typing import Optional

from pylabrobot.resources.plate import Plate


class _DrawerMixin:
  """Drawer control: open, close, sense drawer state."""

  async def sense_drawer_open(self) -> bool:
    """Return True if the plate drawer is currently open."""
    return bool((await self.request_machine_status())["drawer_open"])

  async def open(self) -> None:
    """Extend the plate drawer. Motor takes ~4.3 s."""
    await self.send_command(
      command_family=self.CommandFamily.TRAY,
      command=self.Command.TRAY_OPEN,
      parameters=b"\x00\x00\x00\x00",
      wait=True,
      poll_interval=0.1,
    )

  async def close(self, plate: Optional[Plate] = None) -> None:
    """Retract the plate drawer. Motor takes ~8 s.

    Args:
      plate: Unused (present for PlateReaderBackend interface compatibility).
    """
    await self.send_command(
      command_family=self.CommandFamily.TRAY,
      command=self.Command.TRAY_CLOSE,
      parameters=b"\x00\x00\x00\x00",
      wait=True,
      poll_interval=0.1,
    )
