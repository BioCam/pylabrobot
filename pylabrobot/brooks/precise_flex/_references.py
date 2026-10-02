"""How PreciseFlex events name the controller they come from."""

from typing import TYPE_CHECKING

if TYPE_CHECKING:
  from .precise_flex import PreciseFlex


def _controller_reference(controller: "PreciseFlex") -> dict[str, object]:
  """Return the stable controller identity used by structured execution events."""
  return {
    "name": "precise_flex",
    "type": type(controller).__name__,
    "host": controller.io._host,
    "port": controller.io._port,
  }
