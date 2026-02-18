import warnings

from .bmg_labtech.clariostar_backend import CLARIOstarBackend  # noqa: F401

warnings.warn(
  "pylabrobot.plate_reading.clario_star_backend is deprecated and will be removed in a future release. "
  "Please use pylabrobot.plate_reading.bmg_labtech.clariostar_backend instead.",
)
