import warnings

from .clariostar_backend import CLARIOstarBackend  # noqa: F401

warnings.warn(
  "pylabrobot.plate_reading.bmg_labtech.clario_star_backend is deprecated and will be removed "
  "in 2026-05. Please use pylabrobot.plate_reading.bmg_labtech.clariostar_backend instead.",
  DeprecationWarning,
  stacklevel=2,
)
