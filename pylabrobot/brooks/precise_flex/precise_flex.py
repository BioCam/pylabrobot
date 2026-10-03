"""Deprecated: this module moved to ``pylabrobot.brooks.precise_flex.driver.master``."""

import warnings

warnings.warn(
  "Importing from pylabrobot.brooks.precise_flex.precise_flex is deprecated. "
  "Use pylabrobot.brooks.precise_flex.driver.master instead.",
  DeprecationWarning,
  stacklevel=2,
)

from pylabrobot.brooks.precise_flex.driver.features.arm import BLEND_IN_RANGE  # noqa: E402, F401
from pylabrobot.brooks.precise_flex.driver.master import (  # noqa: E402, F401
  MotionProfile,
  PreciseFlex,
)
