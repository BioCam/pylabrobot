"""Convergence visualizers for :func:`wait_until_converged`.

Each implements the :class:`~pylabrobot.utils.convergence.Visualizer`
protocol (``start`` / ``tick`` / ``finish``) and renders estimator state
to some sink.

  * :class:`TqdmVisualizer` — progress bar via :mod:`pylabrobot.utils.tqdm`.
  * :class:`LogVisualizer`  — periodic ``logger.info`` messages for
    headless/CI environments.
  * :class:`CallbackVisualizer` — user-supplied callback; useful to bridge
    into a WebSocket feed, a live dashboard, or custom test hooks.

The default ``SilentVisualizer`` lives in :mod:`pylabrobot.utils.convergence`
to keep the core free of imports.
"""

import logging
import math
from typing import Callable, Optional

from pylabrobot.utils.convergence import Estimate, Sample
from pylabrobot.utils.tqdm import tqdm


def _format_hms(seconds: Optional[float]) -> str:
  """Format seconds as ``H:MM:SS`` / ``M:SS`` / ``?`` for ``None``/``NaN``."""
  if seconds is None or math.isnan(seconds) or math.isinf(seconds):
    return "?"
  total = max(0, int(seconds))
  h, rem = divmod(total, 3600)
  m, s = divmod(rem, 60)
  return f"{h:d}:{m:02d}:{s:02d}" if h else f"{m:d}:{s:02d}"


class TqdmVisualizer:
  """Render a tqdm progress bar driven by the estimator's ``progress``.

  The bar is kept monotonic (never decreases) even if the estimator
  revises its progress down after the window shifts. The estimator's
  ETA is shown in the bar description.

  Args:
    resolution: Integer ``total`` for tqdm. Purely a granularity knob;
      the visible bar width is still governed by the terminal columns.
    format_description: Optional ``(sample, estimate) -> str`` override
      for the text shown to the left of the bar.
  """

  def __init__(
    self,
    resolution: int = 1000,
    format_description: Optional[Callable[[Sample, Estimate], str]] = None,
  ) -> None:
    self._resolution = resolution
    self._format = format_description or self._default_format
    self._bar: Optional[tqdm] = None
    self._max_progress = 0.0

  @staticmethod
  def _default_format(sample: Sample, estimate: Estimate) -> str:
    eta = _format_hms(estimate.eta) if estimate.eta is not None else "?"
    return f"value={sample.value:.2f}  Δ={sample.diff:.2f}  ETA {eta}"

  def start(self, label: str) -> None:
    self._bar = tqdm(total=self._resolution, desc=label, unit="")
    self._max_progress = 0.0

  def tick(self, sample: Sample, estimate: Estimate) -> None:
    bar = self._bar
    if bar is None:
      return
    self._max_progress = max(self._max_progress, estimate.progress)
    bar.set_description(self._format(sample, estimate))
    target_n = int(self._max_progress * self._resolution)
    bar.update(target_n - bar.n)

  def finish(self, sample: Sample) -> None:
    bar = self._bar
    if bar is None:
      return
    bar.update(self._resolution - bar.n)
    bar.update(close=True)
    self._bar = None


class LogVisualizer:
  """Emit ``logger.info`` messages instead of drawing a bar.

  Useful in non-TTY environments (CI logs, headless daemons, nested
  shells) where a progress bar would be noise or garbled.

  Args:
    logger: Logger to emit to; defaults to ``logging.getLogger(__name__)``.
    every_n_ticks: Emit a message every N ticks (1 = every tick).
  """

  def __init__(
    self,
    logger: Optional[logging.Logger] = None,
    every_n_ticks: int = 10,
  ) -> None:
    self._logger = logger or logging.getLogger(__name__)
    self._every = max(1, every_n_ticks)
    self._tick_i = 0
    self._label = ""

  def start(self, label: str) -> None:
    self._label = label
    self._tick_i = 0
    self._logger.info("wait started: %s", label)

  def tick(self, sample: Sample, estimate: Estimate) -> None:
    self._tick_i += 1
    if self._tick_i % self._every != 0:
      return
    eta = _format_hms(estimate.eta) if estimate.eta is not None else "?"
    self._logger.info(
      "wait %s: t=%.1fs value=%.3f Δ=%.3f ETA=%s",
      self._label,
      sample.t,
      sample.value,
      sample.diff,
      eta,
    )

  def finish(self, sample: Sample) -> None:
    self._logger.info("wait done: %s at t=%.1fs (Δ=%.3f)", self._label, sample.t, sample.diff)


class CallbackVisualizer:
  """Invoke a user-supplied callback on each ``(sample, estimate)`` pair.

  Useful for bridging into external UIs (WebSocket feeds, live plots,
  test assertions) without coupling the wait loop to them.
  """

  def __init__(self, on_tick: Callable[[Sample, Estimate], None]) -> None:
    self._on_tick = on_tick

  def start(self, label: str) -> None:
    return None

  def tick(self, sample: Sample, estimate: Estimate) -> None:
    self._on_tick(sample, estimate)

  def finish(self, sample: Sample) -> None:
    return None
