"""Predicate-based wait pattern for non-numeric observables.

Complements :func:`~pylabrobot.utils.convergence.wait_until_converged` (for
scalar convergence with a tolerance band) by covering the boolean / enum /
status-byte / substring / composite-state patterns where there is no
meaningful "distance to target". The observable is polled and a user-supplied
predicate decides when to stop.

Design:
  - :func:`wait_until_predicate`: async poll loop, returns the final value.
  - :class:`PredicateVisualizer`: Protocol — start/tick/finish for rendering.
  - Concrete visualizers: :class:`SilentPredicateVisualizer` (default),
    :class:`TqdmSpinnerVisualizer`, :class:`LogPredicateVisualizer`.
"""

import asyncio
import logging
from typing import Awaitable, Callable, Optional, Protocol, TypeVar, runtime_checkable

from pylabrobot.utils.tqdm import tqdm

T = TypeVar("T")


@runtime_checkable
class PredicateVisualizer(Protocol):
  """Plug-in visualizer for predicate-based waits.

  Loose typing (``value: object``) at the protocol boundary keeps
  visualizers reusable across arbitrary observable types.
  """

  def start(self, label: str) -> None: ...
  def tick(self, elapsed: float, value: object) -> None: ...
  def finish(self, elapsed: float, value: object) -> None: ...


class SilentPredicateVisualizer:
  """No-op visualizer; default for non-interactive use."""

  def start(self, label: str) -> None:
    return None

  def tick(self, elapsed: float, value: object) -> None:
    return None

  def finish(self, elapsed: float, value: object) -> None:
    return None


class TqdmSpinnerVisualizer:
  """Spinner + elapsed time via :mod:`pylabrobot.utils.tqdm`.

  Unlike ``TqdmVisualizer`` (which draws a progress bar), this
  visualizer only shows a spinning indicator plus count / rate,
  because a predicate has no notion of fractional progress.

  The latest polled value's repr appears in the description, so
  users can watch device state transitions as they happen.

  Args:
    format_value: Optional ``value -> str`` formatter for the value
      shown in the description. Defaults to ``repr()``.
  """

  _SPIN = ("⠋", "⠙", "⠹", "⠸", "⠼", "⠴", "⠦", "⠧", "⠇", "⠏")

  def __init__(self, format_value: Optional[Callable[[object], str]] = None) -> None:
    self._format_value = format_value or (lambda v: f"{v!r}")
    self._bar: Optional[tqdm] = None
    self._label = ""
    self._i = 0

  def _desc(self, value: Optional[object]) -> str:
    spin = self._SPIN[self._i % len(self._SPIN)]
    text = self._format_value(value) if value is not None else "..."
    return f"{spin} {self._label} {text}" if self._label else f"{spin} {text}"

  def start(self, label: str) -> None:
    self._label = label
    self._i = 0
    # total=None → tqdm shows count + rate + elapsed, no bar (since self.t == 0).
    self._bar = tqdm(desc=self._desc(None), unit="poll")

  def tick(self, elapsed: float, value: object) -> None:
    bar = self._bar
    if bar is None:
      return
    self._i += 1
    bar.set_description(self._desc(value))
    bar.update(1)

  def finish(self, elapsed: float, value: object) -> None:
    bar = self._bar
    if bar is None:
      return
    text = self._format_value(value) if value is not None else "..."
    bar.set_description(f"✓ {self._label} {text}" if self._label else f"✓ {text}")
    bar.update(close=True)
    self._bar = None


class LogPredicateVisualizer:
  """Emit ``logger.info`` messages in place of drawing anything.

  Useful in non-TTY environments (CI logs, headless daemons) where a
  spinner would be noise or garbled.

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
    self._label = ""
    self._tick_i = 0

  def start(self, label: str) -> None:
    self._label = label
    self._tick_i = 0
    self._logger.info("wait started: %s", label)

  def tick(self, elapsed: float, value: object) -> None:
    self._tick_i += 1
    if self._tick_i % self._every != 0:
      return
    self._logger.info("wait %s: t=%.1fs value=%r", self._label, elapsed, value)

  def finish(self, elapsed: float, value: object) -> None:
    self._logger.info("wait done: %s at t=%.1fs (value=%r)", self._label, elapsed, value)


async def wait_until_predicate(
  *,
  poll: Callable[[], Awaitable[T]],
  predicate: Callable[[T], bool],
  interval_s: float = 0.1,
  timeout_s: Optional[float] = 60.0,
  visualizer: Optional[PredicateVisualizer] = None,
  label: str = "",
) -> T:
  """Poll ``poll()`` until ``predicate(value)`` returns ``True``.

  The right primitive for non-numeric observables where convergence-
  to-target is not the right mental model: boolean flags, enum state
  bytes, substring presence, dataclasses of device status, etc. For
  scalar observables with a tolerance band, prefer
  :func:`~pylabrobot.utils.convergence.wait_until_converged`.

  Args:
    poll: Async callable returning the current observable value.
    predicate: Called once per polled value; return ``True`` to stop.
    interval_s: Polling interval in seconds.
    timeout_s: Maximum total wait in seconds. ``None`` disables the timeout.
    visualizer: Renders poll state. Defaults to silent.
    label: Human-readable label passed to ``visualizer.start()``.

  Returns:
    The final observed value that satisfied ``predicate``.

  Raises:
    TimeoutError: If ``predicate`` never returns ``True`` within ``timeout_s``.
  """
  viz: PredicateVisualizer = visualizer if visualizer is not None else SilentPredicateVisualizer()
  loop = asyncio.get_event_loop()
  start = loop.time()
  viz.start(label)
  last_value: Optional[T] = None
  try:
    while True:
      value = await poll()
      last_value = value
      elapsed = loop.time() - start
      viz.tick(elapsed, value)
      if predicate(value):
        return value
      if timeout_s is not None and elapsed > timeout_s:
        raise TimeoutError(
          f"wait_until_predicate: predicate not satisfied within "
          f"{timeout_s:.1f}s (last value: {value!r}, label: {label!r})."
        )
      await asyncio.sleep(interval_s)
  finally:
    viz.finish(loop.time() - start, last_value)
