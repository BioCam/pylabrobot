"""Convergence wait pattern with pluggable estimator + visualizer.

A reusable primitive for "poll a scalar observable until it enters a
tolerance band around a target", used by e.g. incubator temperature
ramps, centrifuge spin-up, carousel transfer completion, etc.

Design:
  - ``Sample``    : one (time, diff, raw value) tuple from the poll loop.
  - ``Estimate``  : current rate / ETA / monotonic progress from an estimator.
  - ``Estimator`` : Protocol — takes Samples, returns Estimates.
  - ``Visualizer``: Protocol — renders estimator state to the user.
  - ``wait_until_converged()``: async loop that ties them together.

Concrete Estimator / Visualizer implementations live in sibling modules
(``convergence_estimators``, ``convergence_visualizers``) to keep the core
free of optional dependencies.
"""

import asyncio
from dataclasses import dataclass
from typing import Awaitable, Callable, Optional, Protocol, runtime_checkable


@dataclass
class Sample:
  """One polling observation fed to an Estimator.

  Attributes:
    t: Seconds since ``wait_until_converged`` started.
    diff: Absolute distance from the observable to the target.
    value: Raw observable value as returned by ``poll``.
  """

  t: float
  diff: float
  value: float


@dataclass
class Estimate:
  """An Estimator's output for one Sample.

  Attributes:
    rate: Convergence rate in diff-units per second, or ``None`` if the
      estimator is not yet confident.
    eta: Estimated remaining seconds, or ``None`` if unknown.
    progress: Visual progress in [0, 1]. Should be monotonic-friendly
      (the visualizer typically clamps to max-so-far anyway).
  """

  rate: Optional[float]
  eta: Optional[float]
  progress: float


@runtime_checkable
class Estimator(Protocol):
  """Plug-in estimator: take a Sample, emit an Estimate."""

  def update(self, sample: Sample) -> Estimate: ...


@runtime_checkable
class Visualizer(Protocol):
  """Plug-in visualizer: render estimator state to the user."""

  def start(self, label: str) -> None: ...
  def tick(self, sample: Sample, estimate: Estimate) -> None: ...
  def finish(self, sample: Sample) -> None: ...


class SilentVisualizer:
  """No-op visualizer; default for non-interactive use."""

  def start(self, label: str) -> None:
    return None

  def tick(self, sample: Sample, estimate: Estimate) -> None:
    return None

  def finish(self, sample: Sample) -> None:
    return None


async def wait_until_converged(
  *,
  poll: Callable[[], Awaitable[float]],
  target: float,
  tolerance: float,
  estimator: Estimator,
  visualizer: Optional[Visualizer] = None,
  interval_s: float = 0.5,
  timeout_s: Optional[float] = 600.0,
  label: str = "",
) -> float:
  """Poll ``poll()`` until ``|value - target| <= tolerance``.

  Args:
    poll: Async callable returning the current observable value.
    target: Target value to converge on.
    tolerance: Acceptable absolute difference between observable and target.
    estimator: Plug-in that produces rate / ETA / progress from samples.
    visualizer: Plug-in that renders estimator state. Defaults to silent.
    interval_s: Polling interval in seconds.
    timeout_s: Maximum total wait in seconds. ``None`` disables the timeout.
    label: Human-readable label passed to ``visualizer.start()``.

  Returns:
    Final observed value once within tolerance of the target.

  Raises:
    TimeoutError: If the tolerance band is not reached before ``timeout_s``.
  """
  viz: Visualizer = visualizer if visualizer is not None else SilentVisualizer()
  loop = asyncio.get_event_loop()
  start = loop.time()
  viz.start(label)
  sample = Sample(t=0.0, diff=float("inf"), value=float("nan"))
  try:
    while True:
      value = await poll()
      sample = Sample(t=loop.time() - start, diff=abs(value - target), value=value)
      estimate = estimator.update(sample)
      viz.tick(sample, estimate)
      if sample.diff <= tolerance:
        return value
      if timeout_s is not None and sample.t > timeout_s:
        raise TimeoutError(
          f"wait_until_converged: target {target} not reached "
          f"(current {value}, Δ={sample.diff:.3f}, tolerance {tolerance}) "
          f"within {timeout_s:.1f}s."
        )
      await asyncio.sleep(interval_s)
  finally:
    viz.finish(sample)
