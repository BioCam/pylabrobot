"""Convergence estimators for :func:`wait_until_converged`.

Each takes a stream of :class:`~pylabrobot.utils.convergence.Sample` and emits
per-sample :class:`~pylabrobot.utils.convergence.Estimate`. Pick based on the
expected shape of the observable's approach to target:

  * :class:`LinearSlopeEstimator` — cumulative average slope. Cheap, but
    systematically underestimates ETA near the target because it bakes the
    fast early phase in forever.
  * :class:`RollingWindowEstimator` — windowed least-squares slope with a
    noise floor. Handles multi-regime approaches (sigmoidal warmups, etc.)
    and is the recommended default.
  * :class:`ExponentialFitEstimator` — log-space linearisation. Exact for
    first-order systems (pure exponential). For multi-regime systems it
    over-estimates during any non-exponential phase (e.g. sigmoidal start).
"""

import math
from typing import List, Optional

from pylabrobot.utils.convergence import Estimate, Sample


class LinearSlopeEstimator:
  """Average slope from the very first sample.

  Rate = ``(initial_diff - current_diff) / elapsed``. Always has an estimate
  from the second sample onward but biases ETA low near the target.
  """

  def __init__(self) -> None:
    self._first: Optional[Sample] = None

  def update(self, s: Sample) -> Estimate:
    if self._first is None:
      self._first = s
      return Estimate(rate=None, eta=None, progress=0.0)
    elapsed = s.t - self._first.t
    delta = self._first.diff - s.diff
    if elapsed < 1e-6 or delta <= 0:
      return Estimate(rate=None, eta=None, progress=0.0)
    rate = delta / elapsed
    eta = s.diff / rate if rate > 0 else None
    progress = min(1.0, delta / max(self._first.diff, 1e-6))
    return Estimate(rate=rate, eta=eta, progress=progress)


class RollingWindowEstimator:
  """Least-squares slope over the last ``window_s`` seconds.

  Emits a confident :class:`Estimate` only when the window has
  ``min_samples`` points spanning at least half of ``window_s`` **and**
  the fitted rate exceeds ``rate_floor``. Below the floor the estimator
  returns progress=0 and rate=eta=None — i.e. the visualizer should say
  "warming up, ETA unknown" rather than pretend to know.

  Args:
    window_s: Lookback window for the slope fit.
    rate_floor: Minimum ``|diff|``/s to trust. Tune per device sensor
      noise (roughly 2σ / ``window_s``).
    min_samples: Minimum number of samples required in the window.
  """

  def __init__(
    self,
    window_s: float = 30.0,
    rate_floor: float = 0.005,
    min_samples: int = 4,
  ) -> None:
    self.window_s = window_s
    self.rate_floor = rate_floor
    self.min_samples = min_samples
    self._hist: List[Sample] = []

  def update(self, s: Sample) -> Estimate:
    self._hist.append(s)
    cutoff = s.t - self.window_s
    while self._hist and self._hist[0].t < cutoff:
      self._hist.pop(0)
    if len(self._hist) < self.min_samples:
      return Estimate(rate=None, eta=None, progress=0.0)
    span = self._hist[-1].t - self._hist[0].t
    if span < self.window_s * 0.5:
      return Estimate(rate=None, eta=None, progress=0.0)
    rate = self._fit_rate()
    if rate is None or rate < self.rate_floor:
      return Estimate(rate=None, eta=None, progress=0.0)
    eta = s.diff / rate
    progress = min(1.0, s.t / max(s.t + eta, 1e-6))
    return Estimate(rate=rate, eta=eta, progress=progress)

  def _fit_rate(self) -> Optional[float]:
    """Hand-rolled OLS slope; returns convergence rate (positive = closing)."""
    ts = [s.t for s in self._hist]
    ds = [s.diff for s in self._hist]
    n = len(ts)
    mean_t = sum(ts) / n
    mean_d = sum(ds) / n
    num = sum((t - mean_t) * (d - mean_d) for t, d in zip(ts, ds))
    den = sum((t - mean_t) ** 2 for t in ts)
    if den == 0:
      return None
    # d/dt of diff is num/den; convergence rate is its negation.
    return -num / den


class ExponentialFitEstimator:
  """Log-space linearisation for first-order (exponential) systems.

  Assumes ``diff(t) = diff0 · exp(-k·t)``. Under that model,
  ``log(diff)`` is linear in ``t`` and the ETA formula becomes exact.

  Do NOT use for multi-regime systems (sigmoidal warmups with a
  plateau phase) — empirical tests showed this overestimates ETA by
  an order of magnitude during the plateau. Prefer
  :class:`RollingWindowEstimator` unless you know the system is
  first-order.
  """

  def __init__(self, tolerance: float) -> None:
    self._tolerance = max(tolerance, 1e-12)
    self._log_tol = math.log(self._tolerance)
    self._log_initial: Optional[float] = None

  def update(self, s: Sample) -> Estimate:
    diff_floor = max(s.diff, self._tolerance)
    if self._log_initial is None:
      self._log_initial = math.log(diff_floor)
    log_span = self._log_initial - self._log_tol
    if log_span <= 1e-6:
      return Estimate(rate=None, eta=None, progress=1.0)
    progress = max(0.0, min(1.0, (self._log_initial - math.log(diff_floor)) / log_span))
    if progress < 1e-4 or progress >= 1.0:
      return Estimate(rate=None, eta=None, progress=progress)
    eta = s.t * (1.0 - progress) / progress
    rate = s.diff / eta if eta > 0 else None
    return Estimate(rate=rate, eta=eta, progress=progress)
