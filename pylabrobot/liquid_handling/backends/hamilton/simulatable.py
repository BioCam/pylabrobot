"""Decorator that lets callers inject simulated return values.

``@simulated_value`` is placed on **STARBackend** methods that return parsed
firmware responses.  Callers may pass ``simulated_value=`` to override the
return value.

::

    # STARBackend definition:
    @simulated_value
    async def head96_request_tip_presence(self) -> int:
        ...  # real firmware logic

    # Notebook (simulation):
    q = await star.head96_request_tip_presence(simulated_value=0)   # returns 0
    q = await star.head96_request_tip_presence()                     # returns 0 (from _parse_response zeros)

    # Notebook (execution):
    q = await star.head96_request_tip_presence()                     # real value
    q = await star.head96_request_tip_presence(simulated_value=0)    # real value (simulated_value ignored)
"""

import functools
from typing import Any, Callable


def simulated_value(fn: Callable) -> Callable:
  """Allow callers to pass ``simulated_value=`` to override the return value in simulation.

  - **Simulation** (``self._is_simulation_backend is True``):
    - If ``simulated_value=X`` is passed, the method body still runs (for firmware
      logging) and ``X`` is returned instead of the parsed result.
    - If ``simulated_value`` is omitted, the method runs normally (returns
      whatever ``_parse_response`` produces — typically zeros).
  - **Execution** (``self._is_simulation_backend is False``): the method runs
    normally.  Any ``simulated_value`` kwarg is silently ignored.
  """

  _SENTINEL = object()

  @functools.wraps(fn)
  async def wrapper(self: Any, *args: Any, **kwargs: Any) -> Any:
    override = kwargs.pop("simulated_value", _SENTINEL)

    if self._is_simulation_backend and override is not _SENTINEL:
      # Run method body so firmware commands are assembled and logged
      try:
        await fn(self, *args, **kwargs)
      except Exception:
        pass
      return override

    # Execution, or simulation without override: run normally
    return await fn(self, *args, **kwargs)

  wrapper._is_simulated_value = True  # type: ignore[attr-defined]
  return wrapper
