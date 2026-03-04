# `encapsulate-pipette-orchestration` — Branch Summary

## What this branch does

Replaces the ad-hoc batching logic inside `STAR_backend.py` with a standalone
`pipette_orchestration.py` module. The backend now delegates all
channel-batching decisions to `plan_batches()`, which returns a list of
`ChannelBatch` objects describing exactly which channels fire together, where
the X carriage goes, and what Y positions to set.

This also integrates PR #915's per-channel minimum Y spacing infrastructure,
so machines with non-standard channel spacing (e.g. 4-channel 18 mm) work
correctly throughout.

---

## Differences vs `main` (current PyLabRobot main)

| Area | main | This branch |
|---|---|---|
| **Batching** | `planning.py` with `group_by_x_batch_by_xy()` + `execute_batched()` inside the backend | `pipette_orchestration.py` with `plan_batches()` — pure function, no backend coupling |
| **Channel spacing** | Scalar `_channel_minimum_y_spacing = 9.0` | Per-channel list `_channels_minimum_y_spacing: List[float]`, queried from hardware at setup |
| **Spacing helpers** | None | `_frontmost_channel_min_y()`, `_backmost_channel_max_y()`, `_min_spacing_between()` used in `can_reach_position`, `move_channel_y`, `position_channels_in_y_direction`, CLLD probing |
| **Phantom interpolation** | Not supported — unused channels between active ones are unhandled | Computed automatically per batch; Y positions interpolated for safe movement |
| **Effective spacing** | N/A | `_effective_spacing(spacings, lo, hi)` — just `max(spacings[lo:hi+1])`, no precomputation |
| **`probe_liquid_heights`** | Calls `execute_batched` → `_probe_liquid_heights_batch` | Calls `plan_batches()` directly, iterates `ChannelBatch` list inline |
| **Single-container offsets** | `get_wide_single_resource_liquid_op_offsets` / `get_tight_single_resource_liquid_op_offsets` only | Adds `compute_single_container_offsets()` with per-channel spacing and odd-span center avoidance |
| **Deleted files** | `planning.py`, `planning_tests.py` exist | Deleted — superseded by `pipette_orchestration.py` / `pipette_orchestration_tests.py` |
| **Chatterbox** | Basic mock | Extended: mocks `probe_liquid_heights`, `get_probing_plan`, `ProbingPlan`, per-channel spacing param |

### New files

- `pylabrobot/liquid_handling/pipette_orchestration.py` — batching logic, effective spacing, container offset math
- `pylabrobot/liquid_handling/pipette_orchestration_tests.py` — 39 tests covering uniform spacing, mixed spacing, phantom interpolation, container offsets

### Deleted files

- `pylabrobot/liquid_handling/backends/hamilton/planning.py`
- `pylabrobot/liquid_handling/backends/hamilton/planning_tests.py`

---

## Differences vs the old version of this branch

### PR #915 alignment

| Area | Old branch | After alignment |
|---|---|---|
| **`_backmost_channel_max_y()`** | Returned raw limit (635 or iswap Y) | Returns `limit - spacing[0] + 3`, symmetric with `_frontmost_channel_min_y()` |
| **`_min_spacing_between()` error** | `f"...got {i} and {j}."` | `f"...got i={i}, j={j}"` (matches PR #915) |
| **`position_channels_in_y_direction` validation** | Fudge factor: `round(gap) >= round(spacing) - 10` | Clean: `round(actual * 1000) < round(required * 1000)` (um comparison) |
| **`move_channel_y` frontmost check** | Local var `min_y_pos` | Inline `self._frontmost_channel_min_y()` call |
| **`TestChannelsMinimumYSpacing`** | 4 tests, chatterbox-only, 18 mm-reject only | 4 tests, raw `STARBackend` for `can_reach`, tests both 9 mm-pass AND 18 mm-fail, verifies JY firmware command strings |
| **PR #915 merge** | Not integrated | Fully merged — `core_check_resource_exists_at_location_center`, `_get_core_front_back`, `channels_request_y_minimum_spacing`, `utils.py` spacing param all incorporated |

### Simplification pass

| Area | Before | After |
|---|---|---|
| **Spacing lookup** | `SpacingTable` (NxN precomputed range-max), `_build_spacing_table()`, `_min_physical_spacing()` — 3 abstractions | `_effective_spacing()` — one-liner: `max(spacings[lo:hi+1])` |
| **Batch state tracking** | 5 parallel lists (`batches`, `batch_lo_ch`, `batch_hi_ch`, `batch_lo_y`, `batch_hi_y`) | Single list of `[indices, lo_ch, hi_ch, lo_y, hi_y]` tuples |
| **Odd-span constant** | `ODD_SPAN_CENTER_AVOIDANCE_OFFSET_MM = 5.5` exported, imported by tests | Inlined as `5.5` with comment at use site |
| **Docstrings** | Formal rst markup, Args/Returns on private helpers | Short docstrings on private/simple functions, matching main's style |
| **Module size** | 383 lines | 260 lines (~30% reduction) |

---

## Test coverage

```
STAR_tests.py                    — 63 tests passed
pipette_orchestration_tests.py   — 39 tests passed
```

No stale references to `_channel_minimum_y_spacing` (singular), `planning import`,
`execute_batched`, or `group_by_x_batch_by_xy` remain in the codebase.
