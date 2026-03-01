"""Pipette orchestration: partition channel–target pairs into executable batches.

Multi-channel liquid handlers have physical constraints (single X carriage, minimum
Y spacing, descending Y order by channel index) that limit which channels can act
simultaneously. This module computes execution plans consumed by probe_liquid_heights,
aspirate, and dispense.

    batches = plan_batches(use_channels, x_pos, y_pos, channel_spacings=[9.0]*8)
    for batch in batches:
        # move X carriage to batch.x_position
        # position channels in Y using batch.y_positions
        # execute command for batch.channels
"""

from dataclasses import dataclass, field
from typing import Dict, List, Optional, Tuple, Union

from pylabrobot.liquid_handling.utils import (
  MIN_SPACING_EDGE,
  get_wide_single_resource_liquid_op_offsets,
)
from pylabrobot.resources.container import Container
from pylabrobot.resources.coordinate import Coordinate

X_GROUPING_TOLERANCE_MM = 0.1

# Half the min spacing + margin to avoid container center dividers on odd channel counts.
# Hamilton 1000 uL channels are 9 mm apart → 9/2 + 1 = 5.5 mm
ODD_SPAN_CENTER_AVOIDANCE_OFFSET_MM = 5.5

# Type alias for the precomputed range-max table used by _min_physical_spacing.
SpacingTable = List[List[float]]


def _build_spacing_table(spacings: List[float]) -> SpacingTable:
  """Precompute NxN range-max table for O(1) min-physical-spacing lookups.

  ``table[i][j] == max(spacings[i:j+1])`` for all ``i <= j``.
  N is the number of channels on the instrument (typically ≤16), so this is cheap.
  """
  n = len(spacings)
  table: SpacingTable = [[0.0] * n for _ in range(n)]
  for i in range(n):
    table[i][i] = spacings[i]
    for j in range(i + 1, n):
      table[i][j] = max(table[i][j - 1], spacings[j])
  return table


def _min_physical_spacing(table: SpacingTable, ch_lo: int, ch_hi: int) -> float:
  """O(1) lookup: max(spacings[ch_lo:ch_hi+1])."""
  return table[ch_lo][ch_hi]


@dataclass
class ChannelBatch:
  """A group of channels that can operate simultaneously.

  Attributes:
    x_position: Absolute X coordinate for this batch.
    indices: Indices into the caller's original lists (containers, offsets, etc.).
    channels: Actual channel numbers (values from ``use_channels``).
    y_positions: Channel number → absolute Y position, including phantom (intermediate)
      channels that must be positioned to satisfy spacing constraints.
  """

  x_position: float
  indices: List[int]
  channels: List[int]
  y_positions: Dict[int, float] = field(default_factory=dict)


def plan_batches(
  use_channels: List[int],
  x_pos: List[float],
  y_pos: List[float],
  channel_spacings: Union[float, List[float]],
  x_tolerance: float = X_GROUPING_TOLERANCE_MM,
) -> List[ChannelBatch]:
  """Partition channel–position pairs into executable batches.

  Groups by X position (within ``x_tolerance``), then within each X group partitions
  into Y sub-batches respecting per-channel minimum spacing. Computes phantom channel
  positions for intermediate channels between non-consecutive batch members.

  Args:
    use_channels: Channel indices being used (e.g. ``[0, 1, 2, 5, 6, 7]``).
    x_pos: Absolute X position for each entry in ``use_channels``.
    y_pos: Absolute Y position for each entry in ``use_channels``.
    channel_spacings: Minimum Y spacing per channel (mm). Either a single float
      (uniform spacing, e.g. ``9.0`` for all-1mL) or a list with one entry per
      channel on the instrument (e.g. ``[9.0, 9.0, 18.0, 18.0, ...]`` for mixed
      1mL + 5mL). The effective spacing between channels i and j is
      ``max(channel_spacings[i:j+1])``.
    x_tolerance: Positions within this tolerance share an X group. Default 0.1 mm.

  Returns:
    Flat list of :class:`ChannelBatch` objects. Batches sharing an X position are
    consecutive. Batches with different X positions appear in order of first occurrence.

  Raises:
    ValueError: If input lists have mismatched lengths or ``use_channels`` is empty.
  """

  if not (len(use_channels) == len(x_pos) == len(y_pos)):
    raise ValueError(
      f"use_channels, x_pos, and y_pos must have the same length, "
      f"got {len(use_channels)}, {len(x_pos)}, {len(y_pos)}."
    )
  if len(use_channels) == 0:
    raise ValueError("use_channels must not be empty.")

  # Normalize scalar spacing to per-channel list
  max_ch = max(use_channels)
  if isinstance(channel_spacings, (int, float)):
    spacings: List[float] = [float(channel_spacings)] * (max_ch + 1)
  else:
    spacings = channel_spacings

  # Precompute O(1) range-max table for spacings
  spacing_table = _build_spacing_table(spacings)

  # Group indices by X position (preserving first-appearance order)
  x_groups: Dict[float, List[int]] = {}
  for i, x in enumerate(x_pos):
    x_rounded = round(x / x_tolerance) * x_tolerance
    x_groups.setdefault(x_rounded, []).append(i)

  result: List[ChannelBatch] = []
  for _, indices in x_groups.items():
    group_x = x_pos[indices[0]]
    result.extend(
      _partition_into_y_batches(indices, use_channels, y_pos, spacing_table, group_x)
    )

  return result


def _partition_into_y_batches(
  indices: List[int],
  use_channels: List[int],
  y_pos: List[float],
  spacing_table: SpacingTable,
  x_position: float,
) -> List[ChannelBatch]:
  """Partition channels within an X group into minimum parallel-compatible batches.

  Processes channels in ascending index order. For each candidate, checks whether it
  can join an existing batch by verifying the spacing constraint against both the
  batch's lowest and highest channel (the range extremes).

  **Why two checks suffice:** Since channels are added in ascending order, the candidate
  is always the new high end. The (lo, candidate) check covers the full-span constraint
  — any intermediate member *m* has a shorter range to the candidate, and the effective
  spacing ``max(spacings[m:candidate+1])`` is ≤ ``max(spacings[lo:candidate+1])``, so if
  the full-span check passes, all intermediate checks pass. The (prev_hi, candidate) check
  catches the local constraint where the gap to the nearest neighbor might be too small
  even though the full-span average is satisfied.

  Phantom channels between non-consecutive batch members are assigned Y positions at
  the effective spacing for their segment.

  Args:
    indices: Indices into the caller's original lists for channels in this X group.
    use_channels: Full list of channel indices (same as passed to :func:`plan_batches`).
    y_pos: Full list of absolute Y positions.
    spacing_table: Precomputed range-max table from :func:`_build_spacing_table`.
    x_position: Absolute X coordinate shared by all channels in this group.

  Returns:
    List of :class:`ChannelBatch` objects for this X group, each with phantom channel
    Y positions interpolated between non-consecutive batch members.
  """

  channels_by_index = sorted(indices, key=lambda i: use_channels[i])

  batches: List[List[int]] = []
  batch_lo_ch: List[int] = []    # lowest channel index in batch
  batch_hi_ch: List[int] = []    # highest channel index in batch
  batch_lo_y: List[float] = []   # y position of lowest-index channel
  batch_hi_y: List[float] = []   # y position of highest-index channel

  for idx in channels_by_index:
    channel = use_channels[idx]
    y = y_pos[idx]

    assigned = False
    for b in range(len(batches)):
      # Candidate channel is always >= batch_hi_ch[b] (processing in ascending order)
      lo, hi = batch_lo_ch[b], batch_hi_ch[b]

      # Check against highest-index member (tightest Y constraint from above)
      required_from_hi = (channel - hi) * _min_physical_spacing(spacing_table, hi, channel)
      if batch_hi_y[b] - y < required_from_hi - 1e-9:
        continue

      # Check against lowest-index member (full span constraint)
      required_from_lo = (channel - lo) * _min_physical_spacing(spacing_table, lo, channel)
      if batch_lo_y[b] - y < required_from_lo - 1e-9:
        continue

      batches[b].append(idx)
      batch_hi_ch[b] = channel
      batch_hi_y[b] = y
      assigned = True
      break

    if not assigned:
      batches.append([idx])
      batch_lo_ch.append(channel)
      batch_hi_ch.append(channel)
      batch_lo_y.append(y)
      batch_hi_y.append(y)

  # Build ChannelBatch objects with phantom channel positions
  result: List[ChannelBatch] = []
  for batch_indices in batches:
    batch_channels = [use_channels[i] for i in batch_indices]
    y_positions: Dict[int, float] = {use_channels[i]: y_pos[i] for i in batch_indices}

    # Interpolate phantom channels between non-consecutive batch members
    sorted_chs = sorted(batch_channels)
    for k in range(len(sorted_chs) - 1):
      ch_lo, ch_hi = sorted_chs[k], sorted_chs[k + 1]
      spacing = _min_physical_spacing(spacing_table, ch_lo, ch_hi)
      for phantom in range(ch_lo + 1, ch_hi):
        if phantom not in y_positions:
          y_positions[phantom] = y_positions[ch_lo] - (phantom - ch_lo) * spacing

    result.append(ChannelBatch(
      x_position=x_position,
      indices=batch_indices,
      channels=batch_channels,
      y_positions=y_positions,
    ))

  return result


def compute_single_container_offsets(
  container: Container,
  use_channels: List[int],
  channel_spacings: Union[float, List[float]],
) -> Optional[List[Coordinate]]:
  """Compute spread Y offsets for multiple channels targeting the same container.

  Accounts for the full physical span including phantom intermediate channels.
  Uses the effective spacing (max over the channel range) for layout.
  Applies a +5.5 mm Y offset for odd channel spans to avoid center dividers.

  Args:
    container: The container all channels are targeting.
    use_channels: Channel indices being used (e.g. ``[0, 2, 4]``).
    channel_spacings: Minimum Y spacing per channel (mm). Either a single float
      (uniform) or a list with one entry per channel on the instrument.

  Returns:
    List of :class:`Coordinate` Y offsets (one per entry in ``use_channels``),
    or ``None`` if the container is too small to fit all channels — caller should
    fall back to center offsets and let Y sub-batching serialize.
  """

  if len(use_channels) == 0:
    return []

  ch_lo, ch_hi = min(use_channels), max(use_channels)
  if isinstance(channel_spacings, (int, float)):
    spacing = float(channel_spacings)
  else:
    table = _build_spacing_table(channel_spacings)
    spacing = _min_physical_spacing(table, ch_lo, ch_hi)

  container_size_y = container.get_absolute_size_y()
  num_channels_in_span = ch_hi - ch_lo + 1
  min_required = MIN_SPACING_EDGE * 2 + (num_channels_in_span - 1) * spacing

  if container_size_y < min_required:
    return None

  all_offsets = get_wide_single_resource_liquid_op_offsets(
    resource=container,
    num_channels=num_channels_in_span,
    min_spacing=spacing,
  )
  offsets = [all_offsets[ch - ch_lo] for ch in use_channels]

  if num_channels_in_span > 1 and num_channels_in_span % 2 != 0:
    offsets = [
      offset + Coordinate(0, ODD_SPAN_CENTER_AVOIDANCE_OFFSET_MM, 0) for offset in offsets
    ]

  return offsets


def validate_probing_inputs(
  containers: List[Container],
  use_channels: Optional[List[int]],
  resource_offsets: Optional[List[Coordinate]],
  num_channels: int,
  channel_spacings: Union[float, List[float]],
  allow_duplicate_channels: bool = False,
) -> Tuple[List[int], List[Coordinate]]:
  """Validate and normalize inputs shared by all probe_liquid_heights implementations.

  Handles:
  - Defaulting ``use_channels`` from ``containers`` length
  - Channel range and duplicate validation
  - Auto-computing single-container Y spread offsets
  - Defaulting ``resource_offsets`` to zero
  - Length-matching validation

  Args:
    containers: Target containers, one per channel.
    use_channels: Channel indices (0-indexed), or None to default.
    resource_offsets: Per-container offsets, or None to auto-compute/default.
    num_channels: Total channels on the instrument.
    channel_spacings: Min Y spacing per channel (mm).
    allow_duplicate_channels: If True, skip duplicate channel check.

  Returns:
    (use_channels, resource_offsets) — validated and normalized.

  Raises:
    ValueError: On empty channels, out-of-range, duplicates, or length mismatch.
  """
  if use_channels is None:
    use_channels = list(range(len(containers)))
  if len(use_channels) == 0:
    raise ValueError("use_channels must not be empty.")
  if not all(0 <= ch < num_channels for ch in use_channels):
    raise ValueError(
      f"All use_channels must be integers in range [0, {num_channels - 1}], "
      f"got {use_channels}."
    )
  if not allow_duplicate_channels and len(use_channels) != len(set(use_channels)):
    raise ValueError(
      "use_channels must not contain duplicates. "
      "Set `allow_duplicate_channels=True` to override."
    )

  # Auto-compute offsets for single-container case
  if resource_offsets is None and len(set(containers)) == 1:
    resource_offsets = compute_single_container_offsets(
      container=containers[0],
      use_channels=use_channels,
      channel_spacings=channel_spacings,
    )
    # None return means container too small — fall back to center offsets;
    # plan_batches will serialize channels that can't coexist.
  resource_offsets = resource_offsets or [Coordinate.zero()] * len(containers)

  if not len(containers) == len(use_channels) == len(resource_offsets):
    raise ValueError(
      "Length of containers, use_channels, and resource_offsets must match. "
      f"are {len(containers)}, {len(use_channels)}, {len(resource_offsets)}."
    )

  return use_channels, resource_offsets


def compute_positions(
  containers: List[Container],
  resource_offsets: List[Coordinate],
  deck: "Deck",  # noqa: F821
) -> Tuple[List[float], List[float]]:
  """Compute absolute X/Y positions for each container+offset pair.

  Args:
    containers: Target containers.
    resource_offsets: Per-container offsets (already validated/defaulted).
    deck: Deck reference for coordinate lookups.

  Returns:
    (x_pos, y_pos) — absolute positions in mm.
  """
  x_pos: List[float] = []
  y_pos: List[float] = []
  for resource, offset in zip(containers, resource_offsets):
    loc = resource.get_location_wrt(deck, x="c", y="c", z="b")
    x_pos.append(loc.x + offset.x)
    y_pos.append(loc.y + offset.y)
  return x_pos, y_pos
