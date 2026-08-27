"""Repeated position grids a resource lays things out on, described as data.

A Hamilton deck has rails; another deck will have slots, or a plate nest will have positions. The
viewer should not know what any of them are called. It should be told where the first one is, how
far apart they are, how many there are and how to label them, and draw that.

Upstream, a resource should declare this itself, the way it declares its size. Until it does, this
module derives it from public API the resource already offers, so no constant is copied into the
viewer where it could drift from the machine.
"""

import logging
from typing import Any, Dict, Optional

logger = logging.getLogger(__name__)

# How close a child's own y has to be to the rail line to count as standing on it, in mm.
SEATED_TOLERANCE = 0.5

# How often a rail gets a number. Legacy labels the first and then every fifth, which is dense
# enough to count from and sparse enough to read.
DEFAULT_LABEL_EVERY = 5


def describe_bands(resource: Any) -> Optional[list]:
  """Bands across a resource that some capability can reach, if it declares any.

  Read off an optional `access_bands` attribute, so the viewer draws whatever it is told and this
  module stays free of any one machine's numbers. Upstream these belong to the capability whose
  reach they describe, not to the surface they are measured on.

  Each band is `{"label": str, "from": float, "to": float}` in the resource's own frame, with
  optional `x_from` and `x_to` bounding how far it runs along the other axis.
  """
  bands = getattr(resource, "access_bands", None)
  if not bands:
    return None
  described = []
  for band in bands:
    try:
      described.append(
        {
          "label": str(band["label"]),
          "from": float(band["from"]),
          "to": float(band["to"]),
          # Optional: how far the band runs along the other axis. Absent means the whole resource.
          **({"x_from": float(band["x_from"])} if "x_from" in band else {}),
          **({"x_to": float(band["x_to"])} if "x_to" in band else {}),
        }
      )
    except (KeyError, TypeError, ValueError):
      logger.warning("ignoring malformed access band on %s: %r", resource.name, band)
  return described or None


def describe_grid(resource: Any) -> Optional[Dict[str, Any]]:
  """The repeated grid this resource lays positions on, or None if it lays none.

  Returns a dict in the resource's own frame:
    axis          which way the grid runs
    count         how many positions there are
    spacing       distance between them, in mm
    origin        where the first one sits, [x, y, z] in mm
    extent        how far a position mark runs across the resource, in mm
    label_every   label the first, then every nth
    label         what one position is called
  """
  locate = getattr(resource, "rails_to_location", None)
  count = getattr(resource, "num_rails", None)
  if not callable(locate) or not isinstance(count, int) or count < 2:
    return None

  try:
    first, second = locate(1), locate(2)
  except Exception as e:
    logger.debug("%s declined to locate its rails: %s", getattr(resource, "name", resource), e)
    return None

  spacing = second.x - first.x
  if spacing <= 0:
    return None

  # A rail mark runs from where the rail starts to the back of what the rails CARRY, not to the
  # back of the resource - a deck runs on well past anything standing on it, and a mark that
  # overshoots reads as a reach that is not there.
  #
  # What is standing on the rails is whatever shares their y: a carrier seats on the rail line, so
  # its own y is the grid's. The deepest of those is the reach. A deck with nothing on it yet has
  # nothing to measure, and only then does its own depth stand in.
  try:
    depth = resource.get_absolute_size_y()
  except Exception:
    return None

  seated = []
  for child in getattr(resource, "children", []):
    location = getattr(child, "location", None)
    if location is None or abs(location.y - first.y) > SEATED_TOLERANCE:
      continue
    try:
      seated.append(child.get_absolute_size_y())
    except Exception:
      continue

  return {
    "axis": "x",
    "count": count,
    "spacing": round(spacing, 4),
    "origin": [round(first.x, 4), round(first.y, 4), round(first.z, 4)],
    "extent": round(max(seated) if seated else max(depth - first.y, 0.0), 4),
    "label_every": DEFAULT_LABEL_EVERY,
    "label": "rail",
  }
