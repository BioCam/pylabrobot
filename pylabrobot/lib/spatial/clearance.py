"""What passes over the deck: how far the tips on it reach below a channel's stop disc."""

from typing import Optional

from pylabrobot.resources.resource import Resource
from pylabrobot.resources.tip import Tip
from pylabrobot.resources.tip_rack import TipSpot


def get_longest_tip_overhang(reference_frame: Resource) -> Optional[float]:
  """The longest overhang below a stop disc of any tip under `reference_frame`, in mm.

  A rack's spots count as the tips they make, whether or not tip tracking is on; a tip already
  mounted counts as itself. A tool, which is not a tip, does not count.

  Args:
    reference_frame: the resource whose subtree is searched, e.g. a deck.

  Returns:
    The overhang, its length less its fitting depth, or None if there is no tip.
  """
  longest: Optional[float] = None
  for resource in reference_frame.get_all_children():
    if isinstance(resource, TipSpot):
      tip = resource.make_tip()
    elif isinstance(resource, Tip):
      tip = resource
    else:
      continue
    overhang = tip.get_size_z() - tip.fitting_depth
    if longest is None or overhang > longest:
      longest = overhang
  return longest
