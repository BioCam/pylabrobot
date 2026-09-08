"""Rules about the client's source that no browser is needed to check.

The viewer draws only when something asks it to, which made a whole class of mistake invisible: a
function that changes the scene and does not ask is a silent freeze, not an error. The answer was to
stop asking at the point of change and ask at the edges instead - the few places anything can get
into the page at all. This keeps it that way.
"""

import pathlib
import re
import unittest

APP = pathlib.Path(__file__).parent / "static" / "app.js"

# Every way into the viewer, and what comes in through it. A call to `invalidate` anywhere else is
# the scattering this replaced: correct on the day it is written, and one edit away from being
# forgotten somewhere it matters.
BOUNDARIES = {
  "invalidate": "its own definition",
  "connect": "a message arriving from the server",
  "resize": "the viewport changing shape",
  "atBoundary": "a call from outside the page",
  None: "the document-wide input listeners, and the camera's own change event",
}


def enclosing_function(lines, index):
  """The top-level function containing this line, or None if it sits at module level."""
  for above in range(index, -1, -1):
    text = lines[above]
    opened = re.match(r"^function (\w+)", text)
    if opened is not None:
      return opened.group(1)
    if above != index and text.startswith("}"):
      return None  # a function closed before we reached one, so this is module level
  return None


class InvalidationTests(unittest.TestCase):
  def test_only_the_edges_ask_for_a_frame(self):
    lines = APP.read_text().splitlines()
    stray = []
    for index, text in enumerate(lines):
      if "invalidate" not in text:
        continue
      where = enclosing_function(lines, index)
      if where not in BOUNDARIES:
        stray.append(f"  line {index + 1} in {where}(): {text.strip()}")

    self.assertEqual(
      stray,
      [],
      "invalidate() is called outside the edges of the viewer:\n"
      + "\n".join(stray)
      + "\n\nAsk for a frame where something enters the page, not where something changes. The"
      " places that may are:\n"
      + "\n".join(f"  {name or 'module level'} - {why}" for name, why in BOUNDARIES.items()),
    )

  def test_every_edge_is_still_wired(self):
    """The rule above only helps while the edges themselves still ask."""
    lines = APP.read_text().splitlines()
    found = {enclosing_function(lines, i) for i, t in enumerate(lines) if "invalidate" in t}
    for name, why in BOUNDARIES.items():
      self.assertIn(name, found, f"nothing asks for a frame on {why}")


if __name__ == "__main__":
  unittest.main()
