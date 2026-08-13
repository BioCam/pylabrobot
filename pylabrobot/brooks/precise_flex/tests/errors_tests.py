import unittest

from pylabrobot.brooks.precise_flex.errors import (
  PreciseFlexCollisionError,
  PreciseFlexError,
  PreciseFlexVisionError,
  is_collision,
)


class TestErrorClassDispatch(unittest.TestCase):
  """PreciseFlexError constructs the most specific subclass for a reply code (STAR-style)."""

  def test_collision_code_yields_collision_subclass(self):
    """A torque-saturation / envelope code (-3101) becomes a PreciseFlexCollisionError."""
    err = PreciseFlexError(-3101, "")
    self.assertIsInstance(err, PreciseFlexCollisionError)
    self.assertTrue(is_collision(err))

  def test_vision_code_yields_vision_subclass(self):
    """A -40xx code (-4017) becomes a PreciseFlexVisionError."""
    err = PreciseFlexError(-4017, "")
    self.assertIsInstance(err, PreciseFlexVisionError)
    self.assertFalse(is_collision(err))

  def test_unmapped_code_stays_base(self):
    """A code in neither category stays the plain base type."""
    err = PreciseFlexError(-202, "")
    self.assertIs(type(err), PreciseFlexError)

  def test_subclasses_are_caught_by_the_base_type(self):
    """A category subclass is still an ordinary PreciseFlexError, so `except PreciseFlexError` works."""
    for code in (-3101, -4017):
      self.assertIsInstance(PreciseFlexError(code, ""), PreciseFlexError)

  def test_constructing_a_subclass_directly_is_not_redispatched(self):
    """Building a subclass with a non-matching code keeps that subclass (dispatch only refines base)."""
    err = PreciseFlexVisionError(-202, "")
    self.assertIs(type(err), PreciseFlexVisionError)

  def test_message_still_formats_from_the_code_table(self):
    """The subclass keeps the base formatting: the code's table text appears in the message."""
    self.assertIn("-4017", str(PreciseFlexError(-4017, "")))
