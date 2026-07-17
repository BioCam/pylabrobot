import unittest

from pylabrobot.resources.x_arm_tracker import XArmTracker


class TestXArmTracker(unittest.TestCase):
  def setUp(self):
    self.tracker = XArmTracker(thing="left X-arm")

  def test_starts_unknown(self):
    self.assertFalse(self.tracker.is_known)
    with self.assertRaises(RuntimeError):
      self.tracker.get_x()

  def test_set_x_commits_and_rounds_to_0_1_mm(self):
    self.tracker.set_x(123.456)
    self.assertEqual(self.tracker.get_x(), 123.5)

  def test_set_x_without_commit_stages_only(self):
    self.tracker.set_x(100.0, commit=False)
    self.assertFalse(self.tracker.is_known)
    self.tracker.commit()
    self.assertEqual(self.tracker.get_x(), 100.0)

  def test_rollback_discards_pending(self):
    self.tracker.set_x(100.0)
    self.tracker.set_x(200.0, commit=False)
    self.tracker.rollback()
    self.tracker.commit()
    self.assertEqual(self.tracker.get_x(), 100.0)

  def test_invalidate_returns_to_unknown(self):
    self.tracker.set_x(100.0)
    self.tracker.invalidate()
    self.assertFalse(self.tracker.is_known)
    with self.assertRaises(RuntimeError):
      self.tracker.get_x()

  def test_disabled_set_x_raises(self):
    self.tracker.disable()
    with self.assertRaises(RuntimeError):
      self.tracker.set_x(100.0)

  def test_serialize_round_trip(self):
    self.tracker.set_x(100.0)
    self.tracker.set_x(200.0, commit=False)
    other = XArmTracker(thing="left X-arm")
    other.load_state(self.tracker.serialize())
    self.assertEqual(other.get_x(), 100.0)
    other.commit()
    self.assertEqual(other.get_x(), 200.0)


if __name__ == "__main__":
  unittest.main()
