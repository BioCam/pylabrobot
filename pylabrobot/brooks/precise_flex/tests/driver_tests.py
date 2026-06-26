# mypy: disable-error-code="attr-defined,method-assign,assignment"
import asyncio
import unittest
from unittest.mock import MagicMock

from pylabrobot.brooks.precise_flex.driver import PreciseFlexDriver


def _recording_driver(events: list) -> PreciseFlexDriver:
  """A driver whose socket records each write/read and yields control between them.

  The ``await asyncio.sleep(0)`` after every write hands the event loop to any other ready coroutine,
  so an UNserialized implementation would let a second concurrent command write before the first
  reads - producing ``[w, w, r, r]``. With the per-exchange lock the pairs stay together.
  """
  d = PreciseFlexDriver(host="localhost")
  d.io = MagicMock()

  async def write(data: bytes) -> None:
    events.append(("w", data))
    await asyncio.sleep(0)

  async def readline() -> bytes:
    events.append(("r", None))
    await asyncio.sleep(0)
    return b"0\r\n"

  d.io.write = write
  d.io.readline = readline
  return d


class TestSendCommandSerialization(unittest.IsolatedAsyncioTestCase):
  """Each request->reply pair is one lock-held exchange, so concurrent callers cannot interleave
  their write/read on the single shared connection (port 10100 refuses a second socket)."""

  async def test_concurrent_send_commands_do_not_interleave(self):
    """Two commands run concurrently each keep their own write immediately paired with their read."""
    events: list = []
    d = _recording_driver(events)
    await asyncio.gather(d.send_command("A"), d.send_command("B"))
    self.assertEqual([kind for kind, _ in events], ["w", "r", "w", "r"])

  async def test_bare_vision_read_shares_the_lock_with_send_command(self):
    """The bare VToolProperty read goes through the same _locked_exchange, so it serializes too."""
    events: list = []
    d = _recording_driver(events)
    await asyncio.gather(
      d.send_command("A"),
      d.request_vision_tool_property("led", "Brightness"),
    )
    self.assertEqual([kind for kind, _ in events], ["w", "r", "w", "r"])

  async def test_lock_released_after_an_error(self):
    """A failing exchange releases the lock, so a later command is not deadlocked behind it."""
    d = _recording_driver([])
    calls = {"n": 0}

    async def readline() -> bytes:
      calls["n"] += 1
      if calls["n"] == 1:
        raise TimeoutError()
      return b"0 ok\r\n"

    d.io.readline = readline
    with self.assertRaises(TimeoutError):
      await d.send_command("A")
    self.assertFalse(d._io_lock.locked())
    self.assertEqual(await d.send_command("B"), "ok")
