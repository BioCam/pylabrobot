"""CLARIOstar command bytes and the STATUS reply layout, shared by the driver and its features."""

import enum
from typing import Dict, Optional, Tuple


class CommandFamily(enum.IntEnum):
  """Command family: byte 0 of every logical payload."""

  INITIALIZE = 0x01
  DRAWER = 0x03
  REQUEST = 0x05
  STATUS = 0x80


class Command:
  """Command byte (payload byte 1) within a family; plain ints, as values recur across families."""

  INIT = 0x00
  DRAWER_CLOSE = 0x00
  DRAWER_OPEN = 0x01
  FIRMWARE_INFO = 0x09


# Families whose payload is the family byte plus parameters, without a command byte.
NO_COMMAND_FAMILIES = frozenset({CommandFamily.STATUS})

# Status flags checked against replies from a reader: (name, payload byte, bit mask).
STATUS_FLAGS = [
  ("busy", 1, 1 << 5),
  ("plate_detected", 3, 1 << 1),
  ("drawer_open", 3, 1 << 0),
]


# A reply to a refused command: type 0x01, this bit in byte 1, and quit codes in bytes 6-10.
REFUSED_BIT = 1 << 4


def parse_quit_codes(reply: bytes) -> Optional[Tuple[int, int, int, int, int]]:
  """Return the five quit codes of a refused command's reply, or None if it was not refused."""
  if len(reply) < 11 or reply[0] != 0x01 or not reply[1] & REFUSED_BIT:
    return None
  q1, q2, q3, q4, q5 = reply[6:11]
  return (q1, q2, q3, q4, q5)


def parse_temperatures(payload: bytes) -> Dict[str, Optional[float]]:
  """Parse the incubator temperatures out of a STATUS payload, in degrees C.

  Bytes 11-12 are the bottom heating plate and 13-14 the top, u16 BE in 0.1 C. Both read 0, and
  parse as None, unless the incubator is heating or monitoring.
  """
  temperatures: Dict[str, Optional[float]] = {"bottom": None, "top": None}
  for name, offset in (("bottom", 11), ("top", 13)):
    if len(payload) >= offset + 2:
      raw = int.from_bytes(payload[offset : offset + 2], "big")
      temperatures[name] = raw / 10 if raw else None
  return temperatures


def parse_status(payload: bytes) -> Dict[str, bool]:
  """Parse a STATUS payload into its flags."""
  return {
    name: index < len(payload) and bool(payload[index] & mask) for name, index, mask in STATUS_FLAGS
  }
