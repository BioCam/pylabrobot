"""Exchanges recorded from real CLARIOstar readers, read back by the tests."""

import json
import pathlib
from typing import Dict, Tuple

_DIRECTORY = pathlib.Path(__file__).parent


def load_exchanges(file_name: str) -> Dict[str, Tuple[bytes, bytes]]:
  """Return a recording's exchanges by name, each as its (sent, received) frames."""
  with open(_DIRECTORY / file_name) as f:
    recording = json.load(f)
  return {
    name: (bytes.fromhex(exchange["sent"]), bytes.fromhex(exchange["received"]))
    for name, exchange in recording["exchanges"].items()
  }
