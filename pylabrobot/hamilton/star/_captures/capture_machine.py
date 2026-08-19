"""Ask this machine every read its firmware documents describe, and write down what it says.

Read-only. `read_commands.json` holds every command whose specification describes it as a request,
a query, a check or a read, extracted from the module command sets, with the documented default for
any parameter that takes one. Nothing here moves anything.

Two files come out: what the driver parsed into its configurations, and the raw reply to every read
that was sent - so a parser can be written or corrected away from the machine.

    python -m pylabrobot.hamilton.star._captures.capture_machine
"""

import asyncio
import dataclasses
import datetime
import json
import logging
from pathlib import Path
from typing import Any, Dict

from pylabrobot.hamilton.star.driver.master import STARDriver

HERE = Path(__file__).parent
# Which module each document's commands are addressed to. The channels all take the same set.
CHANNEL_MODULES = [f"P{channel:X}" for channel in range(1, 9)]
# How long to wait for any one read. A command this machine does not know answers at once; one it
# ignores would otherwise hold the sweep for the driver's whole read timeout.
READ_TIMEOUT = 3


def as_json(value: Any) -> Any:
  """Whatever a configuration holds, in something json can write."""
  if dataclasses.is_dataclass(value) and not isinstance(value, type):
    return {field.name: as_json(getattr(value, field.name)) for field in dataclasses.fields(value)}
  if isinstance(value, dict):
    return {str(key): as_json(item) for key, item in value.items()}
  if isinstance(value, (list, tuple)):
    return [as_json(item) for item in value]
  if isinstance(value, (datetime.date, datetime.datetime)):
    return value.isoformat()
  if isinstance(value, (str, int, float, bool)) or value is None:
    return value
  return repr(value)


async def main() -> None:
  logging.basicConfig(level=logging.WARNING)
  catalogue = json.loads((HERE / "read_commands.json").read_text())

  star = STARDriver()
  await star._open()
  star._connected = True
  raw: Dict[str, str] = {}
  parsed: Dict[str, Any] = {}
  try:
    await star.discover()  # read-only
    print(star.format_setup_summary())

    parsed = {"instrument": as_json(star.configuration), "firmware": star.firmware}
    for name in ("pipettes", "left_x_arm", "right_x_arm", "head96", "iswap", "autoload"):
      capability = getattr(star, name, None)
      parsed[name] = None if capability is None else as_json(capability.configuration)

    # A module only answers if this machine has it; the channels answer one set each.
    modules = {"C0": "C0", "X0": "X0", "H0": "H0", "R0": "R0", "I0": "I0"}
    for document, module in modules.items():
      for command, entry in catalogue.get(document, {}).items():
        await ask(star, module, command, entry["parameters"], raw)
    for module in CHANNEL_MODULES[: star.num_channels]:
      for command, entry in catalogue.get("PX", {}).items():
        await ask(star, module, command, entry["parameters"], raw)
  finally:
    await star.stop()

  stamp = datetime.datetime.now().strftime("%Y%m%d_%H%M")
  (HERE / f"{stamp}_configuration.json").write_text(json.dumps(parsed, indent=2))
  (HERE / f"{stamp}_raw_reads.json").write_text(json.dumps(raw, indent=2))
  answered = sum(1 for reply in raw.values() if not reply.startswith("REFUSED"))
  print(f"\n{answered} of {len(raw)} reads answered; written to {HERE}/{stamp}_*.json")


async def ask(
  star: STARDriver, module: str, command: str, parameters: Dict[str, str], raw: Dict[str, str]
) -> None:
  """Send one read and write down what came back, refusal included.

  A command this machine does not know answers with an error, and one it does not answer at all
  would otherwise hold the sweep for the driver's full read timeout - so each is given a few
  seconds and the sweep carries on either way. Only `Exception` is caught, so an interrupt still
  stops it.
  """
  key = f"{module} {command}" + (f" {parameters}" if parameters else "")
  sent: Dict[str, Any] = dict(parameters)
  try:
    reply = await star.send_command(
      module=module, command=command, read_timeout=READ_TIMEOUT, **sent
    )
    raw[key] = str(reply)
  except Exception as error:  # noqa: BLE001 - a refusal is data too
    raw[key] = f"REFUSED: {error}"
  print(f"  {len(raw):3d}  {key:24s} {raw[key][:80]}")


if __name__ == "__main__":
  asyncio.run(main())
