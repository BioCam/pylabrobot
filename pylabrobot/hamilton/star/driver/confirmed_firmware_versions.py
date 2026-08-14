"""STAR firmware versions verified against hardware.

A STAR is not one controller. The master (``C0``) sits on an internal bus of independently
versioned boards, each of which answers ``RF`` with its own version string:

* master              - ``C0``
* X drives            - ``X0``
* pipetting channels  - ``P1``..``PG`` (one board per channel, same firmware on each)
* 96-head             - ``H0``
* iSWAP               - ``R0``
* autoload            - ``I0``

So "the firmware of a STAR" is the whole set read together, not a single number, and a machine
that has been driven successfully is a whole set that worked together. Each
:class:`ConfirmedFirmware` entry is therefore one full stack, not a per-board list.

Every STAR has a master and pipetting channels; the remaining boards depend on what is fitted, so
they are optional and recorded for provenance. :func:`is_confirmed` gates on the pair that is
always present, and :func:`suggest_entry` formats a newly seen stack as a literal to paste in.

Verified readings
-----------------
* a STAR, 54 slots, with 8 pipetting channels, a 96-head, an iSWAP and autoload, 2026-05-27,
  read-only ``RF`` probe of every module: master ``7.6S 25 2021_11_05 (GRU C0)``, channels
  ``4.0S j 2022-03-16``, X drives ``1.4S 2012-04-25``, 96-head ``5.0S i 2021-10-22 (H0 XE167)``,
  iSWAP ``4.1S 2011-12-19``, autoload ``3.4S f 2017-01-09``. The channel, 96-head and iSWAP
  versions re-appear unchanged in every run log through 2026-08.
"""

from dataclasses import dataclass
from typing import Optional


@dataclass(frozen=True)
class ConfirmedFirmware:
  """One full STAR module firmware stack validated against this driver.

  `master_version` and `channels_version` are present on every STAR and are what
  :func:`is_confirmed` gates on. The rest are fitted-option boards: they are recorded when read,
  and are `None` when the option is absent or was not probed.
  """

  master_version: str
  """Master board (`C0`) version, as reported by `RF`."""
  channels_version: str
  """Pipetting channel (`P1`..`PG`) version. One board per channel, all reporting the same."""
  x_drives_version: Optional[str] = None
  """X drive board (`X0`) version."""
  head96_version: Optional[str] = None
  """96-head (`H0`) version."""
  iswap_version: Optional[str] = None
  """iSWAP (`R0`) version."""
  autoload_version: Optional[str] = None
  """Autoload (`I0`) version."""


CONFIRMED_FIRMWARE_VERSIONS = frozenset(
  [
    # STAR with 8 channels, 96-head, iSWAP and autoload; read-only RF probe 2026-05-27.
    ConfirmedFirmware(
      master_version="7.6S 25 2021_11_05 (GRU C0)",
      channels_version="4.0S j 2022-03-16",
      x_drives_version="1.4S 2012-04-25",
      head96_version="5.0S i 2021-10-22 (H0 XE167)",
      iswap_version="4.1S 2011-12-19",
      autoload_version="3.4S f 2017-01-09",
    ),
  ]
)


def is_confirmed(master_version: str, channels_version: str) -> bool:
  """Whether this master and channel firmware pair has been validated together in one stack.

  Args:
    master_version: version reported by the master (`C0`), without the `rf` field marker.
    channels_version: version reported by the pipetting channels (`P1`..`PG`).

  Returns:
    True if a confirmed stack has exactly this pair.
  """
  return any(
    c.master_version == master_version and c.channels_version == channels_version
    for c in CONFIRMED_FIRMWARE_VERSIONS
  )


def suggest_entry(
  master_version: str,
  channels_version: str,
  x_drives_version: Optional[str] = None,
  head96_version: Optional[str] = None,
  iswap_version: Optional[str] = None,
  autoload_version: Optional[str] = None,
) -> str:
  """Format a stack read off a machine as a `ConfirmedFirmware(...)` literal.

  The result is meant to be pasted into `CONFIRMED_FIRMWARE_VERSIONS` once the machine has been
  driven successfully. Option boards are included only when they were read.

  Args:
    master_version: version reported by the master (`C0`).
    channels_version: version reported by the pipetting channels (`P1`..`PG`).
    x_drives_version: version reported by the X drives (`X0`), if read.
    head96_version: version reported by the 96-head (`H0`), if read.
    iswap_version: version reported by the iSWAP (`R0`), if read.
    autoload_version: version reported by the autoload (`I0`), if read.

  Returns:
    The literal, indented to sit inside `CONFIRMED_FIRMWARE_VERSIONS`.
  """
  lines = [
    "    ConfirmedFirmware(",
    f'      master_version="{master_version}",',
    f'      channels_version="{channels_version}",',
  ]
  for name, value in (
    ("x_drives_version", x_drives_version),
    ("head96_version", head96_version),
    ("iswap_version", iswap_version),
    ("autoload_version", autoload_version),
  ):
    if value is not None:
      lines.append(f'      {name}="{value}",')
  lines.append("    ),")
  return "\n".join(lines)
