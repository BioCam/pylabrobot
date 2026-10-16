# Recordings

Frames exchanged with a real CLARIOstar, kept as data for the tests. Every frame here was sent to
or received from a reader; none is written by hand or built from a guess at the protocol.

| file | reader | taken by |
|---|---|---|
| `clariostar_plus_ftdi_2020_v1_driver.json` | CLARIOstar Plus, FTDI, firmware 1.35 | this driver |
| `clariostar_plus_ftdi_2020_oem_software.json` | CLARIOstar Plus, FTDI | the vendor software |
| `clariostar_plus_ftdi_2020_oem_software_refused.json` | CLARIOstar Plus, FTDI | the vendor software |
| `clariostar_plus_ftdi_2020_previous_driver.json` | CLARIOstar Plus, FTDI, firmware 1.35 | an earlier driver, in use |

The second file holds what the first lacks: a status reply with a plate detected, and the vendor
software's own open-drawer frame. The third holds commands the reader refused, one per quit code
seen. The fourth holds an open-drawer the reader refused because it was still busy.

## What is in one

```json
{
  "device": {"model": "...", "interface": "ftdi", "serial_number": "000-0000", "firmware_version": "..."},
  "exchanges": {"<name>": {"sent": "<hex>", "received": "<hex>"}}
}
```

`sent` and `received` are whole frames, framing included. `serial_number` is a placeholder, not
the serial of the reader the frames came from.

## How one is made

Exchanges are extracted from an IO log by a script, never copied by hand. Each name is the first
exchange in the log matching a rule on the frames, e.g. `status_busy` is the first STATUS reply
with `busy` set and the drawer in. Each frame is validated (STX, size, checksum, CR) on the way in.

`load_exchanges(file_name)` returns them by name as `(sent, received)` bytes.

## Naming

`<model>_<interface>_<firmware build year>_<taken by>.json`.
