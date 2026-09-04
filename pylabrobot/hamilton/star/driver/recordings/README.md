# Device recordings

What a real STAR reported about itself, kept as data so a simulated one can stand in for it.

A recording is written by the driver, not by hand:

```python
star = STAR(driver=STARDriver())
await star.setup()
star.driver.save_configuration("star_legacy_2021_8ch_head96_autoload1D.json")
```

and read back by pointing a simulated device at it:

```python
star = STAR(simulation=True, simulated_configuration="star_legacy_2021_8ch_head96_autoload1D.json")
await star.setup()
```

`star_legacy_2021_8ch_head96_autoload1D.json` is the one this package ships, named by the
convention below. A bare `STAR(simulation=True)` answers from it, and the STARlet and STARplus are
derived from it because neither has been read off a device.

## What is in one

Shaped as the device is, so nothing fixes how many of anything a device may have:

```json
{
  "device":   { ... },
  "arms":     { "left": { "pipettes": {...}, "head96": {...}, "iswap": {...} } },
  "autoload": { ... }
}
```

The device's own configuration is what the master answered. Each feature sits under the arm that
carries it; a feature fitted to the device rather than to an arm sits beside `arms`. A device that
grows a second head is one more entry, with no change to the format.

## What is not

- **Documented defaults.** Values the driver holds because a drive documents them, not because a
  device reported them, stay in the code. The 384-head is the standing example: no 384-head has
  been read off any device, so its offsets and drive defaults live in `simulator.py`.
- **Where the device is.** Rest positions, probed Z heights, which track the autoload sits on. That
  is state, not configuration, and it changes every run.

## Naming

A convention to follow, not something the driver does. `save_configuration` writes exactly the path
it is given and nothing else: it chooses no directory, invents no name, and appends no extension.
Where a recording goes and what it is called are yours, so give it a full path.

Six fields, in the order below, joined by `_`. Every one can be read off the device or the file it
wrote, so a name can always be worked out from what you have. Two recordings of the same class of
device then sort together, and a reader can tell them apart without opening either.

| field | value | read from |
|---|---|---|
| 0 | `star`, `starlet`, `starplus` | `device.instrument_size_slots` (54, 30, 76) |
| 1 | `legacy`, `FM` | `arms.<side>.head96.instrument_type` |
| 2 | build year, `YYYY` | `device.firmware_date` |
| 3 | `8ch`, `12ch`, `16ch` | `device.num_pip_channels` |
| 4 | `head96`, `head384` | `device.ka_head96_installed` / `device.dispensing_head_384_installed` |
| 5 | `autoload1D`, `autoload2D` | `autoload.autoload_type` |

Leave a field out only when the device has none of that thing: a device with no autoload ends at
field 4. Do not reorder, and do not abbreviate a field to make a name shorter, because the position
is what carries the meaning.

The device this package ships a recording of reads as:

```
star_legacy_2021_8ch_head96_autoload1D.json
```

### What a recording cannot yet tell you

**Field 1 is not confirmed.** `instrument_type` is decoded from the third of the 96-head's hardware
tokens, and whether that token is populated on every build is unverified. A device reading `legacy`
may be one that does not report the token rather than one that is legacy. Confirm against the
device before trusting the field on an FM.

**Two more identity facts are still unread.** A recording says which device answered and what it
was running, through `device.serial_number` and `device.firmware_version`. Two things the older
driver could read are not implemented here:

| fact | how it is read | why it might matter |
|---|---|---|
| download date | `C0 RO` | another candidate for field 2, though whether it dates the build or the last firmware download is unverified |
| electronic board type | `C0 QB` | four board generations are known, and which one a device has may bear on the encodings that apply to it |

`device.serial_number` is what the device answers, not the USB serial a driver may have picked it
off the bus with. It is null in the recording shipped here: that device's serial was never read,
and it is not ours to invent.
