# CLARIOstar Plus Backend

<!-- TEMPLATE: One-line description of the device, manufacturer, and what it does. -->

PyLabRobot backend for the **BMG Labtech CLARIOstar Plus** multi-detection mode microplate reader, providing absorbance, fluorescence, and luminescence detection over USB.

## Status

<!-- TEMPLATE: Connection type, firmware tested, platform support, feature completeness. -->

| Property | Value |
|---|---|
| Connection | USB (FTDI serial, VID `0x0403` PID `0xBB68`, 125 kBaud 8N1) |
| Firmware tested | 1.35 |
| Platforms | macOS, Linux |
| Absorbance | full (discrete + spectrum, all well-scan modes) |
| Fluorescence | full (discrete + spectrum, top/bottom optic, multi-chromatic, EDR) |
| Luminescence | stub (`NotImplementedError`) |
| Temperature | full (standard 0–45 °C, extended 10–65 °C with option) |
| Shaking | full (orbital, double-orbital, linear, idle movement) |
| Focus | full (Z-scan per well) |

## Features

<!-- TEMPLATE: Bulleted list grouped by feature/mixin. Each bullet = one public method or capability. Mark stubs. -->

### Lifecycle

- `setup()` / `stop()` — FTDI init, EEPROM + firmware discovery, graceful shutdown
- `initialize()` — hardware initialization command
- `open()` / `close()` — drawer control
- `sense_plate_present()` / `sense_drawer_open()` — sensor queries
- `request_machine_status()` / `is_ready()` — status polling (12 flag bits)
- `request_eeprom_data()` / `request_firmware_info()` — device identity
- `request_available_detection_modes()` — capability discovery
- `request_usage_counters()` — lifetime stats
### Absorbance

- `read_absorbance()` — 1–8 discrete wavelengths per read (220–1000 nm), OD / %T / raw reporting
- `read_absorbance_spectrum()` — wavelength sweep with configurable step size
- Well-scan modes: point, orbital, spiral, matrix (2×2 to 11×11)
- Pre-measurement shaking with settling time
- Scan direction control (bidirectional serpentine / unidirectional, vertical, corner selection, flying mode)

### Fluorescence

- `read_fluorescence()` — 1–5 chromatics per read (320–840 nm excitation/emission)
- `read_fluorescence_spectrum()` — excitation or emission sweep
- Top and bottom optic positions
- Filter-based or monochromator-based selection
- `detect_all_filters()` — auto-detect installed excitation, emission, and dichroic filter slides
- EDR (Enhanced Dynamic Range) mode — raises overflow ceiling from ~260K to 700M counts for bright samples
- PMT gain control (0–4095)
- Focal height adjustment (0–25 mm)

### Focus

- `focus_well()` — Z-scan a single well to find optimal focal height

### Luminescence

- `read_luminescence()` — **stub**, raises `NotImplementedError`. No USB captures available; requires captured protocol data to implement.

### Temperature control

- `start_temperature_control()` / `stop_temperature_control()` — heating setpoint
- `measure_temperature()` — bottom, top, or mean sensor reading
- `get_target_temperature()` — current setpoint or `None`

### Shaking

- `start_shaking()` / `stop_shaking()` — standalone plate shaking. Duration is a u16 BE field (2 bytes), max 3600 s (1 hour, OEM limit). Call `stop_shaking()` to interrupt early.
- `start_idle_movement()` / `stop_idle_movement()` — continuous shaking during incubation, with optional on/off cycling. Duration field is a single byte on the wire (max 255 s confirmed; the u16 range 1–65535 is accepted but only the low byte is sent — needs more capture data to verify).

### Measurement control

- `pause_measurement()` / `resume_measurement()` / `stop_measurement()`
- Progressive and status-only polling modes
- Interrupt handling with optional pause-on-interrupt

### Kinetic measurements

The OEM software sends a single "test run" command that encodes the entire kinetic protocol (intervals, cycle count, shaking between reads) into one monolithic payload executed by the firmware. This backend does **not** replicate that approach. Instead, each method (`read_absorbance`, `read_fluorescence`, etc.) performs a single measurement and returns immediately.

Kinetic loops are built in Python by the user:

```python
import time

interval = 300  # 5 minutes between cycle starts
results = []
for cycle in range(60):
    t0 = time.monotonic()
    result = await backend.read_absorbance(plate, wells, wavelength=450)
    results.append(result)
    elapsed = time.monotonic() - t0
    await asyncio.sleep(max(0, interval - elapsed))
```

This gives you control that the OEM firmware loop cannot offer:

- **Adaptive protocols** — change wavelengths, gains, or wells between cycles based on intermediate results.
- **Multi-mode kinetics** — alternate absorbance and fluorescence reads in the same loop.
- **Custom timing** — variable intervals, early stopping, conditional branching.
- **Live data** — process and plot each cycle as it arrives, rather than waiting for the full run to complete.
- **Integration** — coordinate the reader with liquid handlers, pumps, or other instruments between cycles.

## Architecture

<!-- TEMPLATE: File listing with one-line description. For mixin-based backends: which mixin provides which feature. For single-file backends: skip this section. -->

This backend uses a mixin architecture — each feature area lives in its own module and is composed into `CLARIOstarPlusBackend` via multiple inheritance.

| File | Mixin / role |
|---|---|
| `backend.py` | `CLARIOstarPlusBackend` assembly, enums, constants, status flags |
| `_lifecycle.py` | `_LifecycleMixin` — setup, stop, I/O, EEPROM |
| `_drawer.py` | `_DrawerMixin` — drawer open/close/sense |
| `_protocol.py` | Wire protocol framing, checksums, error decoding |
| `_measurement_common.py` | `_MeasurementCommonMixin` — plate encoding, validation, polling |
| `_absorbance.py` | `_AbsorbanceMixin` — discrete + spectrum absorbance |
| `_fluorescence.py` | `_FluorescenceMixin` — discrete + spectrum fluorescence, filter detection |
| `_focus.py` | `_FocusMixin` — Z-scan, auto-focus |
| `_luminescence.py` | `_LuminescenceMixin` — luminescence measurement (stub) |
| `_temperature_control.py` | `_TemperatureControlMixin` — heating, sensor reads |
| `_shaker.py` | `_ShakerMixin` — standalone and idle shaking |
| `backend_tests.py` | 458 hardware-verified tests |
| `test_data/` | 15 binary absorbance spectrum response payloads |
| `developer_docs/` | Architecture, wire protocol, implementation status, guides |

## Configuration

<!-- TEMPLATE: Constructor parameters and defaults. Hardware-specific setup notes. -->

### Constructor parameters

```python
CLARIOstarPlusBackend(
    device_id=None,
    read_timeout=120.0,
    max_temperature=45.0,
    measurement_poll_interval=0.25,
)
```

| Parameter | Default | Why that default |
|---|---|---|
| `device_id` | `None` | Auto-selects the only FTDI device (PID `0xBB68`). Set to a serial number only when multiple CLARIOstar instruments are connected. |
| `read_timeout` | `120.0` s | Bounds total wait time for commands with `wait=True` (open, close, initialize, measurements). 120 s accommodates full-plate absorbance spectrum scans which can take over 60 s. Can be overridden per-command via `send_command(read_timeout=...)`. |
| `max_temperature` | `45.0` °C | Matches the standard incubator hardware limit (0–45 °C). Set to `65.0` for units with the extended incubator option (10–65 °C). Validated on construction — values above 65 are rejected. |
| `measurement_poll_interval` | `0.25` s | Sleep between poll cycles. Combined with approx. 35 ms I/O round-trip this yields approx. 285 ms per cycle, matching the OEM software cadence (280–300 ms observed in USB captures). Set to `0.0` for maximum throughput (I/O-paced only). |

### Hardware setup

- Requires an FTDI USB driver (`libftdi` or equivalent). The device uses a non-standard FTDI PID (`0xBB68`), which may need a udev rule on Linux.
- Only one process may hold the FTDI handle at a time — close OEM software before connecting.
- The reader can auto-detect installed filter slides (see `detect_all_filters()`), incubator type, and pump presence from EEPROM on `setup()`.

## Extensions

<!-- TEMPLATE: Optional peripherals and accessories that the device supports but are not yet implemented. -->

The CLARIOstar Plus supports several optional peripherals. None are currently implemented — the test unit had no peripherals attached, so no USB captures exist for these commands.

| Extension | Purpose | DDE / script commands | Status |
|---|---|---|---|
| **Reagent injectors** (Pump 1 & 2) | Syringe pump injection during kinetic reads | `Pump1`, `Pump2` / `R_Pump1`, `R_Pump2` | not implemented (EEPROM flags detected) |
| **Stacker** (50-plate magazine) | Automated plate loading/unloading with XYZ positioning | 15+ commands: `S_Init`, `S_PlateIn`, `S_PlateOut`, `S_GetPlate`, `S_MoveTable`, etc. | not implemented |
| **Barcode reader** | Plate barcode scanning (front/rear) | `R_PlateInB`, `S_ReadBarcode`, `S_BarcodeData` | not implemented |
| **ACU** (Atmospheric Control Unit) | O₂/CO₂ gas regulation | `ACU` / `R_ACU` | not implemented |
| **Fan** | Air circulation (used with ACU) | `Fan` / `R_Fan` | not implemented |
| **Extended incubator** | 10–65 °C range (vs. standard 0–45 °C) | auto-detected via EEPROM | implemented (auto-selects on `setup()`) |

To add support for a peripheral, capture its USB traffic with Wireshark, decode the command bytes, and add a new mixin following the patterns in [`developer_docs/architecture.md`](developer_docs/architecture.md). The OEM command reference section lists all known DDE/script commands and their parameter signatures.

## Testing

<!-- TEMPLATE: How to run tests, test count, what they cover. -->

```bash
python -m pytest pylabrobot/plate_reading/bmg_labtech/clariostar_plus/backend_tests.py -v
```

**458 tests** covering:

- Wire protocol frame round-trips (initialize, open, close, every command family)
- Status flag parsing (all 12 hardware flags)
- Lifecycle operations (setup, stop, error recovery)
- Absorbance payload construction and response parsing (discrete + spectrum)
- Fluorescence payload construction and response parsing
- Well mask encoding for all plate formats (8 → 384 wells)
- Temperature control state machine
- Shaking parameter validation
- Filter detection
- Spectrum pagination against 15 binary reference capture files

All measurement tests replay captured USB frames — no hardware required.

## Known limitations

<!-- TEMPLATE: What doesn't work yet and why. -->

- **Firmware** — only version 1.35 has been tested. Other firmware versions may use different command encodings or payload lengths.
- **Luminescence** — `read_luminescence()` raises `NotImplementedError`. No USB captures available (test unit has the optic but no luminescence protocol data was captured).
- **1536-well plates** — untested. The protocol supports 1536-well encoding but no hardware validation has been done.
- **Auto-gain** — not implemented. Firmware 1.35 supports `GainWell`/`GainPlate` commands but no captures exist.
- **Windows** — untested. Should work with appropriate FTDI drivers but no validation.
- **Injectors, stacker, ACU, barcode** — not implemented (see [Extensions](#extensions)).

## References

<!-- TEMPLATE: Links to manufacturer docs, protocol specs, internal docs. Skip if not applicable. -->

### Internal documentation

| Document | Description |
|---|---|
| [`developer_docs/architecture.md`](developer_docs/architecture.md) | Backend architecture, feature details, OEM command reference, parameter ranges |
| [`developer_docs/implementation_status.md`](developer_docs/implementation_status.md) | What's implemented, what's missing, test coverage |
| [`developer_docs/wire_protocol.md`](developer_docs/wire_protocol.md) | Wire protocol specification — frame format, byte encoding, checksums |
| [`developer_docs/guides/optics_primer.md`](developer_docs/guides/optics_primer.md) | Optical filter and wavelength configuration guide |
| [`developer_docs/guides/absorbance_result.md`](developer_docs/guides/absorbance_result.md) | Absorbance measurement result structure and calibration math |

### OEM manuals

- **0430N0003I** — ActiveX and DDE Manual, CLARIOstar V5.00–5.70R2 (command reference)
- **0430F0035B** — Software Manual, CLARIOstar 5.70 R2 Part II (script language, stacker commands)
- **0430B0006B** — Operating Manual, CLARIOstar Plus (hardware specs, optional equipment)
