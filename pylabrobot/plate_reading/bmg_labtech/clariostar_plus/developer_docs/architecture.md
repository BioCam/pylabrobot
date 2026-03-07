# CLARIOstar Plus Backend — Architecture & Implementation

Production-grade driver for the BMG Labtech CLARIOstar Plus, built from 88+ capture captures with byte-level verification. Replaces the original ~350-line proof-of-concept.

---

## At a Glance

| Capability | Old backend | Current |
|---|---|---|
| **Code** | ~350 lines, 0 tests | ~5,200 lines (9 mixin modules) + 8,094 lines tests |
| **Tests** | 0 | 458 methods, hardware-verified |
| **Wire protocol** | Hardcoded byte arrays, 2-byte checksum | Structured frame builder, 24-bit checksum, validation, retries |
| **Absorbance** | Single wavelength, point scan | 1–8 wavelengths, spectrum scans, all well-scan modes |
| **Fluorescence** | `NotImplementedError` | Discrete + spectrum, mono + filter + multi-chromatic + EDR + flying + matrix |
| **Luminescence** | Basic (hardcoded payload) | Stub (`NotImplementedError`) — pending capture captures |
| **Temperature** | Not supported (`NaN`) | Full: monitor, set target (0–65 °C), measure (top/bottom/mean) |
| **Shaking** | Not supported | Standalone + idle movement, 4 modes, hardware-validated |
| **Device ID** | EEPROM (unparsed) | EEPROM parsed + firmware version + usage counters |
| **Status** | Single busy/ready byte | 12-flag bitfield (busy, running, plate, drawer, lid, etc.) |
| **Error recovery** | None | CMD_0x0E clears stuck `running=True` (matches OEM software) |
| **Filters** | None | Filter/DichroicFilter dataclasses, 3 slide containers, auto-detection |
| **Focus** | None | Z-scan per well with intensity result |

---

## Module Organisation

`CLARIOstarPlusBackend` is composed from mixins via multiple inheritance:

```
CLARIOstarPlusBackend (backend.py — assembly, enums, constants, status flags)
├── _LifecycleMixin (_lifecycle.py)
│   ├── Constructor, setup, stop
│   ├── Low-level I/O (_write_frame, _read_frame)
│   ├── Frame utilities (_wrap_payload, _validate_frame, _extract_payload)
│   ├── Command layer (send_command)
│   ├── Status & Polling (request_machine_status, is_ready)
│   ├── Device Info (EEPROM, firmware, detection modes)
│   └── Usage counters
├── _DrawerMixin (_drawer.py)
│   └── Drawer control (open, close, sense_drawer_open)
├── _MeasurementCommonMixin (_measurement_common.py)
│   ├── Plate encoding, well mask, validation
│   └── Polling infrastructure (progressive, status-only)
├── _AbsorbanceMixin (_absorbance.py)
│   ├── read_absorbance (1–8 discrete wavelengths)
│   └── read_absorbance_spectrum (paginated)
├── _FluorescenceMixin (_fluorescence.py)
│   ├── read_fluorescence (mono/filter/multi-chromatic/EDR/flying/matrix)
│   ├── read_fluorescence_spectrum (excitation/emission sweep)
│   └── Filter auto-detection (detect_all_filters)
├── _FocusMixin (_focus.py)
│   └── focus_well (Z-scan)
├── _LuminescenceMixin (_luminescence.py)
│   └── read_luminescence (stub)
├── _TemperatureControlMixin (_temperature_control.py)
├── _ShakerMixin (_shaker.py)
│   ├── start_shaking / stop_shaking
│   └── start_idle_movement / stop_idle_movement
└── _protocol.py (wire protocol framing, checksums, error decoding)
```

---

## Feature Details

### Wire Protocol

`_wrap_payload()` / `_validate_frame()` / `_extract_payload()` pipeline. 24-bit checksums. Size-field-aware `0x0D` handling (critical — `0x0D` appears in mid-frame checksum bytes). `send_command()` dispatches by `CommandFamily` enum with automatic retries on `FrameError`.

Frame format:
```
STX (0x02) | size (2B BE) | header (0x0C) | payload | checksum (3B BE) | CR (0x0D)
```
Checksum = `sum(frame[:-4]) & 0xFFFFFF`. 8-byte overhead total. Verified against 6,780 capture frames with zero failures.

### Absorbance

- **Discrete**: 1–8 wavelengths per run (220–1000 nm). Report = `optical_density`, `transmittance`, or `raw` (with per-well references + calibration values).
- **Spectrum**: Wavelength sweep with configurable step size. Paginated data retrieval.
- Well scan modes: point, orbital, spiral, matrix (2×2 to 11×11). Scan diameter 1–6 mm.
- Configurable flashes (1–200), settling time (0–1 s).
- Pre-measurement shaking: orbital, linear, double_orbital, meander (100–700 RPM).

### Fluorescence

- **Monochromator mode**: Excitation/emission 320–840 nm, configurable bandwidths, auto-calculated dichroic split.
- **Filter mode**: Physical filters via `OpticalFilter`/`DichroicFilter` objects. Mixed filter+mono supported.
- **Multi-chromatic**: 1–5 channels per run, each with independent wavelengths/gain/filters.
- **Spectrum**: Excitation or emission sweep with paginated retrieval.
- **EDR**: Raises overflow ceiling from ~260K to 700M counts.
- **Flying mode**: Forces settling=0, flashes=1. Fastest possible scan.
- **Filter auto-detection**: `detect_all_filters()` scans all 11 filter positions spectroscopically, matching the OEM software routine.
- Top and bottom optic positions. PMT gain 0–4095. Focal height 0–25 mm.

### Temperature Control

Three-tier: monitoring only (sensor readout), active heating (setpoint + PID), off. `measure_temperature()` returns bottom, top, or mean. Standard range 0–45 °C, extended incubator 10–65 °C (auto-detected from EEPROM).

DDE `SetTemp`/`TempOff` are NOT valid DDE Execute commands (exit 1000). Our direct USB 0x06 commands work correctly.

### Device Identification

- `request_eeprom_data()` → parsed dict: machine_type, model, capabilities (abs/fl/lum/alpha), monochromator ranges, filter slot counts, pump presence, incubator type.
- `request_firmware_info()` → firmware version + build timestamp. Verified against `CONFIRMED_FIRMWARE_VERSIONS`.
- `request_usage_counters()` → flashes, testruns, wells, well_movements, active_time, shake_time, pump usage.
- `request_available_detection_modes()` → EEPROM-based capability list.

### Status & Error Recovery

12 boolean flags from 5-byte status word: standby, busy, running, valid, unread_data, lid_open, initialized, reading_wells, z_probed, plate_detected, drawer_open, filter_cover_open.

CMD_0x0E sent during every `setup()` boot sequence clears stuck `running=True` state (matches OEM software capture).

### Auto-Focus

`focus_well()` sends `FOCUS_WELL` (0x09) with well mask, polls until complete, retrieves Z-scan result. Returns optimal focal height (u16 BE, mm×100).

The deprecated `auto_focus()` uses `0x0C` but produces incorrect payload length (88 vs 91 bytes) and only gets a 17-byte short response. Use `focus_well()` instead.

### Shaking

**Standalone** (`start_shaking`, 0x1D): 4 modes (orbital, linear, double_orbital, meander), 100–700 RPM, duration u16 BE max 3600 s. Custom X/Y positioning.

**Idle movement** (`start_idle_movement`, 0x27): Background shaking during incubation with on/off cycling. Duration single byte on wire.

### Filter Infrastructure

- `OpticalFilter` — frozen dataclass (slot, name, center_wavelength, bandwidth).
- `DichroicFilter` — frozen dataclass (slot, name, cut_on_wavelength).
- `ExcitationFilterSlide`, `EmissionFilterSlide`, `DichroicFilterSlide` — container classes with `__getitem__` (by slot or name), `register()`. Dichroic supports letter indexing (A/B/C).
- Slot counts auto-populated from EEPROM during `setup()`.

---

## OEM Command Reference

### DDE/ActiveX Commands (§3.1–3.27)

27 commands available via DDE `Execute` / ActiveX `Execute`/`ExecuteAndWait`. The OEM software translates them into USB wire commands.

| # | DDE Command | USB Traffic? | Our Implementation | Capture Status |
|---|-------------|-------------|-------------------|-------------|
| 3.1 | **Dummy** | None — connection test | N/A | N/A |
| 3.2 | **Init** | Yes — 0x01 | `setup()` / `initialize()` | 40+ captures |
| 3.3 | **User** | Unknown | Not implemented | Not captured |
| 3.4 | **PlateIn** / **PlateOut** | Yes — 0x03 | `close()` / `open()` | Confirmed |
| 3.5 | **Pump1** / **Pump2** | Yes — unknown opcode | Not implemented | Not captured |
| 3.6 | **Temp** | None via DDE (exit 1000) | `start/stop_temperature_control()` via USB 0x06 | USB confirmed |
| 3.7 | **GainWell** / **GainPlate** / **GetKFactor** | Yes | Not implemented (auto-gain/FP) | Not captured |
| 3.8 | **SetGain** | Unknown | Not implemented | Not captured |
| 3.9 | **SetFocalHeight** | Unknown | `focal_height=` param | Not captured via DDE |
| 3.10–3.14 | **SetSampleIDs**, **EditLayout**, etc. | None — OEM-internal | N/A | N/A |
| 3.15 | **Run** | Yes — 0x04 | `read_absorbance()` / `read_fluorescence()` | 40+ captures |
| 3.16 | **Pause** | Yes — 0x19 | Not implemented | Not captured |
| 3.17 | **Continue** | Yes — 0x19 | Not implemented | Not captured |
| 3.18 | **StopTest** | Yes — 0x0B | `stop_shaking()` uses 0x0B | Partial |
| 3.19 | **StopSystem** | Yes | Not implemented | Not captured |
| 3.20 | **ACU** | Yes — unknown | Not implemented (no hardware) | Not captured |
| 3.21 | **Fan** | Yes — unknown | Not implemented | Not captured |
| 3.22 | **Shake** | Yes — 0x1D | `start_shaking()` | 13 frames |
| 3.23 | **IdleMove** | Yes — 0x27 | `start_idle_movement()` / `stop_idle_movement()` | 6 captures |
| 3.24–3.25 | **MotorDis** / **MotorEn** | None | N/A | Confirmed no USB |
| 3.26 | **ResetError** | Unknown | Not implemented | Not captured |
| 3.27 | **Terminate** | None — OEM lifecycle | N/A | N/A |

### Script Language Commands (§9.4–9.5)

See [wire_protocol.md](wire_protocol.md) for byte-level details of each command.

**Reader commands (R_):**

| Command | Our Implementation |
|---------|-------------------|
| R_Init | `setup()` / `initialize()` |
| R_PlateOut / R_PlateIn | `open()` / `close()` |
| R_PlateInB / R_BarcodeData | Not implemented (barcode) |
| R_Temp | `start/stop_temperature_control()` |
| R_FocusPlate | Not implemented |
| R_FocusWell | `focus_well()` |
| R_GainPlate / R_GainWell | Not implemented (auto-gain) |
| R_SetFocalHeight | `focal_height=` param |
| R_Run | `read_absorbance()` / `read_fluorescence()` |
| R_Shake | `start_shaking()` |
| R_IdleMove | `start_idle_movement()` / `stop_idle_movement()` |
| R_ACU / R_Fan | Not implemented |
| R_Pump1 / R_Pump2 | Not implemented |
| R_GetData | `request_absorbance_results()` (ABS only) |

**Stacker commands (S_):** 15+ commands — all not implemented (no stacker hardware).

### DDE Status Items (§2)

| Item | Our Equivalent |
|------|----------------|
| Status / DdeServerStatus | `request_machine_status()` |
| DeviceConnected | Implicit in `setup()` |
| DeviceBusy | `is_ready()` |
| Temp1 / Temp2 | `measure_temperature()` |
| PlateCarrierOut | `sense_drawer_open()` |
| PlateInserted | `sense_plate_present()` |
| Version / Firmware | `request_firmware_info()` |
| SerialNo | `request_eeprom_data()` |
| FocalHeight | `focus_well()` returns this |

---

## Shake Mode Reference

### Standalone Shake (0x1D)

| DDE Arg | Mode | Max RPM | Wire byte |
|---------|------|---------|-----------|
| 0 | orbital | 700 | 0x00 |
| 1 | linear | 700 | 0x01 |
| 2 | double orbital | 700 | 0x02 |
| 3 | meander | 300 | 0x03 |

### Idle Movement (0x27)

| DDE Arg | Mode | RPM | Wire byte | Capture status |
|---------|------|-----|-----------|-------------|
| 0 | cancel | — | 0x00 | — |
| 1 | linear corner | — | 0x01 | confirmed |
| 2 | incubation | — | 0x02 | confirmed |
| 3 | meander corner | 100–300 | 0x03 | speculative |
| 4 | orbital corner | 100–700 | 0x04 | speculative |
| 5 | orbital | 100–700 | 0x05 | confirmed |
| 6 | double orbital | 100–700 | 0x06 | confirmed |

---

## Parameter Ranges

| Parameter | Range | Notes |
|-----------|-------|-------|
| ABS wavelength | 220–1000 nm | |
| FL wavelength | 320–840 nm | Excitation and emission |
| Shake frequency | 100–700 RPM | Meander max 300 |
| Shake duration | 1–3600 s | u16 BE |
| IdleMove duration | 1–65535 s | Single byte on wire (needs verification) |
| Temperature | 0–45 °C (standard), 10–65 °C (extended) | |
| PMT gain | 0–4095 | |
| Focal height | 0–25 mm (top), 0–9.7 mm (bottom) | 0.1 mm resolution |
| Flashes (point) | 1–200 | |
| Flashes (orbital) | 1–44 | |
| Flashes (spiral) | 1–127 | |
| Flashes (matrix) | 1–200 | |
| Matrix size | 2×2 to 11×11 | |
| Scan diameter | 1–6 mm | Orbital and spiral |

---

## Model Lookup

| Type code | Model | Monochromator | Filter slots |
|-----------|-------|---------------|-------------|
| `0x0021` | CLARIOstar Plus | 220–1000 nm | 11 |
| `0x0024` | CLARIOstar Plus | 220–1000 nm | 11 |
| `0x0026` | CLARIOstar Plus | 220–1000 nm | 11 |
| `0x0621` | CLARIOstar Plus | 220–1000 nm | 11 |
| `0x0624` | CLARIOstar Plus | 220–1000 nm | 11 |
| `0x0626` | CLARIOstar Plus | 220–1000 nm | 11 |
| `0x0721` | CLARIOstar Plus | 220–1000 nm | 11 |
| `0x0724` | CLARIOstar Plus | 220–1000 nm | 11 |
| `0x0726` | CLARIOstar Plus | 220–1000 nm | 11 |

---

## Implementation Gap Analysis

### High priority (simple, validated protocol)

| Command | Wire opcode | Complexity | Notes |
|---------|------------|------------|-------|
| Pause | 0x19 | Low | Single byte flag |
| Continue | 0x19 | Low | Resume from pause |
| StopTest | 0x0B | Low | Already send 0x0B for shaking; need `save_results` param |

### Medium priority (need captures)

| Command | Complexity | Notes |
|---------|------------|-------|
| Pump1/Pump2 | Medium | Syringe pump control. Need hardware + capture. |
| GainWell/GainPlate | Medium | Auto-gain pre-measurement. Multi-command sequence. |
| StopSystem | Low | Emergency stop. |
| Fan | Low | Only useful with ACU. |

### Low priority (need hardware)

| Command | Notes |
|---------|-------|
| ACU | Atmospheric control — need ACU hardware |
| ResetError | Error state recovery |
| GetKFactor | FP calibration — need FP hardware |
| CalculateTestDuration | Query only |
| Luminescence | Need capture captures |

### Not needed (no USB traffic)

Dummy, SetSampleIDs, ClearSampleIDs, ClearDilutionFactors, EditLayout, EditConcAndVol, ImportLayout, ImportConcAndVol, MotorDis, MotorEn, Terminate.

---

## Sources

- **USB captures:** 130+ USB capture files (59 absorbance + 29 fluorescence + 45+ DDE standalone), 6,780+ frames total.
- **OEM manuals:**
  - `0430N0003I` — ActiveX and DDE Manual, CLARIOstar V5.00–5.70R2
  - `0430F0035B` — Software Manual, CLARIOstar 5.70 R2 Part II (script language, §9)
  - `0430B0006B` — Operating Manual, CLARIOstar Plus (hardware specs)
- **Go reference implementation:** `fl.go`, `abs.go`, command dispatch.
