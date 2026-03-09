# CLARIOstar Plus Backend — Architecture & Implementation

Production-grade driver for the BMG Labtech CLARIOstar Plus, built from 100+ captures (88 OEM + 13 DOE) with byte-level verification. Replaces the original ~350-line proof-of-concept.

---

## At a Glance

| Capability | Old backend | Current |
|---|---|---|
| **Code** | ~350 lines, 0 tests | ~5,200 lines (8 mixin modules + backend) + 8,094 lines tests |
| **Tests** | 0 | 474 methods, hardware-verified |
| **Wire protocol** | Hardcoded byte arrays, 2-byte checksum | Structured frame builder, 24-bit checksum, validation, retries |
| **Absorbance** | Single wavelength, point scan | 1–8 wavelengths, spectrum scans, all well-scan modes |
| **Fluorescence** | `NotImplementedError` | Discrete + spectrum, mono + filter + multi-chromatic + EDR + flying + matrix |
| **Luminescence** | Basic (hardcoded payload) | Stub (`NotImplementedError`) — pending captures |
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
CLARIOstarPlusBackend (backend.py — assembly, enums, constants, status flags, connection, I/O, device info)
│   ├── Constructor, setup, stop
│   ├── Low-level I/O (_write_frame, _read_frame)
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
└── _framing.py (frame encoding/validation, protocol exceptions, payload byte blocks — leaf module)
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
- Kinetic mode: configurable cycles (u8) and cycle time (u16 BE seconds). Shake timing variants: each, first, defined cycles, between readings.
- Shake-between-readings: trailer_prefix encoding with pattern and RPM (DOE_SPC04/SPC05).

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
| 3.5 | **Pump1** / **Pump2** | Pump1: no USB frames observed (MON-05, exit 0); Pump2: DDE error 2000 (no hardware) | Not implemented | MON-05/06 captured — no protocol frames |
| 3.6 | **Temp** | None via DDE (exit 1000) | `start/stop_temperature_control()` via USB 0x06 | USB confirmed |
| 3.7 | **GainWell** / **GainPlate** / **GetKFactor** | Yes | Not implemented (auto-gain/FP) | Not captured |
| 3.8 | **SetGain** | Unknown | Not implemented | Not captured |
| 3.9 | **SetFocalHeight** | Unknown | `focal_height=` param | Not captured via DDE |
| 3.10–3.14 | **SetSampleIDs**, **EditLayout**, etc. | None — OEM-internal | N/A | N/A |
| 3.15 | **Run** | Yes — 0x04 | `read_absorbance()` / `read_fluorescence()` | 40+ captures |
| 3.16 | **Pause** | Yes — 0x0D | `pause_measurement()` | MON-03 (standalone), cleanup/ (mid-measurement) |
| 3.17 | **Continue** | Yes — 0x0D | `resume_measurement_and_collect_data()` | MON-04 (standalone), cleanup/ (mid-measurement) |
| 3.18 | **StopTest** | Yes — 0x0B param 0x00 | `stop_measurement()` | ST-01, ST-04 |
| 3.19 | **StopSystem** | Yes — 0x0B param 0x01 | Not implemented (captured) | MON-02 |
| 3.20 | **ACU** | Yes — unknown | Not implemented (no hardware) | Not captured |
| 3.21 | **Fan** | Yes — unknown | Not implemented | Not captured |
| 3.22 | **Shake** | Yes — 0x1D | `start_shaking()` | 13 frames |
| 3.23 | **IdleMove** | Yes — 0x27 | `start_idle_movement()` / `stop_idle_movement()` | 6 captures |
| 3.24–3.25 | **MotorDis** / **MotorEn** | None | N/A | Confirmed no USB |
| 3.26 | **ResetError** | Re-init sequence: INIT(0x01) → STATUS_QUERY(0x80) → EEPROM(0x05/0x07) → POLL(0x08). No unique opcode. | Not implemented (no unique command needed) | MON-01 |
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
| ~~Pause~~ | ~~0x19~~ 0x0D | ~~Low~~ Done | Implemented as `pause_measurement()`. MON-03 confirms standalone form. |
| ~~Continue~~ | ~~0x19~~ 0x0D | ~~Low~~ Done | Implemented as `resume_measurement_and_collect_data()`. MON-04 confirms. |
| StopTest | 0x0B | Low | Already send 0x0B for shaking; need `save_results` param |
| StopSystem | 0x0B param 0x01 | Low | Captured in MON-02. Trivial to add. |
| **Kinetic modes** | 0x04 (RUN) | Medium | Wire encoding fully decoded (DOE 2026-03-09). Backend parameterized: `kinetic_cycles`, `kinetic_cycle_time_s` in `_build_absorbance_payload`. Shake-between-readings trailer construction implemented. No public `read_absorbance_kinetic()` API yet. See wire_protocol.md §3.3 and §3.6.3. |

### Medium priority (need captures)

| Command | Complexity | Notes |
|---------|------------|-------|
| Pump1/Pump2 | Medium | MON-05 shows Pump1 produces no USB frames (DDEclient exit 0). Likely requires physical pump hardware or uses a different comm channel. MON-06 (Pump2) failed with DDE error 2000. |
| GainWell/GainPlate | Medium | Auto-gain pre-measurement. MON-08/09 failed — need valid FL test protocol `PLR_FI_Test` in MARS. |
| Fan | Low | Only useful with ACU. |

### Low priority (need hardware)

| Command | Notes |
|---------|-------|
| ACU | Atmospheric control — need ACU hardware |
| ~~ResetError~~ | ~~Error state recovery~~ — MON-01 confirms this is a re-init sequence (INIT + EEPROM read), not a unique command. Equivalent to calling `setup()` again. |
| GetKFactor | FP calibration — need FP hardware |
| CalculateTestDuration | Query only |
| Luminescence | Need captures |

### Not needed (no USB traffic)

Dummy, SetSampleIDs, ClearSampleIDs, ClearDilutionFactors, EditLayout, EditConcAndVol, ImportLayout, ImportConcAndVol, MotorDis, MotorEn, Terminate.

---

## Protocol Byte Coverage

How many payload bytes are understood vs unknown/hardcoded for each command.
Frame overhead (STX + size + header + checksum + CR = 8 bytes) is excluded.

### Sent payloads

| # | Command | Hex | Sent Bytes | Known | Unknown | Notes |
|---|---------|-----|-----------|-------|---------|-------|
| 1 | STATUS_QUERY | `0x80` | 1 | 1 (100%) | 0 | |
| 2 | INITIALIZE | `0x01 0x00` | 6 | 2 (33%) | 4 | `\x00\x10\x02\x00` unexplained |
| 3 | TRAY_OPEN/CLOSE | `0x03` | 6 | 2 (33%) | 4 | `\x00\x00\x00\x00` padding |
| 4 | TEMP_CTRL | `0x06` | 3 | 3 (100%) | 0 | Fully understood |
| 5 | EEPROM | `0x05 0x07` | 7 | 2 (29%) | 5 | 5 zero-byte params |
| 6 | FIRMWARE_INFO | `0x05 0x09` | 7 | 2 (29%) | 5 | 5 zero-byte params |
| 7 | USAGE_COUNTERS | `0x05 0x21` | 7 | 2 (29%) | 5 | 5 zero-byte params |
| 8 | GET_DATA | `0x05 0x02` | 7 | 4 (57%) | 3 | `\xff` variant = progressive |
| 9 | CMD_0x0E | `0x0E` | 7 | 1 (14%) | 6 | Most opaque command |
| 10 | STOP | `0x0B` | 2 | 2 (100%) | 0 | |
| 11 | PAUSE/RESUME | `0x0D` | 5 | 1 (20%) | 4 | Magic constants |
| 12 | R_Shake | `0x1D` | 11 | 10 (91%) | 1 | 1 hardcoded zero |
| 13 | R_IdleMove | `0x27` | 11 | 8 (73%) | 3 | 3 hardcoded zeros |
| 14 | ABS discrete RUN | `0x04` | ~136 | ~93 (68%) | ~43 | Separator, reference (partial), pre-sep zeros |
| 15 | ABS spectrum RUN | `0x04` | ~136 | ~93 (68%) | ~43 | Same structure |
| 16 | FL discrete RUN | `0x04` | ~137 | ~90 (66%) | ~47 | Similar unknowns |
| 17 | FL spectrum RUN | `0x04` | ~167 | ~120 (72%) | ~47 | Similar unknowns |
| 18 | FOCUS_WELL | `0x09` | 45 | 39 (87%) | 6 | Mostly padding |
| 19 | FILTER_SCAN | `0x24` | 28 | 20 (71%) | 8 | Wavelength config blob |

### Received payloads

| # | Command | Response Bytes | Known | Unknown | Notes |
|---|---------|---------------|-------|---------|-------|
| 1 | STATUS_QUERY | 16 | 11 (69%) | 5 | Bytes 5-10 unparsed, byte 15 ambiguous |
| 2 | EEPROM | 263 | ~20 (8%) | ~243 | Factory calibration, flags, sparse regions |
| 3 | FIRMWARE_INFO | 32 | 26 (81%) | 6 | 4 trailing + 2 mid-header |
| 4 | USAGE_COUNTERS | 43 | 38 (88%) | 5 | 1 trailing + 4 header |
| 5 | GET_DATA (ABS) | variable | ~60-70% | ~30-40% | 17/36 header bytes unknown |
| 6 | GET_DATA (FL) | variable | ~60-70% | ~30-40% | 19/34 header bytes unknown |
| 7 | FOCUS_RESULT | ~1177 | ~85% | ~15% | ~20 header bytes unknown |
| 8 | FILTER_RESULT | ~13 | 7 (54%) | 6 | Longpass encoding unknown |
| 9 | SPECTRAL_DATA | variable | 0% | 100% | Not parsed (buffer drain only) |

### Largest unknown byte clusters

1. **EEPROM response** (243/263 unknown) — factory calibration (~96B), boolean flags (~18B), sparse regions (~43B), board info (~7B). Only serial, machine type, detection modes, filter slots, and mono ranges are decoded.

2. **Measurement RUN payloads** (~43 unknown bytes each):
   - `_MEAS_BOUNDARY` (`\x27\x0f\x27\x0f`) — 4B, fixed magic constant (confirmed across 135 payloads)
   - `_REFERENCE_BLOCK` — 13B, last byte overloaded as pause mode flag (DOE_SPC06/07)
   - `_TRAILER_PREFIX` — 10B, decoded: mode flag, speed, shake enable, 0x003b constant (DOE_SPC04/05)
   - Kinetic tail (cycles + flashes + cycle_time + final_zero) — fully decoded
   - Pre-separator — 21/31 bytes are unexplained zeros

3. **CMD_0x0E** (6/7 unknown) — sent every boot, meaning not fully understood

4. **All REQUEST parameters** (`0x05 XX`) — 5 zero bytes each. Could be page selectors or truly unused.

5. **GET_DATA response headers** — 17-19 bytes skipped in both ABS and FL parsers.

### Caveats on named fields

**`"initialized"` flag (status byte 3, bit 5)** — Named by correlation: goes high after INITIALIZE (`0x01 0x00`), stays high during normal operation. However, we are not confident this bit truly represents "device has been initialized". It could be a motor-homed flag, optics-ready state, or something else. We have never observed it go low after a successful `setup()`, but edge cases (partial init failure, power glitch) have not been tested.

**`machine_type_code` (EEPROM bytes 2-3)** — Not a stable device identifier. The same physical unit (serial 430-2621, firmware 1.35) reports different values across reads: high byte varies (`0x00`, `0x06`, `0x07`), low byte varies (`0x21`, `0x24`, `0x26`). The full cross-product is enumerated in `_MODEL_LOOKUP` as a workaround. The field name is misleading — these bytes encode some combination of device state or configuration variant, not a fixed hardware type code.

---

## Sources

- **USB captures:** 143+ USB capture files (59 absorbance + 29 fluorescence + 45+ DDE standalone + 13 DOE), 6,780+ frames total.
- **OEM manuals:**
  - `0430N0003I` — ActiveX and DDE Manual, CLARIOstar V5.00–5.70R2
  - `0430F0035B` — Software Manual, CLARIOstar 5.70 R2 Part II (script language, §9)
  - `0430B0006B` — Operating Manual, CLARIOstar Plus (hardware specs)
- **Go reference implementation:** `fl.go`, `abs.go`, command dispatch.
