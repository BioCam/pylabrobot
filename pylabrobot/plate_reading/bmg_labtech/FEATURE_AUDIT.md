# CLARIOstar Plus Feature Audit: Implemented vs Missing

**Date:** 2026-03-03
**Branch:** `clariostar-refactor-with-fluorescence`
**Backend:** `clariostar_plus_backend.py` (3,636 lines)
**Tests:** `clariostar_plus_backend_tests.py` (5,958 lines, 341 tests across 53 classes)

This is an **analysis-only** document. No code changes proposed.

---

## Feature Status Summary

### Fully Implemented (validated on hardware)

| Feature | Method | Evidence |
|---------|--------|----------|
| Lifecycle (setup/stop/initialize) | `setup()`, `stop()`, `initialize()` | 29 unit tests + hardware runs |
| Device ID (EEPROM, firmware, status, counters) | `request_eeprom_data()` etc. | All 6 request commands, real 263-byte EEPROM frame |
| Drawer control | `open()`, `close()` | Validated |
| Temperature control (set/monitor/measure) | `start_temperature_control()`, `measure_temperature()` | Dual-sensor, 14 tests, 0.1C resolution |
| Absorbance (discrete, 1-8 wl) | `read_absorbance()` | 22 pcap ground truth payloads, cross-validated against Feb 27 captures |
| Absorbance spectrum (paginated) | `read_absorbance_spectrum()` | 5 pcap payloads, 781-wavelength real dataset, all report modes |
| Fluorescence intensity (mono/filter, top/bottom, multi-chromatic) | `read_fluorescence()` | 15 pcap-verified wire encodings, 282+ ground-truth tests |
| Auto-focus (Z-scan) | `auto_focus()` | FQ01 pcap verified, 143-point Z-profile parsing |
| Well scan: point, orbital, spiral | All measurement methods | Validated for absorbance + fluorescence |
| Scan direction (all 16 OEM patterns) | `_scan_direction_byte()` | 4 corners x 2 directions x 2 uni/bidi |
| Shaking (orbital, linear, double_orbital) | Integrated into all measurements | RPM 100-700, duration, settling |
| Flying mode | `read_fluorescence(flying_mode=True)` | FO01 pcap match, forces settling=1/flashes=1 |
| EDR (Enhanced Dynamic Range) | `read_fluorescence(edr=True)` | FP01 pcap match, overflow ceiling 700M |
| Filter mode (per-channel mono/filter mixing) | `ex_mode`/`em_mode` params | FLf01/02/03 pcap match, all 3 combos |
| Multi-chromatic (1-5 simultaneous) | `chromatics=` param | FM01 dual-chromatic pcap verified |
| Non-blocking measurement (`wait=False`) | All measurement methods | Fire-and-forget + later retrieval |
| Report modes (OD, transmittance, raw+calibration) | `report=` param | Raw counts + reference calibration |

### Implemented but NOT yet validated on hardware

| Feature | Code Status | Notes |
|---------|-------------|-------|
| Fluorescence bottom optic | `optic_position="bottom"` param, FA02 pcap wire match | No notebook test cell yet |
| Multi-chromatic fluorescence (3-5 ch) | `chromatics=` list, FM01 dual verified | Dual verified; 3-5 ch untested on hardware |
| Filter mode fluorescence | FLf01/02/03 pcap verified | No notebook test cell yet |
| Flying mode fluorescence | FO01 pcap verified | No notebook test cell yet |
| EDR fluorescence | FP01 pcap verified | No notebook test cell yet |
| Matrix well scan (FL only) | `WellScanMode.MATRIX=0x10`, FS01 pcap verified, parser averages | No notebook test cell yet |
| 384-well plate fluorescence | FN01 pcap wire verified | No notebook test cell yet |
| Auto-focus | FQ01 pcap verified, 143-point Z-profile | No notebook test cell yet |

### NOT Implemented (stubs or missing)

| Feature | Current State | Difficulty | Priority |
|---------|--------------|------------|----------|
| **Luminescence** | `read_luminescence()` raises `NotImplementedError` (line 3401). `DetectionMode.LUMINESCENCE = 0x01` now defined (from Go reference). EEPROM correctly reports `has_luminescence=True`. | Medium — wire encoding unverified, response format likely similar to FL | **High** |
| **Matrix well scan (ABS)** | `NotImplementedError` at line 2458. Wire encoding known from FL FS01 pcap. ABS spectrum has no `"matrix"` in validation at all. | Low — encoding verified in FL | **Medium** |
| **Fluorescence spectrum** | No `read_fluorescence_spectrum()` method. OEM supports em/ex/dual scan. | Medium — probably similar to ABS spectrum pagination | **Medium** |
| **TRF (Time-Resolved Fluorescence)** | Not present. EEPROM byte 15 hypothesized as `has_trf` (line 1027), unconfirmed. | Hard — no pcap captures, filter-only, microsecond timing | **Low** |
| **Fluorescence Polarization (FP)** | Not present at all. | Hard — no pcap captures, dual-channel encoding unknown | **Low** |
| **AlphaScreen/AlphaLISA** | Not present. | N/A — requires 680nm laser hardware (not installed) | **Out of scope** |
| **Kinetic modes (plate/well)** | Not present. No kinetic loop or repeated-read method. | Hard — different RUN command structure | **Low** |
| **Injector/pump control** | Not present. EEPROM docs mention `Pump1In`/`Pump2In` fields. | Hard — separate command set | **Low** |
| **Gain adjustment (auto-gain)** | Manual only (default gain=1000). Line 83: `# no auto-gain on firmware 1.35`. | Medium — separate wire commands before RUN | **Medium** |
| **1536-well plate support** | Unknown encoding. Line 1490: `# TODO: capture a 1536-well protocol`. | Unknown — no captures | **Low** |
| **Pause before plate reading** | Wire field known (flag + u16 seconds) but not exposed as a public parameter. Only `settling_time_s` is exposed. | Low — just needs parameter plumbing | **Medium** |
| **Multiple shaking actions** | Only single shake supported. OEM supports chaining multiple shakes. | Low | **Low** |
| **Well multichromatics ordering** | Missing — controls per-well vs per-chromatic measurement order. | Low — flag in wire protocol | **Low** |

---

## Code Inventory

### Public Methods (18 total)

**Lifecycle (3):** `setup`, `stop`, `initialize`

**Device ID (4):** `request_eeprom_data`, `request_firmware_info`, `request_available_detection_modes`, `request_usage_counters`

**Status (3):** `request_machine_status`, `is_ready`, `sense_plate_present`, `sense_drawer_open` (4)

**Drawer (2):** `open`, `close`

**Temperature (4):** `start_temperature_control`, `stop_temperature_control`, `measure_temperature`, `get_target_temperature`

**Measurement (4):** `read_absorbance`, `read_absorbance_spectrum`, `read_fluorescence`, `read_luminescence` (stub)

**Results (1):** `request_absorbance_results`

**Auto-focus (1):** `auto_focus`

### NotImplementedError Locations (2)

| Line | Method | Guard |
|------|--------|-------|
| 2458 | `read_absorbance` | `if well_scan == "matrix": raise NotImplementedError("matrix well scan is not yet implemented.")` |
| 3401 | `read_luminescence` | Entire method body: `raise NotImplementedError("Luminescence not yet implemented for CLARIOstar Plus.")` |

### TODO Comments (6)

| Line | Context |
|------|---------|
| 277 | `# LUMINESCENCE = 0x??  # TODO: determine from captures` |
| 387 | `# TODO: keep searching for a way to retrieve target temp from device` |
| 1490 | `# TODO: capture a 1536-well protocol via OEM software to determine encoding` |
| 1870 | `# TODO: confirm with M-series captures` (settling_time formula) |
| 1909 | `# TODO: confirm formula with M-series captures` (same formula) |
| 2337 | `# TODO: ask community to abolish wavelength: int for wavelengths: List[int]` |

No FIXME or HACK comments anywhere.

---

## OEM Screenshot Analysis: Feature-by-Feature Comparison

### Measurement Methods (from `00_meas_methods_reading_mode.png`)

The OEM MARS software shows **6 measurement methods** with up to **4 reading modes** each:

| Method | Endpoint | Plate Mode | Well Mode | Spectral | Our Status |
|--------|----------|------------|-----------|----------|------------|
| Fluorescence Intensity | Yes | Yes | Yes | Yes | **Endpoint: DONE**, Plate/Well kinetic: MISSING, Spectral: MISSING |
| Dual-Emission FL | Yes | Yes | Yes | — | **DONE** (via multi-chromatic) |
| Fluorescence Polarization | Yes | Yes | Yes | — | MISSING (filter-only, no pcaps) |
| TRF | Yes | Yes | Yes | — | MISSING (filter-only, no pcaps) |
| Luminescence | Yes | Yes | Yes | Yes | **STUB** — `NotImplementedError` |
| Absorbance | Yes | Yes | — | Yes | **Endpoint: DONE, Spectrum: DONE**, Plate kinetic: MISSING |

### Basic Parameters (from `01_window_1_basic_parameters.png`)

| UI Feature | Our Implementation |
|---|---|
| Top/Bottom optic radio | `optic_position="top"/"bottom"` — **DONE** |
| No. of multichromatics (1-5) | `chromatics=` list — **DONE** |
| Well multichromatics checkbox | **MISSING** — controls per-well vs per-chromatic ordering |
| Excitation/Emission dropdowns | Wavelength params — **DONE** |
| Dichroic auto/manual | `dichroic=` param, auto-calc `(ex_upper + em_lower) / 2` — **DONE** |
| Well Scan: None/Orbital/Spiral/Matrix | Point/orbital/spiral **DONE**, matrix **FL only** (ABS stub) |
| Settling time (0.0-1.0s for ABS, 0.0-5.0s for FL) | `settling_time_s=` — **DONE** |
| Flying mode checkbox | `flying_mode=True` — **DONE** |
| No. of flashes (0-200, or 1/3 for flying) | `flashes=` — **DONE** |
| Speed/Precision slider | Not exposed (UI sugar — maps to settling+flashes) |
| Pause before plate reading | **MISSING** — wire field exists but not exposed as param |
| Use enhanced dynamic range | `edr=True` — **DONE** |
| Filter mode (F: prefix) | `ex_mode`/`em_mode` + slot params — **DONE** |

### Layout (from `03_window_2_layout.png`)

| UI Feature | Our Implementation |
|---|---|
| 16 reading direction patterns | `corner`/`vertical`/`unidirectional` — **ALL 16 COVERED** |
| Well selection (Sample/Blank/Standard/Control) | `wells=` list — **DONE** (software-level concept) |

### Shaking (from `04_window_3_shaking_parameters.png`)

| UI Feature | Our Implementation |
|---|---|
| Shake before plate reading | `shake_mode=` — **DONE** |
| Shake modes (orbital, double orbital, linear) | **DONE** (meander also in builder but not exposed publicly) |
| Frequency (100-700 RPM) | `shake_speed_rpm=` — **DONE** |
| Time (seconds) | `shake_duration_s=` — **DONE** |
| Multiple shaking actions (+/- buttons) | **MISSING** — only single shake supported |

### Start Measurement (from `start_measurement_window_*`)

| UI Feature | Our Implementation |
|---|---|
| Focus: Auto focus / Previous / New focal height | `auto_focus()` + `focal_height=` — **DONE** |
| Dynamic range: EDR vs Fixed gain | `edr=` and `gain=` — **DONE** |
| Per-chromatic gain table | `gain` per chromatic dict — **DONE** |
| Gain Adjustment (auto-gain pre-step) | **MISSING** — firmware 1.35 doesn't support (line 83) |
| Gain > 3000 warning | **MISSING** — could add Python-side warning |
| Overflow >= 260000 detection | **MISSING** — could flag in returned data |

### Spectrum / Fluorophore Toolbox (from `f_spectrum_*`)

| UI Feature | Our Implementation |
|---|---|
| 25nm minimum ex-em distance warning | **MISSING** — could add Python-side validation |
| Bandwidth validation (8-100nm) | **DONE** — validated in `read_fluorescence()` |
| Auto-dichroic formula (band-edge midpoint) | **DONE** |

### Filter Configuration (from `settings_0_filters.png`)

| UI Feature | Our Implementation |
|---|---|
| Filter position table (Ex 1-4, Dichroic A-C, Em 5-8) | `ex_filter_slot`/`em_filter_slot` — **DONE** |

---

## Test Coverage Summary

### By Feature Area

| Area | Classes | Tests | Pcap Ground Truth |
|------|---------|-------|-------------------|
| Frame utilities & wire protocol | 3 | 17 | 10 command round-trips |
| Lifecycle (init/open/close/stop) | 5 | 15 | — |
| Status & device ID | 7 | 35 | Real EEPROM (263B) + firmware (39B) frames |
| Temperature | 1 | 14 | — |
| Absorbance discrete | 7 | 70 | 22 pcap payloads (A01-G02) |
| Absorbance spectrum | 5 | 39 | 5 pcap payloads (H01-H05) + 781-wl dataset |
| Fluorescence | 12 | 62 | 15 pcap payloads + 7 response frames |
| Auto-focus | 4 | 25 | FQ01 send + 143-point result frame |
| Input validation | 3 | 28 | — |
| Infrastructure (timeouts, retries) | 6 | 16 | — |
| **Total** | **53** | **~341** | **~60 pcap-derived constants** |

### Notable Gaps in Test Coverage

1. **No luminescence tests** — only EEPROM flag parsing and detection mode listing
2. **No `wait=False` collect helper tests for FL/spectrum** — `request_absorbance_results()` is tested; no FL equivalent exists
3. **No shake validation upper-bound test** — RPM limit is 700 in code but `_pre_separator_block` docstring says 800
4. **Meander shake mode** — exists in builder (index 3) but not exposed or tested publicly

---

## Prioritized Missing Features

### High Priority (common use cases, protocol mostly known)

1. **Luminescence** — Very common assay type. `DetectionMode.LUMINESCENCE = 0x01` now defined (from Go reference, bit 0). Needs 1-2 pcap captures to verify wire encoding, then implementation mirrors fluorescence. EEPROM confirms the hardware has it.

2. **Fluorescence hardware validation notebook** — `read_fluorescence()` is implemented and wire-verified against 29 pcaps, but has zero notebook test cells exercising it on real hardware. Need F-test cells analogous to the T-tests and S-tests.

### Medium Priority (useful features, some unknowns)

3. **Matrix well scan (ABS)** — Wire encoding fully known from FL FS01 pcap. Just need to remove `NotImplementedError` at line 2458 and verify response parsing handles grid-point-per-well.

4. **Fluorescence spectrum** (emission/excitation scan) — OEM supports it, likely uses similar pagination to absorbance spectrum. Needs pcap captures.

5. **Gain adjustment (auto-gain)** — Pre-measurement step that finds optimal gain. Comment at line 83 says "no auto-gain on firmware 1.35" — may need firmware upgrade or different wire approach.

6. **Python-side validation warnings** — Ex-em minimum distance (25nm), gain > 3000 noise warning, overflow detection in returned data. Pure software, no wire work needed.

7. **Pause before plate reading** — Wire field is known (flag + u16 seconds). Just needs to be exposed as a public parameter on measurement methods.

8. **`wait=False` collect helpers for FL/spectrum** — `request_absorbance_results()` exists for ABS; FL and spectrum have no public equivalent.

### Low Priority (specialized, needs captures/hardware)

9. **TRF** — Filter-only, microsecond timing. No pcap captures.
10. **FP** — Filter-only, dual-channel. No pcap captures.
11. **Kinetic modes** — Plate mode (slow) and well mode (fast). Different RUN structure.
12. **Injector control** — Specialized syringe pump hardware.
13. **Well multichromatics ordering** — Flag in wire protocol.
14. **Multiple shaking actions** — OEM supports chaining.

### Out of Scope

- **AlphaScreen/AlphaLISA** — Requires 680nm laser hardware (not installed)
- **1536-well plates** — Unknown encoding, no captures
- **Cuvette mode** — LVis Plate accessory

---

## Minor Inconsistencies Found During Audit

1. **Shake RPM upper bound**: `read_absorbance` validates `shake_speed_rpm <= 700`, but `_pre_separator_block` docstring says 100-800. Should verify which is correct on hardware.

2. **Meander shake mode**: Exists as index 3 in the builder but is not listed in any public method's validation. Either expose it or document why it's excluded.

3. **ABS spectrum matrix**: Not in validation dict (raises `ValueError`), while ABS discrete has it in validation dict (raises `NotImplementedError`). Inconsistent error for the same unsupported feature.

---

## Quantitative Summary

| Metric | Count |
|--------|-------|
| Public methods | 19 |
| Lines of code | 3,636 |
| Lines of tests | 5,958 |
| Test classes | 53 |
| Test methods | ~341 |
| Pcap ground truth constants | ~60 |
| NotImplementedError guards | 2 |
| TODO comments | 6 |
| Measurement modalities implemented | 3 (ABS discrete, ABS spectrum, FL) |
| Measurement modalities stubbed | 1 (luminescence) |
| Measurement modalities missing entirely | 4 (FL spectrum, TRF, FP, kinetic) |
