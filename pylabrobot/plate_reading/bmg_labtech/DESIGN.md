# CLARIOstar Plus Backend — Design & Feature Delta

This branch (`clariostar-refactor-with-fluorescence`) rewrote the plate reader backend from scratch. The original `CLARIOstarBackend` was a proof-of-concept with hardcoded byte strings and incomplete protocol support. The new `CLARIOstarPlusBackend` is a production-grade driver built from 88 pcap captures with byte-level verification.

---

## At a Glance

| Capability | CLARIOstar (old) | CLARIOstarPlus (new) |
|---|---|---|
| **Lines of code** | ~350 | ~3,800 (backend) + 6,345 (tests) + 195 (filters) |
| **Test methods** | 0 | 359 |
| **Wire protocol** | Hardcoded byte arrays, 2-byte checksum | Structured frame builder, 24-bit checksum, validation, retries |
| **Absorbance (discrete)** | Single wavelength | 1-8 wavelengths per run |
| **Absorbance (spectrum)** | Not supported | Full spectrum scans (220-1000 nm, variable step) with paginated retrieval |
| **Fluorescence** | `NotImplementedError` | Full implementation (mono + filter + multi-chromatic + EDR + flying + matrix) |
| **Luminescence** | Basic (hardcoded payload) | Stub (`NotImplementedError`) -- not yet ported |
| **Temperature** | Not supported (`NaN`) | Full control: monitor, set target (0-65 C), measure (top/bottom/mean) |
| **Device identification** | EEPROM only (unparsed) | EEPROM parsed (model, capabilities, mono ranges, filter slots) + firmware version + usage counters |
| **Status polling** | Simple busy/ready byte check | 12-flag bitfield parsing (busy, running, plate_detected, drawer_open, lid_open, etc.) |
| **Error recovery** | None | 4-strategy escalation (standard flush -> progressive flush -> re-init -> USB reset) |
| **Filter support** | None | Filter/DichroicFilter dataclasses, 3 slide containers with slot + name lookup |
| **Auto-focus** | None | Focal-height sweep with best-Z + intensity result |

---

## New Capabilities in Detail

### 1. Wire Protocol Overhaul
- **Old**: Raw `b"\x02\x00\x0d\x0c\x01..."` byte strings with inline 2-byte checksums. No frame validation. 25-byte reads with naive `0x0D` termination.
- **New**: `_wrap_payload()` / `_validate_frame()` / `_extract_payload()` pipeline. 24-bit checksums. Size-field-aware `0x0D` handling (critical -- `0x0D` appears in mid-frame checksum bytes). `send_command()` dispatches by `CommandFamily` enum with automatic retries on `FrameError`.

### 2. Absorbance -- Discrete Multi-Wavelength
- **Old**: One wavelength per run. Report = OD or transmittance. Point scan only.
- **New**: 1-8 wavelengths per run (220-1000 nm). Report = `optical_density`, `transmittance`, or `raw` (with per-well references + calibration values). Well scan modes: point, orbital, spiral, matrix. Configurable flashes (1-200), scan diameter (1-6 mm), settling time (0-1 s). Plate shaking: orbital, linear, double_orbital, meander (100-700 RPM).

### 3. Absorbance -- Spectrum Mode
Entirely new. Scans a wavelength range with configurable step size. Paginated data retrieval for large datasets. Same well scan / shake / settling options as discrete mode. Returns one result dict per wavelength in the scan.

### 4. Fluorescence (all new)
- **Monochromator mode**: Excitation 320-840 nm, emission 320-840 nm, configurable bandwidths (ex: 15 nm, em: 20 nm), auto-calculated dichroic split.
- **Filter mode**: Physical excitation/emission/dichroic filters via `Filter` / `DichroicFilter` objects. Sentinel wavelengths encode filter slot selection. Mixed filter+mono combinations supported.
- **Multi-chromatic**: 1-5 chromatic channels per run. Each channel independently configures wavelengths, gain, filters. Parser returns one result dict per chromatic.
- **EDR (Enhanced Dynamic Range)**: Single bit flag. Raises overflow threshold from ~65K to 700M counts.
- **Flying mode**: Point scan only. Forces settling=0, flashes=1. Fastest possible scan.
- **Matrix scan**: `WellScanMode.MATRIX` -- firmware averages multiple positions per well.
- **Gain control**: PMT gain 0-4095.
- **Optic position**: Top or bottom optics.
- All payloads verified byte-for-byte against 29 pcap captures.

### 5. Temperature Control
- **Old**: Not supported. All temperature fields returned `NaN`.
- **New**: Three-tier control -- monitoring only (sensor readout), active heating (setpoint + PID), off. `measure_temperature()` returns bottom, top, or mean. Setpoint tracked locally. Sensors auto-activated on demand.

### 6. Device Identification & Diagnostics
- **Old**: `request_eeprom_data()` -- returned raw bytes, no parsing.
- **New**:
  - `request_eeprom_data()` -> parsed dict: machine_type, model, capabilities (abs/fl/lum/alpha), monochromator ranges, filter slot counts.
  - `request_firmware_info()` -> firmware_version string + build timestamp. Version verified against `CONFIRMED_FIRMWARE_VERSIONS` dict.
  - `request_usage_counters()` -> flashes, testruns, wells, well_movements, active_time, shake_time, pump usage.
  - `request_available_detection_modes()` -> EEPROM-based capability list.

### 7. Status & Error Recovery
- **Old**: Polls 24-byte status, checks one byte for busy/ready.
- **New**: Parses 12 boolean flags from 5-byte status word. Drawer/plate/lid/filter-cover detection. Running-state recovery with 4-strategy escalation (progressively more aggressive: standard data flush -> progressive flush -> re-initialize -> USB chip reset + full reconfigure). `setup()` auto-recovers from stuck measurement states.

### 8. Auto-Focus
Entirely new. Sends `AUTO_FOCUS_SCAN` command. Sweeps focal height (0-25 mm). Returns best Z position + fluorescence intensity at that height. Supports filter and monochromator modes.

### 9. Filter Infrastructure (`filters.py`)
- `Filter` -- frozen dataclass (slot, name, center_wavelength, bandwidth).
- `DichroicFilter` -- frozen dataclass (slot, name, cut_on_wavelength).
- `ExcitationFilterSlide`, `EmissionFilterSlide`, `DichroicFilterSlide` -- container classes with `__getitem__` (by slot or name), `register()`, `by_slot()`. Dichroic supports letter indexing (A/B/C).
- Backend auto-populates slide slot counts from EEPROM during setup.

---

## What the Old Backend Still Has That the New One Doesn't

| Feature | Status |
|---|---|
| **Luminescence** | Old has a working (basic) implementation. New raises `NotImplementedError`. |
| **`_plate_bytes` well mask** | Both encode 384-bit masks, but old uses a slightly different byte layout -- functionally equivalent. |

---

## Test Coverage

The old backend has **zero tests**. The new backend has **359 test methods** organized across 23 test classes covering:
- Frame utilities and checksum validation
- Lifecycle (setup, recovery, stop)
- All payload builders (byte-for-byte ground truth vs pcap captures)
- Response parsing for absorbance (discrete + spectrum) and fluorescence
- Integration tests (mock I/O end-to-end workflows)
- Input validation (wavelength ranges, flash counts, scan modes, shake parameters)
- Status polling resilience and retry logic
- Temperature control state machine
- Filter dataclass behavior

---

## Summary

The branch transforms the CLARIOstar driver from a ~350-line proof-of-concept (absorbance + luminescence, no tests, hardcoded bytes) into a ~10,000-line production driver with structured protocol handling, comprehensive fluorescence support (6 sub-features), temperature control, auto-focus, device diagnostics, error recovery, and 359 tests. The only regression is luminescence, which is stubbed pending a pcap capture session.

---
---

## Appendix: Command Catalog

Every known CLARIOstar Plus USB command, organized by implementation phase.
Each entry records the wire-level details so future phases can be implemented
without re-analyzing pcap files.

**Protocol overview:** Every command is wrapped in a frame:
```
STX (0x02) | size (2B BE) | header (0x0C) | payload | checksum (3B BE) | CR (0x0D)
```
Checksum = `sum(frame[:-4]) & 0xFFFFFF`. 8-byte overhead total.
Verified against 6,780 pcap frames with zero failures.

---

### Phase 1 -- Core Lifecycle

#### `initialize`
- **Group/Cmd:** `0x01 0x00`
- **Payload:** `01 00 00 10 02 00`
- **Response:** Status frame -- poll until `initialized` flag is set.
- **Notes:** Must be the first command after FTDI setup. Takes ~3-5s.

#### `open` (drawer out)
- **Group/Cmd:** `0x03 0x01`
- **Payload:** `03 01 00 00 00 00`
- **Response:** Status frame -- poll until `drawer_open` flag is set.

#### `close` (drawer in)
- **Group/Cmd:** `0x03 0x00`
- **Payload:** `03 00 00 00 00 00`
- **Response:** Status frame -- poll until `drawer_open` flag clears.

#### `request_machine_status`
- **Group/Cmd:** `0x80` (no command byte -- STATUS is a single-byte family)
- **Payload:** `80`
- **Response:** 5+ status bytes. Bit layout:
  - Byte 0, bit 1: `standby`
  - Byte 1, bit 0: `valid` (status response validity)
  - Byte 1, bit 5: `busy`
  - Byte 1, bit 4: `running` (can persist across power cycles -- see Recovery below)
  - Byte 2, bit 0: `unread_data`
  - Byte 3, bit 6: `lid_open` (instrument lid, distinct from drawer)
  - Byte 3, bit 5: `initialized`
  - Byte 3, bit 3: `reading_wells` (optic head actively scanning wells)
  - Byte 3, bit 2: `z_probed` (z-stage probe contact after plate loading)
  - Byte 3, bit 1: `plate_detected`
  - Byte 3, bit 0: `drawer_open`
  - Byte 4, bit 6: `filter_cover_open`

---

### Phase 2 -- Device Identification

#### `request_eeprom_data`
- **Group/Cmd:** `0x05 0x07`
- **Payload:** `05 07 00 00 00 00 00`
- **Response:** 263-byte payload. Key fields:
  - Bytes 2-3: machine type code (uint16 BE). `0x0024`/`0x0026` = CLARIOstar Plus.
  - Byte 11: `has_absorbance` (bool)
  - Byte 12: `has_fluorescence` (bool)
  - Byte 13: `has_luminescence` (bool)
  - Byte 14: `has_alpha_technology` (bool)
  - Bytes 96-107: dense 16-bit values, likely usage counters.
  - Remaining offsets (pump, stacker, serial) not yet confirmed.
- **Use:** Populate `self.configuration` dict. Parsed inline in `request_eeprom_data()`.

#### `request_firmware_info`
- **Group/Cmd:** `0x05 0x09`
- **Payload:** `05 09 00 00 00 00 00`
- **Response:** 32-byte payload.
  - Bytes 6-7: firmware version x1000 (uint16 BE, e.g. `0x0546` = 1.35).
  - Bytes 8-19: build date, null-terminated ASCII (e.g. `"Nov 20 2020"`).
  - Bytes 20-27: build time, null-terminated ASCII (e.g. `"11:51:21"`).
- **Use:** Log firmware version during `setup()`.

#### `request_usage_counters`
- **Group/Cmd:** `0x05 0x21`
- **Payload:** `05 21 00 00 00 00 00`
- **Response:** Contains lifetime usage stats (flashes, wells measured, shake time).
- **Status:** Response format not fully decoded.

---

### Phase 3 -- Temperature

Temperature commands use standard 3-byte checksum framing (same as all other
command families). The payload is 3 bytes: `[0x06, temp_hi, temp_lo]`.

#### `temperature_off`
- **Group/Cmd:** `0x06` (no command byte -- TEMPERATURE_CONTROLLER is a no-command family)
- **Payload:** `06 00 00`
- **Response:** Acknowledgment frame.

#### `temperature_monitor`
- **Group/Cmd:** `0x06`
- **Payload:** `06 00 01`
- **Notes:** Enables temperature sensor readout without heating.

#### `temperature_set`
- **Group/Cmd:** `0x06` (dynamic)
- **Payload:** `06 <target_hi> <target_lo>` -- target in 0.1 C units (uint16 BE).
- **Notes:** Target 37.0 C -> bytes `01 72` (370 decimal).

---

### Phase 4 -- Absorbance

#### `run_absorbance`
- **Group/Cmd:** `0x04` (RUN family)
- **Payload structure:**
  ```
  04 <plate_bytes(63)> 82 02 00 00 00 00 00 00 00 20 04 00 1e
  <separator: 27 0f 27 0f>
  19 01 <wavelength(2B)> 00 00 00 64 00 00 00 00 00 00 00 64 00 00
  00 00 00 <trailer: 02 00 00 00 00 00 01 00 00 00 01> 00 16 00 01 00 00
  ```
- **Key params:**
  - `plate_bytes`: 63B plate geometry (dimensions + well mask).
  - `wavelength`: uint16 BE, value in 0.1 nm (e.g. 450nm -> `0x1194`).
  - `0x82`: measurement type marker for absorbance.
  - `0x19`: settling time encoding.
- **Scan modes:** Point, orbital, spiral. Encoded in optic config byte.
  - Point: `0x02`, Orbital: `0x32`, Spiral: `0x06`.
- **Well scan block** (after separator, before settling): 5 bytes for non-point modes.
  `[meas_code(0x02), width_mm, well_dia_hi, well_dia_lo, 0x00]`

#### `get_data`
- **Group/Cmd:** `0x05 0x02`
- **Payload:** `05 02 00 00 00 00 00`
- **Response:** Variable-length. Contains:
  - Chromatic readings: N x int32 BE
  - Reference readings: N x int32 BE
  - Calibration: c100, c0, r100, r0 (4 x int32 BE)
- **Data extraction:** Find 6-byte zero divider, data starts after it.

#### `focus_height`
- **Group/Cmd:** `0x05 0x0F`
- **Payload:** `05 0f 00 00 00 00 00`
- **Response:** Microplate and focus height values.

#### `read_order`
- **Group/Cmd:** `0x05 0x1D`
- **Payload:** `05 1d 00 00 00 00 00`
- **Response:** Well measurement order for the last run.

#### `plate_bytes` encoding (63 bytes)
```
plate_length(2B) plate_width(2B) x1(2B) y1(2B) xn(2B) yn(2B)
cols(1B) rows(1B) extra(1B=0x00) well_mask(48B)
```
All dimensions in 0.01mm units (uint16 BE). Well mask is 384-bit big-endian.

---

### Phase 5 -- Fluorescence

#### `run_fluorescence`
- **Group/Cmd:** `0x04` (RUN family)
- **Key differences from absorbance:**
  - Measurement type marker: `0x02` (vs `0x82` for absorbance).
  - Requires: excitation wavelength, emission wavelength, bandwidth, gain, dichroic mirror.
  - Well scan measurement code: `0x03` (vs `0x02`).
- **Params:**
  - Excitation wavelength: uint16 BE, 0.1 nm units.
  - Emission wavelength: uint16 BE, 0.1 nm units.
  - Bandwidth: excitation and emission bandwidths in 0.1 nm units.
  - Gain: PMT gain 0-4095.
  - Dichroic mirror: auto-calculated or explicit position.
- **Multi-chromatic:** 1-5 independent chromatic blocks, each with own wavelengths/gain/filters.
- **Filter mode:** Sentinel wavelengths (0x0002=flag, 0x0001=slot) encode physical filter selection.
- **EDR:** Pre-separator byte[1] = 0x40. No timing penalty.
- **Flying mode:** Scan byte bit2 set, settling=1, flashes=1.

---

### Phase 6 -- Luminescence

#### `run_luminescence`
- **Group/Cmd:** `0x04` (RUN family)
- **Payload structure:**
  ```
  04 <plate_bytes(63)> 02 01 00 00 00 00 00 00 00 20 04 00 1e
  <separator: 27 0f 27 0f>
  01 <focal_height(2B)> 00 00 01 00 00 0e 10 00 01 00 01 00
  01 00 01 00 01 00 06 00 00 00 00 00 00 00 00 00
  <trailer: 02 00 00 00 00 00 01 00 00 00 01> 00 64 00 20 00 00
  ```
- **Key params:**
  - `focal_height`: uint16 BE, 0.01 mm units. Range 0-25mm.
  - `0x02 0x01`: measurement type marker for luminescence.
- **Data format:** Same as absorbance -- N x int32 BE values after zero divider.
- **Status:** Stub (`NotImplementedError`) -- pending pcap capture session.

---

### Phase 7 -- Advanced

#### `hardware_status`
- **Group/Cmd:** `0x81 0x00`
- **Payload:** `81 00`
- **Response:** Hardware-level status. Format not fully decoded.

#### `progressive_polling`
- **Group/Cmd:** `0x08 0x00`
- **Payload:** `08 00`
- **Notes:** Used during long measurement runs to get intermediate data.
  Progressive `get_data` variant uses `FF FF FF FF` at payload bytes 2-5.

#### Shaker
- **Encoding:** 4 bytes embedded in RUN payloads.
  ```
  [(1 << 4) | shake_type, speed_idx, duration_hi, duration_lo]
  ```
- **Types:** Orbital(0), Linear(1), Double-Orbital(2), Meander(3).
- **Speed:** 100-700 RPM in steps of 100. `speed_idx = rpm/100 - 1`.
- **Meander max:** 300 RPM.

#### Scan mode byte
- **Encoding:** Single byte in RUN payloads.
  ```
  | uni(7) | corner(6:5) | 0(4) | vert(3) | 0(2) | always_set(1) | 0(0) |
  ```
- **Start corners (2-bit values before shift):** TopLeft(0), TopRight(1), BottomLeft(2), BottomRight(3).

#### Spectral scans
- Absorbance spectrum fully implemented with paginated retrieval.
- Fluorescence spectrum not yet captured.

#### Stuck `running=True` recovery
- **Problem:** If a session is interrupted mid-measurement (kernel restart, USB
  disconnect), the firmware can retain `running=True` across power cycles.
  In this state it ignores drawer and measurement commands.
- **Recovery:** `setup()` detects `running=True` and runs an escalating sequence:
  1. GET_DATA standard (`05 02`, params `00 00 00 00 00`) -- flush buffered data.
  2. GET_DATA progressive (params `ff ff ff ff 00`) -- alternate flush variant.
  3. Re-initialize (`01 00`) -- reset firmware state machine.
  4. USB reset (`ftdi_usb_reset`) -- chip-level reset + full FTDI reconfigure + re-init.
- **Each step** polls status up to 10 times; exits as soon as `running` clears.
- **If all fail:** `RuntimeError` is raised suggesting a longer power cycle or OEM software reset.

---

### Shared Constants

| Name | Value | Used in |
|------|-------|---------|
| `SEPARATOR` | `27 0f 27 0f` | All RUN payloads |
| `TRAILER` | `02 00 00 00 00 00 01 00 00 00 01` | All RUN payloads |
| `_EXTENDED_PADDING` | `00 20 04 00 1e` | All RUN payloads (before separator) |
| `_FRAME_OVERHEAD` | 8 bytes | Frame construction |

---

### Model Lookup

| Type code | Model | Monochromator | Filter slots |
|-----------|-------|---------------|-------------|
| `0x0021` | CLARIOstar Plus | 220-1000 nm | 11 |
| `0x0024` | CLARIOstar Plus | 220-1000 nm | 11 |
| `0x0026` | CLARIOstar Plus | 220-1000 nm | 11 |
| `0x0621` | CLARIOstar Plus | 220-1000 nm | 11 |
| `0x0624` | CLARIOstar Plus | 220-1000 nm | 11 |
| `0x0626` | CLARIOstar Plus | 220-1000 nm | 11 |
| `0x0721` | CLARIOstar Plus | 220-1000 nm | 11 |
| `0x0724` | CLARIOstar Plus | 220-1000 nm | 11 |
| `0x0726` | CLARIOstar Plus | 220-1000 nm | 11 |

---

### Backend Internal Organisation

```
CLARIOstarPlusBackend
├── Constructor
├── Lifecycle (setup, stop)
├── Low-level I/O (_write_frame, _read_frame)
├── Frame utilities (_wrap_payload, _validate_frame, _extract_payload)
├── Command layer (send_command)
├── Status & Polling (request_machine_status, is_ready)
├── Device Info (EEPROM, firmware, detection modes)
├── Lifecycle (initialize, open, close)
├── Temperature Control
├── Measurement - Absorbance (discrete, 1-8 wavelengths)
├── Measurement - Absorbance Spectrum (paginated)
├── Measurement - Fluorescence (mono/filter/multi-chromatic/EDR/flying/matrix)
├── Measurement - Luminescence (stub)
├── Auto-Focus
└── Usage Counters
```

---

### Sources

- **Pcap captures:** 88 USB capture files (59 absorbance + 29 fluorescence), 6,780+ frames total.
- **Go reference implementation:** `fl.go`, `abs.go`, command dispatch.
- **OEM software (MARS):** Automated capture runs for absorbance, fluorescence, luminescence.
- **ActiveX/DDE manual:** Command family documentation.
- **Hardware:** CLARIOstar Plus.
