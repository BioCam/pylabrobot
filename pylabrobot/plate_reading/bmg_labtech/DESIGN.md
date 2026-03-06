# CLARIOstar Plus Backend — Design & Feature Delta

This branch (`clariostar-refactor-with-fluorescence`) rewrote the plate reader backend from scratch. The original `CLARIOstarBackend` was a proof-of-concept with hardcoded byte strings and incomplete protocol support. The new `CLARIOstarPlusBackend` is a production-grade driver built from 88 pcap captures with byte-level verification.

---

## At a Glance

| Capability | CLARIOstar (old) | CLARIOstarPlus (new) |
|---|---|---|
| **Lines of code** | ~350 | ~5,200 (backend) + 6,345 (tests) + 195 (filters) |
| **Test methods** | 0 | 359 |
| **Standalone shaking** | Not supported | `start_shaking()`, `stop_shaking()`, `start_idle_movement()`, `stop_idle_movement()` — hardware-validated via 27+ pcap captures |
| **Wire protocol** | Hardcoded byte arrays, 2-byte checksum | Structured frame builder, 24-bit checksum, validation, retries |
| **Absorbance (discrete)** | Single wavelength | 1-8 wavelengths per run |
| **Absorbance (spectrum)** | Not supported | Full spectrum scans (220-1000 nm, variable step) with paginated retrieval |
| **Fluorescence** | `NotImplementedError` | Full implementation (mono + filter + multi-chromatic + EDR + flying + matrix) |
| **Luminescence** | Basic (hardcoded payload) | Stub (`NotImplementedError`) -- not yet ported |
| **Temperature** | Not supported (`NaN`) | Full control: monitor, set target (0-65 C), measure (top/bottom/mean) |
| **Device identification** | EEPROM only (unparsed) | EEPROM parsed (model, capabilities, mono ranges, filter slots) + firmware version + usage counters |
| **Status polling** | Simple busy/ready byte check | 12-flag bitfield parsing (busy, running, plate_detected, drawer_open, lid_open, etc.) |
| **Error recovery** | None | CMD_0x0E during boot clears stuck running state (matches OEM MARS pcap) |
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
- **DDE finding (2026-03-06)**: DDE `SetTemp`/`TempOff` are NOT valid DDE Execute commands (exit 1000, no USB traffic). Our direct USB 0x06 commands work correctly. OEM MARS likely uses ActiveX properties or embeds temp control in measurement setup sequences.

### 6. Device Identification & Diagnostics
- **Old**: `request_eeprom_data()` -- returned raw bytes, no parsing.
- **New**:
  - `request_eeprom_data()` -> parsed dict: machine_type, model, capabilities (abs/fl/lum/alpha), monochromator ranges, filter slot counts.
  - `request_firmware_info()` -> firmware_version string + build timestamp. Version verified against `CONFIRMED_FIRMWARE_VERSIONS` dict.
  - `request_usage_counters()` -> flashes, testruns, wells, well_movements, active_time, shake_time, pump usage.
  - `request_available_detection_modes()` -> EEPROM-based capability list.

### 7. Status & Error Recovery
- **Old**: Polls 24-byte status, checks one byte for busy/ready.
- **New**: Parses 12 boolean flags from 5-byte status word. Drawer/plate/lid/filter-cover detection. CMD_0x0E sent during normal boot (matches OEM MARS pcap) clears stuck `running=True` state as a side effect — no special recovery logic needed.

### 8. Auto-Focus

Entirely new.  Sends `AUTO_FOCUS_SCAN` (`0x0C`) command, polls until busy
clears, then retrieves the result via `REQUEST/FOCUS_RESULT` (`0x05/0x05`).

#### OEM two-phase process (from Software Manual Part II, 0430F0035B)

The OEM MARS software implements auto-focus as **two distinct phases**:

1. **Search phase (`R_FocusPlate`)** — Measures all wells in the layout at a
   single (default?) height and selects the well with the **highest signal**.
   This is the "auto search" referenced in Section 6.3.1 (p57).

2. **Z-scan phase (`R_FocusWell`)** — Sweeps the selected well through focal
   heights in 0.1 mm steps (range 0–25 mm top optic, 0–9.7 mm bottom optic).
   Finds the height producing the highest signal.  The "Focal Height Curve"
   dialog (Section 6.3.3, p58) shows this as a table of Z (mm) vs F(raw)
   values and a characteristic confocal W-curve plot.

`R_FocusPlate` performs both phases sequentially.  `R_FocusWell` performs
only phase 2 on a user-specified well (column, row).  Both require firmware
≥ V1.30.  An optional `WithWellScan`/`WithoutWellScan` parameter (firmware
≥ V1.31) controls whether the focus measurement uses the protocol's well
scan pattern (matrix/orbital/spiral) or just the well centre.

**Script commands** (Section 9.4.4, p85):
```
R_FocusPlate {Protocol} {Chromatic} {Channel} (Flying) (WithWellScan)
R_FocusWell  {Protocol} {Col} {Row} {Chromatic} (Wavelength) {Channel} (WithWellScan)
```

**ActiveX/DDE retrieval** (ActiveX manual 0430N0003I, Section 2–3):
After `GainWell`/`GainPlate` with focus parameter `"A"`:
- `GainData` → `"1"` when results ready
- `FocalHeight` → optimal height in mm (string)
- `FocusRaw` → raw signal at that height

#### Current implementation

Our `auto_focus()` sends the `0x0C` command with the user's well mask,
polls STATUS_QUERY until busy clears, then requests the result via
`0x05/0x05`.  The firmware returns one of two response formats:

- **Full response (≥27 bytes):** 27-byte header + N×8-byte Z-scan records.
  Observed in pcap F-Q01 (1177 bytes, 143 Z-points) where MARS had a
  continuous POLL (0x08) idle loop running before the scan.  Best focal
  height at payload[17:19].

- **Short response (17 bytes):** Summary only.  Best focal height at
  payload[10:12].  No Z-profile data.  Observed on real hardware when
  sending the `0x0C` command directly (without MARS's POLL streaming).

Both formats return the firmware-determined optimal focal height as u16 BE
in mm×100.  The parser (`_parse_focus_result`) handles both.

#### What we don't yet understand

The well mask affects the result — different masks produce different focal
heights (e.g. all-96-wells → 10.15 mm, A1-only → 7.43 mm), confirming
the firmware uses the mask during the search phase.  However we cannot yet
distinguish at the USB protocol level:

1. Whether `0x0C` always triggers **both** phases (search + Z-scan) or just
   the Z-scan on a firmware-chosen position.
2. How the search phase selects the target well (first in mask? highest
   signal from a quick pre-scan?).
3. What enables the full Z-profile response vs the 17-byte summary (POLL
   streaming state? a separate configuration command? firmware mode?).

#### Planned pcap captures to resolve unknowns

| Capture | OEM operation | Purpose |
|---------|---------------|---------|
| **F-Q02** | `R_FocusWell` on a single specified well | Isolate the Z-scan phase — no search.  Compare `0x0C` payload & response with F-Q01. |
| **F-Q03** | `R_FocusPlate` with sparse well mask (e.g. 3 wells with different signal levels) | Observe the search phase: does the firmware send intermediate data or just the final best-well result? |
| **F-Q04** | `R_FocusWell` with `WithoutWellScan` | Check if well-scan mode affects the USB command or is purely software-side. |

Once we understand the search and Z-scan phases at the protocol level, we
can implement custom algorithms — e.g. binary-search Z-scan, adaptive
well selection, or parallel multi-well focusing — to accelerate the process
beyond what the OEM firmware provides.

#### Manual references

- **Operating Manual CLARIOstar Plus** (0430B0006B), p5: "Automatic focal
  height adjustment (0.1 mm resolution) with curve monitoring"
- **Operating Manual CLARIOstar Plus** (0430B0006B), p20, §6.6: "Automatic
  Height Sensor" — initial plate height monitoring on every PlateIn command
- **Software Manual Part II** (0430F0035B), p57, §6.3.1: Focus combo box
  (auto focus / previous / new)
- **Software Manual Part II** (0430F0035B), p58, §6.3.3: Focus Adjustment
  dialog — Focal Height Curve with W-curve plot and Z/signal table
- **Software Manual Part II** (0430F0035B), p85, §9.4.4: `R_FocusPlate`,
  `R_FocusWell` script commands
- **ActiveX/DDE Manual** (0430N0003I), §2–3: `GainData`, `FocalHeight`,
  `FocusRaw` status items; `GainWell`/`GainPlate` with focus parameter

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
  OEM MARS sends different params: dynamic byte[0] (0x01/0x0D observed),
  byte[2]=0x03, and 5 param bytes. Our 4-byte payload works fine —
  firmware is tolerant of parameter variations.

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

#### Shaker (embedded in RUN payloads)
- **Encoding:** 4 bytes embedded in RUN payloads.
  ```
  [(1 << 4) | shake_type, speed_idx, duration_hi, duration_lo]
  ```
- **Types:** Orbital(0), Linear(1), Double-Orbital(2), Meander(3).
- **Speed:** 100-700 RPM in steps of 100. `speed_idx = rpm/100 - 1`.
- **Meander max:** 300 RPM.

#### `start_shaking` (standalone R_Shake)
- **Group/Cmd:** `0x1D` (no command byte — SHAKE is a single-byte family)
- **Payload:** 11 bytes: `[0x1D] [mode] [speed_idx] [duration:2B BE] [x:2B BE] [y:2B BE] [0x00] [flags]`
- **Modes:** 0x00=orbital, 0x01=linear, 0x02=double_orbital, 0x03=meander.
- **Speed:** `(RPM/100)-1`. Confirmed for 100-700 RPM via pcap.
- **Duration:** u16 BE, seconds (1–3600). Confirmed via pcap: 5, 10, 256, 300, 512, 600, 3600.
- **Position:** 0x270F (9999) = default. Custom positions set flags byte to 0x01.
- **Hardware-validated:** 13 pcap captures (SH-01 through SH-10, VAL-01 through VAL-03, DIS-06/07).

#### `stop_shaking`
- Queries device status. If `running=True`, sends STOP (0x0B 0x00) then polls until `running` clears.
- Poll cadence: 0.25s (matches device communication interval). Timeout: 15s.
- STOP confirmed via pcap (ST-01, ST-04).

#### `start_idle_movement` (R_IdleMove)
- **Group/Cmd:** `0x27` (no command byte — IDLE_MOVE is a single-byte family)
- **Payload:** 11 bytes: `[0x27] [mode] [speed_idx] [0x00] [duration] [off:2B BE] [on:2B BE] [0x00] [0x00]`
- **Modes confirmed via pcap:** 0x01=linear_corner, 0x02=incubation, 0x06=DDE-mode-3.
  Wire bytes 0x03-0x05 never observed. DDE args 4-7 rejected.
- **Speed:** Same `(RPM/100)-1` as R_Shake. Confirmed via pcap.
- **Periodic:** on_time/off_time enable intermittent movement (e.g. 10s on, 5s off).

#### `stop_idle_movement` (R_IdleMove cancel)
- Sends mode=0x00 (cancel) to stop active idle movement.

#### `stop_measurement`
- **Group/Cmd:** `0x0B 0x00`
- **Notes:** Stops any running operation (measurement or standalone shaking).

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
- **Recovery:** CMD_0x0E (`0x0E 0x0B 0x12 ...`) is sent during every `setup()` boot
  sequence (after INIT → EEPROM → firmware info), matching the OEM MARS pcap. This
  command clears the stuck running state as a side effect — no special detection or
  escalating recovery is needed.

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
├── Standalone Shaking (start_shaking, stop_shaking)
├── Idle Movement (start_idle_movement, stop_idle_movement)
└── Usage Counters
```

---

### Sources

- **Pcap captures:** 130+ USB capture files (59 absorbance + 29 fluorescence + 45+ DDE standalone captures), 6,780+ frames total.
- **Go reference implementation:** `fl.go`, `abs.go`, command dispatch.
- **OEM software (MARS):** Automated capture runs for absorbance, fluorescence, luminescence.
- **ActiveX/DDE manual** (0430N0003I): Command family documentation, `GainWell`/`GainPlate` focus parameters, status items.
- **Software Manual Part II** (0430F0035B): Focus/gain adjustment UI (§6.3), `R_FocusPlate`/`R_FocusWell` script commands (§9.4.4), `WithWellScan` option (§6.3.5).
- **Operating Manual CLARIOstar Plus** (0430B0006B): Hardware specs, automatic height sensor (§6.6).
- **Hardware:** CLARIOstar Plus.
