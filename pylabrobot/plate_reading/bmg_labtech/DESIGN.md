# CLARIOstar Plus Backend — Command Catalog & Design

This document catalogs every known CLARIOstar Plus USB command, organized by
implementation phase. Each entry records the wire-level details so future
phases can be implemented without re-analyzing pcap files.

**Protocol overview:** Every command is wrapped in a frame:
```
STX (0x02) | size (2B BE) | header (0x0C) | payload | checksum (3B BE) | CR (0x0D)
```
Checksum = `sum(frame[:-4]) & 0xFFFFFF`. 8-byte overhead total.
Verified against 6,780 pcap frames with zero failures.

---

## Phase 1 — Core Lifecycle (this PR)

### `initialize`
- **Group/Cmd:** `0x01 0x00`
- **Payload:** `01 00 00 10 02 00`
- **Response:** Status frame — poll until `initialized` flag is set.
- **Notes:** Must be the first command after FTDI setup. Takes ~3-5s.

### `open` (drawer out)
- **Group/Cmd:** `0x03 0x01`
- **Payload:** `03 01 00 00 00 00`
- **Response:** Status frame — poll until `drawer_open` flag is set.

### `close` (drawer in)
- **Group/Cmd:** `0x03 0x00`
- **Payload:** `03 00 00 00 00 00`
- **Response:** Status frame — poll until `drawer_open` flag clears.

### `request_machine_status`
- **Group/Cmd:** `0x80` (no command byte — STATUS is a single-byte family)
- **Payload:** `80`
- **Response:** 5+ status bytes. Bit layout:
  - Byte 0, bit 1: `standby`
  - Byte 1, bit 0: `valid` (status response validity)
  - Byte 1, bit 5: `busy`
  - Byte 1, bit 4: `running`
  - Byte 2, bit 0: `unread_data`
  - Byte 3, bit 6: `lid_open` (instrument lid, distinct from drawer)
  - Byte 3, bit 5: `initialized`
  - Byte 3, bit 3: `reading_wells` (optic head actively scanning wells)
  - Byte 3, bit 2: `z_probed` (z-stage probe contact after plate loading)
  - Byte 3, bit 1: `plate_detected`
  - Byte 3, bit 0: `drawer_open`
  - Byte 4, bit 6: `filter_cover_open`

---

## Phase 2 — Device Identification

### `request_eeprom_data`
- **Group/Cmd:** `0x05 0x07`
- **Payload:** `05 07 00 00 00 00 00 00`
- **Response:** 263-byte payload. Key fields:
  - Bytes 2-3: machine type code (uint16 BE). `0x0024`/`0x0026` = CLARIOstar Plus.
  - Byte 11: `has_absorbance` (bool)
  - Byte 12: `has_fluorescence` (bool)
  - Byte 13: `has_luminescence` (bool)
  - Byte 14: `has_alpha_technology` (bool)
  - Bytes 96-107: dense 16-bit values, likely usage counters.
  - Remaining offsets (pump, stacker, serial) not yet confirmed.
- **Use:** Populate `self.configuration` dict. Parsed inline in `request_eeprom_data()`.

### `request_firmware_info`
- **Group/Cmd:** `0x05 0x09`
- **Payload:** `05 09 00 00 00 00 00 00`
- **Response:** 32-byte payload.
  - Bytes 6-7: firmware version x1000 (uint16 BE, e.g. `0x0546` = 1.35).
  - Bytes 8-19: build date, null-terminated ASCII (e.g. `"Nov 20 2020"`).
  - Bytes 20-27: build time, null-terminated ASCII (e.g. `"11:51:21"`).
- **Use:** Log firmware version during `setup()`.

### `request_usage_counters`
- **Group/Cmd:** `0x05 0x21`
- **Payload:** `05 21 00 00 00 00 00 00`
- **Response:** Contains lifetime usage stats (flashes, wells measured, shake time).
- **Status:** Response format not fully decoded.

---

## Phase 3 — Temperature

Temperature commands use standard 3-byte checksum framing (same as all other
command families). The payload is 3 bytes: `[0x06, temp_hi, temp_lo]`.

### `temperature_off`
- **Group/Cmd:** `0x06` (no command byte — TEMPERATURE_CONTROLLER is a no-command family)
- **Payload:** `06 00 00`
- **Response:** Acknowledgment frame.

### `temperature_monitor`
- **Group/Cmd:** `0x06`
- **Payload:** `06 00 01`
- **Notes:** Enables temperature sensor readout without heating.

### `temperature_set`
- **Group/Cmd:** `0x06` (dynamic)
- **Payload:** `06 <target_hi> <target_lo>` — target in 0.1 C units (uint16 BE).
- **Notes:** Target 37.0 C → bytes `01 72` (370 decimal).

---

## Phase 4 — Absorbance

### `run_absorbance`
- **Group/Cmd:** `0x04` (RUN family)
- **Payload structure:**
  ```
  04 <plate_bytes(62)> 82 02 00 00 00 00 00 00 00 20 04 00 1e
  <separator: 27 0f 27 0f>
  19 01 <wavelength(2B)> 00 00 00 64 00 00 00 00 00 00 00 64 00 00
  00 00 00 <trailer: 02 00 00 00 00 01 00 00 00 01> 00 16 00 01 00 00
  ```
- **Key params:**
  - `plate_bytes`: 63B plate geometry (dimensions + well mask).
  - `wavelength`: uint16 BE, value in 0.1 nm (e.g. 450nm → `0x1194`).
  - `0x82`: measurement type marker for absorbance.
  - `0x19`: settling time encoding.
- **Scan modes:** Point, orbital, spiral. Encoded in optic config byte.
  - Point: `0x02`, Orbital: `0x32`, Spiral: `0x06`.
- **Well scan block** (after separator, before settling): 5 bytes for non-point modes.
  `[meas_code(0x02), width_mm, well_dia_hi, well_dia_lo, 0x00]`

### `get_data`
- **Group/Cmd:** `0x05 0x02`
- **Payload:** `05 02 00 00 00 00 00 00`
- **Response:** Variable-length. Contains:
  - Chromatic readings: N x int32 BE
  - Reference readings: N x int32 BE
  - Calibration: c100, c0, r100, r0 (4 x int32 BE)
- **Data extraction:** Find 6-byte zero divider, data starts after it.

### `focus_height`
- **Group/Cmd:** `0x05 0x0F`
- **Payload:** `05 0f 00 00 00 00 00 00`
- **Response:** Microplate and focus height values.

### `read_order`
- **Group/Cmd:** `0x05 0x1D`
- **Payload:** `05 1d 00 00 00 00 00 00`
- **Response:** Well measurement order for the last run.

### `plate_bytes` encoding (63 bytes)
```
plate_length(2B) plate_width(2B) x1(2B) y1(2B) xn(2B) yn(2B)
cols(1B) rows(1B) extra(1B=0x00) well_mask(48B)
```
All dimensions in 0.01mm units (uint16 BE). Well mask is 384-bit big-endian.

---

## Phase 5 — Fluorescence

### `run_fluorescence`
- **Group/Cmd:** `0x04` (RUN family)
- **Key differences from absorbance:**
  - Measurement type marker: `0x02` (vs `0x82` for absorbance).
  - Requires: excitation wavelength, emission wavelength, bandwidth, gain, dichroic mirror.
  - Well scan measurement code: `0x03` (vs `0x02`).
- **Params (known):**
  - Excitation wavelength: uint16 BE, 0.1 nm units.
  - Emission wavelength: uint16 BE, 0.1 nm units.
  - Bandwidth: excitation and emission, encoding TBD.
  - Gain: value and auto-gain flag.
  - Dichroic mirror position.
- **Status:** Payload structure partially decoded from Go reference and pcap.

---

## Phase 6 — Luminescence

### `run_luminescence`
- **Group/Cmd:** `0x04` (RUN family)
- **Payload structure:**
  ```
  04 <plate_bytes(62)> 02 01 00 00 00 00 00 00 00 20 04 00 1e
  <separator: 27 0f 27 0f>
  01 <focal_height(2B)> 00 00 01 00 00 0e 10 00 01 00 01 00
  01 00 01 00 01 00 06 00 00 00 00 00 00 00 00 00
  <trailer: 02 00 00 00 00 01 00 00 00 01> 00 64 00 20 00 00
  ```
- **Key params:**
  - `focal_height`: uint16 BE, 0.01 mm units. Range 0-25mm.
  - `0x02 0x01`: measurement type marker for luminescence.
- **Data format:** Same as absorbance — N x int32 BE values after zero divider.

---

## Phase 7 — Advanced

### `hardware_status`
- **Group/Cmd:** `0x81 0x00`
- **Payload:** `81 00`
- **Response:** Hardware-level status. Format not fully decoded.

### `progressive_polling`
- **Group/Cmd:** `0x08 0x00`
- **Payload:** `08 00`
- **Notes:** Used during long measurement runs to get intermediate data.
  Progressive `get_data` variant uses `FF FF FF FF` at payload bytes 2-5.

### Shaker
- **Encoding:** 4 bytes embedded in RUN payloads.
  ```
  [(1 << 4) | shake_type, speed_idx, duration_hi, duration_lo]
  ```
- **Types:** Orbital(0), Linear(1), Double-Orbital(2), Meander(3).
- **Speed:** 100-800 RPM in steps of 100. `speed_idx = rpm/100 - 1`.
- **Meander max:** 300 RPM.

### Scan mode byte
- **Encoding:** Single byte in RUN payloads.
  ```
  | uni(7) | corner(6:5) | 0(4) | vert(3) | 0(2) | always_set(1) | 0(0) |
  ```
- **Start corners (2-bit values before shift):** TopLeft(0), TopRight(1), BottomLeft(2), BottomRight(3).

### Spectral scans
- **Status:** Not yet captured. Likely uses monochromator sweep with repeated
  RUN commands at different wavelengths.

---

## Shared Constants

| Name | Value | Used in |
|------|-------|---------|
| `SEPARATOR` | `27 0f 27 0f` | All RUN payloads |
| `TRAILER` | `02 00 00 00 00 00 01 00 00 00 01` | All RUN payloads |
| `_EXTENDED_PADDING` | `00 20 04 00 1e` | All RUN payloads (before separator) |
| `_FRAME_OVERHEAD` | 8 bytes | Frame construction |

---

## Model Lookup

| Type code | Model | Monochromator | Filter slots |
|-----------|-------|---------------|-------------|
| `0x0024` | CLARIOstar Plus | 220-1000 nm | 11 |
| `0x0026` | CLARIOstar Plus | 220-1000 nm | 11 |

---

## Backend Internal Organisation

```
CLARIOstarPlusBackend
├── Constructor
├── Lifecycle (setup, stop)
├── Low-level I/O
├── Command layer (send_command)
├── Status & Polling
├── Device Info (EEPROM, firmware, detection modes)
├── Lifecycle (initialize, open, close)
├── Measurement - Absorbance
├── Measurement - Spectral Absorbance Scan
├── Measurement - Fluorescence
├── Measurement - Luminescence
└── Usage Counters
```

---

## Sources

- **Pcap captures:** 16 USB capture files, 6,780 frames total.
- **Go reference implementation:** `fl.go`, `abs.go`, command dispatch.
- **OEM software (MARS):** Automated capture runs for absorbance, fluorescence, luminescence.
- **ActiveX/DDE manual:** Command family documentation.
- **Hardware:** CLARIOstar Plus.
