# CLARIOstar Plus Wire Protocol Reference

Complete binary protocol specification for the BMG Labtech CLARIOstar Plus plate reader,
derived from byte-level analysis of 40 OEM MARS pcap captures and Go reference implementation.

---

## 1. Frame Envelope

Every frame on the 125 kBaud 8N1 FTDI USB-serial link uses this envelope:

```
 02   SS SS   0C   [payload...]   CC CC CC   0D
 ──   ─────   ──   ────────────   ────────   ──
 STX  size    hdr  inner data     checksum   CR
```

| Field | Bytes | Encoding | Notes |
|-------|-------|----------|-------|
| STX | 1 | `0x02` | Start of frame |
| Size | 2 | u16 BE | Total frame length (STX through CR inclusive) |
| Header | 1 | `0x0C` | Protocol identifier, constant |
| Payload | n | command-specific | See sections below |
| Checksum | 3 | u24 BE | Sum of all bytes from STX through end of payload |
| CR | 1 | `0x0D` | End of frame |

---

## 2. Command Families

The first byte of the payload selects the command family. Some families have a
sub-command byte (payload byte 1), others do not.

### With sub-command byte: `[family, command, ...params]`

| Family | Value | Sub-commands | Direction |
|--------|-------|-------------|-----------|
| INITIALIZE | `0x01` | `0x00` = INIT | Host → Device |
| TRAY | `0x03` | `0x00` = CLOSE, `0x01` = OPEN | Host → Device |
| REQUEST | `0x05` | `0x02` = DATA, `0x07` = EEPROM, `0x09` = FW_INFO, `0x0F` = FOCUS_HEIGHT, `0x1D` = READ_ORDER, `0x21` = USAGE_COUNTERS | Host → Device |
| POLL | `0x08` | `0x00` = keepalive | Host → Device |

### Without sub-command byte: `[family, ...params]`

| Family | Value | Notes | Direction |
|--------|-------|-------|-----------|
| RUN | `0x04` | Measurement command. Payload is plate geometry + measurement config | Host → Device |
| TEMPERATURE_CONTROLLER | `0x06` | Temperature monitoring / heating control | Host → Device |
| STATUS | `0x80` | Status query (no params) | Host → Device |
| HW_STATUS | `0x81` | Hardware telemetry query (no params) | Host → Device |

### Device Responses

| Echo byte | Label | Typical size | Trigger |
|-----------|-------|-------------|---------|
| `0x01` | STATUS / INITIALIZE | 24 B | Response to POLL, STATUS, INITIALIZE |
| `0x02` | DATA_RESPONSE | 92–52836 B | Response to REQUEST/DATA |
| `0x03` | ACCEPTED | 53 B | Acknowledgement of RUN command |
| `0x09` | HW_STATUS | 114 B | Response to HW_STATUS query |
| `0x17` | PRE_MEAS_INFO | 32 B | Response to REQUEST/FOCUS_HEIGHT |
| `0x1D` | READ_ORDER_MAP | 46–222 B | Response to REQUEST/READ_ORDER |

---

## 3. RUN Command (0x04) — Measurement Payload

The RUN command starts all measurement types (absorbance, fluorescence, luminescence).
The payload following the `0x04` family byte has this structure:

```
[0x04] [plate_field 63B] [scan_dir 1B] [pre_sep 31B] [separator 4B] [well_scan 0|5B] [meas_params ...]
 ────   ──────────────    ──────────    ───────────    ──────────     ──────────────    ─────────────
 cmd    §3.1              §3.2         §3.3           §3.4          §3.5              §3.6+
```

### 3.1 Plate Field (63 bytes)

Encodes plate geometry and well selection mask.

```
Offset  Size  Encoding   Field
──────  ────  ────────   ─────
 0       2    u16 BE     plate_length (mm × 100)       e.g. 127.76mm → 0x31E8
 2       2    u16 BE     plate_width  (mm × 100)       e.g. 85.48mm  → 0x2164
 4       2    u16 BE     A1_center_x  (mm × 100)       top-left origin
 6       2    u16 BE     A1_center_y  (mm × 100)       Y inverted: plate_width - abs_y
 8       2    u16 BE     last_well_x  (mm × 100)       plate_length - A1_x
10       2    u16 BE     last_well_y  (mm × 100)       plate_width  - A1_y
12       1    u8         num_cols                       e.g. 12
13       1    u8         num_rows                       e.g. 8
14       1    u8         always 0x00                    purpose unknown, constant across all 40 captures
15      48    384 bits   well_mask                      row-major, MSB-first per byte
```

**Well mask encoding**: Bit index = `row × num_cols + col`. Byte = `idx // 8`, bit = `7 - (idx % 8)`.

Well mask examples (96-well plate):
```
All 96:    ff ff ff ff ff ff ff ff ff ff ff ff 00×36
Column 1:  80 08 00 80 08 00 80 08 00 80 08 00 00×36
Well A1:   80 00×47
Half (1-6): fc 0f c0 fc 0f c0 fc 0f c0 fc 0f c0 00×36
```

### 3.2 Scan Direction Byte (1 byte)

```
Bit 7:   unidirectional (1) / bidirectional serpentine (0)
Bit 6-4: start corner (0=TL, 1=TR, 2=BL, 3=BR)
Bit 3:   vertical (1) / horizontal (0)
Bit 2:   flying mode (not valid for absorbance)
Bit 1:   always set (purpose unknown)
Bit 0:   unused
```

| Value | Meaning | Captures |
|-------|---------|----------|
| `0x8A` | uni, TL, vertical | A01–A07, C04 |
| `0x0A` | bidi, TL, vertical | A08, B-series, D-series, E-series, F-series, G-series, H-series, I-series |
| `0x2A` | bidi, TR, vertical | C01 |
| `0x4A` | bidi, BL, vertical | C02 |
| `0x6A` | bidi, BR, vertical | C03 |
| `0x02` | bidi, TL, horizontal | C05 |

### 3.3 Pre-Separator Block (31 bytes)

Contains the optic configuration byte and shake parameters.

```
Offset  Field
──────  ─────
 0      optic_config = Modality | WellScanMode | OpticPosition  (see §4)
 1-11   zeros (11 bytes)
12      mixer_action: 0x02 when shaking, 0x00 otherwise
13-16   zeros (4 bytes)
17      shake_pattern: 0=orbital, 1=linear, 2=double_orbital
18      shake_speed_index: (RPM / 100) - 1       e.g. 300rpm → 2
19      zero
20-21   shake_duration (u16 LE, seconds)
22-30   zeros (9 bytes)
```

Shake examples from captures:
| Capture | Pattern | Speed | Duration | Bytes [12,17,18,20:22] |
|---------|---------|-------|----------|----------------------|
| F01 | orbital | 300 rpm | 5s | `02, 00, 02, 05 00` |
| F02 | orbital | 500 rpm | 5s | `02, 00, 04, 05 00` |
| F03 | orbital | 300 rpm | 10s | `02, 00, 02, 0a 00` |
| F04 | double_orbital | 300 rpm | 5s | `02, 02, 02, 05 00` |
| F05 | linear | 300 rpm | 5s | `02, 01, 02, 05 00` |

### 3.4 Separator (4 bytes)

Always `27 0f 27 0f`. Fixed magic marker present in every measurement command.

### 3.5 Well Scan Field (0 or 5 bytes)

Only present for non-point scan modes (orbital, spiral).

```
Offset  Field
──────  ─────
 0      modality byte (same as Modality enum: 0x02=abs, 0x00=fl)
 1      scan_diameter (integer mm)
 2-3    well_diameter (mm × 100, u16 BE)       e.g. 6.58mm → 0x0292
 4      always 0x00
```

Examples:
| Scan | Bytes | Meaning |
|------|-------|---------|
| Point | (absent) | — |
| Orbital 3mm | `02 03 02 92 00` | abs, 3mm scan, 6.58mm well |
| Spiral 4mm | `02 04 02 92 00` | abs, 4mm scan, 6.58mm well |

### 3.6 Measurement Parameters

The structure after the well scan field depends on whether this is a
**discrete** or **spectral** measurement.

#### 3.6.1 Discrete Wavelengths (num_wavelengths ≥ 1)

```
Offset  Size  Encoding   Field
──────  ────  ────────   ─────
 0       1    u8         pause_time                    0x05 = 1.0 decisecond, 0x01 = 0
 1       1    u8         num_wavelengths               1–8 (0 = spectral mode, see §3.6.2)
 2      2×N   u16 BE     wavelength[0..N-1]           nm × 10, e.g. 600nm → 0x1770
+0      13    raw        reference_block              constant: 00 00 00 64 23 28 26 ca 00 00 00 64 00
+0       1    u8         settling_flag                0x00=off, 0x01=on
+1       2    u16 BE     settling_time                seconds (0–10)
+0      11    raw        trailer                      constant: 02 00 00 00 00 00 01 00 00 00 01
+0       2    u16 BE     flashes                      flashes per well (1–200)
+0       3    raw        final                        00 01 00
```

Wavelength examples:
| Capture | num_wl | Wavelength bytes | Decoded |
|---------|--------|-----------------|---------|
| A01 | `01` | `17 70` | 600 nm |
| D01 | `01` | `11 94` | 450 nm |
| D02 | `02` | `11 94 17 70` | 450 nm, 600 nm |
| D03 | `03` | `11 94 17 70 19 c8` | 450 nm, 600 nm, 660 nm |

Total inner payload sizes (discrete absorbance):
| Config | Calculation | Inner bytes | Frame bytes |
|--------|------------|-------------|-------------|
| Point, 1 wl | 1+63+1+31+4+0+1+1+2+13+3+11+2+3 | 136 | 144 |
| Point, 2 wl | +2 | 138 | 146 |
| Point, 3 wl | +4 | 140 | 148 |
| Orbital, 1 wl | +5 (well scan field) | 141 | 149 |

#### 3.6.2 Spectral Scan (num_wavelengths = 0)

When `num_wavelengths` is `0x00`, the firmware interprets the following bytes as a
spectral range instead of discrete wavelengths:

```
Offset  Size  Encoding   Field
──────  ────  ────────   ─────
 0       1    u8         pause_time
 1       1    u8         0x00 = spectral mode flag
 2       2    u16 BE     scan_start (nm × 10)         e.g. 300nm → 0x0BB8
 4       2    u16 BE     scan_end   (nm × 10)         e.g. 700nm → 0x1B58
 6       2    u16 BE     scan_step  (nm × 10)         e.g. 1nm → 0x000A, 5nm → 0x0032
 ...     (remainder same as discrete: reference_block, settling, trailer, flashes, final)
```

Spectral examples:
| Capture | Start | End | Step | Wavelength bytes |
|---------|-------|-----|------|-----------------|
| H01 | 300 nm | 700 nm | 1 nm | `00 0b b8 1b 58 00 0a` |
| H02 | 400 nm | 600 nm | 1 nm | `00 0f a0 17 70 00 0a` |
| H03 | 300 nm | 700 nm | 5 nm | `00 0b b8 1b 58 00 32` |

Total inner payload for spectral: same as discrete with 3 wavelengths = 136 bytes (point)
because `0 + 6 spectral bytes` occupies the same space as `1 + 1×2 discrete bytes` + 3 extra.
Verified: H01 frame = 144 bytes = 136 inner.

---

## 4. Optic Configuration Byte

The optic byte at pre-separator offset 0 is a bitfield composed by OR'ing three enums:

### Modality (measurement type)

| Name | Value | Bits | Notes |
|------|-------|------|-------|
| `FLUORESCENCE` | `0x00` | `0000 0000` | No modality bits set |
| `ABSORBANCE` | `0x02` | `0000 0010` | Bit 1 |
| `LUMINESCENCE` | TBD | TBD | No captures available yet |

### WellScanMode (scan pattern)

| Name | Value | Bits | Notes |
|------|-------|------|-------|
| `POINT` | `0x00` | `0000 0000` | Single measurement at well center |
| `SPIRAL` | `0x04` | `0000 0100` | Bit 2 |
| `ORBITAL` | `0x30` | `0011 0000` | Bits 4+5 |

### OpticPosition (fluorescence only)

| Name | Value | Bits | Notes |
|------|-------|------|-------|
| `TOP` | `0x00` | `0000 0000` | Top optic (default) |
| `BOTTOM` | `0x40` | `0100 0000` | Bit 6, fluorescence only |

### Composite values observed in captures

| Optic byte | Binary | Composition | Captures |
|-----------|--------|-------------|----------|
| `0x02` | `0000 0010` | ABSORBANCE \| POINT | A01–A08, C01–C05, D01–D03, E01–E02, H01–H04, I01 |
| `0x06` | `0000 0110` | ABSORBANCE \| SPIRAL | B01–B02 |
| `0x32` | `0011 0010` | ABSORBANCE \| ORBITAL | A02,A04,A06,A08, B03–B04, D04, F01–F06, G01–G02, H05, I02 |
| `0x00` | `0000 0000` | FLUORESCENCE \| POINT \| TOP | (from Go fl.go) |
| `0x30` | `0011 0000` | FLUORESCENCE \| ORBITAL \| TOP | (from Go fl.go) |
| `0x40` | `0100 0000` | FLUORESCENCE \| POINT \| BOTTOM | (from Go fl.go) |

The modality does NOT change between discrete and spectral measurements —
both use `ABSORBANCE` (`0x02`). The discrete-vs-spectral distinction is encoded
in the wavelength section (`num_wavelengths = 0` signals spectral mode).

---

## 5. Data Response Parsing

### 5.1 Response Header (36 bytes of inner payload)

```
Offset  Size  Encoding   Field
──────  ────  ────────   ─────
 0       1    u8         sub-command echo (0x02 = DATA)
 1       1    u8         command family echo (0x05 = REQUEST)
 6       1    u8         schema: 0x29 = absorbance, 0xA9 = absorbance + incubation active
 7       2    u16 BE     total_values (wells × wavelengths × reads_per_well)
 9       2    u16 BE     complete_count (increments during measurement)
18       2    u16 BE     wavelengths_in_response
20       2    u16 BE     wells_measured
23       2    u16 BE     temperature (÷10.0 → °C) when schema=0x29
34       2    u16 BE     temperature when schema=0xA9
```

Schema determines temperature field location:
- `0x29`: standard absorbance → temperature at offset 23
- `0xA9`: absorbance with active incubation → temperature at offset 34

### 5.2 Data Section (starting at offset 36)

Four data groups followed by calibration pairs:

```
Group 0:  wells × wavelengths    u32 BE values    sample detector readings
Group 1:  wells                  u32 BE values    chromatic channel 2
Group 2:  wells                  u32 BE values    chromatic channel 3
Group 3:  wells                  u32 BE values    reference detector readings
Calibration:  4 pairs × 8 bytes = 32 bytes        (hi, lo) u32 BE per channel
```

All well values are in **row-major** order (A1, A2, ..., A12, B1, B2, ..., H12).

### 5.3 OD Computation

Verified against OEM MARS software within ±0.001 OD:

```
calibration_pairs = [(c1_hi, c1_lo), (c2_hi, c2_lo), (c3_hi, c3_lo), (ref_hi, ref_lo)]

T = (sample / c1_hi) × (ref_hi / reference_well)
OD = -log10(T)      if T > 0
OD = +inf            if T ≤ 0
```

Where:
- `sample` = Group 0 value for the well
- `c1_hi` = calibration pair 0, high value
- `ref_hi` = calibration pair 3, high value
- `reference_well` = Group 3 value for the well

---

## 6. Measurement Sequence

```
Host                                          CLARIOstar Plus
 |                                                |
 |  -- POLL (0x08/0x00) ---------------------->   |
 |  <-- STATUS (0x01) -------------------------   |   IDLE
 |      ... repeated until ready ...              |
 |                                                |
 |  -- RUN (0x04, full payload) -------------->   |
 |  <-- ACCEPTED (0x03, 53 bytes) -------------   |   RUNNING
 |                                                |
 |  -- STATUS (0x80) ------------------------->   |
 |  <-- STATUS (0x01, busy=1) -----------------   |   RUNNING
 |      ... poll until busy=0 ...                 |
 |                                                |
 |  -- REQUEST/DATA (0x05/0x02) -------------->   |
 |  <-- DATA_RESPONSE (0x02, full results) ----   |   IDLE
 |                                                |
```

### Timing by configuration

| Config | Wells | Est. time |
|--------|-------|-----------|
| Point, 96 wells | 96 | ~48 s |
| Orbital, 96 wells | 96 | ~80 s |
| Spiral, 96 wells | 96 | ~140 s |
| Point, 8 wells (1 col) | 8 | ~10 s |
| Point, 1 well | 1 | ~8 s |

---

## 7. Other Commands

### 7.1 INITIALIZE (0x01/0x00)

```
02 00 0a 0c 01 00 00 00 19 0d
```

Triggers hardware initialization. Device responds with STATUS frame.
Use `wait=True` to poll until initialization completes.

### 7.2 TRAY (0x03)

```
Close:  02 00 0a 0c 03 00 00 00 19 0d
Open:   02 00 0a 0c 03 01 00 00 1a 0d
```

### 7.3 STATUS (0x80)

```
02 00 09 0c 80 00 00 97 0d
```

9 bytes, no parameters. Response is 24-byte STATUS frame with flags:

| Flag | Byte | Mask | Meaning |
|------|------|------|---------|
| standby | 0 | `0x02` | Device in standby |
| busy | 1 | `0x20` | Operation in progress |
| running | 1 | `0x10` | Measurement running |
| unread_data | 2 | `0x01` | Data available for retrieval |
| initialized | 3 | `0x20` | Hardware initialized |
| drawer_open | 3 | `0x01` | Drawer is open |
| plate_detected | 3 | `0x02` | Plate sensor triggered |

### 7.4 TEMPERATURE_CONTROLLER (0x06)

Single-byte command family (no sub-command). Used for:
- Start/stop temperature monitoring (sensor readout)
- Start/stop heating to target temperature
- Query current temperature

### 7.5 REQUEST/DATA (0x05/0x02)

```
Final:       02 00 0f 0c 05 02 00 00 00 00 00 00 00 24 0d
Progressive: 02 00 0f 0c 05 02 ff ff ff ff 00 00 04 20 0d
```

Bytes 6–9: `00 00 00 00` = final (authoritative), `ff ff ff ff` = progressive (mid-run).

### 7.6 HW_STATUS (0x81)

```
02 00 09 0c 81 00 00 98 0d
```

Returns 114-byte hardware telemetry (temperatures, lamp hours, voltages).

---

## 8. Constant Blocks

These byte sequences are invariant across all 40 captures:

| Name | Hex | Size | Location |
|------|-----|------|----------|
| Separator | `27 0f 27 0f` | 4 B | Between pre-separator block and well scan field |
| Reference block | `00 00 00 64 23 28 26 ca 00 00 00 64 00` | 13 B | After wavelength data |
| Trailer | `02 00 00 00 00 00 01 00 00 00 01` | 11 B | After settling time |
| Final | `00 01 00` | 3 B | Last 3 bytes of payload |

---

## 9. Capture Index

40 captures organized by test group:

| Group | Captures | Purpose |
|-------|----------|---------|
| A (8) | A01–A08 | Baseline: well counts (96, 8, 1, 48) × scan modes (point, orbital) |
| B (4) | B01–B04 | Scan variations: spiral 4mm/3mm, orbital 5mm, orbital 5-flash |
| C (5) | C01–C05 | Scan direction: TR, BL, BR, unidirectional, horizontal |
| D (4) | D01–D04 | Wavelengths: 450nm, dual 450+600, triple 450+600+660, dual orbital |
| E (2) | E01–E02 | Flash counts: 1 flash, 20 flashes |
| F (6) | F01–F06 | Shaking: orbital/linear/double_orbital, speeds, durations |
| G (2) | G01–G02 | Settling time: 0.5s, 1.0s |
| H (5) | H01–H05 | Spectral scans: range/step variations, partial wells, orbital |
| I (2) | I01–I02 | Temperature: measurement at 29°C (point + orbital) |
| J (1) | J01 | Boot / drawer in+out sequence |
| K (1) | K01 | Temperature control only (monitor, heat to 30°C, off) |

---

## 10. PLR vs OEM Plate Geometry

PyLabRobot (`Cor_96_wellplate_360ul_Fb`) and OEM MARS use slightly different
plate definitions. The firmware is tolerant of these differences.

| Dimension | PLR | OEM | Diff |
|-----------|-----|-----|------|
| A1 center X | 14.30 mm | 14.38 mm | 0.08 mm |
| A1 center Y | 11.28 mm | 11.24 mm | 0.04 mm |
| Well diameter | 6.86 mm | 6.58 mm | 0.28 mm |
| Plate size | 127.76 × 85.48 mm | 127.76 × 85.48 mm | identical |
| Well spacing | 9.0 × 9.0 mm | 9.0 × 9.0 mm | identical |

The well diameter is only transmitted in non-point scan modes (orbital/spiral)
as part of the well scan field (§3.5).
