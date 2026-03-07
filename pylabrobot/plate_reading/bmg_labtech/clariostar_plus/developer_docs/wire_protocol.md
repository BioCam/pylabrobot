# CLARIOstar Plus Wire Protocol Reference

Complete binary protocol specification for the BMG Labtech CLARIOstar Plus plate reader,
derived from byte-level analysis of 40 OEM OEM software capture captures and Go reference implementation.

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
| FOCUS_WELL | `0x09` | Focus / Z-height probe | Host → Device |
| STOP | `0x0B` | Stop running operation (measurement, shaking) | Host → Device |
| AUTO_FOCUS | `0x0C` | Auto-focus Z-scan | Host → Device |
| PAUSE_RESUME | `0x0D` | Pause / resume running operation | Host → Device |
| CMD_0x0E | `0x0E` | Boot sequence command; clears stuck running state | Host → Device |
| SHAKE | `0x1D` | Standalone plate shaking (R_Shake) | Host → Device |
| FILTER_SCAN | `0x24` | Filter position scan | Host → Device |
| IDLE_MOVE | `0x27` | Continuous/periodic plate movement (R_IdleMove) | Host → Device |
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
 0      optic_config = DetectionMode | WellScanMode | OpticPosition  (see §4)
 1-11   zeros (11 bytes)
12      mixer_action: 0x02 when shaking, 0x00 otherwise
13-16   zeros (4 bytes)
17      shake_pattern: 0=orbital, 1=linear, 2=double_orbital, 3=meander
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
 0      detection mode byte (same as DetectionMode enum: 0x02=abs, 0x00=fl)
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

### DetectionMode

| Name | Value | Bits | Notes |
|------|-------|------|-------|
| `FLUORESCENCE` | `0x00` | `0000 0000` | No detection mode bits set |
| `LUMINESCENCE` | `0x01` | `0000 0001` | Bit 0 (from Go reference) |
| `ABSORBANCE` | `0x02` | `0000 0010` | Bit 1 |

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

The detection mode does NOT change between discrete and spectral measurements —
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

Verified against OEM OEM software software within ±0.001 OD:

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

**OEM OEM software vs our implementation:**
- OEM software sends dynamic byte[0] (values 0x01, 0x0D observed across boots) and byte[2]=0x03
  with 5 parameter bytes. Our implementation uses fixed `\x00\x10\x02\x00` (4 bytes).
  Both work — the firmware appears tolerant of parameter variations. The meaning of
  OEM software's dynamic byte[0] is unknown (possibly session/sequence counter).

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

**DDE vs direct USB:** The DDE commands `SetTemp` and `TempOff` are NOT valid DDE
Execute commands — they return exit code 1000 and produce NO USB traffic. Temperature
control works correctly via direct USB (0x06 payloads). OEM OEM software likely exposes
temperature via ActiveX properties or embeds it in measurement setup sequences rather
than using standalone DDE Execute calls.

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

### 7.7 STOP (0x0B)

Single-byte family (no sub-command). Stops the currently running operation (measurement
or standalone shaking).

```
02 00 0a 0c 0b 00 00 00 1d 0d
```

Payload: `0b 00` — param `0x00` = StopTest Nosave. The `running` flag clears within
~5 seconds after STOP is sent.

**Capture verification:** Confirmed in ST-01 and ST-04 captures. STOP reliably terminates
standalone shaking started by R_Shake (0x1D).

### 7.8 SHAKE (0x1D) — Standalone Plate Shaking

Single-byte family, 11-byte payload (10 param bytes). Starts plate shaking
independently of any measurement.

```
[0x1D] [mode] [speed_idx] [duration:2B BE] [x_pos:2B BE] [y_pos:2B BE] [0x00] [flags]
```

| Byte | Field | Encoding |
|------|-------|----------|
| 0 | mode | 0x00=orbital, 0x01=linear, 0x02=double_orbital, 0x03=meander |
| 1 | speed_idx | `(RPM / 100) - 1` e.g. 300 RPM → 0x02 |
| 2–3 | duration | u16 BE, seconds (1–3600) |
| 4–5 | x_position | u16 BE (250–3100, or 0x270F for default) |
| 6–7 | y_position | u16 BE (125–800, or 0x270F for default) |
| 8 | reserved | always 0x00 |
| 9 | flags | 0x01 when custom x_position specified, 0x00 otherwise |

**Hardware-verified ground truth (13 captures):**

| Capture | Settings | Wire bytes (payload) |
|---------|----------|---------------------|
| SH-01 | orbital 300rpm 5s default | `1d 00 02 00 05 27 0f 27 0f 00 00` |
| SH-02 | orbital 300rpm 5s x=500 | `1d 00 02 00 05 01 f4 27 0f 00 01` |
| SH-03 | orbital 500rpm 5s default | `1d 00 04 00 05 27 0f 27 0f 00 00` |
| SH-04 | orbital 700rpm 5s default | `1d 00 06 00 05 27 0f 27 0f 00 00` |
| SH-05 | orbital 300rpm 10s default | `1d 00 02 00 0a 27 0f 27 0f 00 00` |
| SH-07 | linear 300rpm 5s default | `1d 01 02 00 05 27 0f 27 0f 00 00` |
| SH-10 | double_orbital 300rpm 5s | `1d 02 02 00 05 27 0f 27 0f 00 00` |
| VAL-01 | orbital 300rpm 300s | `1d 00 02 01 2c 27 0f 27 0f 00 00` |
| VAL-02 | orbital 300rpm 600s | `1d 00 02 02 58 27 0f 27 0f 00 01` |
| VAL-03 | orbital 300rpm 3600s | `1d 00 02 0e 10 27 0f 27 0f 00 00` |
| VAL-06 | orbital 100rpm 5s | `1d 00 00 00 05 27 0f 27 0f 00 00` |
| VAL-07 | orbital 200rpm 5s | `1d 00 01 00 05 27 0f 27 0f 00 00` |
| DIS-06 | orbital 300rpm 256s | `1d 00 02 01 00 27 0f 27 0f 00 00` |

**Key confirmations:**
- Duration encoding: u16 BE (confirmed across 5, 10, 256, 300, 512, 600, 3600 seconds)
- Speed encoding: `(RPM / 100) - 1` (confirmed for 100, 200, 300, 500, 700 RPM)
- Default position: 0x270F (9999) for both X and Y
- Flags byte: 0x01 when custom X position is set

**Boundaries (from validation captures):**
- Duration = 0: DDE rejects (exit 1000)
- Speed = 800 RPM: DDE rejects
- Meander at 400 RPM: DDE rejects

### 7.9 IDLE_MOVE (0x27) — Continuous/Periodic Plate Movement

Single-byte family, 11-byte payload (10 param bytes). Designed for keeping
samples mixed during incubation. Runs in the background.

```
[0x27] [mode] [speed_idx] [0x00] [duration] [off_time:2B BE] [on_time:2B BE] [0x00] [0x00]
```

| Byte | Field | Encoding |
|------|-------|----------|
| 0 | mode | 0x00=cancel, 0x01=linear_corner, 0x02=incubation, 0x06=DDE-mode-3 (see notes) |
| 1 | speed_idx | `(RPM / 100) - 1` for modes that support speed, else 0x00 |
| 2 | reserved | 0x00 |
| 3 | duration | seconds (encoding may be u8 or u16 — needs more capture data) |
| 4–5 | off_time | u16 BE, seconds between movement cycles (0 = permanent) |
| 6–7 | on_time | u16 BE, seconds per movement cycle (0 = permanent) |
| 8–9 | reserved | 0x00 0x00 |

**Mode mapping — DDE arg to wire byte:**

| DDE arg | Wire byte | Name (our label) | Status |
|---------|-----------|-------------------|--------|
| 0 | 0x00 | cancel | Confirmed (capture) |
| 1 | 0x01 | linear_corner | Confirmed (capture IM-01) |
| 2 | 0x02 | incubation | Confirmed (capture IM-02) |
| 3 | 0x06 | unknown (possibly double_orbital) | Confirmed (capture VAL captures) |
| 4–7 | — | — | DDE rejects (invalid mode) |

**Important:** Wire bytes 0x03, 0x04, 0x05 have **never been observed** on the wire.
Our original assumption of sequential mapping (0x03=meander_corner, 0x04=orbital_corner,
0x05=orbital, 0x06=double_orbital) was **incorrect**. Only 0x01, 0x02, and 0x06 are
confirmed via capture captures.

**Hardware-verified ground truth:**

| Capture | Settings | Wire bytes (payload) |
|---------|----------|---------------------|
| IM-01 | linear_corner 60s on=10 off=5 | `27 01 00 00 3c 00 05 00 0a 00 00` |
| IM-02 | incubation 60s on=10 off=5 | `27 02 00 00 3c 00 05 00 0a 00 00` |
| IM-04 | orbital 300rpm 60s on=10 off=5 | `27 05 02 00 3c 00 05 00 0a 00 00` |
| IM-06 | linear_corner 60s on=10 off=5 | `27 01 00 00 3c 00 05 00 0a 00 00` |

### 7.10 CMD_0x0E — Boot Sequence Command

Sent by OEM OEM software during normal boot (after INITIALIZE → EEPROM read) in every
capture capture observed — both normal startup and stuck-state recovery. Clears the
stuck `running=True` state as a side effect.

```
02 00 12 0c 0e 0b 12 00 00 00 01 04 96 00 00 00 00 57 0d
```

Payload: `0e 0b 12 00 00 00 01 04 96 00 00 00 00`. Purpose beyond recovery is
not fully understood.

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

88+ captures organized by test group:

### OEM Measurement Captures (40)

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

### DDE Standalone Captures (2026-03-06)

| Group | Captures | Purpose |
|-------|----------|---------|
| SH (8) | SH-01–SH-07, SH-10 | Standalone shaking: modes, speeds, positions, durations |
| IM (6) | IM-01–IM-06 | Idle movement: modes, speed, periodic timing |
| ST (4) | ST-01–ST-04 | Stop commands: StopTest during shake/idle |
| VAL (22) | VAL-01–VAL-22 | Validation: duration encoding, drawer control, temp, IdleMove modes, boundaries |
| DIS (7) | DIS-01–DIS-07 | Discovery: Init params, duration 256/512, motor/version (DDE-only) |
| CRI (6) | CRI-01–CRI-06 | Critical unknowns: SetTemp (DDE-only), IdleMove modes 4/7 (rejected) |

### Key findings from DDE captures

- **DDE commands with no USB traffic:** MotorDis, MotorEn, Version, GetInfo, SetTemp,
  TempOff — these are OEM software-internal abstractions that do not produce wire commands
- **Duration encoding:** u16 BE confirmed (256=0x0100, 300=0x012C, 512=0x0200,
  600=0x0258, 3600=0x0E10)
- **Speed encoding:** `(RPM/100)-1` confirmed for both R_Shake and R_IdleMove
  (100=0x00, 200=0x01, 300=0x02, 500=0x04, 700=0x06)
- **IdleMove mode mapping:** DDE arg→wire is NOT sequential. DDE arg 3 → wire 0x06.
  Wire bytes 0x03-0x05 never observed.
- **Drawer control:** OEM software sends INIT+EEPROM before PlateOut (our code matches)
- **Boundaries:** duration=0 rejected, speed=800 rejected, meander@400rpm rejected

---

## 10. PLR vs OEM Plate Geometry

PyLabRobot (`Cor_96_wellplate_360ul_Fb`) and OEM OEM software use slightly different
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
