# CLARIOstar Plus: Complete OEM Command Catalog

**Source manuals:**
- `0430N0003I` — ActiveX and DDE Manual CLARIOstar V5.00-5.70R2 (39 pp)
- `0430F0035B` — Software Manual CLARIOstar 5.70 R2 Part II (100 pp, §9 Script Language)

**Date:** 2026-03-06

---

## 1. DDE/ActiveX Control Commands (§3.1–3.27)

These are the 27 commands available via DDE `Execute` / ActiveX `Execute`/`ExecuteAndWait`. MARS translates them into USB wire commands.

| # | DDE Command | Parameters | USB Traffic? | Our Implementation | Pcap Status |
|---|-------------|------------|-------------|-------------------|-------------|
| 3.1 | **Dummy** | _(none)_ | None — just checks DDE connection | N/A — connection test only | N/A |
| 3.2 | **Init** | _(none)_ | Yes — INITIALIZE (0x01) | `setup()` / `initialize()` | 40+ pcaps |
| 3.3 | **User** | username, data_path, root_dir, run_only_flag | Unknown — likely no USB, MARS-internal | Not implemented | Not captured |
| 3.4 | **PlateIn** | mode (Normal/Right/User), x_pos, y_pos | Yes — drawer open (0x02) | `close()` (plate in) | Pcap confirmed |
| 3.4 | **PlateOut** | mode (Normal/Right/User), x_pos, y_pos | Yes — drawer open (0x02) | `open()` (plate out) | Pcap confirmed |
| 3.5 | **Pump1** | strokes, speed, direction, invert, stroke_volume | Yes — unknown cmd byte | **Not implemented** | Not captured |
| 3.5 | **Pump2** | strokes, speed, direction, invert, stroke_volume | Yes — unknown cmd byte | **Not implemented** | Not captured |
| 3.6 | **Temp** | nominal_temp (00.0=off, 00.1=monitor, 25-45/65) | **None** — DDE exit 1000 | `start/stop_temperature_control()` via direct USB (0x06) | DDE fails; USB 0x06 confirmed |
| 3.7 | **GainWell** | protocol, path, well_col, well_row, target_ch1, target_ch2, chromatic, FP_target_mP, wavelength, channel, focus_adj, well_scan | Yes — FOCUS_WELL / GAIN commands | **Not implemented** (auto-gain) | Not captured |
| 3.7 | **GainPlate** | protocol, path, raw_result_A, raw_result_B, chromatic, focus_adj_ch, well_scan | Yes — scans entire plate | **Not implemented** (auto-gain) | Not captured |
| 3.7 | **GetKFactor** | protocol, path, well_col, well_row, chromatic, target_mP, wavelength, channel | Yes — FP calibration | **Not implemented** (FP) | Not captured |
| 3.8 | **SetGain** | protocol, path, chromatic, channel (A/B), gain (0-4095) | Unknown — may modify protocol DB only | **Not implemented** | Not captured |
| 3.9 | **SetFocalHeight** | protocol, path, focal_height (0-25mm top, 0-9.7mm bottom) | Unknown — may modify protocol DB only | `focal_height=` param on measurements | Not captured via DDE |
| 3.10 | **SetSampleIDs** | protocol, path, sample_IDs_file | None — MARS-internal | N/A | N/A |
| 3.10 | **ClearSampleIDs** | protocol, path | None — MARS-internal | N/A | N/A |
| 3.10 | **ClearDilutionFactors** | protocol, path | None — MARS-internal | N/A | N/A |
| 3.11 | **EditLayout** | protocol, path, layout_change_action | None — MARS-internal | N/A | N/A |
| 3.12 | **EditConcAndVol** | protocol, path, conc/vol_change_action | None — MARS-internal | N/A | N/A |
| 3.13 | **ImportLayout** | protocol, path, layout_file (.lb/.LAc) | None — MARS-internal | N/A | N/A |
| 3.14 | **ImportConcAndVol** | protocol, path, conc_vol_file (.cvb) | None — MARS-internal | N/A | N/A |
| 3.15 | **Run** | protocol, path, meas_data_path, ID1-3, ASCII_path, ASCII_name, EDR_mode | Yes — full measurement sequence | `read_absorbance()` / `read_fluorescence()` via direct USB | 40+ OEM pcaps |
| 3.15 | **CalculateTestDuration** | protocol, path | Unknown — may just query | Not implemented | Not captured |
| 3.16 | **Pause** | cycle (1..N or 65535=next) | Yes — PAUSE_RESUME (0x19) | **Not implemented** | Not captured |
| 3.17 | **Continue** | _(none)_ | Yes — PAUSE_RESUME (0x19) | **Not implemented** | Not captured |
| 3.18 | **StopTest** | save_results (Save/Nosave) | Yes — STOP (0x0B) | `stop_shaking()` uses 0x0B; no measurement stop | Partially captured |
| 3.19 | **StopSystem** | _(none)_ | Yes — stops all reader+stacker activity | **Not implemented** | Not captured |
| 3.20 | **ACU** | sub_cmd (0), O2_param (0-200/255), CO2_param (0-200/255) | Yes — unknown cmd byte | **Not implemented** (no ACU attached) | Not captured |
| 3.21 | **Fan** | fan_number (2), speed (0-100%), on_time (0-3600s) | Yes — unknown cmd byte | **Not implemented** | Not captured |
| 3.22 | **Shake** | type (0-4), freq (100-1100), time (1-3600), x_pos, y_pos | Yes — SHAKE (0x1D) | `start_shaking()` | 13 pcap frames |
| 3.23 | **IdleMove** | mode (0-6), freq (100-300), duration (0-65535), on_time, off_time | Yes — IDLE_MOVE (0x27) | `start_idle_movement()` / `stop_idle_movement()` | 6 pcap captures |
| 3.24 | **MotorDis** | _(none)_ | **None** — DDE-only (exit 0 but no USB) | N/A | Confirmed no USB traffic |
| 3.25 | **MotorEn** | _(none)_ | **None** — DDE-only (exit 0 but no USB) | N/A | Confirmed no USB traffic |
| 3.26 | **ResetError** | _(none)_ | Unknown | **Not implemented** | Not captured |
| 3.27 | **Terminate** | _(none)_ | None — shuts down MARS software | N/A — MARS lifecycle only | N/A |

### DDE Status Items (§2)

Readable via `GetInfo()` or DDE `RequestData`. These are read-only status values from MARS.

| Item | Type | Description | Our Equivalent |
|------|------|-------------|----------------|
| Status / DdeServerStatus | String | Ready/Busy/Error/Running/Paused | `request_machine_status()` |
| DeviceConnected | Bool | Reader is connected | Implicit in `setup()` |
| DeviceBusy | Bool | Reader is processing | `is_ready()` |
| Temp1 | Float | Bottom temperature (0.1C) | `measure_temperature()` |
| Temp2 | Float | Top temperature (0.1C) | `measure_temperature()` |
| T1notreached | Bool | Bottom temp not at target | — |
| T2notreached | Bool | Top temp not at target | — |
| Gain1 | Int | Gain channel A | — |
| Gain2 | Int | Gain channel B (FP only) | — |
| FocalHeight | Float | Current focal height (mm) | `auto_focus()` returns this |
| MotorEnabled | Bool | Stepper motors on/off | — |
| PlateCarrierOut | Bool | Drawer open | `sense_drawer_open()` |
| PlateInserted | Bool | Plate detected | `sense_plate_present()` |
| ReagDoorOpen | Bool | Reagent door open | — |
| TestDur | Float | Calculated test duration (s) | — |
| MeasData | String | Last measurement data path | — |
| Version | String | Software version | `request_firmware_info()` |
| Firmware | String | Firmware version | `request_firmware_info()` |
| SerialNo | String | Serial number | `request_eeprom_data()` |

---

## 2. Script Language Reader Commands (§9.4)

These are the `R_` prefixed commands available in the CLARIOstar script language (.btc files). They map closely to the DDE commands but have slightly different syntax.

### 9.4.1 Init Command

| Script Command | DDE Equivalent | Parameters | Our Implementation |
|----------------|---------------|------------|-------------------|
| **R_Init** | Init | InitMode (bitmask: bit0=disable plate in/out, bit1=skip plate search, bit2=unused, bit3=skip incubator reset, bit4=put plate in mag1) | `setup()` / `initialize()` |

### 9.4.2 Plate Carrier Movement

| Script Command | DDE Equivalent | Parameters | Our Implementation |
|----------------|---------------|------------|-------------------|
| **R_PlateOut** | PlateOut | _(none)_ | `open()` |
| **R_PlateOutR** | PlateOut Right | _(none)_ — out to right/stack 2 | `open()` (no right variant) |
| **R_PlateIn** | PlateIn | _(none)_ | `close()` |
| **R_PlateInB** | PlateIn + barcode | BarcodeReaderSelection (F/R/A), barcode_height / MP:name / protocol+path | **Not implemented** (barcode) |
| **R_BarcodeData** | — | _(none)_ — transfers barcode strings to PC | **Not implemented** |
| **R_PlateUser** | PlateIn User | x, y | **Not implemented** (positional plate) |

### 9.4.3 Incubator Control

| Script Command | DDE Equivalent | Parameters | Our Implementation |
|----------------|---------------|------------|-------------------|
| **R_Temp** | Temp | n (0=off, 0.1=monitor, 25-45/65) | `start/stop_temperature_control()` |

### 9.4.4 Focus and Gain Adjustment

| Script Command | DDE Equivalent | Parameters | Our Implementation |
|----------------|---------------|------------|-------------------|
| **R_FocusPlate** | GainPlate (focus part) | protocol, path, chromatic, channel, WithWellScan | **Not implemented** |
| **R_FocusWell** | GainWell (focus part) | protocol, path, col, row, chromatic, wavelength, channel, focus_adj, well_scan | `auto_focus()` (partial) |
| **R_GainPlate** | GainPlate | protocol, path, raw_A, raw_B, chromatic, focus_adj_ch, well_scan | **Not implemented** |
| **R_GainWell** | GainWell | protocol, path, col, row, target_1, target_2, chromatic, target_mP, wavelength, channel, focus_adj, well_scan | **Not implemented** |
| **R_GetKFactor** | GetKFactor | protocol, path, col, row, chromatic, target_mP, wavelength, channel | **Not implemented** (FP) |
| **R_SetGain** | SetGain | protocol, path, chromatic, channel, gain (0-4095) | **Not implemented** |
| **R_SetFocalHeight** | SetFocalHeight | protocol, path, focal_height (0-25mm) | `focal_height=` param |

### 9.4.5 Run Commands

| Script Command | DDE Equivalent | Parameters | Our Implementation |
|----------------|---------------|------------|-------------------|
| **R_Run** | Run | protocol, path, meas_data_path, src_magazine, dest_magazine, LastPlate, EDR, NoCalibration, ReadBarcode, NotLastPlate | `read_absorbance()` / `read_fluorescence()` |
| **R_CalculateTestDuration** | CalculateTestDuration | protocol, path, src_mag, dest_mag, EDR, calc_mode (cmCheckOnly/cmCheckAndCorrect/cmOptimize/cmCheckFilters) | **Not implemented** |

### 9.4.6 Additional Reader Commands

| Script Command | DDE Equivalent | Parameters | Our Implementation |
|----------------|---------------|------------|-------------------|
| **R_Shake** | Shake | mode (0-4), freq (100-1100), time (1-3600), x_pos, y_pos | `start_shaking()` |
| **R_IdleMove** | IdleMove | mode (1-6), freq (100-300), duration (0-65535), on_time, off_time | `start_idle_movement()` / `stop_idle_movement()` |
| **R_ACU** | ACU | sub_cmd, O2_param, CO2_param | **Not implemented** |
| **R_Fan** | Fan | fan_number (2), speed (0-100%), on_time (0-3600s) | **Not implemented** |

### 9.4.7 Protocol Names / Edit Protocol Layout

| Script Command | DDE Equivalent | Parameters | Our Implementation |
|----------------|---------------|------------|-------------------|
| **R_GetProtocolNames** | — | separator, path | N/A — MARS query |
| **R_EditLayout** | EditLayout | protocol, path, layout_change_action | N/A — MARS-internal |
| **R_EditConcAndVol** | EditConcAndVol | protocol, path, conc/vol_change_action | N/A — MARS-internal |
| **R_ExportLayout** | — | protocol, path, layout_file (.lac) | N/A — MARS-internal |
| **R_ImportLayout** | ImportLayout | protocol, path, layout_file | N/A — MARS-internal |
| **R_ImportConcAndVol** | ImportConcAndVol | protocol, path, conc_vol_file (.cvb) | N/A — MARS-internal |
| **R_SetSampleIDs** | SetSampleIDs | protocol, path, sample_IDs_file (.xls/.xlsx) | N/A — MARS-internal |
| **R_ClearSampleIDs** | ClearSampleIDs | protocol, path | N/A — MARS-internal |
| **R_ClearDilutionFactors** | ClearDilutionFactors | protocol, path | N/A — MARS-internal |
| **R_DisableMotors** | MotorDis | _(none)_ | N/A — no USB traffic |

### 9.5 Stacker Commands

| Script Command | Parameters | Our Implementation |
|----------------|------------|-------------------|
| **S_Init** | _(none)_ | **Not implemented** (no stacker) |
| **S_PrepareForPlate** | protocol/path or MP:name | **Not implemented** |
| **S_PlateIn** | magazine (n), NotLastPlate | **Not implemented** |
| **S_PlateInB** | BarcodeReaderSelection, barcode_height / MP:name / protocol+path | **Not implemented** |
| **S_PlateOut** | magazine (n) | **Not implemented** |
| **S_GetPlate** | magazine (n) | **Not implemented** |
| **S_GetPlateB** | magazine (n) + barcode read | **Not implemented** |
| **S_PutPlate** | magazine (n) | **Not implemented** |
| **S_MovePlate** | src, dest, count | **Not implemented** |
| **S_RestackAfterCount** | _(none)_ | **Not implemented** |
| **S_MoveTable** | position (0-3) | **Not implemented** |
| **S_MoveX** | x_pos | **Not implemented** |
| **S_MoveZ** | z_pos | **Not implemented** |
| **S_DisableMotors** | _(none)_ | **Not implemented** |
| **S_ReadBarcode** | _(none)_ | **Not implemented** |
| **S_BarcodeData** | _(none)_ | **Not implemented** |
| **S_SysTest** | mode | **Not implemented** |
| **S_GetSysTestData** | _(none)_ | **Not implemented** |

### 9.10 Measurement Data

| Script Command | Parameters | Our Implementation |
|----------------|------------|-------------------|
| **R_GetData** | well, cycle/interval, chromatic, channel, return_for_unused | `request_absorbance_results()` (partial — ABS only, no FL) |
| **R_GetRawDataFileNumber** | path_to_meas_data | **Not implemented** |

---

## 3. Categorized Implementation Gap Analysis

### Commands that produce USB traffic and are NOT implemented

These are the high-value capture/implementation targets:

| Priority | Command | Wire Opcode (if known) | Complexity | Notes |
|----------|---------|----------------------|------------|-------|
| **HIGH** | **Pause** | 0x19 (PAUSE_RESUME) | Low | Single byte flag. Pauses active measurement at cycle boundary. |
| **HIGH** | **Continue** | 0x19 (PAUSE_RESUME) | Low | Resume from pause. No parameters. |
| **HIGH** | **StopTest** | 0x0B (STOP) | Low | We already send 0x0B for `stop_shaking()`. Just needs `save_results` param. |
| **MEDIUM** | **Pump1/Pump2** | Unknown | Medium | Syringe pump: strokes, speed, direction, invert, stroke_volume. Need pcap. |
| **MEDIUM** | **GainWell** | Unknown (likely 0x1A+) | Medium | Auto-gain pre-measurement step. Sends focus+gain scan commands. |
| **MEDIUM** | **GainPlate** | Unknown | Medium | Full-plate gain scan. Likely multi-command sequence. |
| **MEDIUM** | **StopSystem** | Unknown | Low | Emergency stop — stops all reader + stacker activity. |
| **MEDIUM** | **Fan** | Unknown | Low | Fan 2 speed control. Only useful with ACU. |
| **LOW** | **ACU** | Unknown | Medium | Atmospheric control. O2/CO2 regulation. Need ACU hardware. |
| **LOW** | **ResetError** | Unknown | Low | Clears error state. No params. |
| **LOW** | **GetKFactor** | Unknown | Medium | FP calibration. Need FP hardware. |
| **LOW** | **CalculateTestDuration** | Unknown | Low | Query only — calculates run time. |
| **LOW** | **User** | Unknown (maybe none) | Low | Login/user context. MARS-internal? |

### Commands that produce NO USB traffic (MARS-internal only)

These never need wire-level implementation:

- **Dummy** — DDE connection test
- **SetSampleIDs / ClearSampleIDs / ClearDilutionFactors** — protocol DB manipulation
- **EditLayout / EditConcAndVol** — protocol DB manipulation
- **ImportLayout / ImportConcAndVol** — protocol DB manipulation
- **MotorDis / MotorEn** — confirmed no USB traffic (DDE exit 0, but no wire frames)
- **Terminate** — shuts down MARS software
- **SetGain / SetFocalHeight** (via DDE) — may only modify protocol DB, not send USB

### Commands already fully implemented

| Command | Our Method(s) | Pcap Verified |
|---------|--------------|---------------|
| Init | `setup()`, `initialize()` | Yes (40+) |
| PlateIn | `close()` | Yes |
| PlateOut | `open()` | Yes |
| Temp | `start/stop_temperature_control()`, `measure_temperature()` | Yes (USB 0x06) |
| Run | `read_absorbance()`, `read_fluorescence()` | Yes (40+) |
| Shake | `start_shaking()`, `stop_shaking()` | Yes (13 frames) |
| IdleMove | `start_idle_movement()`, `stop_idle_movement()` | Yes (6 captures) |
| StopTest (partial) | `stop_shaking()` uses STOP 0x0B | Yes |

---

## 4. Shake Mode Reference (consolidated from both manuals)

### DDE Shake (§3.22) — standalone shake

| DDE Arg | Mode | Max Freq | Our Wire Byte |
|---------|------|----------|---------------|
| 0 | orbital | 700 (1100 high-speed) | 0x01 |
| 1 | linear | 700 (800 high-speed) | 0x02 |
| 2 | double orbital | 700 (1100 high-speed) | 0x04 |
| 3 | meander corner well | 300 | 0x03 |
| 4 | orbital corner well | ? | ? (special plate carrier) |

### DDE IdleMove (§3.23) — background idle movement

| DDE Arg | Mode | Freq Range | Our Wire Byte |
|---------|------|-----------|---------------|
| 0 | cancel | — | (send `IdleMove 0 0 0`) |
| 1 | linear corner | — | 0x01 |
| 2 | incubation position | — | 0x02 |
| 3 | meander corner well | 100-300 | 0x03 (speculative) |
| 4 | orbital corner well | 100-700 | 0x04 (speculative) |
| 5 | orbital | 100-700 | 0x05 |
| 6 | double orbital | 100-700 | 0x06 |

**Key finding:** DDE arg 3 (meander) → wire 0x06 was observed in pcap (IM-06), suggesting the DDE→wire mapping is NOT 1:1 for IdleMove. See FEATURE_AUDIT.md inconsistency #4.

---

## 5. Parameter Ranges (consolidated)

| Parameter | Range | Notes |
|-----------|-------|-------|
| Shake frequency | 100-700 RPM (1100 high-speed orbital) | Linear max 800 high-speed; meander max 300 |
| Shake time | 1-3600 seconds | |
| Shake position X | 250-3100 (or 9999=random) | Optional |
| Shake position Y | 125-800 (or 9999=random) | Optional |
| IdleMove duration | 0-65535 seconds | 0 = permanent |
| IdleMove on-time | 0-3600 seconds | 0 = always active |
| IdleMove off-time | 0-3600 seconds | 0 = no pause |
| Temperature | 0 (off), 0.1 (monitor), 25.0-45.0 (std), 10.0-65.0 (extended) | |
| Gain | 0-4095 | |
| Focal height | 0-25.0 mm (top), 0-9.7 mm (bottom) | 0.1mm increments |
| Pump strokes | per pump specification | |
| Pump speed | 100-400 µL/s | |
| Fan speed | 0-100% | Hardware max 93% |
| Fan on-time | 0-3600 seconds | 0 = permanent |
| ACU O2/CO2 | 0 (off), 1-200 (target 1/10%), 255 (monitor) | |
| Pause cycle | 1-N (specific cycle), 65535 (next cycle) | |
| Plate ID | max 100 chars each (ID1, ID2, ID3) | |

---

## 6. Weekend / Next Capture Priority

Based on this catalog, the highest-value uncaptured commands that produce USB traffic:

1. **Pause / Continue** — trivial params, likely simple wire encoding (0x19). Would complete our measurement lifecycle.
2. **StopTest** with save_results — we already know 0x0B; just need to verify the save param.
3. **Pump1/Pump2** — if injector hardware available. New command family entirely.
4. **GainWell** — auto-gain pre-measurement. Complex multi-step but high value.
5. **Fan** — simple command, but only useful with ACU.
6. **StopSystem** — emergency stop. Simple but important for safety.
7. **ResetError** — error recovery. Simple, no params.

### Commands NOT worth capturing

- Anything `MARS-internal` (layout editing, sample IDs, protocol DB) — no USB traffic
- MotorDis/MotorEn — already confirmed no USB traffic
- Stacker commands — no stacker attached
- ACU — no ACU attached
- User/Terminate — MARS software lifecycle only
