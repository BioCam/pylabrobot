# CLARIOstar Plus — Implementation Status

Compact checklist of what's implemented, validated, and missing.

Last updated: 2026-03-09

---

## Implemented and hardware-verified

| Feature | Method(s) | Evidence |
|---------|-----------|----------|
| Connection & init | `setup()`, `stop()`, `initialize()` | 40+ captures |
| Drawer control | `open()`, `close()`, `sense_drawer_open()` | capture confirmed |
| Device identification | `request_eeprom_data()`, `request_firmware_info()`, `request_usage_counters()`, `request_available_detection_modes()` | Real 263-byte EEPROM frame |
| Status polling (12 flags) | `request_machine_status()`, `is_ready()`, `sense_plate_present()` | All flag combinations tested |
| Error recovery | CMD_0x0E during `setup()` | Matches OEM software boot sequence |
| Temperature control | `start/stop_temperature_control()`, `measure_temperature()`, `get_target_temperature()` | USB 0x06 confirmed |
| Absorbance (discrete) | `read_absorbance()` — 1–8 wavelengths | 22 capture payloads |
| Absorbance (spectrum) | `read_absorbance_spectrum()` — paginated | 5 capture payloads, 15 binary ground-truth files |
| Fluorescence (discrete) | `read_fluorescence()` — mono, filter, multi-chromatic, EDR, flying, matrix | 29 captures |
| Fluorescence (spectrum) | `read_fluorescence_spectrum()` — excitation/emission sweep | Implemented |
| Filter auto-detection | `detect_all_filters()` — 11 positions | hardware-verified |
| Focus | `focus_well()` — Z-scan per well | hardware-verified |
| Standalone shaking | `start_shaking()`, `stop_shaking()` | 13 capture frames |
| Idle movement | `start_idle_movement()`, `stop_idle_movement()` | 6 captures |
| Pause / resume | `pause_measurement()`, `resume_measurement_and_collect_data()` | cleanup/ + MON-03/04 |
| Stop measurement | `stop_measurement()` | ST-01, ST-04 |
| Well scan modes | point, orbital, spiral, matrix | All modes for ABS + FL |
| Scan directions | 16 patterns (4 corners × 2 orientations × 2 uni/bidi) | All tested |
| Non-blocking mode | `wait=False` on all measurements | Implemented |

## Implemented, not yet validated on hardware

| Feature | Notes |
|---------|-------|
| Fluorescence bottom optic | `optic_position="bottom"` — capture wire match, no hardware test |
| Multi-chromatic 3–5 channels | Dual verified; 3–5 ch untested |
| 384-well fluorescence | capture wire verified, no hardware test |
| 384-well absorbance | DOE_P384_01 confirmed plate_field[14]=0x00 (padding), full 48-byte mask |
| Matrix well scan | DOE_MTX01/MTX02 confirmed WellScanMode.MATRIX=0x10, well_scan_field encoding |

## Not implemented

| Feature | Blocker | Priority |
|---------|---------|----------|
| **Luminescence** | 1 capture (DOE_LUM01): DetectionMode=0x01, 145-byte payload, different post-boundary structure. ~20 unknown LUM-specific bytes need 2–3 more captures with varied settings to diff. `read_luminescence()` raises `NotImplementedError`. | High |
| **Auto-gain** | Firmware 1.35 supports GainWell/GainPlate but no captures exist. | Medium |
| **Pause before cycle** | Wire encoding decoded (DOE_SPC06/SPC07): bytes [116:120] encode mode flag, target cycle, duration. "each" = manual popup (0xff,0xff), specific cycle = auto-timed. Backend not yet parameterized. | Medium |
| **FL `wait=False` collect helper** | `request_absorbance_results()` exists for ABS; no FL equivalent. | Medium |
| **Python-side warnings** | Ex-em 25nm minimum distance, gain > 3000 noise, overflow detection. | Medium |
| **TRF** | No captures, filter-only, microsecond timing. | Low |
| **Fluorescence Polarization** | No captures, dual-channel encoding unknown. | Low |
| **StopSystem** | `0x0B` param `0x01` — captured (MON-02), trivial to add. | Low |
| **Kinetic modes** | Wire encoding fully decoded (DOE 2026-03-09). Backend parameterized: `kinetic_cycles`, `kinetic_cycle_time_s` in `_build_absorbance_payload`. Shake-between-readings implemented (trailer_prefix encoding). Shake timing variants decoded (each/first/defined/between). No public `read_absorbance_kinetic()` API yet. | High |
| **Injectors (Pump 1 & 2)** | MON-05 shows no USB frames for Pump1 (exit 0). Needs physical pump hardware. | Low |
| **Well multichromatics ordering** | Flag in wire protocol, not exposed. | Low |
| **Multiple shaking actions** | OEM supports chaining; we do single shake only. | Low |
| **1536-well plates** | Unknown encoding, no captures. | Low |
| **AlphaScreen/AlphaLISA** | Requires 680nm laser (not installed). | Out of scope |

## Known inconsistencies

1. **IdleMove mode mapping**: Wire bytes 0x03 (`meander_corner`) and 0x04 (`orbital_corner`) are speculative — never observed on wire. Only 0x01, 0x02, 0x05, 0x06 are hardware-confirmed.
2. **Meander shake**: Exists in builder (index 3) but not exposed in public method validation. DDE confirms 300 RPM max.
3. **Pause payload length**: PLR sends 4 param bytes (`ff ff 00 00`); DDEclient standalone sends 6 (`ff ff 00 00 00 02`). Both accepted by device. The trailing `00 02` purpose is unknown.
4. **ResetError is not CMD_0x0E**: MON-01 (2026-03-09) confirms ResetError triggers a full re-init sequence (INIT → STATUS → EEPROM read), not the 0x0E boot command.
5. **Pause/Continue opcode**: Architecture.md previously listed 0x19; actual wire opcode is 0x0D (PAUSE_RESUME). Corrected 2026-03-09.

## Test coverage

474 test methods across the test suite. Key areas:

| Area | Tests | Ground truth |
|------|-------|-------------|
| Wire protocol & framing | 17 | 10 command round-trips |
| Connection & init | 15 | — |
| Status & device ID | 35 | Real EEPROM (263B) + firmware (39B) |
| Temperature | 14 | — |
| Absorbance discrete | 81 | 22 OEM + 18 DOE capture payloads |
| Absorbance spectrum | 39 | 5 capture payloads + 781-wavelength dataset |
| Fluorescence | 62 | 15 capture payloads + 7 response frames |
| Focus | 25 | capture send + 143-point result |
| Shaking & idle movement | 30+ | 13 + 6 capture frames |
| Input validation | 28 | — |
| Filter detection | 20+ | hardware-verified |
