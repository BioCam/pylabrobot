"""CLARIOstar protocol frame extraction and decoding.

Provides two main capabilities:
  1. Extract protocol frames from USBPcap .pcapng captures
  2. Decode frames into byte-level annotations

Pure stdlib — no external dependencies.

Usage as a module::

    from pylabrobot.plate_reading.bmg_labtech.clariostar_plus_protocol import (
        extract_frames, decode_frame,
    )

Usage as a CLI::

    # Extract frames from pcap
    python -m pylabrobot.plate_reading.bmg_labtech.clariostar_plus_protocol extract <path>

    # Decode extracted frames
    python -m pylabrobot.plate_reading.bmg_labtech.clariostar_plus_protocol decode <path>

    # Both steps at once
    python -m pylabrobot.plate_reading.bmg_labtech.clariostar_plus_protocol both <path>
"""

import os
import struct
import sys
from pathlib import Path
from typing import Dict, List, Optional, Tuple


# ═══════════════════════════════════════════════════════════════════════════════
# Constants
# ═══════════════════════════════════════════════════════════════════════════════

STATUS_FLAGS = [
    # (byte_index, bitmask, name)
    (0, 1 << 1, "STANDBY"),
    (1, 1 << 0, "VALID"),
    (1, 1 << 4, "RUNNING"),
    (1, 1 << 5, "BUSY"),
    (2, 1 << 0, "UNREAD_DATA"),
    (3, 1 << 0, "DRAWER_OPEN"),
    (3, 1 << 1, "PLATE_DETECTED"),
    (3, 1 << 2, "Z_PROBED"),
    (3, 1 << 3, "ACTIVE"),
    (3, 1 << 5, "INITIALIZED"),
    (3, 1 << 6, "LID_OPEN"),
    (4, 1 << 6, "FILTER_COVER_OPEN"),
]

SHAKE_TYPES_0026 = {
    0x01: "LINEAR", 0x02: "ORBITAL", 0x03: "DOUBLE_ORBITAL", 0x04: "MEANDER",
}

ABS_SCHEMA = {
    0x29: "absorbance (no incubation)",
    0xA9: "absorbance (incubation active/was active)",
}

FL_SCHEMA = {
    0x21: "fluorescence (no incubation)",
    0xA1: "fluorescence (incubation active/was active)",
}

COMMAND_LABELS = {
    0x01: "INITIALIZE",
    0x06: "TEMPERATURE",
    0x80: "STATUS_QUERY",
    0x81: "HW_STATUS_QUERY",
}

SUBCOMMAND_05_LABELS = {
    0x02: "GET_DATA",
    0x07: "EEPROM_READ",
    0x09: "FW_INFO",
    0x0F: "FOCUS_HEIGHT",
    0x17: "0x17",
    0x1D: "READ_ORDER",
    0x21: "USAGE_COUNTERS",
}

DATA_SCHEMA_LABELS = {
    0x29: "ABS_DATA",
    0xA9: "ABS_DATA",
    0x21: "FL_DATA",
    0xA1: "FL_DATA",
}


# ═══════════════════════════════════════════════════════════════════════════════
# Part 1: pcapng → frames
# ═══════════════════════════════════════════════════════════════════════════════

def read_pcapng_packets(path):
    """Yield (timestamp_us, raw_packet_bytes) from a pcapng file.

    Only yields Enhanced Packet Blocks (type 6).
    """
    with open(path, "rb") as f:
        data = f.read()

    offset = 0
    while offset < len(data) - 12:
        block_type = struct.unpack_from("<I", data, offset)[0]
        block_len = struct.unpack_from("<I", data, offset + 4)[0]
        if block_len < 12 or offset + block_len > len(data):
            break
        if block_type == 6:  # Enhanced Packet Block
            body = data[offset + 8 : offset + block_len - 4]
            ts_hi = struct.unpack_from("<I", body, 4)[0]
            ts_lo = struct.unpack_from("<I", body, 8)[0]
            cap_len = struct.unpack_from("<I", body, 12)[0]
            pkt_data = body[20 : 20 + cap_len]
            ts_us = (ts_hi << 32) | ts_lo
            yield ts_us, pkt_data
        offset += block_len


def parse_usbpcap_header(data):
    """Parse a USBPcap packet header. Returns dict with endpoint, transfer_type, payload."""
    if len(data) < 27:
        return None
    hdr_len = struct.unpack_from("<H", data, 0)[0]
    endpoint = data[21]
    transfer_type = data[22]  # 0=iso, 1=interrupt, 2=control, 3=bulk
    payload = data[hdr_len:]
    return {"endpoint": endpoint, "transfer_type": transfer_type, "payload": payload}


def _drain_frames(buf, frames, rel_s, direction):
    """Extract complete CLARIOstar frames from a reassembly buffer (modifies buf in-place)."""
    while True:
        start = buf.find(0x02)
        if start == -1:
            buf.clear()
            break
        if start > 0:
            del buf[:start]
        if len(buf) < 3:
            break
        frame_size = int.from_bytes(buf[1:3], "big")
        if frame_size < 7:
            del buf[:1]
            continue
        if len(buf) >= frame_size:
            frame = bytes(buf[:frame_size])
            frames.append((rel_s, direction, frame))
            del buf[:frame_size]
        else:
            break


def extract_frames(path) -> List[Tuple[float, str, bytes]]:
    """Extract CLARIOstar protocol frames from a USB pcapng capture.

    Returns list of (relative_time_s, direction, frame_bytes) tuples.
    Direction is "SEND" (host→device) or "RECV" (device→host).
    """
    first_ts = None
    out_buf = bytearray()
    in_buf = bytearray()
    frames = []

    for ts_us, raw in read_pcapng_packets(path):
        hdr = parse_usbpcap_header(raw)
        if hdr is None or hdr["transfer_type"] != 3:  # only BULK transfers
            continue
        if first_ts is None:
            first_ts = ts_us

        rel_s = (ts_us - first_ts) / 1_000_000.0
        ep = hdr["endpoint"]
        pl = hdr["payload"]

        if ep == 0x02 and len(pl) > 0:
            out_buf += pl
            _drain_frames(out_buf, frames, rel_s, "SEND")
        elif ep == 0x81 and len(pl) > 2:
            in_buf += pl[2:]  # strip 2 FTDI modem-status bytes
            _drain_frames(in_buf, frames, rel_s, "RECV")

    return frames


def describe_frame(frame_bytes: bytes) -> str:
    """Return a human-readable label for a CLARIOstar frame."""
    if len(frame_bytes) < 7:
        return f"(short: {len(frame_bytes)}B)"
    payload = frame_bytes[4:-3]
    if len(payload) == 0:
        return "(empty payload)"
    cmd = payload[0]

    if cmd == 0x03 and len(payload) > 1:
        return f"DRAWER_{'OPEN' if payload[1] == 1 else 'CLOSE'}"
    if cmd == 0x05 and len(payload) > 1:
        sub = payload[1]
        label = SUBCOMMAND_05_LABELS.get(sub, f"0x{sub:02x}")
        return f"CMD_05/{label}"
    if cmd == 0x04:
        return f"MEASUREMENT_RUN ({len(frame_bytes)}B)"
    if cmd in COMMAND_LABELS:
        return COMMAND_LABELS[cmd]
    if len(payload) > 6 and payload[6] in DATA_SCHEMA_LABELS:
        label = DATA_SCHEMA_LABELS[payload[6]]
        return f"{label}_RESPONSE ({len(frame_bytes)}B)"
    if cmd in (0x00, 0x01, 0x02, 0x03):
        return f"RESPONSE (schema=0x{cmd:02x}, {len(frame_bytes)}B)"
    return f"UNKNOWN cmd=0x{cmd:02x} ({len(frame_bytes)}B)"


# ═══════════════════════════════════════════════════════════════════════════════
# Part 2: Frame decoding
# ═══════════════════════════════════════════════════════════════════════════════

def decode_status_flags(status_bytes: bytes) -> str:
    active = []
    for byte_idx, mask, name in STATUS_FLAGS:
        if byte_idx < len(status_bytes) and status_bytes[byte_idx] & mask:
            active.append(name)
    return ", ".join(active) if active else "(none)"


class Annotation:
    """Collects byte-range annotations for a frame."""

    def __init__(self, raw: bytes):
        self.raw = raw
        self.entries: List[Tuple[int, int, str]] = []

    def add(self, start: int, end: int, desc: str):
        self.entries.append((start, end, desc))

    def add1(self, offset: int, desc: str):
        self.entries.append((offset, offset + 1, desc))

    def render(self, indent: str = "  ") -> str:
        lines = []
        lines.append(f"{indent}{'Offset':<8s} {'Hex':<30s} {'Decoded'}")
        lines.append(f"{indent}{'------':<8s} {'---':<30s} {'-------'}")
        for start, end, desc in sorted(self.entries, key=lambda e: e[0]):
            if start >= len(self.raw) or end > len(self.raw):
                continue
            chunk = self.raw[start:end]
            hex_str = " ".join(f"{b:02x}" for b in chunk)
            if len(hex_str) > 28:
                hex_str = hex_str[:25] + "..."
            off_str = f"{start}" if start == end - 1 else f"{start}-{end - 1}"
            lines.append(f"{indent}{off_str:<8s} {hex_str:<30s} {desc}")
        return "\n".join(lines)


# -- Envelope --

def decode_envelope(ann: Annotation, raw: bytes):
    ann.add1(0, "STX (frame start)")
    size = int.from_bytes(raw[1:3], "big")
    ann.add(1, 3, f"Frame size: {size} bytes")
    ann.add1(3, "Protocol header (0x0C)")
    if len(raw) >= 7:
        cs = int.from_bytes(raw[-3:-1], "big")
        computed = sum(raw[:-3]) & 0xFFFF
        cs_ok = "OK" if cs == computed else f"MISMATCH (expected 0x{computed:04x})"
        ann.add(len(raw) - 3, len(raw) - 1, f"Checksum: 0x{cs:04x} ({cs_ok})")
        ann.add1(len(raw) - 1, "CR (frame end)")


# -- SEND command decoders --

def decode_initialize_cmd(ann, payload, off):
    ann.add1(off, "Command: INITIALIZE (0x01)")
    for i in range(1, len(payload)):
        ann.add1(off + i, f"Init param byte [{i}] = 0x{payload[i]:02x} [unknown purpose]")


def decode_drawer_cmd(ann, payload, off):
    action = "OPEN" if len(payload) > 1 and payload[1] == 1 else "CLOSE"
    ann.add1(off, "Command: DRAWER (0x03)")
    if len(payload) > 1:
        ann.add1(off + 1, f"Action: {action} ({'0x01' if payload[1] == 1 else '0x00'})")
    for i in range(2, len(payload)):
        ann.add1(off + i, f"Padding: 0x{payload[i]:02x}")


def decode_status_query_cmd(ann, payload, off):
    ann.add1(off, "Command: STATUS_QUERY (0x80)")
    if len(payload) > 1:
        ann.add1(off + 1, f"Subcommand: 0x{payload[1]:02x}")


def decode_hw_status_cmd(ann, payload, off):
    ann.add1(off, "Command: HW_STATUS_QUERY (0x81)")
    if len(payload) > 1:
        ann.add1(off + 1, f"Subcommand: 0x{payload[1]:02x}")


def decode_temperature_cmd(ann, payload, off):
    ann.add1(off, "Command: TEMPERATURE (0x06)")
    if len(payload) >= 3:
        temp_raw = int.from_bytes(payload[1:3], "big")
        if temp_raw == 0 and len(payload) >= 4 and payload[3] == 1:
            ann.add(off + 1, off + 3, "Temperature: 0 (monitor only mode)")
        elif temp_raw == 0:
            ann.add(off + 1, off + 3, "Temperature: OFF")
        else:
            ann.add(off + 1, off + 3, f"Target: {temp_raw / 10:.1f} C")
    for i in range(3, len(payload)):
        ann.add1(off + i, f"Param: 0x{payload[i]:02x}")


def decode_cmd05(ann, payload, off):
    ann.add1(off, "Command family: DATA/QUERY (0x05)")
    if len(payload) < 2:
        return
    sub = payload[1]
    sub_labels = {
        0x02: "GET_DATA", 0x07: "EEPROM_READ", 0x09: "FIRMWARE_INFO",
        0x0F: "FOCUS_HEIGHT", 0x17: "UNKNOWN_0x17 (pre-measurement query?)",
        0x1D: "READ_ORDER", 0x21: "USAGE_COUNTERS",
    }
    label = sub_labels.get(sub, f"UNKNOWN subcommand 0x{sub:02x}")
    ann.add1(off + 1, f"Subcommand: {label}")
    if sub == 0x02 and len(payload) >= 6:
        if payload[2:6] == b"\xff\xff\xff\xff":
            ann.add(off + 2, off + 6, "Progressive variant (FF FF FF FF)")
        else:
            ann.add(off + 2, off + 6, f"Standard variant ({payload[2:6].hex(' ')})")
    for i in range(6 if sub == 0x02 and len(payload) >= 6 else 2, len(payload)):
        ann.add1(off + i, f"Padding: 0x{payload[i]:02x}")


def decode_cmd08(ann, payload, off):
    ann.add1(off, "Command: UNKNOWN_0x08 (keepalive/poll?)")
    for i in range(1, len(payload)):
        ann.add1(off + i, f"[unknown] 0x{payload[i]:02x}")


def decode_measurement_run(ann, payload, off):
    """Decode an absorbance/fluorescence/luminescence measurement run command.

    OEM plate data layout (65 bytes, 1 more than our code's 64):
      command(1) + dims(12) + cols(1) + rows(1) + extra_byte(1) + well_mask(48) + scan_mode(1)
    Then: pre_separator_block(varies) + SEPARATOR(4) + post_separator(varies)
    """
    p = payload
    o = off

    ann.add1(o, "PLATE_DATA prefix (0x04)")

    if len(p) < 65:
        ann.add(o + 1, o + len(p), f"[truncated plate data, only {len(p)} bytes]")
        return

    plate_len = int.from_bytes(p[1:3], "big") / 100
    plate_wid = int.from_bytes(p[3:5], "big") / 100
    ann.add(o + 1, o + 3, f"Plate length: {plate_len:.2f} mm")
    ann.add(o + 3, o + 5, f"Plate width: {plate_wid:.2f} mm")

    x1 = int.from_bytes(p[5:7], "big") / 100
    y1 = int.from_bytes(p[7:9], "big") / 100
    xn = int.from_bytes(p[9:11], "big") / 100
    yn = int.from_bytes(p[11:13], "big") / 100
    ann.add(o + 5, o + 7, f"Well A1 center X: {x1:.2f} mm")
    ann.add(o + 7, o + 9, f"Well A1 center Y: {y1:.2f} mm")
    ann.add(o + 9, o + 11, f"Last well center X: {xn:.2f} mm")
    ann.add(o + 11, o + 13, f"Last well center Y: {yn:.2f} mm")

    cols = p[13]
    rows = p[14]
    ann.add1(o + 13, f"Columns: {cols}")
    ann.add1(o + 14, f"Rows: {rows}")

    ann.add1(o + 15, f"Plate extra byte: 0x{p[15]:02x}")

    mask = p[16:64]
    selected = sum(bin(b).count("1") for b in mask)
    total = cols * rows
    if selected == total:
        ann.add(o + 16, o + 64, f"Well mask: ALL {total} wells selected (48 bytes)")
    else:
        ann.add(o + 16, o + 64, f"Well mask: {selected}/{total} wells selected (48 bytes)")

    scan = p[64]
    uni = "unidirectional" if scan & 0x80 else "bidirectional"
    corner_bits = (scan >> 4) & 0x07
    corners = {
        0: "TOP_LEFT (OEM default)",
        1: "TOP_LEFT", 3: "TOP_RIGHT", 5: "BOTTOM_LEFT", 7: "BOTTOM_RIGHT",
    }
    corner = corners.get(corner_bits, f"unknown(0x{corner_bits:02x})")
    vert = "vertical" if scan & 0x08 else "horizontal"
    flying = ", flying" if scan & 0x04 else ""
    always_set = " [bit1 set]" if scan & 0x02 else ""
    ann.add1(o + 64, f"Scan mode: {corner}, {vert}, {uni}{flying}{always_set} (0x{scan:02x})")

    # Pre-separator block
    sep_idx = None
    for i in range(65, len(p) - 3):
        if p[i:i + 4] == b"\x27\x0f\x27\x0f":
            sep_idx = i
            break

    if sep_idx is None:
        ann.add(o + 65, o + len(p), "[no separator found]")
        return

    block = p[65:sep_idx]
    block_len = len(block)

    if block_len >= 1:
        optic_byte0 = block[0]
        optic_desc = []
        base_optic = optic_byte0 & 0x03
        if base_optic == 0x02:
            optic_desc.append("absorbance")
        elif base_optic == 0x01:
            optic_desc.append("luminescence")
        elif base_optic == 0x00:
            optic_desc.append("fluorescence")
        scan_flags = optic_byte0 & ~0x43
        if scan_flags == 0x30:
            optic_desc.append("orbital")
        elif scan_flags == 0x04:
            optic_desc.append("spiral")
        elif scan_flags == 0x00:
            optic_desc.append("point")
        else:
            optic_desc.append(f"scan_flags=0x{scan_flags:02x}")
        if optic_byte0 & 0x40:
            optic_desc.append("bottom_optic")
        ann.add1(o + 65, f"Optic byte 0: {', '.join(optic_desc)} (0x{optic_byte0:02x})")

    if block_len >= 2:
        ann.add1(o + 66, f"Optic byte 1: 0x{block[1]:02x}")

    for i in range(2, block_len):
        val = block[i]
        note = ""
        if i == 12 and val != 0:
            note = f" <- shake_type: {SHAKE_TYPES_0026.get(val, f'0x{val:02x}')}"
        elif i == 18 and val != 0:
            note = f" <- shake_speed_idx={val} -> {(val + 1) * 100} RPM"
        elif i == 20 and val != 0:
            note = f" <- shake_duration: {val}s"
        elif val == 0:
            note = ""
        else:
            note = " [unknown]"
        if val == 0 and note == "":
            continue
        ann.add1(o + 65 + i, f"Block[{i}]: 0x{val:02x} = {val}{note}")

    zero_start = None
    for i in range(2, block_len):
        if block[i] == 0:
            if zero_start is None:
                zero_start = i
        else:
            if zero_start is not None:
                if i - zero_start > 1:
                    ann.add(o + 65 + zero_start, o + 65 + i,
                            f"Block[{zero_start}-{i - 1}]: zeros ({i - zero_start} bytes padding)")
                zero_start = None
    if zero_start is not None and block_len - zero_start > 1:
        ann.add(o + 65 + zero_start, o + 65 + block_len,
                f"Block[{zero_start}-{block_len - 1}]: zeros ({block_len - zero_start} bytes padding)")

    ann.add(o + sep_idx, o + sep_idx + 4, "Separator: 27 0F 27 0F")

    post = p[sep_idx + 4:]
    po = o + sep_idx + 4

    if len(post) == 0:
        return

    has_orbital = len(post) >= 5 and post[0] in (0x02, 0x03) and post[4] == 0x00
    if has_orbital:
        well_dia_check = int.from_bytes(post[2:4], "big")
        has_orbital = 1 <= post[1] <= 22 and 100 <= well_dia_check <= 3000

    if has_orbital:
        meas_codes = {0x02: "absorbance", 0x03: "fluorescence"}
        ann.add1(po, f"Orbital: measurement_code ({meas_codes.get(post[0], f'0x{post[0]:02x}')})")
        ann.add1(po + 1, f"Orbital: scan diameter = {post[1]} mm")
        well_dia = int.from_bytes(post[2:4], "big")
        ann.add(po + 2, po + 4, f"Orbital: well diameter = {well_dia / 100:.2f} mm")
        ann.add1(po + 4, "Orbital: terminator (0x00)")
        post = post[5:]
        po += 5

    _decode_abs_post_separator(ann, post, po)


def _decode_abs_post_separator(ann, post, po):
    """Decode absorbance measurement bytes after separator (and orbital block).

    Layout (verified against clariostar_backend.py and OEM pcap):
      pause(1) + num_wl(1) + wavelengths(2*N) + ref_block(13) +
      settling(3) + trailer(11) + flashes(2) + final(4)
    """
    if len(post) < 2:
        return

    idx = 0

    pause_enc = post[idx]
    if pause_enc == 1:
        pause_desc = "0 deciseconds (encoded as 1)"
    else:
        actual_ds = pause_enc * 2 / 10
        pause_desc = f"{actual_ds:.1f} deciseconds (raw=0x{pause_enc:02x})"
    ann.add1(po + idx, f"Per-well pause: {pause_desc}")
    idx += 1

    num_wl = post[idx]
    ann.add1(po + idx, f"Num wavelengths: {num_wl}")
    idx += 1

    for w in range(num_wl):
        if idx + 2 > len(post):
            break
        wl_raw = int.from_bytes(post[idx:idx + 2], "big")
        ann.add(po + idx, po + idx + 2,
                f"Wavelength {w + 1}: {wl_raw / 10:.0f} nm (raw=0x{wl_raw:04x})")
        idx += 2

    if idx + 13 > len(post):
        if idx < len(post):
            ann.add(po + idx, po + len(post),
                    f"[truncated reference block: {post[idx:].hex(' ')}]")
        return

    ann.add(po + idx, po + idx + 3, f"Ref padding A: {post[idx:idx+3].hex(' ')}")
    idx += 3
    ann.add1(po + idx, f"Ref constant A: 0x{post[idx]:02x} = {post[idx]}")
    idx += 1

    ref_hi = int.from_bytes(post[idx:idx + 2], "big")
    if ref_hi:
        ann.add(po + idx, po + idx + 2,
                f"Ref wavelength high: {ref_hi / 10:.0f} nm (raw=0x{ref_hi:04x})")
    else:
        ann.add(po + idx, po + idx + 2, "Ref wavelength high: 0 (unused)")
    idx += 2

    ref_lo = int.from_bytes(post[idx:idx + 2], "big")
    if ref_lo:
        ann.add(po + idx, po + idx + 2,
                f"Ref wavelength low: {ref_lo / 10:.0f} nm (raw=0x{ref_lo:04x})")
    else:
        ann.add(po + idx, po + idx + 2, "Ref wavelength low: 0 (unused)")
    idx += 2

    ann.add(po + idx, po + idx + 3, f"Ref padding B: {post[idx:idx+3].hex(' ')}")
    idx += 3
    ann.add1(po + idx, f"Ref constant B: 0x{post[idx]:02x} = {post[idx]}")
    idx += 1
    ann.add1(po + idx, f"Ref padding C: 0x{post[idx]:02x}")
    idx += 1

    if idx + 3 > len(post):
        if idx < len(post):
            ann.add(po + idx, po + len(post),
                    f"[truncated settling: {post[idx:].hex(' ')}]")
        return

    settling_flag = post[idx]
    ann.add1(po + idx,
             f"Settling flag: {'ENABLED' if settling_flag else 'disabled'} (0x{settling_flag:02x})")
    idx += 1
    settling_time = int.from_bytes(post[idx:idx + 2], "big")
    ann.add(po + idx, po + idx + 2, f"Settling time: {settling_time}s")
    idx += 2

    if idx + 11 > len(post):
        if idx < len(post):
            ann.add(po + idx, po + len(post),
                    f"[truncated trailer: {post[idx:].hex(' ')}]")
        return

    ann.add(po + idx, po + idx + 11,
            f"Fixed trailer (11 bytes): {post[idx:idx + 11].hex(' ')}")
    idx += 11

    if idx + 2 > len(post):
        return
    flashes = int.from_bytes(post[idx:idx + 2], "big")
    ann.add(po + idx, po + idx + 2, f"Flashes per well: {flashes}")
    idx += 2

    if idx + 4 <= len(post):
        ann.add(po + idx, po + idx + 4, f"Final trailer: {post[idx:idx + 4].hex(' ')}")
        idx += 4

    if idx < len(post):
        ann.add(po + idx, po + len(post), f"[unaccounted: {post[idx:].hex(' ')}]")


# -- RECV response decoders --

def decode_status_response(ann, payload, off):
    if len(payload) >= 5:
        flags = decode_status_flags(payload[:5])
        ann.add(off, off + 5, f"Status flags: {flags}")
        for i in range(5):
            ann.add1(off + i, f"  Byte {i}: 0x{payload[i]:02x}")
    if len(payload) >= 15:
        t1_raw = int.from_bytes(payload[11:13], "big")
        t2_raw = int.from_bytes(payload[13:15], "big")
        if t1_raw > 0 or t2_raw > 0:
            ann.add(off + 11, off + 13, f"Temperature bottom: {t1_raw / 10:.1f} C")
            ann.add(off + 13, off + 15, f"Temperature top: {t2_raw / 10:.1f} C")
    for i in range(5, min(len(payload), 11)):
        ann.add1(off + i, f"[unknown] 0x{payload[i]:02x}")
    for i in range(15, len(payload)):
        ann.add1(off + i, f"[unknown] 0x{payload[i]:02x}")


def decode_init_response(ann, payload, off):
    ann.add1(off, f"Command echo: INITIALIZE (0x{payload[0]:02x})")
    if len(payload) >= 6:
        ann.add(off + 1, off + 6, f"Status/config: {payload[1:6].hex(' ')}")
    if len(payload) >= 11:
        flags = decode_status_flags(payload[6:11])
        ann.add(off + 6, off + 11, f"Status flags: {flags}")
    for i in range(11, len(payload)):
        ann.add1(off + i, f"[unknown] 0x{payload[i]:02x}")


def decode_data_response(ann, payload, off):
    if len(payload) < 11:
        ann.add(off, off + len(payload), f"[data response too short: {len(payload)} bytes]")
        return

    ann.add1(off, f"Subcommand echo: 0x{payload[0]:02x}")
    ann.add1(off + 1, f"Command family echo: 0x{payload[1]:02x}")
    ann.add(off + 2, off + 6, f"[header bytes] {payload[2:6].hex(' ')}")

    schema = payload[6]
    schema_label = ABS_SCHEMA.get(schema, FL_SCHEMA.get(schema, f"unknown 0x{schema:02x}"))
    ann.add1(off + 6, f"Schema: 0x{schema:02x} = {schema_label}")

    total = int.from_bytes(payload[7:9], "big")
    complete = int.from_bytes(payload[9:11], "big")
    ann.add(off + 7, off + 9, f"Total values expected: {total}")
    ann.add(off + 9, off + 11, f"Complete count: {complete}")

    is_abs = (schema & 0x7F) == 0x29
    is_fl = (schema & 0x7F) == 0x21

    if is_abs and len(payload) >= 36:
        overflow = struct.unpack(">I", payload[11:15])[0]
        ann.add(off + 11, off + 15, f"Overflow: {overflow}")
        ann.add(off + 15, off + 18, f"[unknown header] {payload[15:18].hex(' ')}")

        wl_count = int.from_bytes(payload[18:20], "big")
        wells = int.from_bytes(payload[20:22], "big")
        ann.add(off + 18, off + 20, f"Wavelengths in response: {wl_count}")
        ann.add(off + 20, off + 22, f"Wells: {wells}")

        temp23 = int.from_bytes(payload[23:25], "big")
        ann.add(off + 22, off + 23, f"[unknown] 0x{payload[22]:02x}")
        ann.add(off + 23, off + 25,
                f"Temperature (offset 23): {temp23 / 10:.1f} C" if temp23 >= 50
                else f"Temperature (offset 23): {temp23} [inactive]")
        ann.add(off + 25, off + 34, f"[header continuation] {payload[25:34].hex(' ')}")

        temp34 = int.from_bytes(payload[34:36], "big")
        ann.add(off + 34, off + 36,
                f"Temperature (offset 34): {temp34 / 10:.1f} C" if temp34 >= 50
                else f"Temperature (offset 34): {temp34} [inactive]")

        data_start = 36
        expected_samples = wells * wl_count
        data_bytes = expected_samples * 4
        if data_start + data_bytes <= len(payload):
            ann.add(off + data_start, off + data_start + data_bytes,
                    f"Sample data: {expected_samples} values x 4 bytes = {data_bytes} bytes")
        else:
            ann.add(off + data_start, off + len(payload),
                    f"Data region: {len(payload) - data_start} bytes "
                    f"(expected {data_bytes} for {expected_samples} samples)")
        after_data = data_start + data_bytes
        remaining = len(payload) - after_data
        if remaining > 0:
            ann.add(off + after_data, off + len(payload),
                    f"Reference channels + calibration: {remaining} bytes")

    elif is_fl and len(payload) >= 34:
        overflow = struct.unpack(">I", payload[11:15])[0]
        ann.add(off + 11, off + 15, f"Overflow: {overflow}")
        ann.add(off + 15, off + 25, f"[FL header] {payload[15:25].hex(' ')}")

        temp_raw = int.from_bytes(payload[25:27], "big")
        ann.add(off + 25, off + 27,
                f"Temperature: {temp_raw / 10:.1f} C" if temp_raw >= 50
                else f"Temperature: {temp_raw} [inactive]")
        ann.add(off + 27, off + 34, f"[FL header continuation] {payload[27:34].hex(' ')}")

        data_start = 34
        data_count = complete
        data_bytes = data_count * 4
        if data_start + data_bytes <= len(payload):
            ann.add(off + data_start, off + data_start + data_bytes,
                    f"FL data: {data_count} values x 4 bytes = {data_bytes} bytes")
        remaining = len(payload) - data_start - data_bytes
        if remaining > 0:
            ann.add(off + data_start + data_bytes, off + len(payload),
                    f"[trailing bytes] {remaining} bytes")
    else:
        ann.add(off + 11, off + len(payload),
                f"[data payload: {len(payload) - 11} bytes, not fully decoded]")


def decode_eeprom_response(ann, payload, off):
    ann.add1(off, f"Subcommand echo: 0x{payload[0]:02x} (EEPROM)")
    ann.add1(off + 1, f"Command family echo: 0x{payload[1]:02x}")
    if len(payload) >= 4:
        machine_type = int.from_bytes(payload[2:4], "big")
        ann.add(off + 2, off + 4, f"Machine type code: 0x{machine_type:04x}")
    if len(payload) >= 15:
        ann.add(off + 4, off + 6, f"[unknown] {payload[4:6].hex(' ')}")
        ann.add(off + 6, off + 11, f"[unknown] {payload[6:11].hex(' ')}")
        ann.add1(off + 11, f"has_absorbance: {bool(payload[11])}")
        ann.add1(off + 12, f"has_fluorescence: {bool(payload[12])}")
        ann.add1(off + 13, f"has_luminescence: {bool(payload[13])}")
        ann.add1(off + 14, f"has_alpha_technology: {bool(payload[14])}")
    if len(payload) > 15:
        ann.add(off + 15, off + len(payload),
                f"[EEPROM data continuation: {len(payload) - 15} bytes]")


def decode_firmware_response(ann, payload, off):
    ann.add1(off, f"Subcommand echo: 0x{payload[0]:02x} (FW_INFO)")
    ann.add1(off + 1, f"Command family echo: 0x{payload[1]:02x}")
    if len(payload) >= 8:
        ann.add(off + 2, off + 6, f"[header] {payload[2:6].hex(' ')}")
        version_raw = int.from_bytes(payload[6:8], "big")
        ann.add(off + 6, off + 8,
                f"Firmware version: {version_raw / 1000:.2f} (raw={version_raw})")
    if len(payload) >= 20:
        build_date = payload[8:20].split(b"\x00")[0].decode("ascii", errors="replace")
        ann.add(off + 8, off + 20, f'Build date: "{build_date}"')
    if len(payload) >= 28:
        build_time = payload[20:28].split(b"\x00")[0].decode("ascii", errors="replace")
        ann.add(off + 20, off + 28, f'Build time: "{build_time}"')
    if len(payload) > 28:
        ann.add(off + 28, off + len(payload),
                f"[unknown trailing: {payload[28:].hex(' ')}]")


def decode_run_response(ann, payload, off):
    cmd_echo = payload[0]
    accepted = cmd_echo == 0x03
    ann.add1(off, f"Command echo: 0x{cmd_echo:02x} ({'ACCEPTED' if accepted else 'REJECTED'})")
    if len(payload) >= 4:
        ann.add(off + 1, off + 4, f"Status bytes: {payload[1:4].hex(' ')}")
    if len(payload) >= 14:
        ann.add(off + 4, off + 12, f"[run response data] {payload[4:12].hex(' ')}")
        total = int.from_bytes(payload[12:14], "big")
        ann.add(off + 12, off + 14, f"Total measurement values: {total}")
    for i in range(14, len(payload)):
        ann.add1(off + i, f"[unknown] 0x{payload[i]:02x}")


def decode_0x17_response(ann, payload, off):
    ann.add1(off, f"Subcommand echo: 0x{payload[0]:02x}")
    ann.add1(off + 1, f"Command family echo: 0x{payload[1]:02x}")
    if len(payload) >= 4:
        ann.add(off + 2, off + 4, f"Status/flags: {payload[2:4].hex(' ')}")
    for i in range(4, len(payload)):
        ann.add1(off + i, f"[unknown] 0x{payload[i]:02x} = {payload[i]}")


def decode_read_order_response(ann, payload, off):
    ann.add1(off, f"Subcommand echo: 0x{payload[0]:02x} (READ_ORDER)")
    ann.add1(off + 1, f"Command family echo: 0x{payload[1]:02x}")
    if len(payload) >= 19:
        ann.add(off + 2, off + 6, f"[header] {payload[2:6].hex(' ')}")
        ann.add1(off + 6, f"Num columns: {payload[6]}")
        ann.add1(off + 7, f"Num rows: {payload[7]}")
        ann.add(off + 8, off + 17, f"[header continuation] {payload[8:17].hex(' ')}")
        n_entries = int.from_bytes(payload[17:19], "big")
        ann.add(off + 17, off + 19, f"Well count: {n_entries}")
        data = payload[19:]
        if len(data) >= n_entries * 2:
            positions = []
            for i in range(min(n_entries, 5)):
                positions.append(f"({data[i * 2]},{data[i * 2 + 1]})")
            summary = ", ".join(positions)
            if n_entries > 5:
                summary += f", ... ({n_entries} total)"
            ann.add(off + 19, off + 19 + n_entries * 2,
                    f"Read order (col,row 1-based): {summary}")


# -- Main dispatch --

def decode_frame(direction: str, raw: bytes) -> Annotation:
    """Decode a complete CLARIOstar frame into byte-level annotations."""
    ann = Annotation(raw)
    decode_envelope(ann, raw)

    if len(raw) < 7:
        return ann

    payload = raw[4:-3]
    off = 4

    if len(payload) == 0:
        return ann

    cmd = payload[0]

    if direction == "SEND":
        if cmd == 0x01:
            decode_initialize_cmd(ann, payload, off)
        elif cmd == 0x03:
            decode_drawer_cmd(ann, payload, off)
        elif cmd == 0x04:
            decode_measurement_run(ann, payload, off)
        elif cmd == 0x05:
            decode_cmd05(ann, payload, off)
        elif cmd == 0x06:
            decode_temperature_cmd(ann, payload, off)
        elif cmd == 0x08:
            decode_cmd08(ann, payload, off)
        elif cmd == 0x80:
            decode_status_query_cmd(ann, payload, off)
        elif cmd == 0x81:
            decode_hw_status_cmd(ann, payload, off)
        else:
            ann.add(off, off + len(payload),
                    f"[unknown command 0x{cmd:02x}, {len(payload)} bytes]")
    else:  # RECV
        if cmd == 0x01:
            decode_init_response(ann, payload, off)
        elif cmd == 0x03:
            decode_run_response(ann, payload, off)
        elif cmd == 0x07:
            decode_eeprom_response(ann, payload, off)
        elif cmd == 0x09:
            decode_firmware_response(ann, payload, off)
        elif cmd == 0x17:
            decode_0x17_response(ann, payload, off)
        elif cmd == 0x1D or cmd == 0x1d:
            decode_read_order_response(ann, payload, off)
        elif cmd == 0x02 or cmd == 0x21:
            decode_data_response(ann, payload, off)
        elif len(payload) >= 5 and all(
            payload[i] == 0 or any(
                payload[bi] & m for bi, m, _ in STATUS_FLAGS if bi == i
            )
            for i in range(min(5, len(payload)))
        ):
            decode_status_response(ann, payload, off)
        else:
            ann.add(off, off + len(payload),
                    f"[unknown response, first byte 0x{cmd:02x}, {len(payload)} bytes]")

    return ann


# ═══════════════════════════════════════════════════════════════════════════════
# File I/O helpers
# ═══════════════════════════════════════════════════════════════════════════════

def write_frames_txt(frames: List[Tuple[float, str, bytes]], output_path: str,
                     source_name: str = ""):
    """Write extracted frames to a _frames.txt file."""
    with open(output_path, "w") as f:
        f.write(f"# CLARIOstar protocol frames extracted from {source_name}\n")
        f.write(f"# Total frames: {len(frames)}\n")
        f.write(f"# Format: TIME_S DIRECTION DESCRIPTION | HEX\n")
        f.write(f"#\n")
        for rel_s, direction, frame in frames:
            desc = describe_frame(frame)
            hex_str = frame.hex(" ")
            f.write(f"{rel_s:10.3f}s {direction:4s} {desc:<40s} | {hex_str}\n")


def read_frames_txt(input_path: str) -> List[Tuple[str, str, str, bytes]]:
    """Read a _frames.txt file. Returns list of (time_str, direction, desc, raw_bytes)."""
    result = []
    with open(input_path) as f:
        for line in f:
            if line.startswith("#") or not line.strip():
                continue
            parts = line.split("|", 1)
            if len(parts) < 2:
                continue
            header = parts[0].strip()
            hex_str = parts[1].strip()
            tokens = header.split(None, 2)
            if len(tokens) < 3:
                continue
            raw = bytes.fromhex(hex_str.replace(" ", ""))
            result.append((tokens[0], tokens[1], tokens[2], raw))
    return result


def write_decoded_txt(input_path: str, output_path: str):
    """Read a _frames.txt file and write a _decoded.txt file."""
    entries = read_frames_txt(input_path)
    lines_out = []
    for i, (time_str, direction, desc, raw) in enumerate(entries, 1):
        lines_out.append("")
        lines_out.append(f"{'=' * 80}")
        lines_out.append(f"Frame #{i} @ {time_str} {direction} {desc} ({len(raw)} bytes)")
        lines_out.append(f"  Raw: {raw.hex(' ')}")
        lines_out.append(f"{'=' * 80}")
        ann = decode_frame(direction, raw)
        lines_out.append(ann.render())

    with open(output_path, "w") as f:
        f.write("\n".join(lines_out) + "\n")
    return len(entries)


# ═══════════════════════════════════════════════════════════════════════════════
# CLI
# ═══════════════════════════════════════════════════════════════════════════════

def _cli_extract(target: Path):
    if target.is_file() and target.suffix == ".pcapng":
        pcaps = [target]
    elif target.is_dir():
        pcaps = sorted(target.glob("*.pcapng"))
        if not pcaps:
            print(f"No .pcapng files found in {target}")
            return
    else:
        print(f"Not a .pcapng file or directory: {target}")
        return

    print(f"Extracting frames from {len(pcaps)} pcapng file(s):\n")
    for pcap in pcaps:
        frames = extract_frames(str(pcap))
        out_path = str(pcap).replace(".pcapng", "_frames.txt")
        write_frames_txt(frames, out_path, os.path.basename(str(pcap)))
        print(f"  {pcap.name}: {len(frames)} frames -> {os.path.basename(out_path)}")
    print("\nDone.")


def _cli_decode(target: Path):
    if target.is_file() and str(target).endswith("_frames.txt"):
        files = [target]
    elif target.is_dir():
        files = sorted(target.glob("*_frames.txt"))
        if not files:
            print(f"No _frames.txt files found in {target}")
            return
    else:
        print(f"Not a _frames.txt file or directory: {target}")
        return

    print(f"Decoding {len(files)} file(s):\n")
    for f in files:
        out_path = str(f).replace("_frames.txt", "_decoded.txt")
        n = write_decoded_txt(str(f), out_path)
        print(f"  {f.name} -> {os.path.basename(out_path)} ({n} frames)")
    print("\nDone.")


def main():
    usage = (
        f"Usage: {sys.argv[0]} <command> <path>\n"
        f"Commands: extract, decode, both"
    )
    if len(sys.argv) != 3:
        print(usage)
        sys.exit(1)

    cmd = sys.argv[1]
    target = Path(sys.argv[2])

    if cmd == "extract":
        _cli_extract(target)
    elif cmd == "decode":
        _cli_decode(target)
    elif cmd == "both":
        _cli_extract(target)
        print()
        _cli_decode(target)
    else:
        print(f"Unknown command: {cmd}\n{usage}")
        sys.exit(1)


if __name__ == "__main__":
    main()
