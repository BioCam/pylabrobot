"""Framing tests, against the frames in ``recordings/``."""

import unittest

from pylabrobot.bmg_labtech.clariostar.driver.errors import (
  ChecksumError,
  FrameError,
)
from pylabrobot.bmg_labtech.clariostar.driver.framing import (
  ftdi_extract_payload,
  ftdi_validate_frame,
  ftdi_wrap_payload,
  usb_packet_type,
  usb_total_length,
  usb_wrap_payload,
)
from pylabrobot.bmg_labtech.clariostar.driver.recordings import (
  load_exchanges,
)

RECORDINGS = {
  name: load_exchanges(name)
  for name in (
    "clariostar_plus_ftdi_2020_v1_driver.json",
    "clariostar_plus_ftdi_2020_oem_software.json",
    "clariostar_plus_ftdi_2020_oem_software_refused.json",
    "clariostar_plus_ftdi_2020_previous_driver.json",
  )
}
# Every recorded exchange whose reply arrived whole.
RECORDED = [
  exchange
  for exchanges in RECORDINGS.values()
  for name, exchange in exchanges.items()
  if name != "status_truncated"
]
STATUS_QUERY_FRAME, STATUS_REPLY_FRAME = load_exchanges(
  "clariostar_plus_ftdi_2020_oem_software.json"
)["status_plate_detected"]


class FTDIFramingTests(unittest.TestCase):
  def test_wrap_reproduces_every_recorded_sent_frame(self):
    for sent, _ in RECORDED:
      self.assertEqual(ftdi_wrap_payload(ftdi_extract_payload(sent)), sent)
    self.assertEqual(ftdi_wrap_payload(b"\x80"), STATUS_QUERY_FRAME)

  def test_every_recorded_frame_validates(self):
    for sent, received in RECORDED:
      ftdi_validate_frame(sent)
      ftdi_validate_frame(received)
      self.assertEqual(len(ftdi_extract_payload(received)), len(received) - 8)

  def test_recorded_truncated_reply_fails(self):
    _, truncated = RECORDINGS["clariostar_plus_ftdi_2020_v1_driver.json"]["status_truncated"]
    with self.assertRaises(FrameError):
      ftdi_validate_frame(truncated)

  def test_checksum_is_three_bytes(self):
    # 300 bytes of 0xFF sum past 16 bits; the checksum must keep the high byte.
    frame = ftdi_wrap_payload(b"\xff" * 300)
    self.assertEqual(int.from_bytes(frame[-4:-1], "big"), sum(frame[:-4]) & 0xFFFFFF)
    self.assertGreater(int.from_bytes(frame[-4:-1], "big"), 0xFFFF)
    ftdi_validate_frame(frame)

  def test_corrupted_byte_fails_checksum(self):
    frame = bytearray(STATUS_REPLY_FRAME)
    frame[6] ^= 0x01
    with self.assertRaises(ChecksumError):
      ftdi_validate_frame(bytes(frame))

  def test_truncated_frame_fails(self):
    with self.assertRaises(FrameError):
      ftdi_validate_frame(STATUS_REPLY_FRAME[:-1])
    with self.assertRaises(FrameError):
      ftdi_validate_frame(STATUS_REPLY_FRAME[:5])


class USBFramingTests(unittest.TestCase):
  def test_short_payload_is_one_packet(self):
    self.assertEqual(usb_wrap_payload(b"\x80"), [bytes.fromhex("000c010000000180")])

  def test_57_bytes_fill_one_packet(self):
    (packet,) = usb_wrap_payload(bytes(range(57)))
    self.assertEqual(len(packet), 64)
    self.assertEqual(packet[:7], bytes.fromhex("000c0100000039"))

  def test_long_payload_splits_into_first_and_continuations(self):
    payload = bytes(i & 0xFF for i in range(130))
    packets = usb_wrap_payload(payload)
    self.assertEqual([len(p) for p in packets], [64, 64, 23])
    self.assertEqual(packets[0][:7], bytes.fromhex("000c0200000082"))
    self.assertEqual(packets[1][:7], bytes.fromhex("000c0300000001"))
    self.assertEqual(packets[2][:7], bytes.fromhex("000c0300000002"))
    self.assertEqual(b"".join(p[7:] for p in packets), payload)
    self.assertEqual(usb_total_length(packets[0]), 130)

  def test_empty_payload_rejected(self):
    with self.assertRaises(ValueError):
      usb_wrap_payload(b"")

  def test_packet_type_requires_header(self):
    self.assertEqual(usb_packet_type(bytes.fromhex("000c010000000180")), 0x01)
    with self.assertRaises(FrameError):
      usb_packet_type(STATUS_QUERY_FRAME)


if __name__ == "__main__":
  unittest.main()
