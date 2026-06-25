"""Persistent client for the PreciseVision engine - the second server behind a camera-gripper arm.

The vision engine runs on a different host from the TCS controller and speaks a credential-free text
property protocol on :1450 (``property get/set <name> [args]``, reply ``0 <value>`` or a negative
code) and pushes JPEG image results on :1500. The OEM GUI holds one connection per port for a whole
session and triggers each frame with ``property set system.cameraacquire <N>``; this driver mirrors
that - ``setup()`` opens and holds both. The driver speaks the wire protocol only: ``property
get/set`` on :1450 and ``read_next_record()`` for the framed :1500 results. The trigger-and-decode
orchestration (``capture_image``) lives in the vision backend, one layer up. The connect "handshake"
is just informational property reads (no auth).

Engine protocol confirmed from the 2026-06-22 captures (per-frame trigger = ``cameraacquire``, framing
below). Open hardware item: whether a freshly-opened :1500 socket receives the pushed frame the way
the GUI's held-from-connect socket does - hence both connections are held from ``setup()``.
"""

import io
import logging
from typing import Optional, Tuple

from pylabrobot.capabilities.capability import BackendParams
from pylabrobot.device import Driver
from pylabrobot.io.socket import Socket

try:
  import numpy as np
except ImportError:
  np = None  # type: ignore[assignment]

try:
  from PIL import Image as PILImage
except ImportError:
  PILImage = None  # type: ignore[assignment]

logger = logging.getLogger(__name__)

ENGINE_PROPERTY_PORT = 1450  # text command/query protocol
ENGINE_IMAGE_PORT = 1500  # binary stream carrying the pushed "Primary Image [n]" JPEG results

# Result framing on :1500 (confirmed live from the 2026-06-22 capture): the engine pushes a sequence
# of length-prefixed records, each a fixed 16-byte header then the result name then the data -
#
#   01 | name_len (u8) | 00 00 00 | data_len (u32 LE) | 00 00 00 00 00 00 00 | <name> | <data>
#
# For a "Primary Image [n]" record the data is the JPEG (FFD8...FFD9) and data_len is its exact byte
# count (verified to land on the EOI for 52/52 frames). The stream interleaves non-image records too
# (e.g. "VisionResults[led]" tool results), framed identically. Parsing by the announced data_len -
# rather than scanning the payload for FFD8/FFD9 - is O(1) per record, demuxes the non-image records,
# and never inspects the JPEG, so an embedded thumbnail or restart marker cannot mis-frame it. The
# parser stays aligned by always consuming exactly one whole record; a freshly held stream starts on a
# record boundary.
_RECORD_HEADER_LEN = 16
_MAX_IMAGE_BYTES = (
  16 * 1024 * 1024
)  # sanity cap: a record this large signals a desync, not a real frame


def parse_engine_reply(reply: str) -> Optional[str]:
  """The data of a ``0 <value>`` success reply, or ``None`` for a negative error code (e.g. ``-4017``)."""
  code, _, rest = reply.partition(" ")
  return rest if code == "0" else None


def _drain_named_record(buf: bytearray) -> Optional[Tuple[str, bytes]]:
  """Pop the next complete ``(name, data)`` result record from the front of ``buf``, consuming it.

  Reads the engine's fixed 16-byte record header (see the module comment): the name length, the
  little-endian ``data_len``, then ``name_len`` name bytes and exactly ``data_len`` data bytes. Parsing
  by the announced length never inspects the payload, so a JPEG's internal markers cannot mis-frame it,
  and the same path frames the interleaved non-image records. Returns ``None`` while the full record has
  not arrived yet. Assumes ``buf`` begins on a record boundary, which a freshly held stream does.

  Raises:
    ValueError: if the header is not a record start (``buf[0] != 0x01``) or declares an implausibly
      large ``data_len`` - both signal a desynchronised stream, which has no safe silent recovery.
  """
  if len(buf) < _RECORD_HEADER_LEN:
    return None
  if buf[0] != 0x01:
    raise ValueError(
      f"PreciseVision image stream desync: record starts with {buf[0]:#04x}, not 0x01"
    )
  name_len = buf[1]
  data_len = int.from_bytes(buf[5:9], "little")
  if data_len > _MAX_IMAGE_BYTES:
    raise ValueError(
      f"PreciseVision record declares an implausible data length of {data_len} bytes"
    )
  end = _RECORD_HEADER_LEN + name_len + data_len
  if len(buf) < end:
    return None
  name = bytes(buf[_RECORD_HEADER_LEN : _RECORD_HEADER_LEN + name_len]).decode("ascii", "replace")
  data = bytes(buf[_RECORD_HEADER_LEN + name_len : end])
  del buf[:end]
  return name, data


def decode_jpeg(jpeg: bytes) -> "np.ndarray":
  """Decode an engine JPEG frame to an RGB ``numpy`` array (height x width x 3, ``uint8``)."""
  if np is None or PILImage is None:
    raise ImportError(
      "Pillow and numpy are required to decode camera images; install them with "
      '`pip install "PyLabRobot[precise-flex-vision]"`.'
    )
  return np.asarray(PILImage.open(io.BytesIO(jpeg)))


class PreciseVisionDriver(Driver):
  """Persistent client for the PreciseVision engine (property ``:1450`` + image stream ``:1500``).

  Separate from the arm's ``PreciseFlexDriver`` - a different host and protocol. Holds both
  connections open for the session, mirroring the OEM GUI; exposes ``property get/set`` and
  ``read_next_record`` for the framed :1500 image stream. The backend composes those into
  ``capture_image``.
  """

  def __init__(
    self,
    host: str,
    *,
    property_port: int = ENGINE_PROPERTY_PORT,
    image_port: int = ENGINE_IMAGE_PORT,
    timeout: float = 5.0,
  ) -> None:
    super().__init__()
    self.io_property = Socket(
      human_readable_device_name="PreciseVision engine (property)", host=host, port=property_port
    )
    self.io_image = Socket(
      human_readable_device_name="PreciseVision engine (image)", host=host, port=image_port
    )
    self.timeout = timeout
    # The held :1500 stream is read in chunks and a record can span reads, so a read that times out
    # mid-record leaves a partial record buffered. Carrying this buffer across read_next_record calls
    # (rather than a fresh local one each time) keeps the next read frame-aligned, so one timeout
    # cannot desync every later read.
    self._image_buf = bytearray()

  async def setup(self, backend_params: Optional[BackendParams] = None) -> None:
    """Open and hold both engine connections (property + image stream)."""
    await self.io_property.setup()
    await self.io_image.setup()
    self._image_buf.clear()  # a fresh stream; drop anything buffered from a previous session
    logger.info(
      "[PreciseVision %s] connected: property=%s image=%s",
      self.io_property._host,
      self.io_property._port,
      self.io_image._port,
    )

  async def stop(self) -> None:
    """Close both engine connections."""
    await self.io_image.stop()
    await self.io_property.stop()

  # -- command/reply (:1450) -----------------------------------------------

  async def send_command(self, command: str) -> Optional[str]:
    """Write one engine command line and return its success value (``None`` on a negative reply).

    The :1450 text protocol's raw command/reply primitive. The backend wraps it with the ``property
    get`` / ``property set`` grammar (``request_parameter`` / ``set_parameter``).
    """
    await self.io_property.write(command.encode("utf-8") + b"\r\n")
    reply = (await self.io_property.readline()).decode("utf-8", "replace").strip()
    return parse_engine_reply(reply)

  # -- image stream (:1500) ------------------------------------------------

  async def read_next_record(self, timeout: Optional[float] = None) -> Optional[Tuple[str, bytes]]:
    """Read the next complete ``(name, data)`` result off the held :1500 stream, or ``None`` at its end.

    Returns a record already buffered if there is one, otherwise reads from the socket until a whole
    record has arrived (framing in the module comment). ``None`` means the stream closed before a full
    record. Partial bytes from a timed-out read stay in ``self._image_buf``, so the next call resumes
    frame-aligned rather than mid-record. This is the transport primitive; the trigger / camera-match /
    decode policy is the backend's ``capture_image``.

    Raises:
      TimeoutError: if no bytes arrive within ``timeout`` (default ``self.timeout``).
      ValueError: if the stream has desynchronised (see ``_drain_named_record``).
    """
    buf = self._image_buf
    while True:
      record = _drain_named_record(buf)
      if record is not None:
        return record
      chunk = await self.io_image.read(65_536, timeout=self.timeout if timeout is None else timeout)
      if not chunk:
        return None
      buf += chunk
