"""Talk to a Hamilton machine through Hamilton's own COM transport instead of libusb.

On Windows the Hamilton driver (``STAR_USB_x64``) claims the USB interface, so PyUSB cannot.
The usual workaround is to rebind the device to WinUSB with Zadig, which breaks Venus. This
transport avoids that entirely by going through Hamilton's ``HxUsbComm`` COM server - the same
path Venus uses - so PyLabRobot and Venus can share a machine sequentially, with the vendor
driver left in place.

The COM server is a 32-bit in-process DLL, so it cannot be loaded by a 64-bit Python. A small
32-bit PowerShell bridge (``hamilton_com_bridge.ps1``) hosts it and relays a line protocol over
stdin/stdout.

Requires a Hamilton installation: without it neither the COM server nor ``ML_STAR.cfg`` exists.
On a machine with no Venus, use :class:`~pylabrobot.io.usb.USB` with a WinUSB/libusb binding
instead - there is no Venus to conflict with there. :func:`hamilton_com_available` reports
which case applies.
"""

import asyncio
import logging
import os
import subprocess
import threading
import time
from typing import Optional

from pylabrobot.io.capture import capturer, get_capture_or_validation_active
from pylabrobot.io.io import IOBase
from pylabrobot.io.usb import USE_USB, USB, USBCommand
from pylabrobot.io.validation_utils import LOG_LEVEL_IO

logger = logging.getLogger(__name__)

DEFAULT_CFG_PATH = r"C:\Program Files (x86)\HAMILTON\Config\ML_STAR.cfg"
DEFAULT_POWERSHELL = r"C:\Windows\SysWOW64\WindowsPowerShell\v1.0\powershell.exe"
BRIDGE_SCRIPT = os.path.join(os.path.dirname(os.path.abspath(__file__)), "hamilton_com_bridge.ps1")

# HxUsbComm's COM class, registered by the Hamilton installer under the 32-bit view.
HXUSBIO_CLSID = "{206068AC-E65F-4243-AEE5-E8854150B8DC}"

ID_VENDOR = 0x08AF
ID_PRODUCT = 0x8000


def _com_server_registered() -> bool:
  """Whether Hamilton's HxUsbComm COM server is registered on this machine."""
  if os.name != "nt":
    return False
  try:
    import winreg
  except ImportError:  # pragma: no cover - Windows only
    return False
  for view in (winreg.KEY_WOW64_32KEY, winreg.KEY_WOW64_64KEY):
    try:
      with winreg.OpenKey(
        winreg.HKEY_LOCAL_MACHINE,
        rf"SOFTWARE\Classes\CLSID\{HXUSBIO_CLSID}\InprocServer32",
        0,
        winreg.KEY_READ | view,
      ):
        return True
    except OSError:
      continue
  return False


def hamilton_com_available(cfg_path: str = DEFAULT_CFG_PATH) -> bool:
  """Whether this machine can use the COM transport.

  Needs Windows, a 32-bit PowerShell to host the in-process COM server, the server itself, and
  the config file that ``InitFromCfgFil`` is given - in other words, a Hamilton installation.
  """
  return (
    os.name == "nt"
    and os.path.exists(DEFAULT_POWERSHELL)
    and _com_server_registered()
    and os.path.exists(cfg_path)
  )


def resolve_star_io(
  cfg_path: str = DEFAULT_CFG_PATH,
  device_address: Optional[int] = None,
  serial_number: Optional[str] = None,
  write_timeout: int = 30,
  prefer: Optional[str] = None,
) -> IOBase:
  """Pick the right transport for a STAR on this machine.

  The two Windows cases are complementary rather than competing:

  * **Hamilton software installed** - use the COM transport. The vendor driver owns the USB
    interface, so libusb cannot claim it; rebinding with Zadig would work but breaks Venus.
  * **No Hamilton software** - nothing claims the device, so libusb (via a WinUSB binding)
    is the right answer and there is no Venus to conflict with.

  Args:
    cfg_path: path to ``ML_STAR.cfg`` for the COM transport.
    device_address: USB device address, for the libusb transport.
    serial_number: USB serial number, for the libusb transport.
    write_timeout: write timeout in seconds, for the libusb transport.
    prefer: force a choice - ``"com"`` or ``"usb"``. Raises if that one is unavailable.

  Raises:
    HamiltonComBridgeError: if neither transport is usable, with what to install.
  """
  com_ok = hamilton_com_available(cfg_path)

  if prefer == "com":
    if not com_ok:
      raise HamiltonComBridgeError(
        "COM transport requested but unavailable. It needs Windows, 32-bit PowerShell, the "
        f"HxUsbComm COM server, and {cfg_path} - i.e. a Hamilton/Venus installation."
      )
    logger.info("STAR transport: Hamilton COM (forced)")
    return HamiltonComIO(cfg_path=cfg_path)

  if prefer == "usb":
    if not USE_USB:
      raise HamiltonComBridgeError(
        "libusb transport requested but pyusb/libusb_package are not installed. "
        "Install them with: pip install pylabrobot[usb]"
      )
    logger.info("STAR transport: libusb (forced)")
    return USB(
      human_readable_device_name="Hamilton",
      id_vendor=ID_VENDOR,
      id_product=ID_PRODUCT,
      device_address=device_address,
      serial_number=serial_number,
      write_timeout=write_timeout,
    )

  if com_ok:
    logger.info("STAR transport: Hamilton COM (Hamilton installation detected)")
    return HamiltonComIO(cfg_path=cfg_path)

  if USE_USB:
    logger.info("STAR transport: libusb (no Hamilton installation detected)")
    return USB(
      human_readable_device_name="Hamilton",
      id_vendor=ID_VENDOR,
      id_product=ID_PRODUCT,
      device_address=device_address,
      serial_number=serial_number,
      write_timeout=write_timeout,
    )

  raise HamiltonComBridgeError(
    "No usable transport for the Hamilton STAR.\n"
    "\n"
    "Two options, easiest first:\n"
    "  1. Install libusb support:  pip install pylabrobot[usb]\n"
    "     On Windows you must also bind the STAR to WinUSB with Zadig. Note that this takes\n"
    "     the device away from Hamilton's own driver, so do not do it on a PC that runs\n"
    "     Venus.\n"
    "  2. Install the Hamilton/Venus software, which provides the COM transport used here.\n"
    "     This keeps the vendor driver in place, so PyLabRobot and Venus can share the\n"
    "     machine.\n"
    f"\n(checked: os={os.name}, com_server={_com_server_registered()}, "
    f"cfg_exists={os.path.exists(cfg_path)}, pyusb={USE_USB})"
  )


class HamiltonComBridgeError(RuntimeError):
  """The bridge process reported an error or died."""


class HamiltonComIO(IOBase):
  """IO for a Hamilton machine over Hamilton's own COM transport.

  ``write`` maps to ``HxUSBIO.Send``. Replies arrive asynchronously on the COM ``OnReceive``
  event, which the bridge queues; ``read`` polls that queue and returns ``b""`` when nothing is
  waiting, which is what :class:`~pylabrobot.hamilton.protocol.text.router.ReplyRouter` expects.
  """

  def __init__(
    self,
    cfg_path: str = DEFAULT_CFG_PATH,
    powershell: str = DEFAULT_POWERSHELL,
    bridge_script: str = BRIDGE_SCRIPT,
    default_read_timeout: float = 0.5,
    poll_interval: float = 0.02,
    startup_timeout: float = 30.0,
  ):
    """
    Args:
      cfg_path: path to ``ML_STAR.cfg``, passed to ``InitFromCfgFil``.
      powershell: path to the 32-bit PowerShell that hosts the COM server.
      bridge_script: path to the bridge script.
      default_read_timeout: how long ``read`` waits for a reply before returning ``b""``.
      poll_interval: how often ``read`` polls the bridge while waiting.
      startup_timeout: how long to wait for the transport to connect.
    """
    super().__init__()

    if get_capture_or_validation_active():
      raise RuntimeError("Cannot create a new HamiltonComIO while capture or validation is active")

    self.cfg_path = cfg_path
    self.powershell = powershell
    self.bridge_script = bridge_script
    self.default_read_timeout = default_read_timeout
    self.poll_interval = poll_interval
    self.startup_timeout = startup_timeout

    self._proc: Optional[subprocess.Popen] = None
    # One transaction at a time: the router's reader thread polls `read` while the main loop
    # writes, and both share the bridge's stdin/stdout pipe.
    self._lock = threading.Lock()

    self._unique_id = f"[{hex(ID_VENDOR)}:{hex(ID_PRODUCT)}][][]"

  # -- bridge plumbing -------------------------------------------------------

  def _transact(self, line: str) -> str:
    """Send one protocol line and return the one-line answer. Blocking; hold `_lock`."""
    proc = self._proc
    if proc is None or proc.poll() is not None:
      raise HamiltonComBridgeError("bridge process is not running")
    assert proc.stdin is not None and proc.stdout is not None

    proc.stdin.write(line + "\n")
    proc.stdin.flush()

    answer = proc.stdout.readline()
    if answer == "":
      raise HamiltonComBridgeError("bridge process closed its output")
    return answer.strip()

    # note: the protocol is strictly one answer per line, so no framing is needed here.

  async def _transact_async(self, line: str) -> str:
    def run() -> str:
      with self._lock:
        return self._transact(line)

    return await asyncio.get_event_loop().run_in_executor(None, run)

  # -- IOBase ----------------------------------------------------------------

  async def setup(self, empty_buffer: bool = True):
    """Start the bridge and open the transport."""
    if not os.path.exists(self.powershell):
      raise HamiltonComBridgeError(f"32-bit PowerShell not found at {self.powershell}")
    if not os.path.exists(self.cfg_path):
      raise HamiltonComBridgeError(
        f"{self.cfg_path} not found - a Hamilton installation is required for the COM transport"
      )

    self._proc = subprocess.Popen(
      [
        self.powershell,
        "-NonInteractive",
        "-NoProfile",
        "-ExecutionPolicy",
        "Bypass",
        "-File",
        self.bridge_script,
      ],
      stdin=subprocess.PIPE,
      stdout=subprocess.PIPE,
      stderr=subprocess.PIPE,
      text=True,
      encoding="utf-8",
      errors="replace",
      bufsize=1,
    )

    logger.info("HamiltonComIO: bridge started (pid %s)", self._proc.pid)

    answer = await self._transact_async(f"CONNECT {self.cfg_path}")
    if answer != "OK":
      await self.stop()
      raise HamiltonComBridgeError(
        f"could not open the Hamilton COM transport: {answer}. "
        "Is Venus or the Maintenance & Verification runner holding the instrument?"
      )
    logger.info("HamiltonComIO: connected via %s", self.cfg_path)

  async def write(self, data: bytes, timeout: Optional[float] = None):
    command = data.decode("utf-8")
    logger.log(LOG_LEVEL_IO, "%s write: %s", self._unique_id, command)

    answer = await self._transact_async(f"W {command}")
    if answer != "OK":
      raise HamiltonComBridgeError(f"write failed: {answer}")

    capturer.record(
      USBCommand(module="usb", device_id=self._unique_id, action="write", data=command)
    )

  async def read(self, timeout: Optional[float] = None, size: Optional[int] = None) -> bytes:
    """Return one queued reply, or ``b""`` if none arrives before the timeout."""
    if timeout is None:
      timeout = self.default_read_timeout
    deadline = time.time() + timeout

    while True:
      answer = await self._transact_async("R")

      if answer.startswith("D "):
        payload = answer[2:]
        logger.log(LOG_LEVEL_IO, "%s read: %s", self._unique_id, payload)
        capturer.record(
          USBCommand(module="usb", device_id=self._unique_id, action="read", data=payload)
        )
        data = payload.encode("utf-8")
        return data[:size] if size is not None else data

      if answer.startswith("ERR"):
        raise HamiltonComBridgeError(f"read failed: {answer}")

      if time.time() >= deadline:
        return b""
      await asyncio.sleep(self.poll_interval)

  async def stop(self):
    """Close the transport and stop the bridge. Safe to call more than once."""
    if self._proc is None:
      return

    try:
      await self._transact_async("QUIT")
    except HamiltonComBridgeError:
      pass

    try:
      self._proc.wait(timeout=5)
    except subprocess.TimeoutExpired:
      self._proc.kill()
    finally:
      for stream in (self._proc.stdin, self._proc.stdout, self._proc.stderr):
        if stream is not None:
          try:
            stream.close()
          except OSError:
            pass
      self._proc = None
      logger.info("HamiltonComIO: bridge stopped")

  def serialize(self) -> dict:
    return {"cfg_path": self.cfg_path, "transport": "hamilton_com"}
