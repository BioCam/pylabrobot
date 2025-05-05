from typing import Optional
from sensirion_shdlc_driver import ShdlcSerialPort, ShdlcConnection
from sensirion_shdlc_sensorbridge import (
  SensorBridgeShdlcDevice,
  SensorBridgeI2cProxy,
  SensorBridgePort
)
from sensirion_i2c_driver import I2cConnection
from sensirion_i2c_sht.sht3x import Sht3xI2cDevice

from pylabrobot.sensors.temperature_backend import TemperatureSensorBackend
from pylabrobot.sensors.humidity_backend import HumiditySensorBackend

class SensirionSCC30Backend(TemperatureSensorBackend, HumiditySensorBackend):
  """
  Sensirion cat. no.:
    - SCC30 cat. no.: SEK-SCC30-DB-Sensor (https://sensirion.com/products/catalog/SCC30-DB)
    - SensorBridge cat. no.:  SEK-SensorBridge
  PLR backend for Sensirion SCC30-DB sensor module using the
    Sensirion SensorBridge connector.
  Sensirion SCC30-DB is a digital temperature and humidity sensor module that
    uses a SHT3x chip as the actual sensor.
  It communicates over I2C and is connected to a SensorBridge.
  """

  def __init__(
    self,
    port: str,
    bridge_port: SensorBridgePort = SensorBridgePort.ONE,
    i2c_voltage: float = 3.3,
    i2c_frequency: float = 100e3,
    slave_address: int = 0
  ):
    self._com_port = port
    self._bridge_port = bridge_port
    self._voltage = i2c_voltage
    self._frequency = i2c_frequency
    self._slave_address = slave_address

    self._serial: Optional[ShdlcSerialPort] = None
    self._sensor: Optional[Sht3xI2cDevice] = None

  async def setup(self) -> None:
    self._serial = ShdlcSerialPort(port=self._com_port, baudrate=460800)
    self._serial.open()

    connection = ShdlcConnection(self._serial)
    bridge = SensorBridgeShdlcDevice(connection, slave_address=self._slave_address)

    bridge.set_i2c_frequency(self._bridge_port, self._frequency)
    bridge.set_supply_voltage(self._bridge_port, self._voltage)
    bridge.switch_supply_on(self._bridge_port)

    i2c_proxy = SensorBridgeI2cProxy(bridge, self._bridge_port)
    i2c_connection = I2cConnection(i2c_proxy)
    self._sensor = Sht3xI2cDevice(i2c_connection)

  async def stop(self) -> None:
    if self._serial is not None:
      self._serial.close()
      self._serial = None
    self._sensor = None

  def serialize(self) -> dict:
    return {
      "port": self._com_port,
      "bridge_port": str(self._bridge_port),
      "voltage": self._voltage,
      "frequency": self._frequency,
      "slave_address": self._slave_address
    }

  async def get_temperature(self) -> float:
    if self._sensor is None:
      raise RuntimeError("Sensor not initialized.")
    temperature, _ = self._sensor.single_shot_measurement()
    return temperature.degrees_celsius

  async def get_humidity(self) -> float:
    if self._sensor is None:
      raise RuntimeError("Sensor not initialized.")
    _, humidity = self._sensor.single_shot_measurement()
    return humidity.percent_rh

  async def get_temperature_and_humidity(self) -> tuple[float, float]:
    if self._sensor is None:
      raise RuntimeError("Sensor not initialized.")
    temperature, humidity = self._sensor.single_shot_measurement()
    return temperature.degrees_celsius, humidity.percent_rh
