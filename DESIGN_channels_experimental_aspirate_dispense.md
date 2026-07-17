# Design: single-channel experimental aspirate / dispense

Status: draft for review. Not implemented yet.

## Goal

`channels_experimental_aspirate` / `channels_experimental_dispense`: two new `STARBackend` methods
that are **PX `DA`/`DB` (piston-only aspirate/dispense) plus a declared surface-following distance**,
run in place, across selected channels in parallel.

`DA`/`DB` take no Z and cannot follow the surface; the only channel commands that follow the surface
are `MG` (aspirate) / `MH` (dispense). So these are built on `MG`/`MH` with the piston fields set as
`DA`/`DB` would set them, plus `zd`/`ze` for the surface following.

### Everything is explicit - nothing is left to a firmware default

`MG`/`MH` use a leaving-liquid ("swap") speed, a mechanical-clearance reversal, a drive acceleration,
current limits, and emerge/end heights whether or not the caller names them. Hiding those behind
firmware defaults would make the method *look* simple while the actual behaviour is decided by values
nobody can see in the code. So instead:

- Every knob is a method argument with its real firmware default shown in the signature (override any).
- Every field the command sends - including the ones we turn **off** (pre-wetting, blow-out, transport
  air, settling, mixing, bottom-search) - is set explicitly in the `send_command`, with a comment. No
  field is omitted and inherited silently.

Read the method and you know exactly what the channel will do.

### In place

`za` is filled from each channel's current position (`channels_request_stop_disk_z_positions()`), and
`zb`/`zg` are pinned to `za` so the channel does not retract afterwards (the firmware default for both
is fully retracted). `surface_following_distance=0` is a pure in-place `DA`/`DB`; a positive value
makes the Z-drive follow the surface down during the stroke and return. An explicit `z` overrides
"current position". Z is in stop-disk space (probe Z, excluding any tip), matching the query, so the
current-position round trip is exact.

## Reused building blocks (already in `STARBackend`)

- `channel_id(channel_idx)` -> `"P1".."PG"` module string.
- `channels_request_stop_disk_z_positions()` -> stop-disk Z (mm) per channel.
- `request_tip_presence()` -> `List[Optional[bool]]`.
- `dispensing_drive_vol_to_increment` (uL -> incs), `mm_to_z_drive_increment` (mm -> Z incs), and the
  reverse converters.
- `MINIMUM_CHANNEL_Z_POSITION` / `MAXIMUM_CHANNEL_Z_POSITION` (Z window, mm).

## Implementation

```python
async def channels_experimental_aspirate(
    self,
    volume: Union[float, List[float]],
    use_channels: List[int],
    z: Optional[Union[float, List[float]]] = None,
    surface_following_distance: Union[float, List[float]] = 0.0,
    minimum_height: Optional[Union[float, List[float]]] = None,
    flow_rate: Union[float, List[float]] = 250.0,  # dv
    mechanical_clearance_reversing_distance: Union[float, List[float]] = 4.69,  # de
    acceleration: Union[float, List[float]] = 4687.6,  # dr
    current_limit: int = 5,  # dw
    z_speed: float = 128.7,  # zv
    swap_speed: float = 10.7,  # zu, speed leaving liquid
    z_acceleration: float = 804.0,  # zr
    z_current_limit: int = 3,  # zw
    requires_tip: bool = True,
) -> None:
    """Aspirate a raw piston volume in place on selected channels, with optional surface following.

    PX `DA` (piston-only aspirate) plus a declared `surface_following_distance`, issued as an `MG`
    command whose every field is set explicitly (see the send below). No resource, liquid class or
    computed positions. Each channel operates where it already sits (or at `z`); with
    `surface_following_distance > 0` the Z-drive follows the surface down during the stroke and returns.
    Channels run concurrently via `asyncio.gather`.

    Args:
      volume: Piston volume to aspirate, uL; raw, not liquid-class corrected. Scalar or per-channel.
      use_channels: Channel indices to act on (0-based, backmost = 0).
      z: Operating height per channel, mm (stop-disk space); None uses each channel's current position.
      surface_following_distance: Z travel during aspiration, mm; 0 = pure in-place `DA`.
      minimum_height: Safety floor, mm; None uses the deck floor.
      flow_rate: Dispensing-drive speed, uL/s (`dv`).
      mechanical_clearance_reversing_distance: Piston backlash take-up, uL (`de`).
      acceleration: Dispensing-drive acceleration, uL/s^2 (`dr`).
      current_limit: Dispensing-drive current limit, 0..7 (`dw`).
      z_speed: Z-drive travel speed, mm/s (`zv`).
      swap_speed: Z-drive speed on leaving the liquid, mm/s (`zu`).
      z_acceleration: Z-drive acceleration, mm/s^2 (`zr`).
      z_current_limit: Z-drive current limit, 0..7 (`zw`).
      requires_tip: If True, raise on any selected channel that holds no tip; if False, aspirate air.
    """
    n = len(use_channels)
    for channel_idx in use_channels:
      if not (0 <= channel_idx < self.num_channels):
        raise ValueError(
          f"channel index {channel_idx} out of range for instrument with {self.num_channels} channels"
        )

    def _per_channel(value, name: str) -> List:
      if isinstance(value, list):
        if len(value) != n:
          raise ValueError(f"{name} has length {len(value)} but {n} channels were selected")
        return list(value)
      return [value] * n

    if z is None:
      all_z = await self.channels_request_stop_disk_z_positions()
      z = [all_z[channel_idx] for channel_idx in use_channels]

    volumes = _per_channel(volume, "volume")
    zs = _per_channel(z, "z")
    following = _per_channel(surface_following_distance, "surface_following_distance")
    floors = _per_channel(
      STARBackend.MINIMUM_CHANNEL_Z_POSITION if minimum_height is None else minimum_height,
      "minimum_height",
    )
    flow_rates = _per_channel(flow_rate, "flow_rate")
    clearances = _per_channel(mechanical_clearance_reversing_distance, "mechanical_clearance_reversing_distance")
    accelerations = _per_channel(acceleration, "acceleration")

    vol_max = STARBackend.dispensing_drive_increment_to_volume(26666)
    flow_min = STARBackend.dispensing_drive_increment_to_volume(20)
    flow_max = STARBackend.dispensing_drive_increment_to_volume(13500)
    following_max = STARBackend.z_drive_increment_to_mm(9999)
    z_min = STARBackend.MINIMUM_CHANNEL_Z_POSITION
    z_max = STARBackend.MAXIMUM_CHANNEL_Z_POSITION
    assert 0 <= current_limit <= 7 and 0 <= z_current_limit <= 7, "current limits must be 0..7"

    tip_present = await self.request_tip_presence()

    async def _aspirate_one(channel_idx, vol, operating_z, sfd, floor, flow, clearance, accel) -> None:
      if requires_tip and not tip_present[channel_idx]:
        raise RuntimeError(f"channel {channel_idx} has no tip; pick up a tip before aspirating")
      assert 0.0 <= vol <= vol_max, f"volume must be between 0 and {vol_max} uL, got {vol}"
      assert z_min <= operating_z <= z_max, f"z must be between {z_min} and {z_max} mm, got {operating_z}"
      assert 0.0 <= sfd <= following_max, (
        f"surface_following_distance must be between 0 and {following_max} mm, got {sfd}"
      )
      assert z_min <= floor <= operating_z, (
        f"minimum_height must be between {z_min} mm and z ({operating_z} mm), got {floor}"
      )
      assert flow_min <= flow <= flow_max, (
        f"flow_rate must be between {flow_min} and {flow_max} uL/s, got {flow}"
      )
      za = f"{STARBackend.mm_to_z_drive_increment(operating_z):05}"
      await self.send_command(
        module=STARBackend.channel_id(channel_idx),
        command="MG",
        # piston (as DA): volume, backlash take-up, speed, acceleration, current
        da=f"{STARBackend.dispensing_drive_vol_to_increment(vol):05}",
        de=f"{STARBackend.dispensing_drive_vol_to_increment(clearance):03}",
        dv=f"{STARBackend.dispensing_drive_vol_to_increment(flow):05}",
        dr=f"{round(STARBackend.dispensing_drive_vol_to_increment(accel) * 0.001):03}",
        dw=f"{current_limit}",
        # Z: operate at za, follow surface by zd, floor at zh, stay in place (zb, zg = za)
        za=za,
        zb=za,
        zd=f"{STARBackend.mm_to_z_drive_increment(sfd):04}",
        zh=f"{STARBackend.mm_to_z_drive_increment(floor):05}",
        zg=za,
        zv=f"{STARBackend.mm_to_z_drive_increment(z_speed):05}",
        zu=f"{STARBackend.mm_to_z_drive_increment(swap_speed):05}",
        zr=f"{STARBackend.mm_to_z_drive_increment(z_acceleration / 1000):03}",
        zw=f"{z_current_limit}",
        # everything else explicitly off (so nothing is a hidden firmware default)
        dc="0000",  # pre-wetting off (firmware default is ON)
        df="00000",  # blow-out air off
        dg="0000",  # transport air off
        to="000",  # settling time off
        dj="0",  # aspirate (not empty-cup)
        bl="0",  # pressure/ADC algorithm off
        dm="00000",  # mix volume off
        zm="0",  # bottom-search off
        ci="0",  # touch-off normal (inert with bottom-search off)
      )

    await asyncio.gather(
      *[
        _aspirate_one(c, volumes[i], zs[i], following[i], floors[i], flow_rates[i], clearances[i], accelerations[i])
        for i, c in enumerate(use_channels)
      ]
    )


async def channels_experimental_dispense(
    self,
    volume: Union[float, List[float]],
    use_channels: List[int],
    z: Optional[Union[float, List[float]]] = None,
    surface_following_distance: Union[float, List[float]] = 0.0,
    minimum_height: Optional[Union[float, List[float]]] = None,
    stop_back_volume: Union[float, List[float]] = 0.0,  # dd
    flow_rate: Union[float, List[float]] = 250.0,  # dv
    stop_flow_rate: Union[float, List[float]] = 140.6,  # du
    acceleration: Union[float, List[float]] = 4687.6,  # dr
    current_limit: int = 5,  # dw
    z_speed: float = 128.7,  # zv
    swap_speed: float = 10.7,  # zu
    z_acceleration: float = 804.0,  # zr
    z_current_limit: int = 3,  # zw
    requires_tip: bool = True,
) -> None:
    """Dispense a raw piston volume in place on selected channels, with optional surface following.

    PX `DB` (piston-only dispense) plus a declared `surface_following_distance`, issued as an `MH`
    command whose every field is set explicitly. Channels run concurrently via `asyncio.gather`.

    Args:
      volume: Piston volume to dispense, uL; raw, not liquid-class corrected. Scalar or per-channel.
      use_channels: Channel indices to act on (0-based, backmost = 0).
      z: Operating height per channel, mm (stop-disk space); None uses each channel's current position.
      surface_following_distance: Z travel during dispense, mm; 0 = pure in-place `DB`.
      minimum_height: Safety floor, mm; None uses the deck floor.
      stop_back_volume: Volume drawn back at the end to stop dripping, uL (`dd`).
      flow_rate: Dispensing-drive speed, uL/s (`dv`).
      stop_flow_rate: Cut-off speed, uL/s (`du`).
      acceleration: Dispensing-drive acceleration, uL/s^2 (`dr`).
      current_limit: Dispensing-drive current limit, 0..7 (`dw`).
      z_speed: Z-drive travel speed, mm/s (`zv`).
      swap_speed: Z-drive speed on leaving the liquid, mm/s (`zu`).
      z_acceleration: Z-drive acceleration, mm/s^2 (`zr`).
      z_current_limit: Z-drive current limit, 0..7 (`zw`).
      requires_tip: If True, raise on any selected channel that holds no tip; if False, dispense air.
    """
    n = len(use_channels)
    for channel_idx in use_channels:
      if not (0 <= channel_idx < self.num_channels):
        raise ValueError(
          f"channel index {channel_idx} out of range for instrument with {self.num_channels} channels"
        )

    def _per_channel(value, name: str) -> List:
      if isinstance(value, list):
        if len(value) != n:
          raise ValueError(f"{name} has length {len(value)} but {n} channels were selected")
        return list(value)
      return [value] * n

    if z is None:
      all_z = await self.channels_request_stop_disk_z_positions()
      z = [all_z[channel_idx] for channel_idx in use_channels]

    volumes = _per_channel(volume, "volume")
    zs = _per_channel(z, "z")
    following = _per_channel(surface_following_distance, "surface_following_distance")
    floors = _per_channel(
      STARBackend.MINIMUM_CHANNEL_Z_POSITION if minimum_height is None else minimum_height,
      "minimum_height",
    )
    stop_backs = _per_channel(stop_back_volume, "stop_back_volume")
    flow_rates = _per_channel(flow_rate, "flow_rate")
    stop_flows = _per_channel(stop_flow_rate, "stop_flow_rate")
    accelerations = _per_channel(acceleration, "acceleration")

    vol_max = STARBackend.dispensing_drive_increment_to_volume(26666)
    flow_min = STARBackend.dispensing_drive_increment_to_volume(20)
    flow_max = STARBackend.dispensing_drive_increment_to_volume(13500)
    stop_back_max = STARBackend.dispensing_drive_increment_to_volume(999)
    following_max = STARBackend.z_drive_increment_to_mm(9999)
    z_min = STARBackend.MINIMUM_CHANNEL_Z_POSITION
    z_max = STARBackend.MAXIMUM_CHANNEL_Z_POSITION
    assert 0 <= current_limit <= 7 and 0 <= z_current_limit <= 7, "current limits must be 0..7"

    tip_present = await self.request_tip_presence()

    async def _dispense_one(
      channel_idx, vol, operating_z, sfd, floor, stop_back, flow, stop_flow, accel
    ) -> None:
      if requires_tip and not tip_present[channel_idx]:
        raise RuntimeError(f"channel {channel_idx} has no tip; pick up a tip before dispensing")
      assert 0.0 <= vol <= vol_max, f"volume must be between 0 and {vol_max} uL, got {vol}"
      assert z_min <= operating_z <= z_max, f"z must be between {z_min} and {z_max} mm, got {operating_z}"
      assert 0.0 <= sfd <= following_max, (
        f"surface_following_distance must be between 0 and {following_max} mm, got {sfd}"
      )
      assert z_min <= floor <= operating_z, (
        f"minimum_height must be between {z_min} mm and z ({operating_z} mm), got {floor}"
      )
      assert 0.0 <= stop_back <= stop_back_max, (
        f"stop_back_volume must be between 0 and {stop_back_max} uL, got {stop_back}"
      )
      assert flow_min <= flow <= flow_max, (
        f"flow_rate must be between {flow_min} and {flow_max} uL/s, got {flow}"
      )
      za = f"{STARBackend.mm_to_z_drive_increment(operating_z):05}"
      await self.send_command(
        module=STARBackend.channel_id(channel_idx),
        command="MH",
        # piston (as DB): volume, stop-back, speed, cut-off speed, acceleration, current
        db=f"{STARBackend.dispensing_drive_vol_to_increment(vol):05}",
        dd=f"{STARBackend.dispensing_drive_vol_to_increment(stop_back):03}",
        dv=f"{STARBackend.dispensing_drive_vol_to_increment(flow):05}",
        du=f"{STARBackend.dispensing_drive_vol_to_increment(stop_flow):05}",
        dr=f"{round(STARBackend.dispensing_drive_vol_to_increment(accel) * 0.001):03}",
        dw=f"{current_limit}",
        # Z: operate at za, follow surface by ze, floor at zh, stay in place (zb, zg = za)
        za=za,
        zb=za,
        ze=f"{STARBackend.mm_to_z_drive_increment(sfd):04}",  # dispense surface following is `ze`
        zh=f"{STARBackend.mm_to_z_drive_increment(floor):05}",
        zg=za,
        zv=f"{STARBackend.mm_to_z_drive_increment(z_speed):05}",
        zu=f"{STARBackend.mm_to_z_drive_increment(swap_speed):05}",
        zr=f"{STARBackend.mm_to_z_drive_increment(z_acceleration / 1000):03}",
        zw=f"{z_current_limit}",
        # everything else explicitly off
        dg="0000",  # transport air off
        to="000",  # settling time off
        bl="0",  # pressure/ADC algorithm off
        dm="00000",  # mix volume off
        zm="0",  # bottom-search off
        ci="0",  # touch-off normal (inert with bottom-search off)
      )

    await asyncio.gather(
      *[
        _dispense_one(c, volumes[i], zs[i], following[i], floors[i], stop_backs[i], flow_rates[i], stop_flows[i], accelerations[i])
        for i, c in enumerate(use_channels)
      ]
    )
```

## Private piston primitive: `_channel_dispensing_drive_aspirate` (`DA`)

The piston-only aspirate, one channel, no Z. This is the leanest primitive - no surface following, no
positioning - the pure `DA` command with every field explicit and in human units. (A `DB` dispense
counterpart, `_channel_dispensing_drive_dispense`, mirrors it with `dd` stop-back and `du` stop speed.)

```python
async def _channel_dispensing_drive_aspirate(
    self,
    channel_idx: int,
    volume: float,  # da, uL
    mechanical_clearance_reversing_distance: float = 4.69,  # de, uL (100 increments)
    flow_rate: float = 250.0,  # dv, uL/s (5333 increments/s)
    acceleration: float = 4687.6,  # dr, uL/s^2 (100 x1000 increments/s^2)
    current_limit: int = 5,  # dw
    requires_tip: bool = True,
) -> Any:
    """Aspirate a raw piston volume on one channel (`DA`) - piston only, no Z motion.

    The dispensing drive draws `volume` where the channel currently sits; there is no Z, LLD, surface
    following or liquid-class handling. Every firmware field is set explicitly; units are human
    (uL, uL/s, uL/s^2) and converted to increments.

    Args:
      channel_idx: Channel index (0-based, backmost = 0).
      volume: Piston volume to aspirate, uL (`da`); raw, not liquid-class corrected.
      mechanical_clearance_reversing_distance: Piston backlash take-up, uL (`de`); the drive over-travels
        by this to absorb drivetrain clearance so the drawn volume matches the commanded volume.
      flow_rate: Dispensing-drive speed, uL/s (`dv`).
      acceleration: Dispensing-drive acceleration, uL/s^2 (`dr`).
      current_limit: Dispensing-drive current limit, 0..7 (`dw`).
      requires_tip: If True, raise if the channel holds no tip; if False, allow aspirating air.

    Raises:
      ValueError: If channel_idx is out of range.
      RuntimeError: If requires_tip and the channel holds no tip.
      AssertionError: If a parameter is out of the firmware range.
    """
    if not (0 <= channel_idx < self.num_channels):
      raise ValueError(
        f"channel index {channel_idx} out of range for instrument with {self.num_channels} channels"
      )
    if requires_tip and not (await self.request_tip_presence())[channel_idx]:
      raise RuntimeError(f"channel {channel_idx} has no tip; pick up a tip before aspirating")

    vol_max = STARBackend.dispensing_drive_increment_to_volume(26666)
    clearance_max = STARBackend.dispensing_drive_increment_to_volume(999)
    flow_min = STARBackend.dispensing_drive_increment_to_volume(20)
    flow_max = STARBackend.dispensing_drive_increment_to_volume(13500)
    accel_min = STARBackend.dispensing_drive_increment_to_volume(5000)  # dr = 005 (x1000 inc/s^2)
    accel_max = STARBackend.dispensing_drive_increment_to_volume(600000)  # dr = 600
    assert 0.0 <= volume <= vol_max, f"volume must be between 0 and {vol_max} uL, got {volume}"
    assert 0.0 <= mechanical_clearance_reversing_distance <= clearance_max, (
      f"mechanical_clearance_reversing_distance must be between 0 and {clearance_max} uL, "
      f"got {mechanical_clearance_reversing_distance}"
    )
    assert flow_min <= flow_rate <= flow_max, (
      f"flow_rate must be between {flow_min} and {flow_max} uL/s, got {flow_rate}"
    )
    assert accel_min <= acceleration <= accel_max, (
      f"acceleration must be between {accel_min} and {accel_max} uL/s^2, got {acceleration}"
    )
    assert 0 <= current_limit <= 7, f"current_limit must be between 0 and 7, got {current_limit}"

    return await self.send_command(
      module=STARBackend.channel_id(channel_idx),
      command="DA",
      da=f"{STARBackend.dispensing_drive_vol_to_increment(volume):05}",
      de=f"{STARBackend.dispensing_drive_vol_to_increment(mechanical_clearance_reversing_distance):03}",
      dv=f"{STARBackend.dispensing_drive_vol_to_increment(flow_rate):05}",
      dr=f"{round(STARBackend.dispensing_drive_vol_to_increment(acceleration) * 0.001):03}",
      dw=f"{current_limit}",
    )
```

Notes on this primitive:
- `DA` is relative: it draws `volume` from the drive's current piston position. It does not know about
  tip capacity or total piston travel; over-drawing is a firmware error, surfaced through `send_command`.
- No Z at all, so it aspirates wherever the channel currently is. Position the channel first (e.g.
  `move_channel_stop_disk_z`) if a specific height is wanted.
- The defaults shown are the firmware `DA` defaults, made visible: `de`=100 inc (4.69 uL), `dv`=5333
  inc/s (250 uL/s), `dr`=100 (4687.6 uL/s^2), `dw`=5.

## Private air primitive: `_channel_dispensing_drive_aspirate_air` (`DC`)

`DC` ("Aspirate blow-out or air volume") is `DA`'s twin for air: piston only, no Z, same
`de`/`dv`/`dr`/`dw` fields. The only differences are the volume field - `dh` (air), range `0000..9999`
(4 digits, ~0..468.7 uL) rather than `da` (liquid, 5 digits, ~0..1250 uL) - and that it draws air, not
liquid. Whether the air becomes blow-out (below the liquid) or transport air (above it) is decided by
*when* the caller runs it relative to the liquid aspirate, not by the command itself.

```python
async def _channel_dispensing_drive_aspirate_air(
    self,
    channel_idx: int,
    air_volume: float,  # dh, uL
    mechanical_clearance_reversing_distance: float = 4.69,  # de, uL (100 increments)
    flow_rate: float = 250.0,  # dv, uL/s (5333 increments/s)
    acceleration: float = 4687.6,  # dr, uL/s^2 (100 x1000 increments/s^2)
    current_limit: int = 5,  # dw
    requires_tip: bool = True,
) -> Any:
    """Aspirate an air volume on one channel (`DC`) - piston only, no Z motion.

    Draws `air_volume` of air into the tip with the dispensing drive. Used for blow-out air or
    transport air; which one it is depends on when it is run relative to the liquid aspirate. There is
    no Z, LLD or liquid-class handling. Every firmware field is set explicitly; units are human
    (uL, uL/s, uL/s^2) and converted to increments.

    Args:
      channel_idx: Channel index (0-based, backmost = 0).
      air_volume: Air volume to draw, uL (`dh`).
      mechanical_clearance_reversing_distance: Piston backlash take-up, uL (`de`).
      flow_rate: Dispensing-drive speed, uL/s (`dv`).
      acceleration: Dispensing-drive acceleration, uL/s^2 (`dr`).
      current_limit: Dispensing-drive current limit, 0..7 (`dw`).
      requires_tip: If True, raise if the channel holds no tip; if False, allow drawing air with none.

    Raises:
      ValueError: If channel_idx is out of range.
      RuntimeError: If requires_tip and the channel holds no tip.
      AssertionError: If a parameter is out of the firmware range.
    """
    if not (0 <= channel_idx < self.num_channels):
      raise ValueError(
        f"channel index {channel_idx} out of range for instrument with {self.num_channels} channels"
      )
    if requires_tip and not (await self.request_tip_presence())[channel_idx]:
      raise RuntimeError(f"channel {channel_idx} has no tip; pick up a tip before drawing air")

    air_max = STARBackend.dispensing_drive_increment_to_volume(9999)
    clearance_max = STARBackend.dispensing_drive_increment_to_volume(999)
    flow_min = STARBackend.dispensing_drive_increment_to_volume(20)
    flow_max = STARBackend.dispensing_drive_increment_to_volume(13500)
    accel_min = STARBackend.dispensing_drive_increment_to_volume(5000)  # dr = 005 (x1000 inc/s^2)
    accel_max = STARBackend.dispensing_drive_increment_to_volume(600000)  # dr = 600
    assert 0.0 <= air_volume <= air_max, f"air_volume must be between 0 and {air_max} uL, got {air_volume}"
    assert 0.0 <= mechanical_clearance_reversing_distance <= clearance_max, (
      f"mechanical_clearance_reversing_distance must be between 0 and {clearance_max} uL, "
      f"got {mechanical_clearance_reversing_distance}"
    )
    assert flow_min <= flow_rate <= flow_max, (
      f"flow_rate must be between {flow_min} and {flow_max} uL/s, got {flow_rate}"
    )
    assert accel_min <= acceleration <= accel_max, (
      f"acceleration must be between {accel_min} and {accel_max} uL/s^2, got {acceleration}"
    )
    assert 0 <= current_limit <= 7, f"current_limit must be between 0 and 7, got {current_limit}"

    return await self.send_command(
      module=STARBackend.channel_id(channel_idx),
      command="DC",
      dh=f"{STARBackend.dispensing_drive_vol_to_increment(air_volume):04}",
      de=f"{STARBackend.dispensing_drive_vol_to_increment(mechanical_clearance_reversing_distance):03}",
      dv=f"{STARBackend.dispensing_drive_vol_to_increment(flow_rate):05}",
      dr=f"{round(STARBackend.dispensing_drive_vol_to_increment(acceleration) * 0.001):03}",
      dw=f"{current_limit}",
    )
```

Note the one field-width difference from `DA`: `dh` is 4 digits (`:04`), so the air-volume ceiling is
9999 increments (~468.7 uL), well below the liquid ceiling of `da` (26666 increments, ~1250 uL).

## Notes

- The signature defaults (`flow_rate=250.0`, `acceleration=4687.6`, `swap_speed=10.7`, ...) are the
  firmware's own `MG`/`MH` defaults, made visible and overridable rather than inherited silently.
  Confirm each against the head you run before relying on it.
- Gather runs the channels concurrently in Python, but they share one serial link, so the `MG`/`MH`
  commands go out one after another, not in true mechanical parallel. For synchronised motion across
  channels the `C0` multi-channel (tip-pattern) command is the right path; gather is what was asked for.
- `zb`/`zg` are pinned to `za` to stay in place (no retract). Exposing an end/emerge height is the
  natural next knob if a caller wants the tip to lift clear of the liquid after the stroke.
```
