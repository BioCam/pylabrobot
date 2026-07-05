# WIP: channel gripper vs integrated arm in the visualizer

Work-in-progress handoff note for branch `visualizer-channel-gripper-label`. This is a
scratch note to resume from; remove it before opening any upstream pull request.

## Problem

The visualizer's arm panel showed a held plate as if the integrated arm (e.g. iSWAP)
was holding it, even when the plate was actually gripped by the channel gripper (the
plate gripper formed by the pipetting channels). The two gripper paths were
indistinguishable to the frontend, because the pickup carried no gripper identity and
both wrote into the same single arm slot.

## Approach (decided)

Give the channel gripper its own pickup slot (not a relabel of the arm's slot), so the
integrated arm stays visible and idle while the channel gripper holds a plate as a
separate, distinctly drawn entry. This also decouples the channel gripper from the
"an arm must be installed" requirement.

## What changed (by symbol)

Backend / LiquidHandler:
- `standard.py` `ResourcePickup`: added `gripper: str = "arm"` (default keeps existing
  callers and serialized state valid).
- `liquid_handler.py`:
  - `pick_up_resource` gained a generic `gripper` parameter; when unset it is inferred
    from the backend's own gripper selector (the STAR `use_arm` argument), mapping the
    channel-gripper option to `"channel"` and anything else to `"arm"`. The `use_arm`
    argument itself is untouched.
  - Added a dedicated `_channel_gripper_pickup` slot. The `_resource_pickup` property now
    routes a `"channel"` pickup to that slot (anything else to the first arm slot) and
    returns whichever gripper is currently holding.
  - The "no robotic arm installed" guard now applies only to arm pickups.
  - `serialize_state` always emits the integrated arm slot(s) and adds a `"channel"`
    entry only while the channel gripper holds; it also emits `arm_names`.
- `backend.py` `LiquidHandlerBackend.arm_names`: new property, defaults to generic
  `"Arm 0"`, `"Arm 1"`, ... (one per `num_arms`).
- `STAR_backend.py`: overrides `arm_names` to return `["iSWAP"]` when the iSWAP is
  installed.

Frontend (`visualizer/lib.js`):
- `fillArmPanel` / `buildSingleArm`: label each column from `arm_names` (so an idle
  integrated arm reads its real name, e.g. "iSWAP") and label a `"channel"` pickup as
  "Channel gripper".
- `buildSingleArm` draws the channel gripper differently: only the two gripping pads
  (no finger rails, no back-panel carriage), rotated 90 degrees so it grips front-back
  (pads above and below the plate, gripping nubs facing the plate), centered vertically
  in the panel. The integrated arm drawing is unchanged.
- Key sort in `fillArmPanel` places numeric arm slots first, then the `"channel"` entry.

## Status

- Verified in a headless browser: the arm panel shows the integrated arm (idle) and the
  channel gripper (holding) as two labeled columns; the channel gripper renders as
  centered front-back pads gripping toward the plate.
- All green: liquid handling test suite, STAR backend tests, `ruff format`, `ruff check`,
  `ruff check --select I`, and `mypy`.
- New tests cover: default pickup attributes to the arm; a channel pickup occupies its
  own slot while the arm slot stays present and idle; a channel pickup works with no arm
  installed; and `arm_names` accompanies the arm slots.

## Terminology

Call it the "channel gripper" (the plate gripper formed by the pipetting channels).
The gripper-identity value is `"channel"`; the integrated arm is `"arm"`. The STAR
`use_arm` selector is a pre-existing API we only read.

## Open follow-ups

- The channel-gripper pads are geometrically symmetric, so front vs back is a convention
  in the code (top of panel = back, bottom = front); add a visible front/back marker only
  if desired.
- Consider whether the integrated arm and channel gripper should ever be allowed to hold
  simultaneously (today a single pickup is enforced across both).
