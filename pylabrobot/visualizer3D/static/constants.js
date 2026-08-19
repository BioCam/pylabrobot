import * as THREE from "three";

// Colours and thresholds for the viewer. Pure data: nothing here reads or writes scene state, so
// it can be changed without knowing anything about how the scene is built.

export const DEG = Math.PI / 180;

// The existing visualizer's resource colours, so the same deck reads the same in both.
export const WORKCELL_OUTLINE = 0x1a4b8c;

export const RESOURCE_COLORS = {
  facility: 0xe8ebed,
  workcell: 0xe8ebed,
  device: 0xdfe4e7,
  bench: 0xe4e8ea,
  deck: 0xf5fafc,
  carrier: 0x5c6c8f,
  mfx_carrier: 0x536181,
  plate_carrier: 0x5c6c8f,
  tip_carrier: 0x4e3149,  // darkest of the three: the carrier
  trough_carrier: 0x756793,
  tube_carrier: 0x756793,
  plate: 0x3a3a3a,
  well: 0xbcc7cf,
  tip_rack: 0x9b6690,     // mid: the rack sitting in it
  tip_spot: 0x6b4f66,     // the spot's rim; its inside carries whether a tip is in it
  tube_rack: 0x122d42,
  tube: 0xbcc7cf,
  trough: 0x756793,
  container: 0x756793,
  resource_holder: 0x5b6277,
  plate_holder: 0x8d99ae,
  plate_adapter: 0x7a8088,
  lid: 0x9aa7ad,
  trash: 0x8a949a,
  x_arm: 0x6b7a85,
  default: 0xbdb163,
};

// Parts that travel over the deck rather than standing on it. Drawn see-through, because an arm
// spanning the full deck depth otherwise hides everything under it in a plan view. This is the
// case a per-package renderer registry should own: the arm's own package knows it is a moving
// part, and this list is a stand-in until that exists.
export const MOVING_PARTS = new Set(["x_arm", "arm", "gripper", "head", "channel"]);

// Structure, reference and content, in that order of prominence. With the fills gone, outlines
// carry the information about what is on the deck, so they are the darkest thing; rails, bands and
// grid are references and recede; only live contents are saturated.
export const STRUCTURE_LIGHT = 0xaeb7bd; // an outer shell: a facility, a device
export const STRUCTURE_DARK = 0x49555e; // an inner one: a plate, a holder
export const STRUCTURE_MAX_DEPTH = 4; // depth at which the ramp reaches STRUCTURE_DARK
// Outlines are drawn as fat lines, because `LineBasicMaterial.linewidth` is ignored on every
// backend that matters: a hairline is one device pixel whatever you ask for. This is in CSS
// pixels, so it means the same thing on a retina display as anywhere else.
// An axis view is a drawing, not a lit scene: a fill is exactly its colour, and every resource is
// stroked near-black. That flat, outlined look is most of why the 2D visualizer reads.
export const FLAT_EDGE = 0x1f2529;
export const EDGE_WIDTH_FLAT = 1.0; // an axis view is a drawing: hairlines, as the 2D visualizer has
export const EDGE_WIDTH_3D = 1.2; // 20 percent thicker where the scene has depth to read

export function structureEdgeStyle(depth) {
  const t = Math.min(depth, STRUCTURE_MAX_DEPTH) / STRUCTURE_MAX_DEPTH;
  return {
    color: new THREE.Color(STRUCTURE_LIGHT).lerp(new THREE.Color(STRUCTURE_DARK), t),
    opacity: 0.5 + 0.45 * t,
  };
}

export const LIQUID = 0xf39c12;
export const VESSEL_EMPTY = 0xffffff; // nothing in it reads as white, as it does on a plan
export const VESSEL_RIM = 0x5c666e;
export const VESSEL_INSET = 0.6; // how much of the footprint the inside takes; the rest is the rim
export const TIP = 0x40cda1; // the colour the existing visualizer fills a fitted tip spot with
export const SELECT = 0x1a4b8c;
export const HOVER = 0xbbcc33;
// Ported from the X-arm tracker branch's `XArm` renderer: a translucent frame with a window
// punched through it, and a cyan line at the tracked X. The window is what lets you read the deck
// underneath, and the line sits inside it rather than crossing the whole deck.
export const ARM_COLOR = 0x404040;
export const ARM_OPACITY = 0.575;
// The carriage is see-through so you can read the deck under it, which leaves its own extent hard
// to place. A stroke noticeably heavier than a resource outline is what puts the boundary back,
// and it follows the window as well as the footprint, so the opening reads as part of the part.
// A carrier or a rack is a container you look into, so its walls are glass and its bottom is not:
// the floor is drawn opaque as its own surface, and these are the five faces around it.
export const SHELL_OPACITY = 0.5;
// The facility is the space everything stands in, not a thing to look at.
export const SPACE_OPACITY = 0.06;

export const ARM_EDGE = 0x1a1f24;
export const ARM_EDGE_WIDTH_FLAT = 2.2;
export const ARM_EDGE_WIDTH_3D = 2.6;
// Fallback opening, used when a part does not declare its own: symmetric, which is the least
// wrong guess. A part that knows its geometry says so in `window`.
export const ARM_INSET_X = 95;
export const ARM_INSET_Y = 20;
export const REFERENCE_LINE = 0x00e5ff;
// A line material's width is ignored on most backends, so the reference mark is geometry: a thin
// quad lying just under the arm, where it reads against the deck rather than floating inside the
// carriage.
export const REFERENCE_WIDTH = 4.2; // mm
export const REFERENCE_DROP = 2; // mm below the arm's underside
export const PROVENANCE_COLOR = { measured: 0x198754, derived: 0xd8a200, unavailable: 0xb02a37 };
