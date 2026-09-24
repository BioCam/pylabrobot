import * as THREE from "three";
import { LineSegments2 } from "three/addons/lines/LineSegments2.js";
import { LineSegmentsGeometry } from "three/addons/lines/LineSegmentsGeometry.js";

import { forgetDetail, updateDetail, updateEdgeMode } from "./appearance.js";
import { buildMeshes, colorFor } from "./boxes.js";
import {
  BULLSEYE_HOVER,
  BULLSEYE_PX,
  BULLSEYE_WRT,
  CONTENTS,
  HOLDERS,
  HOVER,
  MOVING_PARTS,
  PICKABLE_PARTS,
  PROTOCOL,
  SEARCH_CONTAINERS,
  SELECT,
  SELECTION_SHOWN_MS,
  TREE_HIDDEN,
} from "./constants.js";
import { initCoords } from "./coords.js";
import { initDeviceTools } from "./device_tools.js";
import { input, query } from "./dom.js";
import {
  hiddenNames,
  isVisible,
  meshes,
  meshRoots,
  modelMeshes,
  OVERLAY_ORDER,
  referencePoint,
  stateOf,
  worldBox,
} from "./drawn.js";
import { escapeHtml, fmt, NBSP, section, tuple, withUnit } from "./format.js";
import {
  afterDraw,
  applyQuality,
  beforeDraw,
  invalidate,
  lastFrameMs,
  qualityNow,
  qualityPinned,
  sceneArrived,
  setStats,
  statsNow,
  whileMoving,
} from "./frame.js";
import { initGif } from "./gif.js";
import {
  applyMoves,
  applyState,
  glides,
  onChange,
  setGlideSeconds,
  setHidden,
  updateArms,
  updateGlides,
} from "./live.js";
import {
  AXIS_COLORS,
  arms,
  armWindow,
  buildArms,
  buildGridMarks,
  buildHalos,
  buildOrigin,
  buildOriginDots,
  buildReferenceMarks,
  gridLabels,
  gridMarks,
  gridState,
  halos,
  hexOf,
  niceNumber,
  resetFloor,
  showHalos,
  showHalosIf,
  showOriginDots,
  showOriginDotsIf,
  updateGrid,
  updateHalos,
  updateOrigin,
} from "./marks.js";
import { buildDeclaredMeshes, dracoLoader, gltfLoader } from "./models.js";
import {
  buildViewHelper,
  camera,
  controls,
  dolly,
  frameBox,
  mmPerPixel,
  projection,
  projectionButton,
  renderer,
  rendererInitMs,
  resize,
  setProjection,
  startView,
  startViewName,
  VIEWS,
  view,
  viewHelper,
  viewportEl,
} from "./renderer.js";
import { connect, initTransport } from "./transport.js";
import { buildWorld, modelOf, setWorld, sizeOf, treeDepth, world } from "./world.js";

// A facility viewer that knows nothing about liquid handlers.
//
// The server sends models once and instances as a packed transform array. One InstancedMesh is
// built per model, so a full deck draws in a couple of dozen calls no matter how many wells are
// on it. Nothing here is keyed on a resource type: geometry comes from the model's own fields,
// colour from its category, and the tree from the parent array.
//
// The interface follows the existing visualizer. Only what three dimensions genuinely adds is
// new: camera presets, an axis gizmo that turns with the view, and a Z reference in the
// coordinate tool.
const _t0 = performance.now();

const timings = { moduleMs: performance.now() - _t0, rendererMs: rendererInitMs };

let selected = -1;

let activeTool = "cursor";

let framed = false; // whether this connection has framed the camera on its first scene

// A two-finger swipe is not a touch as far as the page is concerned: it arrives as the same `wheel`
// event a mouse sends, and nothing says which device sent it. OrbitControls does not try to tell
// them apart, so every swipe read as a zoom and a trackpad could not pan at all.
const WHEEL_NOTCH = 120; // one notch, in the units of the pre-standard `wheelDelta`

const WHEEL_NOTCH_PX = 50; // fallback threshold, for browsers reporting no `wheelDelta`

const GESTURE_GAP_MS = 120;

let gestureEndsAt = 0;

let gesturePans = false;

function looksLikeTrackpad(event) {
  if (event.deltaMode !== 0) return false; // lines and pages are only ever reported by a wheel
  if (event.deltaX !== 0) return true; // no wheel has a horizontal axis to report
  // `deltaY` cannot separate them on macOS, where it is the wheel that gets accelerated: one notch
  // ramps 4, 10, 42, 208 and arrives fractional, while a swipe stays in whole single digits.
  // `wheelDelta` survives that - a notch is a whole multiple of 120 in it however `deltaY` was
  // scaled, and a swipe reports three times its own delta.
  const legacy = Math.abs(event.wheelDeltaY ?? event.wheelDelta ?? 0);
  if (legacy > 0) return legacy % WHEEL_NOTCH !== 0;
  return Math.abs(event.deltaY) < WHEEL_NOTCH_PX;
}

// Once per gesture, not once per event: a swipe's momentum tail decays to deltas no wheel would
// send, and re-reading each event would flip from panning to zooming mid-stroke.
function wheelPans(event) {
  const now = performance.now();
  const fresh = now > gestureEndsAt;
  gestureEndsAt = now + GESTURE_GAP_MS;
  if (event.ctrlKey) {
    gesturePans = false; // a pinch is a zoom, whatever came before it
    return false;
  }
  if (fresh) gesturePans = looksLikeTrackpad(event);
  return gesturePans;
}

const panRight = new THREE.Vector3();

const panUp = new THREE.Vector3();

// Slide the view without turning it: camera and target move by the same vector, so the angle
// between them is untouched.
function panByPixels(dx, dy) {
  const perPixel = mmPerPixel();
  if (!Number.isFinite(perPixel) || perPixel <= 0) return;
  // Columns 0 and 1 of the camera's matrix are screen right and screen up, in world space. Moving
  // against the scroll is what makes the scene follow the fingers.
  panRight.setFromMatrixColumn(camera.matrix, 0).multiplyScalar(dx * perPixel);
  panUp.setFromMatrixColumn(camera.matrix, 1).multiplyScalar(-dy * perPixel);
  panRight.add(panUp);
  camera.position.add(panRight);
  controls.target.add(panRight);
  controls.update();
}

// On the viewport rather than the canvas inside it, so a swipe can be stopped before OrbitControls
// sees it and zooms.
viewportEl.addEventListener(
  "wheel",
  (event) => {
    if (!wheelPans(event)) return;
    event.preventDefault();
    event.stopPropagation();
    panByPixels(event.deltaX, event.deltaY);
  },
  { capture: true, passive: false },
);

dracoLoader.setDecoderPath("./vendor/draco/");

dracoLoader.setDecoderConfig({ type: "wasm" });

gltfLoader.setDRACOLoader(dracoLoader);

const selectionBox = new THREE.Box3Helper(new THREE.Box3(), new THREE.Color(SELECT));

selectionBox.visible = false;

view.add(selectionBox);

const hoverBox = new THREE.Box3Helper(new THREE.Box3(), new THREE.Color(HOVER));

hoverBox.visible = false;

view.add(hoverBox);

// Both highlights draw over everything. A hairline box behind translucent walls, landing on the
// resource's own outline, is a highlight nobody can see.
for (const helper of [selectionBox, hoverBox]) {
  helper.material.depthTest = false;
  helper.material.transparent = true;
  helper.renderOrder = OVERLAY_ORDER + 30;
}

// "TipRack" -> "tipracks", as the existing visualizer writes them. Deliberately naive: a count is
// always in front of it, so "1 plates" reads as a count rather than as a mistake.
const plural = (type) => `${String(type).toLowerCase()}s`;

// The plural naming these resources, from the first of them, as the existing visualizer counts a
// carrier: "3 plates" says what a carrier is for even when one site holds something else.
function countable(indices) {
  return plural(modelOf(indices[0]).type);
}

const treeEl = document.getElementById("resource-tree");

const rowOf = new Map();

const expanded = new Set();

function eyeSvg(hidden) {
  return hidden
    ? '<svg width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-linecap="round" stroke-linejoin="round"><path d="M3 10.5c2.6 3.3 5.9 5 9 5s6.4-1.7 9-5" stroke-width="2.2"/></svg>'
    : '<svg width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-linecap="round" stroke-linejoin="round"><path d="M3.07 12C5.23 8.2 8.43 6 12 6s6.77 2.2 8.93 6c-2.16 3.8-5.36 6-8.93 6s-6.77-2.2-8.93-6Z" stroke-width="2.2"/><circle cx="12" cy="12" r="3.8" fill="currentColor" stroke="none"/></svg>';
}

function shortName(index) {
  const parent = world.parentOf[index];
  const name = world.names[index];
  if (parent < 0) return name;
  const prefix = `${world.names[parent]}_`;
  return name.startsWith(prefix) ? name.slice(prefix.length) : name;
}

// What the tree says about a resource beyond its name and type: a carrier counts what it holds by
// kind, a rack how many of its spots are taken, a plate its well count, a container its volume, and
// a site with nothing in it says so. The existing visualizer's tree answers the same questions.
function summaryOf(index) {
  const children = world.childrenOf[index];

  // An adapter carries one thing, and its row says which, as the existing visualizer's does.
  if (modelOf(index).category === "plate_adapter") {
    return children.length ? shortName(children[0]) : "empty";
  }

  if (!children.length) {
    const state = stateOf.get(index);
    if (state?.volume !== undefined) return `${fmt(state.volume)} uL`;
    // A vacant site is labelled `<empty>` in place of its name, so a summary would repeat it.
    return "";
  }

  // An occupied holder needs no summary: the row directly beneath it says what is standing there.
  if (HOLDERS.has(modelOf(index).category)) return "";

  const kind = modelOf(children[0]).category;

  if (kind === "tip_spot") {
    // A tip is a resource standing in its spot, so a spot holds one when the tree says so.
    const filled = children.filter((c) => world.childrenOf[c].length > 0).length;
    return `${filled}/${children.length} tips`;
  }
  if (kind === "well") return `${children.length} wells`;
  if (kind === "tube") return `${children.length} tubes`;

  // Look through holders to what stands in them, so the count names the contents. With every site
  // empty there is nothing to name, and the useful fact is how many positions there are.
  if (HOLDERS.has(kind)) {
    const held = children.map((c) => world.childrenOf[c][0]).filter((c) => c !== undefined);
    if (!held.length) return `${children.length} sites`;
    return `${held.length} ${countable(held)}`;
  }

  // Nothing else is counted. A deck holding carriers, a waste block and an arm has no single
  // number worth quoting, and a device holding one deck has none either. The existing visualizer
  // is summarised the same way: carriers, racks and plates, and nothing above them.
  return "";
}

// How far apart two sites may stand in y and still count as the same row, in mm.
const SAME_ROW = 0.5;

// The sites on a carrier, in the order a reader takes them and numbered the way PyLabRobot numbers
// them. Holders arrive in whatever order they were assigned; what a person reads is the deck, so
// they are listed back to front, and left to right within a row. The numbers then run the other
// way down a column, because site 0 is the front one - and straight along a single row across.
//
// Null for anything that is not a carrier: only a resource whose children are all holders has
// sites at all.
function siteOrder(index) {
  const children = index >= 0 ? world.childrenOf[index] : [];
  if (children.length < 2 || !children.every((c) => HOLDERS.has(modelOf(c).category))) return null;
  const at = (i) => world.matrices[i].elements;
  const sorted = [...children].sort((a, b) => {
    const dy = at(b)[13] - at(a)[13];
    return Math.abs(dy) > SAME_ROW ? dy : at(a)[12] - at(b)[12];
  });
  const oneRow = sorted.every((c) => Math.abs(at(c)[13] - at(sorted[0])[13]) <= SAME_ROW);
  const number = new Map();
  sorted.forEach((c, i) => {
    number.set(c, oneRow ? i : sorted.length - 1 - i);
  });
  return { sorted, number };
}

// What the reader has open, by name, so a scene arriving does not fold the tree they opened, drop
// what they selected or close the panel they were reading. Taken before the new world replaces
// the old, since the indices held here mean nothing once it has.
function rememberView() {
  if (!world) return null;
  return {
    open: [...expanded].map((i) => world.names[i]),
    selected: selected >= 0 ? world.names[selected] : null,
    panel: infoPanel?.isConnected === true,
  };
}

function openPathTo(index) {
  const chain = [];
  for (let i = index; i >= 0; i = world.parentOf[i]) chain.unshift(i);
  for (const i of chain) toggle(i, true);
}

function restoreView(kept) {
  if (!kept) return;
  for (const name of kept.open) {
    const index = world.indexOfName.get(name);
    if (index !== undefined) openPathTo(index);
  }
  const index = world.indexOfName.get(kept.selected);
  if (index === undefined) return;
  selected = index;
  revealAndHighlight(index);
  if (kept.panel) renderInfoPanel();
}

function buildTree() {
  treeEl.textContent = "";
  rowOf.clear();
  expanded.clear();
  for (let i = 0; i < world.names.length; i++) if (world.parentOf[i] < 0) addRow(i, 0, null);
  showToDepth(Number(depthInput.value) || 1);
}

function addRow(index, depth, before) {
  const model = modelOf(index);
  const children = treeChildren(index);

  const row = document.createElement("div");
  row.className = "tree-node-row";
  row.style.paddingLeft = `${8 + depth * 16}px`;
  row.dataset.index = index;

  const arrow = document.createElement("span");
  arrow.className = `tree-node-arrow${children.length ? " has-children" : ""}`;
  arrow.textContent = children.length ? "▶" : "";
  row.appendChild(arrow);

  // A holder is a numbered position on its carrier, so what stands in it is labelled by that
  // number rather than by a name nobody chose - and the number takes the colour dot's place, as it
  // does in the existing visualizer. The holder itself only gets a row while it stands empty.
  const holder = HOLDERS.has(model.category);
  const parent = world.parentOf[index];
  const seat = holder ? index : parent >= 0 && HOLDERS.has(modelOf(parent).category) ? parent : -1;
  const number = seat < 0 ? undefined : siteOrder(world.parentOf[seat])?.number.get(seat);
  if (number !== undefined) {
    const site = document.createElement("span");
    site.className = "tree-node-site";
    site.textContent = String(number);
    row.appendChild(site);
  } else {
    const dot = document.createElement("span");
    dot.className = "tree-node-dot";
    dot.style.backgroundColor = hexOf(colorFor(model));
    row.appendChild(dot);
  }

  const name = document.createElement("span");
  name.className = "tree-node-name";
  // An empty site has nothing worth naming, and saying so is the point of showing it at all.
  const vacant = holder && !children.length;
  if (vacant) name.classList.add("tree-node-vacant");
  name.textContent = vacant ? "<empty>" : shortName(index);
  name.title = `${world.names[index]} (${model.type})`;
  row.appendChild(name);

  const type = document.createElement("span");
  type.className = "tree-node-type";
  type.textContent = vacant ? "" : model.type;
  row.appendChild(type);

  const info = document.createElement("span");
  info.className = "tree-node-info";
  info.textContent = summaryOf(index);
  row.appendChild(info);

  const eye = document.createElement("button");
  eye.className = "tree-eye-btn";
  eye.title = "Show or hide";
  eye.innerHTML = eyeSvg(hiddenNames.has(world.names[index]));
  eye.addEventListener("click", (e) => {
    e.stopPropagation();
    // Hidden by a parent, a plain click can do nothing and says so; alt-click clears the whole
    // chain above, as the existing visualizer's does.
    if (!hiddenNames.has(world.names[index]) && !isVisible(index)) {
      if (!e.altKey) return;
      for (let i = index; i >= 0; i = world.parentOf[i]) {
        if (hiddenNames.has(world.names[i])) setHidden(world.names[i], false);
      }
      return;
    }
    setHidden(world.names[index], !hiddenNames.has(world.names[index]));
  });
  row.appendChild(eye);

  row.addEventListener("mouseenter", () => showHoverBox(index));
  row.addEventListener("mouseleave", () => (hoverBox.visible = false));
  // As the existing visualizer's rows: a click opens the panel on the resource, a double click
  // frames it in the viewport, from wherever the camera is looking.
  // The arrow and the indent before it fold the row; the rest of it, from the name on, selects.
  const onArrow = (e) =>
    children.length > 0 && e.clientX <= arrow.getBoundingClientRect().right + 4;
  row.addEventListener("click", (e) => {
    if (onArrow(e)) toggle(index, !expanded.has(index));
    else select(index, true);
  });
  row.addEventListener("dblclick", (e) => {
    if (onArrow(e)) return;
    frameBox(worldBox(index), camera.position.clone().sub(controls.target));
  });

  treeEl.insertBefore(row, before ?? null);
  rowOf.set(index, { row, depth, arrow, info, eye });
  applyRowVisibility(index);
  return row;
}

// Children only enter the DOM when a node is opened, so a deck of thousands of wells does not
// build thousands of rows to show four carriers.
function toggle(index, open) {
  const entry = rowOf.get(index);
  if (!entry || !treeChildren(index).length || open === expanded.has(index)) return;

  if (open) {
    expanded.add(index);
    entry.arrow.textContent = "▼";
    const before = entry.row.nextSibling;
    for (const child of treeChildren(index)) addRow(child, entry.depth + 1, before);
  } else {
    expanded.delete(index);
    entry.arrow.textContent = "▶";
    const drop = (i) => {
      for (const child of world.childrenOf[i]) {
        drop(child);
        const childEntry = rowOf.get(child);
        if (childEntry) {
          childEntry.row.remove();
          rowOf.delete(child);
          expanded.delete(child);
        }
      }
    };
    drop(index);
  }
}

// What the tree lists below a row, in the order a reader takes them. Organised as the existing
// visualizer's tree is. The positions inside a container are left out: a plate already says how
// many wells it has. A deck is looked through, and what stood on it is listed left to right: the
// carriers are what a person came to find, not the surface under them. A holder is a numbered
// position, not a thing: the row is what stands in it, or the holder itself while it stands empty,
// so the vacancy still shows. Nothing about the viewport changes - this decides the panel only.
function treeChildren(index) {
  const listed = [];
  let sawDeck = false;
  for (const child of world.childrenOf[index]) {
    const category = modelOf(child).category;
    if (TREE_HIDDEN.has(category)) continue;
    if (category === "deck") {
      sawDeck = true;
      listed.push(...treeChildren(child));
      continue;
    }
    listed.push(child);
  }
  if (sawDeck) {
    listed.sort((a, b) => world.matrices[a].elements[12] - world.matrices[b].elements[12]);
  }
  const rows = [];
  for (const child of siteOrder(index)?.sorted ?? listed) {
    const held = HOLDERS.has(modelOf(child).category)
      ? world.childrenOf[child].filter((c) => !TREE_HIDDEN.has(modelOf(c).category))
      : [];
    rows.push(...(held.length ? held : [child]));
  }
  return rows;
}

// Whether opening this row would open a grid of positions rather than a level of the deck. Those
// rows exist - a mounting shaft is a real part - but a depth should not spend itself on ninety-six
// of them, so they open when they are asked for by name.
function holdsContentsOnly(index) {
  const children = treeChildren(index);
  return children.length > 0 && children.every((c) => CONTENTS.has(modelOf(c).category));
}

function showToDepth(maxDepth) {
  const walk = (index, depth) => {
    if (depth < maxDepth && !holdsContentsOnly(index)) {
      toggle(index, true);
      for (const child of treeChildren(index)) walk(child, depth + 1);
    } else {
      toggle(index, false);
    }
  };
  for (let i = 0; i < world.names.length; i++) if (world.parentOf[i] < 0) walk(i, 0);
}

function expandAll(open) {
  if (!open) {
    for (let i = 0; i < world.names.length; i++) if (world.parentOf[i] < 0) toggle(i, false);
    return;
  }
  const walk = (index) => {
    toggle(index, true);
    for (const child of treeChildren(index)) walk(child);
  };
  for (let i = 0; i < world.names.length; i++) if (world.parentOf[i] < 0) walk(i);
}

function applyRowVisibility(index) {
  const entry = rowOf.get(index);
  if (!entry) return;
  const own = hiddenNames.has(world.names[index]);
  const inherited = !own && !isVisible(index);
  entry.row.classList.toggle("resource-hidden", !isVisible(index));
  entry.eye.innerHTML = eyeSvg(own);
  entry.eye.classList.toggle("is-hidden", own);
  entry.eye.classList.toggle("inherited", inherited);
  entry.eye.title = inherited
    ? "Hidden by a parent - alt-click to reveal it"
    : own
      ? "Show"
      : "Hide";
}

function refreshTreeVisibility() {
  for (const [index] of rowOf) applyRowVisibility(index);
}

function refreshTreeInfo() {
  for (const [index, entry] of rowOf) entry.info.textContent = summaryOf(index);
}

function revealAndHighlight(index) {
  // A position inside a container has no row of its own, so the row to land on is the container
  // that names it - which is where a reader would look for it anyway.
  let at = index;
  while (at >= 0 && TREE_HIDDEN.has(modelOf(at).category)) at = world.parentOf[at];
  if (at < 0) at = index;
  const chain = [];
  for (let i = world.parentOf[at]; i >= 0; i = world.parentOf[i]) chain.unshift(i);
  for (const ancestor of chain) toggle(ancestor, true);
  for (const [, entry] of rowOf) entry.row.classList.remove("selected");
  const entry = rowOf.get(at);
  if (entry) {
    entry.row.classList.add("selected");
    entry.row.scrollIntoView({ block: "nearest" });
  }
}

let infoPanel = null;

// Values go through innerHTML, and a resource name is user data. Escape it, or a model field
// holding `<resource>` disappears into the markup.
function ensureInfoPanel() {
  if (infoPanel?.isConnected) return infoPanel;
  infoPanel = document.createElement("div");
  infoPanel.className = "uml-panel";
  document.querySelector("main").appendChild(infoPanel);
  return infoPanel;
}

function refreshPlacement(index) {
  if (selected !== index || !infoPanel?.isConnected) return;
  const o = index * 6;
  const xf = world.local;
  const m = world.matrices[index].elements;
  const local = infoPanel.querySelector('[data-live="location"]');
  const global = infoPanel.querySelector('[data-live="world"]');
  if (local) local.textContent = tuple(xf[o], xf[o + 1], xf[o + 2], "mm");
  if (global) global.textContent = tuple(m[12], m[13], m[14], "mm");
}

function closeInfoPanel() {
  selected = -1;
  selectionBox.visible = false;
  for (const [, entry] of rowOf) entry.row.classList.remove("selected");
  hideInfoPanel();
}

function hideInfoPanel() {
  if (infoPanel) infoPanel.remove();
  infoPanel = null;
}

// Units for the fields that have them. A number without its unit is not an answer.
// Shown by the panel's own sections, so they must not appear again under Specifics.
const HANDLED = new Set([
  "type",
  "category",
  "methods",
  "model",
  "size_x",
  "size_y",
  "size_z",
  "max_volume",
  "volume",
  "pending_volume",
  "height_volume_data",
  "ordering",
]);

// A field that records how a resource was constructed rather than what it is now. These are kept,
// not hidden, but put under a heading that says what they are: a deck reports `with_trash: false`
// while holding a trash, and a reader has to be able to see that without being misled by it.
const isConstruction = (key) => key.startsWith("with_") || key === "core_grippers";

// Per-category panel contributions. This is the seam a package that defines a resource would
// write into; everything works without an entry, which is what makes it a default rather than a
// registry every new type must join.
const PANELS = {
  deck: { note: "Construction flags describe how the deck was built, not what it now holds." },
};

function renderInfoPanel() {
  if (selected < 0) return hideInfoPanel();
  const panel = ensureInfoPanel();
  const index = selected;
  const model = modelOf(index);
  const contributed = PANELS[model.category] ?? {};
  const m = world.matrices[index].elements;
  const o = index * 6;
  const xf = world.local;
  const state = stateOf.get(index);

  const identity = [
    ["name", escapeHtml(world.names[index])],
    ["type", escapeHtml(model.type)],
  ];
  if (model.model) identity.push(["model", escapeHtml(String(model.model))]);
  identity.push(["category", escapeHtml(model.category ?? "uncategorised")]);

  const placement = [
    ["location", `<span data-live="location">${tuple(xf[o], xf[o + 1], xf[o + 2], "mm")}</span>`],
    ["world", `<span data-live="world">${tuple(m[12], m[13], m[14], "mm")}</span>`],
  ];
  if (xf[o + 3] || xf[o + 4] || xf[o + 5]) {
    placement.push(["rotation", tuple(xf[o + 3], xf[o + 4], xf[o + 5], "deg")]);
  }
  placement.push([
    "parent",
    world.parentOf[index] >= 0 ? escapeHtml(world.names[world.parentOf[index]]) : "none",
  ]);
  placement.push(["children", String(world.childrenOf[index].length)]);

  const [sx, sy, sz] = sizeOf(model);
  const geometry = [
    ["size", `${fmt(sx)}${NBSP}&#215;${NBSP}${fmt(sy)}${NBSP}&#215;${NBSP}${fmt(sz)}${NBSP}mm`],
  ];
  if (model.ordering) geometry.push(["items", String(Object.keys(model.ordering).length)]);

  const contents = [];
  if (model.max_volume !== undefined) {
    const volume = state?.volume ?? 0;
    contents.push(["volume", `${fmt(volume)}${NBSP}/${NBSP}${fmt(model.max_volume)}${NBSP}uL`]);
  }

  const specifics = [];
  const construction = [];
  for (const [key, value] of Object.entries(model)) {
    if (HANDLED.has(key)) continue;
    (isConstruction(key) ? construction : specifics).push([key, withUnit(key, value)]);
  }

  const tracker = state
    ? Object.entries(state)
        .filter(
          ([k]) =>
            !["rotation", "pending_volume", "volume", "tip", "pending_tip", "tip_state"].includes(
              k,
            ),
        )
        .map(([k, v]) => [k, withUnit(k, v)])
    : [];

  const methods = (model.methods ?? [])
    .map((signature) => `<div class="uml-method">${escapeHtml(signature)}</div>`)
    .join("");

  panel.innerHTML =
    `<button class="uml-close-btn" title="Close">&times;</button>` +
    `<div class="uml-header">` +
    `<div class="uml-header-name">${escapeHtml(world.names[index])}</div>` +
    `<div class="uml-header-type">${escapeHtml(model.type)} &middot; ${escapeHtml(model.category ?? "uncategorised")}</div>` +
    `</div>` +
    section("Identity", identity) +
    section("Placement", placement) +
    section("Geometry", geometry) +
    section("Contents", contents) +
    section("Specifics", specifics) +
    section("Tracker state", tracker) +
    section("Construction", construction, contributed.note) +
    // The one section that is a list rather than a fact about the part. Sixty signatures push
    // everything a reader came for off the top of the panel, so it opens shut and says how many are
    // behind it.
    (methods
      ? `<div class="uml-separator"></div><div class="uml-section">` +
        `<details class="uml-methods-block"><summary class="uml-section-title">` +
        `Methods <span class="uml-count">${model.methods.length}</span></summary>` +
        `<div class="uml-methods">${methods}</div></details></div>`
      : "");

  panel.querySelector(".uml-close-btn").addEventListener("click", closeInfoPanel);
}

// Selecting and inspecting are separate, as they are in the existing visualizer: a click in the
// viewport selects, a double click opens the panel, and a click in the tree does both. An already
// open panel follows the selection rather than being left showing something else.
let selectionTimer = null;

// The selection box stays a moment and goes, as the existing visualizer's dashed rectangle does.
// A timer the page set for itself asks for the one frame that removes it; keeping the loop
// running for the whole moment cost two seconds of frames on every click.
function hideSelectionLater() {
  clearTimeout(selectionTimer);
  selectionTimer = setTimeout(() => {
    selectionTimer = null;
    selectionBox.visible = false;
    invalidate();
  }, SELECTION_SHOWN_MS);
}

function select(index, openPanel = true) {
  selected = index;
  selectionBox.box.copy(worldBox(index));
  selectionBox.visible = true;
  hideSelectionLater();
  revealAndHighlight(index);
  if (openPanel || infoPanel?.isConnected) renderInfoPanel();
}

let hoveredRow = null;

function showHoverBox(index) {
  hoverBox.box.copy(worldBox(index));
  hoverBox.visible = true;
}

// Hovering a resource in the viewport marks its row in the tree, the mirror of hovering a row
// marking the resource. The existing visualizer does both, and only having one of them is what
// makes a tree feel disconnected from the scene.
function markTreeRow(index) {
  const entry = index === null ? null : rowOf.get(index);
  if (entry === hoveredRow) return;
  hoveredRow?.row.classList.remove("canvas-hover");
  hoveredRow = entry ?? null;
  hoveredRow?.row.classList.add("canvas-hover");
}

function clearHover() {
  hoverBox.visible = false;
  hoverBullseye.visible = false;
  markTreeRow(null);
}

// A line at the X the device positions the arm by. Where that sits on the arm is the whole
// difference between a dual-rail arm, positioned by its centre, and a single-rail one, positioned
// by its right edge - so drawing the reported X against the arm shows which it is without the
// viewer needing to know anything about rail types.
const raycaster = new THREE.Raycaster();

const pointer = new THREE.Vector2();

const readout = document.getElementById("hover-readout");

const _hitLocal = new THREE.Vector3();

const _hitInverse = new THREE.Matrix4();

/**
 * Whether a hit on a moving part lands in its window. The part's box is not drawn - its frame is,
 * with an opening - so through the opening the pointer is on whatever stands below, not on the
 * arm that happens to be parked over it.
 */
function throughWindow(index, point) {
  const model = modelOf(index);
  if (!MOVING_PARTS.has(model.category)) return false;
  const [left, right, front, back] = armWindow(model);
  _hitLocal.copy(point).applyMatrix4(_hitInverse.copy(world.matrices[index]).invert());
  return _hitLocal.x > left && _hitLocal.x < right && _hitLocal.y > front && _hitLocal.y < back;
}

function pick(event) {
  const rect = renderer.domElement.getBoundingClientRect();
  pointer.x = ((event.clientX - rect.left) / rect.width) * 2 - 1;
  pointer.y = -((event.clientY - rect.top) / rect.height) * 2 + 1;
  raycaster.setFromCamera(pointer, camera);
  const candidates = meshes.map((m) => m.mesh);
  const hits = raycaster.intersectObjects(candidates, false).filter((hit) => {
    const instances = hit.object.userData.instances;
    if (!instances || hit.instanceId === undefined) return false;
    return !throughWindow(instances[hit.instanceId], hit.point);
  });
  for (const hit of hits) {
    const instances = hit.object.userData.instances;
    if (instances && hit.instanceId !== undefined) {
      const index = instances[hit.instanceId];
      if (!isVisible(index)) continue;
      // Enclosures are translucent, so clicking through one to its contents is the useful
      // behaviour; take an enclosure only when nothing solid lies behind it. A part that always
      // carries something - a pipetting channel and its shaft - is taken where it is clicked, and
      // so is a moving part's frame: its window is already looked through, so this is its rim.
      const category = modelOf(index).category;
      const takesClick =
        world.childrenOf[index].length === 0 ||
        PICKABLE_PARTS.has(category) ||
        MOVING_PARTS.has(category);
      if (takesClick || hits.length === 1) return { index };
    }
  }
  // Nothing along the ray is a leaf: the pointer is on a plate between its wells, or on a deck
  // between its carriers. The deepest thing it passes through is the one it is over - never the
  // bench or the arm that happens to enclose it, which the nearest hit would name.
  let deepest = -1;
  for (const hit of hits) {
    const index = hit.object.userData.instances[hit.instanceId];
    if (!isVisible(index)) continue;
    if (deepest < 0 || treeDepth(index) > treeDepth(deepest)) deepest = index;
  }
  return deepest < 0 ? null : { index: deepest };
}

const coords = initCoords({ getWorld: () => world, referencePoint, escapeHtml });

// What each device carries, offered from the navbar. It reads the tree rather than being told, so
// there is nothing to keep in step: a tip picked up is a resource assigned, and the panel that
// draws tips is looking at the same tree the viewport is.
const deviceTools = initDeviceTools({
  getWorld: () => world,
  modelOf,
  stateOf: (index) => stateOf.get(index),
  onSelect: (index) => {
    revealAndHighlight(index);
    select(index, true);
  },
});

const {
  coordinateLabel,
  recordMeasurement,
  populateWrtDropdown,
  endpoints: deltaEndpoints,
  wrtPoint,
} = coords;

// The get-location tool's two markers, as the existing visualizer draws them: blue on the resource
// under the pointer, at the reference asked of it, and pink on the resource everything is measured
// against. Sprites held at BULLSEYE_PX, placed by transform, so a frame costs no buffer.
function bullseyeTexture(colour) {
  const canvas = document.createElement("canvas");
  canvas.width = 64;
  canvas.height = 64;
  const context = canvas.getContext("2d");
  context.strokeStyle = "rgba(255,255,255,0.85)";
  context.lineWidth = 9;
  context.beginPath();
  context.arc(32, 32, 16, 0, Math.PI * 2);
  context.stroke();
  context.strokeStyle = colour;
  context.fillStyle = colour;
  context.lineWidth = 4;
  context.beginPath();
  context.arc(32, 32, 16, 0, Math.PI * 2);
  context.stroke();
  context.beginPath();
  context.arc(32, 32, 3.5, 0, Math.PI * 2);
  context.fill();
  for (const [dx, dy] of [
    [1, 0],
    [-1, 0],
    [0, 1],
    [0, -1],
  ]) {
    context.beginPath();
    context.moveTo(32 + dx * 20, 32 + dy * 20);
    context.lineTo(32 + dx * 31, 32 + dy * 31);
    context.stroke();
  }
  const texture = new THREE.CanvasTexture(canvas);
  texture.colorSpace = THREE.SRGBColorSpace;
  return texture;
}

function bullseye(colour) {
  const sprite = new THREE.Sprite(
    new THREE.SpriteMaterial({
      map: bullseyeTexture(hexOf(colour)),
      transparent: true,
      depthTest: false,
      depthWrite: false,
    }),
  );
  sprite.renderOrder = OVERLAY_ORDER;
  sprite.frustumCulled = false;
  sprite.visible = false;
  view.add(sprite);
  return sprite;
}

const hoverBullseye = bullseye(BULLSEYE_HOVER);

const wrtBullseye = bullseye(BULLSEYE_WRT);

// Every frame: the tool decides whether either shows, the reference dropdown decides where the
// pink one stands, and the zoom decides how big both are drawn.
function updateBullseyes() {
  if (activeTool !== "coords" || !world) {
    hoverBullseye.visible = false;
    wrtBullseye.visible = false;
    return;
  }
  const perPixel = mmPerPixel();
  if (!Number.isFinite(perPixel) || perPixel <= 0) return;
  const at = wrtPoint();
  wrtBullseye.visible = at !== null;
  if (at !== null) wrtBullseye.position.copy(at);
  hoverBullseye.scale.setScalar(perPixel * BULLSEYE_PX);
  wrtBullseye.scale.setScalar(perPixel * BULLSEYE_PX);
}

// The existing visualizer draws an L between the two points a measurement runs between, one leg per
// axis in the axis' own colour, labelled with the distance. In three dimensions the L becomes a
// staircase: x, then y, then z. A coordinate tells you how far apart two things are; this tells you
// which way, which is the part a number alone never shows.
//
// Drawn over everything, because it annotates the scene rather than standing in it: a measurement
// half-buried in a carrier would be worse than useless.
const DELTA_WIDTH = 2.4;

const DELTA_HALO_WIDTH = 6.0;

const DELTA_HALO_OPACITY = 0.35;

const DELTA_LABEL_MM = 26;

const DELTA_MIN = 0.05; // mm; a leg shorter than this is a rounding artefact, not a distance

const DELTA_AXES = ["x", "y", "z"];

const deltaToggle = input("delta-lines-toggle");

// Built once and then moved, never rebuilt. Hovering fires on every frame the pointer moves, so
// allocating a dozen objects each time would be waste - but the reason it has to be this way is
// harder to see: a material has no pipeline ready on the frame it is created, so an annotation
// rebuilt per hover is permanently on its first frame and never draws at all.
let deltaAnnotation = null;

function buildDeltaAnnotation() {
  const group = new THREE.Group();
  group.visible = false;
  const legs = DELTA_AXES.map((axis) => {
    const color = AXIS_COLORS[axis];
    // Pale and wide behind, saturated and thin in front: the halo is what keeps a thin line
    // readable against a surface of any colour.
    const lines = [
      [DELTA_HALO_WIDTH, DELTA_HALO_OPACITY, OVERLAY_ORDER + 40],
      [DELTA_WIDTH, 1, OVERLAY_ORDER + 41],
    ].map(([linewidth, opacity, order]) => {
      const geometry = new LineSegmentsGeometry();
      geometry.setPositions([0, 0, 0, 0, 0, 0]);
      const material = new THREE.Line2NodeMaterial({
        color,
        linewidth,
        worldUnits: false,
        transparent: true,
        opacity,
        depthTest: false,
      });
      const line = new LineSegments2(geometry, material);
      line.frustumCulled = false;
      line.renderOrder = order;
      group.add(line);
      return line;
    });

    const canvas = document.createElement("canvas");
    canvas.width = 256;
    canvas.height = 64;
    const texture = new THREE.CanvasTexture(canvas);
    texture.colorSpace = THREE.SRGBColorSpace;
    // A quad rather than a sprite, as the rail numbers are: this build draws one and not the other.
    // It is turned to face the camera each frame instead, since a distance should read the same
    // from wherever it is looked at.
    const label = new THREE.Mesh(
      new THREE.PlaneGeometry(DELTA_LABEL_MM * 4, DELTA_LABEL_MM),
      new THREE.MeshBasicMaterial({ map: texture, transparent: true, depthTest: false }),
    );
    label.frustumCulled = false;
    label.renderOrder = OVERLAY_ORDER + 42;
    group.add(label);
    return {
      axis,
      color: `#${color.toString(16).padStart(6, "0")}`,
      lines,
      canvas,
      texture,
      label,
      text: null,
    };
  });
  view.add(group);
  return { group, legs };
}

function writeDeltaLabel(leg, text) {
  if (leg.text === text) return; // the same number, redrawn, costs a texture upload for nothing
  leg.text = text;
  const context = leg.canvas.getContext("2d");
  context.clearRect(0, 0, leg.canvas.width, leg.canvas.height);
  context.font = "bold 34px ui-monospace, Menlo, monospace";
  context.textAlign = "center";
  context.textBaseline = "middle";
  context.lineWidth = 6;
  context.strokeStyle = "rgba(255, 255, 255, 0.9)";
  context.strokeText(text, 128, 34);
  context.fillStyle = leg.color;
  context.fillText(text, 128, 34);
  leg.texture.needsUpdate = true;
}

function clearDeltaLines() {
  if (deltaAnnotation) deltaAnnotation.group.visible = false;
}

function drawDeltaLines(index) {
  if (activeTool !== "coords" || !deltaToggle.checked) return clearDeltaLines();
  const { from, to } = deltaEndpoints(index);
  if (!from) return clearDeltaLines(); // an absolute measurement has no second point to run to

  deltaAnnotation = deltaAnnotation ?? buildDeltaAnnotation();
  // One corner per axis taken in turn, so each leg is parallel to the axis it is coloured for.
  const corners = [
    from,
    new THREE.Vector3(to.x, from.y, from.z),
    new THREE.Vector3(to.x, to.y, from.z),
    to,
  ];
  let any = false;
  deltaAnnotation.legs.forEach((leg, i) => {
    const start = corners[i];
    const end = corners[i + 1];
    const distance = to[leg.axis] - from[leg.axis];
    const shown = Math.abs(distance) >= DELTA_MIN;
    for (const line of leg.lines) {
      line.visible = shown;
      if (shown) line.geometry.setPositions([start.x, start.y, start.z, end.x, end.y, end.z]);
    }
    leg.label.visible = shown;
    if (!shown) return;
    writeDeltaLabel(leg, `\u0394${leg.axis} ${distance.toFixed(1)}`);
    leg.label.position.copy(start).add(end).multiplyScalar(0.5);
    any = true;
  });
  deltaAnnotation.group.visible = any;
}

// The labels are geometry, so left alone they turn with the scene and shrink with distance. Both
// are wrong for a number: it is read, not looked at. Turned to face the camera and sized in pixels
// rather than millimetres, they stay the same on screen at any zoom, as the existing visualizer's
// do - it scales its by the stage's own zoom for the same reason.
const DELTA_LABEL_PX = 34;

function updateDeltaLabels() {
  const perPixel = mmPerPixel();
  if (!Number.isFinite(perPixel) || perPixel <= 0) return;
  const scale = (DELTA_LABEL_PX * perPixel) / DELTA_LABEL_MM;
  for (const leg of deltaAnnotation.legs) {
    leg.label.quaternion.copy(camera.quaternion);
    leg.label.scale.setScalar(scale);
  }
}

// Turning them off takes the drawn one with it, rather than leaving it until the next hover.
deltaToggle.addEventListener("change", () => {
  if (!deltaToggle.checked) clearDeltaLines();
});

function sceneBounds() {
  const box = new THREE.Box3();
  for (let i = 0; i < world.names.length; i++) {
    if (world.parentOf[i] >= 0) continue;
    box.union(worldBox(i));
  }
  if (box.isEmpty()) box.set(new THREE.Vector3(0, 0, 0), new THREE.Vector3(1000, 500, 300));
  return box;
}

// Fit what the box actually covers from this direction, not its bounding sphere. A sphere fitted
// to a 2600 x 1400 x 1000 facility is 3.1 m across, so framing one leaves most of the viewport
// empty in a plan view where the height contributes nothing.
const frame = (direction) => frameBox(sceneBounds(), direction ?? VIEWS.iso);

function goToStartView() {
  setProjection(startViewName === "iso" ? "perspective" : "orthographic");
  frame(startView);
}

// A small handle on the viewer, so a notebook cell or a link can drive it.
// The fourth and last way in: a call from outside the page, which tests and benchmarks use to drive
// the same paths a message takes. Everything that changes something is wrapped as a group, so a
// method added to that group is covered without anyone remembering to cover it.
//
// Reads are deliberately not wrapped. Asking the viewer a question must not be a reason to redraw,
// or watching for it to settle is what stops it settling.
function atBoundary(surface) {
  return Object.fromEntries(
    Object.entries(surface).map(([name, fn]) => [
      name,
      (...args) => {
        const result = fn(...args);
        invalidate();
        return result;
      },
    ]),
  );
}

/** @type {any} */ (window).plrViewer = {
  // Changes something, so asking for a frame afterwards is not the caller's job.
  ...atBoundary({
    focus(name, viewName) {
      const index = world?.indexOfName.get(name);
      if (index === undefined) return false;
      select(index);
      if (viewName) setProjection(viewName === "iso" ? "perspective" : "orthographic");
      frameBox(worldBox(index), VIEWS[viewName] ?? VIEWS.iso);
      return true;
    },
    view: (name) => {
      setProjection(name === "iso" ? "perspective" : "orthographic");
      frame(VIEWS[name] ?? VIEWS.iso);
    },
    projection: (kind) => setProjection(kind),
    hide: (name) => setHidden(name, true),
    show: (name) => setHidden(name, false),
    // Exposed so a benchmark can drive the same path a websocket message takes.
    applyState: (payload) => applyState(payload),
  }),

  // Only answers questions. Asking must not be a reason to redraw, or watching the viewer settle
  // is what stops it settling.
  stats: () => statsNow(),
  resources: () => world?.names ?? [],
  // What a resource last published, as the page holds it: what its colour and panel are drawn from.
  stateOf: (name) => {
    const index = world?.indexOfName.get(name);
    return index === undefined ? null : (stateOf.get(index) ?? null);
  },
  // What the pointer at a point of the page would be over, by name.
  pickAt: (clientX, clientY) => {
    const hit = world ? pick({ clientX, clientY }) : null;
    return hit ? world.names[hit.index] : null;
  },
  // Where a resource is drawn, in facility coordinates. The one thing a test outside the page
  // cannot work out for itself, because it is the product of the whole parent chain.
  worldOf: (name) => {
    const index = world?.indexOfName.get(name);
    if (index === undefined) return null;
    const m = world.matrices[index].elements;
    return [m[12], m[13], m[14]];
  },
  // Where the view is looking from and at. Panning moves both by the same amount and zooming moves
  // only the first, which is how the two are told apart from outside the page.
  camera: () => ({
    from: camera.position.toArray(),
    at: controls.target.toArray(),
    distance: camera.position.distanceTo(controls.target),
    zoom: camera.zoom,
  }),
  timings: () => timings,
  // The models that arrived as files, and what is being done with each. A box that is not drawn
  // and a model that is not either leaves nothing on screen, and from outside the page the two
  // are indistinguishable - so the model has to be able to say so itself.
  models: () => {
    const drawnBy = (o) => ({
      visible: o.visible && o.material.visible,
      order: o.renderOrder,
      depthTest: o.material.depthTest,
      transparent: o.material.transparent,
      opacity: o.material.opacity,
    });
    // One entry per resource drawn from a file, whichever way it is drawn.
    const listed = meshRoots.map((root) => {
      const parts = [];
      root.traverse((o) => o.isMesh && parts.push(drawnBy(o)));
      return { name: world?.names[root.userData.index], parts };
    });
    for (const built of modelMeshes) {
      const parts = built.meshes.map(drawnBy);
      for (const index of built.instances) listed.push({ name: world?.names[index], parts });
    }
    return listed;
  },
  detail: () =>
    meshes.map((e) => ({
      type: e.model.type,
      mm: Math.max(e.model.size_x ?? 0, e.model.size_y ?? 0),
      drawn: e.mesh.visible,
      filled: e.mesh.material.visible,
      outlineRule: !!e.holdsEnclosure,
      // What decides which of two overlapping models is seen. Order alone does not: three draws
      // every transparent material after every opaque one, so a translucent shell wins over a solid
      // thing above it whatever its order says.
      order: e.mesh.renderOrder,
      transparent: e.mesh.material.transparent,
      opacity: e.mesh.material.opacity,
    })),
  // What the coordinate tool is drawing, so a test can check the annotation rather than the number
  // the panel prints beside it.
  deltas: () =>
    !deltaAnnotation?.group.visible
      ? []
      : deltaAnnotation.legs
          .filter((leg) => leg.label.visible)
          .map((leg) => ({
            axis: leg.axis,
            text: leg.text,
            at: leg.label.position.toArray().map((v) => +v.toFixed(1)),
          })),
  grid: () => {
    // Rail numbers are flat quads lying in the deck, not sprites - they were sprites once, and
    // this counted them by that type long after they stopped being it.
    const out = {
      groups: gridMarks.length,
      lines: 0,
      labels: gridLabels.length,
      labelsDrawn: gridLabels.filter((l) => l.visible).length,
      at: null,
    };
    for (const g of gridMarks) {
      g.traverse((o) => {
        if (o.type === "LineSegments") out.lines++;
      });
    }
    if (gridLabels.length) {
      out.at = gridLabels[0]
        .getWorldPosition(new THREE.Vector3())
        .toArray()
        .map((v) => +v.toFixed(1));
    }
    return out;
  },
  // What a travelling part is doing: where it is drawn, where it has been told to go, and where
  // along it the drive's position refers to. A part that will not move is one of those three.
  arms: () =>
    arms.map((arm) => ({
      name: world?.names[arm.index],
      currentX: +arm.currentX.toFixed(2),
      targetX: +arm.targetX.toFixed(2),
      referenceOffset: arm.referenceOffset,
    })),
  hover: () => ({
    visible: hoverBox.visible,
    empty: hoverBox.box.isEmpty(),
    min: hoverBox.box.min.toArray().map((v) => +v.toFixed(1)),
    max: hoverBox.box.max.toArray().map((v) => +v.toFixed(1)),
  }),
  // What the toolbar's origins button does, for a test that has no pointer.
  origins: (on = true) => setOriginDots(on),
  // What the toolbar's halos button does, for the same reason.
  halos: (on = true) => setHalos(on),
  // The quality level, set when given, for a test that has no slow machine to hand.
  quality: (level) => {
    if (level !== undefined) applyQuality(level);
    return {
      level: qualityNow(),
      pixelRatio: renderer.getPixelRatio(),
      environment: view.environment !== null,
      pinned: qualityPinned,
    };
  },
  // Renders `frames` frames back to back and reports what each one cost. The viewer only draws
  // when something changes, so the cost of a frame is otherwise not observable from outside.
  benchmark: (frames = 120) => {
    // The counters run on until they are reset, so one frame is measured on its own.
    renderer.render(view, camera); // warm up
    renderer.info.reset?.();
    renderer.render(view, camera);
    const info = renderer.info.render;
    const calls = info.drawCalls ?? info.calls ?? 0;
    const triangles = info.triangles;
    const t = performance.now();
    for (let i = 0; i < frames; i++) renderer.render(view, camera);
    const ms = (performance.now() - t) / frames;
    return { frames, msPerFrame: +ms.toFixed(3), fps: Math.round(1000 / ms), calls, triangles };
  },
  // What the renderer is actually asked to draw, by kind: one line per group, a draw call each
  // unless it is instanced. Answering "where do the draw calls come from" without guessing.
  audit: () => {
    const kinds = {};
    view.traverse((o) => {
      if (!o.visible || !(o.isMesh || o.isLine || o.isPoints || o.isSprite)) return;
      for (let p = o.parent; p; p = p.parent) if (!p.visible) return;
      const drawn = o.material?.visible !== false;
      const kind = o.isInstancedMesh
        ? "instanced mesh"
        : o.isLine
          ? "line"
          : o.isSprite
            ? "sprite"
            : o.isPoints
              ? "points"
              : "mesh";
      const index = o.geometry?.index?.count ?? o.geometry?.attributes?.position?.count ?? 0;
      kinds[kind] ??= { objects: 0, drawn: 0, triangles: 0 };
      const row = kinds[kind];
      row.objects += 1;
      if (drawn) {
        row.drawn += 1;
        row.triangles += Math.round((index / 3) * (o.isInstancedMesh ? o.count : 1));
      }
    });
    return kinds;
  },
  sceneObjects: () => {
    let n = 0;
    view.traverse(() => n++);
    return n;
  },
};

const scaleLine = document.getElementById("scale-bar-line");

const scaleLabel = document.getElementById("scale-bar-label");

// Under perspective there is no single scale, so the bar is quoted at the orbit target's depth.
// Under orthographic there is one scale for the whole viewport, and the bar is exact.
// About how long the bar should be, in pixels. Long enough to read a number against, short enough
// to leave the corner it sits in.
const SCALE_BAR_PX = 120;

function updateScaleBar() {
  const perPixel = mmPerPixel();
  if (!Number.isFinite(perPixel) || perPixel <= 0) return;
  // Counted in floor cells rather than rounded on its own, so the bar always spans a whole number
  // of the squares it is drawn over. Both used to pick a nice number from the same 1-2-5 ladder
  // but for different pixel targets, which agree only sometimes - and a scale that disagrees with
  // the grid beneath it is worse than having no grid to check it against.
  const cell = gridState?.cell;
  const nice = cell
    ? cell * ([1, 2, 5].find((n) => (n * cell) / perPixel >= SCALE_BAR_PX) ?? 10)
    : niceNumber(perPixel * SCALE_BAR_PX);
  scaleLine.style.width = `${Math.round(nice / perPixel)}px`;
  scaleLabel.textContent = nice >= 1000 ? `${nice / 1000} m` : `${nice} mm`;
}

// Hover is answered once a frame at most, and not at all while a button is down.
//
// A pointer crossing the canvas fires far faster than frames are drawn, and every one of those
// events used to raycast the whole scene to produce a readout that had not changed. Measured, it
// cost more than panning the camera did - 12.2% of a profile against 4.5% - and none of it was our
// own code: it was three walking every instance of every model. Coalescing to a frame throws away
// the events nobody could have seen the result of. A pointer with a button down is driving the
// camera rather than pointing at anything, so there is nothing to pick.
let hoverAt = null;

// Answered by the loop, at the start of the frame the pointer's own input asked for. Answering it
// in a callback of its own instead put it a frame behind: the loop registers its callback first,
// because the input that starts it is handled in the capture phase, so the hover box and the delta
// lines were drawn one frame late and the last hover before the pointer stopped never drew at all.
function answerHover() {
  const at = hoverAt;
  hoverAt = null;
  if (at !== null && world) showHoverFor(at);
}

function showHoverFor(event) {
  const hit = pick(event);
  if (!hit) {
    readout.style.display = "none";
    clearHover();
    clearDeltaLines();
    return;
  }
  readout.style.display = "block";
  const rect = viewportEl.getBoundingClientRect();
  readout.style.left = `${event.clientX - rect.left + 14}px`;
  readout.style.top = `${event.clientY - rect.top + 14}px`;
  showHoverBox(hit.index);
  markTreeRow(hit.index);
  drawDeltaLines(hit.index);
  if (activeTool === "coords") {
    hoverBullseye.position.copy(deltaEndpoints(hit.index).to);
    hoverBullseye.visible = true;
  }
  const model = modelOf(hit.index);
  readout.textContent =
    activeTool === "coords"
      ? coordinateLabel(hit.index)
      : [world.names[hit.index], model.type, model.model].filter(Boolean).join("\n");
}

renderer.domElement.addEventListener("pointermove", (event) => {
  if (!world) return;
  if (event.buttons !== 0) {
    // Dragging: whatever the pointer passes over on the way is not being pointed at.
    readout.style.display = "none";
    clearHover();
    return;
  }
  hoverAt = { clientX: event.clientX, clientY: event.clientY };
});

renderer.domElement.addEventListener("pointerleave", () => {
  readout.style.display = "none";
  clearHover();
});

// Click behaviour follows the existing visualizer exactly. With the cursor tool a single click on
// a resource does nothing; what a canvas click does is close the info panel, guarded by 400 ms so
// the second click of a double click cannot close what the first one opened. A double click
// toggles: the same resource again closes it. The coordinate tool takes clicks instead, recording
// a measurement.
const PANEL_GUARD_MS = 400;

let panelOpenedAt = 0;

renderer.domElement.addEventListener("click", (event) => {
  // The helper owns its corner of the canvas; only if it declines does the click reach the scene.
  if (viewHelper) {
    viewHelper.center.copy(controls.target);
    if (viewHelper.handleClick(event)) return;
  }
  if (!world) return;

  if (activeTool === "coords") {
    const hit = pick(event);
    if (hit && hit.index !== undefined) recordMeasurement(hit.index);
    return;
  }
  if (performance.now() - panelOpenedAt > PANEL_GUARD_MS) closeInfoPanel();
});

renderer.domElement.addEventListener("dblclick", (event) => {
  if (!world || activeTool === "coords") return;
  const hit = pick(event);
  if (!hit || hit.index === undefined) return;
  if (selected === hit.index && infoPanel?.isConnected) {
    closeInfoPanel();
    return;
  }
  select(hit.index, true);
  panelOpenedAt = performance.now();
});

// tools
const toolButtons = {
  cursor: document.getElementById("toolbar-cursor-btn"),
  coords: document.getElementById("toolbar-coords-btn"),
  gif: document.getElementById("toolbar-gif-btn"),
};

const panels = {
  coords: document.getElementById("coords-panel"),
  gif: document.getElementById("gif-panel"),
};

// The active tool decides what a click on the canvas does; the open panel is separate, because
// the GIF panel does not change what clicking a resource means.
let openPanel = null;

function refreshToolUI() {
  toolButtons.cursor.classList.toggle("active", activeTool === "cursor");
  toolButtons.coords.classList.toggle("active", activeTool === "coords");
  toolButtons.gif.classList.toggle("active", openPanel === "gif");
  panels.coords.style.display = openPanel === "coords" ? "flex" : "none";
  panels.gif.style.display = openPanel === "gif" ? "flex" : "none";
}

function setTool(tool) {
  activeTool = tool;
  if (tool !== "coords") clearDeltaLines();
  openPanel = tool === "coords" ? "coords" : openPanel === "coords" ? null : openPanel;
  refreshToolUI();
}

// The origins button is not a tool: it changes what is drawn, not what a click means.
const originsButton = document.getElementById("toolbar-origins-btn");

function setOriginDots(on) {
  originsButton.classList.toggle("active", on);
  const t = performance.now();
  showOriginDotsIf(on);
  return {
    on,
    dots: on ? (world?.names.length ?? 0) : 0,
    buildMs: +(performance.now() - t).toFixed(1),
  };
}

// The click is the edge, as it is for every other button: a frame is asked for where the press
// comes into the page, not where the scene changes. `plrViewer.origins` asks through `atBoundary`.
originsButton.addEventListener("click", () => {
  setOriginDots(!showOriginDots);
  invalidate();
});

// The halos button is the same kind of button: what is drawn changes, what a click means does not.
const halosButton = document.getElementById("toolbar-halos-btn");

halosButton.classList.toggle("active", showHalos);

function setHalos(on) {
  halosButton.classList.toggle("active", on);
  showHalosIf(on);
  return { on, halos: halos?.children.length ?? 0 };
}

halosButton.addEventListener("click", () => {
  setHalos(!showHalos);
  invalidate();
});

// How fast a move is drawn, kept across reloads: a viewer left watching a run stays as it was set.
// Storage may refuse - a private window, or site data cleared - and the default stands.
const glideSlider = document.getElementById("glide-rate");

try {
  const kept = window.localStorage?.getItem("plr.glideSeconds");
  if (kept !== null && kept !== undefined) glideSlider.value = kept;
} catch {
  /* left at the default */
}

setGlideSeconds(Number(glideSlider.value));

const glideLabel = document.getElementById("glide-label");

const sayGlide = () => {
  glideLabel.textContent = Number(glideSlider.value) ? `${glideSlider.value}s` : "off";
};

sayGlide();

glideSlider.addEventListener("input", () => {
  setGlideSeconds(Number(glideSlider.value));
  sayGlide();
  try {
    window.localStorage?.setItem("plr.glideSeconds", glideSlider.value);
  } catch {
    /* not remembered, which changes nothing about this session */
  }
  invalidate();
});

toolButtons.cursor.addEventListener("click", () => setTool("cursor"));

toolButtons.coords.addEventListener("click", () => setTool("coords"));

toolButtons.gif.addEventListener("click", () => {
  openPanel = openPanel === "gif" ? (activeTool === "coords" ? "coords" : null) : "gif";
  refreshToolUI();
});

// view presets and viewport furniture
// The axis presets live on the view helper now: click an axis there and the camera animates onto
// it. What the helper cannot do is choose a projection, so that button stays.
projectionButton.addEventListener("click", () =>
  setProjection(projection === "orthographic" ? "perspective" : "orthographic"),
);

const homeButton = document.getElementById("home-button");

homeButton.addEventListener("click", () => {
  goToStartView();
  // A flash while the camera moves, so the button that did it is the thing you were last looking
  // at. Long enough to register, short enough not to linger over a view that has already settled.
  homeButton.classList.add("clicked");
  setTimeout(() => homeButton.classList.remove("clicked"), 400);
});

document.getElementById("zoom-in-btn").addEventListener("click", () => dolly(0.8));

document.getElementById("zoom-out-btn").addEventListener("click", () => dolly(1.25));

// panel toggles
const leftRail = document.getElementById("toolbar-left");

const sidepanel = document.getElementById("sidepanel");

document.getElementById("toolbar-left-toggle").addEventListener("click", () => {
  leftRail.classList.toggle("collapsed");
  resize();
});

document.getElementById("toolbar-right-toggle").addEventListener("click", () => {
  sidepanel.classList.toggle("collapsed");
  resize();
});

// tree actions
const depthInput = input("tree-depth-input");

let allExpanded = false;

document.getElementById("toggle-expand-btn").addEventListener("click", () => {
  allExpanded = !allExpanded;
  expandAll(allExpanded);
});

document
  .getElementById("collapse-all-btn")
  .addEventListener("click", () => showToDepth(Number(depthInput.value) || 0));

depthInput.addEventListener("change", () => showToDepth(Number(depthInput.value) || 0));

// search
const searchView = document.getElementById("search-view");

const searchInput = input("search-input");

const searchResults = document.getElementById("search-results");

const treeButton = document.getElementById("toolbar-tree-btn");

const searchButton = document.getElementById("toolbar-search-btn");

function showPane(which) {
  const searching = which === "search";
  treeEl.style.display = searching ? "none" : "block";
  query(".sidepanel-header").style.display = searching ? "none" : "flex";
  searchView.style.display = searching ? "flex" : "none";
  treeButton.classList.toggle("active", !searching);
  searchButton.classList.toggle("active", searching);
  if (searching) searchInput.focus();
}

// Each rail button is a toggle, as the existing visualizer's are: it opens the panel on its own
// pane, switches panes when the other one is showing, and closes the panel when its own pane
// already is. Closing is a class, and the stylesheet's width beats the resize handle's inline one,
// so a panel dragged wider comes back the width it was left at.
function pickPane(which, button) {
  const showing = !sidepanel.classList.contains("collapsed") && button.classList.contains("active");
  sidepanel.classList.toggle("collapsed", showing);
  if (showing) button.classList.remove("active");
  else showPane(which);
  resize();
}

treeButton.addEventListener("click", () => pickPane("tree", treeButton));

searchButton.addEventListener("click", () => pickPane("search", searchButton));

// Matching as the existing visualizer matches: every term of the query must be found, as a
// subsequence, in the name or the type; an exact name outranks a prefix, a prefix a substring, a
// substring a mere subsequence; ties keep the scene's order. No cap on hits.
function fuzzyMatch(term, text) {
  let at = 0;
  for (let i = 0; i < text.length && at < term.length; i++) if (text[i] === term[at]) at++;
  return at === term.length;
}

function fuzzyScore(term, text) {
  if (text === term) return 4;
  if (text.startsWith(term)) return 3;
  if (text.includes(term)) return 2;
  return 1;
}

function runSearch() {
  if (!world) return;
  const query = searchInput.value.trim().toLowerCase();
  const includeWells = input("search-include-wells").checked;
  const includeTips = input("search-include-tips").checked;
  const includeSites = input("search-include-sites").checked;
  searchResults.textContent = "";
  if (!query) {
    searchResults.innerHTML = '<div class="search-empty">Type to search.</div>';
    return;
  }
  const terms = query.split(/\s+/);
  const hits = [];
  for (let i = 0; i < world.names.length; i++) {
    const category = modelOf(i).category;
    if (SEARCH_CONTAINERS.has(category) && !includeWells) continue;
    if (category === "tip_spot" && !includeTips) continue;
    if (HOLDERS.has(category) && !includeSites) continue;
    const name = world.names[i].toLowerCase();
    const type = String(modelOf(i).type ?? "").toLowerCase();
    let score = 0;
    for (const term of terms) {
      if (fuzzyMatch(term, name)) score += fuzzyScore(term, name);
      else if (fuzzyMatch(term, type)) score += fuzzyScore(term, type);
      else {
        score = -1;
        break;
      }
    }
    if (score >= 0) hits.push({ index: i, score });
  }
  hits.sort((a, b) => b.score - a.score || a.index - b.index);
  if (!hits.length) {
    searchResults.innerHTML = '<div class="search-empty">No resource matches.</div>';
    return;
  }
  for (const { index } of hits) {
    const row = document.createElement("div");
    row.className = "search-result";
    row.innerHTML =
      `<span class="tree-node-dot" style="background:${hexOf(colorFor(modelOf(index)))}"></span>` +
      `<span class="sr-name">${escapeHtml(world.names[index])}</span>` +
      `<span class="sr-type">${escapeHtml(modelOf(index).type)}</span>`;
    row.addEventListener("mouseenter", () => showHoverBox(index));
    row.addEventListener("mouseleave", () => (hoverBox.visible = false));
    row.addEventListener("click", () => {
      showPane("tree");
      select(index);
      frameBox(worldBox(index), VIEWS.iso);
    });
    searchResults.appendChild(row);
  }
}

searchInput.addEventListener("input", runSearch);

for (const id of ["search-include-wells", "search-include-tips", "search-include-sites"]) {
  document.getElementById(id).addEventListener("change", runSearch);
}

// sidepanel resize
const resizeHandle = document.getElementById("sidepanel-resize-handle");

let resizingFrom = null;

resizeHandle.addEventListener("pointerdown", (e) => {
  resizingFrom = { x: e.clientX, width: sidepanel.offsetWidth };
  resizeHandle.setPointerCapture(e.pointerId);
});

resizeHandle.addEventListener("pointermove", (e) => {
  if (!resizingFrom) return;
  const width = Math.max(
    150,
    Math.min(window.innerWidth * 0.6, resizingFrom.width - (e.clientX - resizingFrom.x)),
  );
  sidepanel.style.width = `${width}px`;
  resize();
});

resizeHandle.addEventListener("pointerup", () => (resizingFrom = null));

// A scene arriving whole: everything drawn is built again from it, in this order, with what the
// reader had open put back afterwards.
function rebuildScene(data) {
  // A page is fetched fresh on every load; the Python serving it is as old as its process. A
  // scene from another protocol is not drawn, since what it says would be misread.
  if (data.protocol !== PROTOCOL) {
    window.dispatchEvent(new CustomEvent("plr:mismatch"));
    return;
  }
  const _tScene = performance.now();
  sceneArrived();
  setStats(data.stats ?? {});
  const kept = rememberView();
  setWorld(buildWorld(data));
  glides.clear();
  timings.decodeMs = performance.now() - _tScene;
  const _tBuild = performance.now();
  forgetDetail();
  buildMeshes();
  resetFloor(sceneBounds().min.z);
  buildGridMarks();
  buildArms();
  buildReferenceMarks();
  buildDeclaredMeshes();
  buildOrigin();
  buildOriginDots();
  buildHalos();
  timings.meshesMs = performance.now() - _tBuild;
  const _tTree = performance.now();
  buildTree();
  // A rebuild draws everything at its true position, but what was switched off stays switched
  // off: the tree is rebuilt on every assignment while a deck is being laid out, and without
  // this, hiding a plate and then assigning anything at all put the plate and its wells back
  // on screen with the eye still showing them as hidden.
  for (const name of [...hiddenNames]) setHidden(name, true);
  deviceTools.rebuild();
  timings.treeMs = performance.now() - _tTree;
  timings.readyMs = performance.now() - _t0;
  populateWrtDropdown();
  selected = -1;
  selectionBox.visible = false;
  hideInfoPanel();
  stateOf.clear();
  restoreView(kept);
  resize();
  // Only the first scene of a connection frames the camera. A tree that is assembled while the
  // viewer watches rebuilds on every assignment, and framing each one would throw the view away
  // as you build. The camera holds no scene indices, so it survives a rebuild unchanged.
  if (!framed) {
    goToStartView();
    framed = true;
  }
}

// The rows under the nearest ancestor that has one, listed again if it is open, so a moved
// resource is shown where it now stands. A holder has no row of its own; its carrier does.
function reopenRowsUnder(index) {
  let at = index;
  while (at >= 0 && !rowOf.has(at)) at = world.parentOf[at];
  if (at < 0 || !expanded.has(at)) return;
  toggle(at, false);
  toggle(at, true);
}

// The camera is read at capture time: a view change swaps it, and the recording follows the view.
const gif = initGif({
  renderer,
  view,
  get camera() {
    return camera;
  },
});

// The tree, the panels and the toolbars all change the scene through their own handlers. Rather
// than raise the flag in each one and miss the next one added, any input earns a frame: the cost is
// one redraw per interaction, and it stops the moment the pointer does.
for (const kind of ["pointerdown", "pointerup", "keydown", "click"]) {
  document.addEventListener(kind, invalidate, { passive: true, capture: true });
}

// A pointer moving is the one input that arrives faster than frames, and it only reaches the
// picture through the viewport: elsewhere a move changes nothing until it crosses into a row that
// raises a hover box, so the crossing asks, not the move. Over the viewport a move is answered
// with a raycast and a frame; on a machine whose frames are slow that is asked for at most every
// HOVER_SLOW_INTERVAL_MS, with the last move always answered, so the readout never lags behind
// a pointer that has stopped.
const HOVER_SLOW_FRAME_MS = 24;

const HOVER_SLOW_INTERVAL_MS = 150;

let hoverAskedAt = 0;

let hoverTrailing = null;

viewportEl.addEventListener(
  "pointermove",
  () => {
    const now = performance.now();
    if (lastFrameMs < HOVER_SLOW_FRAME_MS || now - hoverAskedAt >= HOVER_SLOW_INTERVAL_MS) {
      hoverAskedAt = now;
      invalidate();
      return;
    }
    if (hoverTrailing === null) {
      hoverTrailing = setTimeout(
        () => {
          hoverTrailing = null;
          hoverAskedAt = performance.now();
          invalidate();
        },
        HOVER_SLOW_INTERVAL_MS - (now - hoverAskedAt),
      );
    }
  },
  { passive: true, capture: true },
);

viewportEl.addEventListener("wheel", invalidate, { passive: true, capture: true });

for (const kind of ["mouseover", "mouseout"]) {
  document.addEventListener(
    kind,
    (event) => {
      const target = /** @type {Element | null} */ (event.target);
      if (target?.closest?.(".tree-node-row, .search-result, #viewport")) invalidate();
    },
    { passive: true, capture: true },
  );
}

// What a frame runs, in order. Three things keep drawing on their own account: the helper's snap
// animation, an arm gliding to a new position, and a recording that needs a frame to capture;
// `controls.update` reports whether damping is still carrying the camera.
whileMoving(() => {
  // At most one hover answered per frame, however many times the pointer moved in between: a
  // pointer crosses the canvas far faster than frames are drawn, and each answer raycasts the
  // whole scene to produce a readout nobody could have seen the previous version of.
  if (hoverAt !== null) answerHover();
  return false;
});

whileMoving((delta) => {
  if (!viewHelper?.animating) return false;
  viewHelper.update(delta);
  // Every direction the helper can snap to is axis-aligned, so the view it lands on is a plan or
  // an elevation. Switch once the animation is done, not during it, since changing projection
  // rebuilds the helper.
  if (!viewHelper.animating) setProjection("orthographic");
  return true;
});

whileMoving(() => {
  if (deltaAnnotation?.group.visible) updateDeltaLabels();
  return false;
});

whileMoving(updateArms);

whileMoving(updateGlides);

whileMoving(() => controls.update());

whileMoving(() => gif.isRecording());

// What the camera can see decides what is worth drawing, so it is decided before the frame is
// drawn rather than after it. Asked afterwards, every frame drew what the frame before it had
// worked out, and the last frame of a move - the one left on screen - never drew its own answer
// at all: a zoom settled with the detail of where it started, a window resize changed nothing
// until the camera next moved, and a view turned to a plan kept the colours of the angle it came
// from. Nothing here asks for another frame; they are worked out for this one.
for (const prepare of [
  updateGrid,
  updateDetail,
  updateEdgeMode,
  updateOrigin,
  updateHalos,
  updateBullseyes,
  updateScaleBar,
]) {
  beforeDraw(prepare);
}

afterDraw(() => {
  if (!viewHelper) return;
  // The helper renders a second pass into a corner of the same canvas. Without turning auto-clear
  // off it clears the colour buffer for that corner first, leaving a blank patch over the scene.
  renderer.autoClear = false;
  viewHelper.render(renderer);
  renderer.autoClear = true;
});

afterDraw(() => gif.tick());

// The panels and the tree follow the live state: told what changed, each redraws its own part.
onChange((change) => {
  if (change.kind === "glide") {
    if (change.index !== selected) return;
    selectionBox.box.copy(worldBox(change.index));
    refreshPlacement(change.index);
  } else if (change.kind === "state") {
    // Only a panel showing something this message touched is drawn again: drawing the rest
    // afresh reset what the reader had opened in it, on every well of a protocol.
    if (change.changed.has(selected) && infoPanel?.isConnected) renderInfoPanel();
    refreshTreeInfo();
    deviceTools.refresh(change.changed);
  } else if (change.kind === "moves") {
    for (const at of change.rowsUnder) reopenRowsUnder(at);
    refreshTreeInfo();
    deviceTools.refresh();
    if (selected >= 0 && infoPanel?.isConnected) renderInfoPanel();
  } else if (change.kind === "visibility") {
    refreshTreeVisibility();
  }
});

initTransport({
  renderer,
  handlers: {
    // A new socket frames the camera on its first scene, and on that one only.
    opened: () => {
      framed = false;
    },
    scene: rebuildScene,
    state: (data) => {
      if (world) applyState(data);
    },
    moves: (moves) => {
      if (world && Array.isArray(moves)) applyMoves(moves);
    },
  },
});

buildViewHelper();

refreshToolUI();

showPane("tree");

resize();

connect();
