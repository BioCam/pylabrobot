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

import * as THREE from "three";
import { DRACOLoader } from "three/addons/DRACOLoader.js";
import { GLTFLoader } from "three/addons/GLTFLoader.js";
import { LineSegments2 } from "three/addons/lines/LineSegments2.js";
import { LineSegmentsGeometry } from "three/addons/lines/LineSegmentsGeometry.js";
import { OrbitControls } from "three/addons/OrbitControls.js";
import { RoomEnvironment } from "three/addons/RoomEnvironment.js";
import { ViewHelper } from "three/addons/ViewHelper.js";

import {
  ARM_COLOR,
  ARM_EDGE,
  ARM_EDGE_WIDTH_3D,
  ARM_EDGE_WIDTH_FLAT,
  ARM_INSET_X,
  ARM_INSET_Y,
  ARM_OPACITY,
  ARM_REFERENCE_OPACITY,
  BOX_OPACITY,
  BULLSEYE_HOVER,
  BULLSEYE_PX,
  BULLSEYE_WRT,
  CATEGORY_OPACITY,
  CHANNEL_RAMP,
  CHANNEL_RAMP_DARK_INK_STEPS,
  CONTAINERS,
  CONTENTS,
  DEG,
  EDGE_WIDTH_3D,
  EDGE_WIDTH_FLAT,
  FILTER,
  FILTER_BELOW_COLLAR,
  FILTER_WIDTH_UNMEASURED,
  FLAT_EDGE,
  GLAZED_MAX_OPACITY,
  GRIP_MARK_OPACITY,
  GRIP_MARK_OPENING,
  GRIP_MARK_WIDTH,
  HALO_CENTRED_AT,
  HALO_INK,
  HALO_MARK_PX,
  HALO_OFFSET_PX,
  HALO_PX,
  HALO_TIPPED_BACKGROUND,
  HOLDERS,
  HOVER,
  LIQUID,
  MODEL_EDGE_OPACITY,
  MOVING_OPACITY,
  MOVING_PARTS,
  NO_REFERENCE_MARK,
  PICKABLE_PARTS,
  PROTOCOL,
  QUALITY_FAST_MS,
  QUALITY_HOLD_MS,
  QUALITY_LEVELS,
  QUALITY_RECOVER_MS,
  QUALITY_SETTLE_MS,
  QUALITY_SLOW_MS,
  QUALITY_WARMUP_MS,
  REFERENCE_DROP,
  REFERENCE_LINE,
  REFERENCE_WIDTH,
  RESOURCE_COLORS,
  SEARCH_CONTAINERS,
  SELECT,
  SELECTION_SHOWN_MS,
  SHELL_OPACITY,
  SKY_LIGHT,
  SKY_LIGHT_WITHOUT_ENVIRONMENT,
  SPACE_OPACITY,
  structureEdgeStyle,
  TIP_PLAN_FILL,
  TREE_HIDDEN,
  VESSEL_EMPTY,
  VESSEL_RIM,
  VESSEL_WALL,
  VESSEL_WALL_OPACITY,
} from "./constants.js";
import { initCoords } from "./coords.js";
import { initDeviceTools } from "./device_tools.js";
import { input, query } from "./dom.js";
import { escapeHtml, fmt, NBSP, section, tuple, withUnit } from "./format.js";
import { initGif } from "./gif.js";
import {
  buildWorld,
  mirrorPlacement,
  modelOf,
  refreshTransforms,
  setLocal,
  setLocalRotation,
  setWorld,
  sizeOf,
  treeDepth,
  world,
} from "./world.js";

const timings = { moduleMs: performance.now() - _t0 };

// ---------------------------------------------------------------- ownership

// What each builder made for itself last time - geometries, materials, textures, instance buffers -
// so it can let them go before making them again. Nothing shared is ever listed here.
const ownedBy = new Map();

function own(owner, ...things) {
  if (!ownedBy.has(owner)) ownedBy.set(owner, []);
  ownedBy.get(owner).push(...things);
}

/** Release what an owner made. The renderer keeps a draw's state until its material is disposed. */
function disposeOwned(owner) {
  for (const thing of ownedBy.get(owner) ?? []) thing.dispose();
  ownedBy.delete(owner);
}

// ---------------------------------------------------------------- state

let meshes = [];
let placementOf = []; // instance index -> { mesh, slot }
let vesselOf = new Map(); // index -> the inner body whose colour tracks what is in it
// index -> the instanced parts drawn for it outside the box pipeline, and where each one stands.
// Switching a resource off empties its box; these have to be emptied with it, or hiding a plate
// leaves ninety-six cavities and their walls floating where the plate was.
let overlayOf = new Map();
// model index -> the filter discs drawn in its tips, so reading the tip's file can size them.
let filterDiscsOf = new Map();
let edgeOf = new Map();
// The instances whose model arrived as a file. Their box is not drawn at all and its border is
// only just there, and both have to be decided from here rather than at the moment the file
// landed: everything that says what is drawn runs again on every view change, so a one-off switch
// would be undone by the next orbit past an axis.
let drawnFromFile = new Set();
const stateOf = new Map();
const hiddenNames = new Set();
let selected = -1;
let stats = {};
let activeTool = "cursor";
let framed = false; // whether this connection has framed the camera on its first scene

// ---------------------------------------------------------------- renderer

const viewportEl = document.getElementById("viewport");
// No `preserveDrawingBuffer`: this three never reads it, and a GIF frame is captured through a
// render target rather than off the canvas.
const renderer = new THREE.WebGPURenderer({ antialias: true });
const _tInit = performance.now();
await renderer.init();
timings.rendererMs = performance.now() - _tInit;
renderer.setPixelRatio(Math.min(window.devicePixelRatio, 2));
// No tone mapping: it compresses the top of the range, which turns a pure white background grey.
// Over-exposure is handled by budgeting the lights instead.
renderer.toneMapping = THREE.NoToneMapping;
viewportEl.appendChild(renderer.domElement);

const view = new THREE.Scene();
// A shade off white, so the deck has something to be brighter than. Pure white left the work
// surface - which is very nearly white itself - with no edge against the space around it, and the
// whole view read as washed out. The number to turn if it wants more or less separation.
const BACKGROUND = 0xe8ecef;
view.background = new THREE.Color(BACKGROUND);

// Two projections. Perspective reads a three-dimensional scene better; orthographic is what an
// axis view has to be, because under perspective only the point directly beneath the camera
// projects straight down and everything else is seen at an angle. A plan view with converging
// verticals is not a plan view.
const perspectiveCamera = new THREE.PerspectiveCamera(45, 1, 1, 20000);
const orthographicCamera = new THREE.OrthographicCamera(-1, 1, 1, -1, -20000, 20000);
for (const c of [perspectiveCamera, orthographicCamera]) c.up.set(0, 0, 1); // PLR is Z-up

let camera = perspectiveCamera;
let projection = "perspective";

// Drawing only when something has changed. A scene with nothing moving in it costs a full core at
// sixty frames a second otherwise, which is the wrong price for a viewer meant to sit open beside a
// running protocol all day. Anything that changes what is on screen raises this flag; the loop
// draws once and lowers it again.
let renderPending = true;
let lastRenderAt = 0;
let looping = false;

// Skipping the draw is not enough on its own: the per-frame callback alone costs a third of a core,
// because it is still called sixty times a second to decide there is nothing to do. So the loop is
// stopped outright when the scene settles, and started again by whatever changes it.
//
// Raised at the edges of the viewer rather than wherever something happens to change: a message
// arriving, an input, a resize, a call from outside. That way adding a function that changes the
// scene cannot forget to ask for a frame, which is a silent freeze - the failure this had five
// times over while it was the caller's job to remember.
function invalidate() {
  renderPending = true;
  if (!looping) {
    looping = true;
    clock.getDelta(); // discard the idle gap, or the first frame back sees a huge delta
    // The frame-rate window restarts with the loop. Left running across the idle gap, the first
    // frame back averages out to nothing and reads as "0 fps".
    frames = 0;
    lastSample = performance.now();
    renderer.setAnimationLoop(drawFrame);
  }
}

const controls = new OrbitControls(camera, renderer.domElement);
controls.enableDamping = true;
controls.addEventListener("change", invalidate);
controls.dampingFactor = 0.12;

// A mouse has no second finger and a laptop has no middle button, so panning is bound to whichever
// each one has. Out of the box the middle button dollies, which the wheel already does.
controls.mouseButtons = {
  LEFT: THREE.MOUSE.ROTATE,
  MIDDLE: THREE.MOUSE.PAN,
  RIGHT: THREE.MOUSE.PAN,
};

// ---------------------------------------------------------------- two-finger pan

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

// Lighting that rides with the camera. Lights fixed in the world make the same surface a different
// colour from every angle - a top face catches the key from above and washes out, a side face goes
// dark - and looking down an axis is exactly where a device modelled in white stops reading.
// Carried on the camera, the shading a surface gets follows its own shape and not where you stand,
// so a view can change without anything changing colour, and the form is still there to see.
//
// A key off to one side rather than straight down the lens: dead-on light flattens as surely as no
// light at all, because every face pointing at you gets the same amount of it.
const lights = new THREE.Group();
const skyLight = new THREE.HemisphereLight(0xffffff, 0xeceff1, SKY_LIGHT);
lights.add(skyLight);
const keyLight = new THREE.DirectionalLight(0xffffff, 0.9);
keyLight.position.set(-0.6, 0.5, 1);
lights.add(keyLight);
const fillLight = new THREE.DirectionalLight(0xffffff, 0.45);
fillLight.position.set(0.8, -0.4, 0.6);
lights.add(fillLight);
camera.add(lights);
view.add(camera);

// A metal surface has almost no diffuse colour of its own; it is what it reflects. Without an
// environment it renders nearly black under directional lights, so give the scene something to
// reflect. Kept dim, so the flat technical shading of everything else is barely touched.
try {
  const pmrem = new THREE.PMREMGenerator(renderer);
  view.environment = pmrem.fromScene(new RoomEnvironment(), 0.04).texture;
  view.environmentIntensity = 0.45;
  // Kept, so a quality level that takes the lighting away can give it back.
  view.userData.roomEnvironment = view.environment;
  pmrem.dispose();
} catch (error) {
  console.warn("no environment map; metal surfaces will look flat", error);
}

// A resource that lays things out on a repeated grid says so in its model, and the viewer draws
// whatever it is told: how many, how far apart, where the first one sits, how to label them.
// Nothing here knows what a rail is, so a deck with slots or a nest with positions draws the same
// way the day it declares one.
let gridMarks = [];
// Every rail number in the scene. They are one draw call each and the largest per-device cost the
// viewer has, so they are the first thing to stop drawing once they are too small to read.
let gridLabels = [];
let surfaces = [];
let arms = []; // { group, index, referenceOffset, targetX, currentX }

const GRID_LINE = 0x4a545c; // dark, so it reads on a light deck as the numbers beside it do
const GRID_LABEL = "#3d4a52";
const GRID_LIFT = 0.4; // mm above the surface, so the marks do not fight the deck for depth
// The work surface a grid is laid out on. A resource that declares a grid is declaring that things
// stand on it at that height, so that is where the surface goes; nothing here knows it is a deck.
const SURFACE_COLOR = 0xfbfcfd; // the deck is the brightest thing; what stands on it is darker
// The work surface is a lid over everything the instrument keeps below it, and drawing it hid all
// of that. Fully transparent, what stands on the deck reads against the space around it rather than
// against a sheet the same colour. The number to turn: above zero the surface is drawn again, and in
// an axis view it will paint over what stands on it, because a transparent material draws after
// every opaque one and depth testing is off there.
const SURFACE_OPACITY = 0;

// What counts as ground rather than as an object standing on it.
const GROUND = new Set(["facility", "deck"]);
// Bands a capability can reach across a surface, drawn as a pair of lines with the reach labelled
// at the near edge. Blue keeps them apart from the grey position grid they cross.
const BAND_COLOR = 0x8ba7c6;
const GRID_LABEL_MM = 30; // label height in deck millimetres
const GRID_TICK = 30; // mm the mark runs forward of the grid, into the margin where labels sit
// How far a number keeps from the front edge of what it is drawn on, in mm. Only reached where the
// resource has no margin to give: a deck runs on well ahead of its first carrier, and a loading
// tray's grid starts at the tray's own front edge.
const GRID_MARGIN = 4;
// How strongly a track mark shows through what is standing on it. A carrier with a solid base hides
// the very mark that says which track it is on, and which track a carrier is on is most of what a
// person reads a deck for - but a line at full strength over an opaque part reads as an error
// rather than as a reference. Faint, it reads the way a hidden line does on a drawing: behind the
// thing, and still there.
//
// Set against the ink, not on its own: 0.3 of a near-white line was barely there, and the same 0.3
// of the dark line that replaced it painted stripes across every carrier floor, which reads as a
// floor you can see through rather than as a mark behind one.
const GRID_GHOST_OPACITY = 0.14;
// A number is drawn inside its quad with room above and below it, so the quad's edge is not where
// the ink stops. This is how much of the quad's height the digits actually take - a bold face's
// cap height against the canvas the label is drawn on - and it is what a margin has to be measured
// against, or the gap comes out 8.5 mm wider than it says.
const GRID_LABEL_INK = 0.433;

function labelSprite(text, color = GRID_LABEL, sizeMm = GRID_LABEL_MM) {
  const canvas = document.createElement("canvas");
  canvas.width = 128;
  canvas.height = 64;
  const context = canvas.getContext("2d");
  context.font = "bold 38px ui-monospace, Menlo, monospace";
  context.fillStyle = color;
  context.textAlign = "center";
  context.textBaseline = "middle";
  context.fillText(text, 64, 34);
  const texture = new THREE.CanvasTexture(canvas);
  texture.colorSpace = THREE.SRGBColorSpace;
  // A flat quad in the surface's own plane, not a sprite. A sprite turns to face the camera, which
  // is right for a marker and wrong for a number painted on a deck: these are part of the drawing,
  // so they lie in it. PlaneGeometry is already in XY, which is the surface's plane.
  const label = new THREE.Mesh(
    new THREE.PlaneGeometry(sizeMm * 2, sizeMm),
    new THREE.MeshBasicMaterial({ map: texture, transparent: true, depthTest: false }),
  );
  label.frustumCulled = false;
  return label;
}

// Where the device's x refers to, from the resource's own origin. Declared by the resource, so the
// viewer needs no knowledge of rail types: a dual-rail arm reports its centre, a single-rail one its
// right edge, and the line lands in the right place either way. Half the width when undeclared.
function referenceOffset(model) {
  const [sx] = sizeOf(model);
  return model.reference_point?.x ?? sx / 2;
}

// Geometry a resource declared for itself, drawn in place of its box.
//
// The file is loaded once per model and shared by every instance of it, the same way one geometry
// serves every well of a plate. Loading is asynchronous and the scene is already on screen by the
// time it lands, so each mesh is added when it arrives rather than being waited for: the box shows
// until then, and nothing blocks.
const gltfLoader = new GLTFLoader();
// Draco-compressed meshes are common in files exported for the web, and cannot be read without a
// decoder. It is fetched only when a compressed mesh actually turns up, so a viewer that never
// loads one pays nothing for it. Only the WebAssembly decoder is vendored; the much larger
// JavaScript fallback is for browsers that predate WebAssembly, which cannot run this viewer anyway.
const dracoLoader = new DRACOLoader();
dracoLoader.setDecoderPath("./vendor/draco/");
dracoLoader.setDecoderConfig({ type: "wasm" });
gltfLoader.setDRACOLoader(dracoLoader);
let meshRoots = [];
// Counted up per rebuild, so a file that lands late is placed only by the scene that asked for it.
let sceneGeneration = 0;
// A model drawn for many resources at once: one instanced mesh per mesh in its file, however many
// resources stand on it. A clone apiece is a draw call apiece, and a rack of tips is ninety-six of
// them. Each entry is { modelIndex, instances, meshes }.
let modelMeshes = [];
// Every file that has been fetched and parsed, by url. A tree that changes shape sends a whole
// scene, and an instanced mesh cannot be resized - so the meshes are built again, from this,
// without going back to the network.
const parsedByUrl = new Map();

// What identifies a drawn model across rebuilds: the resource it belongs to and the file it was
// drawn from. A scene arrives whole whenever the tree changes shape, and most of what it describes
// is what was already on screen.
function meshKey(index) {
  return `${world.names[index]}\n${modelOf(index).mesh?.url}`;
}

// A model that is on screen puts its box away. Recorded on the entry rather than only switched
// off, because everything that decides what is drawn runs again on every view change, and each of
// those would otherwise put the box back over the model it was standing in for.
function modelIsDrawn(modelIndex) {
  // Geometry that has just arrived has not been asked whether it is big enough to be worth
  // drawing: that is decided per view, and the view has not changed just because a file loaded.
  detailScale = null;
  const entry = meshes.find((m) => m.modelIndex === modelIndex);
  if (!entry) return;
  entry.modelDrawn = true;
  entry.mesh.material.visible = false;
  for (const i of entry.instances) drawnFromFile.add(i);
  // A part that travels is drawn twice over: once as the open frame `buildArms` extrudes for it,
  // and now as itself. The frame and the stroke around it were standing in for geometry nobody
  // had, so they go the way the box does. The reference line stays: it marks where the drive
  // reports this part to be, which is not a fact about the shape and is the one thing the geometry
  // cannot say for itself.
  for (const arm of arms) {
    if (!entry.instances.includes(arm.index)) continue;
    arm.frame.visible = false;
    arm.outline.visible = false;
  }
  // The view is not going to change just because a file finished loading, so the border has to be
  // faded here as well as in the rule that keeps it faded.
  setRenderMode(planView ?? false);
}

// Put a model that is already on screen where the new scene says it is. Its geometry, its
// materials and its joints are the same objects; what changed is which instance it belongs to and
// the transform that places it.
function replaceInScene(root, index) {
  root.userData.index = index;
  root.matrix.copy(world.matrices[index]);
  root.matrixWorldNeedsUpdate = true;
  root.traverse((o) => {
    if (o.isMesh) o.userData.declaredBy = index;
  });
  applyJoints(index);
}

// glTF says metres and Y-up; a resource that means something else says so in its declaration.
const MESH_UNITS = { mm: 1, cm: 10, m: 1000 };

function buildDeclaredMeshes() {
  // What is on screen already, by the resource and file it was drawn for. A tree that changes
  // shape - a tip picked up, a plate moved - sends a whole scene, and rebuilding the geometry for
  // it would take every model off screen and put the boxes back until the files had been fetched
  // and parsed again. That flash is what this is here to stop.
  sceneGeneration++;
  const onScreen = new Map();
  for (const root of meshRoots) onScreen.set(root.userData.key, root);
  meshRoots = [];
  // An instanced mesh holds a fixed number of instances, so a scene with a different number of
  // them needs new ones. The file behind it is already parsed, so they are built again in this
  // same turn and nothing is ever off screen.
  for (const built of modelMeshes) for (const mesh of built.meshes) view.remove(mesh);
  disposeOwned(buildDeclaredMeshes);
  modelMeshes = [];

  // One load per distinct model, however many instances stand on it. A file of several hundred
  // thousand triangles is expensive to fetch and parse, and cloning shares both geometry and
  // materials, so the cost is paid once no matter how many arms are in the facility.
  const byModel = new Map();
  const kept = new Set();
  for (let index = 0; index < world.names.length; index++) {
    const declared = modelOf(index).mesh;
    if (!declared?.url) continue;
    const modelIndex = world.modelOf[index];
    const root = onScreen.get(meshKey(index));
    if (root !== undefined) {
      onScreen.delete(meshKey(index));
      replaceInScene(root, index);
      meshRoots.push(root);
      kept.add(modelIndex);
      continue;
    }
    if (!byModel.has(modelIndex)) byModel.set(modelIndex, []);
    byModel.get(modelIndex).push(index);
  }
  // Whatever is left belongs to a resource this scene does not have, or to one that now declares a
  // different file.
  for (const root of onScreen.values()) {
    view.remove(root);
    disposeOwned(root);
  }
  for (const modelIndex of kept) modelIsDrawn(modelIndex);

  for (const [modelIndex, instances] of byModel) {
    const declared = world.models[modelIndex].mesh;
    const scale = MESH_UNITS[declared.units] ?? 1;
    const names = instances.map((i) => world.names[i]);
    const generation = sceneGeneration;

    const place = (gltf) => {
      // The scene may have been rebuilt while this was in flight; that scene issued its own load.
      // Placing this one too would draw the model twice, and the same names do not make it current.
      parsedByUrl.set(declared.url, gltf);
      if (generation !== sceneGeneration) return;

      fitFilterDiscs(modelIndex, gltf.scene, scale, declared.up ?? "Y");

      // What rides something that travels keeps a copy of its own: it is drawn see-through and
      // in a layer of its own while it is being carried, and instances of one model share a
      // material, so a tip on a channel cannot be told from a tip in a rack through one. There
      // are never many of them - a head has eight channels, not ninety-six.
      const riding = instances.filter((index) => travels(index));
      const standing = instances.filter((index) => !travels(index));
      if (standing.length > 0) {
        buildInstancedModel(modelIndex, standing, gltf, scale, declared.up ?? "Y");
      }

      riding.forEach((index) => {
        const scene = gltf.scene.clone(true);
        scene.scale.setScalar(scale);
        // Y-up is glTF's default; a Z-up file is already in our own convention.
        if ((declared.up ?? "Y") === "Y") scene.rotation.x = Math.PI / 2;

        const root = new THREE.Group();
        root.add(scene);
        root.matrixAutoUpdate = false;
        root.matrix.copy(world.matrices[index]);
        root.matrixWorldNeedsUpdate = true;
        root.traverse((o) => {
          if (o.isMesh) {
            o.userData.declaredBy = index;
            // Its own material: the view sets opacity per resource, and a copy can be let go.
            o.material = o.material.clone();
            own(root, o.material);
            o.userData.lit = o.material;
            // What the file said, kept before a plan view changes it. A travelling part is put
            // into the same pass as the content below it, which means writing over its material's
            // own flags - and a material asked afterwards what it was modelled as would answer
            // with whatever the plan view just gave it.
            o.userData.asModelled = {
              transparent: o.material.transparent,
              opacity: o.material.opacity,
              depthWrite: o.material.depthWrite,
              glazed: o.material.transparent && o.material.opacity <= GLAZED_MAX_OPACITY,
            };
          }
        });

        // A rigged file names the parts that move. The declaration says which node answers to
        // which joint, so the viewer drives what it is told and holds no knowledge of any arm's
        // geometry. Each node's rest transform is kept, because a joint value is a displacement
        // from where the file was authored, not an absolute pose.
        const joints = new Map();
        for (const [key, spec] of Object.entries(declared.joints ?? {})) {
          const node = scene.getObjectByName(spec.node);
          if (!node) {
            console.warn(
              `${world.names[index]} declares joint ${key} on node ${spec.node}, which the file does not have`,
            );
            continue;
          }
          joints.set(key, {
            node,
            spec,
            restPosition: node.position.clone(),
            restQuaternion: node.quaternion.clone(),
          });
        }
        root.userData.joints = joints;
        root.userData.scale = scale;
        root.userData.index = index;
        root.userData.key = meshKey(index);

        view.add(root);
        meshRoots.push(root);
        applyJoints(index);
      });

      modelIsDrawn(modelIndex);
    };

    const parsed = parsedByUrl.get(declared.url);
    if (parsed !== undefined) {
      place(parsed);
      continue;
    }
    gltfLoader.load(declared.url, place, undefined, (error) =>
      console.warn(`could not load the mesh declared by ${names[0]}`, error),
    );
  }
}

/**
 * Draw one model for every resource standing on it, in one instanced mesh per mesh in its file.
 *
 * A cloned model is a draw call apiece: a tip carrier's five racks came to 1,544 of the 1,962 draws
 * a close view cost, for geometry that is the same tip ninety-six times over. Instanced, a model
 * costs one draw however many resources it is drawn for, and the geometry and the materials are
 * the ones the file was parsed into - shared, as the clones shared them.
 *
 * Each instance is registered the way a box's own parts are, so a resource that moves or is
 * switched off takes its geometry with it without this knowing anything about either.
 */
function buildInstancedModel(modelIndex, instances, gltf, scale, up) {
  const carrier = new THREE.Group();
  const scene = gltf.scene.clone(true);
  scene.scale.setScalar(scale);
  // Y-up is glTF's default; a Z-up file is already in our own convention.
  if (up === "Y") scene.rotation.x = Math.PI / 2;
  carrier.add(scene);
  carrier.updateMatrixWorld(true);

  const meshes = [];
  scene.traverse((o) => {
    if (!o.isMesh) return;
    // Where this mesh sits inside the file, with the file's units and its up-axis already in it.
    const local = o.matrixWorld.clone();
    const material = o.material.clone();
    const mesh = new THREE.InstancedMesh(o.geometry, material, instances.length);
    own(buildDeclaredMeshes, mesh, material);
    mesh.userData.instances = instances;
    mesh.userData.lit = material;
    mesh.userData.asModelled = {
      transparent: o.material.transparent,
      opacity: o.material.opacity,
      depthWrite: o.material.depthWrite,
      color: o.material.color.getHex(),
      glazed: o.material.transparent && o.material.opacity <= GLAZED_MAX_OPACITY,
    };
    instances.forEach((index, slot) => {
      placeInstance(mesh, slot, world.matrices[index], local);
      remember(index, mesh, slot, [local]);
    });
    mesh.instanceMatrix.needsUpdate = true;
    view.add(mesh);
    meshes.push(mesh);
  });
  modelMeshes.push({ modelIndex, instances, meshes });
  return meshes;
}

// Move a resource's mesh to the joint values it publishes.
//
// A revolute joint turns about its declared axis, a prismatic one slides along it. Both are applied
// as a displacement from the rest transform the file was authored in, so a value of zero puts the
// arm back exactly where the file drew it.
function applyJoints(index) {
  const root = meshRoots.find((r) => r.userData.index === index);
  if (!root) return;
  const published = stateOf.get(index)?.joints;
  if (!published) return;

  for (const [key, joint] of root.userData.joints) {
    const value = published[key];
    if (value === undefined || value === null) continue;
    const axis = AXIS_VECTOR[joint.spec.axis ?? "z"];
    if (!axis) continue;

    if (joint.spec.type === "prismatic") {
      // Published in millimetres; the node lives in the file's own units.
      const travel = value / (root.userData.scale || 1);
      joint.node.position.copy(joint.restPosition).addScaledVector(axis, travel);
    } else {
      const turn = new THREE.Quaternion().setFromAxisAngle(axis, value * DEG);
      joint.node.quaternion.copy(joint.restQuaternion).multiply(turn);
    }
  }
}

const AXIS_VECTOR = {
  x: new THREE.Vector3(1, 0, 0),
  y: new THREE.Vector3(0, 1, 0),
  z: new THREE.Vector3(0, 0, 1),
};

// A resource that says where the device's x refers to gets that point marked, whether or not it is
// an arm. An arm draws its own inside the group that carries it; everything else is marked here -
// the autoload's sled being the case that prompted it, since the drive reports its carrier-handling
// wheel rather than the sled's own corner.
let referenceMarks = [];

// A moving part is drawn as three objects rather than one instanced box - a reference line, the
// carriage, and the stroke that bounds it - so they need ordering against each other as well as
// against the scene. These are the three offsets, applied to whatever order the part is at: the
// line reads under the carriage, and the stroke over it. They match the offsets a static resource
// uses for its own surface and edge, so the two schemes interleave.
const ARM_LINE_OFFSET = -0.5;
const ARM_FRAME_OFFSET = 0;
const ARM_OUTLINE_OFFSET = 1;

// The reference mark on a resource that does not travel, drawn over its own resource but under the
// edge line that bounds it.
const REFERENCE_MARK_OFFSET = 0.75;

// What the tree calls a gripper, and what it calls the faces it grips with.
const GRIPPER = "mechanical_gripper";
const PAD = "pad";

/** The pad a gripper meets a resource with, as its model, or null where it grips with its fingers. */
function padOf(index) {
  const stack = [...world.childrenOf[index]];
  while (stack.length) {
    const at = stack.pop();
    if (modelOf(at).category === PAD) return modelOf(at);
    stack.push(...world.childrenOf[at]);
  }
  return null;
}

/**
 * A crosshair lying flat at the grip centre: two arms as long as a pad's face, crossing, with a
 * circular opening in the middle so the mark does not cover the very point it is marking.
 */
// How finely the opening's edge is stepped. Ten is smooth at any size this is ever drawn at.
const GRIP_ARC_STEPS = 10;

function gripCross(reach, width, opening) {
  const arm = reach / 2;
  const half = width / 2;
  // Each arm is its own shape, starting ON the circle rather than at the centre. Punching a hole
  // through one solid cross only works while the cross is wider than the hole, and it is not: the
  // opening is deliberately the wider of the two, so the arms stand clear of it.
  const theta = Math.asin(Math.min(1, half / opening));
  const shapes = [];
  for (let quarter = 0; quarter < 4; quarter++) {
    const turn = (quarter * Math.PI) / 2;
    const points = [];
    for (let step = 0; step <= GRIP_ARC_STEPS; step++) {
      const angle = turn - theta + (2 * theta * step) / GRIP_ARC_STEPS;
      points.push(new THREE.Vector2(opening * Math.cos(angle), opening * Math.sin(angle)));
    }
    for (const [x, y] of [
      [arm, half],
      [arm, -half],
    ]) {
      points.push(
        new THREE.Vector2(
          x * Math.cos(turn) - y * Math.sin(turn),
          x * Math.sin(turn) + y * Math.cos(turn),
        ),
      );
    }
    shapes.push(new THREE.Shape(points));
  }
  return new THREE.ShapeGeometry(shapes);
}

/** A crosshair lying flat at the grip centre, where the tool says its grip centre is. */
function buildGripMark(index, model, pad) {
  const tcp = model.tool_center_point;
  const [along] = sizeOf(pad);
  const plane = new THREE.Mesh(
    gripCross(along, GRIP_MARK_WIDTH, GRIP_MARK_OPENING),
    new THREE.MeshBasicMaterial({
      color: REFERENCE_LINE,
      transparent: true,
      opacity: GRIP_MARK_OPACITY,
      depthTest: false,
      side: THREE.DoubleSide,
    }),
  );
  own(buildReferenceMarks, plane.geometry, plane.material);
  plane.frustumCulled = false;
  plane.renderOrder = OVERLAY_ORDER + 5;
  plane.matrixAutoUpdate = false;
  // Lying flat, centred where the tool says it is programmed against. Read from the tool rather
  // than taken as the far end of its own box: the two agree on this gripper, and only because its
  // box is its link length - a tool that grips somewhere other than its tip would have the mark
  // drawn at the tip, which is the one place it is not.
  //
  // The tool states that point from its joint, not from its own origin, so the joint is added back:
  // left out, the mark stands the joint's offset away from where the jaws close.
  const joint = model.proximal_joint;
  plane.userData.local = new THREE.Matrix4().makeTranslation(
    joint.x + tcp.x,
    joint.y + tcp.y,
    joint.z + tcp.z,
  );
  plane.matrix.multiplyMatrices(world.matrices[index], plane.userData.local);
  plane.matrixWorldNeedsUpdate = true;
  view.add(plane);
  referenceMarks.push({ plane, index });
}

/** Whether this resource travels over the deck, itself or by riding something that does. */
function travels(index) {
  return MOVING_PARTS.has(modelOf(index).category) || carried(index);
}

/** Whether this resource rides something that travels, rather than standing on the deck. */
function carried(index) {
  for (let i = world.parentOf[index]; i >= 0; i = world.parentOf[i]) {
    if (MOVING_PARTS.has(modelOf(i).category)) return true;
  }
  return false;
}

function buildReferenceMarks() {
  for (const mark of referenceMarks) view.remove(mark.plane);
  disposeOwned(buildReferenceMarks);
  referenceMarks = [];

  // Draw these at the deck's working surface. A mark at the top of its own resource floats above
  // whatever it is pointing at, which on a part as tall as the autoload sled is 215 mm of daylight.
  // The surface is not the deck resource's origin - on a Hamilton deck that sits 100 mm below it -
  // but the z its rail grid is measured on, which is where anything seated on the deck stands.
  let deckZ = null;
  for (let index = 0; index < world.names.length; index++) {
    const deck = modelOf(index);
    if (deck.category !== "deck" || !deck.grid) continue;
    deckZ = world.matrices[index].elements[14] + deck.grid.origin[2];
    break;
  }

  for (let index = 0; index < world.names.length; index++) {
    const model = modelOf(index);

    // A gripper states the point it is programmed against, and that is what gets the mark. What is
    // worth seeing there is not a line on the deck but the face the pads close on, so the mark is
    // drawn as long as a pad - a crosshair in the middle, where the resource goes.
    if (model.category === GRIPPER) {
      const pad = padOf(index);
      // A tool that does not say where it grips gets no mark: the point is the tool's to state,
      // and guessing it from the box is what this stopped doing.
      if (pad && model.tool_center_point) buildGripMark(index, model, pad);
      continue;
    }

    if (!model.reference_point || MOVING_PARTS.has(model.category)) continue;
    if (NO_REFERENCE_MARK.has(model.category)) continue;
    const [, sy] = sizeOf(model);
    // Held in the resource's own frame, so a part that only travels in x keeps it as it moves.
    //
    // Dropped to the deck's surface for something standing on the deck, where a mark at the top of
    // a tall part would float above whatever it points at. A part CARRIED by an arm is not standing
    // on anything, so its mark rides with it - at the reference point's own height, which is the
    // height the drive reports and the only one worth marking. On a head that is the bottom of
    // shaft A1, eight millimetres below the plane the body is measured from; the mark used to sit
    // on that plane, which is the resource's origin and nothing the device ever refers to.
    const sz = carried(index)
      ? (model.reference_point.z ?? 0)
      : deckZ === null
        ? 0
        : deckZ - world.matrices[index].elements[14];
    const plane = new THREE.Mesh(
      new THREE.PlaneGeometry(REFERENCE_WIDTH, sy),
      new THREE.MeshBasicMaterial({
        color: REFERENCE_LINE,
        transparent: true,
        opacity: ARM_REFERENCE_OPACITY,
        depthTest: false,
        side: THREE.DoubleSide,
      }),
    );
    own(buildReferenceMarks, plane.geometry, plane.material);
    plane.frustumCulled = false;
    plane.renderOrder = paintOrderOf(index) + REFERENCE_MARK_OFFSET;
    plane.matrixAutoUpdate = false;
    plane.userData.local = new THREE.Matrix4().makeTranslation(referenceOffset(model), sy / 2, sz);
    plane.matrix.multiplyMatrices(world.matrices[index], plane.userData.local);
    plane.matrixWorldNeedsUpdate = true;
    view.add(plane);
    referenceMarks.push({ plane, index });
  }
}

/**
 * The opening in a moving part's frame, in the part's own frame: left, right, front, back in mm.
 *
 * Declared by the part when it knows its own geometry. A declared width is centred on the part
 * unless the part also says how far its right edge sits from the end, which is the case for an
 * opening that is deliberately off-centre.
 */
function armWindow(model) {
  const [sx, sy] = sizeOf(model);
  const window = model.window ?? {};
  const insetY = window.inset_y ?? ARM_INSET_Y;
  let left;
  let right;
  if (window.width === undefined) {
    left = ARM_INSET_X;
    right = sx - ARM_INSET_X;
  } else if (window.right_margin === undefined) {
    left = (sx - window.width) / 2;
    right = left + window.width;
  } else {
    right = sx - window.right_margin;
    left = right - window.width;
  }
  return [left, right, insetY, sy - insetY];
}

function buildArms() {
  for (const arm of arms) view.remove(arm.group);
  disposeOwned(buildArms);
  arms = [];

  for (let index = 0; index < world.names.length; index++) {
    const model = modelOf(index);
    if (!MOVING_PARTS.has(model.category)) continue;
    const [sx, sy, sz] = sizeOf(model);

    // Outer footprint with a rectangular hole, extruded to the part's height: a carriage you can
    // see the deck through, rather than a wall across it.
    const shape = new THREE.Shape();
    shape.moveTo(0, 0);
    shape.lineTo(sx, 0);
    shape.lineTo(sx, sy);
    shape.lineTo(0, sy);
    shape.closePath();
    const [holeLeft, holeRight, holeFront, holeBack] = armWindow(model);
    if (holeRight > holeLeft && holeBack > holeFront) {
      const hole = new THREE.Path();
      hole.moveTo(holeLeft, holeFront);
      hole.lineTo(holeLeft, holeBack);
      hole.lineTo(holeRight, holeBack);
      hole.lineTo(holeRight, holeFront);
      hole.closePath();
      shape.holes.push(hole);
    }

    const solid = new THREE.ExtrudeGeometry(shape, { depth: sz, bevelEnabled: false });
    // How the part looks, when it says: its colour and how metallic it reads. Otherwise every arm
    // is the same translucent grey.
    const appearance = model.appearance ?? {};
    const frame = new THREE.Mesh(
      solid,
      new THREE.MeshStandardMaterial({
        color: appearance.color ?? ARM_COLOR,
        metalness: appearance.metalness ?? 0,
        roughness: appearance.roughness ?? 0.6,
        transparent: true,
        opacity: ARM_OPACITY,
        depthWrite: false,
      }),
    );
    frame.renderOrder = paintOrderOf(index) + ARM_FRAME_OFFSET;
    own(buildArms, solid, frame.material);

    // Struck from the same extrusion, so the stroke follows the window and the footprint both.
    // It lives in the arm's own group, which is what moves, so there is nothing left behind to
    // keep in step - the failure the generic box outline had.
    const outlineEdges = new THREE.EdgesGeometry(solid);
    const outlineGeometry = new LineSegmentsGeometry();
    outlineGeometry.setPositions(outlineEdges.getAttribute("position").array);
    outlineEdges.dispose();
    const outlineMaterial = new THREE.Line2NodeMaterial({
      color: ARM_EDGE,
      linewidth: ARM_EDGE_WIDTH_3D,
      worldUnits: false,
    });
    own(buildArms, outlineGeometry, outlineMaterial);
    const outline = new LineSegments2(outlineGeometry, outlineMaterial);
    outline.frustumCulled = false;
    outline.renderOrder = paintOrderOf(index) + ARM_OUTLINE_OFFSET;

    const offset = referenceOffset(model);
    // Along the Y its reference point reaches, when the arm declares it, else the arm's whole depth.
    const [reachFront, reachBack] = model.reference_point?.y_range ?? [0, sy];
    const line = new THREE.Mesh(
      new THREE.PlaneGeometry(REFERENCE_WIDTH, reachBack - reachFront),
      new THREE.MeshBasicMaterial({
        color: REFERENCE_LINE,
        transparent: true,
        opacity: ARM_REFERENCE_OPACITY,
        depthTest: false,
      }),
    );
    line.position.set(offset, (reachFront + reachBack) / 2, -REFERENCE_DROP);
    own(buildArms, line.geometry, line.material);
    // Under the frame in paint order as well as in z, so it reads through the window and is tinted
    // by the carriage everywhere else. Ordering, not position, is what decides this: depth testing
    // is off in an axis view, so a lower render order is the only thing that puts it underneath.
    line.renderOrder = paintOrderOf(index) + ARM_LINE_OFFSET;

    const group = new THREE.Group();
    group.add(line, frame, outline);
    group.matrixAutoUpdate = false;
    group.matrix.copy(world.matrices[index]);
    group.matrixWorldNeedsUpdate = true;
    view.add(group);

    arms.push({ group, frame, outline, line, index, referenceOffset: offset, ...armPose(index) });
  }
}

/** Where an arm stands in the model: what its group is drawn from, and where its glide ends. */
function armPose(index) {
  const parent = world.parentOf[index];
  const local = world.local.slice(index * 6, index * 6 + 6);
  return {
    parentMatrix: parent >= 0 ? world.matrices[parent].clone() : new THREE.Matrix4(),
    local,
    currentX: local[0],
    targetX: local[0],
  };
}

// Glide rather than teleport, so a move reads as motion. The tracker carries commanded targets, so
// this interpolation is cosmetic and says nothing about where the arm physically is mid-move.
// How long a move takes to draw, in seconds. Off by default: a viewer watching a device should
// show where it is, and a glide is the drawing running that far behind. Turned up to follow a
// simulation, where the run is the thing being watched rather than the machine.
const DEFAULT_GLIDE_SECONDS = 0;
let glideSeconds = DEFAULT_GLIDE_SECONDS;

export function setGlideSeconds(seconds) {
  glideSeconds = Math.max(0, seconds);
}

const reducedMotion = window.matchMedia?.("(prefers-reduced-motion: reduce)");

function updateArms(delta) {
  const reduce = reducedMotion?.matches;
  let moved = false;
  for (const arm of arms) {
    if (Math.abs(arm.targetX - arm.currentX) < 0.01) continue;
    moved = true;
    arm.currentX =
      reduce || !glideSeconds
        ? arm.targetX
        : arm.currentX + (arm.targetX - arm.currentX) * Math.min(1, delta / glideSeconds);
    const local = new THREE.Matrix4().makeTranslation(arm.currentX, arm.local[1], arm.local[2]);
    arm.group.matrix.multiplyMatrices(arm.parentMatrix, local);
    arm.group.matrixWorldNeedsUpdate = true;

    // Keep the scene model in step with what is drawn. Everything else reads position from here -
    // the info panel, the selection box, the coordinate tool - so moving only the group would
    // leave all of them quoting where the arm used to be.
    mirrorPlacement(arm.index, arm.currentX, arm.group.matrix);
    // What the arm itself is drawn from. Its frame and outline ride the group and have moved
    // already, but everything else the arm owns is a separate object with a baked matrix - its
    // declared model above all, which hangs off the view rather than off the group - and the line
    // below deliberately skips the arm while it works out the subtree beneath it. Without this a
    // part drawn from a file stays where it was loaded while the arm travels out from under it,
    // which is what a model-drawn X-arm did: the reference line moved and the geometry did not.
    redraw([arm.index]);
    // Whatever rides the arm moves with it. Its own matrix is already set from the group, so only
    // what is beneath it needs working out.
    refreshSubtree(arm.index, true);
    if (selected === arm.index) {
      selectionBox.box.copy(worldBox(arm.index));
      refreshPlacement(arm.index);
    }
  }
  return moved;
}

// The tracked X, from the arm's own tracker when it has one. The frame's left edge sits at that X
// minus the reference offset, so the resource's box stays where the resource says it is.
// A resource has moved. Position is published as state now, the same way rotation always has been,
// so this is the one path by which anything that travels reaches the picture: an arm over a deck, a
// plate put down somewhere new, a robot between workcells.
//
// Its own transform changes, and so does the world transform of everything standing on it, so the
// subtree is recomputed and every instance in it repositioned.
// Recompute the world transform of everything at or beneath `index`, and move the drawn instances
// to match. A resource's own transform is relative to its parent, so a parent moving carries its
// children with it in the model for free - but the matrices the scene draws from are absolute, and
// those have to be worked out again.
// Move the drawn instances to wherever the world now says they are. The transforms are worked out
// in `world.js`, which has no idea any of this is on screen; this is only the part that is.
function redraw(indices) {
  const touched = new Set();
  for (const at of indices) {
    const [sx, sy, sz] = sizeOf(modelOf(at));
    // A resource that is switched off is drawn nowhere, and moving it does not turn it back on.
    // Putting the instance back at its new transform regardless is what brought a hidden plate's
    // wells back the moment anything under it moved.
    const visible = isVisible(at);
    const placement = placementOf[at];
    if (placement) {
      if (visible) placeInstance(placement.mesh, placement.slot, world.matrices[at], sx, sy, sz);
      else placement.mesh.setMatrixAt(placement.slot, ZERO);
      touched.add(placement.mesh);
    }
    // An outline is its own object with its own baked matrix, so a move that touched only the
    // instance left it standing at the old position - a wireframe ghost of whatever rode the arm.
    const line = edgeOf.get(at);
    if (line) line.matrix.copy(boxMatrix(world.matrices[at], sx, sy, sz));
    // A reference mark is its own object too, and marks a point ON the resource - so when the
    // resource travels, the point travels with it.
    for (const mark of referenceMarks) {
      if (mark.index !== at) continue;
      mark.plane.matrix.multiplyMatrices(world.matrices[at], mark.plane.userData.local);
      mark.plane.matrixWorldNeedsUpdate = true;
    }
    // A declared mesh is its own object with a baked matrix for the same reason, and needs the same
    // treatment: without it the model stays where it was loaded while the box it stood in for
    // travels on without it. An autoload sled driven along its rail showed exactly that - box in
    // one place, geometry in another.
    const root = meshRoots.find((r) => r.userData.index === at);
    if (root) {
      root.matrix.copy(world.matrices[at]);
      root.matrixWorldNeedsUpdate = true;
    }
    // A well's rim and cavity are their own instances, so a move that touched only the box left
    // them where the resource was - and left them standing when the resource was switched off.
    placeParts(at, touched);
  }
  for (const mesh of touched) {
    mesh.instanceMatrix.needsUpdate = true;
    mesh.boundingSphere = null;
  }
}

function refreshSubtree(index, skipSelf) {
  redraw(refreshTransforms(index, skipSelf));
}

function applyLocation(index, location) {
  // A travelling part is drawn by its own group and glides there, so it is told the target rather
  // than being moved under it. What stands on it is not part of that group, though - the 96-head
  // rides the arm in the model but is drawn with everything else - so the glide carries it.
  if (MOVING_PARTS.has(modelOf(index).category)) {
    const arm = arms.find((a) => a.index === index);
    if (arm) {
      if (!setLocal(index, location)) return;
      arm.targetX = location.x;
      return;
    }
  }

  // Everything else eases its own transform, so what stands on it comes along and every panel
  // reads the position where it always has.
  if (!glideSeconds || reducedMotion?.matches) {
    glides.delete(index);
    if (setLocal(index, location)) refreshSubtree(index);
    return;
  }
  const o = index * 6;
  if (
    world.local[o] === location.x &&
    world.local[o + 1] === location.y &&
    world.local[o + 2] === location.z
  ) {
    glides.delete(index);
    return;
  }
  // No frame asked for here: the message that carried this position asked for one at its own
  // edge, and `updateGlides` keeps the loop running while anything is still easing.
  glides.set(index, {
    from: { x: world.local[o], y: world.local[o + 1], z: world.local[o + 2] },
    to: { x: location.x, y: location.y, z: location.z },
    left: glideSeconds,
  });
}

// What each gliding resource is easing toward, by index. A second move replaces the first: the
// model is already at the new target and only the drawing is behind.
const glides = new Map();

function updateGlides(delta) {
  if (!glides.size) return false;
  for (const [index, glide] of glides) {
    glide.left -= delta;
    const done = glide.left <= 0;
    // How much of the move is still to come, so the whole of it takes `glideSeconds` whatever its
    // length and however the frames fall.
    const left = done ? 0 : glide.left / glideSeconds;
    const next = done
      ? glide.to
      : {
          x: glide.to.x - (glide.to.x - glide.from.x) * left,
          y: glide.to.y - (glide.to.y - glide.from.y) * left,
          z: glide.to.z - (glide.to.z - glide.from.z) * left,
        };
    if (done) glides.delete(index);
    if (setLocal(index, next)) refreshSubtree(index);
  }
  return true;
}

// A resource has turned. Only its own transform changes, but everything standing on it is drawn
// from an absolute matrix worked out through that transform - so an arm's links carry the gripper,
// its fingers and their pads round with them, and all of it has to be recomputed.
function applyRotation(index, rotation) {
  if (!setLocalRotation(index, rotation)) return;
  refreshSubtree(index);
}

function setArmX(index, referenceX) {
  const arm = arms.find((a) => a.index === index);
  if (arm) arm.targetX = referenceX - arm.referenceOffset;
}

function buildGridMarks() {
  for (const mark of gridMarks) view.remove(mark);
  disposeOwned(buildGridMarks);
  gridMarks = [];
  gridLabels = [];
  surfaces = [];

  for (let index = 0; index < world.names.length; index++) {
    const grid = modelOf(index).grid;
    if (!grid) continue;

    const group = new THREE.Group();
    group.matrixAutoUpdate = false;
    group.matrix.copy(world.matrices[index]);
    // With matrixAutoUpdate off, three only recomputes matrixWorld when told to; without this the
    // whole group silently renders at the identity transform.
    group.matrixWorldNeedsUpdate = true;

    const [ox, oy, oz] = grid.origin;
    const z = oz + GRID_LIFT;

    const [footprintX, footprintY] = sizeOf(modelOf(index));
    // Nothing to draw at all when it is fully transparent, rather than a draw call per deck that
    // contributes no pixels. The grid, the rail numbers and the access bands are their own objects
    // and stay either way, so the deck still reads as a deck.
    if (SURFACE_OPACITY > 0) {
      const surfaceMaterial = new THREE.MeshStandardMaterial({
        color: SURFACE_COLOR,
        metalness: 0.3,
        roughness: 0.42,
        transparent: true,
        opacity: SURFACE_OPACITY,
        // What stands on the deck is drawn opaque and so lands in the depth buffer first; the surface
        // is below it and fails against it, which is what keeps a plate from being tinted by the deck
        // it sits on. Writing depth as well would have the surface occlude whatever is under it.
        depthWrite: false,
      });
      const surface = new THREE.Mesh(
        new THREE.PlaneGeometry(footprintX, footprintY),
        surfaceMaterial,
      );
      // The deck's own top face, so it paints just after the deck's box and just before whatever
      // stands on it. On the same height scale as everything else - left on the old tree-depth scale
      // it sorted below the box it belongs to, and the box covered it.
      surface.renderOrder = paintOrderOf(index) + 0.25;
      surface.userData.lit = surfaceMaterial;
      own(buildGridMarks, surface.geometry, surfaceMaterial);
      surfaces.push(surface);
      surface.position.set(footprintX / 2, footprintY / 2, oz);
      group.add(surface);
    }
    // A mark reaches forward of the grid into a margin the numbers sit in, and neither leaves the
    // resource it is drawn on: a line hanging off the front of a part reads as geometry that is not
    // there, and a number floating past the edge belongs to nothing. Where there is no margin to
    // reach into - a loading tray's grid starts at the tray's own front edge - both come inside.
    const half = GRID_LABEL_MM / 2;
    const ink = (GRID_LABEL_MM * GRID_LABEL_INK) / 2;
    const front = Math.max(oy - GRID_TICK, 0);
    const labelY = Math.max(oy - GRID_TICK - half, ink + GRID_MARGIN);
    const points = [];
    for (let i = 0; i < grid.count; i++) {
      const x = ox + i * grid.spacing;
      points.push(x, front, z, x, oy + grid.extent, z);

      const position = i + 1;
      if (position === 1 || position % grid.label_every === 0) {
        const sprite = labelSprite(String(position));
        own(buildGridMarks, sprite.geometry, sprite.material, sprite.material.map);
        gridLabels.push(sprite);
        // Between this mark and the next, so a number never sits on a line.
        sprite.position.set(x + grid.spacing / 2, labelY, z);
        group.add(sprite);
      }
    }

    // Access bands: two lines each, spanning the surface, labelled at the near edge.
    const bands = modelOf(index).bands ?? [];
    if (bands.length) {
      const bandPoints = [];
      // Lines only: the reach each pair belongs to is in the band's label if anything ever needs
      // it, but drawn on the deck the numbers competed with the rail numbering.
      for (const band of bands) {
        // A band runs only as far as whatever reaches across it says it does.
        const x0 = band.x_from ?? 0;
        const x1 = band.x_to ?? footprintX;
        for (const y of [band.from, band.to]) bandPoints.push(x0, y, z, x1, y, z);
      }
      const bandGeometry = new THREE.BufferGeometry();
      bandGeometry.setAttribute("position", new THREE.Float32BufferAttribute(bandPoints, 3));
      const bandLines = new THREE.LineSegments(
        bandGeometry,
        new THREE.LineBasicMaterial({ color: BAND_COLOR, depthTest: false }),
      );
      bandLines.renderOrder = paintOrderOf(index) + 0.5;
      own(buildGridMarks, bandGeometry, bandLines.material);
      group.add(bandLines);
    }

    const geometry = new THREE.BufferGeometry();
    geometry.setAttribute("position", new THREE.Float32BufferAttribute(points, 3));
    const marks = new THREE.LineSegments(
      geometry,
      // Opaque, so it sorts with everything else: a transparent line renders after all opaque
      // geometry no matter its render order, which is what kept these on top of the carriers.
      new THREE.LineBasicMaterial({ color: GRID_LINE, depthTest: false }),
    );
    // Just above the surface it is drawn on, and below anything standing on that surface.
    marks.renderOrder = paintOrderOf(index) + 0.5;
    marks.userData.mark = "solid";
    group.add(marks);

    // The same marks again, faint and over the top of whatever is standing on them, so the track a
    // carrier occupies can still be read off. Shares the geometry - this is a second material, not
    // a second set of lines.
    const showThrough = new THREE.LineSegments(
      geometry,
      new THREE.LineBasicMaterial({
        color: GRID_LINE,
        transparent: true,
        opacity: GRID_GHOST_OPACITY,
        depthTest: false,
      }),
    );
    showThrough.userData.mark = "through";
    showThrough.renderOrder = OVERLAY_ORDER - 1;
    group.add(showThrough);
    own(buildGridMarks, geometry, marks.material, showThrough.material);

    group.userData.owner = index;
    view.add(group);
    gridMarks.push(group);
  }
}

// The facility's origin, drawn as a triad. Everything in the scene is measured from here, so it
// should be findable without hunting: the coordinate tool, the deck maths and the readouts all
// resolve against this point.
let originMarker = null;

const AXIS_COLORS = { x: 0xdc3545, y: 0x198754, z: 0x1a4b8c };

// ---------------------------------------------------------------- origin markers (trial)

// A small magenta sphere on every resource's origin, for checking where a resource is measured
// from. Off until the toolbar button turns it on.
//
// One InstancedMesh, not a mesh each: measured on a 316-resource Prep, instancing costs one draw
// call and 0.9% of a frame, where a mesh per resource cost 215 draw calls and 37%.
const ORIGIN_DOT_RADIUS = 1.0; // mm
const ORIGIN_DOT_COLOR = 0xff00ff;
let originDots = null;
let showOriginDots = false;

function buildOriginDots() {
  if (originDots) {
    view.remove(originDots);
    originDots.geometry.dispose();
    originDots.material.dispose();
    originDots = null;
  }
  if (!showOriginDots || !world) return;
  const count = world.names.length;
  const mesh = new THREE.InstancedMesh(
    new THREE.SphereGeometry(ORIGIN_DOT_RADIUS, 8, 6),
    new THREE.MeshBasicMaterial({ color: ORIGIN_DOT_COLOR }),
    count,
  );
  mesh.frustumCulled = false;
  const at = new THREE.Vector3();
  const matrix = new THREE.Matrix4();
  for (let i = 0; i < count; i++) {
    at.setFromMatrixPosition(world.matrices[i]);
    mesh.setMatrixAt(i, matrix.makeTranslation(at.x, at.y, at.z));
  }
  mesh.instanceMatrix.needsUpdate = true;
  originDots = mesh;
  view.add(originDots);
}

function buildOrigin() {
  if (originMarker) view.remove(originMarker);
  disposeOwned(buildOrigin);
  const length = 1; // unit sized; scaled to a constant screen size in updateOrigin()
  const shaft = length * 0.022;

  originMarker = new THREE.Group();
  // The facility is the root instance, so its own frame is the origin everything resolves against.
  originMarker.position.setFromMatrixPosition(world.matrices[0]);

  // Solid shafts rather than lines: a one-pixel line disappears the moment the scene is a room
  // wide, and the origin is the one thing that has to stay findable at any zoom.
  const axes = [
    [new THREE.Vector3(1, 0, 0), AXIS_COLORS.x],
    [new THREE.Vector3(0, 1, 0), AXIS_COLORS.y],
    [new THREE.Vector3(0, 0, 1), AXIS_COLORS.z],
  ];
  for (const [direction, color] of axes) {
    const material = new THREE.MeshStandardMaterial({ color, roughness: 0.45 });
    const body = length * 0.78;
    const bar = new THREE.Mesh(new THREE.CylinderGeometry(shaft, shaft, body, 12), material);
    const head = new THREE.Mesh(new THREE.ConeGeometry(shaft * 2.6, length - body, 14), material);
    // Cylinders and cones point along +Y; turn each onto its own axis.
    const quaternion = new THREE.Quaternion().setFromUnitVectors(
      new THREE.Vector3(0, 1, 0),
      direction,
    );
    bar.quaternion.copy(quaternion);
    head.quaternion.copy(quaternion);
    bar.position.copy(direction).multiplyScalar(body / 2);
    head.position.copy(direction).multiplyScalar(body + (length - body) / 2);
    originMarker.add(bar, head);
    own(buildOrigin, material, bar.geometry, head.geometry);
  }

  const centre = new THREE.Mesh(
    new THREE.SphereGeometry(shaft * 2.2, 18, 14),
    new THREE.MeshStandardMaterial({ color: 0x1a1f22, roughness: 0.4 }),
  );
  originMarker.add(centre);
  own(buildOrigin, centre.geometry, centre.material);

  // A ring flat on the floor, so the origin is still findable from directly above.
  const ring = new THREE.Mesh(
    new THREE.RingGeometry(length * 0.15, length * 0.2, 48),
    new THREE.MeshBasicMaterial({
      color: 0x1a4b8c,
      transparent: true,
      opacity: 0.6,
      side: THREE.DoubleSide,
    }),
  );
  originMarker.add(ring);
  own(buildOrigin, ring.geometry, ring.material);

  // The origin is a marker on the viewport, not something standing in the scene, so it reads over
  // whatever is drawn there.
  originMarker.traverse((o) => {
    if (o.material) {
      o.material.depthTest = false;
      o.material.depthWrite = false;
      o.renderOrder = OVERLAY_ORDER;
    }
  });
  view.add(originMarker);
  updateOrigin();
}

// Below this many pixels across, a resource contributes noise rather than information. Set so a
// well still draws at a 500 mm scale bar, where a pixel is worth about 2.5 mm and a 6.9 mm well
// projects to roughly 2.7 px; it drops out at facility zoom, where it is closer to 1.4 px and a
// thousand of them read as grey haze. Its parent is still drawn, so nothing vanishes without
// something in its place.
const DETAIL_MIN_PX = 2;
// And below this a model is not worth its geometry: the box it stood in for says the same thing
// at a fraction of the cost, and one box is drawn with all the others in a single call. Between
// the two a resource is still there, drawn as a box; below the smaller one it is not drawn at all.
// Eight pixels is where an 8.2 mm tip lands with the camera about a metre off an 840 px tall
// canvas: far enough out that a deck being worked on is still made of things, not boxes.
const MODEL_MIN_PX = 8;
// Below this a rail number is a smudge rather than a number. Nothing is lost by not drawing it, and
// at facility scale it is most of what the renderer is being asked to do.
const LABEL_MIN_PX = 7;
let detailScale = null;

function updateDetail() {
  const perPixel = mmPerPixel();
  if (!Number.isFinite(perPixel) || perPixel <= 0) return;
  // Only rework when the scale has moved enough to change an answer.
  if (detailScale !== null && Math.abs(perPixel / detailScale - 1) < 0.02) return;
  detailScale = perPixel;

  // A rail number is drawn in deck millimetres, so how big it lands on screen is a division away.
  const labelsLegible = GRID_LABEL_MM / perPixel >= LABEL_MIN_PX;
  for (const label of gridLabels) {
    if (label.visible !== labelsLegible) label.visible = labelsLegible;
  }

  // A model is geometry, and geometry is what the renderer spends its frame on: a tip rack two
  // pixels across was still drawing its ninety-six tips, one draw call each. The rule that decides
  // whether a box is worth drawing decides this too - and a part that travels is exempt, because
  // what it is doing is the thing being watched.
  const geometryOf = new Set();
  for (const root of meshRoots) {
    const index = root.userData.index;
    const [sx, sy] = sizeOf(modelOf(index));
    const visible = travels(index) || Math.max(sx, sy) / perPixel >= MODEL_MIN_PX;
    if (root.visible !== visible) root.visible = visible;
    if (visible) geometryOf.add(world.modelOf[index]);
  }
  // Every resource drawn from one instanced mesh is the same model at the same size, and none of
  // them travels - what travels keeps a clone of its own - so one answer covers the lot.
  for (const built of modelMeshes) {
    const [sx, sy] = sizeOf(world.models[built.modelIndex]);
    const visible = Math.max(sx, sy) / perPixel >= MODEL_MIN_PX;
    for (const mesh of built.meshes) if (mesh.visible !== visible) mesh.visible = visible;
    if (visible) geometryOf.add(built.modelIndex);
  }

  const drawn = new Set();
  for (const entry of meshes) {
    const [sx, sy] = sizeOf(entry.model);
    const visible = Math.max(sx, sy) / perPixel >= DETAIL_MIN_PX;
    if (entry.mesh.visible !== visible) entry.mesh.visible = visible;
    // The box stands in for the model again as soon as the model is too small to be worth
    // drawing, and steps back out of the way when it is not. Standing in, it is drawn as solidly
    // as the model was, so what a resource looks like does not change as it crosses the threshold.
    if (entry.modelDrawn) {
      const fills = !geometryOf.has(entry.modelIndex);
      if (entry.mesh.material.visible !== fills) entry.mesh.material.visible = fills;
      if (entry.standsIn !== fills) {
        entry.standsIn = fills;
        entry.mesh.material.opacity = boxOpacity(entry);
        entry.mesh.material.needsUpdate = true;
      }
    }
    entry.detailVisible = visible;
    for (const overlay of entry.overlays ?? []) {
      const wanted = visible && (!overlay.userData.planOnly || planView === true);
      if (overlay.visible !== wanted) overlay.visible = wanted;
    }
    if (visible) drawn.add(entry.modelIndex);
  }

  // In a free view an enclosure gets its fill back once nothing inside it is being drawn, so a
  // plate whose wells have been culled reads as a plate rather than an empty frame. In an axis
  // view everything is opaque and painted in order, so an enclosure keeps its fill whatever stands
  // in it - and the fill is put back here rather than left to the mode change that turns painting
  // on. A fill is only ever taken away in a free view, so one missed transition used to leave a
  // plan view drawn as bare outlines with nothing behind them, which is what it looked like.
  if (planView) {
    for (const entry of meshes) {
      const wanted = fillsBox(entry);
      if (entry.mesh.material.visible !== wanted) entry.mesh.material.visible = wanted;
    }
    return;
  }
  for (const entry of meshes) {
    // A container is exempt: its walls are what you read the layout off, so they stay drawn at
    // SHELL_OPACITY whether or not what it holds is on screen. Everything above it in the stack -
    // a bench, a device, the facility - still drops to its outline, which is what keeps the layers
    // from compounding.
    if (!entry.holdsEnclosure || keepsWalls(entry) || entry.modelDrawn) continue;
    const showsContents = entry.enclosedModels.some((m) => drawn.has(m));
    if (entry.mesh.material.visible === showsContents) entry.mesh.material.visible = !showsContents;
  }
}

// Whether the camera is looking straight down. The plan view is the one view drawn differently -
// flatter, and with a container's walls kept - and it is the only one, because "higher" and
// "nearer" are the same thing only from directly above.
//
// What it is NOT is a drawing painted by rule. Both views let the depth buffer decide what covers
// what, which is the one arbiter that is per-pixel and therefore right about every instance of a
// model at once. The plan view used to sort by a number worked out from each resource's height,
// with depth testing off; a number cannot be per instance - one mesh carries them all - so every
// well on a deck was ordered as the tallest well in the room, and everything that had to be seen
// over them needed its own exception. The exceptions are gone. What is left ordered by hand is
// what has no depth of its own to test: grids, numbers, marks and outlines, up in OVERLAY_ORDER.
let planView = null;

// What a resource stands on, in facility mm, and then how deep it sits in the tree. Depth testing is
// off in an axis view, so what paints last is what shows, and nesting alone decided that - which put
// a well 100 mm up over a 96-head 400 mm up, because the well sat one level deeper. Height leads
// now; nesting only separates things standing at the same level, where a parent still paints first.
//
// Where a resource stands rather than how high it reaches: a shell is as tall as everything it
// holds, so reaching highest would have the facility paint over its own contents.
const PAINT_LEVEL = 100;

function paintOrderOf(index) {
  return world.matrices[index].elements[14] * PAINT_LEVEL + treeDepth(index) * 2;
}

// Anything drawn over the scene rather than in it - the origin marker, the highlight boxes, the
// measurement legs - orders above every paint order a resource can reach. A fixed number cannot do
// that on its own: paint order is a height in millimetres times PAINT_LEVEL, so the band has to
// start past the tallest facility anyone will draw. Ten metres of stacked equipment is that.
const OVERLAY_ORDER = 10_000 * PAINT_LEVEL;

// The layer a part held over the deck is drawn in, above what stands on the deck. Not a height and
// not a band of them: depth says what is over what, and this says only that a travelling part is
// blended over the deck rather than into it. Whole numbers, with room for a vessel's own contents
// between them.
const CARRIED_LAYER = 2;

// Whether a model's box is drawn as a filled solid at all. A part that travels over the deck is
// drawn see-through wherever it is, and a model whose own geometry has arrived has no use for the
// box that stood in for it. Every mode change asks this rather than each one deciding again.
function fillsBox(entry) {
  // A vessel's box is drawn by its own cavity mesh, which fills it exactly. Drawing the box as well
  // puts two surfaces on the same plane, and the depth buffer cannot choose between them.
  return !MOVING_PARTS.has(entry.model.category) && !entry.modelDrawn && !entry.isVessel;
}

// Whether this is a thing you look into. Its walls stay drawn, at the shell's opacity, however much
// is standing in it: a plate with no walls is a floor with wells floating over it, and a carrier
// with none is a line around some plates.
function keepsWalls(entry) {
  return isCarrier(entry.model) || CONTAINERS.has(entry.model.category);
}

// How see-through a resource is drawn, whatever the angle it is seen from. A part that travels is
// the see-through one, because drawn solid it hides whatever it happens to be above.
function OPACITY_OF(isSpace, moves, own, isShell, standsIn) {
  if (isSpace) return SPACE_OPACITY;
  if (moves) return MOVING_OPACITY;
  if (own !== undefined) return own;
  // A box that is holding the place of a model is no longer a statement about extent: it is the
  // picture of the thing, and it is drawn as solidly as the model would have been. A tip at
  // BOX_OPACITY over a white rack composites to about #a3a3a3, which is the colour of an empty
  // spot - so a full rack and a spent one looked alike everywhere the model was too small to draw.
  if (standsIn) return 1;
  if (isShell) return SHELL_OPACITY;
  return BOX_OPACITY;
}

/** How see-through this model's box is drawn, given what it is and whether it stands in for a
 * model. Read by the mode change and by the rule that hands the box back and forth with the
 * model, so the two cannot disagree about it. */
function boxOpacity(entry) {
  return OPACITY_OF(
    GROUND.has(entry.model.category),
    MOVING_PARTS.has(entry.model.category),
    CATEGORY_OPACITY[entry.model.category],
    entry.holdsEnclosure,
    entry.standsIn === true,
  );
}

function setRenderMode(plan) {
  for (const entry of meshes) {
    // Lit, at every angle. The lights ride with the camera, so a surface is shaded by its own shape
    // rather than by where it is being looked at - which is what makes a box read as a box without
    // the view being able to change what colour it is.
    const material = entry.mesh.material.userData.lit ?? entry.mesh.material;
    if (entry.mesh.material !== material) entry.mesh.material = material;
    const isShell = entry.holdsEnclosure;
    // Ground: the space things stand in, and the surface they stand on. Neither is a thing to look
    // at, and drawing either solid hides what it carries - a deck drawn opaque is a sheet the same
    // colour as the plates on it. Both stay barely there in every mode: enough to see where the
    // floor ends and where the deck reaches, never enough to tint what is on them. What makes a
    // deck legible is its rail grid, its numbers and its access bands, and those are their own
    // objects.
    const isSpace = GROUND.has(entry.model.category);
    const rides = entry.instances.some((i) => travels(i));

    material.transparent = true;
    material.opacity = boxOpacity(entry);
    material.side = isShell || isSpace ? THREE.BackSide : THREE.FrontSide;
    // Ground stays out of the depth buffer in either view - a wash over the picture, not a surface
    // anything is behind.
    material.depthTest = !isSpace;
    // Everything writes depth, in either view, so the nearest surface wins per pixel - which is
    // right about every instance of a model at once, where an order could only ever be right about
    // the model.
    //
    // A container used to be held out of the depth buffer in a free view, so that you could look
    // into it. It never needed to be: a container is drawn back-faces-only, so the only surface of
    // a plate ever seen is its far wall, which stands behind its own contents and cannot hide
    // them. What holding it out did instead was stop it hiding anything at all - a plate behind
    // another still drew, a well printed through its own plate from underneath, and an empty
    // well's white cavity read as floating with nothing around it.
    //
    // A part held over the deck writes too, and it costs nothing: it is drawn after everything it
    // is above, so the deck is already in the picture and a depth written now cannot rub it out.
    // What it does stop is the part shading itself - an arm is several surfaces and it carries
    // channels and an iSWAP, and with nothing to separate them each overlap blended again, so the
    // arm came out at a third of its own opacity here and two thirds there as it travelled.
    material.depthWrite = !isSpace;
    // A shell that is not a container shows its outline and nothing else: a device drawn as a
    // sheet the size of the device sits under everything standing on it. A container keeps its
    // walls, which is what makes it read as one.
    material.visible = fillsBox(entry) && (!isShell || keepsWalls(entry));
    // Two layers, and only in a plan: what stands on the deck, and what is held over it. Depth
    // decides everything else; this decides only that a travelling part is blended over the deck
    // rather than into it.
    const layer = plan && rides ? CARRIED_LAYER : 0;
    entry.mesh.renderOrder = layer;
    for (const overlay of entry.overlays ?? []) {
      if (overlay.userData.lit) overlay.material = overlay.userData.lit;
      // A mode change is not a zoom, so the rule that culls small things may not run again before
      // the next frame: a plan-only overlay is switched here too, and by the same two tests.
      if (overlay.userData.planOnly) overlay.visible = plan && entry.detailVisible !== false;
      // From above a vessel has to show its own contents, and depth would stop it: a tip hangs
      // below the spot that holds it, and liquid sits below the cavity it fills. So in a plan they
      // are painted in their own resource's layer, which is as far as they can reach. From any
      // other angle depth is right - what stands in front of a well does cover it - and there they
      // test like everything else.
      overlay.material.depthTest = !plan;
      overlay.material.depthWrite = !plan;
      overlay.renderOrder = plan ? layer + (overlay.userData.behind ? 0.5 : 1) : 0;
      overlay.material.needsUpdate = true;
    }
    material.needsUpdate = true;
  }

  for (const surface of surfaces) {
    surface.material = surface.userData.lit;
  }

  // A mesh out of a model file, whether it was cloned for one resource or instanced for many.
  const fromFile = [];
  for (const root of meshRoots) root.traverse((o) => o.isMesh && fromFile.push(o));
  for (const built of modelMeshes) for (const mesh of built.meshes) fromFile.push(mesh);
  for (const o of fromFile) {
    if (o.userData.lit) o.material = o.userData.lit;
    const modelled = o.userData.asModelled;
    // An instanced mesh holds only what stands still; a clone is drawn for one resource.
    const rides = o.userData.declaredBy !== undefined && travels(o.userData.declaredBy);
    // Glazing comes out of an axis view. A part that travels keeps whatever it was modelled with,
    // see-through included: it is drawn that way so the deck under it can be read.
    o.material.visible = !(plan && modelled?.glazed && !rides);
    if (!modelled) return;
    // A part held over the deck is drawn see-through, as its box is, so that what it is above
    // still reads through it. It does not write depth for the same reason; it still tests, so
    // the machine's own structure above it covers it as it should.
    const lifted = plan && rides;
    o.material.transparent = lifted ? true : modelled.transparent;
    o.material.opacity = lifted ? Math.min(modelled.opacity, MOVING_OPACITY) : modelled.opacity;
    o.material.depthWrite = lifted ? true : modelled.depthWrite;
    o.material.depthTest = true;
    o.renderOrder = lifted ? CARRIED_LAYER : 0;
    o.material.needsUpdate = true;
  }

  for (const mark of gridMarks) {
    mark.traverse((o) => {
      if (!o.material) return;
      // The faint copy belongs to a plan alone, and which view that is follows the camera rather
      // than the mode: an elevation is axis-aligned too, and from the front a line over a carrier
      // is a line through it.
      if (o.userData.mark === "through") {
        o.visible = planView === true;
        return;
      }
      // Against depth, in either view: a mark lies on the deck surface, and whatever stands on the
      // deck is above it. It used to be drawn without depth and kept under a carrier by its order
      // instead, which stopped working the moment content stopped carrying orders - the solid mark
      // was then painted over every carrier at full strength, which is the error the faint copy
      // handled above exists to avoid.
      if (o.material.depthTest !== undefined) o.material.depthTest = true;
    });
  }

  for (const arm of arms) {
    // Where the part stands now. An arm is the one thing in the scene that travels, so the order it
    // was built with is the order it had when it was somewhere else - and in an axis view, where
    // depth testing is off, that order is the whole of what puts it over the deck it passes above.
    const order = paintOrderOf(arm.index);
    arm.frame.renderOrder = order + ARM_FRAME_OFFSET;
    arm.outline.renderOrder = order + ARM_OUTLINE_OFFSET;
    arm.outline.material.depthTest = !plan;
    arm.outline.material.linewidth = plan ? ARM_EDGE_WIDTH_FLAT : ARM_EDGE_WIDTH_3D;
    arm.outline.material.needsUpdate = true;
    // The reference line lies under the carriage, so in a 3D view the channels hanging off it stand
    // in front and have to hide it - but only those, not the deck it is well above.
    //
    // A transparent material always draws after every opaque one, whatever its render order, so as
    // long as the line was transparent it could only be wholly in front or wholly behind. Opaque and
    // drawn first, it lays down its own depth: what is nearer covers it, what is further fails
    // against it and stays behind. In an axis view nothing is in front of anything, so there it goes
    // back to painting through, under the carriage it marks.
    arm.line.material.transparent = plan;
    arm.line.material.opacity = plan ? ARM_REFERENCE_OPACITY : 1;
    arm.line.material.depthTest = !plan;
    arm.line.renderOrder = plan ? order + ARM_LINE_OFFSET : -1;
    arm.line.material.needsUpdate = true;
  }

  for (const [index, line] of edgeOf) {
    // All that is left of a box whose model is being drawn: its border, and only just.
    const stoodIn = drawnFromFile.has(index);
    line.material.depthTest = !plan;
    line.material.opacity = stoodIn ? MODEL_EDGE_OPACITY : plan ? 1 : line.userData.baseOpacity;
    line.material.linewidth = plan ? EDGE_WIDTH_FLAT : EDGE_WIDTH_3D;
    line.material.color.set(plan ? FLAT_EDGE : line.userData.baseColor);
    line.renderOrder = plan ? paintOrderOf(index) + 1 : 0;
    const wanted = plan ? line.userData.footprintGeometry : line.userData.boxGeometry;
    if (wanted && line.geometry !== wanted) line.geometry = wanted;
    line.material.needsUpdate = true;
  }
}

function updateEdgeMode() {
  const direction = camera.position.clone().sub(controls.target).normalize();
  // Looking straight down, and nothing else. An elevation is axis-aligned too and used to get the
  // same treatment, which is wrong twice over: from the front, higher is not nearer, and a drawing
  // painted by height puts the deck's back row in front of its front row. Looking straight up is
  // not a plan either - what is highest is then furthest away.
  const plan = direction.z > 0.999;
  // No frame is asked for: this runs inside one, and the camera only reaches an axis through an
  // input, which has asked for frames already and is still damping to a stop.
  if (plan === planView) return;
  planView = plan;
  for (const mark of gridMarks) showThroughMarks(mark);
  setRenderMode(plan);
}

/** Show or hide the faint copies of a grid's marks, which belong to a plan view alone. */
function showThroughMarks(group) {
  group.traverse((o) => {
    if (o.userData.mark === "through") o.visible = planView === true;
  });
}

// Held at a constant size on screen, so it marks the origin without swamping a close view or
// vanishing from a wide one.
const ORIGIN_PX = 90;

// How close to the edge of the viewport an origin that has left it is brought, in normalised
// device coordinates. Inside 1.0 so the whole marker shows rather than half of it.
const ORIGIN_EDGE = 0.92;

const _originAt = new THREE.Vector3();
const _originNdc = new THREE.Vector3();
const _originDepth = new THREE.Vector3();

function updateOrigin() {
  if (!originMarker) return;
  const perPixel = mmPerPixel();
  if (!Number.isFinite(perPixel) || perPixel <= 0) return;
  originMarker.scale.setScalar(perPixel * ORIGIN_PX);

  // The frame every coordinate in the panel is measured against, so it is the one marker that must
  // not be able to go missing: panned or zoomed far enough, the facility's own corner leaves the
  // viewport entirely. It is held at the edge instead, in the direction the origin actually lies,
  // which keeps both the frame and the way back to it on screen.
  _originAt.setFromMatrixPosition(world.matrices[0]);
  _originNdc.copy(_originAt).project(camera);
  // A point behind the camera projects mirrored through the centre, so it would be pinned to the
  // opposite edge from the one it lies towards.
  if (_originAt.clone().applyMatrix4(camera.matrixWorldInverse).z > 0) {
    _originNdc.x *= -1;
    _originNdc.y *= -1;
  }
  if (Math.abs(_originNdc.x) <= ORIGIN_EDGE && Math.abs(_originNdc.y) <= ORIGIN_EDGE) {
    originMarker.position.copy(_originAt);
    return;
  }
  // Held at the depth the camera is looking at, so it is drawn at the size the scale above gives it.
  const depth = _originDepth.copy(controls.target).project(camera).z;
  originMarker.position
    .set(
      Math.max(-ORIGIN_EDGE, Math.min(ORIGIN_EDGE, _originNdc.x)),
      Math.max(-ORIGIN_EDGE, Math.min(ORIGIN_EDGE, _originNdc.y)),
      depth,
    )
    .unproject(camera);
}

// The floor grid follows the view, the way the existing visualizer's does: its spacing is chosen
// from how many millimetres a pixel is worth, and it re-centres on what you are looking at. A grid
// fixed at build time is a grid that means nothing once you zoom.
let grid = null;
let gridState = null;
let floorZ = 0;

// 1, 2 or 5 times a power of ten: the spacings a person can count in.
function niceNumber(value) {
  const magnitude = 10 ** Math.floor(Math.log10(Math.max(value, 1e-6)));
  return [1, 2, 5, 10].map((m) => m * magnitude).find((v) => v >= value) ?? magnitude * 10;
}

function mmPerPixel() {
  const height = viewportEl.clientHeight || 1;
  if (projection === "orthographic") {
    return (camera.top - camera.bottom) / camera.zoom / height;
  }
  const distance = camera.position.distanceTo(controls.target);
  return (2 * distance * Math.tan((camera.fov * DEG) / 2)) / height;
}

// ---------------------------------------------------------------- channel halos

// A halo on each pipetting channel: a disc facing the camera, held at HALO_PX across whatever the
// zoom. Sprites, one a channel, rather than one instanced quad:
// a sprite faces the camera on its own and is placed through its own transform, where an
// instanced quad needs its matrix buffer rewritten every frame, and on the WebGPU backend a buffer
// rewritten every frame drew on some frames and not others. Drawn in the overlay band, so a halo
// sits over the arm's frame and whatever the channel is above without any of them being reordered.
//
// What a halo says: its colour is the channel's place in CHANNEL_RAMP, its number is drawn in it,
// and it is filled while the channel's mounting shaft holds a tip and hollow while it does not.
// On from the start; the rail button turns them off and on.
let halos = null;
let showHalos = true;

const HALO_TEXTURE_PX = 96;
/** One texture per look, kept: a look is a number, a ramp step and whether it is filled. */
const haloTextures = new Map();

function haloTextureFor(label, step, filled) {
  const key = `${label}|${step}|${filled}`;
  const kept = haloTextures.get(key);
  if (kept) return kept;
  const canvas = document.createElement("canvas");
  canvas.width = HALO_TEXTURE_PX;
  canvas.height = HALO_TEXTURE_PX;
  const context = canvas.getContext("2d");
  const colour = hexOf(CHANNEL_RAMP[step]);
  const mid = HALO_TEXTURE_PX / 2;
  const radius = mid - 6;
  // Two zones. The background is white with an empty shaft and light green with a tip in it, so
  // the change reads from across the deck. The coin at the centre carries the channel's colour:
  // a solid coin with a tip, a ring without.
  context.beginPath();
  context.arc(mid, mid, radius, 0, Math.PI * 2);
  // A surface ring around every disc, so two halos that overlap still read as two.
  context.lineWidth = 4;
  context.strokeStyle = "rgba(255,255,255,0.9)";
  context.fillStyle = filled ? HALO_TIPPED_BACKGROUND : "rgba(255,255,255,0.88)";
  context.fill();
  context.stroke();
  const coin = radius - 12;
  context.beginPath();
  context.arc(mid, mid, coin, 0, Math.PI * 2);
  if (filled) {
    context.fillStyle = colour;
    context.fill();
  } else {
    context.lineWidth = 6;
    context.strokeStyle = colour;
    context.stroke();
  }
  // Ink, never the series colour, on a solid coin; the ramp colour itself inside a ring.
  context.fillStyle = filled ? (step < CHANNEL_RAMP_DARK_INK_STEPS ? HALO_INK : "#ffffff") : colour;
  context.font = `bold ${label.length > 1 ? 34 : 42}px ui-monospace, Menlo, monospace`;
  context.textAlign = "center";
  context.textBaseline = "middle";
  context.fillText(label, mid, mid + 2);
  const texture = new THREE.CanvasTexture(canvas);
  texture.colorSpace = THREE.SRGBColorSpace;
  haloTextures.set(key, texture);
  return texture;
}

/** A sprite material over a kept texture: made per build, so the build can let it go. */
function haloMaterial(map, color = 0xffffff) {
  return new THREE.SpriteMaterial({
    map,
    color,
    transparent: true,
    depthTest: false,
    depthWrite: false,
  });
}

// The line from a channel to its disc: a unit line along x, placed by its transform alone, so the
// frame-by-frame update touches no buffer. One material per ramp step, kept like the discs' are.
const LEADER_GEOMETRY = new THREE.BufferGeometry().setFromPoints([
  new THREE.Vector3(0, 0, 0),
  new THREE.Vector3(1, 0, 0),
]);

function leaderMaterial(step) {
  return new THREE.LineBasicMaterial({
    color: CHANNEL_RAMP[step],
    transparent: true,
    opacity: 0.9,
    depthTest: false,
    depthWrite: false,
  });
}

// The glow on the channel itself: one soft white disc, tinted per ramp step by its material.
function markTexture() {
  const canvas = document.createElement("canvas");
  canvas.width = 64;
  canvas.height = 64;
  const context = canvas.getContext("2d");
  const gradient = context.createRadialGradient(32, 32, 0, 32, 32, 32);
  gradient.addColorStop(0, "rgba(255,255,255,1)");
  gradient.addColorStop(0.5, "rgba(255,255,255,0.7)");
  gradient.addColorStop(1, "rgba(255,255,255,0)");
  context.fillStyle = gradient;
  context.fillRect(0, 0, 64, 64);
  const texture = new THREE.CanvasTexture(canvas);
  texture.colorSpace = THREE.SRGBColorSpace;
  return texture;
}
const MARK_TEXTURE = markTexture();

/** Whether a channel holds a tip: a tip is a resource under the channel's mounting shaft. */
function channelTipped(index) {
  return world.childrenOf[index].some(
    (c) => modelOf(c).category === "tip_mounting_shaft" && world.childrenOf[c].length > 0,
  );
}

/** The channel's own number, as the tree names it, so the halo, the panel and the tree agree. */
function channelLabel(index, ordinal) {
  const numbered = /(\d+)$/.exec(world.names[index]);
  return numbered ? numbered[1] : String(ordinal);
}

function buildHalos() {
  if (halos) {
    view.remove(halos);
    halos = null;
  }
  disposeOwned(buildHalos);
  if (!showHalos || !world) return;
  const channels = [];
  for (let index = 0; index < world.names.length; index++) {
    if (modelOf(index).category === "pipette_channel") channels.push(index);
  }
  if (!channels.length) return;
  const group = new THREE.Group();
  for (const index of channels) {
    // Its place in the row it belongs to: the channels on the same arm, in tree order. Sixteen
    // channels take the whole ramp; eight take every other step, so the ends stay the ends.
    const row = channels.filter((c) => world.parentOf[c] === world.parentOf[index]);
    const ordinal = row.indexOf(index);
    const step = Math.round((ordinal * (CHANNEL_RAMP.length - 1)) / Math.max(1, row.length - 1));
    const sprite = new THREE.Sprite(
      haloMaterial(haloTextureFor(channelLabel(index, ordinal), step, channelTipped(index))),
    );
    sprite.renderOrder = OVERLAY_ORDER;
    sprite.frustumCulled = false;
    sprite.userData.index = index;
    // Discs alternate sides down the row, the first to the right, so neighbours nine millimetres
    // apart do not stack their discs on one side.
    sprite.userData.side = ordinal % 2 === 0 ? 1 : -1;
    const leader = new THREE.Line(LEADER_GEOMETRY, leaderMaterial(step));
    leader.renderOrder = OVERLAY_ORDER - 2;
    leader.frustumCulled = false;
    const mark = new THREE.Sprite(haloMaterial(MARK_TEXTURE, CHANNEL_RAMP[step]));
    mark.renderOrder = OVERLAY_ORDER - 1;
    mark.frustumCulled = false;
    mark.userData.mark = true;
    sprite.userData.leader = leader;
    sprite.userData.mark = mark;
    own(buildHalos, sprite.material, leader.material, mark.material);
    group.add(leader, mark, sprite);
  }
  halos = group;
  view.add(halos);
}

const _haloRight = new THREE.Vector3();
const _haloUp = new THREE.Vector3();
const _haloAnchor = new THREE.Vector3();
const _haloReach = new THREE.Vector3();
const X_AXIS = new THREE.Vector3(1, 0, 0);

// Each disc sits off the middle of its channel, right and up as the camera sees it, scaled to
// HALO_PX, with its line running from the channel to the disc's edge - while the channel is small
// on screen. As it grows the offset shrinks, and at HALO_CENTRED_AT discs wide the disc sits on the
// channel and the line is gone. Done every frame, since the arm and the camera both move.
function updateHalos() {
  if (!halos) return;
  const perPixel = mmPerPixel();
  if (!Number.isFinite(perPixel) || perPixel <= 0) return;
  _haloRight.set(1, 0, 0).applyQuaternion(camera.quaternion);
  _haloUp.set(0, 1, 0).applyQuaternion(camera.quaternion);
  const discMm = perPixel * HALO_PX;
  for (const sprite of halos.children) {
    if (!sprite.isSprite || sprite.userData.mark === true) continue;
    const index = sprite.userData.index;
    const [sx, sy, sz] = sizeOf(modelOf(index));
    // How many discs wide the channel is on screen: none of the offset once it reaches
    // HALO_CENTRED_AT, all of it while it is under one.
    const widths = Math.max(sx, sy) / discMm;
    const standOff = Math.max(0, Math.min(1, (HALO_CENTRED_AT - widths) / (HALO_CENTRED_AT - 1)));
    _haloReach
      .copy(_haloRight)
      .multiplyScalar(HALO_OFFSET_PX.right * sprite.userData.side)
      .addScaledVector(_haloUp, HALO_OFFSET_PX.up)
      .multiplyScalar(perPixel * standOff);
    _haloAnchor.set(sx / 2, sy / 2, sz / 2).applyMatrix4(world.matrices[index]);
    sprite.position.copy(_haloAnchor).add(_haloReach);
    sprite.scale.setScalar(discMm);
    sprite.userData.mark.position.copy(_haloAnchor);
    sprite.userData.mark.scale.setScalar(perPixel * HALO_MARK_PX);
    const leader = sprite.userData.leader;
    const toEdge = _haloReach.length() - discMm / 2;
    leader.visible = toEdge > 0;
    if (!leader.visible) continue;
    leader.position.copy(_haloAnchor);
    leader.quaternion.setFromUnitVectors(X_AXIS, _haloReach.clone().normalize());
    leader.scale.set(toEdge, 1, 1);
  }
}

// Aim for a cell around this many pixels: dense enough to measure against, open enough to see past.
const GRID_TARGET_PX = 64;
const GRID_MAX_DIVISIONS = 320;

// The floor is drawn with the same fat lines everything else uses, rather than with `GridHelper`:
// a hairline is one device pixel whatever width is asked for, which on a retina display is half of
// what it looks like anywhere else and too faint to measure against either way. In CSS pixels, so
// it means the same thing on every screen.
const FLOOR_LINE = 0xc0c7cc;
const FLOOR_AXIS = 0x9aa4ab; // the two lines through the centre, which say where the origin is
const FLOOR_LINE_WIDTH = 1.4;
const FLOOR_AXIS_WIDTH = 2.0;

// A material per line, gone with the line: the renderer keeps a line's draw state until its
// material is disposed, so lines sharing one material piled that up with every change of zoom.
function floorMaterial(axis) {
  const material = new THREE.Line2NodeMaterial({
    color: axis ? FLOOR_AXIS : FLOOR_LINE,
    linewidth: axis ? FLOOR_AXIS_WIDTH : FLOOR_LINE_WIDTH,
    worldUnits: false,
  });
  return material;
}

function updateGrid() {
  const perPixel = mmPerPixel();
  if (!Number.isFinite(perPixel) || perPixel <= 0) return;

  const span = perPixel * Math.hypot(viewportEl.clientWidth, viewportEl.clientHeight) * 1.3;
  // Coarsen the spacing rather than shrink the coverage: a grid that stops inside the viewport
  // reads as a hole in the floor, whereas a larger cell just reads as a larger cell.
  const cell = Math.max(
    niceNumber(perPixel * GRID_TARGET_PX),
    niceNumber(span / GRID_MAX_DIVISIONS),
  );
  const divisions = Math.max(4, Math.ceil(span / cell));
  // Snap the centre to the spacing, or the lines crawl as you pan.
  const cx = Math.round(controls.target.x / cell) * cell;
  const cy = Math.round(controls.target.y / cell) * cell;

  if (
    gridState &&
    gridState.cell === cell &&
    gridState.divisions === divisions &&
    gridState.cx === cx &&
    gridState.cy === cy
  ) {
    return;
  }
  gridState = { cell, divisions, cx, cy };

  for (const line of grid ?? []) {
    view.remove(line);
    line.geometry.dispose();
    line.material.dispose();
  }

  // Already in PLR's XY: the lines are built in the plane rather than laid down from another one.
  const half = (divisions * cell) / 2;
  const runs = [[], []]; // ordinary lines, then the two the world's own axes fall on
  // A line is an axis when it lands on zero IN THE WORLD, which is not the middle of the patch: the
  // patch follows the camera, so its middle is wherever you happen to be looking. The geometry is
  // built around the patch's centre and drawn at (cx, cy), so a local t sits at t + cx or t + cy.
  // Where the origin is off the patch entirely, neither axis is drawn, which is the truth.
  const axis = (at) => (Math.abs(at) < cell * 1e-6 ? 1 : 0);
  for (let i = 0; i <= divisions; i++) {
    const t = -half + i * cell;
    runs[axis(t + cy)].push(-half, t, 0, half, t, 0);
    runs[axis(t + cx)].push(t, -half, 0, t, half, 0);
  }

  grid = runs
    .map((points, kind) => {
      if (!points.length) return null;
      const geometry = new LineSegmentsGeometry();
      geometry.setPositions(new Float32Array(points));
      const line = new LineSegments2(geometry, floorMaterial(kind === 1));
      line.position.set(cx, cy, floorZ);
      line.renderOrder = -1;
      line.frustumCulled = false;
      view.add(line);
      return line;
    })
    .filter(Boolean);
}

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

// three's own view helper, in place of the hand-drawn legend: same three axes, but clickable,
// and it animates the camera onto the axis you pick.
const clock = new THREE.Clock();
let viewHelper = null;

function buildViewHelper() {
  viewHelper?.dispose();
  viewHelper = new ViewHelper(camera, renderer.domElement);
  viewHelper.corner = "left";
  viewHelper.setLabels("X", "Y", "Z");
}

// Unit primitives, shared by every model of the same shape and scaled per instance.
const BOX = new THREE.BoxGeometry(1, 1, 1);
const CYL = new THREE.CylinderGeometry(0.5, 0.5, 1, 20).rotateX(Math.PI / 2);
// Open at both ends. A shaft is a length of tube: the bottom is where a tip goes on and the top is
// where the channel carries on, so capping either reads as a solid slug hanging off the head.
const TUBE = new THREE.CylinderGeometry(0.5, 0.5, 1, 20, 1, true).rotateX(Math.PI / 2);
// Flat in XY, facing up: a filter lies across a tip standing on the deck.
const DISC = new THREE.CircleGeometry(0.5, 32);

// Above this many instances of one model, outlining each stops being cheap.
const EDGE_LIMIT = 160;

// ---------------------------------------------------------------- scene build

// A resource says what shape it is through `cross_section_type`. A tip spot does not serialize
// one, though it is plainly round, so it is special-cased here; upstream it should declare the
// field the way a well does, and this line can go.
function geometryFor(model) {
  // A shaft is open at both ends; anything else round is a vessel or a spot, which is not.
  if (model.category === "tip_mounting_shaft") return TUBE;
  return model.cross_section_type === "circle" || model.category === "tip_spot" ? CYL : BOX;
}

// The outline a resource drops to in an axis view. Unit-sized and scaled per instance, so there is
// one of each shape rather than one per model.
function ringFootprint(corners) {
  const points = [];
  for (let corner = 0; corner < corners; corner++) {
    // Square from the diagonals, circle from a fine enough ring: the same walk either way.
    const from = ((corner + 0.5) / corners) * Math.PI * 2;
    const to = ((corner + 1.5) / corners) * Math.PI * 2;
    const reach = corners === 4 ? Math.SQRT1_2 : 0.5;
    points.push(
      Math.cos(from) * reach,
      Math.sin(from) * reach,
      -0.5,
      Math.cos(to) * reach,
      Math.sin(to) * reach,
      -0.5,
    );
  }
  const geometry = new LineSegmentsGeometry();
  geometry.setPositions(new Float32Array(points));
  return geometry;
}

const SQUARE_FOOTPRINT = ringFootprint(4);
const ROUND_FOOTPRINT = ringFootprint(20);

const footprintFor = (model) => (geometryFor(model) === BOX ? SQUARE_FOOTPRINT : ROUND_FOOTPRINT);
const colorFor = (model) =>
  model.appearance?.color ?? RESOURCE_COLORS[model.category] ?? RESOURCE_COLORS.default;
// "TipRack" -> "tipracks", as the existing visualizer writes them. Deliberately naive: a count is
// always in front of it, so "1 plates" reads as a count rather than as a mistake.
const plural = (type) => `${String(type).toLowerCase()}s`;

// The plural naming these resources, from the first of them, as the existing visualizer counts a
// carrier: "3 plates" says what a carrier is for even when one site holds something else.
function countable(indices) {
  return plural(modelOf(indices[0]).type);
}
const hexOf = (n) => `#${n.toString(16).padStart(6, "0")}`;

const IDENTITY_Q = new THREE.Quaternion();
const tmpMatrix = new THREE.Matrix4();
const tmpVec = new THREE.Vector3();
const tmpScale = new THREE.Vector3();
const ZERO = new THREE.Matrix4().makeScale(0, 0, 0);

// A resource's origin is the minimum corner of its box, so the drawn centre sits half a size in.
function boxMatrix(matrix, sx, sy, sz, ox, oy, oz) {
  tmpVec.set(ox ?? sx / 2, oy ?? sy / 2, oz ?? sz / 2);
  tmpScale.set(sx, sy, sz);
  return tmpMatrix.compose(tmpVec, IDENTITY_Q, tmpScale).premultiply(matrix);
}

function placeInstance(mesh, slot, matrix, sx, sy, sz, ox, oy, oz) {
  // A mesh out of a model file sits at a transform of its own inside that file, which is not a
  // scale and an offset. Given one, it is applied to the resource's own matrix as it stands.
  if (sx?.isMatrix4) {
    mesh.setMatrixAt(slot, tmpMatrix.multiplyMatrices(matrix, sx));
    return;
  }
  mesh.setMatrixAt(slot, boxMatrix(matrix, sx, sy, sz, ox, oy, oz));
}

function isEnclosure(index) {
  const model = modelOf(index);
  return (
    world.childrenOf[index].length > 0 ||
    model.max_volume !== undefined ||
    MOVING_PARTS.has(model.category)
  );
}

function collectEnclosedModels(index, into) {
  for (const child of world.childrenOf[index]) {
    if (isEnclosure(child)) into.add(world.modelOf[child]);
    collectEnclosedModels(child, into);
  }
}

// A carrier is the level you look at rather than through: its floor is filled in, and its walls
// keep their fill instead of being culled when the things it holds are drawn.
function isCarrier(model) {
  return String(model.category).includes("carrier");
}

function enclosureDepth(index) {
  let depth = 0;
  for (let i = world.parentOf[index]; i >= 0; i = world.parentOf[i]) {
    if (isEnclosure(i)) depth++;
  }
  return depth;
}

function hasEnclosedDescendant(index) {
  for (const child of world.childrenOf[index]) {
    if (isEnclosure(child) || hasEnclosedDescendant(child)) return true;
  }
  return false;
}

function buildMeshes() {
  for (const entry of meshes) {
    view.remove(entry.mesh);
    // An overlay is its own object in the view: a vessel's floor, its walls and its cavity, a
    // tip's filter disc, the green disc that says a spot is filled. Taking the box out and leaving
    // those behind does not leave them alone, it puts them out of reach - both rules that show and
    // hide an overlay walk `meshes`, so one dropped from that list keeps whatever it was last told
    // for the life of the page. A scene rebuilt while a plan view was up kept its green discs, and
    // they then showed from every angle.
    for (const overlay of entry.overlays ?? []) view.remove(overlay);
  }
  for (const line of edgeOf.values()) view.remove(line);
  disposeOwned(buildMeshes);
  planView = null;
  detailScale = null;
  meshes = [];
  placementOf = new Array(world.names.length);
  vesselOf = new Map();
  overlayOf = new Map();
  filterDiscsOf = new Map();
  edgeOf = new Map();
  drawnFromFile = new Set();

  const byModel = new Map();
  for (let i = 0; i < world.names.length; i++) {
    const m = world.modelOf[i];
    if (!byModel.has(m)) byModel.set(m, []);
    byModel.get(m).push(i);
  }

  for (const [modelIndex, instances] of byModel) {
    const model = world.models[modelIndex];
    const [sx, sy, sz] = sizeOf(model);

    // A well or a tip spot is not drawn as a shell to see through, but as a rim with an inside:
    // the rim gives it an edge thick enough to find, and the inside carries what is in it. That is
    // how the existing visualizer draws them, and it is what survives being looked at from above.
    const isVessel =
      (Number.isFinite(model.max_volume) && model.max_volume > 0) || model.category === "tip_spot";

    // A resource that holds something is an enclosure: other resources, read off the tree, or
    // liquid, read off its own capacity. Neither test names a resource type.
    const encloses =
      !isVessel &&
      (instances.some((i) => world.childrenOf[i].length > 0) ||
        model.max_volume !== undefined ||
        MOVING_PARTS.has(model.category));

    // But only the innermost enclosures are filled. A well in a plate on a holder on a carrier on
    // a deck in a device in a facility sits under six translucent shells, and six layers at 0.3
    // opacity leave about a tenth of the contrast underneath. So anything that holds another
    // enclosure is drawn as its outline alone, and only the level you are actually looking into
    // keeps a fill.
    const holdsEnclosure = encloses && instances.some((i) => hasEnclosedDescendant(i));

    const material = new THREE.MeshStandardMaterial({
      color: colorFor(model),
      roughness: 0.68,
      metalness: 0.0,
      transparent: encloses,
      opacity: encloses ? 0.26 : 1.0,
      depthWrite: !encloses,
      side: encloses ? THREE.BackSide : THREE.FrontSide,
    });

    if (isVessel) material.color.setHex(VESSEL_RIM);
    material.userData.lit = material;

    if (MOVING_PARTS.has(model.category)) material.visible = false;

    // Culled by the sphere three works out over the instances, as every instanced mesh, overlay
    // and outline here is: what is off screen is not submitted. A move or a hide drops the sphere.
    const mesh = new THREE.InstancedMesh(geometryFor(model), material, instances.length);
    own(buildMeshes, mesh, material);
    instances.forEach((globalIndex, slot) => {
      placeInstance(mesh, slot, world.matrices[globalIndex], sx, sy, sz);
      placementOf[globalIndex] = { mesh, slot };
    });
    mesh.instanceMatrix.needsUpdate = true;
    mesh.userData.instances = instances;
    view.add(mesh);
    meshes.push({
      mesh,
      model,
      modelIndex,
      instances,
      depth: treeDepth(instances[0]),
      lit: material,
      // Filled in below, once the overlays this model needs are known.
      overlays: /** @type {any[]} */ ([]),
      // Set once this model's declared .glb has arrived and been placed.
      modelDrawn: false,
      // Whether the box is currently holding the place of a model too small to be worth drawing.
      standsIn: false,
      holdsEnclosure: false,
      enclosedModels: /** @type {any[]} */ ([]),
    });

    // The existing visualizer strokes every resource, and a translucent box on a white ground
    // needs that stroke to read at all. So does a solid one that holds nothing: a 96-head, a
    // channel, a loading tray. What decides is how many there are, not whether anything is inside -
    // an outline is one line object per instance, and there are a thousand wells. The count is the
    // whole of the cost control, and it already excludes exactly the things too small to read.
    //
    // A travelling part draws its own frame and moves, so it gets no generic box outline: the box
    // would describe the slab rather than the frame, and it would be a second thing to keep in
    // step with every move - which is exactly what left a ghost behind at the old position.
    if (!MOVING_PARTS.has(model.category) && instances.length <= EDGE_LIMIT) {
      const boxEdges = new THREE.EdgesGeometry(geometryFor(model));
      const edgeGeometry = new LineSegmentsGeometry();
      edgeGeometry.setPositions(boxEdges.getAttribute("position").array);
      boxEdges.dispose();
      // Looking down an axis, every edge projects onto the footprint anyway, and the verticals
      // collapse to points. Keeping a footprint-only geometry to swap in removes that redundancy
      // and, more usefully, stops stacked shapes reading as a thicket in a plan view.
      const footprintGeometry = footprintFor(model);
      const style = structureEdgeStyle(enclosureDepth(instances[0]));
      const edgeMaterial = new THREE.Line2NodeMaterial({
        color: style.color,
        transparent: true,
        opacity: style.opacity,
        linewidth: EDGE_WIDTH_3D,
        worldUnits: false,
      });
      own(buildMeshes, edgeGeometry, edgeMaterial);
      for (const globalIndex of instances) {
        const line = new LineSegments2(edgeGeometry, edgeMaterial);
        line.userData.boxGeometry = edgeGeometry;
        line.userData.baseOpacity = style.opacity;
        line.userData.baseColor = style.color.clone();
        line.userData.footprintGeometry = footprintGeometry;
        line.matrixAutoUpdate = false;
        line.matrix.copy(boxMatrix(world.matrices[globalIndex], sx, sy, sz));
        view.add(line);
        edgeOf.set(globalIndex, line);
      }
    }

    // A trough reports an infinite capacity, which arrives as the string "Infinity". There is no
    // fill fraction to draw against that, so it gets no liquid body.
    // Which enclosure models sit inside this one. An outline is only the right answer while its
    // contents are actually being drawn; once they are culled the outline has nothing to frame.
    const enclosedModels = new Set();
    for (const i of instances) collectEnclosedModels(i, enclosedModels);

    const overlays = [];

    // A carrier's base is solid, so looking into one should stop at its floor rather than carrying
    // on through to the deck. The shell stays see-through; only the bottom face is filled in.
    if (encloses && isCarrier(model)) {
      const floor = new THREE.InstancedMesh(
        // Unit geometry: `placeInstance` supplies the real size through the instance matrix, so a
        // pre-sized plane would be scaled by its own dimensions a second time.
        new THREE.PlaneGeometry(1, 1),
        new THREE.MeshStandardMaterial({ color: colorFor(model), roughness: 0.7 }),
        instances.length,
      );
      instances.forEach((globalIndex, slot) => {
        // A hair above its own base, or it fights the deck surface it stands on for depth.
        const at = [sx, sy, 1, sx / 2, sy / 2, 0.3];
        placeInstance(floor, slot, world.matrices[globalIndex], ...at);
        remember(globalIndex, floor, slot, at);
      });
      floor.instanceMatrix.needsUpdate = true;
      floor.userData.lit = floor.material;
      own(buildMeshes, floor, floor.geometry, floor.material);
      view.add(floor);
      overlays.push(floor);
    }

    if (isVessel) {
      // The wall, standing outside the cavity. Grown rather than inset, because the box IS the
      // cavity - and grown rather than left as the box itself, because a box and a cavity on the
      // same plane are two surfaces at the same depth, which is what made the side of every well
      // shimmer. Nothing is coplanar with anything now.
      const wall = new THREE.InstancedMesh(
        geometryFor(model),
        new THREE.MeshStandardMaterial({
          color: VESSEL_RIM,
          roughness: 0.6,
          transparent: true,
          opacity: VESSEL_WALL_OPACITY,
        }),
        instances.length,
      );
      instances.forEach((globalIndex, slot) => {
        const at = [sx + 2 * VESSEL_WALL, sy + 2 * VESSEL_WALL, sz, sx / 2, sy / 2, sz / 2];
        placeInstance(wall, slot, world.matrices[globalIndex], ...at);
        remember(globalIndex, wall, slot, at);
      });
      wall.instanceMatrix.needsUpdate = true;
      wall.userData.lit = wall.material;
      own(buildMeshes, wall, wall.material);
      wall.userData.behind = true; // painted before the cavity it surrounds
      view.add(wall);
      overlays.push(wall);

      const inner = new THREE.InstancedMesh(
        geometryFor(model),
        // Flagged transparent although it is fully opaque, so that it sits in the same pass as the
        // wall around it. Three draws every transparent object after every opaque one whatever the
        // render order says, so an opaque cavity inside a see-through wall is painted first and
        // then covered by the wall's own top face - which is what hid the well from above.
        new THREE.MeshStandardMaterial({
          color: 0xffffff,
          roughness: 0.55,
          transparent: true,
          opacity: 1,
        }),
        instances.length,
      );
      const white = new THREE.Color(VESSEL_EMPTY);
      instances.forEach((globalIndex, slot) => {
        // The cavity IS the box. A container's size is what it holds, and the material around it
        // stands outside that - so the inside fills the resource's own extent exactly, and a wall
        // is never drawn within it. Drawn inset, as this was, the walls were inside the box, which
        // is the opposite of what the box means. A hair taller only, so that from directly above it
        // does not fight the box's own top face for depth.
        const at = [sx, sy, sz * 1.02, sx / 2, sy / 2, (sz * 1.02) / 2];
        // A spot holding a tip shows the tip, and the white of an empty hole would lie across its
        // bore - over the filter, which sits just below the spot.
        remember(globalIndex, inner, slot, at, model.category === "tip_spot");
        if (model.category === "tip_spot" && world.childrenOf[globalIndex].length > 0) {
          inner.setMatrixAt(slot, ZERO);
        } else {
          placeInstance(inner, slot, world.matrices[globalIndex], ...at);
        }
        inner.setColorAt(slot, white);
        vesselOf.set(globalIndex, { mesh: inner, slot, model });
      });
      inner.instanceMatrix.needsUpdate = true;
      inner.instanceColor.needsUpdate = true;
      inner.userData.lit = inner.material;
      own(buildMeshes, inner, inner.material);
      view.add(inner);
      overlays.push(inner);
    }
    if (model.category === "tip" && model.has_filter && Number.isFinite(model.collar_height)) {
      overlays.push(buildFilterDiscs(modelIndex, instances, model, sx, sy, sz));
    }
    if (model.category === "tip") overlays.push(buildPlanDiscs(instances, sx, sy, sz));
    const entry = meshes[meshes.length - 1];
    entry.overlays = overlays;
    entry.isVessel = isVessel;
    entry.holdsEnclosure = holdsEnclosure;
    entry.enclosedModels = [...enclosedModels];
  }
}

/**
 * A filter in every tip of one model: a white disc across the bore, `FILTER_BELOW_COLLAR` below the
 * collar. One instanced mesh however many tips there are, so a rack of filtered tips costs one draw.
 */
function buildFilterDiscs(modelIndex, instances, model, sx, sy, sz) {
  const disc = new THREE.InstancedMesh(
    DISC,
    new THREE.MeshBasicMaterial({ color: FILTER, side: THREE.DoubleSide }),
    instances.length,
  );
  // A tip stands on its bottom end, so its top is its length and the collar hangs from there.
  const z = sz - (model.collar_height + FILTER_BELOW_COLLAR);
  const width = sx * FILTER_WIDTH_UNMEASURED;
  const placed = [];
  instances.forEach((globalIndex, slot) => {
    const at = [width, width, 1, sx / 2, sy / 2, z];
    placeInstance(disc, slot, world.matrices[globalIndex], ...at);
    remember(globalIndex, disc, slot, at);
    placed.push({ index: globalIndex, at });
  });
  disc.instanceMatrix.needsUpdate = true;
  disc.userData.lit = disc.material;
  own(buildMeshes, disc, disc.material);
  view.add(disc);
  filterDiscsOf.set(modelIndex, { mesh: disc, placed, z, cx: sx / 2, cy: sy / 2 });
  return disc;
}

/**
 * The green disc that says a spot is filled, lying across the top of every tip of one model.
 *
 * From directly above a tip is a circle, and the only thing worth reading off it is that something
 * is standing there - which is what the existing visualizer says with a green circle. Said with a
 * disc rather than by colouring the tip, it is unlit, so the colour lands on the value asked for
 * rather than on whatever the lighting makes of it; and it is one instanced mesh however many tips
 * there are, so a rack of them costs one draw. A tip is only a resource while it is in its spot, so
 * there is one of these for every tip still standing and none for a spot that has been used.
 */
function buildPlanDiscs(instances, sx, sy, sz) {
  const disc = new THREE.InstancedMesh(
    DISC,
    // Flagged transparent although it is fully opaque, for the reason the cavity above is: three
    // draws every transparent object after every opaque one whatever the render order says, and
    // the spot's own rim is in that pass. Left opaque, this was painted first and the rim it is
    // meant to fill then covered it, which is a green disc nobody ever saw.
    new THREE.MeshBasicMaterial({ color: TIP_PLAN_FILL, transparent: true, opacity: 1 }),
    instances.length,
  );
  // A plan view alone. The mode change and the rule that culls small things share the switch.
  disc.userData.planOnly = true;
  disc.visible = false;
  instances.forEach((globalIndex, slot) => {
    // Level with the top of the tip, which is the first thing the eye meets looking down at it.
    const at = [sx, sy, 1, sx / 2, sy / 2, sz];
    placeInstance(disc, slot, world.matrices[globalIndex], ...at);
    remember(globalIndex, disc, slot, at);
  });
  disc.instanceMatrix.needsUpdate = true;
  disc.userData.lit = disc.material;
  own(buildMeshes, disc, disc.material);
  view.add(disc);
  return disc;
}

/**
 * Size a model's filter discs to the bore its own file has at their height, once the file is here.
 * The file is in the tip's frame, so the plane the disc lies in cuts the tip's inner wall at the
 * nearest distance from the axis.
 */
function fitFilterDiscs(modelIndex, scene, scale, up) {
  const discs = filterDiscsOf.get(modelIndex);
  if (!discs) return;
  scene.scale.setScalar(scale);
  if (up === "Y") scene.rotation.x = Math.PI / 2;
  scene.updateMatrixWorld(true);
  const width = boreWidthAt(scene, discs.z, discs.cx, discs.cy);
  if (width === null) return;
  const touched = new Set();
  for (const { index, at } of discs.placed) {
    at[0] = width;
    at[1] = width;
    placeParts(index, touched);
  }
  for (const mesh of touched) {
    mesh.instanceMatrix.needsUpdate = true;
    mesh.boundingSphere = null;
  }
}

/** Twice the nearest a surface of `object` comes to the axis through (cx, cy), in the plane z. */
function boreWidthAt(object, z, cx, cy) {
  let nearest = Number.POSITIVE_INFINITY;
  const corners = [new THREE.Vector3(), new THREE.Vector3(), new THREE.Vector3()];
  object.traverse((o) => {
    if (!o.isMesh) return;
    const position = o.geometry.attributes.position;
    const index = o.geometry.index;
    const count = index ? index.count : position.count;
    for (let i = 0; i + 2 < count; i += 3) {
      for (let k = 0; k < 3; k++) {
        const vertex = index ? index.getX(i + k) : i + k;
        corners[k].fromBufferAttribute(position, vertex).applyMatrix4(o.matrixWorld);
      }
      // Where each edge crosses the plane, if it does.
      for (let k = 0; k < 3; k++) {
        const p = corners[k];
        const q = corners[(k + 1) % 3];
        if (p.z === q.z || (p.z - z) * (q.z - z) > 0) continue;
        const t = (z - p.z) / (q.z - p.z);
        const r = Math.hypot(p.x + t * (q.x - p.x) - cx, p.y + t * (q.y - p.y) - cy);
        if (r < nearest) nearest = r;
      }
    }
  });
  return Number.isFinite(nearest) ? 2 * nearest : null;
}

/**
 * Where one instanced part stands, so it can be put back after being emptied. `emptyOnly` marks
 * a part drawn only while the resource holds nothing, such as a spot's cavity.
 */
function remember(index, mesh, slot, at, emptyOnly = false) {
  if (!overlayOf.has(index)) overlayOf.set(index, []);
  overlayOf.get(index).push({ mesh, slot, at, emptyOnly });
}

// ---------------------------------------------------------------- live state

// State arrives as a table of the distinct states in the scene, plus which of them each resource
// holds. Empty wells and unused tip spots share a single entry, and anything that has not changed
// since the client was last told is absent.
//
// Addressed by name rather than by scene index: the order instances are emitted in is not stable
// across rebuilds, so an index can mean a different resource in the next scene. A name cannot.
function applyState(payload) {
  const touched = new Set();
  const { states, of } = payload;
  if (!states || !of) return;
  for (const [name, slot] of Object.entries(of)) {
    const index = world.indexOfName.get(name);
    if (index === undefined) continue;
    // Shared between every resource in the same state, and only ever read.
    stateOf.set(index, states[slot]);
    // A state carries the whole of what a resource publishes, so a rotation that is not in it is
    // one that has come back to zero - the sender drops the identity to keep the message small.
    // Taking absence as "unchanged" leaves a joint drawn at the last angle it was turned to.
    applyRotation(index, states[slot]?.rotation ?? { x: 0, y: 0, z: 0 });
    refreshOverlays(index, touched);
    applyJoints(index);
  }
  for (const [name, location] of Object.entries(payload.locations ?? {})) {
    const index = world.indexOfName.get(name);
    if (index !== undefined) applyLocation(index, location);
  }
  for (const mesh of touched) {
    mesh.instanceMatrix.needsUpdate = true;
    mesh.boundingSphere = null;
  }
  // Only a panel showing something this message touched is drawn again: drawing the rest
  // afresh reset what the reader had opened in it, on every well of a protocol.
  const changed = new Set(Object.keys(of).map((name) => world.indexOfName.get(name)));
  if (changed.has(selected) && infoPanel?.isConnected) renderInfoPanel();
  refreshTreeInfo();
  deviceTools.refresh(changed);
}

function refreshOverlays(index, touched) {
  const state = stateOf.get(index);

  if (MOVING_PARTS.has(modelOf(index).category)) {
    const tracked = state?.tracker?.x;
    if (tracked !== undefined && tracked !== null) setArmX(index, tracked);
  }

  const vessel = vesselOf.get(index);
  if (vessel && Number.isFinite(vessel.model.max_volume)) {
    // The committed volume, as the existing visualizer draws it: what is in the well, not what an
    // operation under way would leave there if it succeeds - and a rollback publishes nothing.
    const volume = state?.volume ?? 0;
    const fraction = Math.max(0, Math.min(1, volume / (vessel.model.max_volume || 1)));
    // Empty is white; any liquid at all steps clear of white so a nearly empty well still reads.
    const t = fraction > 0 ? 0.35 + 0.65 * fraction : 0;
    vessel.mesh.setColorAt(
      vessel.slot,
      new THREE.Color(VESSEL_EMPTY).lerp(new THREE.Color(LIQUID), t),
    );
    if (vessel.mesh.instanceColor) vessel.mesh.instanceColor.needsUpdate = true;
  }

  placeParts(index, touched);
}

// A well's rim and its cavity, a carrier's floor: everything drawn outside the box
// pipeline. Each one follows the resource it belongs to - emptied when that resource is switched
// off, put back where it stands when it is switched on, and carried along when it moves.
function placeParts(index, touched) {
  const visible = isVisible(index);

  for (const part of overlayOf.get(index) ?? []) {
    const shown = visible && !(part.emptyOnly && world.childrenOf[index].length > 0);
    if (shown) placeInstance(part.mesh, part.slot, world.matrices[index], ...part.at);
    else part.mesh.setMatrixAt(part.slot, ZERO);
    touched.add(part.mesh);
  }
}

// ---------------------------------------------------------------- visibility

// Only explicitly hidden resources go in the set. A resource is drawn when neither it nor any
// ancestor is hidden, so "hidden because I was toggled off" stays distinct from "hidden because
// a parent is off".
function isVisible(index) {
  for (let i = index; i >= 0; i = world.parentOf[i]) {
    if (hiddenNames.has(world.names[i])) return false;
  }
  return true;
}

function setHidden(name, hidden) {
  if (hidden) hiddenNames.add(name);
  else hiddenNames.delete(name);
  const root = world.indexOfName.get(name);
  if (root === undefined) return;

  const touched = new Set();
  const walk = (index) => {
    const placement = placementOf[index];
    if (placement) {
      if (isVisible(index)) {
        const [sx, sy, sz] = sizeOf(modelOf(index));
        placeInstance(placement.mesh, placement.slot, world.matrices[index], sx, sy, sz);
      } else {
        placement.mesh.setMatrixAt(placement.slot, ZERO);
      }
      touched.add(placement.mesh);
    }
    const line = edgeOf.get(index);
    if (line) line.visible = isVisible(index);
    // A resource drawn from a file is drawn outside the instanced pipeline, so switching off the
    // box it stood in for leaves the geometry on screen unless it is told too.
    const model = meshRoots.find((r) => r.userData.index === index);
    if (model) model.visible = isVisible(index);
    for (const mark of gridMarks) {
      if (mark.userData.owner === index) mark.visible = isVisible(index);
    }
    // A travelling part is drawn by its own group rather than the instanced pipeline, so it has to
    // be told separately. Anything else drawn outside that pipeline needs the same line.
    const arm = arms.find((a) => a.index === index);
    if (arm) arm.group.visible = isVisible(index);
    refreshOverlays(index, touched);
    for (const child of world.childrenOf[index]) walk(child);
  };
  walk(root);
  for (const mesh of touched) {
    mesh.instanceMatrix.needsUpdate = true;
    mesh.boundingSphere = null;
  }
  refreshTreeVisibility();
}

// ---------------------------------------------------------------- reference points

// PLR's own reference semantics: a resource's origin is its left, front, bottom corner.
//
// `cavity_bottom` is the one reference a resource may be unable to answer: it is the floor of what
// a container holds, standing its base's thickness above the outside of that base, and only a
// container states a thickness. The point still comes back, so x and y read as they always do,
// with `zKnown` false so a caller can say the height is unavailable rather than print the bottom
// of the box as though it were the cavity's.
function referencePoint(index, xRef, yRef, zRef) {
  const model = modelOf(index);
  const [sx, sy, sz] = sizeOf(model);
  const thickness = model.material_z_thickness;
  const x = xRef === "center" ? sx / 2 : xRef === "right" ? sx : 0;
  const y = yRef === "center" ? sy / 2 : yRef === "back" ? sy : 0;
  const z =
    zRef === "center"
      ? sz / 2
      : zRef === "top"
        ? sz
        : zRef === "cavity_bottom"
          ? (thickness ?? 0)
          : 0;
  const point = new THREE.Vector3(x, y, z).applyMatrix4(world.matrices[index]);
  point.zKnown = zRef !== "cavity_bottom" || typeof thickness === "number";
  return point;
}

function worldBox(index) {
  const [sx, sy, sz] = sizeOf(modelOf(index));
  const box = new THREE.Box3();
  const corner = new THREE.Vector3();
  for (const c of [
    [0, 0, 0],
    [sx, 0, 0],
    [0, sy, 0],
    [0, 0, sz],
    [sx, sy, 0],
    [sx, 0, sz],
    [0, sy, sz],
    [sx, sy, sz],
  ]) {
    corner.set(c[0], c[1], c[2]).applyMatrix4(world.matrices[index]);
    box.expandByPoint(corner);
  }
  return box;
}

// ---------------------------------------------------------------- facility tree

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

// ---------------------------------------------------------------- info panel

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

// ---------------------------------------------------------------- picking

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

// ---------------------------------------------------------------- bullseyes

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

// ---------------------------------------------------------------- delta lines

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

// ---------------------------------------------------------------- camera

const VIEWS = {
  iso: new THREE.Vector3(-0.7, -1, 0.85),
  top: new THREE.Vector3(0, -0.001, 1),
  front: new THREE.Vector3(0, -1, 0.12),
};

// The orthographic frustum is sized to cover what the perspective camera covered at the target,
// so switching does not jump the framing.
function sizeOrthographic(distance) {
  const aspect = (viewportEl.clientWidth || 1) / (viewportEl.clientHeight || 1);
  const halfHeight = distance * Math.tan((perspectiveCamera.fov * DEG) / 2);
  orthographicCamera.top = halfHeight;
  orthographicCamera.bottom = -halfHeight;
  orthographicCamera.left = -halfHeight * aspect;
  orthographicCamera.right = halfHeight * aspect;
  orthographicCamera.updateProjectionMatrix();
}

function setProjection(kind) {
  if (kind === projection) return;
  const target = controls.target.clone();
  const position = camera.position.clone();
  const distance = position.distanceTo(target);

  projection = kind;
  camera = kind === "orthographic" ? orthographicCamera : perspectiveCamera;
  // The lights ride the camera, and there are two cameras with only one ever in use. Whichever
  // that is has to be carrying them: left on the other, they keep the pose it was last at, and the
  // scene goes on being lit from a direction the view no longer has - which is the one thing
  // putting the lights on the camera exists to prevent.
  camera.add(lights);
  view.add(camera);
  camera.position.copy(position);
  camera.up.set(0, 0, 1);
  if (kind === "orthographic") {
    camera.zoom = 1;
    sizeOrthographic(distance);
  } else {
    camera.updateProjectionMatrix();
  }
  controls.object = camera;
  controls.target.copy(target);
  controls.update();
  buildViewHelper();
  projectionButton.textContent = kind === "orthographic" ? "ORT" : "PSP";
  projectionButton.title =
    kind === "orthographic"
      ? "Orthographic: switch to perspective"
      : "Perspective: switch to orthographic";
}

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
const FRAME_MARGIN = 1.06;

function viewBasis(direction) {
  const forward = direction.clone().normalize();
  // The world up is Z, except when that is what we are looking along.
  const up = Math.abs(forward.z) > 0.99 ? new THREE.Vector3(0, 1, 0) : new THREE.Vector3(0, 0, 1);
  const right = new THREE.Vector3().crossVectors(forward, up).normalize();
  const camUp = new THREE.Vector3().crossVectors(right, forward).normalize();
  return { forward, right, camUp };
}

function projectedExtent(box, direction) {
  const { forward, right, camUp } = viewBasis(direction);
  const centre = box.getCenter(new THREE.Vector3());
  const corner = new THREE.Vector3();
  const offset = new THREE.Vector3();
  let halfWidth = 0;
  let halfHeight = 0;
  let halfDepth = 0;
  for (const c of [box.min, box.max]) void c;
  for (let i = 0; i < 8; i++) {
    corner.set(
      i & 1 ? box.max.x : box.min.x,
      i & 2 ? box.max.y : box.min.y,
      i & 4 ? box.max.z : box.min.z,
    );
    offset.subVectors(corner, centre);
    halfWidth = Math.max(halfWidth, Math.abs(offset.dot(right)));
    halfHeight = Math.max(halfHeight, Math.abs(offset.dot(camUp)));
    halfDepth = Math.max(halfDepth, Math.abs(offset.dot(forward)));
  }
  return { centre, halfWidth, halfHeight, halfDepth };
}

function fitOrthographic(halfWidth, halfHeight) {
  const aspect = (viewportEl.clientWidth || 1) / (viewportEl.clientHeight || 1);
  let w = halfWidth;
  let h = halfHeight;
  if (w / h > aspect) h = w / aspect;
  else w = h * aspect;
  orthographicCamera.zoom = 1;
  orthographicCamera.top = h;
  orthographicCamera.bottom = -h;
  orthographicCamera.left = -w;
  orthographicCamera.right = w;
  orthographicCamera.updateProjectionMatrix();
}

function frameBox(box, direction) {
  const { centre, halfWidth, halfHeight, halfDepth } = projectedExtent(box, direction);
  const w = Math.max(halfWidth * FRAME_MARGIN, 1);
  const h = Math.max(halfHeight * FRAME_MARGIN, 1);
  const aspect = (viewportEl.clientWidth || 1) / (viewportEl.clientHeight || 1);

  const halfFov = (perspectiveCamera.fov * DEG) / 2;
  const distance = Math.max(h / Math.tan(halfFov), w / (Math.tan(halfFov) * aspect)) + halfDepth;

  controls.target.copy(centre);
  camera.position.copy(centre).add(direction.clone().normalize().multiplyScalar(distance));
  if (projection === "orthographic") {
    fitOrthographic(w, h);
  } else {
    camera.near = Math.max(distance / 1000, 0.1);
    camera.far = distance * 50;
    camera.updateProjectionMatrix();
  }
  // A drag leaves OrbitControls holding a rotation it has not finished applying: with damping on it
  // spends that residue over the following frames and only decays it, so it outlives the pointer
  // going up. Framing writes the camera straight to where it belongs, and the residue then turns it
  // back off the axis - by more than the 2.5 degrees an axis view is allowed, which is why a plan
  // view reached through the home button came back drawn as a free one, translucent and washed out,
  // while the same view on opening was solid. Damping off for the single update that lands the
  // frame is what clears it; `update` zeroes the residue itself in that branch.
  const damped = controls.enableDamping;
  controls.enableDamping = false;
  controls.update();
  controls.enableDamping = damped;
}

const frame = (direction) => frameBox(sceneBounds(), direction ?? VIEWS.iso);

function dolly(factor) {
  if (projection === "orthographic") {
    camera.zoom = Math.max(0.02, camera.zoom / factor);
    camera.updateProjectionMatrix();
  } else {
    const offset = camera.position.clone().sub(controls.target).multiplyScalar(factor);
    camera.position.copy(controls.target).add(offset);
  }
  controls.update();
}

// A plan view is what a deck is read in, so that is where the viewer opens. `?view=iso` or
// `?view=front` picks another, so a link can still point at a particular angle.
const startViewName = new URLSearchParams(location.search).get("view") ?? "top";
const startView = VIEWS[startViewName] ?? VIEWS.top;

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
  stats: () => stats,
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
      level: quality,
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

// ---------------------------------------------------------------- overlays

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

const statsEl = document.getElementById("stats-panel");
let frames = 0;
let lastSample = performance.now();

function updateStats() {
  frames++;
  const now = performance.now();
  if (now - lastSample < 500) return;
  const fps = Math.round((frames * 1000) / (now - lastSample));
  frames = 0;
  lastSample = now;
  drawStats(`${String(fps)} fps`);
}

// Quoting a frame rate while nothing is being drawn would be a lie, so an idle viewer says so. This
// runs on a timer rather than in the loop, because the loop is exactly what has stopped.
function reportIdle() {
  if (performance.now() - lastRenderAt > 400) drawStats("idle");
}

let lastDrawCalls = 0;

function drawStats(rate) {
  // three zeroes its counters between frames, so an idle viewer would otherwise report no draws at
  // all. What the scene costs when it is drawn does not change just because it is not being drawn.
  const info = renderer.info.render;
  const calls = info.drawCalls ?? info.calls ?? 0;
  if (calls > 0) lastDrawCalls = calls;
  const text =
    `instances  <b>${(stats.instances ?? 0).toLocaleString()}</b>   ` +
    `models <b>${stats.models ?? 0}</b>   ` +
    `draws <b>${lastDrawCalls}</b>   ` +
    `${renderer.backend?.isWebGPUBackend ? "WebGPU" : "WebGL2"}   ` +
    `<b>${rate}</b>` +
    `${quality > 0 ? `   quality <b>${quality === 1 ? "low" : "lowest"}</b>` : ""}\n` +
    `tree JSON ${((stats.legacy_bytes ?? 0) / 1024).toFixed(1)} kB  ` +
    `→ this scene <b>${((stats.scene_bytes ?? 0) / 1024).toFixed(1)} kB</b> (${stats.ratio ?? 0}×)`;
  // Writing the same markup back forces layout and paint for nothing, twice a second, forever.
  if (text !== statsEl.innerHTML) statsEl.innerHTML = text;
}

// ---------------------------------------------------------------- interaction

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
  showOriginDots = on;
  originsButton.classList.toggle("active", on);
  const t = performance.now();
  buildOriginDots();
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
  showHalos = on;
  halosButton.classList.toggle("active", on);
  buildHalos();
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
const projectionButton = document.getElementById("view-projection");
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

// ---------------------------------------------------------------- transport

const statusDot = document.getElementById("status-indicator");
const statusLabel = document.getElementById("status-label");

// The status is only ever as fresh as the last time this tab ran. A backgrounded tab gets frozen,
// so neither the close handler nor the reconnect timer fires, and it goes on painting whatever it
// last said. Keep a handle on the socket and re-read its real state whenever the tab comes back.
let socket = null;

const RECONNECT_MS = 1500;
// A minute of refused attempts says the viewer is gone, not busy: its kernel was restarted, or the
// run that served this page has ended. A new run serves a new page with a key of its own.
const GIVE_UP_MS = 60000;
let lostAt = null;

function showStatus(connected) {
  for (const el of [statusDot, statusLabel]) {
    el.classList.toggle("connected", connected);
    el.classList.toggle("disconnected", !connected);
  }
  statusLabel.textContent = connected ? "Connected" : "Disconnected";
  window.dispatchEvent(new CustomEvent("plr:status", { detail: { connected } }));
}

/** Tell the server what this page draws with, so a slow or odd viewer is visible from Python. */
function sayHello() {
  const probe = window.plrCapability ?? {};
  const webgpu = !!renderer.backend?.isWebGPUBackend;
  socket.send(
    JSON.stringify({
      event: "hello",
      data: {
        backend: webgpu ? "WebGPU" : "WebGL2",
        renderer: webgpu ? null : probe.renderer,
        software: webgpu ? false : !!probe.software,
        quality,
        userAgent: navigator.userAgent,
      },
    }),
  );
}

document.addEventListener("visibilitychange", () => {
  if (document.visibilityState !== "visible") return;
  const live = socket && socket.readyState === WebSocket.OPEN;
  showStatus(!!live);
  if (live) return;
  lostAt = null; // a tab coming back gets its minute again
  connect();
});

function connect() {
  if (
    socket &&
    (socket.readyState === WebSocket.OPEN || socket.readyState === WebSocket.CONNECTING)
  ) {
    return;
  }
  socket = new WebSocket(window.WS_URL);
  framed = false;
  socket.onopen = () => {
    lostAt = null;
    showStatus(true);
    sayHello();
  };
  socket.onclose = () => {
    showStatus(false);
    lostAt ??= performance.now();
    if (performance.now() - lostAt < GIVE_UP_MS) setTimeout(connect, RECONNECT_MS);
    else window.dispatchEvent(new CustomEvent("plr:gone"));
  };
  socket.onmessage = (event) => {
    let message;
    try {
      message = JSON.parse(event.data);
    } catch {
      console.warn("a message from the viewer was not JSON, and was ignored");
      return;
    }
    const { event: kind, data } = message;
    if (!data) return;
    // Everything the server says changes what is on screen: the scene it draws, or the state it
    // draws it in. There is no message that only touches the panels around the viewport.
    invalidate();
    if (kind === "scene") {
      // A page is fetched fresh on every load; the Python serving it is as old as its process. A
      // scene from another protocol is not drawn, since what it says would be misread.
      if (data.protocol !== PROTOCOL) {
        window.dispatchEvent(new CustomEvent("plr:mismatch"));
        return;
      }
      const _tScene = performance.now();
      // New pipelines to compile: the frame cost is not judged again until they have been.
      sceneCameAt = _tScene;
      frameCostAverage = 0;
      slowSince = null;
      fastSince = null;
      stats = data.stats ?? {};
      const kept = rememberView();
      setWorld(buildWorld(data));
      glides.clear();
      timings.decodeMs = performance.now() - _tScene;
      const _tBuild = performance.now();
      buildMeshes();
      floorZ = sceneBounds().min.z;
      gridState = null;
      planView = null;
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
    } else if (kind === "state" && world) {
      applyState(data);
    } else if (kind === "moves" && world && Array.isArray(data.moves)) {
      applyMoves(data.moves);
    }
  };
}

// ---------------------------------------------------------------- moves

// A resource put somewhere else, applied to the scene the page has rather than the scene being
// built again: a tip picked up is the same tip, now under a channel's shaft. The tree keeps its
// shape, the panel stays open, nothing is torn down to be fetched and drawn again.
function applyMoves(moves) {
  const touched = new Set();
  const rowsUnder = new Set();
  for (const move of moves) {
    const index = world.indexOfName.get(move.name);
    if (index === undefined) continue;
    const parent = move.parent === null ? -1 : (world.indexOfName.get(move.parent) ?? -1);
    const was = world.parentOf[index];
    if (was !== parent) {
      if (was >= 0) {
        const siblings = world.childrenOf[was];
        const at = siblings.indexOf(index);
        if (at >= 0) siblings.splice(at, 1);
        rowsUnder.add(was);
      }
      if (parent >= 0) {
        world.childrenOf[parent].push(index);
        rowsUnder.add(parent);
      }
      world.parentOf[index] = parent;
    }
    setLocal(index, move.location);
    setLocalRotation(index, move.rotation);
    for (const i of refreshTransforms(index)) touched.add(i);
    // The spot it left and the one it reached draw their cavities from whether they hold a tip.
    for (const i of [was, parent]) if (i >= 0) touched.add(i);
    // An arm is drawn by its own group, which is put where the model now says, with nothing to glide.
    const arm = arms.find((a) => a.index === index);
    if (arm) {
      Object.assign(arm, armPose(index));
      arm.group.matrix.copy(world.matrices[index]);
      arm.group.matrixWorldNeedsUpdate = true;
    }
  }
  redraw([...touched]);
  for (const at of rowsUnder) reopenRowsUnder(at);
  refreshTreeInfo();
  deviceTools.refresh();
  buildHalos();
  if (selected >= 0 && infoPanel?.isConnected) renderInfoPanel();
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

statusDot.addEventListener("click", connect);

// The camera is read at capture time: a view change swaps it, and the recording follows the view.
const gif = initGif({
  renderer,
  view,
  get camera() {
    return camera;
  },
});

// ---------------------------------------------------------------- loop

let sizedTo = { w: 0, h: 0 };

function resize() {
  const { clientWidth: w, clientHeight: h } = viewportEl;
  // `setSize` writes the canvas' CSS size, which changes layout, which wakes the ResizeObserver
  // that called this. Without this guard the two chase each other at sixty layouts a second for as
  // long as the page is open, drawing nothing and costing a third of a core.
  if (w === sizedTo.w && h === sizedTo.h) return;
  sizedTo = { w, h };
  invalidate();
  // three must set the canvas' CSS size as well as its drawing buffer. Told not to, it still sizes
  // the buffer by the pixel ratio, and with no CSS size the element lays out at that buffer size -
  // twice the viewport on a 2x display, overflowing down and right.
  renderer.setSize(w, h);
  perspectiveCamera.aspect = w / Math.max(h, 1);
  perspectiveCamera.updateProjectionMatrix();
  if (projection === "orthographic") {
    sizeOrthographic(camera.position.distanceTo(controls.target));
  }
}

// The viewport changes size without the window doing so: dragging the side panel, or toggling
// either panel, resizes it while `window.resize` stays silent. The renderer and the camera aspect
// then go stale, and anything that frames against them - the home button most visibly - works off
// the wrong shape. Observing the element covers both cases, as the existing visualizer does.
new ResizeObserver(resize).observe(viewportEl);

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
setInterval(reportIdle, 500);

// How long the last frame took on the main thread, submission included. What the pointer gate
// above reads: a slow frame is a machine that cannot answer every pointer sample.
let lastFrameMs = 0;

// ---------------------------------------------------------------- adaptive quality

// The page steps its own cost down while frames are slow and back up once they are fast, so a
// machine that cannot draw the scene at full quality still draws it at a usable rate without
// anyone naming its renderer. `?quality=high` or `?quality=low` pins a level instead.
const qualityPinned = new URLSearchParams(location.search).get("quality");
let quality = qualityPinned === "low" ? QUALITY_LEVELS - 1 : 0;
let frameCostAverage = 0;
let slowSince = null;
let fastSince = null;
let sceneCameAt = performance.now();
const demotedAt = new Map(); // level -> when it was last found too slow

function applyQuality(level) {
  quality = Math.max(0, Math.min(QUALITY_LEVELS - 1, level));
  renderer.setPixelRatio(quality >= 1 ? 1 : Math.min(window.devicePixelRatio, 2));
  // The drawing buffer follows the pixel ratio only through setSize.
  renderer.setSize(viewportEl.clientWidth || 1, viewportEl.clientHeight || 1);
  view.environment = quality >= 2 ? null : (view.userData.roomEnvironment ?? null);
  skyLight.intensity = view.environment ? SKY_LIGHT : SKY_LIGHT_WITHOUT_ENVIRONMENT;
}

// Read after each drawn frame. Down after slow frames have settled, up after fast ones have, and
// never back into a level found slow within QUALITY_HOLD_MS.
function adaptQuality(frameMs) {
  if (qualityPinned !== null) return;
  if (performance.now() - sceneCameAt < QUALITY_WARMUP_MS) return;
  frameCostAverage = frameCostAverage === 0 ? frameMs : frameCostAverage * 0.9 + frameMs * 0.1;
  const now = performance.now();
  if (frameCostAverage > QUALITY_SLOW_MS) {
    fastSince = null;
    slowSince ??= now;
    if (now - slowSince >= QUALITY_SETTLE_MS && quality < QUALITY_LEVELS - 1) {
      demotedAt.set(quality, now);
      applyQuality(quality + 1);
      slowSince = null;
      frameCostAverage = 0;
    }
  } else if (frameCostAverage < QUALITY_FAST_MS) {
    slowSince = null;
    fastSince ??= now;
    const above = quality - 1;
    const heldBack = above >= 0 && now - (demotedAt.get(above) ?? -Infinity) < QUALITY_HOLD_MS;
    if (now - fastSince >= QUALITY_RECOVER_MS && above >= 0 && !heldBack) {
      applyQuality(above);
      fastSince = null;
      frameCostAverage = 0;
    }
  } else {
    slowSince = null;
    fastSince = null;
  }
}

function drawFrame() {
  const frameStarted = performance.now();
  const delta = clock.getDelta();

  // At most one hover answered per frame, however many times the pointer moved in between: a
  // pointer crosses the canvas far faster than frames are drawn, and each answer raycasts the whole
  // scene to produce a readout nobody could have seen the previous version of.
  if (hoverAt !== null) answerHover();

  // Three things keep drawing on their own account: the helper's snap animation, an arm gliding to
  // a new position, and a recording that needs a frame to capture. `controls.update` reports
  // whether damping is still carrying the camera.
  let moving = false;
  if (viewHelper?.animating) {
    viewHelper.update(delta);
    // Every direction the helper can snap to is axis-aligned, so the view it lands on is a plan or
    // an elevation. Switch once the animation is done, not during it, since changing projection
    // rebuilds the helper.
    if (!viewHelper.animating) setProjection("orthographic");
    moving = true;
  }
  if (deltaAnnotation?.group.visible) updateDeltaLabels();
  if (updateArms(delta)) moving = true;
  if (updateGlides(delta)) moving = true;
  if (controls.update()) moving = true;
  if (gif.isRecording()) moving = true;

  if (!renderPending && !moving) {
    looping = false;
    renderer.setAnimationLoop(null);
    return;
  }
  renderPending = false;
  lastRenderAt = performance.now();

  // What the camera can see decides what is worth drawing, so it is decided before the frame is
  // drawn rather than after it. Asked afterwards, every frame drew what the frame before it had
  // worked out, and the last frame of a move - the one left on screen - never drew its own answer
  // at all: a zoom settled with the detail of where it started, a window resize changed nothing
  // until the camera next moved, and a view turned to a plan kept the colours of the angle it came
  // from. Nothing here asks for another frame; they are worked out for this one.
  updateGrid();
  updateDetail();
  updateEdgeMode();
  updateOrigin();
  updateHalos();
  updateBullseyes();
  updateScaleBar();

  renderer.render(view, camera);
  // What a frame costs is the longer of this thread's work and the gap since the last frame: the
  // GPU, or a rasteriser in another process, shows up only in the gap. The gap of an idle spell is
  // discarded where the loop is woken, so the first frame back is costed by its work alone.
  lastFrameMs = Math.max(performance.now() - frameStarted, delta * 1000);
  adaptQuality(lastFrameMs);
  if (viewHelper) {
    // The helper renders a second pass into a corner of the same canvas. Without turning auto-clear
    // off it clears the colour buffer for that corner first, leaving a blank patch over the scene.
    renderer.autoClear = false;
    viewHelper.render(renderer);
    renderer.autoClear = true;
  }
  gif.tick();
  // Read after the draw, because it is the draw it reports.
  updateStats();
}

buildViewHelper();
refreshToolUI();
showPane("tree");
resize();
if (quality > 0) applyQuality(quality);
connect();
