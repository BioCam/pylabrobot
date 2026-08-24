// A workcell viewer that knows nothing about liquid handlers.
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
import { OrbitControls } from "three/addons/OrbitControls.js";
import { ViewHelper } from "three/addons/ViewHelper.js";
import { RoomEnvironment } from "three/addons/RoomEnvironment.js";
import { LineSegments2 } from "three/addons/lines/LineSegments2.js";
import { LineSegmentsGeometry } from "three/addons/lines/LineSegmentsGeometry.js";
import { GLTFLoader } from "three/addons/GLTFLoader.js";
import { DRACOLoader } from "three/addons/DRACOLoader.js";

import {
  DEG,
  WORKCELL_OUTLINE,
  RESOURCE_COLORS,
  MOVING_PARTS,
  FLAT_EDGE,
  EDGE_WIDTH_FLAT,
  EDGE_WIDTH_3D,
  structureEdgeStyle,
  LIQUID,
  VESSEL_EMPTY,
  VESSEL_RIM,
  VESSEL_INSET,
  TIP,
  SELECT,
  HOVER,
  ARM_COLOR,
  ARM_OPACITY,
  SHELL_OPACITY,
  SPACE_OPACITY,
  HOLDERS,
  ARM_EDGE,
  ARM_EDGE_WIDTH_FLAT,
  ARM_EDGE_WIDTH_3D,
  ARM_INSET_X,
  ARM_INSET_Y,
  REFERENCE_LINE,
  REFERENCE_WIDTH,
  REFERENCE_DROP,
} from "./constants.js";
import { initGif } from "./gif.js";
import { initCoords } from "./coords.js";
import { input, query } from "./dom.js";
import {
  buildWorld,
  mirrorPlacement,
  modelOf,
  refreshTransforms,
  setLocal,
  setWorld,
  sizeOf,
  treeDepth,
  world,
} from "./world.js";
import { escapeHtml, fmt, NBSP, tuple, withUnit, section } from "./format.js";


const timings = { moduleMs: performance.now() - _t0 };

// Every fat-line material, so a resize can refresh the resolution each one is sized against.
const edgeMaterials = new Set();

// ---------------------------------------------------------------- state

let meshes = [];
let placementOf = []; // instance index -> { mesh, slot }
let vesselOf = new Map(); // index -> the inner body whose colour tracks what is in it
let tipOf = new Map();
let edgeOf = new Map();
let stateOf = new Map();
let hiddenNames = new Set();
let selected = -1;
let stats = {};
let workcells = []; // { name, members: [name] } - groupings, not places
let workcellBoxes = new Map(); // name -> Box3Helper drawn from the members' own extents
let activeTool = "cursor";

// ---------------------------------------------------------------- renderer

const viewportEl = document.getElementById("viewport");
// `preserveDrawingBuffer` keeps the rendered frame readable after it is composited, which is
// what lets a GIF frame be copied off the canvas. Without it the copy comes back blank on the
// WebGL2 fallback path.
const renderer = new THREE.WebGPURenderer({ antialias: true, preserveDrawingBuffer: true });
const _tInit = performance.now();
await renderer.init();
timings.rendererMs = performance.now() - _tInit;
renderer.setPixelRatio(Math.min(window.devicePixelRatio, 2));
// No tone mapping: it compresses the top of the range, which turns a pure white background grey.
// Over-exposure is handled by budgeting the lights instead.
renderer.toneMapping = THREE.NoToneMapping;
viewportEl.appendChild(renderer.domElement);

const view = new THREE.Scene();
view.background = new THREE.Color(0xffffff);

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
  if (event.ctrlKey) return (gesturePans = false); // a pinch is a zoom, whatever came before it
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

view.add(new THREE.HemisphereLight(0xffffff, 0xc8d0d4, 1.1));
const keyLight = new THREE.DirectionalLight(0xffffff, 0.9);
keyLight.position.set(-0.5, -1, 1.3);
view.add(keyLight);
const fillLight = new THREE.DirectionalLight(0xffffff, 0.3);
fillLight.position.set(1, 0.6, 0.4);
view.add(fillLight);

// A metal surface has almost no diffuse colour of its own; it is what it reflects. Without an
// environment it renders nearly black under directional lights, so give the scene something to
// reflect. Kept dim, so the flat technical shading of everything else is barely touched.
try {
  const pmrem = new THREE.PMREMGenerator(renderer);
  view.environment = pmrem.fromScene(new RoomEnvironment(), 0.04).texture;
  view.environmentIntensity = 0.28;
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

const GRID_LINE = 0xb4bdc3;
const GRID_LABEL = "#3d4a52";
const GRID_LIFT = 0.4; // mm above the surface, so the marks do not fight the deck for depth
// The work surface a grid is laid out on. A resource that declares a grid is declaring that things
// stand on it at that height, so that is where the surface goes; nothing here knows it is a deck.
const SURFACE_COLOR = 0xfbfcfd; // the deck is the brightest thing; what stands on it is darker
// Bands a capability can reach across a surface, drawn as a pair of lines with the reach labelled
// at the near edge. Blue keeps them apart from the grey position grid they cross.
const BAND_COLOR = 0x8ba7c6;
const GRID_LABEL_MM = 30; // label height in deck millimetres
const GRID_TICK = 30; // mm the mark runs forward of the grid, into the margin where labels sit

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
    new THREE.MeshBasicMaterial({ map: texture, transparent: true, depthTest: false })
  );
  label.frustumCulled = false;
  return label;
}

// Where along its width the machine's x refers to. Declared by the resource, so the viewer needs
// no knowledge of rail types: a dual-rail arm is positioned by its centre, a single-rail one by
// its right edge, and the line lands in the right place either way.
function referenceOffset(model) {
  const [sx] = sizeOf(model);
  return model.reference_point === "right" ? sx : sx / 2;
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

function clearDeclaredMeshes() {
  for (const root of meshRoots) view.remove(root);
  meshRoots = [];
}

// glTF says metres and Y-up; a resource that means something else says so in its declaration.
const MESH_UNITS = { mm: 1, cm: 10, m: 1000 };

function buildDeclaredMeshes() {
  clearDeclaredMeshes();

  // One load per distinct model, however many instances stand on it. A file of several hundred
  // thousand triangles is expensive to fetch and parse, and cloning shares both geometry and
  // materials, so the cost is paid once no matter how many arms are in the facility.
  const byModel = new Map();
  for (let index = 0; index < world.names.length; index++) {
    const declared = modelOf(index).mesh;
    if (!declared || !declared.url) continue;
    if (!byModel.has(world.modelOf[index])) byModel.set(world.modelOf[index], []);
    byModel.get(world.modelOf[index]).push(index);
  }

  for (const [modelIndex, instances] of byModel) {
    const declared = world.models[modelIndex].mesh;
    const scale = MESH_UNITS[declared.units] ?? 1;
    const names = instances.map((i) => world.names[i]);

    gltfLoader.load(
      declared.url,
      (gltf) => {
        // The scene may have been rebuilt while this was in flight. Placing it then would leave
        // objects nothing owns, positioned by transforms that no longer apply.
        if (!world || names.some((n, k) => world.indexOfName.get(n) !== instances[k])) return;

        instances.forEach((index, k) => {
          const scene = k === 0 ? gltf.scene : gltf.scene.clone(true);
          scene.scale.setScalar(scale);
          // Y-up is glTF's default; a Z-up file is already in our own convention.
          if ((declared.up ?? "Y") === "Y") scene.rotation.x = Math.PI / 2;

          const root = new THREE.Group();
          root.add(scene);
          root.matrixAutoUpdate = false;
          root.matrix.copy(world.matrices[index]);
          root.matrixWorldNeedsUpdate = true;
          root.traverse((o) => {
            o.frustumCulled = false;
            if (o.isMesh) o.userData.declaredBy = index;
          });

          // A rigged file names the parts that move. The declaration says which node answers to
          // which joint, so the viewer drives what it is told and holds no knowledge of any arm's
          // geometry. Each node's rest transform is kept, because a joint value is a displacement
          // from where the file was authored, not an absolute pose.
          const joints = new Map();
          for (const [key, spec] of Object.entries(declared.joints ?? {})) {
            const node = scene.getObjectByName(spec.node);
            if (!node) {
              console.warn(`${world.names[index]} declares joint ${key} on node ${spec.node}, which the file does not have`);
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

          view.add(root);
          meshRoots.push(root);
          applyJoints(index);
        });

        // The box that stood in for it is not needed once the real geometry is here.
        const entry = meshes.find((m) => m.modelIndex === modelIndex);
        if (entry) entry.mesh.material.visible = false;
      },
      undefined,
      (error) => console.warn(`could not load the mesh declared by ${names[0]}`, error)
    );
  }
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

function buildArms() {
  for (const arm of arms) view.remove(arm.group);
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
    // The opening is declared by the part when it knows its own geometry. A declared width is
    // centred on the part unless the part also says how far its right edge sits from the end,
    // which is the case for an opening that is deliberately off-centre.
    const window = model.window ?? {};
    const insetY = window.inset_y ?? ARM_INSET_Y;
    let holeLeft;
    let holeRight;
    if (window.width === undefined) {
      holeLeft = ARM_INSET_X;
      holeRight = sx - ARM_INSET_X;
    } else if (window.right_margin === undefined) {
      holeLeft = (sx - window.width) / 2;
      holeRight = holeLeft + window.width;
    } else {
      holeRight = sx - window.right_margin;
      holeLeft = holeRight - window.width;
    }
    const innerH = sy - 2 * insetY;
    if (holeRight > holeLeft && innerH > 0) {
      const hole = new THREE.Path();
      hole.moveTo(holeLeft, insetY);
      hole.lineTo(holeLeft, sy - insetY);
      hole.lineTo(holeRight, sy - insetY);
      hole.lineTo(holeRight, insetY);
      hole.closePath();
      shape.holes.push(hole);
    }

    const solid = new THREE.ExtrudeGeometry(shape, { depth: sz, bevelEnabled: false });
    const frame = new THREE.Mesh(
      solid,
      new THREE.MeshStandardMaterial({
        color: ARM_COLOR,
        roughness: 0.6,
        transparent: true,
        opacity: ARM_OPACITY,
        depthWrite: false,
      })
    );
    frame.renderOrder = 500;

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
    outlineMaterial.resolution?.set(viewportEl.clientWidth || 1, viewportEl.clientHeight || 1);
    edgeMaterials.add(outlineMaterial);
    const outline = new LineSegments2(outlineGeometry, outlineMaterial);
    outline.frustumCulled = false;
    outline.renderOrder = 510; // over the carriage it bounds

    const offset = referenceOffset(model);
    const line = new THREE.Mesh(
      new THREE.PlaneGeometry(REFERENCE_WIDTH, sy),
      new THREE.MeshBasicMaterial({
        color: REFERENCE_LINE, transparent: true, opacity: 0.7, depthTest: false,
      })
    );
    line.position.set(offset, sy / 2, -REFERENCE_DROP);
    // Under the frame in paint order as well as in z, so it reads through the window and is tinted
    // by the carriage everywhere else. Ordering, not position, is what decides this: depth testing
    // is off in an axis view, so a lower render order is the only thing that puts it underneath.
    line.renderOrder = 490;

    const group = new THREE.Group();
    group.add(line, frame, outline);
    group.matrixAutoUpdate = false;
    group.matrix.copy(world.matrices[index]);
    group.matrixWorldNeedsUpdate = true;
    view.add(group);

    const parent = world.parentOf[index];
    arms.push({
      group,
      outline,
      line,
      index,
      parentMatrix: parent >= 0 ? world.matrices[parent].clone() : new THREE.Matrix4(),
      local: world.local.slice(index * 6, index * 6 + 6),
      referenceOffset: offset,
      currentX: world.local[index * 6],
      targetX: world.local[index * 6],
    });
  }
}

// Glide rather than teleport, so a move reads as motion. The tracker carries commanded targets, so
// this interpolation is cosmetic and says nothing about where the arm physically is mid-move.
const ARM_GLIDE_PER_SECOND = 6;

const reducedMotion = window.matchMedia?.("(prefers-reduced-motion: reduce)");

function updateArms(delta) {
  const reduce = reducedMotion?.matches;
  let moved = false;
  for (const arm of arms) {
    if (Math.abs(arm.targetX - arm.currentX) < 0.01) continue;
    moved = true;
    arm.currentX = reduce
      ? arm.targetX
      : arm.currentX + (arm.targetX - arm.currentX) * Math.min(1, delta * ARM_GLIDE_PER_SECOND);
    const local = new THREE.Matrix4().makeTranslation(
      arm.currentX, arm.local[1], arm.local[2]
    );
    arm.group.matrix.multiplyMatrices(arm.parentMatrix, local);
    arm.group.matrixWorldNeedsUpdate = true;

    // Keep the scene model in step with what is drawn. Everything else reads position from here -
    // the info panel, the selection box, the coordinate tool - so moving only the group would
    // leave all of them quoting where the arm used to be.
    mirrorPlacement(arm.index, arm.currentX, arm.group.matrix);
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
  for (const at of indices) {
    const [sx, sy, sz] = sizeOf(modelOf(at));
    const placement = placementOf[at];
    if (placement) {
      placeInstance(placement.mesh, placement.slot, world.matrices[at], sx, sy, sz);
      placement.mesh.instanceMatrix.needsUpdate = true;
    }
    // An outline is its own object with its own baked matrix, so a move that touched only the
    // instance left it standing at the old position - a wireframe ghost of whatever rode the arm.
    const line = edgeOf.get(at);
    if (line) line.matrix.copy(boxMatrix(world.matrices[at], sx, sy, sz));
  }
}

function refreshSubtree(index, skipSelf) {
  redraw(refreshTransforms(index, skipSelf));
}

function applyLocation(index, location) {
  if (!setLocal(index, location)) return;

  // A travelling part is drawn by its own group and glides there, so it is told the target rather
  // than being moved under it. What stands on it is not part of that group, though - the 96-head
  // rides the arm in the model but is drawn with everything else - so the glide carries it.
  if (MOVING_PARTS.has(modelOf(index).category)) {
    const arm = arms.find((a) => a.index === index);
    if (arm) {
      arm.targetX = location.x;
      return;
    }
  }

  refreshSubtree(index);
}

function setArmX(index, referenceX) {
  const arm = arms.find((a) => a.index === index);
  if (arm) arm.targetX = referenceX - arm.referenceOffset;
}

function buildGridMarks() {
  for (const mark of gridMarks) view.remove(mark);
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
    const surfaceMaterial = new THREE.MeshStandardMaterial({
      color: SURFACE_COLOR,
      metalness: 0.3,
      roughness: 0.42,
    });
    const surface = new THREE.Mesh(
      new THREE.PlaneGeometry(footprintX, footprintY),
      surfaceMaterial
    );
    surface.renderOrder = treeDepth(index) * 2;
    surface.userData.lit = surfaceMaterial;
    surface.userData.flat = flatVariant(surfaceMaterial);
    surfaces.push(surface);
    surface.position.set(footprintX / 2, footprintY / 2, oz);
    group.add(surface);
    const points = [];
    for (let i = 0; i < grid.count; i++) {
      const x = ox + i * grid.spacing;
      points.push(x, oy - GRID_TICK, z, x, oy + grid.extent, z);

      const position = i + 1;
      if (position === 1 || position % grid.label_every === 0) {
        const sprite = labelSprite(String(position));
        gridLabels.push(sprite);
        // Between this mark and the next, in the margin the tick reaches into.
        sprite.position.set(x + grid.spacing / 2, oy - GRID_TICK - GRID_LABEL_MM * 0.5, z);
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
        new THREE.LineBasicMaterial({ color: BAND_COLOR, depthTest: false })
      );
      bandLines.renderOrder = treeDepth(index) * 2 + 1;
      group.add(bandLines);
    }

    const geometry = new THREE.BufferGeometry();
    geometry.setAttribute("position", new THREE.Float32BufferAttribute(points, 3));
    const marks = new THREE.LineSegments(
        geometry,
        // Drawn without a depth test, like the underlay on a drawing: a rail is a reference for
        // where things sit, so it has to stay readable with a carrier standing on it.
        // Opaque, so it sorts with everything else: a transparent line renders after all opaque
        // geometry no matter its render order, which is what kept these on top of the carriers.
        new THREE.LineBasicMaterial({ color: GRID_LINE, depthTest: false })
    );
    // Just above the surface it is drawn on, and below anything standing on that surface.
    marks.renderOrder = treeDepth(index) * 2 + 1;
    group.add(marks);

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

function buildOrigin() {
  if (originMarker) view.remove(originMarker);
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
    const head = new THREE.Mesh(
      new THREE.ConeGeometry(shaft * 2.6, length - body, 14), material
    );
    // Cylinders and cones point along +Y; turn each onto its own axis.
    const quaternion = new THREE.Quaternion().setFromUnitVectors(new THREE.Vector3(0, 1, 0), direction);
    bar.quaternion.copy(quaternion);
    head.quaternion.copy(quaternion);
    bar.position.copy(direction).multiplyScalar(body / 2);
    head.position.copy(direction).multiplyScalar(body + (length - body) / 2);
    originMarker.add(bar, head);
  }

  originMarker.add(
    new THREE.Mesh(
      new THREE.SphereGeometry(shaft * 2.2, 18, 14),
      new THREE.MeshStandardMaterial({ color: 0x1a1f22, roughness: 0.4 })
    )
  );

  // A ring flat on the floor, so the origin is still findable from directly above.
  const ring = new THREE.Mesh(
    new THREE.RingGeometry(length * 0.15, length * 0.2, 48),
    new THREE.MeshBasicMaterial({ color: 0x1a4b8c, transparent: true, opacity: 0.6, side: THREE.DoubleSide })
  );
  originMarker.add(ring);

  // The origin is a marker on the viewport, not something standing in the scene, so it reads over
  // whatever is drawn there.
  originMarker.traverse((o) => {
    if (o.material) {
      o.material.depthTest = false;
      o.material.depthWrite = false;
      o.renderOrder = 920;
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

  const drawn = new Set();
  for (const entry of meshes) {
    const [sx, sy] = sizeOf(entry.model);
    const visible = Math.max(sx, sy) / perPixel >= DETAIL_MIN_PX;
    if (entry.mesh.visible !== visible) entry.mesh.visible = visible;
    for (const overlay of entry.overlays ?? []) {
      if (overlay.visible !== visible) overlay.visible = visible;
    }
    if (visible) drawn.add(entry.modelIndex);
  }

  // In a free view an enclosure gets its fill back once nothing inside it is being drawn, so a
  // plate whose wells have been culled reads as a plate rather than an empty frame. In an axis
  // view everything is opaque and painted in order, so there is nothing to restore.
  if (axisAligned) return;
  for (const entry of meshes) {
    // A carrier is exempt: its walls are the surface you read the layout off, so they stay drawn
    // at SHELL_OPACITY whether or not what it holds is on screen. Everything above it in the
    // stack still drops to its outline, which is what keeps the layers from compounding.
    if (!entry.holdsEnclosure || isCarrier(entry.model)) continue;
    const showsContents = entry.enclosedModels.some((m) => drawn.has(m));
    if (entry.mesh.material.visible === showsContents) entry.mesh.material.visible = !showsContents;
  }
}

// Two ways to draw the same scene.
//
// Looking down an axis, draw it the way the two-dimensional visualizer does: every resource
// opaque, painted in tree order so a child covers its parent. That is what makes a deck legible
// from above, and it is why the old viewer reads at a glance where a stack of translucent shells
// does not. Depth testing is off, so the tree decides what is on top rather than the geometry -
// which is correct here, since a child is always the thing you want to see.
//
// From any other angle that would be wrong: things behind would paint over things in front. So a
// free view goes back to depth testing, with the enclosures translucent so you can see inside.
let axisAligned = null;

function setRenderMode(painter) {
  for (const entry of meshes) {
    const material = entry.mesh.material;
    const isShell = entry.holdsEnclosure;
    const moves = MOVING_PARTS.has(entry.model.category);
    // The facility is the space everything stands in, not a thing to look at. It stays barely
    // there in every mode: enough to see where the floor ends, never enough to tint what is on it.
    const isSpace = entry.model.category === "facility";
    if (painter) {
      // A part that travels over the deck is not content standing on it: drawn opaque it hides
      // whatever it happens to be above, which is the one thing you need to see. It stays
      // see-through, and paints last because that is where it physically is.
      material.transparent = moves || isSpace;
      material.opacity = isSpace ? SPACE_OPACITY : moves ? 0.35 : 1;
      material.side = THREE.FrontSide;
      material.depthTest = false;
      material.depthWrite = false;
      material.visible = !moves;
      entry.mesh.renderOrder = moves ? 500 : entry.depth * 2;
      // What is inside a vessel, and the tip standing in it, paint after its rim.
      for (const overlay of entry.overlays ?? []) {
        if (overlay.userData.flat) overlay.material = overlay.userData.flat;
        overlay.material.depthTest = false;
        overlay.material.depthWrite = false;
        overlay.renderOrder = entry.depth * 2 + 1;
        overlay.material.needsUpdate = true;
      }
    } else {
      material.transparent = isShell || isSpace;
      material.opacity = isSpace ? SPACE_OPACITY : isShell ? SHELL_OPACITY : 1;
      material.side = isShell || isSpace ? THREE.BackSide : THREE.FrontSide;
      material.depthTest = true;
      material.depthWrite = !(isShell || isSpace);
      material.visible = !moves;
      entry.mesh.renderOrder = 0;
      for (const overlay of entry.overlays ?? []) {
        if (overlay.userData.lit) overlay.material = overlay.userData.lit;
        overlay.material.depthTest = true;
        overlay.material.depthWrite = true;
        overlay.renderOrder = 0;
        overlay.material.needsUpdate = true;
      }
    }
    material.needsUpdate = true;
  }

  for (const surface of surfaces) {
    surface.material = painter ? surface.userData.flat : surface.userData.lit;
  }

  for (const mark of gridMarks) {
    mark.traverse((o) => {
      if (o.material && o.material.depthTest !== undefined) o.material.depthTest = !painter;
    });
  }

  for (const arm of arms) {
    arm.outline.material.depthTest = !painter;
    arm.outline.material.linewidth = painter ? ARM_EDGE_WIDTH_FLAT : ARM_EDGE_WIDTH_3D;
    arm.outline.material.needsUpdate = true;
    // The reference line lies under the carriage, so in a 3D view the shafts hanging off it stand
    // in front and have to hide it. Only in an axis view, where nothing is in front of anything,
    // does it paint through regardless.
    arm.line.material.depthTest = !painter;
    arm.line.material.needsUpdate = true;
  }

  for (const [index, line] of edgeOf) {
    line.material.depthTest = !painter;
    line.material.opacity = painter ? 1 : line.userData.baseOpacity;
    line.material.linewidth = painter ? EDGE_WIDTH_FLAT : EDGE_WIDTH_3D;
    line.material.color.set(painter ? FLAT_EDGE : line.userData.baseColor);
    line.renderOrder = painter ? treeDepth(index) * 2 + 1 : 0;
    const wanted = painter ? line.userData.footprintGeometry : line.userData.boxGeometry;
    if (wanted && line.geometry !== wanted) line.geometry = wanted;
    line.material.needsUpdate = true;
  }
}

function updateEdgeMode() {
  const direction = camera.position.clone().sub(controls.target).normalize();
  const aligned =
    Math.abs(direction.x) > 0.999 || Math.abs(direction.y) > 0.999 || Math.abs(direction.z) > 0.999;
  if (aligned === axisAligned) return;
  axisAligned = aligned;
  setRenderMode(aligned);
}

// Held at a constant size on screen, so it marks the origin without swamping a close view or
// vanishing from a wide one.
const ORIGIN_PX = 90;

function updateOrigin() {
  if (!originMarker) return;
  const perPixel = mmPerPixel();
  if (!Number.isFinite(perPixel) || perPixel <= 0) return;
  originMarker.scale.setScalar(perPixel * ORIGIN_PX);
}

// The floor grid follows the view, the way the existing visualizer's does: its spacing is chosen
// from how many millimetres a pixel is worth, and it re-centres on what you are looking at. A grid
// fixed at build time is a grid that means nothing once you zoom.
let grid = null;
let gridState = null;
let floorZ = 0;

// 1, 2 or 5 times a power of ten: the spacings a person can count in.
function niceNumber(value) {
  const magnitude = Math.pow(10, Math.floor(Math.log10(Math.max(value, 1e-6))));
  return ([1, 2, 5, 10].map((m) => m * magnitude).find((v) => v >= value) ?? magnitude * 10);
}

function mmPerPixel() {
  const height = viewportEl.clientHeight || 1;
  if (projection === "orthographic") {
    return (camera.top - camera.bottom) / camera.zoom / height;
  }
  const distance = camera.position.distanceTo(controls.target);
  return (2 * distance * Math.tan((camera.fov * DEG) / 2)) / height;
}

// Aim for a cell around this many pixels: dense enough to measure against, open enough to see past.
const GRID_TARGET_PX = 64;
const GRID_MAX_DIVISIONS = 320;

function updateGrid() {
  const perPixel = mmPerPixel();
  if (!Number.isFinite(perPixel) || perPixel <= 0) return;

  const span = perPixel * Math.hypot(viewportEl.clientWidth, viewportEl.clientHeight) * 1.3;
  // Coarsen the spacing rather than shrink the coverage: a grid that stops inside the viewport
  // reads as a hole in the floor, whereas a larger cell just reads as a larger cell.
  const cell = Math.max(niceNumber(perPixel * GRID_TARGET_PX), niceNumber(span / GRID_MAX_DIVISIONS));
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

  if (grid) {
    view.remove(grid);
    grid.geometry.dispose();
    grid.material.dispose();
  }
  grid = new THREE.GridHelper(divisions * cell, divisions, 0xc8ced2, 0xe4e8ea);
  grid.rotation.x = Math.PI / 2; // GridHelper lies in XZ; stand it up into PLR's XY
  grid.position.set(cx, cy, floorZ);
  grid.renderOrder = -1;
  view.add(grid);
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
  helper.renderOrder = 950;
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
const CONE = new THREE.ConeGeometry(0.5, 1, 14).rotateX(-Math.PI / 2);

// Above this many instances of one model, outlining each stops being cheap.
const EDGE_LIMIT = 160;

// ---------------------------------------------------------------- scene build



// A resource says what shape it is through `cross_section_type`. A tip spot does not serialize
// one, though it is plainly round, so it is special-cased here; upstream it should declare the
// field the way a well does, and this line can go.
// The same material, unlit. Colours land exactly as specified rather than being darkened by the
// lighting, and per-instance colour still works because basic materials multiply it into the fill.
function flatVariant(material) {
  const flat = new THREE.MeshBasicMaterial({ color: material.color.clone() });
  flat.transparent = material.transparent;
  flat.opacity = material.opacity;
  flat.side = material.side;
  flat.visible = material.visible;
  return flat;
}

const geometryFor = (model) =>
  model.cross_section_type === "circle" || model.category === "tip_spot" ? CYL : BOX;
const colorFor = (model) => RESOURCE_COLORS[model.category] ?? RESOURCE_COLORS.default;
// "TipRack" -> "tipracks", as the existing visualizer writes them. Deliberately naive: a count is
// always in front of it, so "1 plates" reads as a count rather than as a mistake.
const plural = (type) => String(type).toLowerCase() + "s";

// The plural naming these resources, or "" if they are not all of one kind and so cannot be
// counted as one thing.
function countable(indices) {
  const types = new Set(indices.map((i) => modelOf(i).type));
  return types.size === 1 ? plural(modelOf(indices[0]).type) : "";
}
const hexOf = (n) => "#" + n.toString(16).padStart(6, "0");

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
    entry.mesh.dispose();
  }
  for (const line of edgeOf.values()) view.remove(line);
  edgeMaterials.clear();
  axisAligned = null;
  detailScale = null;
  meshes = [];
  placementOf = new Array(world.names.length);
  vesselOf = new Map();
  tipOf = new Map();
  edgeOf = new Map();

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

    if (MOVING_PARTS.has(model.category)) material.visible = false;

    const mesh = new THREE.InstancedMesh(geometryFor(model), material, instances.length);
    mesh.frustumCulled = false;
    instances.forEach((globalIndex, slot) => {
      placeInstance(mesh, slot, world.matrices[globalIndex], sx, sy, sz);
      placementOf[globalIndex] = { mesh, slot };
    });
    mesh.instanceMatrix.needsUpdate = true;
    mesh.userData.instances = instances;
    view.add(mesh);
    meshes.push({
      mesh, model, modelIndex, instances,
      depth: treeDepth(instances[0]),
      lit: material,
      flat: flatVariant(material),
      // Filled in below, once the overlays this model needs are known.
      overlays: /** @type {any[]} */ ([]),
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
      // Looking down an axis, all twelve edges of a box project onto its footprint anyway, and the
      // verticals collapse to points. Keeping a footprint-only geometry to swap in removes that
      // redundancy and, more usefully, stops stacked boxes reading as a thicket in a plan view.
      const footprintGeometry = new LineSegmentsGeometry();
      footprintGeometry.setPositions(
        new Float32Array([
            -0.5, -0.5, -0.5, 0.5, -0.5, -0.5,
            0.5, -0.5, -0.5, 0.5, 0.5, -0.5,
            0.5, 0.5, -0.5, -0.5, 0.5, -0.5,
            -0.5, 0.5, -0.5, -0.5, -0.5, -0.5,
        ])
      );
      const style = structureEdgeStyle(enclosureDepth(instances[0]));
      const edgeMaterial = new THREE.Line2NodeMaterial({
        color: style.color,
        transparent: true,
        opacity: style.opacity,
        linewidth: EDGE_WIDTH_3D,
        worldUnits: false,
      });
      edgeMaterial.resolution?.set(viewportEl.clientWidth || 1, viewportEl.clientHeight || 1);
      edgeMaterials.add(edgeMaterial);
      for (const globalIndex of instances) {
        const line = new LineSegments2(edgeGeometry, edgeMaterial);
        line.userData.boxGeometry = edgeGeometry;
        line.userData.baseOpacity = style.opacity;
        line.userData.baseColor = style.color.clone();
        line.userData.footprintGeometry = footprintGeometry;
        line.matrixAutoUpdate = false;
        line.matrix.copy(boxMatrix(world.matrices[globalIndex], sx, sy, sz));
        line.frustumCulled = false;
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
        instances.length
      );
      floor.frustumCulled = false;
      instances.forEach((globalIndex, slot) => {
        // A hair above its own base, or it fights the deck surface it stands on for depth.
        placeInstance(floor, slot, world.matrices[globalIndex], sx, sy, 1, sx / 2, sy / 2, 0.3);
      });
      floor.instanceMatrix.needsUpdate = true;
      floor.userData.lit = floor.material;
      floor.userData.flat = flatVariant(floor.material);
      view.add(floor);
      overlays.push(floor);
    }

    if (isVessel) {
      const inner = new THREE.InstancedMesh(
        geometryFor(model),
        new THREE.MeshStandardMaterial({ color: 0xffffff, roughness: 0.55 }),
        instances.length
      );
      inner.frustumCulled = false;
      const white = new THREE.Color(VESSEL_EMPTY);
      instances.forEach((globalIndex, slot) => {
        // Inset, and a hair taller, so from above the rim reads as a ring around it.
        placeInstance(
          inner, slot, world.matrices[globalIndex],
          sx * VESSEL_INSET, sy * VESSEL_INSET, sz * 1.02,
          sx / 2, sy / 2, (sz * 1.02) / 2
        );
        inner.setColorAt(slot, white);
        vesselOf.set(globalIndex, { mesh: inner, slot, model });
      });
      inner.instanceMatrix.needsUpdate = true;
      inner.instanceColor.needsUpdate = true;
      inner.userData.flat = flatVariant(inner.material);
      inner.userData.lit = inner.material;
      view.add(inner);
      overlays.push(inner);
    }
    // Only tip spots get an overlay. What a container holds is shown by colouring its inner body
    // through `vesselOf`, not by a mesh of its own.
    if (model.category === "tip_spot") overlays.push(buildOverlay(instances, model));
    const entry = meshes[meshes.length - 1];
    entry.overlays = overlays;
    entry.holdsEnclosure = holdsEnclosure;
    entry.enclosedModels = [...enclosedModels];
  }
}

function buildOverlay(instances, model) {
  const mesh = new THREE.InstancedMesh(
    CONE,
    new THREE.MeshStandardMaterial({ color: TIP, roughness: 0.55 }),
    instances.length
  );
  mesh.frustumCulled = false;
  for (let slot = 0; slot < instances.length; slot++) mesh.setMatrixAt(slot, ZERO);
  mesh.instanceMatrix.needsUpdate = true;
  mesh.userData.flat = flatVariant(mesh.material);
  mesh.userData.lit = mesh.material;
  view.add(mesh);
  instances.forEach((globalIndex, slot) => tipOf.set(globalIndex, { mesh, slot, model }));
  return mesh;
}

// ---------------------------------------------------------------- workcells

// A workcell is a grouping, not a place: no transform passes through it, so it has no box of its
// own. What it occupies is whatever its members occupy, derived here and redrawn whenever the
// scene changes.
function memberIndices(workcell) {
  return workcell.members.map((name) => world.indexOfName.get(name)).filter((i) => i !== undefined);
}

function workcellExtent(workcell) {
  const box = new THREE.Box3();
  for (const index of memberIndices(workcell)) {
    const walk = (i) => {
      box.union(worldBox(i));
      for (const child of world.childrenOf[i]) walk(child);
    };
    walk(index);
  }
  return box;
}

function buildWorkcellBoxes() {
  for (const helper of workcellBoxes.values()) view.remove(helper);
  workcellBoxes = new Map();
  for (const workcell of workcells) {
    const box = workcellExtent(workcell);
    if (box.isEmpty()) continue;
    const helper = new THREE.Box3Helper(box, new THREE.Color(WORKCELL_OUTLINE));
    helper.material.transparent = true;
    helper.material.opacity = 0.35;
    helper.material.depthTest = false;
    helper.renderOrder = 940;
    helper.visible = false; // shown on hover or selection, so it never clutters the view
    view.add(helper);
    workcellBoxes.set(workcell.name, helper);
  }
}

function showWorkcellBox(name) {
  for (const [key, helper] of workcellBoxes) helper.visible = key === name;
}

function clearWorkcellBoxes() {
  for (const helper of workcellBoxes.values()) helper.visible = false;
}

function workcellOf(index) {
  for (let i = index; i >= 0; i = world.parentOf[i]) {
    const name = world.names[i];
    const hit = workcells.find((w) => w.members.includes(name));
    if (hit) return hit;
  }
  return null;
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
  for (const [name, slot] of Object.entries(of ?? {})) {
    const index = world.indexOfName.get(name);
    if (index === undefined) continue;
    // Shared between every resource in the same state, and only ever read.
    stateOf.set(index, states[slot]);
    if (states[slot]?.location) applyLocation(index, states[slot].location);
    refreshOverlays(index, touched);
    applyJoints(index);
  }
  for (const mesh of touched) mesh.instanceMatrix.needsUpdate = true;
  if (selected >= 0 && infoPanel?.isConnected) renderInfoPanel();
  refreshTreeInfo();
}

function refreshOverlays(index, touched) {
  const state = stateOf.get(index);
  const visible = isVisible(index);

  if (MOVING_PARTS.has(modelOf(index).category)) {
    const tracked = state?.tracker?.x;
    if (tracked !== undefined && tracked !== null) setArmX(index, tracked);
  }

  const vessel = vesselOf.get(index);
  if (vessel && vessel.model.category === "tip_spot") {
    // Green when a tip is fitted, white when not, as the existing visualizer does. `pending_tip`
    // is the live intent, so a pickup shows the moment it is requested.
    const fitted = state ? !!state.pending_tip : false;
    vessel.mesh.setColorAt(vessel.slot, new THREE.Color(fitted ? TIP : VESSEL_EMPTY));
    if (vessel.mesh.instanceColor) vessel.mesh.instanceColor.needsUpdate = true;
  } else if (vessel && Number.isFinite(vessel.model.max_volume)) {
    const volume = state ? state.pending_volume ?? state.volume ?? 0 : 0;
    const fraction = Math.max(0, Math.min(1, volume / (vessel.model.max_volume || 1)));
    // Empty is white; any liquid at all steps clear of white so a nearly empty well still reads.
    const t = fraction > 0 ? 0.35 + 0.65 * fraction : 0;
    vessel.mesh.setColorAt(
      vessel.slot,
      new THREE.Color(VESSEL_EMPTY).lerp(new THREE.Color(LIQUID), t)
    );
    if (vessel.mesh.instanceColor) vessel.mesh.instanceColor.needsUpdate = true;
  }

  const tip = tipOf.get(index);
  if (tip) {
    const [sx, sy, sz] = sizeOf(tip.model);
    // `pending_tip` is the live intent; `tip` is what has been committed. The viewer follows
    // intent, so a pickup shows the moment it is requested.
    const mounted = state ? state.pending_tip ?? null : null;
    if (!mounted || !visible) tip.mesh.setMatrixAt(tip.slot, ZERO);
    else {
      const length = mounted.total_tip_length || sz;
      placeInstance(tip.mesh, tip.slot, world.matrices[index],
        sx * 0.62, sy * 0.62, length, sx / 2, sy / 2, length / 2);
    }
    touched.add(tip.mesh);
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
  for (const mesh of touched) mesh.instanceMatrix.needsUpdate = true;
  refreshTreeVisibility();
}

// ---------------------------------------------------------------- reference points

// PLR's own reference semantics: a resource's origin is its left, front, bottom corner.
function referencePoint(index, xRef, yRef, zRef) {
  const [sx, sy, sz] = sizeOf(modelOf(index));
  const x = xRef === "center" ? sx / 2 : xRef === "right" ? sx : 0;
  const y = yRef === "center" ? sy / 2 : yRef === "back" ? sy : 0;
  const z = zRef === "center" ? sz / 2 : zRef === "top" ? sz : 0;
  return new THREE.Vector3(x, y, z).applyMatrix4(world.matrices[index]);
}

function worldBox(index) {
  const [sx, sy, sz] = sizeOf(modelOf(index));
  const box = new THREE.Box3();
  const corner = new THREE.Vector3();
  for (const c of [
    [0, 0, 0], [sx, 0, 0], [0, sy, 0], [0, 0, sz],
    [sx, sy, 0], [sx, 0, sz], [0, sy, sz], [sx, sy, sz],
  ]) {
    corner.set(c[0], c[1], c[2]).applyMatrix4(world.matrices[index]);
    box.expandByPoint(corner);
  }
  return box;
}

// ---------------------------------------------------------------- workcell tree

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
  const prefix = world.names[parent] + "_";
  return name.startsWith(prefix) ? name.slice(prefix.length) : name;
}

// What the tree says about a resource beyond its name and type: a carrier counts what it holds by
// kind, a rack how many of its spots are taken, a plate its well count, a container its volume, and
// a site with nothing in it says so. The existing visualizer's tree answers the same questions.
function summaryOf(index) {
  const children = world.childrenOf[index];

  if (!children.length) {
    const state = stateOf.get(index);
    if (state && state.pending_volume !== undefined) return `${fmt(state.pending_volume)} uL`;
    if (state && "pending_tip" in state) return state.pending_tip ? "tip" : "";
    // A vacant site is labelled `<empty>` in place of its name, so a summary would repeat it.
    return "";
  }

  // An occupied holder needs no summary: the row directly beneath it says what is standing there.
  if (HOLDERS.has(modelOf(index).category)) return "";

  const kind = modelOf(children[0]).category;

  if (kind === "tip_spot") {
    const filled = children.filter((c) => !!stateOf.get(c)?.pending_tip).length;
    return `${filled}/${children.length} tips`;
  }
  if (kind === "well") return `${children.length} wells`;

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

function buildTree() {
  treeEl.textContent = "";
  rowOf.clear();
  expanded.clear();
  for (let i = 0; i < world.names.length; i++) if (world.parentOf[i] < 0) addRow(i, 0, null);
  showToDepth(Number(depthInput.value) || 1);
}

function addRow(index, depth, before) {
  const model = modelOf(index);
  const children = world.childrenOf[index];

  const row = document.createElement("div");
  row.className = "tree-node-row";
  row.style.paddingLeft = `${8 + depth * 16}px`;
  row.dataset.index = index;

  const arrow = document.createElement("span");
  arrow.className = "tree-node-arrow" + (children.length ? " has-children" : "");
  arrow.textContent = children.length ? "▶" : "";
  row.appendChild(arrow);

  const dot = document.createElement("span");
  dot.className = "tree-node-dot";
  dot.style.backgroundColor = hexOf(colorFor(model));
  row.appendChild(dot);

  // A holder is a numbered position on its carrier, so it is labelled by that number rather than by
  // a name nobody chose. Its ordinal among its parent's children is the site number.
  const holder = HOLDERS.has(model.category);
  if (holder) {
    const siblings = world.childrenOf[world.parentOf[index]] ?? [];
    const site = document.createElement("span");
    site.className = "tree-node-site";
    site.textContent = String(siblings.indexOf(index));
    row.appendChild(site);
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

  // Membership is shown as a tag on the member itself, not as a parent node. A workcell is a
  // grouping, so putting it in a tree of places would say the wrong thing about it.
  const ownGroup = workcells.find((w) => w.members.includes(world.names[index]));
  if (ownGroup) {
    const tag = document.createElement("span");
    tag.className = "tree-workcell-tag";
    tag.textContent = ownGroup.name;
    tag.title = `workcell ${ownGroup.name}: ${ownGroup.members.length} members`;
    tag.addEventListener("mouseenter", (e) => {
      e.stopPropagation();
      showWorkcellBox(ownGroup.name);
    });
    tag.addEventListener("mouseleave", clearWorkcellBoxes);
    row.appendChild(tag);
  }

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
    setHidden(world.names[index], !hiddenNames.has(world.names[index]));
  });
  row.appendChild(eye);

  row.addEventListener("mouseenter", () => showHoverBox(index));
  row.addEventListener("mouseleave", () => (hoverBox.visible = false));
  // Same gesture as the viewport: click selects, double click inspects. The existing visualizer
  // opens the panel on a single click here, which made the tree and the scene behave differently
  // for the same intent.
  row.addEventListener("click", (e) => {
    if (e.offsetX < 20 && children.length) toggle(index, !expanded.has(index));
    else select(index, false);
  });
  row.addEventListener("dblclick", (e) => {
    if (e.offsetX < 20 && children.length) return;
    select(index, true);
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
  if (!entry || !world.childrenOf[index].length || open === expanded.has(index)) return;

  if (open) {
    expanded.add(index);
    entry.arrow.textContent = "▼";
    const before = entry.row.nextSibling;
    for (const child of world.childrenOf[index]) addRow(child, entry.depth + 1, before);
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

function showToDepth(maxDepth) {
  const walk = (index, depth) => {
    if (depth < maxDepth) {
      toggle(index, true);
      for (const child of world.childrenOf[index]) walk(child, depth + 1);
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
    for (const child of world.childrenOf[index]) walk(child);
  };
  for (let i = 0; i < world.names.length; i++) if (world.parentOf[i] < 0) walk(i);
}

function applyRowVisibility(index) {
  const entry = rowOf.get(index);
  if (!entry) return;
  const own = hiddenNames.has(world.names[index]);
  entry.row.classList.toggle("resource-hidden", !isVisible(index));
  entry.eye.innerHTML = eyeSvg(own);
  entry.eye.classList.toggle("is-hidden", own);
}

function refreshTreeVisibility() {
  for (const [index] of rowOf) applyRowVisibility(index);
}

function refreshTreeInfo() {
  for (const [index, entry] of rowOf) entry.info.textContent = summaryOf(index);
}

function revealAndHighlight(index) {
  const chain = [];
  for (let i = world.parentOf[index]; i >= 0; i = world.parentOf[i]) chain.unshift(i);
  for (const ancestor of chain) toggle(ancestor, true);
  for (const [, entry] of rowOf) entry.row.classList.remove("selected");
  const entry = rowOf.get(index);
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
  clearWorkcellBoxes();
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
  "type", "category", "methods", "model",
  "size_x", "size_y", "size_z",
  "max_volume", "volume", "pending_volume",
  "height_volume_data", "ordering",
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
  const group = workcellOf(index);

  const identity = [["name", escapeHtml(world.names[index])], ["type", escapeHtml(model.type)]];
  if (model.model) identity.push(["model", escapeHtml(String(model.model))]);
  identity.push(["category", escapeHtml(model.category ?? "uncategorised")]);
  identity.push(["workcell", group ? escapeHtml(group.name) : "none"]);

  const placement = [
    ["location", `<span data-live="location">${tuple(xf[o], xf[o + 1], xf[o + 2], "mm")}</span>`],
    ["world", `<span data-live="world">${tuple(m[12], m[13], m[14], "mm")}</span>`],
  ];
  if (xf[o + 3] || xf[o + 4] || xf[o + 5]) {
    placement.push(["rotation", tuple(xf[o + 3], xf[o + 4], xf[o + 5], "deg")]);
  }
  placement.push(["parent", world.parentOf[index] >= 0 ? escapeHtml(world.names[world.parentOf[index]]) : "none"]);
  placement.push(["children", String(world.childrenOf[index].length)]);

  const [sx, sy, sz] = sizeOf(model);
  const geometry = [["size", `${fmt(sx)}${NBSP}&#215;${NBSP}${fmt(sy)}${NBSP}&#215;${NBSP}${fmt(sz)}${NBSP}mm`]];
  if (model.ordering) geometry.push(["items", String(Object.keys(model.ordering).length)]);

  const contents = [];
  if (model.max_volume !== undefined) {
    const volume = state ? state.pending_volume ?? state.volume ?? 0 : 0;
    contents.push(["volume", `${fmt(volume)}${NBSP}/${NBSP}${fmt(model.max_volume)}${NBSP}uL`]);
  }
  if (state && "pending_tip" in state) {
    contents.push(["tip", state.pending_tip ? "fitted" : "none"]);
    if (state.pending_tip) {
      for (const key of ["total_tip_length", "nominal_volume", "has_filter"]) {
        if (state.pending_tip[key] !== undefined) contents.push([key, withUnit(key, state.pending_tip[key])]);
      }
    }
  }

  const specifics = [];
  const construction = [];
  for (const [key, value] of Object.entries(model)) {
    if (HANDLED.has(key)) continue;
    (isConstruction(key) ? construction : specifics).push([key, withUnit(key, value)]);
  }

  const tracker = state
    ? Object.entries(state)
        .filter(([k]) => !["rotation", "pending_volume", "volume", "tip", "pending_tip", "tip_state"].includes(k))
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
    (methods
      ? `<div class="uml-separator"></div><div class="uml-section">` +
        `<div class="uml-section-title">Methods <span class="uml-count">${model.methods.length}</span></div>` +
        `<div class="uml-methods">${methods}</div></div>`
      : "");

  panel.querySelector(".uml-close-btn").addEventListener("click", closeInfoPanel);
}

// Selecting and inspecting are separate, as they are in the existing visualizer: a click in the
// viewport selects, a double click opens the panel, and a click in the tree does both. An already
// open panel follows the selection rather than being left showing something else.
function select(index, openPanel = true) {
  selected = index;
  selectionBox.box.copy(worldBox(index));
  selectionBox.visible = true;
  const group = workcellOf(index);
  if (group) showWorkcellBox(group.name);
  else clearWorkcellBoxes();
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
  markTreeRow(null);
}

// ---------------------------------------------------------------- machine tools

function buildMachineTools(devices) {
  const host = document.getElementById("navbar-machine-tools");
  if (host.dataset.built === String(devices.length)) return updateMachinePanels(devices);
  host.textContent = "";
  host.dataset.built = String(devices.length);

  devices.forEach((device, i) => {
    const group = document.createElement("div");
    group.className = "navbar-machine-group";

    const label = document.createElement("button");
    label.className = "navbar-machine-label";
    label.textContent = device.device;
    group.appendChild(label);

    const button = document.createElement("button");
    button.className = "navbar-machine-btn";
    button.textContent = `${device.channels.length} ch`;
    button.title = "Channel state";
    group.appendChild(button);

    const panel = document.createElement("div");
    panel.className = "machine-tool-dropdown";
    panel.style.display = "none";
    panel.id = `machine-panel-${i}`;
    group.appendChild(panel);

    const open = () => {
      const showing = panel.style.display !== "none";
      panel.style.display = showing ? "none" : "block";
      button.classList.toggle("active", !showing);
    };
    button.addEventListener("click", open);
    label.addEventListener("click", open);

    host.appendChild(group);
  });
  updateMachinePanels(devices);
}

function updateMachinePanels(devices) {
  devices.forEach((device, i) => {
    const panel = document.getElementById(`machine-panel-${i}`);
    if (!panel) return;
    const readings = [];
    if (device.arm_x) readings.push(["arm x", device.arm_x]);
    if (device.iswap_y) readings.push(["iSWAP y", device.iswap_y]);
    for (const channel of device.channels) {
      readings.push([`ch ${channel.index} x`, channel.x]);
      readings.push([`ch ${channel.index} y`, channel.y]);
      readings.push([`ch ${channel.index} z`, channel.z]);
    }
    panel.innerHTML =
      `<div class="uml-section-title">Readings</div>` +
      readings
        .map(
          ([k, r]) =>
            `<div class="uml-row"><span class="uml-key" title="${r.note}">${k}</span>` +
            `<span class="uml-value">${fmt(r.value)}` +
            `<span class="prov ${r.provenance}">${r.provenance}</span></span></div>`
        )
        .join("") +
      `<div class="uml-separator" style="margin:8px 0"></div>` +
      `<div class="uml-section-title">Not published by v1</div>` +
      device.gaps.map((g) => `<p class="gap-note">&middot; ${g}</p>`).join("");
  });
}

function applyTelemetry(devices) {
  buildMachineTools(devices);

  for (const device of devices) {
    // The arm publishes where it is through the state channel now, so this is a second opinion
    // rather than the only one; it costs nothing and covers a device whose arm has no tracker.
    const deviceIndex = world.indexOfName.get(device.device);
    if (deviceIndex !== undefined && device.arm_x && device.arm_x.value !== null) {
      const armIndex = armIndexOf(deviceIndex);
      if (armIndex !== null) setArmX(armIndex, device.arm_x.value);
    }
  }
}

// The arm resource under a device, if it has one.
function armIndexOf(deviceIndex) {
  let found = null;
  const walk = (index) => {
    if (found !== null) return;
    if (MOVING_PARTS.has(modelOf(index).category)) {
      found = index;
      return;
    }
    for (const child of world.childrenOf[index]) walk(child);
  };
  walk(deviceIndex);
  return found;
}

// A line at the X the machine positions the arm by. Where that sits on the arm is the whole
// difference between a dual-rail arm, positioned by its centre, and a single-rail one, positioned
// by its right edge - so drawing the reported X against the arm shows which it is without the
// viewer needing to know anything about rail types.


// ---------------------------------------------------------------- picking

const raycaster = new THREE.Raycaster();
const pointer = new THREE.Vector2();
const readout = document.getElementById("hover-readout");

function pick(event) {
  const rect = renderer.domElement.getBoundingClientRect();
  pointer.x = ((event.clientX - rect.left) / rect.width) * 2 - 1;
  pointer.y = -((event.clientY - rect.top) / rect.height) * 2 + 1;
  raycaster.setFromCamera(pointer, camera);
  const candidates = meshes.map((m) => m.mesh);
  const hits = raycaster.intersectObjects(candidates, false);
  for (const hit of hits) {
    const instances = hit.object.userData.instances;
    if (instances && hit.instanceId !== undefined) {
      const index = instances[hit.instanceId];
      if (!isVisible(index)) continue;
      // Enclosures are translucent, so clicking through one to its contents is the useful
      // behaviour; take an enclosure only when nothing solid lies behind it.
      if (world.childrenOf[index].length === 0 || hits.length === 1) return { index };
    }
  }
  const first = hits.find((h) => h.object.userData.instances && h.instanceId !== undefined);
  return first ? { index: first.object.userData.instances[first.instanceId] } : null;
}

const coords = initCoords({ getWorld: () => world, referencePoint, escapeHtml });
const { coordinateLabel, recordMeasurement, populateWrtDropdown } = coords;

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
    kind === "orthographic" ? "Orthographic: switch to perspective" : "Perspective: switch to orthographic";
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
      i & 4 ? box.max.z : box.min.z
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
  controls.update();
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
    ])
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
  detail: () =>
    meshes.map((e) => ({
      type: e.model.type,
      mm: Math.max(e.model.size_x ?? 0, e.model.size_y ?? 0),
      drawn: e.mesh.visible,
      filled: e.mesh.material.visible,
      outlineRule: !!e.holdsEnclosure,
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
      out.at = gridLabels[0].getWorldPosition(new THREE.Vector3()).toArray().map((v) => +v.toFixed(1));
    }
    return out;
  },
  hover: () => ({
    visible: hoverBox.visible,
    empty: hoverBox.box.isEmpty(),
    min: hoverBox.box.min.toArray().map((v) => +v.toFixed(1)),
    max: hoverBox.box.max.toArray().map((v) => +v.toFixed(1)),
  }),
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
function updateScaleBar() {
  const perPixel = mmPerPixel();
  if (!Number.isFinite(perPixel) || perPixel <= 0) return;
  const nice = niceNumber(perPixel * 120);
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
  drawStats(String(fps) + " fps");
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
    `<b>${rate}</b>\n` +
    `tree JSON ${((stats.legacy_bytes ?? 0) / 1024).toFixed(1)} kB  ` +
    `→ this scene <b>${((stats.scene_bytes ?? 0) / 1024).toFixed(1)} kB</b> (${stats.ratio ?? 0}×)`;
  // Writing the same markup back forces layout and paint for nothing, twice a second, forever.
  if (text !== statsEl.innerHTML) statsEl.innerHTML = text;
}

// ---------------------------------------------------------------- interaction

renderer.domElement.addEventListener("pointermove", (event) => {
  if (!world) return;
  const hit = pick(event);
  if (!hit) {
    readout.style.display = "none";
    clearHover();
    return;
  }
  readout.style.display = "block";
  const rect = viewportEl.getBoundingClientRect();
  readout.style.left = `${event.clientX - rect.left + 14}px`;
  readout.style.top = `${event.clientY - rect.top + 14}px`;
  if (hit.channel) {
    clearHover();
    const c = hit.channel.channel;
    readout.textContent = `${hit.channel.device} channel ${c.index}\nx ${fmt(c.x.value)} (${c.x.provenance})\ny ${fmt(c.y.value)} (${c.y.provenance})\nz ${fmt(c.z.value)} (${c.z.provenance})`;
    return;
  }
  showHoverBox(hit.index);
  markTreeRow(hit.index);
  readout.textContent =
    activeTool === "coords" ? coordinateLabel(hit.index) : `${world.names[hit.index]}\n${modelOf(hit.index).type}`;
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
  openPanel = tool === "coords" ? "coords" : openPanel === "coords" ? null : openPanel;
  refreshToolUI();
}

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
  setProjection(projection === "orthographic" ? "perspective" : "orthographic")
);
document.getElementById("home-button").addEventListener("click", goToStartView);
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
document.getElementById("collapse-all-btn").addEventListener("click", () =>
  showToDepth(Number(depthInput.value) || 0)
);
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

treeButton.addEventListener("click", () => showPane("tree"));
searchButton.addEventListener("click", () => showPane("search"));

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
  const hits = [];
  for (let i = 0; i < world.names.length && hits.length < 300; i++) {
    const category = modelOf(i).category;
    if (category === "well" && !includeWells) continue;
    if (category === "tip_spot" && !includeTips) continue;
    if ((category === "resource_holder" || category === "plate_holder") && !includeSites) continue;
    if (world.names[i].toLowerCase().includes(query)) hits.push(i);
  }
  if (!hits.length) {
    searchResults.innerHTML = '<div class="search-empty">No resource matches.</div>';
    return;
  }
  for (const index of hits) {
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
  const width = Math.max(150, Math.min(window.innerWidth * 0.6, resizingFrom.width - (e.clientX - resizingFrom.x)));
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

function showStatus(connected) {
  for (const el of [statusDot, statusLabel]) {
    el.classList.toggle("connected", connected);
    el.classList.toggle("disconnected", !connected);
  }
  statusLabel.textContent = connected ? "Connected" : "Disconnected";
}

document.addEventListener("visibilitychange", () => {
  if (document.visibilityState !== "visible") return;
  const live = socket && socket.readyState === WebSocket.OPEN;
  showStatus(!!live);
  if (!live) connect();
});

function connect() {
  if (socket && (socket.readyState === WebSocket.OPEN || socket.readyState === WebSocket.CONNECTING)) {
    return;
  }
  socket = new WebSocket(`ws://${location.hostname}:${window.WS_PORT}`);
  socket.onopen = () => showStatus(true);
  socket.onclose = () => {
    showStatus(false);
    setTimeout(connect, 1500);
  };
  socket.onmessage = (event) => {
    const { event: kind, data } = JSON.parse(event.data);
    // Anything the server says is assumed to change what is on screen. Saying otherwise is a
    // deliberate, listed exception, so a message kind added later errs towards a wasted redraw
    // rather than towards not drawing at all.
    if (!DOM_ONLY_MESSAGES.has(kind)) invalidate();
    if (kind === "scene") {
      const _tScene = performance.now();
      stats = data.stats ?? {};
      workcells = data.workcells ?? [];
      setWorld(buildWorld(data));
      timings.decodeMs = performance.now() - _tScene;
      const _tBuild = performance.now();
      buildMeshes();
      buildWorkcellBoxes();
      floorZ = sceneBounds().min.z;
      gridState = null;
      buildGridMarks();
      buildArms();
      buildDeclaredMeshes();
      buildOrigin();
      timings.meshesMs = performance.now() - _tBuild;
      const _tTree = performance.now();
      buildTree();
      timings.treeMs = performance.now() - _tTree;
      timings.readyMs = performance.now() - _t0;
      populateWrtDropdown();
      selected = -1;
      selectionBox.visible = false;
      hideInfoPanel();
      stateOf.clear();
      resize();
      goToStartView();
    } else if (kind === "state" && world) {
      applyState(data);
    } else if (kind === "telemetry" && world) {
      applyTelemetry(data);
    }
  };
}

statusDot.addEventListener("click", connect);

const gif = initGif({ renderer, view, camera });

// ---------------------------------------------------------------- loop

// Messages that only ever touch the panels around the viewport, never the scene in it.
const DOM_ONLY_MESSAGES = new Set(["telemetry"]);

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
  for (const material of edgeMaterials) material.resolution?.set(w, Math.max(h, 1));
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
for (const kind of ["pointerdown", "pointermove", "pointerup", "wheel", "keydown", "click"]) {
  document.addEventListener(kind, invalidate, { passive: true, capture: true });
}
setInterval(reportIdle, 500);

function drawFrame() {
  const delta = clock.getDelta();

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
  if (updateArms(delta)) moving = true;
  if (controls.update()) moving = true;
  if (gif.isRecording()) moving = true;

  if (!renderPending && !moving) {
    looping = false;
    renderer.setAnimationLoop(null);
    return;
  }
  renderPending = false;
  lastRenderAt = performance.now();

  renderer.render(view, camera);
  if (viewHelper) {
    // The helper renders a second pass into a corner of the same canvas. Without turning auto-clear
    // off it clears the colour buffer for that corner first, leaving a blank patch over the scene.
    renderer.autoClear = false;
    viewHelper.render(renderer);
    renderer.autoClear = true;
  }
  gif.tick();
  updateGrid();
  updateDetail();
  updateEdgeMode();
  updateOrigin();
  updateScaleBar();
  updateStats();
}

buildViewHelper();
refreshToolUI();
showPane("tree");
resize();
connect();
