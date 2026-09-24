// Every resource as a box: one instanced mesh per model, with the outlines, the vessel cavities,
// the filter and plan discs that ride on it.

import * as THREE from "three";
import { LineSegments2 } from "three/addons/lines/LineSegments2.js";
import { LineSegmentsGeometry } from "three/addons/lines/LineSegmentsGeometry.js";

import {
  EDGE_WIDTH_3D,
  FILTER,
  FILTER_BELOW_COLLAR,
  FILTER_WIDTH_UNMEASURED,
  MOVING_PARTS,
  RESOURCE_COLORS,
  structureEdgeStyle,
  TIP_PLAN_FILL,
  VESSEL_EMPTY,
  VESSEL_RIM,
  VESSEL_WALL,
  VESSEL_WALL_OPACITY,
} from "./constants.js";
import {
  boxMatrix,
  clearDrawn,
  collectEnclosedModels,
  disposeOwned,
  edgeOf,
  enclosureDepth,
  filterDiscsOf,
  hasEnclosedDescendant,
  isCarrier,
  meshes,
  own,
  placeInstance,
  placementOf,
  placeParts,
  remember,
  vesselOf,
  ZERO,
} from "./drawn.js";
import { view } from "./renderer.js";
import { sizeOf, treeDepth, world } from "./world.js";

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

export const colorFor = (model) =>
  model.appearance?.color ?? RESOURCE_COLORS[model.category] ?? RESOURCE_COLORS.default;

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

export function buildMeshes() {
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
  clearDrawn();

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
 * Size a model's filter discs to the bore its own file has at their height, once the file is here.
 * The file is in the tip's frame, so the plane the disc lies in cuts the tip's inner wall at the
 * nearest distance from the axis.
 */
export function fitFilterDiscs(modelIndex, scene, scale, up) {
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
