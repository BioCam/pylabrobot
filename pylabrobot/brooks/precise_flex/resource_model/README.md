# The PreciseFlex resource model

What the arm is made of, as resources: the plate it stands on, the column it rides, the carriage
the Z drive moves up that column, the two links, and the gripper. The model mirrors the machine:
every position in it comes from what the controller reports. The driver consults it before a
joint move, and refuses one that would carry the gripper against the column.

## The frame

A resource is a cuboid located by its left front bottom corner, and sizes are in mm. Each part is
built in its own frame, so a part can be placed, drawn or measured without knowing what carries it.

The controller reports from somewhere else: the shoulder axis, at the plane the tool flange lies in
when the Z drive is at 0, its lowest point. The manufacturer calls this the World origin.
`SHOULDER_AXIS` records where that point sits within the base plate, and
`Z_CARRIAGE_REFERENCE_POINT` where it sits within the carriage. A reading is turned into a location
by taking the reference point out of it, which is what `z_carriage_location` does. Nothing else in
the model is allowed to guess a position.

## The workspace

An arm has no deck. What stands in a deck's place is its `Workspace`: the region its tool point can
reach about the shoulder axis, over the Z travel. It is a resource like any other, located by its
corner, and the point the controller reports from is its `reference_point`.

The region is stated by its `boundary`: how far the tool point reaches at each bearing, which
`kinematics.compute_workspace_boundary` sweeps from the shoulder's and the elbow's ranges. It is
not a ring: the arm reaches further ahead than behind. Its cuboid is only the boundary's bounding
box; `is_reachable` asks the boundary. The boundary does not know the column stands behind the
shoulder.

## The parts

| Resource | Category | Model | What it is |
|---|---|---|---|
| `base_plate` | `base_plate` | `brooks_pf400_base_plate` | The plate the machine bolts to |
| `z_column` | `z_column` | `brooks_pf400_z_column` | The column the carriage rides, as tall as the travel makes it |
| `z_carriage` | `z_carriage` | `brooks_pf400_z_carriage` | What the Z drive moves: the housing the arm turns in |
| `link_1` | `link_body` | `brooks_pf400_link_1` | Shoulder joint to elbow joint |
| `link_2` | `link_body` | `brooks_pf400_link_2` | Elbow joint to wrist joint, turning underneath link 1 |
| `gripper` | `mechanical_gripper` | `brooks_pf400_gripper` | Wrist joint to the point the fingers grip at |
| its two jaws | `jaw` | `brooks_pf400_gripper_jaw_left`, `_right` | What the gripper's drive moves |
| its two fingers | `finger` | `brooks_pf400_gripper_finger_left`, `_right` | Bolted one to each jaw, and changed without it |
| `linear_rail` | `linear_rail` | `brooks_pf400_linear_rail_1m`, `_1_5m`, `_2m` | The optional rail, as long as its travel |
| `linear_rail_carriage` | `linear_rail_carriage` | `brooks_pf400_linear_rail_carriage_0deg`, `_90deg` | What rides the rail, and the arm stands on |

`PreciseFlex400` in `device.py` builds only the plate and an empty workspace. The driver builds the
rest from a configuration: the one declared from a file, at once, or else the one the controller
answers at setup. So the column is as tall as the configuration's Z travel makes it, the links as
long as it says, and the workspace reaches as far as its limits allow.

## Meshes

A part is drawn as its own box until a mesh is named after it. A file called `<model>.glb`, shipped
anywhere under the package, is found by the viewer and drawn instead - nothing in the code holds a
path. The file is authored in the part's own frame, in metres, Z up.

The cuboids are therefore the specification for how a model of the whole machine is split: one file
per part, each cut at that part's own corner, so a file can be dropped in without an offset and
without anything else changing.

The chassis, link and gripper files are split from a model of the standard-reach arm, each placed
by the shoulder axis and its joints. The links are lengthened to the extended reach by moving the
far half of each out.

A link is as long as the controller reports between its joints, plus the hub past each joint, so
one factory serves both reaches. The driver hangs the carriage, the links and the gripper at
setup, each by its joint, and every joint read stands and turns them to what was read.

The gripper is its body, two jaws and two fingers. The two sides are mirror images, so a jaw and a
finger each have a left and a right mesh. Left is the gripper's +y side.

## Outlines

A cuboid says more than a rounded part covers. The column and the gripper's body each have an
outline as well, a constant beside its sizes: the part seen from above, as the points round it in
its own frame. It is the convex outline of everything the mesh covers, so it never says less than
the part. A finger is a bar, and its cuboid is its outline.

## Not built yet

The rail and its carriage exist as parts, with their meshes, and nothing builds them: an arm on a
rail is still modelled as standing still. What is missing is known only from an arm on a rail:
where on the rail its carriage stands when the drive reports 0, and where on the carriage the
arm's plate is bolted.
