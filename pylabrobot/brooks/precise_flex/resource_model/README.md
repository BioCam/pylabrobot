# The PreciseFlex resource model

What the arm is made of, as resources: the plate it stands on, the column it rides, and the
carriage the Z drive moves up that column. The model mirrors the machine and never decides for it,
so every position in it comes from what the controller reports.

## The frame

A resource is a cuboid located by its left front bottom corner, and sizes are in mm. Each part is
built in its own frame, so a part can be placed, drawn or measured without knowing what carries it.

The controller reports from somewhere else: the shoulder axis, at the plane the tool flange lies in
when the Z drive is homed. `SHOULDER_AXIS` records where that point sits within the base plate, and
`Z_CARRIAGE_REFERENCE_POINT` where it sits within the carriage. A reading is turned into a location
by taking the reference point out of it, which is what `z_carriage_location` does. Nothing else in
the model is allowed to guess a position.

## The parts

| Resource | Category | Model | What it is |
|---|---|---|---|
| `base_plate` | `base_plate` | `brooks_pf400_base_plate` | The plate the machine bolts to |
| `z_column` | `z_column` | `brooks_pf400_z_column` | The column the carriage rides, as tall as the travel makes it |
| `z_carriage` | `z_carriage` | `brooks_pf400_z_carriage` | What the Z drive moves: the housing the arm turns in |

`PreciseFlex400` in `device.py` assembles them: the plate is the machine's, and the column is the
plate's. The carriage is hung on by the driver at setup, because where it stands has to be read
first.

## Meshes

A part is drawn as its own box until a mesh is named after it. A file called `<model>.glb`, shipped
anywhere under the package, is found by the viewer and drawn instead - nothing in the code holds a
path. The file is authored in the part's own frame, in metres, Z up.

The cuboids are therefore the specification for how a model of the whole machine is split: one file
per part, each cut at that part's own corner, so a file can be dropped in without an offset and
without anything else changing.

## Not modelled yet

The two links, the gripper and the optional rail. Until they are here, the arm reaches past a
machine that ends at its carriage.
