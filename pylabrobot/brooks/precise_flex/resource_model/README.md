# The PreciseFlex resource model

What the arm is made of, as resources: the manipulator (`pf400_manipulator.py`: the base plate, the
column, the carriage and the two links), the gripper (`pf400_end_effector.py`) and the optional
linear rail with its carriage (`pf400_rail.py`). The device builds the base plate; the driver builds
the rest at setup, from the configuration the controller answers.

## Meshes

A part is drawn as its own box until a mesh is named after it. A file called `<model>.glb`, shipped
anywhere under the package, is found by the viewer and drawn instead - nothing in the code holds a
path. The file is authored in the part's own frame, in metres, Z up, cut at the part's own corner,
so it can be dropped in without an offset.

Each file comes from Brooks: the datasheet (612736, Robot Mounting) where it gives a dimension, and
otherwise the IGES models of the standard-reach (PF400S) and extended-reach (PF400SX) arms. What no
one can see is left out, and the rest is simplified only where the eye cannot tell.

- The base plate is the datasheet's: 201 x 235, with the holes that show from above (the M10
  leveling and the counterbored mounting holes). Thickness, radii and hole sizes are the CAD's.
- The column is the CAD's extrusion, top plate and front cover. Black strips seal its two front
  slots, which the CAD leaves open. Its connector panel keeps the Ethernet socket, the power
  switch and the power inlet. The 750 and 1160 mm columns extend the 400 mm one in z above the
  panel, to the datasheet's robot heights.
- The carriage is the housing the arm turns in, at the CAD's dimensions: its lid, blue bumper,
  screw heads and the bracket under it. The block inside the column is left out.
- The links are the PF400S's (225 and 210 between their hub centres) or the PF400SX's (302 and
  289), each link drawn as the reach its length is nearest.
- Both gripper bodies, the jaws and both grippers' fingers are Brooks' IntelliGuide STEP models;
  each finger stands where its two screws meet its jaw's tapped holes. A jaw and a finger each
  have a left and a right mesh, as the two sides are mirror images; left is the gripper's +y side.

White parts next to each other alternate between two shades, so each stands apart from its
neighbour.

## Not built yet

The rail and its carriage exist as parts, with their meshes, and nothing builds them: an arm on a
rail is still modelled as standing still. What is missing is known only from an arm on a rail:
where on the rail its carriage stands when the drive reports 0, and where on the carriage the
arm's base plate is bolted.
