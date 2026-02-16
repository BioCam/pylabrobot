# Terminology

Standard terminology used across PyLabRobot. Using consistent names makes code portable between machines from different manufacturers.

## Mechanical Components

### Drawer

A motorized plate carrier that slides out of the instrument so you can place or remove a plate, then slides back in for measurement. The door and the plate holder move together as one unit.

Examples: the CLARIOstar plate reader loading tray, the Cytation plate loading mechanism.

**In code:** `open()` slides the drawer out, `close()` slides it back in.

### Lid

A hinged or removable cover on top of a resource (e.g. a plate lid). In PLR, `Lid` is a resource class that can be picked up and put down by a robotic arm.

Not to be confused with instrument doors or drawers.
