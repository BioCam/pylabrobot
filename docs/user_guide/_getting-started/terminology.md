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

## Wire Protocol

### Command

A message sent **to** a device instructing it to perform an action or return information.

### Response

A message sent **from** a device after receiving a command.

## Plate Reader

### Detection Mode

The physical measurement principle used by a plate reader to interrogate a sample. Each detection mode uses different optics and light paths:

- **Absorbance** — measures how much light a sample absorbs at one or more wavelengths. The instrument shines a broadband light source through the sample and records the transmitted intensity. Reported as optical density (OD) or percent transmittance.
- **Fluorescence** — excites fluorophores in the sample at one wavelength and measures emitted light at a longer wavelength. Requires an excitation/emission wavelength pair, gain setting, and focal height.
- **Luminescence** — detects light emitted by a chemical or biological reaction in the sample (no external excitation light). Requires a focal height but no wavelength selection on the excitation side.
- **Spectral absorbance scan** — a variant of absorbance that sweeps across a continuous wavelength range (e.g. 220–1000 nm) rather than measuring at discrete wavelengths.

**In code:** the `detection_mode` field on `MeasurementRecord` stores which mode was used (e.g. `"absorbance"`, `"fluorescence"`, `"luminescence"`, `"spectral_absorbance_scan"`).
