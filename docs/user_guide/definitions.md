# Definitions

We try to keep jargon to a minimum, but some terms are commonly used in lab automation speak/PLR docs. It is a form of tacit knowledge. In some cases it's best to accept the universally used terms and not reinvent the wheel with more descriptive/longer terms. In those cases, we help newcomers by defining those terms here.

Use `` {term}`term name` `` in any doc page to link back to a definition here.

## Liquid Handling

```{glossary}
Gantry
   The motion system (rails, motors) that provides X/Y travel. Same usage as in general robotics.

Pipette
   A unit of machinery that attaches to the {term}`Gantry` and executes aspirate/dispense actions. Moves in X/Y via the gantry.

Head
   The component of a {term}`Pipette` that moves in the Z dimension (vertical travel). Contains one or more {term}`Channel`s.

Channel
   The nozzle at the bottom of a {term}`Head` where a tip physically attaches. A head has one or more channels.

96 head
   A {term}`Head` with 96 {term}`Channel`s that do not move independently.
```

<details style="background-color:#f8f9fa; border-left:5px solid #007bff; padding:10px; border-radius:5px; margin-bottom:15px;">
<summary style="font-weight:bold; cursor:pointer;">How these parts relate: Gantry → Pipette → Head → Channel</summary>
<hr>

```
Gantry ─── The motion system (rails, motors) that
  │         provides X/Y travel.
  │
  └── Pipette ─── Attaches to the gantry and executes
        │          aspirate/dispense actions.
        │
        └── Head ─── Moves in the Z dimension
              │       (vertical travel).
              │
              └── Channel(s) ─── The nozzle(s) where
                                  tips physically attach.
                                  A head has 1 or more
                                  channels.
```

</details>

## Plate Reading

```{glossary}
Detection mode
   The physical measurement principle used by a plate reader to interrogate a sample. Each mode uses different optics and light paths. The three standard modes are {term}`Absorbance`, {term}`Fluorescence`, and {term}`Luminescence`. Multi-mode readers may also support {term}`Fluorescence polarization`, {term}`Time-resolved fluorescence`, and {term}`AlphaScreen`.

Absorbance
   A {term}`detection mode` that measures how much light a sample absorbs at one or more wavelengths. Reported as {term}`OD` or percent transmittance.

Spectral scanning
   A variant of {term}`Absorbance` that sweeps across a continuous wavelength range (e.g. 220–1000 nm) rather than measuring at discrete wavelengths. Produces a full absorption spectrum per well.

Fluorescence
   A {term}`detection mode` that excites fluorophores at one wavelength and measures emitted light at a longer wavelength. Requires an excitation/emission wavelength pair, gain, and focal height.

Fluorescence polarization
   A {term}`detection mode` that measures the rotational motion of fluorophores by comparing parallel vs perpendicular polarised emission. Used in binding and competition assays where bound (large, slow-rotating) molecules produce higher polarisation than free (small, fast-rotating) ones. Abbreviated FP.

Time-resolved fluorescence
   A {term}`detection mode` that uses lanthanide-based fluorophores (e.g. europium, terbium) with long emission decay times. A time gate delays detection by microseconds, eliminating short-lived background autofluorescence. The basis for TR-FRET / HTRF assays. Abbreviated TRF.

AlphaScreen
   A bead-based proximity {term}`detection mode`. Donor beads are excited at 680 nm by a laser; when an acceptor bead is within ~200 nm, singlet oxygen transfers energy and the acceptor emits at 520–620 nm. Requires a dedicated laser module. AlphaLISA is a variant using europium acceptor beads for a narrower emission window.

Luminescence
   A {term}`detection mode` that detects light emitted by a chemical or biological reaction (no external excitation). Requires a focal height but no excitation wavelength.

OD
   Optical density — a unitless measure of {term}`Absorbance`. OD = −log₁₀(transmittance / 100).
```

<details style="background-color:#f8f9fa; border-left:5px solid #28a745; padding:10px; border-radius:5px; margin-bottom:15px;">
<summary style="font-weight:bold; cursor:pointer;">How detection modes relate</summary>
<hr>

```
Detection Mode ─── The measurement principle used to
  │                 interrogate a sample.
  │
  ├── Absorbance ─── Light source → sample → detector.
  │     │             Measures transmitted light.
  │     │             Reported as OD, %T, or raw counts.
  │     │
  │     └── Spectral scanning ─── Sweeps a continuous
  │                                wavelength range
  │                                (e.g. 220–1000 nm).
  │
  ├── Fluorescence ─── Excite at λ₁, detect emission at λ₂.
  │     │
  │     ├── Fluorescence polarization (FP) ─── Compares
  │     │     parallel vs perpendicular emission to measure
  │     │     molecular rotation / binding.
  │     │
  │     ├── Time-resolved fluorescence (TRF) ─── Gated
  │     │     detection after µs delay; eliminates
  │     │     background. Basis for TR-FRET / HTRF.
  │     │
  │     └── AlphaScreen ─── Bead-based proximity assay.
  │           680 nm laser → donor beads → singlet
  │           oxygen → acceptor beads emit at 520–620 nm.
  │           Detection is fluorescence; requires
  │           dedicated laser module.
  │
  └── Luminescence ─── Detects light from a chemical or
                        biological reaction. No excitation
                        light source needed.
```

</details>

## Storage & Transport

```{glossary}
Drawer
   A motorized plate carrier that slides out of an instrument for plate loading/unloading, then slides back in for measurement. Common on plate readers and incubators. In PLR: `open()` slides out, `close()` slides in.
```

<details style="background-color:#f8f9fa; border-left:5px solid #ffc107; padding:10px; border-radius:5px; margin-bottom:15px;">
<summary style="font-weight:bold; cursor:pointer;">Drawer control in code</summary>
<hr>

```python
# Open the drawer to load a plate
await pr.open()

# ... place plate on the drawer ...

# Close to begin measurement
await pr.close()
```

</details>
