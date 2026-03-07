# Optics Primer — Dichroic Mirrors & Beam Splitters

A short reference for anyone working on the CLARIOstar driver who wants to
understand what the optical components actually do.

---

## What does the dichroic mirror do?

In fluorescence, you shine light at one wavelength (excitation) and detect
light at a different wavelength (emission). Both beams travel through the
same optical path. You need something to separate them.

The dichroic sits at 45° between the light source and detector. It works
like a one-way mirror tuned to a specific wavelength cutoff:

```
                    Light source
                        │
                        ▼  (excitation, e.g. 485 nm)
                   ┌─────────┐
                   │ Dichroic │──── REFLECTS short λ ──→ (bounced away)
                   │  Mirror  │
                   └─────────┘
                        │
                        │  TRANSMITS long λ  (emission, e.g. 528 nm)
                        ▼
                    Detector
```

Short wavelengths (excitation) get **reflected** down toward the sample.
Longer wavelengths (emission) coming back from the sample **pass through**
to the detector. The cutoff wavelength sits in the gap between excitation
and emission — that's why the auto-dichroic formula is:

```
dichroic = (ex_upper_edge + em_lower_edge) / 2
```

Without it, the detector would be blinded by the excitation light, which is
orders of magnitude brighter than the fluorescence signal.

### CLARIOstar implementation

The CLARIOstar has two options for this separation:

- **LVDM** (Linear Variable Dichroic Mirror) — a continuously tunable
  dichroic. A physical slide moves to change the cutoff wavelength anywhere
  in the 340–760 nm range. Used when `dichroic_filter=None` (default).
- **Fixed dichroic filters** in slots A/B/C — pre-cut for specific
  wavelengths, higher optical throughput. Used when
  `dichroic_filter=Filter(slot=1)` (slot 1 = position A).

---

## Is a dichroic filter the same as a beam splitter?

Not exactly. A beam splitter is the broader category — anything that splits
a beam into two paths. There are different types:

| Type | How it splits | Use case |
|------|--------------|----------|
| **50/50 beam splitter** | Reflects 50%, transmits 50% regardless of wavelength | Interferometry, cameras |
| **Polarizing beam splitter** | Splits by polarization (s vs p) | Microscopy, laser optics |
| **Dichroic beam splitter** | Splits by wavelength (reflects short λ, transmits long λ) | Fluorescence |

A dichroic filter/mirror is a **wavelength-selective beam splitter**. All
dichroics are beam splitters, but not all beam splitters are dichroic.

### Terminology note

"Dichroic filter" and "dichroic mirror" refer to the same physical thing —
a thin-film interference coating that reflects some wavelengths and transmits
others. The name depends on whether you characterize it by what it
**passes** (filter) or what it **reflects** (mirror). Same construction,
same physics. BMG's own documentation uses both terms interchangeably.

---

## Excitation, emission, and dichroic filters compared

Excitation and emission filters are **bandpass** filters — they select a
narrow band of wavelengths and block everything else. The dichroic is a
**beam splitter** — it separates two wavelength ranges into two different
physical directions.

| | Excitation filter | Emission filter | Dichroic mirror |
|---|---|---|---|
| **Job** | Select excitation band from broadband lamp | Select emission band, block excitation leakage | Separate excitation path from emission path |
| **Optical behavior** | Transmits narrow band, blocks rest | Transmits narrow band, blocks rest | Reflects short λ, transmits long λ |
| **Angle in light path** | 0° (perpendicular to beam) | 0° (perpendicular to beam) | 45° (angled) |
| **Type** | Bandpass | Bandpass | Long-pass edge filter |
| **Key spec** | Center wavelength + bandwidth (e.g. 485/15) | Center wavelength + bandwidth (e.g. 528/20) | Cut-on wavelength (e.g. LP 504) |
| **Construction** | Thin-film interference coating | Thin-film interference coating | Thin-film interference coating |
| **CLARIOstar positions** | Slide positions 1–4 | Slide positions 1–4 | Slide positions A/B/C |

The physical construction is identical — all three are glass substrates with
multi-layer dielectric coatings. The difference is purely in the coating
design (what wavelengths to pass/reflect) and how they're mounted
(0° vs 45°).

### How they work together

```
    Lamp ──→ [Ex filter] ──→ ╲              ╱ ──→ [Em filter] ──→ Detector
                              ╲  Dichroic  ╱
                               ╲__________╱
                                   │
                                   ▼
                                Sample
                                   │
                                   ▲ (fluorescence)
```

The excitation filter narrows the lamp output to your excitation band. That
light hits the dichroic at 45° and gets **reflected** down to the sample.
Fluorescence comes back at a longer wavelength, passes **through** the
dichroic, then the emission filter rejects any remaining excitation bleed
before the detector sees it.

All three work together as a matched set — which is why in filter mode you
typically specify all three (`excitation_filter`, `emission_filter`,
`dichroic_filter`), and why BMG sells them as coordinated filter sets for
specific fluorophores.
