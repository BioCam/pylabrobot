# plr_viz3d

A parallel PyLabRobot visualizer whose world is a resource, not a liquid handler. Prototype only:
no tests, no packaging, no upstream wiring. It exists to check that the three claims in the
architecture note hold against real v1 code.

## Running it

Needs the v1 STAR branch on the path and `websockets`.

```
python -m plr_viz3d.demo
```

It opens a browser on `http://127.0.0.1:1338`. Append `?view=top` for a top view. From the console,
`plrViewer.focus("destination_0")` frames and selects a named resource.

## What it demonstrates

**Any resource is the world.** `Viewer3D(root)` takes a `Resource`. The demo's world is a plain
`Resource` holding a simulated `STARDevice` at one coordinate and a bench at another. The bench has
no deck, no driver and no machine of any kind; it holds a plate and a tip rack, and renders exactly
like everything else. Nothing in the client switches on a resource type: geometry comes from the
model's own `cross_section_type` and sizes, colour from its `category`, structure from the parent
array, and the inspector prints whatever fields arrived.

**Prototype and instance, measured.** On the demo facility:

| | value |
|---|---|
| instances | 1,490 |
| distinct models | 18 |
| tree JSON, as the current visualizer sends it | 847.3 kB |
| models plus a packed instance array | 100.1 kB |
| ratio | 8.46x |
| draw calls | 24 to 34 |

A single 96-well plate goes from 59,870 to 8,261 bytes, 7.25x. Transforms ride as base64
little-endian float32, six per instance.

Getting there needed one correction worth keeping. Splitting on `Resource.serialize()` alone gives
421 models for 1,490 instances, because identity leaks below the top level: a tip spot carries the
name of its prototype tip, and a plate carries a map of identifier to the name of the well it
holds. Two general rules fix it, both in `scene.py`: a key called `name` at any depth names one
particular thing, and inside a nested structure a string matching a resource in this tree is a link
to it. The rule deliberately stops at the top level, or a deck called "deck" loses its category.

**One channel, not two.** Everything the viewer draws arrives as tracking state: a well's volume, a
tip spot's fitting, and the position of anything that travels. A moving part reaches the picture
because `Resource.location` publishes when it is set, so an X-arm read off the machine is on the
same path as a well being filled.

A polling reader sat beside that for a while, asking a device where its arm was five times a second
and labelling each number `measured`, `derived` or `unavailable`. It was a second communication
channel for a position state already carried, so it is gone. What is lost with it is the labelling
of what v1 does not publish - per-channel X, Y and Z have no live readout, and saying so in the
interface is worth doing again once state itself can carry that distinction.

## What it is not

- No WebGPU verification. The headless browser used to check it has no adapter, so it exercised the
  WebGL2 fallback path. Frame rates seen there are software rendering and mean nothing; draw calls
  are the figure that transfers.
- Tips and liquid are driven from tracker state only. The v1 STAR has no aspirate, dispense or
  tip-pickup yet, so the demo moves trackers directly. A real command would move the same trackers.
- Picking is `InstancedMesh` raycasting, which is fine at this size. GPU picking is the production
  answer.
- GIF recording only works on the WebGPU backend. three's WebGL2 backend cannot read a render
  target back (r180), so on the fallback path the control disables itself and says why rather than
  producing an empty file. Untested on WebGPU here, since the browser used to check it has no
  adapter. It captures the viewport only, not the floating panels over it.
- No GUI editing mode.

## Interface

The shell follows the existing visualizer: its palette and metrics, the navbar with the source
name, the left tool rail (select, get-location, GIF), the facility tree
with per-item eye toggles, expand-all and show-to-depth, the search pane with its include filters,
the floating info panel, the scale bar and the resizable side panel.

Three things are new, because three dimensions asks for them: camera presets in the left rail
(ISO, TOP, FRT), an axis legend that turns with the view instead of a fixed x/y pair, and a Z
reference in the coordinate tool alongside X and Y.

## Layout

```
scene.py      flatten any resource tree into models and instances; measure the split
server.py     static files and a websocket, same two servers as today
demo.py       a facility with a STAR and a bench in it
static/       index.html, main.css, and the client modules below; vendored three.js and gif.js
              (no CDN, so it runs air-gapped)
```

The client is plain ES modules, loaded straight by the browser. There is no build step, and adding
one is not on the table: the page has to keep working from a checkout, offline.

```
static/app.js         the scene: geometry, camera, tree, info panel, interaction, transport
static/constants.js   the palette and the thresholds, as data
static/format.js      turning values into the text the info panel shows
static/dom.js         element lookups that say which kind of element is being asked for
static/coords.js      the get-location tool
static/gif.js         recording the viewport
```

## Type checking

The JavaScript is checked without being converted. `static/tsconfig.json` turns on `checkJs`, and
`static/types/vendor.d.ts` marks where our code stops and three's begins.

```
npx tsc --noEmit -p pylabrobot/visualizer3D/static
```

Editors that read `tsconfig.json` report the same findings inline, with no install. `strict` is
deliberately off: against untyped JavaScript it reports far more than anyone acts on, and buries
what matters.
