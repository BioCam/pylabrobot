# Measurement results directory

A CLARIOstar measure call can be given a directory. As soon as the reader delivers data, its
rows are appended to that directory, so a run that fails keeps everything measured so far, and
other programs can follow the run while it is measured: a live plot, a monitor, an analysis.

Pass `results_directory="results/run_1"` to a measure call, or set the feature's
`default_results_directory`. Readers never lock and never write, so following a run never slows
down the measurement.

## What the directory holds

| file | contents |
|---|---|
| `rows.jsonl` | one JSON object per line: one row per measured value, appended as data arrives |
| `replies.jsonl` | every data reply from the reader, to decode again later |
| `manifest.jsonl` | one line per writing session: schema version, PyLabRobot version, the device |
| `.lock` | held by the one program writing the directory |

Each row carries every coordinate and setting of its value:

| columns | meaning |
|---|---|
| `read`, `mode`, `start_timestamp`, `end_timestamp` | which read, and when (UTC) |
| `well`, `row`, `column`, `row_index`, `column_index` | the well ("B3", "B", 3, 1, 2) |
| `wavelength`, `excitation_wavelength`, `excitation_bandwidth`, `emission_wavelength`, `emission_bandwidth`, `scanned` | the optics |
| `point`, `x`, `y`, `focal_height` | where in the well: matrix points, grids (mm from the centre), height |
| `optic_position`, `gain`, `temperature` | settings |
| `quantity`, `value`, `saturated` | the value, what it is ("optical_density", "counts"), and whether it is at the detector's ceiling |

Columns that do not apply to a row are `null`. A directory can be written again: reads continue
its `read` numbering.

## Loading a run

`load_rows` reads every complete row, also while the run is still being written: a last line
still being written is skipped. It needs only the standard library.

```python
from pylabrobot.lib.results.reading import get_dataframe, load_rows

rows = load_rows("results/run_1")
print(len(rows), rows[0]["well"], rows[0]["value"])
```

`get_dataframe` gives the rows as a pandas DataFrame with their types: timestamps as UTC
datetimes, integers as pandas' nullable `Int64` (absorbance rows have no `gain`), text as
`string`. It takes a directory or rows already loaded. pandas is not a PyLabRobot dependency:
install it with `pip install pandas`.

```python
frame = get_dataframe("results/run_1")
print(frame.groupby(["read", "mode", "quantity"])["value"].describe())
```

A plate layout (well to sample, concentration, condition) joins on `well`:
`frame.merge(layout, on="well")`.

## Quick plots

These use matplotlib (`pip install matplotlib`).

A plate heatmap of one read, by pivoting `row` and `column`:

```python
import matplotlib.pyplot as plt

read = frame[frame["read"] == 0]
plate = read.pivot_table(index="row", columns="column", values="value")
figure, axes = plt.subplots()
image = axes.imshow(plate.to_numpy(dtype=float))
axes.set_xticks(range(len(plate.columns)), plate.columns)
axes.set_yticks(range(len(plate.index)), plate.index)
figure.colorbar(image, label=read["quantity"].iloc[0])
plt.show()
```

A series per well across reads, for example a kinetic run:

```python
kinetics = frame[frame["mode"] == "absorbance"]
figure, axes = plt.subplots()
for well, series in kinetics[kinetics["well"].isin(["A1", "B1", "C1"])].groupby("well"):
  axes.plot(series["start_timestamp"], series["value"], marker="o", label=well)
axes.set_ylabel("optical density")
axes.legend()
figure.autofmt_xdate()
plt.show()
```

A grid heatmap of a well, by `x` and `y` in mm from its centre:

```python
grid = frame[(frame["mode"] == "fluorescence_grid") & (frame["well"] == "A1")]
points = grid.pivot_table(index="y", columns="x", values="value")
figure, axes = plt.subplots()
image = axes.pcolormesh(points.columns, points.index, points.to_numpy(dtype=float))
axes.set_aspect("equal")
axes.set_xlabel("x (mm)")
axes.set_ylabel("y (mm)")
figure.colorbar(image, label="counts")
plt.show()
```

## Following a run live

`follow_rows` yields each batch of new rows as the writer appends them, starting with every row
written so far. It reads only what was added since its last look, and a look that finds nothing
new costs one `os.stat`. A line still being written waits for its end. The directory may not
exist yet when it starts. It stops once nothing has been added for `idle_timeout` seconds (by
default it follows forever).

A run is followed from another program, for example this script, which redraws the latest read
as a plate heatmap whenever new rows arrive. Passing `plt.pause` as `sleep` keeps the window
responsive between looks.

```python
import sys

import matplotlib.pyplot as plt

from pylabrobot.lib.results.reading import follow_rows, get_dataframe

directory = sys.argv[1]
rows = []
figure, axes = plt.subplots()
for batch in follow_rows(directory, poll_interval=0.2, idle_timeout=600, sleep=plt.pause):
  rows.extend(batch)
  frame = get_dataframe(rows)
  read = frame[frame["read"] == frame["read"].max()]
  plate = read.pivot_table(index="row", columns="column", values="value")
  axes.clear()
  axes.imshow(plate.to_numpy(dtype=float))
  axes.set_xticks(range(len(plate.columns)), plate.columns)
  axes.set_yticks(range(len(plate.index)), plate.index)
  axes.set_title(f"read {read['read'].iloc[0]} ({read['mode'].iloc[0]}), {len(rows)} rows")
  plt.pause(0.01)
plt.show()
```

Run it as `python live_plot.py results/run_1`. A plot updates as often as the reader delivers
data: a discrete read arrives at its end, a spectrum page by page, a grid well by well.

`follow_rows` raises a `ValueError` for a file that shrank or was replaced: it is no longer
append-only. Both functions raise a `ValueError` for a complete line that is not a JSON object,
naming its line number.
