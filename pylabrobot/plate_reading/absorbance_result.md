# AbsorbanceResult

`AbsorbanceResult` is a container class for absorbance plate reader data. It wraps the raw `List[Dict]` that backends return and provides wavelength-aware access, spectrum extraction, and conversion to pandas/numpy — without breaking backwards compatibility.

It lives in `pylabrobot/plate_reading/result.py` and inherits from `PlateReaderResult`.

## Class hierarchy

```
collections.abc.Sequence
  └── PlateReaderResult        # base: well access, grid, temps, times, to_numpy, to_dataframe
        ├── AbsorbanceResult   # + wavelengths, at_wavelength(), spectrum()
        ├── FluorescenceResult # + ex/em wavelengths
        └── LuminescenceResult # no wavelength concepts
```

`AbsorbanceResult` is the only subclass with `spectrum()` and `at_wavelength()` because those concepts are specific to absorbance scans where each entry corresponds to exactly one wavelength.

## What the raw data looks like

Backends return a `List[Dict]`, one dict per wavelength measured:

```python
[
  {"wavelength": 300, "temperature": 25.0, "time": 1.2, "data": [[0.12, 0.34, ...], ...]},
  {"wavelength": 301, "temperature": 25.0, "time": 1.3, "data": [[0.13, 0.35, ...], ...]},
  ...
  {"wavelength": 700, "temperature": 25.0, "time": 5.1, "data": [[0.08, 0.22, ...], ...]},
]
```

Each `"data"` value is a 2D grid (`List[List[float]]`) — rows are plate rows (A-H), columns are plate columns (1-12 for a 96-well plate).

## Getting an AbsorbanceResult

Use `return_type="result"` on the plate reader frontend:

```python
from pylabrobot.plate_reading import PlateReader, AbsorbanceResult

pr = PlateReader(name="pr", backend=..., size_x=1, size_y=1, size_z=1)
await pr.setup()

# return_type controls what you get back:
#   "legacy"  -> result[0]["data"]  (the old default, a bare 2D grid)
#   "dict"    -> List[Dict]         (same as use_new_return_type=True)
#   "result"  -> AbsorbanceResult   (the new container)
result = await pr.read_absorbance(wavelength=600, return_type="result")
```

The older `use_new_return_type=True` parameter still works and returns `List[Dict]` — it is not affected.

You can also construct one directly from raw data:

```python
result = AbsorbanceResult(raw_list_of_dicts)
# or with explicit grid dimensions:
result = AbsorbanceResult(raw_list_of_dicts, num_rows=8, num_cols=12)
```

If `num_rows`/`num_cols` are not given, they are inferred from `data[0]["data"]`.

## Backwards compatibility

`AbsorbanceResult` implements `collections.abc.Sequence`, so all existing list operations work:

```python
len(result)          # number of entries (one per wavelength)
result[0]            # first dict, same as raw_list[0]
result[-1]           # last dict
result[0]["wavelength"]  # 300

for entry in result:
    print(entry["wavelength"])

result == raw_list   # True — compares equal to the original list
```

Integer indexing always means **list position**, not wavelength. This avoids silent breakage: wavelengths 300-700 overlap with valid list indices 0-400, so `result[300]` means "entry at index 300", not "the entry for 300 nm". Use `at_wavelength()` for wavelength lookup.

## Indexing convention

| Syntax | Returns | Meaning |
|---|---|---|
| `result[0]` | `Dict` | Entry at list index 0 |
| `result[-1]` | `Dict` | Last entry |
| `result[0:5]` | `AbsorbanceResult` | Sliced result (preserves type) |
| `result["A1"]` | `List[float]` | OD values for well A1 across all wavelengths |

## Properties

### `.wavelengths -> List[int]`

Sorted list of all wavelengths in the result, built from the `"wavelength"` key in each entry:

```python
result.wavelengths
# [300, 301, 302, ..., 700]
```

### `.temperatures -> List[Optional[float]]`

Temperature recorded at each measurement, in entry order:

```python
result.temperatures
# [25.0, 25.0, 25.0, ...]
```

### `.times -> List[Optional[float]]`

Timestamp of each measurement, in entry order.

### `.num_rows -> int` / `.num_cols -> int`

Grid dimensions. 8 and 12 for a standard 96-well plate.

### `.raw -> List[Dict]`

The underlying list of dictionaries, same reference as stored internally.

## Methods

### `result["A1"]` / `result.well("A1") -> List[Optional[float]]`

Returns the OD value for well A1 from every entry, in order. For a 300-700 nm scan, this gives you 401 values — one per wavelength:

```python
od_values = result["A1"]
# [0.12, 0.13, 0.14, ..., 0.08]   (one value per wavelength)
```

Well names follow standard plate notation: row letter(s) + column number. Single letters `A`-`Z` for rows 0-25, double letters `AA`, `AB`, ... for 384/1536-well plates.

### `result.at_wavelength(wavelength) -> List[List[float]]`

Returns the full 2D plate grid at a specific wavelength. O(1) lookup via an internal index:

```python
grid_600 = result.at_wavelength(600)
# [[od_A1, od_A2, ...], [od_B1, od_B2, ...], ..., [od_H1, od_H2, ...]]

od_A1_at_600 = grid_600[0][0]
```

Raises `KeyError` if the wavelength is not in the data, with a message listing available wavelengths.

### `result.spectrum(well_name) -> (List[int], List[Optional[float]])`

Returns a `(wavelengths, values)` tuple for one well, sorted by wavelength. Designed so you can unpack it directly into `matplotlib.pyplot.plot`:

```python
import matplotlib.pyplot as plt

plt.plot(*result.spectrum("A1"))
plt.xlabel("Wavelength (nm)")
plt.ylabel("OD")
plt.title("Absorbance spectrum — well A1")
plt.show()
```

Or compare multiple wells:

```python
for well in ["A1", "A2", "B1"]:
    wls, vals = result.spectrum(well)
    plt.plot(wls, vals, label=well)
plt.legend()
plt.show()
```

### `result.grid(index) -> List[List[float]]`

Returns the 2D data grid at a list index (supports negative indexing):

```python
first_grid = result.grid(0)
last_grid = result.grid(-1)
```

### `result.well_names() -> List[str]`

All well names in row-major order:

```python
result.well_names()
# ["A1", "A2", ..., "A12", "B1", ..., "H12"]
```

### `result.to_list() -> List[Dict]`

Returns the underlying data. Alias for `.raw`.

### `result.to_dataframe() -> pandas.DataFrame`

Converts to a pandas DataFrame. Requires `pandas` (lazy import — raises `ImportError` with install instructions if missing).

- **Index:** `wavelength`
- **Columns:** well names (`A1`, `A2`, ..., `H12`) + `temperature` + `time`

```python
df = result.to_dataframe()

#              temperature  time    A1      A2    ...   H12
# wavelength
# 300              25.0     1.2   0.120   0.340  ...  0.050
# 301              25.0     1.3   0.130   0.350  ...  0.051
# ...

# Plot a spectrum directly from the DataFrame:
df["A1"].plot()

# Compare wells:
df[["A1", "A2", "B1"]].plot()
```

### `result.to_numpy() -> numpy.ndarray`

Converts to a 3D numpy array. Requires `numpy` (lazy import).

- **Shape:** `(n_wavelengths, num_rows, num_cols)`
- `None` values become `numpy.nan`

```python
arr = result.to_numpy()
arr.shape  # (401, 8, 12) for a 300-700nm scan on a 96-well plate

# OD at wavelength index 0, row A, column 1:
arr[0, 0, 0]
```

## repr

The repr is informative and shows key dimensions at a glance:

```python
repr(result)
# AbsorbanceResult(401 entries, 8x12 grid, wavelengths=300-700nm)

# Single wavelength:
# AbsorbanceResult(1 entry, 8x12 grid, wavelength=600nm)
```

## Internal details

### Wavelength index

On construction, `AbsorbanceResult` builds a `dict` mapping `{wavelength_nm: list_index}` for O(1) lookups. This is stored in `_wl_index` (a `__slots__` attribute).

### Immutability

The class does not expose `.append()`, `.sort()`, `.pop()`, or other mutating list methods. It is not a `list` subclass — it registers as `collections.abc.Sequence` via inheritance. The internal data list is a defensive copy made at construction time.

### Slicing preserves type

`result[0:5]` returns a new `AbsorbanceResult` (not a plain `PlateReaderResult`), so wavelength-specific methods remain available on the slice.

## Complete example

```python
from pylabrobot.plate_reading import PlateReader, AbsorbanceResult
import matplotlib.pyplot as plt

# Setup
pr = PlateReader(name="pr", backend=my_backend, size_x=1, size_y=1, size_z=1)
await pr.setup()
pr.assign_child_resource(my_plate)

# Read a spectrum scan (backend handles wavelength sweep)
result = await pr.read_absorbance(wavelength=600, return_type="result")

# Quick inspection
print(result)
# AbsorbanceResult(1 entry, 8x12 grid, wavelength=600nm)
print(result.wavelengths)
# [600]

# Access a single well
print(result["A1"])
# [0.342]

# Full 2D grid
grid = result.at_wavelength(600)
print(grid[0][0])  # well A1
# 0.342

# Convert for analysis
df = result.to_dataframe()
arr = result.to_numpy()

# Still works like a list
assert result[0]["wavelength"] == 600
assert len(result) == 1
```
