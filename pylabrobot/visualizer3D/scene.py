"""Flatten any resource tree into prototypes and instances.

The current visualizer sends one JSON object per resource, so a 96-well plate repeats the same
geometry ninety-six times. Here a resource is split in two: what it *is* (its model, shared by
every resource serializing to the same thing) and where it *is* (its instance: a name, a parent,
and a transform). Models go over the wire once; instances are six floats in a typed array.

Nothing here knows about any resource type. The split is derived from `Resource.serialize()` by
removing the fields that vary per instance, so a resource type that does not exist yet flattens
correctly the day it is written.
"""

import base64
import functools
import inspect
import json
import struct
from typing import Any, Dict, List, Optional, Tuple

from pylabrobot.resources.resource import Resource

from .grids import describe_bands, describe_grid

# Fields of a serialized resource that describe this one resource rather than its kind. Everything
# else is shared by every resource that serializes the same way, and so belongs to the model.
INSTANCE_FIELDS = frozenset({"name", "location", "rotation", "parent_name", "children"})

# Identity also leaks below the top level: a tip spot carries the name of its prototype tip, and a
# plate carries a map of identifier to the name of the well it holds. Both are this resource's
# links, not its kind, and leaving them in gives every plate and every tip spot its own model.
NAME_KEYS = frozenset({"name", "parent_name"})

# Fields a resource may declare about itself that `serialize()` does not yet carry. Upstream these
# belong in the resource's own serialization; passing them through here keeps the viewer free of
# any machine's constants in the meantime.
DECLARED_FIELDS = ("reference_point", "window")
RESOURCE_LINK = "<resource>"


def _model_of(data: Dict[str, Any], names: frozenset) -> Dict[str, Any]:
  """The kind-defining part of a serialized resource, with every identity removed.

  Two rules, both general. A key called `name` anywhere names one particular thing. And inside a
  nested structure, a string that matches a resource in this tree is a link to it. Ordered maps
  such as a plate's item ordering keep their keys, which is the part that does describe the kind.

  The link rule deliberately stops at the top level: a resource's own descriptive fields are
  scalars there, and a category can legitimately read the same as some resource's name (a deck
  called "deck", a bench called "bench") without being a reference to it.
  """

  def strip(value: Any) -> Any:
    if isinstance(value, dict):
      return {k: strip(v) for k, v in value.items() if k not in NAME_KEYS}
    if isinstance(value, list):
      return [strip(v) for v in value]
    if isinstance(value, str) and value in names:
      return RESOURCE_LINK
    return value

  return {
    k: (v if not isinstance(v, (dict, list)) else strip(v))
    for k, v in data.items()
    if k not in INSTANCE_FIELDS
  }


@functools.lru_cache(maxsize=None)
def _public_methods(cls: type) -> Tuple[str, ...]:
  """The public operations of a resource class, as signatures.

  A model is already one per class, so the operations belong on the model. The existing visualizer
  keeps them in a separate registry keyed by type name and re-sends it with every assignment; here
  they ride along with the thing they describe and are sent once.
  """
  signatures = []
  for name in dir(cls):
    if name.startswith("_"):
      continue
    try:
      attribute = getattr(cls, name, None)
    except Exception:
      continue
    if attribute is None or not callable(attribute) or isinstance(attribute, property):
      continue
    try:
      parameters = [p for p in inspect.signature(attribute).parameters if p != "self"]
      signatures.append(f"{name}({', '.join(parameters)})")
    except (ValueError, TypeError):
      signatures.append(f"{name}()")
  return tuple(sorted(signatures))


def _model_class(model: Dict[str, Any]) -> str:
  """The bucket a model is compared within. Two resources of different types are never the same."""
  return str(model.get("type", ""))


def _location_of(data: Dict[str, Any]) -> Tuple[float, float, float]:
  loc = data.get("location") or {}
  return (float(loc.get("x", 0.0)), float(loc.get("y", 0.0)), float(loc.get("z", 0.0)))


def _rotation_of(data: Dict[str, Any]) -> Tuple[float, float, float]:
  rot = data.get("rotation") or {}
  return (float(rot.get("x", 0.0)), float(rot.get("y", 0.0)), float(rot.get("z", 0.0)))


class Scene:
  """A flattened resource tree: models, instances, and the measurements that justify the split."""

  def __init__(self, names: Optional[frozenset] = None) -> None:
    self.names_in_tree = names or frozenset()
    self.models: List[Dict[str, Any]] = []
    # Candidate models per serialized type. Interning compares dictionaries directly rather than
    # serializing each one to a key: dict equality is a C-level compare, and a tree has only a
    # handful of distinct models per type, so the scan is short.
    self._candidates: Dict[str, List[int]] = {}
    self.names: List[str] = []
    self.model_of_instance: List[int] = []
    self.parent_of_instance: List[int] = []
    self.transforms: List[float] = []  # 6 floats per instance: x, y, z, rx, ry, rz
    self.legacy_bytes = 0

  def _intern(self, model: Dict[str, Any]) -> int:
    bucket = self._candidates.setdefault(_model_class(model), [])
    for index in bucket:
      if self.models[index] == model:
        return index
    index = len(self.models)
    self.models.append(model)
    bucket.append(index)
    return index

  def add(
    self,
    data: Dict[str, Any],
    parent: int,
    cls: Optional[type] = None,
    grid: Optional[Dict[str, Any]] = None,
    bands: Optional[List[Dict[str, Any]]] = None,
    declared: Optional[Dict[str, Any]] = None,
  ) -> int:
    """Add one serialized resource, returning its instance index."""
    index = len(self.names)
    self.names.append(data["name"])
    model = _model_of(data, self.names_in_tree)
    if cls is not None:
      model["methods"] = list(_public_methods(cls))
    if grid is not None:
      model["grid"] = grid
    if bands is not None:
      model["bands"] = bands
    for field, value in (declared or {}).items():
      model[field] = value
    self.model_of_instance.append(self._intern(model))
    self.parent_of_instance.append(parent)
    self.transforms.extend(_location_of(data))
    self.transforms.extend(_rotation_of(data))
    return index

  @property
  def num_instances(self) -> int:
    return len(self.names)

  def serialize(self) -> Dict[str, Any]:
    """The scene message. Transforms ride as base64 little-endian float32, not as JSON numbers."""
    packed = struct.pack(f"<{len(self.transforms)}f", *self.transforms)
    return {
      "models": self.models,
      "instances": {
        "names": self.names,
        "model": self.model_of_instance,
        "parent": self.parent_of_instance,
        "transforms": base64.b64encode(packed).decode("ascii"),
      },
    }

  def stats(self, scene_bytes: Optional[int] = None) -> Dict[str, Any]:
    """What the split cost and what it saved, in bytes actually sent."""
    new_bytes = scene_bytes if scene_bytes is not None else len(json.dumps(self.serialize()))
    return {
      "instances": self.num_instances,
      "models": len(self.models),
      "legacy_bytes": self.legacy_bytes,
      "scene_bytes": new_bytes,
      "ratio": round(self.legacy_bytes / new_bytes, 2) if new_bytes else 0.0,
    }


def build_scene(root: Resource, measure_legacy: bool = False) -> Scene:
  """Flatten `root` and every descendant into models and instances.

  Traversal is depth-first and parents are emitted before children, so a client can resolve world
  transforms in one forward pass without sorting.

  Args:
    root: the resource to flatten.
    measure_legacy: also serialize the tree the way the existing visualizer sends it, to report
      what the split saves. It costs a second full serialization, so it is off by default and
      belongs in a benchmark rather than in a running viewer.
  """
  scene = Scene(names=frozenset(_all_names(root)))

  def walk(resource: Resource, parent: int) -> None:
    data = resource.serialize()
    data.pop("children", None)
    declared = {
      field: getattr(resource, field)
      for field in DECLARED_FIELDS
      if getattr(resource, field, None) is not None
    }
    index = scene.add(
      data, parent, type(resource), describe_grid(resource), describe_bands(resource), declared
    )
    for child in resource.children:
      walk(child, index)

  walk(root, -1)
  if measure_legacy:
    scene.legacy_bytes = len(json.dumps(_serialize_tree(root)))
  return scene


def _all_names(resource: Resource) -> List[str]:
  """Every resource name in the tree, so a link to one can be recognised as a link."""
  found = [resource.name]
  for child in resource.children:
    found.extend(_all_names(child))
  return found


def _serialize_tree(resource: Resource) -> Dict[str, Any]:
  """The existing visualizer's payload shape, for the comparison only."""
  data = resource.serialize()
  data["children"] = [_serialize_tree(child) for child in resource.children]
  return data


def collect_state(root: Resource) -> Dict[str, Dict[str, Any]]:
  """Tracker state for every resource that publishes any, keyed by name.

  Only resources whose state says something beyond the base rotation are included, so a scene of
  mostly static geometry sends a small message.
  """
  state: Dict[str, Dict[str, Any]] = {}

  def walk(resource: Resource) -> None:
    published = resource.serialize_state()
    if published and set(published) - {"rotation"}:
      state[resource.name] = published
    for child in resource.children:
      walk(child)

  walk(root)
  return state


def find(root: Resource, name: str) -> Optional[Resource]:
  """The descendant called `name`, or None."""
  if root.name == name:
    return root
  for child in root.children:
    hit = find(child, name)
    if hit is not None:
      return hit
  return None
