from .container import Container
from .resource import Resource


class TrashHalo(Resource):
  """Visual frame around the trash area."""

  def __init__(self, name: str, size_x: float, size_y: float, size_z: float = 0):
    super().__init__(name=name, size_x=size_x, size_y=size_y, size_z=size_z, category="trash_halo")


class Trash(Container):
  """Trash area."""

  def __init__(
    self,
    name,
    size_x,
    size_y,
    size_z,
    material_z_thickness=0,
    max_volume=float("inf"),
    category="trash",
    model=None,
    compute_volume_from_height=None,
    compute_height_from_volume=None,
  ):
    super().__init__(
      name=name,
      size_x=size_x,
      size_y=size_y,
      size_z=size_z,
      material_z_thickness=material_z_thickness,
      max_volume=max_volume,
      category=category,
      model=model,
      compute_volume_from_height=compute_volume_from_height,
      compute_height_from_volume=compute_height_from_volume,
    )
