from pylabrobot.resources.height_volume_functions import (
  calculate_liquid_volume_container_2segments_square_vbottom,
)
from pylabrobot.resources.plate import Lid, Plate
from pylabrobot.resources.utils import create_ordered_items_2d
from pylabrobot.resources.well import (
  CrossSectionType,
  Well,
  WellBottomType,
)


def _compute_volume_from_height_Cor_Axy_24_wellplate_10ml_Vb(h: float):
  if h > 42.1:
    raise ValueError(f"Height {h} is too large for Cor_Axy_24_wellplate_10ml_Vb")
  return calculate_liquid_volume_container_2segments_square_vbottom(
    x=17, y=17, h_pyramid=5, h_cube=37, liquid_height=h
  )


def Cor_Axy_24_wellplate_10ml_Vb_Lid(name: str) -> Lid:
  raise NotImplementedError("This lid is not currently defined.")
  # See https://github.com/PyLabRobot/pylabrobot/pull/161.
  # return Lid(
  #   name=name,
  #   size_x=127.76,
  #   size_y=86.0,
  #   size_z=5,
  #   nesting_z_height=None, # measure overlap between lid and plate
  #   model="Gre_1536_Sq_Lid",
  # )


#: Cor_Axy_24_wellplate_10ml_Vb
def Cor_Axy_24_wellplate_10ml_Vb(name: str, with_lid: bool = False) -> Plate:
  return Plate(
    name=name,
    size_x=127.76,
    size_y=85.48,
    size_z=44.24,
    lid=Cor_Axy_24_wellplate_10ml_Vb_Lid(name + "_lid") if with_lid else None,
    model="Cor_Axy_24_wellplate_10ml_Vb",
    ordered_items=create_ordered_items_2d(
      Well,
      num_items_x=6,
      num_items_y=4,
      dx=9.8,
      dy=7.2,
      dz=0.63,
      item_dx=18,
      item_dy=18,
      size_x=17.0,
      size_y=17.0,
      size_z=42,
      bottom_type=WellBottomType.V,
      material_z_thickness=1.44,
      compute_volume_from_height=_compute_volume_from_height_Cor_Axy_24_wellplate_10ml_Vb,
      cross_section_type=CrossSectionType.RECTANGLE,
    ),
  )
