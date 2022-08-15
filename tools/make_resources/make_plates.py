""" Create Python representations of various VENUS Method Editor resources. """
# pylint: skip-file

import os
import sys
from maker import make

sys.path.insert(0, '..')

from pylabrobot.utils.file_parsing import find_int, find_float, find_string


BASE_DIR = "./LabWare/Corning-Costar"
BASE_CLASS = "Plate"
OUT_FILE = "plates.py"


def make_from_file(fn, o):
  with open(fn, 'r', encoding='ISO-8859-1') as f:
    c = f.read()

  size_x = find_float('Dim.Dx', c)
  size_y = find_float('Dim.Dy', c)
  size_z = find_float('Dim.Dz', c)
  tip_type = None

  num_wells_x = find_int('Columns', c)
  num_wells_y = find_int('Rows', c)
  well_size_x = find_float('Dx', c)
  well_size_y = find_float('Dy', c)

  dx = find_float('BndryX', c) or 0
  dy = find_float('BndryY', c) or 0
  dz = 0

  cname = os.path.basename(fn).split('.')[0]
  description = cname
  EqnOfVol = None
  one_dot_max = None

  # .rck to .ctr filename
  def rck2ctr(fn):
    return fn.replace("_P.rck", ".ctr").replace("_L.rck", ".ctr").replace(".rck", ".ctr") \
      .replace("ProtCryst", "Post")

  with open(rck2ctr(fn), 'r', encoding='ISO-8859-1') as f2:
    c2 = f2.read()
    EqnOfVol = find_string("1.EqnOfVol", c2)
    dz = find_float("BaseMM", c2)

    one_dot_max = find_float('1.Max', c2)

  o.write(f'\n\n')
  o.write(f"class {cname}({BASE_CLASS}):\n")
  o.write(f'  """ {description} """\n')
  o.write('\n')
  o.write(f'  def __init__(\n')
  o.write(f'    self,\n')
  o.write(f'    name: str,\n')
  o.write(f'    location: Coordinate = Coordinate(None, None, None),\n')
  o.write(f'    with_lid: bool = False\n')
  o.write(f'  ):\n')
  o.write(f'    super().__init__(\n')
  o.write(f'      name=name,\n')
  o.write(f'      location=location,\n')
  o.write(f'      size_x={size_x},\n')
  o.write(f'      size_y={size_y},\n')
  o.write(f'      size_z={size_z},\n')
  o.write(f'      dx={dx},\n')
  o.write(f'      dy={dy},\n')
  o.write(f'      dz={dz},\n')
  o.write(f'      num_wells_x={num_wells_x},\n')
  o.write(f'      num_wells_y={num_wells_y},\n')
  o.write(f'      well_size_x={well_size_x},\n')
  o.write(f'      well_size_y={well_size_y},\n')
  o.write(f'      one_dot_max={one_dot_max},\n')
  o.write(f'      lid_height=10 if with_lid else None\n')
  o.write(f'    )\n')
  o.write(f'\n')
  o.write(f'  def compute_volume_from_height(self, h):\n')
  o.write(f'    return {EqnOfVol}\n')


if __name__ == "__main__":
  make(
    base_dir=BASE_DIR,
    out_file=OUT_FILE,
    pattern=r'[\S]+\.rck',
    make_from_file=make_from_file
  )
