import functools
import inspect
import json
import logging
import time
import typing
from typing import Union, Optional, List

import pylabrobot.utils.file_parsing as file_parser
from pylabrobot.liquid_handling.resources.abstract import Deck
from pylabrobot import utils

from .backends import LiquidHandlerBackend
from . import resources
from .liquid_classes import (
  LiquidClass,
  StandardVolumeFilter_Water_DispenseSurface_Part_no_transport_vol
)
from .resources import (
  Resource,
  Coordinate,
  Carrier,
  Hotel,
  Lid,
  Plate,
  Tips
)

logger = logging.getLogger(__name__) # TODO: get from somewhere else?


_RAILS_WIDTH = 22.5 # space between rails (mm)


class AspirationInfo:
  """ AspirationInfo is a class that contains information about an aspiration.

  This class is be used by
  :meth:`pyhamilton.liquid_handling.liquid_handler.LiquidHandler.aspirate` to store information
  about the aspiration for each individual channel.

  Examples:
    Directly initialize the class:

    >>> aspiration_info = AspirationInfo('A1', 50)
    >>> aspiration_info.position
    'A1'
    >>> aspiration_info.volume
    50

    Instantiate an aspiration info object from a tuple:

    >>> AspirationInfo.from_tuple(('A1', 50))
    AspirationInfo(position='A1', volume=50)

    Instantiate an aspiration info object from a dict:

    >>> AspirationInfo.from_dict({'position': 'A1', 'volume': 50})
    AspirationInfo(position='A1', volume=50)

    Get the corrected volume, using the default liquid class
    (:class:`pyhamilton.liquid_handling.liquid_classes.StandardVolumeFilter_Water_DispenseSurface_Part_no_transport_vol`):

    >>> aspiration_info = AspirationInfo('A1', 100)
    >>> aspiration_info.get_corrected_volume()
    107.2
  """

  def __init__(
    self,
    position: str,
    volume: float,
    liquid_class: LiquidClass = StandardVolumeFilter_Water_DispenseSurface_Part_no_transport_vol
  ):
    """ Initialize the aspiration info.

    Args:
      position: The position of the aspiration. Positions are formatted as `<row><column>` where
        `<row>` is the row string (`A` for row 1, `B` for row 2, etc.) and `<column>` is the column
        number. For example, `A1` is the top left corner of the resource and `H12` is the bottom
        right.
      volume: The volume of the aspiration.
      liquid_class: The liquid class of the aspiration.
    """

    self.position = position
    self.volume = volume
    self.liquid_class = liquid_class

  @classmethod
  def from_tuple(cls, tuple_):
    """ Create aspiration info from a tuple.

    The tuple should either be in the form (position, volume) or (position, volume, liquid_class).
    In the former case, the liquid class will be set to
    `StandardVolumeFilter_Water_DispenseSurface_Part_no_transport_vol`. (TODO: link to liquid class
    in docs)

    Args:
      tuple: A tuple in the form (position, volume) or (position, volume, liquid_class)

    Returns:
      AspirationInfo object.

    Raises:
      ValueError if the tuple is not in the correct format.
    """

    if len(tuple_) == 2:
      position, volume = tuple_
      return cls(position, volume)
    elif len(tuple_) == 3:
      position, volume, liquid_class = tuple_
      return cls(position, volume, liquid_class)
    else:
      raise ValueError("Invalid tuple length")

  @classmethod
  def from_dict(cls, dict_):
    """ Create aspiration info from a dictionary.

    The dictionary should either be in the form {"position": position, "volume": volume} or
    {"position": position, "volume": volume, "liquid_class": liquid_class}. In the former case,
    the liquid class will be set to
    `StandardVolumeFilter_Water_DispenseSurface_Part_no_transport_vol`.

    Args:
      dict: A dictionary in the form {"position": position, "volume": volume} or
        {"position": position, "volume": volume, "liquid_class": liquid_class}

    Returns:
      AspirationInfo object.

    Raises:
      ValueError: If the dictionary is invalid.
    """

    if "position" in dict_ and "volume" in dict_:
      position = dict_["position"]
      volume = dict_["volume"]
      return cls(
        position=position,
        volume=volume,
        liquid_class=dict_.get("liquid_class",
          StandardVolumeFilter_Water_DispenseSurface_Part_no_transport_vol))

    raise ValueError("Invalid dictionary")

  def __repr__(self):
    return f"AspirationInfo(position={self.position}, volume={self.volume})"

  def get_corrected_volume(self):
    """ Get the corrected volume.

    The corrected volume is computed based on various properties of a liquid, as defined by the
    :class:`pyhamilton.liquid_handling.liquid_classes.LiquidClass` object.

    Returns:
      The corrected volume.
    """

    return self.liquid_class.compute_corrected_volume(self.volume)

  def serialize(self):
    """ Serialize the aspiration info.

    Returns:
      A dictionary containing the serialized dispense info.
    """

    return {
      "position": self.position,
      "volume": self.volume,
      "liquid_class": self.liquid_class.__class__.__name__
    }


class DispenseInfo:
  """ DispenseInfo is a class that contains information about an dispense.

  This class is be used by
  :meth:`pyhamilton.liquid_handling.liquid_handler.LiquidHandler.aspirate` to store information
  about the dispense for each individual channel.

  Examples:
    Directly initialize the class:

    >>> dispense_info = DispenseInfo('A1', 0.5)
    >>> dispense_info.position
    'A1'
    >>> dispense_info.volume
    0.5

    Instantiate an dispense info object from a tuple:

    >>> DispenseInfo.from_tuple(('A1', 0.5))
    DispenseInfo(position='A1', volume=0.5)

    Instantiate an dispense info object from a dict:

    >>> DispenseInfo.from_dict({'position': 'A1', 'volume': 0.5})
    DispenseInfo(position='A1', volume=0.5)

    Get the corrected volume:

    >>> dispense_info = DispenseInfo('A1', 100)
    >>> dispense_info.get_corrected_volume()
    107.2
  """

  def __init__(
    self,
    position: str,
    volume: float,
    liquid_class: LiquidClass = StandardVolumeFilter_Water_DispenseSurface_Part_no_transport_vol
  ):
    """ Initialize the dispense info.

    Args:
      position: The position of the dispense. Positions are formatted as `<row><column>` where
        `<row>` is the row string (`A` for row 1, `B` for row 2, etc.) and `<column>` is the column
        number. For example, `A1` is the top left corner of the resource and `H12` is the bottom
        right.
      volume: The volume of the dispense.
      liquid_class: The liquid class of the dispense.
    """

    self.position = position
    self.volume = volume
    self.liquid_class = liquid_class

  @classmethod
  def from_tuple(cls, tuple_):
    """ Create dispense info from a tuple.

    The tuple should either be in the form (position, volume) or (position, volume, liquid_class).
    In the former case, the liquid class will be set to
    `StandardVolumeFilter_Water_DispenseSurface_Part_no_transport_vol`. (TODO: link to liquid class
    in docs)

    Args:
      tuple: A tuple in the form (position, volume) or (position, volume, liquid_class)

    Returns:
      DispenseInfo object.

    Raises:
      ValueError if the tuple is not in the correct format.
    """

    if len(tuple_) == 2:
      position, volume = tuple_
      return cls(position, volume)
    elif len(tuple_) == 3:
      position, volume, liquid_class = tuple_
      return cls(position, volume, liquid_class)
    else:
      raise ValueError("Invalid tuple length")

  @classmethod
  def from_dict(cls, dict):
    """ Create dispense info from a dictionary.

    The dictionary should either be in the form {"position": position, "volume": volume} or
    {"position": position, "volume": volume, "liquid_class": liquid_class}. In the former case,
    the liquid class will be set to
    `StandardVolumeFilter_Water_DispenseSurface_Part_no_transport_vol`.

    Args:
      dict: A dictionary in the form {"position": position, "volume": volume} or
        {"position": position, "volume": volume, "liquid_class": liquid_class}

    Returns:
      DispenseInfo object.

    Raises:
      ValueError: If the dictionary is invalid.
    """

    if "position" in dict and "volume" in dict:
      position = dict["position"]
      volume = dict["volume"]
      return cls(
        position=position,
        volume=volume,
        liquid_class=dict.get("liquid_class",
          StandardVolumeFilter_Water_DispenseSurface_Part_no_transport_vol))

    raise ValueError("Invalid dictionary")

  def __repr__(self):
    return f"DispenseInfo(position={self.position}, volume={self.volume})"

  def get_corrected_volume(self):
    """ Get the corrected volume.

    The corrected volume is computed based on various properties of a liquid, as defined by the
    :class:`pyhamilton.liquid_handling.liquid_classes.LiquidClass` object.

    Returns:
      The corrected volume.
    """

    return self.liquid_class.compute_corrected_volume(self.volume)

  def serialize(self):
    """ Serialize the dispense info.

    Returns:
      A dictionary containing the serialized dispense info.
    """

    return {
      "position": self.position,
      "volume": self.volume,
      "liquid_class": self.liquid_class.__class__.__name__
    }


class LiquidHandler:
  """
  Front end for liquid handlers.

  This class is the front end for liquid handlers; it provides a high-level interface for
  interacting with liquid handlers. In the background, this class uses the low-level backend (
  defined in `pyhamilton.liquid_handling.backends`) to communicate with the liquid handler.

  This class is responsible for:
    - Parsing and validating the layout.
    - Performing liquid handling operations. This includes:
      - Aspirating from / dispensing liquid to a location.
      - Transporting liquid from one location to another.
      - Picking up tips from and dropping tips into a tip box.
    - Serializing and deserializing the liquid handler deck. Decks are serialized as JSON and can
      be loaded from a JSON or .lay (legacy) file.
    - Static analysis of commands. This includes checking the presence of tips on the head, keeping
      track of the number of tips in the tip box, and checking the volume of liquid in the liquid
      handler.

  Attributes:
    setup_finished: Whether the liquid handler has been setup.
  """

  def __init__(self, backend: LiquidHandlerBackend):
    """ Initialize a LiquidHandler.

    Args:
      backend: Backend to use.
    """

    self.backend = backend
    self.setup_finished = False

    self.deck = Deck(
      resource_assigned_callback=self.resource_assigned_callback,
      resource_unassigned_callback=self.resource_unassigned_callback,
      origin=Coordinate(0, 63, 100)
    )

  def need_setup_finished(func: typing.Callable): # pylint: disable=no-self-argument
    """ Decorator for methods that require the liquid handler to be set up.

    Checked by verifying `self.setup_finished` is `True`.

    Raises:
      RuntimeError: If the liquid handler is not set up.
    """

    @functools.wraps(func)
    def wrapper(self, *args, **kwargs):
      if not self.setup_finished:
        raise RuntimeError("The setup has not finished. See `LiquidHandler.setup`.")
      func(self, *args, **kwargs) # pylint: disable=not-callable
    return wrapper

  def setup(self):
    """ Prepare the robot for use. """

    if self.setup_finished:
      raise RuntimeError("The setup has already finished. See `LiquidHandler.stop`.")

    self.backend.setup()
    self.setup_finished = True

  def stop(self):
    self.backend.stop()
    self.setup_finished = False

  def __enter__(self):
    self.setup()
    return self

  def __exit__(self, *exc):
    self.stop()
    return False

  @staticmethod
  def _x_coordinate_for_rails(rails: int):
    """ Convert a rail identifier (1-30 for STARLet, max 54 for STAR) to an x coordinate. """
    return 100.0 + (rails - 1) * _RAILS_WIDTH

  @staticmethod
  def _rails_for_x_coordinate(x: int):
    """ Convert an x coordinate to a rail identifier (1-30 for STARLet, max 54 for STAR). """
    return int((x - 100.0) / _RAILS_WIDTH) + 1

  def assign_resource(
    self,
    resource: Resource,
    rails: typing.Optional[int] = None, # board location, 1..52
    location: typing.Optional[Coordinate] = None,
    # y: int, # board location, x..y?
    replace: bool = False
  ):
    """ Assign a new deck resource.

    The identifier will be the Resource.name, which must be unique amongst previously assigned
    resources.

    Note that some resources, such as tips on a tip carrier or plates on a plate carrier must
    be assigned directly to the tip or plate carrier respectively. See TipCarrier and PlateCarrier
    for details.

    Based on the rails argument, the absolute (x, y, z) coordinates will be computed.

    Args:
      resource: A Resource to assign to this liquid handler.
      rails: The left most real (inclusive) of the deck resource (between and 1-30 for STARLet,
             max 54 for STAR.) Either rails or location must be None, but not both.
      location: The location of the resource relative to the liquid handler. Either rails or
                location must be None, but not both.
      replace: Replace the resource with the same name that was previously assigned, if it exists.
               If a resource is assigned with the same name and replace is False, a ValueError
               will be raised.

    Raises:
      ValueError: If a resource is assigned with the same name and replace is `False`.
    """

    # TODO: most things here should be handled by Deck.

    if (rails is not None) == (location is not None):
      raise ValueError("Rails or location must be None.")

    if rails is not None and not 1 <= rails <= 30:
      raise ValueError("Rails must be between 1 and 30.")

    # Check if resource exists.
    if self.deck.has_resource(resource.name):
      if replace:
        # unassign first, so we don't have problems with location checking later.
        self.unassign_resource(resource.name)
      else:
        raise ValueError(f"Resource with name '{resource.name}' already defined.")

    # Set resource location.
    if rails is not None:
      resource.location = Coordinate(x=LiquidHandler._x_coordinate_for_rails(rails), y=0, z=0)
    else:
      resource.location = location

    if resource.location.x + resource.get_size_x() > LiquidHandler._x_coordinate_for_rails(30) and \
      rails is not None:
      raise ValueError(f"Resource with width {resource.get_size_x()} does not fit at rails {rails}.")

    # Check if there is space for this new resource.
    for og_resource in self.deck.get_resources():
      og_x = og_resource.get_absolute_location().x
      og_y = og_resource.get_absolute_location().y

      # hack parent to get the absolute location.
      resource.parent = self.deck

      # A resource is not allowed to overlap with another resource. Resources overlap when a corner
      # of one resource is inside the boundaries other resource.
      if (og_x <= resource.get_absolute_location().x < og_x + og_resource.get_size_x() or \
         og_x <= resource.get_absolute_location().x + resource.get_size_x() < og_x + og_resource.get_size_x()) and\
          (og_y <= resource.get_absolute_location().y < og_y + og_resource.get_size_y() or \
            og_y <= resource.get_absolute_location().y + resource.get_size_y() < og_y + og_resource.get_size_y()):
        # resource.location = None # Revert location.
        # resource.parent = None # Revert parent.
        if rails is not None:
          if not (replace and resource.name == og_resource.name):
            raise ValueError(f"Rails {rails} is already occupied by resource '{og_resource.name}'.")
        else:
          # raise ValueError(f"Location {location} is already occupied by resource '{og_resource.name}'.")
          pass

    self.deck.assign_child_resource(resource)

  def resource_assigned_callback(self, resource: Resource):
    self.backend.assigned_resource_callback(resource)

  def resource_unassigned_callback(self, resource: Resource):
    self.backend.unassigned_resource_callback(resource)

  def unassign_resource(self, resource: typing.Union[str, Resource]):
    """ Unassign an assigned resource.

    Args:
      resource: The resource to unassign.

    Raises:
      KeyError: If the resource is not currently assigned to this liquid handler.
    """

    if isinstance(resource, Resource):
      resource = resource.name

    r = self.deck.get_resource(resource)
    if r is None:
      raise KeyError(f"Resource '{resource}' is not assigned to this liquid handler.")
    r.unassign()

  def get_resource(self, name: str) -> typing.Optional[Resource]:
    """ Find a resource on the deck of this liquid handler. Also see :meth:`~Deck.get_resource`.

    Args:
      name: name of the resource.

    Returns:
      The resource with the given name, or None if not found.
    """

    return self.deck.get_resource(name)

  def summary(self):
    """ Prints a string summary of the deck layout.

    Example:
      Printing a summary of the deck layout:

      >>> lh.summary()
      Rail     Resource                   Type                Coordinates (mm)
      ===============================================================================================
      (1) ├── tip_car                    TIP_CAR_480_A00     (x: 100.000, y: 240.800, z: 164.450)
          │   ├── tips_01                STF_L               (x: 117.900, y: 240.000, z: 100.000)
    """

    if len(self.deck.get_resources()) == 0:
      raise ValueError(
          "This liquid editor does not have any resources yet. "
          "Build a layout first by calling `assign_resource()`. "
          "See the documentation for details. (TODO: link)"
      )

    # Print header.
    print(utils.pad_string("Rail", 9) + utils.pad_string("Resource", 27) + \
          utils.pad_string("Type", 20) + "Coordinates (mm)")
    print("=" * 95)

    def print_resource(resource):
      # TODO: print something else if resource is not assigned to a rails.
      rails = LiquidHandler._rails_for_x_coordinate(resource.location.x)
      rail_label = utils.pad_string(f"({rails})", 4)
      print(f"{rail_label} ├── {utils.pad_string(resource.name, 27)}"
            f"{utils.pad_string(resource.__class__.__name__, 20)}"
            f"{resource.get_absolute_location()}")

      if isinstance(resource, Carrier):
        for site in resource.get_sites():
          if site.resource is None:
            print("     │   ├── <empty>")
          else:
            # Get subresource using `self.get_resource` to update it with the new location.
            subresource = site.resource
            print(f"     │   ├── {utils.pad_string(subresource.name, 27-4)}"
                  f"{utils.pad_string(subresource.__class__.__name__, 20)}"
                  f"{subresource.get_absolute_location()}")

    # Sort resources by rails, left to right in reality.
    sorted_resources = sorted(self.deck.children, key=lambda r: r.get_absolute_location().x)

    # Print table body.
    print_resource(sorted_resources[0])
    for resource in sorted_resources[1:]:
      print("     │")
      print_resource(resource)

  def load_from_lay_file(self, fn: str):
    """ Parse a .lay file (legacy layout definition) and build the layout on this liquid handler.

    Args:
      fn: Filename of .lay file.
    """

    c = None
    with open(fn, "r", encoding="ISO-8859-1") as f:
      c = f.read()

    # Get class names of all defined resources.
    resource_classes = [c[0] for c in inspect.getmembers(resources)]

    # Get number of items on deck.
    num_items = file_parser.find_int("Labware.Cnt", c)

    # Collect all items on deck.

    containers = {}
    children = {}

    for i in range(1, num_items+1):
      name = file_parser.find_string(f"Labware.{i}.Id", c)

      # get class name (generated from file name)
      file_name = file_parser.find_string(f"Labware.{i}.File", c).split("\\")[-1]
      class_name = None
      if ".rck" in file_name:
        class_name = file_name.split(".rck")[0]
      elif ".tml" in file_name:
        class_name = file_name.split(".tml")[0]

      if class_name in resource_classes:
        klass = getattr(resources, class_name)
        resource = klass(name=name)
      else:
        # TODO: replace with real template.
        # logger.warning(
          # "Resource with classname %s not found. Please file an issue at "
          # "https://github.com/pyhamilton/pyhamilton/issues/new?assignees=&"
          # "labels=&template=bug_report.md&title=Class\%20%s\%20not\%20found", class_name)
        continue

      # get location props
      # 'default' template means resource are placed directly on the deck, otherwise it
      # contains the name of the containing resource.
      if file_parser.find_string(f"Labware.{i}.Template", c) == "default":
        x = file_parser.find_float(f"Labware.{i}.TForm.3.X", c)
        y = file_parser.find_float(f"Labware.{i}.TForm.3.Y", c)
        z = file_parser.find_float(f"Labware.{i}.ZTrans", c)
        resource.location = Coordinate(x=x, y=y, z=z)
        containers[name] = resource
      else:
        children[name] = {
          "container": file_parser.find_string(f"Labware.{i}.Template", c),
          "site": file_parser.find_int(f"Labware.{i}.SiteId", c),
          "resource": resource}

    # Assign child resources to their parents.
    for child in children.values():
      cont = containers[child["container"]]
      cont[5 - child["site"]] = child["resource"]

    # Assign all resources to self.
    for cont in containers.values():
      self.assign_resource(cont, location=cont.location - Coordinate(0, 63.0, 100)) # TODO(63) fix

  def save(self, fn: str, indent: typing.Optional[int] = None):
    """ Save a deck layout to a JSON file.

    Args:
      fn: File name. Caution: file will be overwritten.
      indent: Same as `json.dump`'s `indent` argument (for json pretty printing).
    """

    serialized_resources = []

    for resource in self.deck.children:
      serialized_resources.append(resource.serialize())

    deck = dict(resources=serialized_resources)

    with open(fn, "w", encoding="utf-8") as f:
      json.dump(deck, f, indent=indent)

  def load_from_json(self, fn: str):
    """ Load deck layout serialized in a layout file.

    Args:
      fn: File name.
    """

    with open(fn, "r", encoding="utf-8") as f:
      content = json.load(f)
    dict_resources = content["resources"]

    # Get class names of all defined resources.
    resource_classes = [c[0] for c in inspect.getmembers(resources)]

    for resource_dict in dict_resources:
      klass_type = resource_dict["type"]
      location = Coordinate.deserialize(resource_dict.pop("location"))
      if klass_type in resource_classes: # properties pre-defined
        klass = getattr(resources, resource_dict["type"])
        resource = klass(name=resource_dict["name"])
      else: # read properties explicitly
        args = dict(
          name=resource_dict["name"],
          size_x=resource_dict["size_x"],
          size_y=resource_dict["size_y"],
          size_z=resource_dict["size_z"]
        )
        if "type" in resource_dict:
          args["type"] = resource_dict["type"]
        subresource = subresource_klass(**args)

      if "sites" in resource_dict:
        for subresource_dict in resource_dict["sites"]:
          if subresource_dict["resource"] is None:
            continue
          subtype = subresource_dict["resource"]["type"]
          if subtype in resource_classes: # properties pre-defined
            subresource_klass = getattr(resources, subtype)
            subresource = subresource_klass(name=subresource_dict["resource"]["name"])
            print(subresource)
          else: # Custom resources should deserialize the properties they serialized.
            subresource = subresource_klass(**subresource_dict["resource"])
          resource[subresource_dict["spot"]] = subresource

      print(resource, resource)
      self.assign_resource(resource, location=location)

  def load(self, fn: str, file_format: typing.Optional[str] = None):
    """ Load deck layout serialized in a file, either from a .lay or .json file.

    Args:
      fn: Filename for serialized model file.
      format: file format (`json` or `lay`). If None, file format will be inferred from file name.
    """

    extension = "." + (file_format or fn.split(".")[-1])
    if extension == ".json":
      self.load_from_json(fn)
    elif extension == ".lay":
      self.load_from_lay_file(fn)
    else:
      raise ValueError(f"Unsupported file extension: {extension}")

  def _assert_positions_unique(self, positions: typing.List[str]):
    """ Returns whether all items in `positions` are unique where they are not `None`.

    Args:
      positions: List of positions.
    """

    not_none = [p for p in positions if p is not None]
    if len(not_none) != len(set(not_none)):
      raise ValueError("Positions must be unique.")

  def _intelligently_convert_channel_params_to_channels(
    self,
    channel_1: Optional[str] = None,
    channel_2: Optional[str] = None,
    channel_3: Optional[str] = None,
    channel_4: Optional[str] = None,
    channel_5: Optional[str] = None,
    channel_6: Optional[str] = None,
    channel_7: Optional[str] = None,
    channel_8: Optional[str] = None,
  ) -> List[str]:
    """ Optionally intrapolate or extrapolate channels when the `...` (Ellipsis) operator is used.
    Removes trailing `None`s.

    Examples:
      Extrapolation along a diagonal:

      >>> _intelligently_convert_channel_params_to_channel("A1", "B2", ...)
      ["A1", "B2", "C3", "D4", "E5", "F6", "G7", "H8"]

      Extrapolation along a horizontal line:

      >>> _intelligently_convert_channel_params_to_channel("A1", "B1", ...)
      ["A1", "B1", "C1", "D1", "E1", "F1", "G1", "H1"]

      Intrapolation along a vertical line:

      >>> _intelligently_convert_channel_params_to_channel("A1", ..., "A5")
      ["A1", "A2", "A3", "A4", "A5"]

    Args:
      channels: Channel parameters.
    """

    channels = [channel_1, channel_2, channel_3, channel_4,
                channel_5, channel_6, channel_7, channel_8]

    if all(c is None for c in channels):
      raise ValueError("At least one channel must be specified.")

    self._assert_positions_unique(channels)

    if channels.count(...) == 0:
      # return all channels
      pass
    elif channels.count(...) == 1:
      if channel_1 is None or channel_2 is None or channel_3 is None:
        raise ValueError("Unable to infer channels: first three channels must be specified")

      if channel_1 == ...:
        raise ValueError("Unable to infer channels: first channel must not be ellipsis (...)")

      if not all(item is None for item in channels[3:]):
        raise ValueError("Unable to infer channels: too many channels specified")

      if channel_3 is ...: # parse `"A1", "B1", ...` (extrapolation)
        a, b = channel_1, channel_2
        if a == b:
          raise ValueError("Unable to infer channels: channels are the same")
        step_row = ord(b[0]) - ord(a[0])
        step_column = int(b[1:]) - int(a[1:])
        channels = [
          (chr(ord(a[0]) + i*step_row) + str(int(a[1:]) + i*step_column)) for i in range(8)
        ]
      elif channel_2 is ...: # parse `"A1", ..., "C1"` (intrapolation)
        start, end = channel_1, channel_3
        if start == end:
          raise ValueError("Invalid channels: channels are the same")
        start_row, end_row = ord(start[0]), ord(end[0])
        start_column, end_column = int(start[1:]), int(end[1:])
        num_rows = end_row - start_row + 1
        num_columns = end_column - start_column + 1

        if (end_row - start_row) != 0 and (end_column - start_column) != 0 and \
          num_rows != num_columns:
          raise ValueError("Unable to infer channels: the number of rows and columns " + \
            "do not match")

        num_items = max(num_rows, num_columns) # one of them might be 1, if constant dimension

        if num_items > 8:
          raise ValueError("Unable to infer channels: the number of items is too large")

        assert (end_row - start_row) % 1 == 0, "Delta in row must be an integer"
        assert (end_column - start_column) % 1 == 0, "Delta in column must be an integer"

        step_row = (end_row - start_row) // (num_items-1)
        step_column = (end_column - start_column) // (num_items-1)

        channels = [
          (chr(start_row + i*step_row) + str(start_column + i*step_column)) for i in range(num_items)
        ]
    else:
      raise ValueError("Unable to infer channels: too many ellipsis (...) operators")

    # assert min row is A and max row is H
    for channel in channels:
      if channel is not None and channel[0] not in "ABCDEFGH":
        raise ValueError("Invalid channel: row must be in A-H")

    # assert min column is 1 and max column is 12
    for channel in channels:
      if channel is not None and not channel[1:].isdigit() and int(channel[1:]) not in range(1, 13):
        raise ValueError("Invalid channel: column must be an integer")

    # remove trailing `None`s
    while channels[-1] is None:
      channels.pop()

    return channels

  @need_setup_finished
  def pickup_tips(
    self,
    resource: typing.Union[str, Tips],
    channel_1: typing.Optional[str] = None,
    channel_2: typing.Optional[str] = None,
    channel_3: typing.Optional[str] = None,
    channel_4: typing.Optional[str] = None,
    channel_5: typing.Optional[str] = None,
    channel_6: typing.Optional[str] = None,
    channel_7: typing.Optional[str] = None,
    channel_8: typing.Optional[str] = None,
    **backend_kwargs
  ):
    """ Pick up tips from a resource.

    Exampels:
      Pick up all tips in the first column.

      >>> lh.pickup_tips(tips_resource, "A1", "B1", "C1", "D1", "E1", "F1", "G1", "H1")

      Specifying each channel explicitly:

      >>> lh.pickup_tips(
      ...   tips_resource,
      ...   channel_1="A1",
      ...   channel_2="B1",
      ...   channel_3="C1",
      ...   channel_4="D1",
      ...   channel_5="E1",
      ...   channel_6="F1",
      ...   channel_7="G1",
      ...   channel_8="H1"
      ... )

      Pick up tips from the diagonal:

      >>> lh.pickup_tips(tips_resource, "A1", "B2", "C3", "D4", "E5", "F6", "G7", "H8")

      Using intelligent extrapolation along a column:

      >>> lh.pickup_tips(tips_resource, "A1", "B1", ...)

      Using intelligent extrapolation along the diagonal:

      >>> lh.pickup_tips(tips_resource, "A1", "B2", ...)

      Using intelligent intrapolation along the diagonal from `"A1"` to `"D4"`:

      >>> lh.pickup_tips(tips_resource, "A1", ..., "D4"

    Args:
      resource: Resource name or resource object.
      channel_1: The location where the tip will be picked up. If None, this channel will not pick
        up a tip.
      channel_2: The location where the tip will be picked up. If None, this channel will not pick
        up a tip.
      channel_3: The location where the tip will be picked up. If None, this channel will not pick
        up a tip.
      channel_4: The location where the tip will be picked up. If None, this channel will not pick
        up a tip.
      channel_5: The location where the tip will be picked up. If None, this channel will not pick
        up a tip.
      channel_6: The location where the tip will be picked up. If None, this channel will not pick
        up a tip.
      channel_7: The location where the tip will be picked up. If None, this channel will not pick
        up a tip.
      channel_8: The location where the tip will be picked up. If None, this channel will not pick
        up a tip.
      kwargs: Additional keyword arguments for the backend, optional.

    Raises:
      RuntimeError: If the setup has not been run. See :meth:`~LiquidHandler.setup`.

      ValueError: If no channel will pick up a tip, in other words, if all channels are `None`.

      ValueError: If the positions are not unique.
    """

    positions = [channel_1, channel_2, channel_3, channel_4,
                 channel_5, channel_6, channel_7, channel_8]
    positions = self._intelligently_convert_channel_params_to_channels(*positions)
    # pad `None`s to the end of the list to make length 8
    positions += [None] * (8 - len(positions))
    channel_1, channel_2, channel_3, channel_4, channel_5, channel_6, channel_7, channel_8 = positions

    # Get resource using `get_resource` to adjust location.
    if not isinstance(resource, str):
      if isinstance(resource, Tips):
        resource = resource.name
      else:
        raise ValueError("Resource must be a string or a Tips object.")
    resource = self.get_resource(resource)

    assert resource is not None, "Resource not found."

    self.backend.pickup_tips(
      resource,
      channel_1, channel_2, channel_3, channel_4, channel_5, channel_6, channel_7, channel_8,
      **backend_kwargs
    )

  @need_setup_finished
  def discard_tips(
    self,
    resource: typing.Union[str, Tips],
    channel_1: typing.Optional[str] = None,
    channel_2: typing.Optional[str] = None,
    channel_3: typing.Optional[str] = None,
    channel_4: typing.Optional[str] = None,
    channel_5: typing.Optional[str] = None,
    channel_6: typing.Optional[str] = None,
    channel_7: typing.Optional[str] = None,
    channel_8: typing.Optional[str] = None,
    **backend_kwargs
  ):
    """ Discard tips to a resource.

    Args:
      resource: Resource name or resource object.
      channel_1: The location where the tip will be discarded. If None, this channel will not
        discard a tip.
      channel_2: The location where the tip will be discarded. If None, this channel will not
        discard a tip.
      channel_3: The location where the tip will be discarded. If None, this channel will not
        discard a tip.
      channel_4: The location where the tip will be discarded. If None, this channel will not
        discard a tip.
      channel_5: The location where the tip will be discarded. If None, this channel will not
        discard a tip.
      channel_6: The location where the tip will be discarded. If None, this channel will not
        discard a tip.
      channel_7: The location where the tip will be discarded. If None, this channel will not
        discard a tip.
      channel_8: The location where the tip will be discarded. If None, this channel will not
        discard a tip.
      kwargs: Additional keyword arguments for the backend, optional.

    Raises:
      RuntimeError: If the setup has not been run. See :meth:`~LiquidHandler.setup`.

      ValueError: If no channel will pick up a tip, in other words, if all channels are `None`.

      ValueError: If the positions are not unique.
    """

    positions = [channel_1, channel_2, channel_3, channel_4,
                 channel_5, channel_6, channel_7, channel_8]
    positions = self._intelligently_convert_channel_params_to_channels(*positions)
    # pad `None` to make length 8
    positions += [None] * (8 - len(positions))
    channel_1, channel_2, channel_3, channel_4, channel_5, channel_6, channel_7, channel_8 = positions

    # Get resource using `get_resource` to adjust location.
    if not isinstance(resource, str):
      if isinstance(resource, Tips):
        resource = resource.name
      else:
        raise ValueError("Resource must be a string or a Tips object.")
    resource = self.get_resource(resource)

    assert resource is not None, "Resource not found."

    self.backend.discard_tips(
      resource,
      channel_1, channel_2, channel_3, channel_4, channel_5, channel_6, channel_7, channel_8,
      **backend_kwargs
    )

  @need_setup_finished
  def aspirate(
    self,
    resource: typing.Union[str, Resource],
    channel_1: typing.Optional[typing.Union[tuple, dict, AspirationInfo]] = None,
    channel_2: typing.Optional[typing.Union[tuple, dict, AspirationInfo]] = None,
    channel_3: typing.Optional[typing.Union[tuple, dict, AspirationInfo]] = None,
    channel_4: typing.Optional[typing.Union[tuple, dict, AspirationInfo]] = None,
    channel_5: typing.Optional[typing.Union[tuple, dict, AspirationInfo]] = None,
    channel_6: typing.Optional[typing.Union[tuple, dict, AspirationInfo]] = None,
    channel_7: typing.Optional[typing.Union[tuple, dict, AspirationInfo]] = None,
    channel_8: typing.Optional[typing.Union[tuple, dict, AspirationInfo]] = None,
    end_delay: float = 0,
    **backend_kwargs
  ):
    """Aspirate liquid from the specified channels.

    Examples:
      Aspirate liquid from the specified channels using a tuple:

      >>> aspirate("plate_01", ('A1', 50), ('B1', 50))

      Aspirate liquid from the specified channels using a dictionary:

      >>> aspirate("plate_02", {'position': 'A1', 'volume': 50}, {'position': 'B1', 'volume': 50})

      Aspirate liquid from the specified channels using an AspirationInfo object:

      >>> aspiration_info_1 = AspirationInfo('A1', 50)
      >>> aspiration_info_2 = AspirationInfo('B1', 50)
      >>> aspirate("plate_01", aspiration_info_1, aspiration_info_2)

    Args:
      resource: Resource name or resource object.
      channel_1: The aspiration info for channel 1.
      channel_2: The aspiration info for channel 2.
      channel_3: The aspiration info for channel 3.
      channel_4: The aspiration info for channel 4.
      channel_5: The aspiration info for channel 5.
      channel_6: The aspiration info for channel 6.
      channel_7: The aspiration info for channel 7.
      channel_8: The aspiration info for channel 8.
      end_delay: The delay after the last aspiration in seconds, optional. This is useful for when
        the tips used in the aspiration are dripping.
      backend_kwargs: Additional keyword arguments for the backend, optional.

    Raises:
      RuntimeError: If the setup has not been run. See :meth:`~LiquidHandler.setup`.

      ValueError: If the resource could not be found. See :meth:`~LiquidHandler.assign_resource`.

      ValueError: If the aspiration info is invalid, in other words, when all channels are `None`.

      ValueError: If all channels are `None`.
    """

    channels = [channel_1, channel_2, channel_3, channel_4,
                channel_5, channel_6, channel_7, channel_8]

    # Check that there is at least one channel specified
    if not any(channel is not None for channel in channels):
      raise ValueError("No channels specified")

    # Get resource using `get_resource` to adjust location.
    if isinstance(resource, Resource):
      resource = resource.name
    resource = self.get_resource(resource)
    if not resource:
      raise ValueError(f"Resource with name {resource} not found.")

    # Convert the channels to `AspirationInfo` objects
    channels_dict = {}
    for channel_idx, channel in enumerate(channels):
      if channel is None:
        channels_dict[f"channel_{channel_idx+1}"] = None
      elif isinstance(channel, tuple):
        channels_dict[f"channel_{channel_idx+1}"] = AspirationInfo.from_tuple(channel)
      elif isinstance(channel, dict):
        channels_dict[f"channel_{channel_idx+1}"] = AspirationInfo.from_dict(channel)
      elif isinstance(channel, AspirationInfo):
        channels_dict[f"channel_{channel_idx+1}"] = channel
      else:
        raise ValueError(f"Invalid channel type for channel {channel_idx+1}")

    self.backend.aspirate(resource, **channels_dict, **backend_kwargs)

    if end_delay > 0:
      time.sleep(end_delay)

  @need_setup_finished
  def dispense(
    self,
    resource: typing.Union[str, Resource],
    channel_1: typing.Optional[typing.Union[tuple, dict, DispenseInfo]] = None,
    channel_2: typing.Optional[typing.Union[tuple, dict, DispenseInfo]] = None,
    channel_3: typing.Optional[typing.Union[tuple, dict, DispenseInfo]] = None,
    channel_4: typing.Optional[typing.Union[tuple, dict, DispenseInfo]] = None,
    channel_5: typing.Optional[typing.Union[tuple, dict, DispenseInfo]] = None,
    channel_6: typing.Optional[typing.Union[tuple, dict, DispenseInfo]] = None,
    channel_7: typing.Optional[typing.Union[tuple, dict, DispenseInfo]] = None,
    channel_8: typing.Optional[typing.Union[tuple, dict, DispenseInfo]] = None,
    end_delay: float = 0,
    **backend_kwargs
  ):
    """Dispense liquid from the specified channels.

    Examples:
      Dispense liquid from the specified channels using a tuple:

      >>> dispense("plate_01", ('A1', 50), ('B1', 50))

      Dispense liquid from the specified channels using a dictionary:

      >>> dispense("plate_02", {'position': 'A1', 'volume': 50}, {'position': 'B1', 'volume': 50})

      Dispense liquid from the specified channels using an DispenseInfo object:

      >>> dispense_info_1 = DispenseInfo('A1', 50)
      >>> dispense_info_2 = DispenseInfo('B1', 50)
      >>> dispense("plate_01", dispense_info_1, dispense_info_2)

    Args:
      resource: Resource name or resource object.
      channel_1: The dispense info for channel 1.
      channel_2: The dispense info for channel 2.
      channel_3: The dispense info for channel 3.
      channel_4: The dispense info for channel 4.
      channel_5: The dispense info for channel 5.
      channel_6: The dispense info for channel 6.
      channel_7: The dispense info for channel 7.
      channel_8: The dispense info for channel 8.
      end_delay: The delay after the last dispense in seconds, optional. This is useful for when
        the tips used in the dispense are dripping.
      backend_kwargs: Additional keyword arguments for the backend, optional.

    Raises:
      RuntimeError: If the setup has not been run. See :meth:`~LiquidHandler.setup`.

      ValueError: If the resource could not be found. See :meth:`~LiquidHandler.assign_resource`.

      ValueError: If the dispense info is invalid, in other words, when all channels are `None`.

      ValueError: If all channels are `None`.
    """

    channels = [channel_1, channel_2, channel_3, channel_4,
                channel_5, channel_6, channel_7, channel_8]

    # Check that there is at least one channel specified
    if not any(channel is not None for channel in channels):
      raise ValueError("No channels specified")

    # Get resource using `get_resource` to adjust location.
    if isinstance(resource, Resource):
      resource = resource.name
    resource = self.get_resource(resource)
    if not resource:
      raise ValueError(f"Resource with name {resource} not found.")

    # Convert the channels to `DispenseInfo` objects
    channels_dict = {}
    for channel_id, channel in enumerate(channels):
      if channel is None:
        channels_dict[f"channel_{channel_id+1}"] = None
      elif isinstance(channel, tuple):
        channels_dict[f"channel_{channel_id+1}"] = AspirationInfo.from_tuple(channel)
      elif isinstance(channel, dict):
        channels_dict[f"channel_{channel_id+1}"] = AspirationInfo.from_dict(channel)
      elif isinstance(channel, AspirationInfo):
        channels_dict[f"channel_{channel_id+1}"] = channel
      else:
        raise ValueError(f"Invalid channel type for channel {channel_id+1}")

    self.backend.dispense(resource, **channels_dict, **backend_kwargs)

    if end_delay > 0:
      time.sleep(end_delay)

  def pickup_tips96(self, resource: typing.Union[str, Resource], **backend_kwargs):
    """ Pick up tips using the CoRe 96 head. This will pick up 96 tips.

    Examples:
      Pick up tips from an entire 96 tips plate:

      >>> lh.pickup_tips96("plate_01")

      Pick up tips from the left half of a 96 well plate:

      >>> lh.pickup_tips96("plate_01")

    Args:
      resource: Resource name or resource object.
      backend_kwargs: Additional keyword arguments for the backend, optional.
    """

    # Get resource using `get_resource` to adjust location.
    if isinstance(resource, Tips):
      resource = resource.name
    resource = self.get_resource(resource)
    if not resource:
      raise ValueError(f"Resource with name {resource} not found.")

    self.backend.pickup_tips96(resource, **backend_kwargs)

  def discard_tips96(self, resource: typing.Union[str, Resource], **backend_kwargs):
    """ Discard tips using the CoRe 96 head. This will discard 96 tips.

    Examples:
      Discard tips to an entire 96 tips plate:

      >>> lh.discard_tips96("plate_01")

    Args:
      resource: Resource name or resource object.
      backend_kwargs: Additional keyword arguments for the backend, optional.
    """

    # Get resource using `get_resource` to adjust location.
    if isinstance(resource, Tips):
      resource = resource.name
    if not self.get_resource(resource):
      raise ValueError(f"Resource with name {resource} not found.")
    resource = self.get_resource(resource)

    self.backend.discard_tips96(resource, **backend_kwargs)

  def aspirate96(
    self,
    resource: typing.Union[str, Resource],
    volume: float,
    pattern: typing.Union[typing.List[typing.List[bool]], str] = [[True]*12]*8,
    end_delay: float = 0,
    liquid_class: LiquidClass = StandardVolumeFilter_Water_DispenseSurface_Part_no_transport_vol,
    **backend_kwargs
  ):
    """ Aspirate liquid using the CoR96 head in the locations where pattern is `True`.

    Examples:
      Aspirate an entire 96 well plate:

      >>> lh.aspirate96("plate_01", "A1:H12", volume=50)

      Aspirate an entire 96 well plate:

      >>> lh.aspirate96("plate_01", [[True]*12]*8, volume=50)

      Aspirate from the left half of a 96 well plate:

      >>> lh.aspirate96("plate_01", "A1:H6", volume=50)

      Aspirate from the left half of a 96 well plate:

      >>> lh.aspirate96("plate_01", [[True]*6+[False]*6]*8], volume=50)

    Args:
      resource: Resource name or resource object.
      pattern: Either a list of lists of booleans where inner lists represent rows and outer lists
        represent columns, or a string representing a range of positions.
      volume: The volume to aspirate from each well.
      end_delay: The delay after the last aspiration in seconds, optional. This is useful for when
        the tips used in the aspiration are dripping.
      backend_kwargs: Additional keyword arguments for the backend, optional.
    """

    # Get resource using `get_resource` to adjust location.
    if isinstance(resource, Resource):
      resource = resource.name
    resource = self.get_resource(resource)
    if not resource:
      raise ValueError(f"Resource with name {resource} not found.")

    # Convert the pattern to a list of lists of booleans
    if isinstance(pattern, str):
      pattern = utils.string_to_pattern(pattern)

    utils.assert_shape(pattern, (8, 12))

    self.backend.aspirate96(resource, pattern, volume, **backend_kwargs)

    if end_delay > 0:
      time.sleep(end_delay)

  def dispense96(
    self,
    resource: typing.Union[str, Resource],
    # pattern: typing.Union[typing.List[typing.List[bool]], str],
    volume: float,
    pattern: typing.Union[typing.List[typing.List[bool]], str] = [[True]*12]*8,
    liquid_class: LiquidClass = StandardVolumeFilter_Water_DispenseSurface_Part_no_transport_vol,
    end_delay: float = 0,
    **backend_kwargs
  ):
    """ Dispense liquid using the CoR96 head in the locations where pattern is `True`.

    Examples:
      Dispense an entire 96 well plate:

      >>> dispense96("plate_01", [[True * 12] * 8], volume=50)

      Dispense an entire 96 well plate:

      >>> dispense96("plate_01", "A1:H12", volume=50)

      Dispense from the left half of a 96 well plate:

      >>> dispense96("plate_01", "A1:H6", volume=50)

      Dispense from the left half of a 96 well plate:

      >>> dispense96("plate_01", [[True]*6+[False]*6]*8], volume=50)

    Args:
      resource: Resource name or resource object.
      pattern: Either a list of lists of booleans where inner lists represent rows and outer lists
        represent columns, or a string representing a range of positions.
      volume: The volume to dispense to each well.
      end_delay: The delay after the last dispense in seconds, optional. This is useful for when
        the tips used in the dispense are dripping.
      backend_kwargs: Additional keyword arguments for the backend, optional.
    """

    # Get resource using `get_resource` to adjust location.
    if isinstance(resource, Resource):
      resource = resource.name
    resource = self.get_resource(resource)
    if not resource:
      raise ValueError(f"Resource with name {resource} not found.")

    # Convert the pattern to a list of lists of booleans
    if isinstance(pattern, str):
      pattern = utils.string_to_pattern(pattern)

    utils.assert_shape(pattern, (8, 12))

    self.backend.dispense96(resource, pattern, volume, **backend_kwargs)

    if end_delay > 0:
      time.sleep(end_delay)

  def move_plate(
    self,
    plate: typing.Union[Plate, Carrier.CarrierSite],
    target: typing.Union[Resource, Coordinate],
    **backend_kwargs
  ):
    """ Move a plate to a new location.

    Examples:
      Move a plate to a new location within the same carrier:

      >>> lh.move_plate(plt_car[0], plt_car[1])

      Move a plate to a new location within a different carrier:

      >>> lh.move_plate(plt_car[0], plt_car2[0])

      Move a plate to an absolute location:

      >>> lh.move_plate(plate_01, Coordinate(100, 100, 100))

    Args:
      plate: The plate to move. Can be either a Plate object or a CarrierSite object.
      target: The location to move the plate to, either a CarrierSite object or a Coordinate.
    """

    # Get plate from `plate` param. # (this could be a `Resource` too)
    if isinstance(plate, Carrier.CarrierSite):
      if plate.resource is None:
        raise ValueError(f"No resource found at CarrierSite '{plate}'.")
      plate = plate.resource
    elif isinstance(plate, str):
      plate = self.get_resource(plate)
      if not plate:
        raise ValueError(f"Resource with name '{plate}' not found.")

    if isinstance(target, Carrier.CarrierSite):
      if target.resource is not None:
        raise ValueError(f"There already exists a resource at {target}.")

    # Try to move the physical plate first.
    self.backend.move_plate(plate, target, **backend_kwargs)

    # Move the resource in the layout manager.
    plate.unassign()
    if isinstance(target, Resource):
      target.assign_child_resource(plate)
    elif isinstance(target, Coordinate):
      plate.location = target
      self.deck.assign_child_resource(plate) # Assign "free" objects directly to the deck.
    else:
      raise TypeError(f"Invalid location type: {type(target)}")

  def move_lid(
    self,
    lid: Lid,
    target: typing.Union[Plate, Hotel, Carrier.CarrierSite],
    **backend_kwargs
  ):
    """ Move a lid to a new location.

    Examples:
      Move a lid to the :class:`~resources.Hotel`:

      >>> lh.move_lid(plate.lid, hotel)

    Args:
      lid: The lid to move. Can be either a Plate object or a Lid object.
      to: The location to move the lid to, either a Resource object or a Coordinate.

    Raises:
      ValueError: If the lid is not assigned to a resource.
    """

    if isinstance(target, Carrier.CarrierSite):
      if target.resource is None:
        raise ValueError(f"No plate exists at {target}.")

    self.backend.move_lid(lid, target, **backend_kwargs)

    # Move the resource in the layout manager.
    lid.unassign()
    if isinstance(target, Resource):
      target.assign_child_resource(lid)
    elif isinstance(target, Coordinate):
      lid.location = target
      self.deck.assign_child_resource(lid) # Assign "free" objects directly to the deck.
    else:
      raise TypeError(f"Invalid location type: {type(target)}")
