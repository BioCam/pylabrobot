# Hamilton

Hamilton machines fall into two protocol families that share only the cable.

- **Text grammar** — `<module><command>id####<params>`, with replies carrying an `er` field.
  STAR, STARLet, Vantage, STAR V, the heater shaker box and the tilter.
- **Binary packets** — HARP/HOI frames over TCP. Prep and Nimbus.

The HEPA fan belongs to neither: a different USB vendor and raw binary frames.

Nothing above the transport is shared between the two.

## Layout

```
hamilton/
  io.py                 what a driver needs from a pylabrobot.io transport
  protocol/text/        framing + reply routing
  protocol/binary/      frames, messages, commands, enums, errors + connection
  <device>/             one folder per machine
```

Nothing here is a transport - that is `pylabrobot.io`. The two families are told apart by their
grammar, not their wire: the text grammar runs over USB, Ethernet and RS-232 depending on the
machine.

A text-family device is `<device>/driver/master.py` (the driver) plus `errors.py` (its own error
vocabulary). A binary-family device follows the shape in `prep/`.

## Layers

The seven OSI layers, numbered. Some we implement, some the bus or the operating system hands us.

| # | Layer | Text family | Binary family |
|---|---|---|---|
| 7 | Application | `<device>/driver/master.py` | `<device>/{device,client}.py` |
| 6 | Presentation | `protocol/text/framing.py` | `protocol/binary/{packets,messages,commands,enums}.py` |
| 5 | Session | — none | `protocol/binary/connection.py` |
| 4 | Transport | `protocol/text/router.py` | TCP, from the operating system |
| 3 | Network | module id, carried as a string | `protocol/binary/packets.py::Address`, over IP |
| 2 | Data link | USB bulk transfers, or 8N1 on a serial line | Ethernet frames |
| 1 | Physical | the cable | the cable |

`pylabrobot.io` covers whatever the bus provides beneath our protocol: layers 1-2 for `USB`,
`Serial` and `FTDI`; layers 1-4 for `Socket`, since TCP is itself layer 4.

**The two families sit at different layers, and it is not the symmetry you might expect.**

`ReplyRouter` is **transport (4)**, not session. It multiplexes several commands over one link and
demultiplexes the replies by `id####`, with a timeout per command - the job TCP does with ports. It
establishes no dialogue, so the text family has no session layer at all.

`HamiltonTCPConnection` is **session (5)**. It runs Protocol 7 initialization to obtain a client
id, then Protocol 3 registration, and only then exchanges commands - dialogue establishment,
textbook. It multiplexes nothing; TCP beneath it already provides layer 4.

So the text family implements transport and skips session; the binary family implements session and
inherits transport. The tilter implements neither: no id to multiplex, no handshake to establish.

## Machines

| Machine | Transport | Product id | Module id | Correlation | State |
|---|---|---|---|---|---|
| STAR / STARLet | USB | `0x8000` | 2 char | `id####` | driver + discovery |
| Vantage | USB | `0x8003` | 4 char | `id####` | connect and send |
| STAR V | Ethernet | — | node-routed | `id`, wide range | connect and send, unverified |
| Heater shaker box | USB | `0x8002` | `T<n>` | `id####` | connect and send |
| Tilt module | RS-232 | — | `T1` | none | stub; legacy driver only |
| Prep | TCP | `:2000` | `module:node:object` | sequence number, sequential | stub; open PR |
| Nimbus | TCP | `:2000` | `module:node:object` | sequence number, sequential | stub; branch only |
| HEPA fan | FTDI | `0x0856` | — | none | stub; legacy driver only |

A folder marked **stub** holds an empty `__init__.py` and nothing else. It exists so the set of
machines is visible; the work either lives elsewhere or has not started.

STAR addresses only the gateway (`C0`) so far: `setup()` asks it for the installed hardware, the
X-drive geometry and the channel count. No module has been addressed directly yet - the pipetting
channels, 96-head, iSWAP, autoload and wash stations are nodes on the same bus reached over the
same router, so each is a module to add rather than new plumbing.

## Writing a text-family driver

The driver owns its link and its vocabulary; the router owns only reply matching.

```python
self.io = io or USB(id_vendor=ID_VENDOR, id_product=ID_PRODUCT, ...)

self._replies = ReplyRouter(
  io=self.io,
  module_id_length=2,            # how wide a module id is
  parse_id=...,                  # read the id out of a reply
  raise_for_error=...,           # raise if the reply reports a fault
)
```

Sending a command runs through all three layers:

```python
id_ = self._replies.next_id()
cmd = assemble_command(module="C0", command="RT", id_=id_, num_channels=self._num_channels)
resp = await self._replies.send(cmd, id_)
return parse_fw_string(resp, fmt)
```

`setup()` opens the link then starts the router; `stop()` reverses it. The router is not a
connection - it holds no link lifecycle of its own.

A device that sits behind another machine's gateway takes a router rather than opening one:

```python
HeaterShakerDriver(index=1, replies=box.replies)    # its own control box
HeaterShakerDriver(index=1, replies=star.replies)   # the same shaker, through a STAR
```

## Conventions

- **Error syntax is shared, error meaning is not.** `find_error_fields` locates the `er` fields for
  any text-family machine. What trace code `06` *means* differs per machine - "parameter out of
  range" on a tilter, "too little liquid" on a STAR - so each keeps its own table in
  `<device>/driver/errors.py`.
- **A module addressed directly replies `er<trace>`; the master replies `er<code>/<trace>`** and may
  append one field per failing module.
- **A device behind a gateway takes the router it should speak over** rather than opening one. A
  heater shaker is module `T<n>` whether it sits on its own box or on a STAR.
- **Several machines mean several routers.** Each driver builds its own link, id counter and
  reader thread; USB tells identical devices apart by `device_address` or `serial_number`.
- **A module id is a node address.** The gateway routes to modules over the instrument's internal
  bus, which is why the same heater shaker is reachable through two different gateways. The text
  family carries the address as a string; the binary family models it as `Address`.
