# Device recordings

What a real PreciseFlex reported about itself, kept as data.

A recording is written by the driver, not by hand:

```python
await driver.setup()
driver.save_configuration("pf400_extended_400mm.json")
```

| arm | recording |
|---|---|
| PreciseFlex 400, extended reach, 400 mm of Z travel, vision server, no rail | `pf400_extended_400mm.json` |

It is every answer one arm gave to the driver's discovery, replayed from a session's IO log through
`discover` and saved. The one field changed afterwards is `controller_serial`, which is blanked: a
recording says what kind of arm it is, not which one.

## Derived, not recorded

`pf400_extended_1160mm_rail_derived.json` was not read off an arm. It is the recording above with
four values written in by hand, to stand for an arm nobody here has read: extended reach, the
1160 mm column, a 2 m rail, a vision gripper.

| value | recorded | written in | from |
|---|---|---|---|
| `arm.soft_limits.BASE` | 1.5 to 401.5 | 1.5 to 1161.5 | the 1160 mm column, with the recorded arm's 1.5 mm margin |
| `arm.hard_limits.BASE` | 0 to 402 | 0 to 1162 | likewise |
| `rail` | none | soft limits 0 to 2000, nothing else | the 2 m rail's travel |
| `has_vision_gripper` | false | true | - |

Everything else is the recorded arm's, including values a rail would change on a real controller:
the axis count, the axis mask, and every speed. It says how such an arm would be modelled. It is
not evidence of what its controller answers, and nothing that tests how answers are read uses it.
