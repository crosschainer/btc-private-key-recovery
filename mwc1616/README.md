# MWC1616

This method reconstructs the internal state of a multiply-with-carry generator from partly disclosed outputs. The solver checks which states could have produced the observed bytes.

## What it needs

The exact generator version, output format, byte order, and call schedule. The disclosed output must contain enough information to distinguish possible states.

## Run the example

From the collection root:

```bash
python3 -B mwc1616/example.py
```

The example recovers the state component exposed by its chosen output format and verifies a later key. It also checks that the recovered component is unique.

## Limits

Some output formats expose only one of the generator's two state components. A timeout or multiple possible states must be reported as unresolved.

## Code

- [example.py](example.py)
- [recovery.py](recovery.py)
- [high_bits.py](high_bits.py)
- [test_recovery.py](test_recovery.py)

[Direct-search example](direct/README.md)

[Overview](../README.md)
