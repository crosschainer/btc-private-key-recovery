# .NET Random seed recovery

This method uses the System.Random constructor to restrict the search to states that a valid seed can create. It filters possible seeds using disclosed output bytes, then replays each survivor through the exact constructor.

## What it needs

The constructor version, output layout, disclosed bytes, and the number of initial skipped draws. The included scanner uses a fixed initial offset.

## Run the example

From the collection root:

```bash
python3 -B dotnet-seed/example.py
```

The example searches the constructor domain, recovers the test seed magnitude, and verifies two later keys. Positive and negative seeds can produce the same stream, so the result identifies a magnitude.

## Limits

A different constructor or an unknown initial skip count changes the search. Exceptional constructor cases are replayed numerically rather than silently skipped.

## Code

- [example.py](example.py)
- [affine_model.py](affine_model.py)
- [scanner.cpp](scanner.cpp)
- [recovery.py](recovery.py)
- [audit.py](audit.py)
- [test_recovery.py](test_recovery.py)

[Overview](../README.md)
