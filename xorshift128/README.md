# Xorshift128

This method uses disclosed output bits to reconstruct the internal state of xorshift128. Once that state is known, the same stream of outputs can be generated again.

## What it needs

Enough output bits from the specified xorshift128 version, together with the byte order and any skipped calls.

## Run the example

From the collection root:

```bash
python3 -B xorshift128/example.py
```

The example reconstructs a 128-bit state from data produced by a separate C implementation, predicts later keys, and checks that altered observations are rejected.

## Limits

This implementation covers the original xor128 recurrence. Other generators with similar names can use different updates or output processing.

## Code

- [example.py](example.py)
- [recovery.py](recovery.py)
- [reference.c](reference.c)
- [native_reference.py](native_reference.py)
- [test_recovery.py](test_recovery.py)

[Overview](../README.md)
