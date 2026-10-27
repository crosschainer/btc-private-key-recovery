# MWC1616 direct search

This is an alternative to the solver: try every compatible state in a declared range and replay the output sequence. A fully observed output unit reduces the number of states that must be tried.

## What it needs

Consecutive observed output units, the generator multiplier, and the exact state interval to search.

## Run the example

From the collection root:

```bash
python3 -B mwc1616/direct/example.py
```

The example compiles the C scanner, checks 4,096 candidate states, recovers the matching state, and verifies a key derived from later output.

## Limits

The example checks a small interval. Its result does not claim that every possible generator state has been searched.

## Code

- [example.py](example.py)
- [mwc_scan.c](mwc_scan.c)
- [recovery.py](recovery.py)
- [test_direct.py](test_direct.py)

[Overview](../../README.md)
