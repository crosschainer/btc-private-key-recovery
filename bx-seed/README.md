# BX seed recovery

This method searches the small generator state behind a seed string. A seed can contain many bytes while still having only a limited number of possible starting states.

## What it needs

The seed engine, byte-generation rule, seed length, wallet path, and a bounded state range.

## Run the example

From the collection root:

```bash
python3 -B bx-seed/example.py
```

The example searches 32 states, recovers the state that generated a test seed, and verifies two later wallet keys. The reference tests also check published BIP32 vectors.

## Limits

The example does not search the full state domain. A recovered state is meaningful only for the exact seed recipe and wallet settings being tested.

## Code

- [example.py](example.py)
- [reference.py](reference.py)
- [recovery.py](recovery.py)
- [seed_space.py](seed_space.py)
- [test_reference.py](test_reference.py)
- [test_recovery.py](test_recovery.py)

[Pinned seed recipe](https://github.com/libbitcoin/libbitcoin-explorer/blob/aae99b278fdbfa31005cfa083ccbbf909212cbe4/src/utility/utility.cpp)

[Overview](../README.md)
