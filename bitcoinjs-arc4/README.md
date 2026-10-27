# BitcoinJS ARC4 seed recovery

This method rebuilds the path from browser random output to an entropy pool, ARC4 seed bytes, and wallet keys. A small or predictable source state can make the resulting seed searchable.

## What it needs

The exact PRNG version, pool construction, time-mixing values, stream offset, and wallet derivation settings. The state search needs an explicit range.

## Run the example

From the collection root:

```bash
python3 -B bitcoinjs-arc4/example.py
```

The example recovers a state from a small synthetic range, reproduces its wallet keys, and verifies a later key.

## Limits

The time-mixing inputs are part of the assumed construction. Knowing when a transaction appeared does not reveal when a wallet seed was generated.

## Code

- [example.py](example.py)
- [pipeline.py](pipeline.py)
- [recovery.py](recovery.py)
- [test_pipeline.py](test_pipeline.py)
- [test_recovery.py](test_recovery.py)

[Pinned BitcoinJS source](https://github.com/bitcoinjs/bitcoinjs-lib/tree/ff625968ce776ac1d463ee5a36ca857477d3de8b/src)

[Overview](../README.md)
