# Small PRNGs

This method recovers the hidden state or a small seed of a predictable random-number generator. If that generator directly supplies the key bytes, recovering its state lets you reproduce later keys.

## What it needs

Several disclosed outputs, the exact generator, and the order in which it was called. A search over seeds also needs a clearly defined seed range.

## Run the example

From the collection root:

```bash
python3 -B small-prng/example.py
```

The example recovers a xorshift state, an LCG state, and a Python generator seed. It then checks predicted keys against the public keys generated for the example.

## Limits

The result applies to the stated generator and key format. A small seed search covers only the range it actually checks.

## Code

- [example.py](example.py)
- [recovery.py](recovery.py)
- [test_recovery.py](test_recovery.py)

[Overview](../README.md)
