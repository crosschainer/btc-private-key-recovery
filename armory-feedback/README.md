# Masked multiplicative feedback

This method studies a custom feedback chain with a fixed secret chain code. Each disclosed shortened key constrains that shared secret value. The solver keeps refining the possibilities and replays complete candidates.

## What it needs

The exact feedback rule, its chain-code width, and enough disclosed keys from the chain.

## Run the example

From the collection root:

```bash
python3 -B armory-feedback/example.py
```

The example recovers an eight-bit chain code in a deliberately small model. The independent tests check its search against direct enumeration and full-width transition calculations.

## Limits

The small example demonstrates the recovery mechanism; it does not establish a practical full-width recovery. This custom construction is distinct from stock Armory wallet generation.

## Code

- [example.py](example.py)
- [recover.py](recover.py)
- [test_recover.py](test_recover.py)

[Overview](../README.md)
