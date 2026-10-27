# Hash and counter feedback

This method applies when a shortened key is fed back into the process that creates the next key. If that shortened key is disclosed, it can expose the complete input to the next step.

## What it needs

Several disclosed keys and a finite set of possible encodings, hashes, counters, and update rules. The shortened key must actually be used as feedback.

## Run the example

From the collection root:

```bash
python3 -B masking-feedback/example.py
```

The example checks 34,272 possible rules, identifies one from known-answer values, and verifies two subsequent keys. It also rejects an altered observation.

## Limits

This does not invert a hash. It reproduces the next step from a known input. A wallet that keeps its full internal state while exporting shortened copies behaves differently.

## Code

- [example.py](example.py)
- [feedback.py](feedback.py)
- [test_feedback.py](test_feedback.py)

[Overview](../README.md)
