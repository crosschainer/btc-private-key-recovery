# .NET Random state constraints

This method checks which internal states of the subtractive System.Random generator could have produced disclosed bytes. A fast byte-level check narrows the possibilities, and an exact solver checks complete states.

## What it needs

The byte layout, call schedule, and enough disclosed output. Short samples can fit many different internal states.

## Run the example

From the collection root:

```bash
python3 -B dotnet-random/example.py
```

The small example finds and replays a compatible state. It deliberately reports that the original generating state has not been uniquely identified.

## Limits

Passing the byte check is not recovery. An exact fit can still be ambiguous, and the solver can reach its time limit. For constructor-generated streams, the seed-recovery method provides a more constrained search.

## Code

- [example.py](example.py)
- [reference.py](reference.py)
- [screen.py](screen.py)
- [exact_solver.py](exact_solver.py)
- [audit.py](audit.py)
- [test_screen.py](test_screen.py)
- [test_exact.py](test_exact.py)

[Constructor seed recovery](../dotnet-seed/README.md)

[Microsoft Reference Source](https://github.com/microsoft/referencesource/blob/9da503f9ef21e8d1f2905c78d4e3e5cbb3d6f85a/mscorlib/system/random.cs)

[Overview](../README.md)
