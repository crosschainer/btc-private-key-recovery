# What the checks cover

Run every reference test and each fixed example from the repository root:

```bash
python3 -B verify.py
```

The checks use local code, generated wallets, and public test vectors. They make
no network requests and read no external wallet data.

All **97 tests** and **11 examples** pass. The separate masked-BIP32 constraint
analysis also passes. The detailed results are in [verification.json](verification.json).

| Area | Tests | What is checked |
| --- | ---: | --- |
| BX seeds | 12 | Seed recovery in small ranges, range boundaries, published BIP32 values, and seed-engine behavior. |
| Masked multiplicative feedback | 8 | Chain-code candidates, direct enumeration in small models, curve hashes, and resource limits. |
| Shared references | 5 | Independent curve arithmetic, byte mixing, RC4 vectors, and constructor arithmetic. |
| Small PRNGs | 3 | State recovery, corrupted outputs, and projected LCG states checked against complete small searches. |
| Xorshift128 | 3 | All 54 layouts against a separate C generator, new-output prediction, and contradiction checks. |
| Hash feedback | 15 | Known-answer hashes, encodings, counters, transitions, missing widths, and the rule list. |
| MWC1616 | 18 | Low-bit and high-bit observations, state replay, independent native enumeration, boundaries, and search accounting. |
| .NET Random state constraints | 10 | Byte constraints, independent replay, corrupted observations, exact solver models, and invalid state inputs. |
| .NET Random seeds | 9 | Constructor fixtures, ordinary and exceptional seeds, complete anchor scans, corruption, and timeouts. |
| BitcoinJS ARC4 | 14 | Pool and stream vectors, seed recovery in a small range, invalid settings, and rejection of altered observations. |

The eleven examples cover each method listed in the main README. They use fixed
test cases and check their results rather than merely printing candidate values.
The .NET state example explicitly leaves the original generating state
unidentified: it finds one compatible state from a short sample.

The masked-BIP32 examples include twelve generated parent-key recoveries and six
rejection checks. A separate analysis compares candidate counts with exhaustive
small cases and demonstrates a deliberately reduced 65,536-candidate search.

These checks establish the behavior of the included examples. They do not claim
that every possible full-width seed or state has been searched. A small range,
a partial state, multiple matches, and a timeout remain distinct outcomes.

Checked environment: Python 3.10.12, cryptography 3.4.8, z3-solver 5.3.2.0,
and the available C/C++ compilers. These versions describe the check conditions.

The included Bitcoin Core test source has its original
[license](shared/BITCOIN_CORE_COPYING) and
[source metadata](shared/upstream.json). Fixture transcription is checked
against its recorded source hash.
