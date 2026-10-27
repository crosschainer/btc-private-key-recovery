# BTC Private Key Recovery

This collection shows how weak or exposed key-generation processes can make
private keys recoverable. Every method has a runnable example using fixed
generated test data and code you can inspect.

Each row below is one method guide, with a link to its matching folder. The two
MWC1616 approaches share a folder; direct search is in its `direct/` subfolder.
`shared/` and `fixtures/` contain helper code and public test data.

| Method | Required recovery advantage | Possible output | Guide and example |
| --- | --- | --- | --- |
| Small PRNGs | Output from a predictable generator, or a small seed range. | PRNG state or seed; candidate private keys. | [Guide](small-prng/README.md) · [Example](small-prng/example.py) |
| Xorshift128 | Enough disclosed output bits and the exact generator settings. | 128-bit PRNG state; candidate private keys. | [Guide](xorshift128/README.md) · [Example](xorshift128/example.py) |
| MWC1616 solver | Partly disclosed output and a known generator layout. | Observable state components; candidate private keys. | [Guide](mwc1616/README.md) · [Example](mwc1616/example.py) |
| MWC1616 direct search | Complete output units and a bounded range of possible states. | An observable state component; candidate private keys. | [Guide](mwc1616/direct/README.md) · [Example](mwc1616/direct/example.py) |
| BitcoinJS ARC4 | A searchable source state and exact pool and wallet settings. | Source state, wallet seed, and candidate private keys. | [Guide](bitcoinjs-arc4/README.md) · [Example](bitcoinjs-arc4/example.py) |
| BX seeds | A restricted seed engine and known wallet derivation settings. | Seed-engine state, seed bytes, and candidate private keys. | [Guide](bx-seed/README.md) · [Example](bx-seed/example.py) |
| .NET Random states | Disclosed bytes and a known output layout; several states may fit. | Compatible internal states, potentially more than one. | [Guide](dotnet-random/README.md) · [Example](dotnet-random/example.py) |
| .NET Random seeds | A known constructor and enough disclosed output to filter seeds. | Seed magnitude and candidate private keys. | [Guide](dotnet-seed/README.md) · [Example](dotnet-seed/example.py) |
| Hash feedback | Disclosed shortened keys that are reused to generate later keys. | Matching feedback rules and predicted private keys. | [Guide](masking-feedback/README.md) · [Example](masking-feedback/example.py) |
| Masked multiplicative feedback | A known feedback rule and keys that constrain its secret chain code. | Candidate chain codes and subsequent keys. | [Guide](armory-feedback/README.md) · [Example](armory-feedback/example.py) |
| Masked BIP32 | An extended public key, an exact child mapping, and shortened-key observations. | Child private scalars and a parent private key. | [Guide](masked-xpub/README.md) · [Example](masked-xpub/example.py) |

A candidate private key still needs to match the expected public key or address.
A matching internal state alone does not guarantee that it is the unique state
that generated the observations.

In a nutshell: these methods use weaknesses or disclosed information to shrink
the candidate search space. Any remaining candidates need to be checked, but
some methods recover the state or key directly without further brute force.

## Try an example

Use Python 3.10 or later. Install the Python dependencies from `requirements.txt`.
The native examples also need C and C++ compilers (`cc` and `g++`).

```bash
python3 -m pip install -r requirements.txt
python3 -B masking-feedback/example.py
python3 -B mwc1616/example.py
```

Each guide explains what its example needs, what it recovers, and where its
limits are. Some examples recover only part of a state or find multiple possible
answers; their output says so. All seeds and keys in the examples are public test data.

To run the reference tests and every example:

```bash
python3 -B verify.py
```

[What the checks cover](VERIFICATION.md)
