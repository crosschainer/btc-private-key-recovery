# Reference helpers

Local dependencies for the executable recovery examples:

- [curve.py](curve.py): affine secp256k1 arithmetic, point encoding, and hashing.
- [example_helpers.py](example_helpers.py): loading and public-key checks for the examples.
- [test_references.py](test_references.py): independent arithmetic and vector checks.
- [bip32_tests.cpp](bip32_tests.cpp): pinned upstream BIP32 test-vector source.
- [upstream.json](upstream.json): source revision and SHA-256 metadata.
- [BITCOIN_CORE_COPYING](BITCOIN_CORE_COPYING): upstream license.

The Python curve arithmetic is variable time and intended for reference checks.

[Research overview](../README.md)
