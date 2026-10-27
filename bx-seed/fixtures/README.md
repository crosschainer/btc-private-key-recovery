# Public test fixtures

[bip32_vectors.json](bip32_vectors.json) supplies standardized seed bytes and
expected extended keys for checking BIP32 derivation. Its metadata records the
upstream source revision and SHA-256.

The [reference tests](../test_reference.py) compare these values with the
included upstream source and exercise derivation against the expected keys.

[Seed recovery](../README.md)
