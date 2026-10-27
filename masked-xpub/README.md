# Masked BIP32 recovery

This method combines a wallet's extended public key with shortened child-key observations. Public derivation data links the children, allowing a known shortened value to be extended and checked against later public outputs.

## What it needs

The extended public key, exact child mapping, the masking rule, and sufficient observations. The required child derivations must be available from public data; hardened boundaries prevent that.

## Run the example

From the collection root:

```bash
python3 -B masked-xpub/example.py
```

The example recovers parent keys for four generated wallets under three observation schedules. A separate analysis counts possible parent keys and checks small cases exhaustively.

## Limits

An ordinary public key does not contain the chain code supplied by an extended public key. Wrong mappings, gaps, missing observations, or different masking rules can prevent recovery.

## Code

- [example.py](example.py)
- [bootstrap_analysis.py](bootstrap_analysis.py)
- [synthetic_analysis.py](synthetic_analysis.py)

[BIP32 specification](https://github.com/bitcoin/bips/blob/master/bip-0032.mediawiki)

[Overview](../README.md)
