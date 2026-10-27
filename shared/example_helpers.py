"""Small utilities for fixed synthetic examples."""
import argparse
import importlib.util
import json
from pathlib import Path
import sys
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

ROOT=Path(__file__).resolve().parent.parent

def load_module(name,relative):
    spec=importlib.util.spec_from_file_location(name,ROOT/relative)
    module=importlib.util.module_from_spec(spec)
    sys.modules[name]=module
    spec.loader.exec_module(module)
    return module

def public_key(scalar):
    return ec.derive_private_key(scalar,ec.SECP256K1()).public_key().public_bytes(Encoding.X962,PublicFormat.CompressedPoint)

def print_example(run):
    argparse.ArgumentParser(description=run.__doc__).parse_args()
    print(json.dumps(run(),indent=2))
