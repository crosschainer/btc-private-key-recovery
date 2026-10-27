"""Cross-check generic implementations against independent arithmetic and vectors."""
import importlib.util
from pathlib import Path
import sys
import unittest

from cryptography.hazmat.primitives.asymmetric import ec

HERE = Path(__file__).resolve().parent


def module(name, relative):
    spec = importlib.util.spec_from_file_location(name, HERE.parent / relative)
    result = importlib.util.module_from_spec(spec)
    sys.modules[name] = result
    spec.loader.exec_module(result)
    return result


class ReferenceChecks(unittest.TestCase):
    def test_affine_outputs_against_numeric_constructor_with_warmup(self):
        numeric = module('numeric_reference', 'dotnet-random/reference.py')
        affine = module('affine_reference', 'dotnet-seed/affine_model.py')
        seeds = (0, 1, -1, 255, -65537, 161803398, 1234567890,
                 2147483647, -2147483648,
                 *(s + delta for s in affine.EXCEPTIONAL_SEEDS for delta in (-1, 1)))
        for seed in seeds:
            magnitude = abs(seed) if seed != -(1 << 31) else numeric.MODULUS
            branch = affine.branch_for_seed(magnitude)
            self.assertIsNotNone(branch)
            coefficients = affine.output_coefficients(320, branch)
            stream = numeric.LegacyRandom(seed)
            for index, (a, b) in enumerate(coefficients):
                with self.subTest(seed=seed, draw=index):
                    self.assertEqual(stream.next(), (a * magnitude + b) % numeric.MODULUS)

    def test_exceptional_seed_branch_is_explicit(self):
        affine = module('affine_exception_reference', 'dotnet-seed/affine_model.py')
        for seed in affine.EXCEPTIONAL_SEEDS:
            self.assertIsNone(affine.branch_for_seed(seed))

    def test_curve_against_openssl_and_encoding(self):
        curve = module('curve_reference', 'shared/curve.py')
        for scalar in (1, 2, 255, 65537, curve.N - 1):
            numbers = ec.derive_private_key(scalar, ec.SECP256K1()).public_key().public_numbers()
            expected = (numbers.x, numbers.y)
            self.assertEqual(curve.point_multiply(scalar, curve.G), expected)
            self.assertEqual(curve.decode_point(curve.encode_point(expected)), expected)
        self.assertIsNone(curve.point_multiply(curve.N, curve.G))
        with self.assertRaises(ValueError):
            curve.decode_point(b'\x02' + curve.P.to_bytes(32, 'big'))

    def test_arc4_rfc6229_offsets_and_continuation(self):
        pipeline = module('arc4_reference', 'bitcoinjs-arc4/pipeline.py')
        stream = pipeline.ARC4(bytes.fromhex('0102030405'))
        self.assertEqual(stream.read(16).hex(), 'b2396305f03dc027ccc3524a0a1118a8')
        stream.read(240)
        self.assertEqual(stream.read(16).hex(), '1cfcf62b03eddb641d77dfcf7f8d8c93')

    def test_pool_mixing_endianness_and_draw_boundary(self):
        pipeline = module('pool_reference', 'bitcoinjs-arc4/pipeline.py')
        for multiplier in pipeline.MULTIPLIERS:
            baseline = pipeline.pool_for_state(multiplier, 17, [0, 0])
            mixed = pipeline.pool_for_state(multiplier, 17, [0x12345678, 0x90ABCDEF])
            self.assertEqual(bytes(a ^ b for a, b in zip(baseline, mixed)),
                             bytes.fromhex('78563412efcdab90') + bytes(248))
            after = pipeline.next_state(17, multiplier)
            self.assertEqual(baseline, pipeline.pool_for_state(
                multiplier, after, [0, 0], boundary='after'))


if __name__ == '__main__':
    unittest.main()
