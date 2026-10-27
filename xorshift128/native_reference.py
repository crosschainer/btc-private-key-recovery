"""Independent uint32 C oracle and contradiction-certificate checking."""
import ctypes
import hashlib
from pathlib import Path
import subprocess
import tempfile
HERE=Path(__file__).resolve().parent
MASK32=(1<<32)-1

def require(condition, message):
    if not condition:
        raise AssertionError(message)


def sha256(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


class NativeReference:
    """A temporary compiled oracle; compilation metadata is retained in reports."""

    def __init__(self):
        self.directory = tempfile.TemporaryDirectory(prefix="xorshift128-audit-")
        binary = Path(self.directory.name) / "reference.so"
        source = HERE / "reference.c"
        compiler = subprocess.run(["cc", "--version"], check=True, text=True,
                                  capture_output=True).stdout.splitlines()[0]
        command = ["cc", "-std=c11", "-O2", "-Wall", "-Wextra", "-Werror",
                   "-fPIC", "-shared", str(source), "-o", str(binary)]
        subprocess.run(command, check=True, text=True, capture_output=True)
        self.library = ctypes.CDLL(str(binary))
        self.function = self.library.xs128_stream
        self.function.argtypes = [ctypes.c_uint32] * 4 + [
            ctypes.POINTER(ctypes.c_uint32), ctypes.c_size_t]
        self.function.restype = None
        self.metadata = {
            "compiler": compiler,
            "flags": command[1:8],
            "source": "reference.c",
            "source_sha256": sha256(source),
            "binary_sha256": sha256(binary),
        }

    def stream(self, state, count):
        require(0 <= state < 1 << 128, "Reference state outside 128 bits")
        require(count >= 0, "Negative reference output count")
        result = (ctypes.c_uint32 * count)()
        self.function(*[(state >> (32 * i)) & MASK32 for i in range(4)],
                      result, count)
        return list(result)

    def close(self):
        self.directory.cleanup()

    def __enter__(self):
        return self

    def __exit__(self, *_args):
        self.close()


def pack_units(words, layout):
    """Construct a scalar through explicit byte serialization."""
    extract = layout["extract"]
    units = []
    for word in words:
        if extract == "raw":
            unit = word
        elif extract == "bswap":
            unit = int.from_bytes(word.to_bytes(4, "little"), "big")
        elif extract == "low8":
            unit = word.to_bytes(4, "little")[0]
        elif extract == "high8":
            unit = word.to_bytes(4, "big")[0]
        else:
            raise ValueError(f"Unsupported reference extraction: {extract}")
        units.append(unit.to_bytes(layout["unit_bits"] // 8, layout["order"]))
    return int.from_bytes(b"".join(units), layout["order"])


def apply_mask(raw, n, mask):
    if mask == "low":
        retained = raw % (1 << (n - 1))
    elif mask == "high":
        require(0 <= raw < 1 << 256, "High mask requires fixed 256-bit source")
        # Binary text explicitly preserves leading zeros and reads top n-1 bits.
        retained = int(format(raw, "0256b")[:n - 1] or "0", 2)
    else:
        raise ValueError(f"Unsupported reference mask: {mask}")
    return (1 << (n - 1)) + retained


def independent_values(native, state, indices, config):
    indices = set(indices)
    if not indices:
        return {}
    maximum = max(indices)
    require(min(indices) >= 1 and maximum <= 256, "Invalid reference observation index")
    layout = config["layout"]
    counts = [(n + 31) // 32 if isinstance(layout["count"], str)
              else layout["count"] for n in range(1, maximum + 1)]
    skip = config["skip_after_each_key"]
    stream = native.stream(state, sum(counts) + maximum * skip)
    cursor = 0
    output = {}
    for n, count in enumerate(counts, 1):
        if n in indices:
            raw = pack_units(stream[cursor:cursor + count], layout)
            output[n] = apply_mask(raw, n, config["mask"])
        cursor += count + skip
    require(cursor == len(stream), "Reference stream advancement mismatch")
    return output


def verify_certificate(native, config, values, certificate):
    """Check XOR(rows) == 0 and XOR(observed bits) == 1 using C basis streams."""
    require(bool(certificate), "Empty contradiction certificate")
    pairs = [(item["observation_index"], item["retained_bit"]) for item in certificate]
    require(len(set(pairs)) == len(pairs), "Duplicate certificate observation")
    for n, bit in pairs:
        require(n in values and 0 <= bit < n - 1, "Invalid certificate observation")
    rhs = sum((values[n] >> bit) & 1 for n, bit in pairs) % 2
    require(rhs == 1, "Certificate observed RHS does not XOR to one")
    indices = {n for n, _ in pairs}
    for state_bit in range(128):
        generated = independent_values(native, 1 << state_bit, indices, config)
        coefficient = sum((generated[n] >> bit) & 1 for n, bit in pairs) % 2
        require(coefficient == 0,
                f"Certificate coefficient {state_bit} does not XOR to zero")
    return {"verified": True, "terms": len(pairs),
            "independent_basis_states": 128, "observed_rhs_xor": 1,
            "coefficient_xor_hex": "0" * 32}


def basic_reference_controls(native):
    # Simple one-hot arithmetic vectors, derived directly from the recurrence.
    cases = [(0, 0), (1, 2057), (1 << 31, 0x80800000),
             (1 << 96, 1), (1 << 127, 0x80001000)]
    for state, expected in cases:
        require(native.stream(state, 1) == [expected], "C one-step arithmetic vector")
    require(native.stream(0, 100) == [0] * 100, "Zero state is not absorbing")
    words = [0x01020304, 0x11223344]
    layout = {"unit_bits": 32, "order": "big", "extract": "raw"}
    require(pack_units(words, layout) == 0x0102030411223344, "Big word packing")
    layout["order"] = "little"
    require(pack_units(words, layout) == 0x1122334401020304, "Little word packing")
    layout.update(order="big", extract="bswap")
    require(pack_units(words, layout) == 0x0403020144332211, "Swapped word packing")
    layout.update(unit_bits=8, extract="low8")
    require(pack_units(words, layout) == 0x0444, "Low byte extraction")
    layout.update(extract="high8")
    require(pack_units(words, layout) == 0x0111, "High byte extraction")
    layout.update(order="little")
    require(pack_units(words, layout) == 0x1101, "Little byte packing")
    raw = (1 << 255) + (1 << 248) + 5
    for n in (1, 2, 8, 9, 32, 33, 40, 65, 135, 256):
        require(apply_mask(raw, n, "high") ==
                (1 << (n - 1)) + (raw >> (257 - n)), "High bit text/shift agreement")
        require(apply_mask(5, n, "high") ==
                (1 << (n - 1)) + (5 >> (257 - n)), "Leading-zero source agreement")
    return {"one_hot_step_vectors": len(cases), "zero_stream_words": 100,
            "literal_packing_vectors": 6, "high_mask_text_shift_checks": 20}
