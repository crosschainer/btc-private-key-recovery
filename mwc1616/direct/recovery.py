"""Native finite MWC projection enumeration with independently checked accounting."""
import json
from pathlib import Path
import subprocess

def require(value, message):
    if not value:
        raise ValueError(message)


def check_scan(data, multiplier, bits, units, begin, end):
    for key, expected in [('multiplier', multiplier), ('bits', bits), ('begin', begin),
                          ('end', end), ('candidates_checked', end - begin)]:
        require(data.get(key) == expected, 'Native accounting mismatch: ' + key)
    require(not data['matches_truncated'], 'Native match storage limit reached; cannot claim exhaustive recovery')
    require(data['match_count'] == len(data['matches']), 'Match count mismatch')
    require(len(data['matches']) == len(set(data['matches'])), 'Duplicate anchors')
    prefix = data['prefix_survivors']
    require(len(prefix) == len(units) and prefix[0] == end - begin
            and prefix[-1] == data['match_count'], 'Prefix accounting mismatch')
    require(all(type(x) is int and x >= 0 for x in prefix)
            and all(a >= b for a, b in zip(prefix, prefix[1:])), 'Invalid prefix counters')
    require(isinstance(data['elapsed_seconds'], (int, float))
            and 0 <= data['elapsed_seconds'] < float('inf'), 'Invalid scan duration')
    shift = 16 - bits
    for anchor in data['matches']:
        require(type(anchor) is int and 0 <= anchor < 2**32, 'Invalid anchor word')
        index = ((anchor >> 16) << shift) | (anchor & ((1 << shift) - 1))
        require(begin <= index < end, 'Anchor outside enumerated interval')
        x = anchor
        for expected in units:
            require((x >> shift) & ((1 << bits) - 1) == expected, 'Independent native survivor replay failed')
            x = multiplier * (x % 65536) + x // 65536


def scan(binary, multiplier, bits, units, begin=0, end=None):
    if end is None:
        end = 1 << (32 - bits)
    require(bits in (4, 8) and units, 'Unsupported or empty projection')
    command = [str(binary), str(multiplier), str(bits), ','.join(map(str, units)), str(begin), str(end)]
    data = json.loads(subprocess.check_output(command, text=True))
    check_scan(data, multiplier, bits, units, begin, end)
    return data


import importlib.util
HERE=Path(__file__).resolve().parent
def modules():
    result={}
    for mask,name in (("low","recovery.py"),("high","high_bits.py")):
        spec=importlib.util.spec_from_file_location("direct_"+mask,HERE.parent/name)
        module=importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        result[mask]=module
    return result

def layout(module, bits, order):
    name = f'fixed256_high{bits}_{order}'
    return next(item for item in module.LAYOUTS if item['id'] == name)


def full_observations(module, n, scalar, config):
    observed = module.observed_units(n, scalar, config)
    full = [(j, value) for j, bits, value in observed if bits == config['bits']]
    require(full, 'No completely observed units')
    require([j for j, _ in full] == list(range(full[0][0], full[-1][0] + 1)),
            'Full observations must be contiguous')
    return {'first_full_unit': full[0][0], 'units': [value for _, value in full],
            'bits': config['bits'], 'retained_bits_used': len(full) * config['bits'],
            'discarded_partial_bits': sum(bits for _, bits, _ in observed) - len(full) * config['bits']}
