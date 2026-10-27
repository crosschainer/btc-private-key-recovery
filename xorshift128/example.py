"""Fixed synthetic recovery example; accepts no target inputs."""
from pathlib import Path
import sys
sys.path.insert(0,str(Path(__file__).resolve().parents[1]/'shared'))
from example_helpers import load_module, public_key, print_example

import recovery as r
from native_reference import NativeReference, independent_values, verify_certificate

def run():
    """Recover a 128-bit generator state from independently generated outputs."""
    state=0x0123456789abcdeffedcba9876543210
    config=r.configs()[0]
    with NativeReference() as native:
        values=independent_values(native,state,range(1,97),config)
        fit={w:values[w] for w in range(1,41)}
        result=r.solve(fit,config)
        assert result['compatible'] and result['rank']==128
        recovered=int(result['initial_state_hex'],16)
        assert recovered==state
        predicted=r.predict(recovered,[64,96],config)
        assert all(public_key(predicted[w])==public_key(values[w]) for w in predicted)
        damaged=dict(fit);damaged[40]^=1
        conflict=r.solve(damaged,config)
        assert not conflict['compatible']
        certificate=verify_certificate(native,config,damaged,conflict['first_conflict']['certificate'])
    return {'state_bits_recovered':128,'new_keys_verified':2,'independent_contradiction_verified':certificate['verified']}


if __name__=="__main__":
    print_example(run)
