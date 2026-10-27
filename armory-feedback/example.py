"""Fixed synthetic recovery example; accepts no target inputs."""
from pathlib import Path
import sys
sys.path.insert(0,str(Path(__file__).resolve().parents[1]/'shared'))
from example_helpers import load_module, public_key, print_example

import hashlib
import recover

def run():
    """Recover a hidden chain code in a deliberately small feedback model."""
    width=8;order=253
    digest=lambda key:int.from_bytes(hashlib.sha256(key.to_bytes(2,'big')).digest(),'big')%256
    # Independent fixture generation uses literal integer arithmetic.
    planted=61;key=1;values={1:1}
    for source in range(1,7):
        raw=(key*(planted^digest(key)))%order
        key=(1<<source)+(raw%(1<<source))
        values[source+1]=key
    result=recover.solve(values,width=width,order=order,hash_fn=digest)
    assert result['status']=='recovered'
    assert hex(planted) in result['chain_codes']
    return {'toy_chain_code_bits':width,'status':result['status'],'matching_chain_codes':result['chain_codes'],
            'explanation':'This small model demonstrates chain-code recovery; it is not a full-width wallet recovery.'}


if __name__=="__main__":
    print_example(run)
