"""Fixed synthetic recovery example; accepts no target inputs."""
from pathlib import Path
import sys
sys.path.insert(0,str(Path(__file__).resolve().parents[1]/'shared'))
from example_helpers import load_module, public_key, print_example

import recovery
import reference as r

def run():
    """Recover a seed-engine state within a declared small interval."""
    seed=r.seed_bytes(19,16)
    values=r.observations(seed,"m/0'",0,False,[32,48,64,80,96])
    fit={w:values[w] for w in (32,48,64)}
    result=recovery.scan_interval(1,33,fit)
    assert result['matching_states']==[19]
    predicted=r.observations(r.seed_bytes(result['matching_states'][0],16),"m/0'",0,False,[80,96])
    assert all(public_key(predicted[w])==public_key(values[w]) for w in predicted)
    return {'canonical_state_interval':[1,33],'states_checked':result['states_checked'],'matching_states':result['matching_states'],'new_keys_verified':2}


if __name__=="__main__":
    print_example(run)
