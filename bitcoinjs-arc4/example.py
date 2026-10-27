"""Fixed synthetic recovery example; accepts no target inputs."""
from pathlib import Path
import sys
sys.path.insert(0,str(Path(__file__).resolve().parents[1]/'shared'))
from example_helpers import load_module, public_key, print_example

import recovery as r
import pipeline as p

def run():
    """Recover a synthetic ARC4 pool state within a small declared interval."""
    recipe={'id':'synthetic','multiplier':18273,'times_ms':[0,1],'extra_seed_ints':[],'stream_offset':0,'rationale':'Fixed synthetic mixing events'}
    r.validate_recipes([recipe])
    values=p.observations(r.seed_at(recipe,2),(32,48,64,80,96))
    result=r.scan_interval(recipe,1,4,values)
    assert result['matches']==[{'state_after_first_call':2,'config':r.configurations()[0]}]
    match=result['matches'][0]
    predicted=p.observations(r.seed_at(recipe,match['state_after_first_call']),(112,),**match['config'])
    expected=p.observations(r.seed_at(recipe,2),(112,))
    assert public_key(predicted[112])==public_key(expected[112])
    return {'state_interval':[1,4],'states_checked':result['states_checked'],'matching_states':len(result['matches']),'new_keys_verified':1}


if __name__=="__main__":
    print_example(run)
