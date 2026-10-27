"""Fixed synthetic recovery example; accepts no target inputs."""
from pathlib import Path
import sys
sys.path.insert(0,str(Path(__file__).resolve().parents[1]/'shared'))
from example_helpers import load_module, public_key, print_example

import screen
import exact_solver
from reference import LegacyRandom

def run():
    """Build and replay an exact compatible state, without claiming uniqueness."""
    config=next(c for c in screen.configs() if c['count']=='ceil_n' and c['order']=='little' and c['skip']==0)
    values=screen.generate(LegacyRandom(1234567),set(range(1,17)),config)
    domain_result=screen.solve(values,config)
    assert domain_result['status']=='survives_necessary_screen'
    exact=exact_solver.solve(values,config,timeout_ms=5000)
    if exact['status']=='sat_exact_replay':
        assert exact['replay_matches']
    else:
        assert exact['status'] in ('inconclusive_timeout','inconclusive_unknown')
    return {'byte_screen':domain_result['status'],'exact_solver':exact['status'],
            'unique_generating_state_established':False,
            'explanation':('A compatible state fits these observations, but it is not uniquely identified.' if exact['status']=='sat_exact_replay' else 'The exact solver did not establish a generating state within its resource limit.')}


if __name__=="__main__":
    print_example(run)
