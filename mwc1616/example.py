"""Fixed synthetic recovery example; accepts no target inputs."""
from pathlib import Path
import sys
sys.path.insert(0,str(Path(__file__).resolve().parents[1]/'shared'))
from example_helpers import load_module, public_key, print_example

import z3
import recovery as r

def run():
    """Recover the active MWC component and verify a subsequent synthetic key."""
    multipliers=(18030,36969)
    layout=next(c for c in r.LAYOUTS if c['id']=='fixed256_high16_big')
    all_values=r.generate((0xfedcba98,0x87654321),multipliers,layout,last=112,skip=1)
    fit={w:all_values[w] for w in (16,24,32,48,64,80,96)}
    solver,anchor,observed=r.make_solver(96,fit[96],multipliers,layout,20000)
    for component in r.active_components(layout):
        solver.add(z3.ULE(anchor[component],multipliers[component]*65536-1))
    assert solver.check()==z3.sat
    state=r.state_from_model(solver,anchor,layout)
    replay,_=r.replay_candidate(state,multipliers,layout,96,observed[0][0],fit,1)
    assert replay['compatible']
    initial=tuple(int(x,16) for x in replay['canonical_initial_state'])
    candidate=r.generate(initial,multipliers,layout,last=112,skip=1)[112]
    assert public_key(candidate)==public_key(all_values[112])
    r.block_state(solver,anchor,state,layout)
    assert solver.check()==z3.unsat
    return {'active_state_bits_recovered':32,'inactive_state_bits_unobserved':32,'active_state_unique':True,'new_keys_verified':1}


if __name__=="__main__":
    print_example(run)
