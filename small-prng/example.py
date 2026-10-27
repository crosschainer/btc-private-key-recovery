"""Fixed synthetic recovery example; accepts no target inputs."""
from pathlib import Path
import sys
sys.path.insert(0,str(Path(__file__).resolve().parents[1]/'shared'))
from example_helpers import load_module, public_key, print_example

import recovery as r

def run():
    """Recover a xorshift state, an LCG state, and a seed from a bounded range."""
    config={'shifts':(13,17,5),'orientation':'LRL','layout':r.LAYOUTS[0],'skip_after_each_key':1}
    # Generate the fixture with literal shifts and byte packing.
    state=0x12345678;values={}
    for width in range(1,81):
        words=[]
        for _ in range(8):
            state^=(state<<13)&0xffffffff;state^=state>>17;state^=(state<<5)&0xffffffff
            words.append(state)
        raw=int.from_bytes(b''.join(w.to_bytes(4,'little') for w in words),'little')
        values[width]=(1<<(width-1))+(raw%(1<<(width-1)))
        state^=(state<<13)&0xffffffff;state^=state>>17;state^=(state<<5)&0xffffffff
    recovered=r.solve_xorshift({w:values[w] for w in range(1,33)},config)
    assert recovered['compatible'] and recovered['_state']==0x12345678
    predicted=r.xorshift_values(recovered['_state'],[64,80],config)
    assert all(public_key(predicted[w])==public_key(values[w]) for w in predicted)
    lcg=r.LCGS[0];state=1234567;observed={}
    for index in range(1,9):
        state=(1103515245*state+12345)%(1<<31)
        observed[index]=(state//65536)%32768
    lcg_result=r.solve_lcg_projection(observed,lcg,1)
    assert lcg_result['_terminal_states']==[state]
    python_config={'mode':'getrandbits256','initial_raw32_draws':1,'skip_after_each_key':0}
    generator=r.python_generator(721,python_config);known={}
    for width in range(1,49):
        value=r.python_draw(generator,width,python_config)
        if width in (24,32,48):known[width]=value
    seeds=[s for s in range(512,1024) if r.python_mismatch(s,known,python_config) is None]
    assert seeds==[721]
    return {'xorshift_state_recovered':True,'new_keys_verified':2,'lcg_terminal_states':len(lcg_result['_terminal_states']),
            'python_seed_range':[512,1024],'matching_python_seeds':seeds}


if __name__=="__main__":
    print_example(run)
