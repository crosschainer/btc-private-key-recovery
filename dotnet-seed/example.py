"""Fixed synthetic recovery example; accepts no target inputs."""
from pathlib import Path
import sys
sys.path.insert(0,str(Path(__file__).resolve().parents[1]/'shared'))
from example_helpers import load_module, public_key, print_example

import tempfile
import recovery as r
import audit

def run():
    """Recover a constructor seed without supplying it to the scanner."""
    config=r.configurations()[0]
    values=audit.independent_generate(2000000000,set(range(1,97)),config)
    fit={w:value for w,value in values.items() if w<=64}
    with tempfile.TemporaryDirectory(prefix='seed-recovery-') as directory:
        binary,_=r.build_scanner(directory)
        result=r.recover(fit,config,binary)
    assert result['status']=='recovered' and result['complete']
    assert result['candidate_seed_magnitudes']==[2000000000]
    predicted=r.numeric_generate(result['candidate_seed_magnitudes'][0],[80,96],config)
    assert all(public_key(predicted[w])==public_key(values[w]) for w in predicted)
    return {'candidate_seed_magnitudes':result['candidate_seed_magnitudes'],'anchor_values_checked':result['scanner']['tested_anchor_values'],
            'complete_constructor_domain':True,'new_keys_verified':2}


if __name__=="__main__":
    print_example(run)
