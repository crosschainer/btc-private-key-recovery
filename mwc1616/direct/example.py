"""Fixed synthetic recovery example; accepts no target inputs."""
from pathlib import Path
import sys
sys.path.insert(0,str(Path(__file__).resolve().parents[2]/'shared'))
from example_helpers import load_module, public_key, print_example

import subprocess
import tempfile
import recovery as r

def units(state,multiplier,count):
    result=[]
    for _ in range(count):
        result.append((state//256)%256)
        state=multiplier*(state%65536)+state//65536
    return result

def run():
    """Recover an MWC component by scanning a complete small declared interval."""
    multiplier=18030;index=2407
    planted=(index//256)*65536+13*256+index%256
    observed=units(planted,multiplier,16)
    with tempfile.TemporaryDirectory(prefix='mwc-enumeration-') as directory:
        binary=Path(directory)/'mwc_scan'
        subprocess.run(['cc','-O3','-std=c11','-Wall','-Wextra','-Werror',str(Path(__file__).with_name('mwc_scan.c')),'-o',str(binary)],check=True,capture_output=True)
        result=r.scan(binary,multiplier,8,observed,0,4096)
    assert result['matches']==[planted]
    # The undisclosed byte suffix is checked only after recovering the state.
    expected=units(planted,multiplier,48)[16:]
    predicted=units(result['matches'][0],multiplier,48)[16:]
    candidate=(1<<95)+(int.from_bytes(bytes(predicted),'big')%(1<<95))
    reference=(1<<95)+(int.from_bytes(bytes(expected),'big')%(1<<95))
    assert public_key(candidate)==public_key(reference)
    return {'interval':[0,4096],'states_checked':result['candidates_checked'],'matching_states':result['match_count'],'new_keys_verified':1}


if __name__=="__main__":
    print_example(run)
