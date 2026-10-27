"""Fixed synthetic recovery example; accepts no target inputs."""
from pathlib import Path
import sys
sys.path.insert(0,str(Path(__file__).resolve().parents[1]/'shared'))
from example_helpers import load_module, public_key, print_example

import bootstrap_analysis as ladder

def run():
    """Recover synthetic parent keys from public derivation data and address ladders."""
    result=ladder.run()
    assert result['successful_recoveries']==12
    return {'synthetic_parent_recoveries':result['successful_recoveries'],'negative_controls':len(result['negative_controls'])}


if __name__=="__main__":
    print_example(run)
