"""Fixed synthetic recovery example; accepts no target inputs."""
from pathlib import Path
import sys
sys.path.insert(0,str(Path(__file__).resolve().parents[1]/'shared'))
from example_helpers import load_module, public_key, print_example

import feedback

def run():
    """Identify a feedback rule and verify two undisclosed synthetic keys."""
    # Independent known-answer scalars for SHA256 of the decimal current key.
    fixture={32:0x80012345,33:0x11760F22B,35:0x5109048AA,37:0x159FFFA2B8}
    expected_public={38:public_key(0x3E02E9F932),39:public_key(0x5E54FB8F9D)}
    configs=list(feedback.configurations())
    matches=[c for c in configs if feedback.compare(fixture,c)['compatible']]
    assert len(matches)==1,'Fixture must identify one rule'
    rule=matches[0]
    for width,expected in expected_public.items():
        candidate=feedback.traverse(fixture[37],37,width,rule)
        assert public_key(candidate)==expected
    damaged=dict(fixture);damaged[35]^=1
    assert not any(feedback.compare(damaged,c)['compatible'] for c in configs)
    return {'rules_checked':len(configs),'matching_rule':feedback.config_id(rule),
            'new_keys_verified':len(expected_public),'corrupted_observation_rejected':True}


if __name__=="__main__":
    print_example(run)
