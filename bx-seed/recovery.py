"""Bounded canonical-state enumeration using explicit seed and BIP32 references."""
import reference as r

def scan_interval(begin,end,values,engine='minstd_rand0',size=16,path="m/0'",start=0,hardened=False,mask='low'):
    if type(begin) is not int or type(end) is not int or not 1<=begin<end<=r.ENGINE_MODULUS:
        raise ValueError('Need a nonempty canonical-state interval with an exclusive end')
    if not values or any(type(w) is not int or not 1<=w<=255 or type(k) is not int or not 1<<(w-1)<=k<1<<w for w,k in values.items()):
        raise ValueError('Need valid masked observations')
    matches=[]
    for state in range(begin,end):
        seed=r.seed_bytes(state,size,engine)
        if r.observations(seed,path,start,hardened,values,mask)==values:
            matches.append(state)
    return {'begin':begin,'end':end,'states_checked':end-begin,'complete_interval':True,'matching_states':matches}
