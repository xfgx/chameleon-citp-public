from cml_ru import *
mu,e1,e2,x,y0=fields(32)
y=np.repeat(y0[:,None,:],6,axis=1)
hashes=[hashlib.sha256() for _ in range(32)]
cr=np.array([0,950,950,999,950,950],dtype=object)*SCALE//1000
for t in range(2048):
    masks=np.zeros((6,8),dtype=object)
    for h in range(1,6):
        k=4 if h>=4 else 1
        ix=(np.arange(k)*(8//k)+(t if h in [2,3,5] else 0))%8
        masks[h,ix]=1
    x=step(x,mu,e1[:,None],e2[:,None])
    y=step(y,mu[:,None,:],e1[:,None,None],e2[:,None,None])
    y+=mul(masks[None,:,:]*cr[None,:,None],x[:,None,:]-y)
    for f in range(32):
        for state in [x[f],*y[f]]:
            for v in state:hashes[f].update(int(v).to_bytes(8,'big',signed=True))
actual={str(i):h.hexdigest() for i,h in enumerate(hashes)}
expected=json.loads((ROOT/'go_kernel_hashes.json').read_text())
assert actual==expected
result={'status':'PASS','fields':32,'steps':2048,'states_per_step':7,'coordinates_per_state':8,'hashed_integer_values':32*2048*7*8,'trajectory_hashes':actual}
(ROOT/'kernel_crosscheck.json').write_text(json.dumps(result,indent=2))
print('Cross-language Q16.48 trajectory hashes PASS: 32/32 fields; 3,670,016 integer values')
