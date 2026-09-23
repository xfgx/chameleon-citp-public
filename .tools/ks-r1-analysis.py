import csv,json,math,statistics,hashlib
from pathlib import Path
r=Path(__file__).resolve().parent
assert (r/'cml_completed.txt').read_text().strip()=='RUN_RC=0'
def read(p):
    with p.open() as f:return list(csv.DictReader(f))
a=read(r/'go_length_cases.csv')
assert len(a)==24016 and len({(x['seed'],x['plaintext_bytes']) for x in a})==24016
assert {int(x['seed']) for x in a}==set(range(16))
assert all(int(x['wire_bytes'])-int(x['plaintext_bytes'])==28 and x['roundtrip']=='1' for x in a)
for seed in range(16):assert {int(x['plaintext_bytes']) for x in a if int(x['seed'])==seed}==set(range(1501))
report={'A':{'cases':len(a),'all_lengths_0_through_1500_per_seed':True,'overhead_bytes':28,'roundtrip_pass':len(a)},'B':{},'duration_sensitivity':{}}
datasets={}
for m in [8192,16384]:
    rows=read(r/'results'/f'cml_{m}.csv');datasets[m]=rows
    assert len(rows)==224 and len({(x['field'],x['variant']) for x in rows})==224
    assert all(all(v!='' for v in x.values()) for x in rows)
    for x in rows:
        for k,v in x.items():
            if k!='variant':assert math.isfinite(float(v))
    groups={}
    for name in dict.fromkeys(x['variant'] for x in rows):
        g=[x for x in rows if x['variant']==name];lam=[float(x['lambda_top_bits']) for x in g];rms=[float(x['rms_final_1024']) for x in g]
        groups[name]={'fields':len(g),'lambda_median':statistics.median(lam),'lambda_min':min(lam),'lambda_max':max(lam),'negative_top':sum(v<0 for v in lam),'rms_median':statistics.median(rms),'rms_max':max(rms),'exact_zero_rms':sum(v==0 for v in rms),'negative_top_nonzero_rms':sum(l<0 and e>0 for l,e in zip(lam,rms)),'negative_sum_positive_top':sum(float(x['conditional_sum_bits'])<0 and float(x['lambda_top_bits'])>0 for x in g)}
    report['B'][str(m)]=groups
old={(x['field'],x['variant']):float(x['lambda_top_bits']) for x in datasets[8192]}
for name in report['B']['8192']:
    g=[x for x in datasets[16384] if x['variant']==name]
    report['duration_sensitivity'][name]={'max_abs_top_difference':max(abs(float(x['lambda_top_bits'])-old[(x['field'],name)]) for x in g),'sign_changes':sum((float(x['lambda_top_bits'])<0)!=(old[(x['field'],name)]<0) for x in g)}
fields=json.loads((r/'results/fields.json').read_text());report['fields_satisfying_sufficient_smooth_bound']=sum((x['eps1_raw']+x['eps2_raw'])/(1<<48)<1/76 for x in fields)
report['kernel_crosscheck']=json.loads((r/'kernel_crosscheck.json').read_text())['status']
report['grain']='field x variant x duration; 32 paired fields, not 448 independent fields'
(r/'ANALYSIS.json').write_text(json.dumps(report,indent=2));print(json.dumps(report,indent=2))
