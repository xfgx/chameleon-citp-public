import pathlib,csv,json,math,statistics,hashlib,itertools,collections
import numpy as np
r=pathlib.Path('/root/build/ks-integration-20260908');p=r/'r2-results';rows=list(csv.DictReader((p/'channel_results.csv').open()))
ints=['field','bits','loss_percent_target','burn','measure','tail','dropped_measure','exact_tail']
floats=['rms_tail','max_abs_tail','fraction_steps_above_0_01']
for row in rows:
 for k in ints:row[k]=int(row[k])
 for k in floats:row[k]=float(row[k]);assert math.isfinite(row[k])
 assert row['burn']==2048 and row['measure']==8192 and row['tail']==1024
 assert row['cohort']==('replication-R1' if row['field']<32 else 'fresh-R2')
 assert 0<=row['rms_tail']<=row['max_abs_tail']<=1
 assert 0<=row['fraction_steps_above_0_01']<=1
 assert row['exact_tail']==int(row['rms_tail']==0)
conditions=[(b,l,pat) for b in [12,16,24,48] for l,pat in [(0,'none'),(1,'iid'),(1,'burst8'),(5,'iid'),(5,'burst8'),(10,'iid'),(10,'burst8')]]
keys={(x['field'],x['bits'],x['loss_percent_target'],x['pattern']) for x in rows}
assert len(rows)==len(keys)==1792
assert keys=={(f,*c) for f in range(64) for c in conditions}
info=json.loads((p/'run.json').read_text());assert info['status']=='PASS' and info['rows']==1792 and info['quantizer_control_cases']==40004
fs=json.loads((p/'fields.json').read_text());orig=json.loads((r/'project/internal/chaossync/testdata/ks_r1_fields.json').read_text())
assert len(fs)==64
for f,o in zip(fs[:32],orig):
 assert o['cycle']==list(range(8))
 for k,v in o.items():
  if k!='cycle':assert f[k]==v
bykey={(x['field'],x['bits'],x['loss_percent_target'],x['pattern']):x for x in rows}
def uniform(f,t):
 h=hashlib.sha256(('KS-R2-loss/'+str(f)+'/'+str(t)).encode()).digest();return (int.from_bytes(h[:8],'big')>>11)/2**53
loss_checks=[]
for f in range(64):
 masks={}
 for loss in [1,5,10]:
  drop=uniform(f,-loss)<loss/100;v=[];iid=[]
  for tick in range(10240):
   u=uniform(f,tick)
   drop=(u>=0.125) if drop else (u<(loss/100)/(8*(1-loss/100)))
   if tick>=2048:v.append(drop);iid.append(u<loss/100)
  for pat,mask in [('iid',iid),('burst8',v)]:
   runs=[sum(1 for _ in g) for z,g in itertools.groupby(mask) if z]
   for b in [12,16,24,48]:assert sum(mask)==bykey[f,b,loss,pat]['dropped_measure']
   loss_checks.append({'field':f,'loss_target':loss,'pattern':pat,'dropped':sum(mask),'mean_dropped_run':statistics.mean(runs) if runs else 0,'max_dropped_run':max(runs,default=0)})
summary=[]
for cohort in ['all','replication-R1','fresh-R2']:
 for b,l,pat in conditions:
  xs=[x for x in rows if x['bits']==b and x['loss_percent_target']==l and x['pattern']==pat and (cohort=='all' or x['cohort']==cohort)]
  vals=[x['rms_tail'] for x in xs];n=len(xs);assert n==(64 if cohort=='all' else 32)
  summary.append({'cohort':cohort,'bits':b,'loss_target':l,'pattern':pat,'n':n,'tolerance_success':sum(x<.001 for x in vals),'exact':sum(x['exact_tail'] for x in xs),'rms_median':statistics.median(vals),'rms_p95':float(np.quantile(vals,.95)),'rms_max':max(vals),'max_abs_error':max(x['max_abs_tail'] for x in xs),'loss_realized_percent':100*sum(x['dropped_measure'] for x in xs)/(n*8192)})
# Independent grouped pass: verify the headline counts and medians without reusing filters.
groups=collections.defaultdict(list)
for x in rows:groups[x['bits'],x['loss_percent_target'],x['pattern']].append(x)
for s in summary[:28]:
 xs=groups[s['bits'],s['loss_target'],s['pattern']];vals=sorted(x['rms_tail'] for x in xs)
 assert s['tolerance_success']==len([1 for x in xs if x['rms_tail']<1e-3])
 assert s['rms_median']==(vals[31]+vals[32])/2
pairs=[]
for b in [12,16,24,48]:
 for loss in [1,5,10]:
  a=[bykey[f,b,loss,'iid']['rms_tail'] for f in range(64)];z=[bykey[f,b,loss,'burst8']['rms_tail'] for f in range(64)]
  pairs.append({'bits':b,'loss_target':loss,'burst_rms_greater':sum(y>x for x,y in zip(a,z)),'equal':sum(y==x for x,y in zip(a,z)),'median_paired_difference':statistics.median(y-x for x,y in zip(a,z))})
controls={'status':'PASS','rows':len(rows),'unique_conditions':len(keys),'public_replication_fields_match':32,'loss_count_checks':len(loss_checks)*4,'independent_summary_groups':28,'quantizer_cases':40004,'no_loss_48_exact':sum(x['exact_tail'] for x in rows if x['bits']==48 and x['loss_percent_target']==0),'limitations':'one loss realization per field and condition; ideal shared clock; fixed-point finite window; no network, modem or DPI tests'}
for name,obj in [('summary.json',summary),('paired.json',pairs),('loss-controls.json',loss_checks),('verification.json',controls)]:
 (p/name).write_text(json.dumps(obj,indent=2)+'\n')
with (p/'summary.csv').open('w',newline='') as f:w=csv.DictWriter(f,fieldnames=list(summary[0]));w.writeheader();w.writerows(summary)
print(json.dumps(controls))
for s in summary[:28]:print(json.dumps(s))
print('PAIRED',json.dumps(pairs))
