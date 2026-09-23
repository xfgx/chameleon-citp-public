"""Independent accounting and counter-model audit; does not import KS implementation."""
import json,hashlib,collections,sys
from pathlib import Path
ROOT=Path(sys.argv[1]);names=['legacy-8192','legacy-16384','frontier','checkpoint-reset','checkpoint-retain']
def read(p):return [json.loads(l) for l in p.read_text().splitlines() if l]
def sha(p):return hashlib.sha256(p.read_bytes()).hexdigest()
class Model:
 def __init__(self,name):
  self.name=name;self.legacy=name.startswith('legacy');self.w=16384 if name=='legacy-16384' else 8192;self.hist=64 if name=='checkpoint-retain' else 128;self.used=set();self.high=0;self.gen=self.w;self.floor=1;self.retired=set();self.restores=0
 def event(self,e):
  c=e['index']
  if e['op']=='checkpoint':
   cp=self.name.startswith('checkpoint') and c>self.gen
   if cp:
    self.retired={v for v in range(max(1,self.high-63),self.high+1) if v>=self.floor and v not in self.used} if self.name=='checkpoint-retain' else set()
    self.high=c;self.gen=c+self.w;self.floor=c+1;self.restores+=1
   return False,cp
  if e['stage']=='corrupt':return False,False
  if c in self.used:return False,False
  if self.legacy:ok=c<=len(self.used)+self.w
  else:ok=(self.floor<=c<=self.gen) or c in self.retired
  if ok:
   self.used.add(c)
   if not self.legacy:
    if c in self.retired:self.retired.remove(c)
    else:
     self.high=max(self.high,c);self.gen=self.high+self.w;self.floor=max(self.floor,self.high-self.hist+1,1)
  return ok,False

all_sources=set();all_records=[];all_counts=[];run_audits={}
for run in ['main','confirmation']:
 p=ROOT/run;client=read(p/'mcp-raw.jsonl');server=read(p/'ru-raw.jsonl');rx=[e for e in server if e['op']!='end'];tx=[e for e in client if e['op'] in ('data','checkpoint')]
 assert len(tx)==len(rx),(run,'event mismatch')
 source={}
 for e in client:
  if 'payload_sha256' in e:
   k=(e['case'],e['index']);h=e['payload_sha256'];assert len(h)==64
   if k in source:assert source[k]==h
   source[k]=h
 assert len(set(source.values()))==len(source),'payload reuse inside run'
 assert not (set(source.values())&all_sources),'payload reuse between runs'
 all_sources.update(source.values())
 for case in {k[0] for k in source}:
  indices={k[1] for k in source if k[0]==case};assert indices==set(range(1,max(indices)+1)),(run,case,'source position gap')
 rows=collections.defaultdict(lambda:collections.Counter());first_reject={};seen=collections.defaultdict(set);models={};offered=collections.defaultdict(set);payload_checks=0;cp_events=0
 for s,r in zip(tx,rx):
  for k in ['op','case','index','stage','wire_sha256','wire_bytes']:assert s[k]==r[k],(run,k)
  case=s['case'];c=s['index']
  if case not in models:models[case]=[Model(n) for n in names]
  expected_mask=0;expected_cp=0
  for i,m in enumerate(models[case]):
   ok,cp=m.event(s)
   if ok:expected_mask|=1<<i
   if cp:expected_cp|=1<<i
  assert r['ok_mask']==expected_mask,(run,case,c,s['stage'],r['ok_mask'],expected_mask)
  assert r['checkpoint_mask']==expected_cp,(run,case,c,'checkpoint mask')
  if s['op']=='checkpoint':cp_events+=1;continue
  if s['stage'] not in ('corrupt','replay'):offered[case].add(c)
  if s['stage'] in ('corrupt','replay'):assert r['ok_mask']==0
  for i,name in enumerate(names):
   ok=bool(r['ok_mask']&(1<<i));key=(case,name)
   if ok:
    assert r['payload_sha256'][name]==s['payload_sha256'],(run,case,c,name,'hash mismatch')
    assert r['decoded_index'][name]==c,(run,case,c,name,'index mismatch')
    assert c not in seen[key],(run,case,c,name,'duplicate application delivery');seen[key].add(c);payload_checks+=1
    rows[key]['accepted']+=1;rows[key][s['stage']]+=1
   elif s['stage'] not in ('corrupt','replay') and key not in first_reject:first_reject[key]=c
  # Only disjoint intervals, if a subsequent chart needs a progression view.
  if case=='cumulative-loss':all_records.append({'run':run,'position':c,'block':(c-1)//4000+1,**{n:int(bool(r['ok_mask']&(1<<i))) for i,n in enumerate(names)}})
 summary=json.loads((p/'mcp-summary.json').read_text());ru=json.loads((p/'ru-summary.json').read_text());audit=json.loads((p/'audit.json').read_text())
 assert summary['source_payloads']==len(source)
 assert summary['ks_bytes_sent']==sum(e['wire_bytes'] for e in tx)
 assert audit['client_exit']==audit['server_exit']==0 and audit['listener_closed'] and audit['production_snapshot_unchanged']
 assert audit['raw_sha256']=={n:sha(p/n) for n in ['mcp-raw.jsonl','ru-raw.jsonl']}
 for name in names:
  assert rows[('no-loss',name)]['accepted']==256
  assert rows[('burst-boundary',name)]['accepted']==160
  assert rows[('corruption-replay',name)]['accepted']==1
  assert rows[('long-gap-no-checkpoint',name)]['resumed']==0
  assert rows[('long-gap-no-checkpoint',name)]['accepted']==64
 expected=[8191,16383,20000,20000,20000]
 for name,count in zip(names,expected):assert rows[('cumulative-loss',name)]['accepted']==count
 assert first_reject[('cumulative-loss','legacy-8192')]==16384
 assert first_reject[('cumulative-loss','legacy-16384')]==32768
 for name in ['checkpoint-reset','checkpoint-retain']:assert rows[('long-gap',name)]['resumed']==128
 assert rows[('long-gap','checkpoint-reset')]['late']==0
 assert rows[('long-gap','checkpoint-retain')]['late']==32
 for name in names[:3]:assert rows[('long-gap',name)]['resumed']==0
 for case,ms in models.items():
  for m in ms:
   if not m.legacy:
    assert ru[case][m.name]['max_slots']<=8320
    assert ru[case][m.name]['restores']==m.restores
 for (case,name),counts in sorted(rows.items()):all_counts.append({'run':run,'case':case,'variant':name,'offered_unique_valid':len(offered[case]),'accepted':counts['accepted'],'warm':counts['warm'],'resumed':counts['resumed'],'late':counts['late'],'first_rejected_valid_position':first_reject.get((case,name)),**ru[case][name]})
 assert all(ru['source_restart_characterization'].values())
 run_audits[run]={'verified':True,'source_payloads':len(source),'wire_events':len(tx),'payload_hash_checks':payload_checks,'checkpoint_events':cp_events,'raw_sha256':audit['raw_sha256'],'predictions_match_every_event':True,'listener_closed':True,'production_snapshot_unchanged':True,'elapsed_ms':summary['elapsed_ms'],'ks_bytes_sent':summary['ks_bytes_sent']}

# Aggregate disjoint 4000-position blocks, never overlapping cumulative points.
blocks=[]
for run in ['main','confirmation']:
 for block in range(1,11):
  xs=[x for x in all_records if x['run']==run and x['block']==block]
  assert len(xs)==2000
  blocks.append({'run':run,'block':block,'delivered':len(xs),**{n:sum(x[n] for x in xs) for n in names}})
result={'verified':True,'kind':'independent log accounting and counter model; NOT independent cryptographic proof','no_payload_reuse_across_runs':True,'fresh_source_payloads_total':len(all_sources),'runs':run_audits,'counts':all_counts,'disjoint_blocks':blocks}
(ROOT/'independent-audit.json').write_text(json.dumps(result,ensure_ascii=False,indent=2)+'\n')
(ROOT/'comparison.csv').write_text('run,case,variant,offered_unique_valid,accepted,warm,resumed,late,first_rejected_valid_position,slots,max_slots,steps,high,gen,restores\n'+'\n'.join(','.join(str(r.get(k,'')) if r.get(k) is not None else '' for k in ['run','case','variant','offered_unique_valid','accepted','warm','resumed','late','first_rejected_valid_position','slots','max_slots','steps','high','gen','restores']) for r in all_counts)+'\n')
print(json.dumps({k:v for k,v in result.items() if k not in ('counts','disjoint_blocks')},ensure_ascii=False))
