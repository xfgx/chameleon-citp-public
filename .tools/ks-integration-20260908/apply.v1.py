#!/usr/bin/env python3
import sys, pathlib, json, hashlib, tarfile, os, re, io
root=pathlib.Path(sys.argv[1]).resolve(); backup=pathlib.Path(sys.argv[2]).resolve(); mode=sys.argv[3]
def digest(b): return hashlib.sha256(b).hexdigest()
def path(n):
 p=root/n
 if pathlib.PurePosixPath(n).is_absolute() or '..' in pathlib.PurePosixPath(n).parts: raise RuntimeError('unsafe path')
 if p.is_symlink() or not p.resolve().is_relative_to(root): raise RuntimeError('unsafe symlink')
 return p
def state(p):
 if not p.exists(): return None
 if not p.is_file(): raise RuntimeError('not file: '+str(p))
 b=p.read_bytes();return {'sha256':digest(b),'bytes':len(b),'mode':p.stat().st_mode&511}
def write(p,b,perm=420):
 p.parent.mkdir(parents=True,exist_ok=True); q=p.with_name(p.name+'.ks-integration.tmp')
 with open(q,'xb') as f: f.write(b);f.flush();os.fsync(f.fileno())
 os.chmod(q,perm);os.replace(q,p)
def dump(p,x):write(p,(json.dumps(x,indent=2,ensure_ascii=False)+'\n').encode(),384)
if mode=='apply':
 if (backup/'manifest.after.json').exists():raise RuntimeError('already applied; refusing')
 patchfile=pathlib.Path(sys.argv[4]);patch=json.loads(patchfile.read_text());before=json.loads((backup/'manifest.before.json').read_text())
 targets=set(patch['files'])|set(patch['replace'])|set(patch['notes'])|{'agent.md'}
 for n,s in before.items():
  if state(path(n))!=s:raise RuntimeError('pre-state changed: '+n)
 extra={n:state(path(n)) for n in sorted(targets-set(before))}
 if not (backup/'supplemental.before.json').exists():
  with tarfile.open(backup/'supplemental.before.tar.gz','x:gz') as t:
   for n,s in extra.items():
    if s:t.add(path(n),arcname=n,recursive=False)
  dump(backup/'supplemental.before.json',extra)
 else:
  if json.loads((backup/'supplemental.before.json').read_text())!=extra:raise RuntimeError('supplement changed')
 before.update(extra);dump(backup/'manifest.complete.before.json',before)
 original={}
 for archive in ['before.tar.gz','supplemental.before.tar.gz']:
  with tarfile.open(backup/archive) as t:
   for n in t.getnames():
    original[n]=t.extractfile(n).read()
 for n,s in before.items():
  if s and digest(original[n])!=s['sha256']:raise RuntimeError('backup mismatch: '+n)
 planned={}
 for n,text in patch['files'].items():
  if before[n] is not None:raise RuntimeError('new target already exists: '+n)
  planned[n]=text.encode()
 for n,edits in patch['replace'].items():
  text=original[n].decode()
  for a,b in edits:
   if text.count(a)!=1:raise RuntimeError('replacement not unique: '+n)
   text=text.replace(a,b,1)
  if n.endswith('/map.go'):
   strip=lambda x:re.sub(r'/\*.*?\*/|//[^\n]*','',x,flags=re.S)
   if strip(text)!=strip(original[n].decode()):raise RuntimeError('non-comment map edit')
  planned[n]=text.encode()
 for n,note in patch['notes'].items():
  old=original[n];idx=old.find(b'\n')+1
  if idx<=0:raise RuntimeError('no heading')
  planned[n]=old[:idx]+b'\n'+note.encode()+b'\n'+old[idx:]
 planned['agent.md']=original['agent.md']+b'\n\n'+patch['journal'].encode()
 assert planned['agent.md'].startswith(original['agent.md'])
 dump(backup/'apply.plan.json',{'patch_sha256':digest(patchfile.read_bytes()),'targets':sorted(targets),'comment_only_map':True,'journal_prefix_preserved':True})
 for n,b in sorted(planned.items()):
  if state(path(n))!=before[n]:raise RuntimeError('changed during preparation: '+n)
  perm=before[n]['mode'] if before[n] else (493 if n.endswith('.sh') else 420)
  write(path(n),b,perm)
 dump(backup/'manifest.after.json',{n:state(path(n)) for n in sorted(targets)})
 print(json.dumps({'status':'APPLIED','targets':len(targets),'backups_verified':True,'map_comments_only':True,'journal_prefix_preserved':True}))
elif mode in ('check','rollback'):
 before=json.loads((backup/'manifest.complete.before.json').read_text());after=json.loads((backup/'manifest.after.json').read_text())
 for n,s in after.items():
  if state(path(n))!=s:raise RuntimeError('after-state changed; manual review required: '+n)
 if mode=='rollback':
  original={}
  for archive in ['before.tar.gz','supplemental.before.tar.gz']:
   with tarfile.open(backup/archive) as t:
    for n in t.getnames():original[n]=t.extractfile(n).read()
  for n in after:
   s=before[n]
   if s:
    if digest(original[n])!=s['sha256']:raise RuntimeError('backup mismatch')
    write(path(n),original[n],s['mode'])
   else:path(n).unlink()
  print('ROLLED BACK FILES ONLY; no services restarted')
 else:print('ROLLBACK DRY-RUN PASS; all after-hashes match; no writes')
else:raise RuntimeError('unknown mode')
