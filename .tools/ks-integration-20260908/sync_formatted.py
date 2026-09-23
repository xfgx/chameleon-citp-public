import pathlib,sys,json,hashlib,tarfile,shutil,os
root=pathlib.Path(sys.argv[1]);backup=pathlib.Path(sys.argv[2]);source=pathlib.Path(sys.argv[3]);names=['internal/chaossync/ks_research_regression_test.go','research/ks-r2-20260908/channel_lab/main.go']
def state(p):
 b=p.read_bytes();return {'sha256':hashlib.sha256(b).hexdigest(),'bytes':len(b),'mode':p.stat().st_mode&511}
after=json.loads((backup/'manifest.after.json').read_text())
for n in names:assert state(root/n)==after[n]
b=backup/'revision-03';b.mkdir(mode=448)
with tarfile.open(b/'before.tar.gz','x:gz') as t:
 for n in names:t.add(root/n,arcname=n,recursive=False)
shutil.copy2(backup/'manifest.after.json',b/'manifest.after.previous.json')
for n in names:
 q=root/n;tmp=q.with_name(q.name+'.formatted.tmp');tmp.write_bytes((source/n).read_bytes());os.chmod(tmp,420);os.replace(tmp,q);after[n]=state(q)
(backup/'manifest.after.json').write_text(json.dumps(after,indent=2))
print('FORMATTED SOURCE INTEGRATED',len(names))
