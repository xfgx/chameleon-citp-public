import ast,asyncio,hashlib,io,json,os,secrets,shlex,subprocess,sys,time,urllib.request,zipfile
from pathlib import Path

ROOT=Path('/files/VPN'); OUT=ROOT/'experiments/ks-recovery-20260908-v2'
REMOTE='/tmp/ks-recovery-20260908-v2'
EXPECTED='1c70557dff5f07d379fdc8f89c7b2d747a8e7bdf25e1a998868d595b4e3dbc10'
def sha(b):return hashlib.sha256(b).hexdigest()
def dump(p,obj):p.write_text(json.dumps(obj,ensure_ascii=False,indent=2)+'\n')
def stage(name,**kw):dump(OUT/'status.json',{'stage':name,'time_unix':time.time(),**kw});print(name,flush=True)
def ssh_setup():
 tree=ast.parse((ROOT/'experiments/fec-r2-20260906-v1/fec_r2.py').read_text())
 ns={'io':io,'sys':sys,'zipfile':zipfile,'urllib':urllib,'h':sha}
 for n in tree.body:
  if isinstance(n,ast.Assign) and any(isinstance(t,ast.Name) and t.id in ('WHEEL_URL','WHEEL_SHA') for t in n.targets):exec(compile(ast.Module(body=[n],type_ignores=[]),'<audited constants>','exec'),ns)
 n=next(n for n in tree.body if isinstance(n,ast.FunctionDef) and n.name=='load_ssh');exec(compile(ast.Module(body=[n],type_ignores=[]),'<audited SSH loader>','exec'),ns)
 host=None
 for n in ast.parse((ROOT/'.tools/ru.py').read_text()).body:
  if isinstance(n,ast.Assign) and any(isinstance(t,ast.Name) and t.id=='HOST' for t in n.targets):host=ast.literal_eval(n.value.args[1])
 if not host:raise RuntimeError('RU unresolved')
 return ns['load_ssh'](),host

SNAPSHOT="""python3 -B - <<'RUPY'
import subprocess,json,hashlib,re
from pathlib import Path
commands=['ip route show','ip -6 route show','ip rule show','ip -6 rule show','nft list ruleset','systemctl show ks-vpn-node ks-vpn-exit ks-vpn-hub ks-vpn-phone ks-admin chaossync-server -p Id -p ActiveState -p MainPID -p NRestarts']
r={}
for cmd in commands:
 q=subprocess.run(cmd,shell=True,capture_output=True,text=True,timeout=12)
 if q.returncode:raise RuntimeError('snapshot command failed')
 text=q.stdout
 if cmd=='nft list ruleset':text=re.sub(r'counter packets \\d+ bytes \\d+','counter',text)
 r[cmd]=hashlib.sha256(text.encode()).hexdigest()
p=Path('/root/vpn/internal/chaossync/ks.go');r['production_ks_source']=hashlib.sha256(p.read_bytes()).hexdigest()
for name in ['ks-vpn','ks-hub','ks-admin']:
 p=Path('/root/build')/name
 if p.exists():r['production_binary_'+name]=hashlib.sha256(p.read_bytes()).hexdigest()
print(json.dumps(r))
RUPY"""

async def main():
 if sha((ROOT/'internal/chaossync/ks.go').read_bytes())!=EXPECTED:raise RuntimeError('MCP source changed')
 if (OUT/'completed.json').exists():raise RuntimeError('Do not repeat completed run')
 stage('CONNECTING_RU');ssh,host=ssh_setup()
 async with ssh.connect(host,username='root',client_keys=[str(ROOT/'bin/data/ssh_ed25519')],known_hosts=str(ROOT/'bin/data/known_hosts'),agent_path=None,login_timeout=15) as c:
  async def snap():return json.loads((await c.run(SNAPSHOT,timeout=60,check=True)).stdout)
  before=await snap();dump(OUT/'environment-before.json',before)
  if before['production_ks_source']!=EXPECTED:raise RuntimeError('RU source changed')
  setup="""python3 -B - <<'PY'
from pathlib import Path
import shutil,hashlib
r=Path('/tmp/ks-recovery-20260908-v2');r.mkdir(mode=0o700,exist_ok=False)
(r/'internal/chaossync').mkdir(parents=True);(r/'cmd/ks-recovery-lab').mkdir(parents=True)
for p in Path('/root/vpn/internal/chaossync').glob('*.go'):shutil.copyfile(p,r/'internal/chaossync'/p.name)
(r/'internal/chameleon').mkdir(parents=True)
for p in Path('/root/vpn/internal/chameleon').glob('*.go'):shutil.copyfile(p,r/'internal/chameleon'/p.name)
for n in ['go.mod','go.sum']:shutil.copyfile(Path('/root/vpn')/n,r/n)
assert hashlib.sha256((r/'internal/chaossync/ks.go').read_bytes()).hexdigest()=='1c70557dff5f07d379fdc8f89c7b2d747a8e7bdf25e1a998868d595b4e3dbc10'
print('ISOLATED_SOURCE_COPIED')
PY"""
  await c.run(setup,timeout=20,check=True)
  async with c.start_sftp_client() as sftp:
   for local,remote in [('ks_recovery_lab.go','internal/chaossync/ks_recovery_lab.go'),('ks_recovery_lab_test.go','internal/chaossync/ks_recovery_lab_test.go'),('main.go','cmd/ks-recovery-lab/main.go'),('protocol.md','protocol.md')]:await sftp.put(str(OUT/local),REMOTE+'/'+remote)
  env='export PATH=/usr/local/go/bin:$PATH GOPROXY=off GOSUMDB=off GOTOOLCHAIN=local GOMAXPROCS=2; '
  prefix='cd '+shlex.quote(REMOTE)+' && '+env
  stage('RU_FORMAT_AND_UNIT_TESTS')
  cmds=[('format.log','gofmt -w internal/chaossync/ks_recovery_lab.go internal/chaossync/ks_recovery_lab_test.go cmd/ks-recovery-lab/main.go'),('unit.log',"nice -n 15 go test -count=1 -v -timeout 120s -run '^(TestKs|TestKSRecovery)' ./internal/chaossync"),('race.log',"nice -n 15 go test -race -count=1 -timeout 120s -run '^TestKSRecovery' ./internal/chaossync"),('vet.log','nice -n 15 go vet ./internal/chaossync ./cmd/ks-recovery-lab'),('build.log','CGO_ENABLED=0 nice -n 15 go build -trimpath -o lab ./cmd/ks-recovery-lab')]
  for name,cmd in cmds:
   result=await c.run(prefix+cmd,timeout=240,check=False)
   (OUT/name).write_text(result.stdout+'\nSTDERR\n'+result.stderr)
   dump(OUT/(name+'.status.json'),{'exit':result.exit_status})
   if result.exit_status!=0:raise RuntimeError('RU phase failed: '+name)
   stage('RU_PHASE_PASSED',phase=name)
  built=await c.run('sha256sum '+REMOTE+'/lab '+REMOTE+'/internal/chaossync/ks.go '+REMOTE+'/internal/chaossync/ks_recovery_lab.go '+REMOTE+'/internal/chaossync/ks_recovery_lab_test.go '+REMOTE+'/cmd/ks-recovery-lab/main.go',timeout=10,check=True)
  (OUT/'RU-build-sha256.txt').write_text(built.stdout)
  async with c.start_sftp_client() as sftp:
   await sftp.get(REMOTE+'/lab',str(OUT/'lab'))
   for name in ['ks_recovery_lab.go','ks_recovery_lab_test.go']:await sftp.get(REMOTE+'/internal/chaossync/'+name,str(OUT/('built-'+name)))
   await sftp.get(REMOTE+'/cmd/ks-recovery-lab/main.go',str(OUT/'built-main.go'))
  binaryHash=sha((OUT/'lab').read_bytes());assert binaryHash==built.stdout.split()[0];os.chmod(OUT/'lab',0o700)
  if await snap()!=before:raise RuntimeError('Environment changed during build')
  for run in ['main','confirmation']:
   local=OUT/run;local.mkdir(mode=0o700,exist_ok=False);rd=REMOTE+'/'+run
   await c.run('mkdir -m 700 '+rd,timeout=10,check=True)
   cfg={'key':secrets.token_hex(32),'auth':secrets.token_hex(32),'out':rd,'epoch':int.from_bytes(secrets.token_bytes(4),'big')}
   proc=None;client=None;port=None;stage('LIVE_'+run.upper())
   try:
    proc=await c.create_process('GOMAXPROCS=2 timeout 180s '+REMOTE+'/lab server')
    proc.stdin.write(json.dumps(cfg)+'\n');await proc.stdin.drain()
    ready=json.loads(await asyncio.wait_for(proc.stdout.readline(),30));port=int(ready['port']);assert ready['ready'] and 1024<=port<=65535
    cfg['out']=str(local);cfg['target']=host+':'+str(port)
    client=await asyncio.create_subprocess_exec(str(OUT/'lab'),'client',stdin=asyncio.subprocess.PIPE,stdout=asyncio.subprocess.PIPE,stderr=asyncio.subprocess.PIPE,env={**os.environ,'GOMAXPROCS':'2'})
    stdout,stderr=await asyncio.wait_for(client.communicate((json.dumps(cfg)+'\n').encode()),180)
    (local/'client.log').write_bytes(stdout+b'\nSTDERR\n'+stderr)
    if client.returncode!=0:raise RuntimeError('Live client nonzero exit')
    await asyncio.wait_for(proc.wait_closed(),25)
    if proc.exit_status!=0:raise RuntimeError('Live RU nonzero exit')
    async with c.start_sftp_client() as sftp:
     for n in ['ru-raw.jsonl','ru-summary.json']:await sftp.get(rd+'/'+n,str(local/n))
    listeners=await c.run("ss -H -ltn 'sport = :%d'"%port,timeout=10,check=True)
    after=await snap();dump(local/'environment-after.json',after)
    audit={'binary_sha256':binaryHash,'mcp_source_sha256':EXPECTED,'ru_source_sha256':before['production_ks_source'],'client_exit':client.returncode,'server_exit':proc.exit_status,'listener_closed':not listeners.stdout.strip(),'production_snapshot_unchanged':after==before,'management_channel_carried_payload':False,'compilation_host':'RU only','transport':'MCP to RU; TCP laboratory framing of KS datagrams; no production UDP claim','raw_sha256':{n:sha((local/n).read_bytes()) for n in ['mcp-raw.jsonl','ru-raw.jsonl']}}
    dump(local/'audit.json',audit)
    if not audit['listener_closed'] or not audit['production_snapshot_unchanged']:raise RuntimeError('Post-run condition failed')
   finally:
    cfg.clear()
    if client is not None and client.returncode is None:client.kill();await client.wait()
    if proc is not None and proc.exit_status is None:
     proc.terminate()
     try:await asyncio.wait_for(proc.wait_closed(),10)
     except asyncio.TimeoutError:proc.kill()
  final=await snap();dump(OUT/'environment-after.json',final)
  if final!=before:raise RuntimeError('Final snapshot changed')
  dump(OUT/'completed.json',{'completed':True,'runs':['main','confirmation'],'binary_sha256':binaryHash,'production_unchanged':True,'note':'Independent raw-data verification is a separate next step.'})
  stage('COMPLETE_AWAITING_INDEPENDENT_AUDIT')

if __name__=='__main__':
 try:asyncio.run(main())
 except BaseException as e:
  stage('FAILED',error_type=type(e).__name__,detail=str(e) if isinstance(e,(AssertionError,RuntimeError)) else 'Details withheld to avoid endpoint disclosure')
  raise SystemExit(1)
