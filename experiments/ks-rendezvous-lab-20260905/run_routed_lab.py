#!/usr/bin/env python3
"""Run ONLY in fresh network+mount namespaces; models routed /64, not Internet.
Example: unshare --net --mount --propagation private --fork sh -c \
'mount -t tmpfs tmpfs /run/netns && exec python3 run_routed_lab.py'
Requires root, iproute2, nft, tcpdump, and ./ks-rendezvous-linux-amd64.
"""
import collections,hashlib,ipaddress,json,os,pathlib,signal,struct,subprocess,sys,tempfile,time
ROOT=pathlib.Path(__file__).resolve().parent
BIN=str(ROOT/'ks-rendezvous-linux-amd64')
OUT=ROOT/'routed-results';OUT.mkdir(exist_ok=True)
PREFIX='2001:db8:300::/64';PRIMARY='2001:db8:300::193';PORT=24443
NAMES=['rv_client','rv_node'];processes=[];handles=[];created=[];creds=None
report={'scope':'isolated routed IPv6 on RU, NOT MCP-to-RU Internet','clock':'injected epochs 100 and 101, not a wall-clock rotation daemon','cases':[]}

def cmd(args,ns=None,check=True,timeout=10):
    if ns:args=['ip','netns','exec',ns]+args
    p=subprocess.run(args,text=True,capture_output=True,timeout=timeout)
    if check and p.returncode:raise RuntimeError(f'{args}: {p.stderr}')
    return p

def ip(args,ns=None):return cmd(['ip']+args,ns)

def save(path,obj):path.write_text(json.dumps(obj,indent=2)+'\n')

def plan(profile,epoch,ns):
    return json.loads(cmd([BIN,'-mode','plan','-schedule',str(profile),'-at-unix',str(epoch*30)],ns).stdout)

def start_server(eps,label):
    config=json.loads((creds/'server.json').read_text());config.update(endpoints=eps,protected_ips=[PRIMARY],timeout_ms=1200)
    path=creds/(label+'-server.json');save(path,config)
    log=OUT/(label+'-server.log');h=log.open('w');handles.append(h)
    p=subprocess.Popen(['ip','netns','exec','rv_node',BIN,'-mode','server','-config',str(path),'-duration','60s'],stdout=h,stderr=subprocess.STDOUT);processes.append(p)
    for _ in range(50):
        if '"event":"ready"' in log.read_text():return p
        if p.poll() is not None:raise RuntimeError('server exited: '+log.read_text())
        time.sleep(.04)
    raise RuntimeError('server not ready')

def stop(p):
    if p.poll() is None:
        p.terminate()
        try:p.wait(timeout=4)
        except subprocess.TimeoutExpired:p.kill();p.wait(timeout=2)

def probe(label,eps,expected,count=3,pin=None):
    config=json.loads((creds/'client.json').read_text());config.update(endpoints=eps,protected_ips=[PRIMARY],timeout_ms=1200)
    if pin:config['node_spki_sha256']=pin
    path=creds/(label+'-client.json');save(path,config)
    p=cmd([BIN,'-mode','probe','-config',str(path),'-count',str(count),'-interval','10ms'],'rv_client',check=False,timeout=12)
    (OUT/(label+'-client.jsonl')).write_text(p.stdout+p.stderr)
    events=[json.loads(x) for x in p.stdout.splitlines() if x.startswith('{')]
    dials=[e.get('endpoint','') for e in events if e['event']=='dial']
    ok=sum(e['event']=='probe_ok' for e in events)
    row={'case':label,'requested':count,'application_probes':sum(e['event'] in ('probe_ok','probe_failed') for e in events),'successful':ok,'expected':expected,'returncode':p.returncode,'dialed':dials,'connected':[e.get('endpoint') for e in events if e['event']=='connected'],'authentication_rejections':sum(e['event']=='authentication_failed' for e in events),'primary_dialed':f'[{PRIMARY}]:{PORT}' in dials}
    row['passed']=ok==expected and (p.returncode==0 if expected==count else p.returncode!=0) and not row['primary_dialed']
    report['cases'].append(row)
    if not row['passed']:raise AssertionError(row)
    return row

def main():
    global creds
    interfaces=json.loads(cmd(['ip','-j','link']).stdout)
    if os.readlink('/proc/self/ns/net')==os.readlink('/proc/1/ns/net'):raise RuntimeError('REFUSE: initial host network namespace')
    if any(x['ifname']!='lo' and not (x['ifname']=='sit0' and x.get('link_type')=='sit' and x.get('operstate')=='DOWN' and x.get('address')=='0.0.0.0') for x in interfaces):raise RuntimeError('REFUSE: unexpected interface in isolated namespace')
    if cmd(['ip','-4','route']).stdout.strip() or cmd(['ip','-6','route']).stdout.strip():raise RuntimeError('REFUSE: preexisting routes')
    # Refuse to mount over the real host namespace directory accidentally.
    if 'tmpfs /run/netns tmpfs' not in pathlib.Path('/proc/mounts').read_text():raise RuntimeError('REFUSE: private tmpfs /run/netns required')
    ip(['link','set','lo','up'])
    for ns in NAMES:ip(['netns','add',ns]);created.append(ns);ip(['link','set','lo','up'],ns)
    for name,ns,sub in [('c','rv_client','100'),('n','rv_node','200')]:
        outer='rv_'+name+'0';peer='rv_'+name+'p'
        ip(['link','add',outer,'type','veth','peer','name',peer]);ip(['link','set',peer,'netns',ns]);ip(['link','set',outer,'up']);ip(['link','set',peer,'up'],ns)
        ip(['-6','addr','add',f'2001:db8:{sub}::1/64','dev',outer,'nodad']);ip(['-6','addr','add',f'2001:db8:{sub}::2/64','dev',peer,'nodad'],ns)
        ip(['-6','route','add','default','via',f'2001:db8:{sub}::1'],ns)
    cmd(['sysctl','-q','-w','net.ipv6.conf.all.forwarding=1'])
    # Wait for automatic link-local DAD on all four freshly created interfaces.
    # This is setup readiness, not an application probe or an Internet claim.
    ready=False
    for _ in range(100):
        pending=False
        for dev,ns in [('rv_c0',None),('rv_n0',None),('rv_cp','rv_client'),('rv_np','rv_node')]:
            state=json.loads(ip(['-j','-6','addr','show','dev',dev],ns).stdout)
            links=[a for row in state for a in row['addr_info'] if a.get('scope')=='link']
            pending=pending or not links or any(a.get('tentative',False) or a.get('dadfailed',False) or 'tentative' in a.get('flags',[]) or 'dadfailed' in a.get('flags',[]) for a in links)
        if not pending:ready=True;break
        time.sleep(.05)
    if not ready:raise RuntimeError('link-local address initialization did not finish')
    report['link_local_setup_ready']=True
    ip(['-6','route','add',PREFIX,'via','2001:db8:200::2'])
    ip(['-6','route','add','unreachable',PREFIX],'rv_node')
    ip(['-6','addr','add',PRIMARY+'/128','dev','lo','nodad'],'rv_node')
    creds=pathlib.Path(tempfile.mkdtemp(prefix='rv-fixture-',dir=ROOT));creds.rmdir()
    cmd([BIN,'-mode','init','-dir',str(creds)])
    (creds/'hop.key').write_bytes(os.urandom(32));os.chmod(creds/'hop.key',0o600)
    public=json.loads((creds/'client.json').read_text())['node_spki_sha256']
    profile={'prefix':PREFIX,'full_prefix_authorized':True,'hop_key_file':'hop.key','node_id':public,'step_seconds':30,'port':PORT,'protected_ips':[PRIMARY]}
    cp=creds/'client-schedule.json';sp=creds/'server-schedule.json';save(cp,profile);save(sp,profile)
    p0=plan(cp,100,'rv_client');s0=plan(sp,100,'rv_node');p1=plan(cp,101,'rv_client');s1=plan(sp,101,'rv_node')
    assert p0==s0 and p1==s1 and p0['endpoints'][0]!=p1['endpoints'][0]
    report['independent_plans_match']=True;report['plans']={'epoch100':p0,'epoch101':p1}
    eps=sorted(set(p0['endpoints']+p1['endpoints']));addrs=[ep[1:ep.index(']')] for ep in eps]
    for a in addrs:ip(['-6','addr','add',a+'/128','dev','lo','nodad'],'rv_node')
    cmd(['nft','add','table','ip6','rv_filter'])
    cmd(['nft','add','chain','ip6','rv_filter','forward','{ type filter hook forward priority 0; policy accept; }'])
    cmd(['nft','add','rule','ip6','rv_filter','forward','ip6','daddr',PREFIX,'ip6','daddr','!=','{ '+', '.join(addrs)+' }','drop'])
    caplog=(OUT/'capture.log').open('w');handles.append(caplog)
    cap=subprocess.Popen(['tcpdump','--immediate-mode','-n','-U','-i','rv_c0','-w',str(OUT/'wire.pcap'),'ip6'],stdout=caplog,stderr=caplog);processes.append(cap);time.sleep(.25)
    server=start_server(s0['endpoints'],'epoch100')
    probe('initial',p0['endpoints'],3)
    old=p0['endpoints'][0][1:].split(']')[0]
    cmd(['nft','insert','rule','ip6','rv_filter','forward','ip6','daddr',old,'counter','drop'])
    row=probe('current_ip_blocked',p0['endpoints'],3)
    assert row['connected'] and row['connected'][0]!=p0['endpoints'][0]
    stop(server);server=start_server(s1['endpoints'],'epoch101')
    probe('next_epoch_new_address',p1['endpoints'],3)
    probe('expired_window',plan(cp,98,'rv_client')['endpoints'],0,1)
    wrong=dict(profile);wrong['hop_key_file']='wrong-hop.key';(creds/'wrong-hop.key').write_bytes(os.urandom(32));os.chmod(creds/'wrong-hop.key',0o600);wp=creds/'wrong-schedule.json';save(wp,wrong)
    probe('wrong_hop_key',plan(wp,101,'rv_client')['endpoints'],0,1)
    row=probe('wrong_node_identity',p1['endpoints'],0,1,pin='0'*64);assert row['authentication_rejections']>0
    row=probe('protected_primary_config',[f'[{PRIMARY}]:{PORT}'],0,1);assert not row['dialed']
    cmd(['nft','insert','rule','ip6','rv_filter','forward','ip6','daddr',PREFIX,'counter','drop'])
    probe('entire_prefix_blocked',p1['endpoints'],0,1)
    report['router_filters']=cmd(['nft','list','ruleset']).stdout
    stop(server);cap.send_signal(signal.SIGINT);cap.wait(timeout=4)
    data=(OUT/'wire.pcap').read_bytes();endian='<' if data[:4]==bytes.fromhex('d4c3b2a1') else '>'
    if struct.unpack(endian+'I',data[20:24])[0]!=1:raise RuntimeError('unexpected capture linktype')
    i=24;total=0;primary=0;tcp=0;seen=set()
    while i+16<=len(data):
        n=struct.unpack(endian+'IIII',data[i:i+16])[2];frame=data[i+16:i+16+n];i+=16+n
        if len(frame)>=54 and frame[12:14]==bytes.fromhex('86dd'):
            total+=1;src=str(ipaddress.IPv6Address(frame[22:38]));dst=str(ipaddress.IPv6Address(frame[38:54]));seen.update([src,dst]);primary+=PRIMARY in (src,dst);tcp+=frame[20]==6
    report['capture']={'ipv6_packets':total,'tcp_packets':tcp,'protected_primary_packets':primary,'scope':'all IPv6 on the isolated client-router link','sha256':hashlib.sha256(data).hexdigest(),'seen_addresses':sorted(seen)}
    assert total>0 and primary==0
    report['overall_pass']=all(c['passed'] for c in report['cases'])

if __name__=='__main__':
    def interrupt(*_):raise KeyboardInterrupt()
    signal.signal(signal.SIGTERM,interrupt)
    try:main()
    except BaseException as e:report['overall_pass']=False;report['error']=repr(e)
    finally:
        for p in reversed(processes):stop(p)
        for h in handles:h.close()
        for ns in reversed(created):cmd(['ip','netns','del',ns],check=False)
        if creds:
            for p in creds.glob('*.key'):p.unlink()
        report['private_keys_removed']=True
        save(OUT/'RESULTS.json',report);print(json.dumps(report,indent=2));sys.exit(0 if report.get('overall_pass') else 1)
