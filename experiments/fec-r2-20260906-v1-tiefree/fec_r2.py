#!/usr/bin/env python3
"""FEC-R2 v1. Synthetic MCP/RU functional research. Not a VPN benchmark."""
import argparse, ast, asyncio, hashlib, io, itertools, json, os, secrets
import shlex, signal, socket, struct, sys, time, urllib.request, zipfile
from pathlib import Path

K, SIZE, MAX_FRAME, MAX_BYTES = 5, 64, 65536, 5 * 1024 * 1024
POLICIES = ('certificate', 'greedy', 'recommendation')
WHEEL_URL = 'https://files.pythonhosted.org/packages/0e/89/4a9a61bc120ca68bce92b0ea176ddc0e550e58c60ab820603bd5246e7261/asyncssh-2.21.1-py3-none-any.whl'
WHEEL_SHA = 'f218f9f303c78df6627d0646835e04039a156d15e174ad63c058d62de61e1968'

def dump(p, x):
    Path(p).write_text(json.dumps(x, indent=2, sort_keys=True) + '\n')

def h(b):
    return hashlib.sha256(b).hexdigest()

class Wire:
    def __init__(self, sock):
        self.s = sock; self.rx = 0; self.tx = 0
    def exact(self, n):
        parts = []
        while n:
            b = self.s.recv(n)
            if not b: raise EOFError('test connection closed')
            parts.append(b); n -= len(b)
        return b''.join(parts)
    def send(self, x):
        b = json.dumps(x, separators=(',', ':')).encode()
        if len(b) > MAX_FRAME: raise ValueError('frame budget')
        self.tx += len(b) + 4
        if self.tx + self.rx > MAX_BYTES: raise ValueError('traffic budget')
        self.s.sendall(struct.pack('!I', len(b)) + b)
    def recv(self):
        n = struct.unpack('!I', self.exact(4))[0]
        if n > MAX_FRAME: raise ValueError('frame budget')
        self.rx += n + 4
        if self.tx + self.rx > MAX_BYTES: raise ValueError('traffic budget')
        return json.loads(self.exact(n))

class Decoder:
    """Incremental elimination of actual received coefficient/payload equations."""
    def __init__(self, rows=()):
        self.rows = {}
        for m, x in rows: self.add(m, x)
    def add(self, m, hexdata):
        if not isinstance(m, int) or not 0 <= m < (1 << K): raise ValueError('mask')
        raw = bytes.fromhex(hexdata)
        if len(raw) != SIZE: raise ValueError('symbol size')
        v = int.from_bytes(raw, 'big')
        while m:
            p = m.bit_length() - 1
            if p not in self.rows:
                self.rows[p] = (m, v); return
            a, b = self.rows[p]; m ^= a; v ^= b
        if v: raise ValueError('inconsistent equation')
    def remainder(self, m):
        for p in sorted(self.rows, reverse=True):
            if m & (1 << p): m ^= self.rows[p][0]
        return m
    def decoded(self):
        out = {}
        for i in range(K):
            m, v = 1 << i, 0
            for p in sorted(self.rows, reverse=True):
                if m & (1 << p):
                    a, b = self.rows[p]; m ^= a; v ^= b
            if m == 0: out[str(i)] = h(v.to_bytes(SIZE, 'big'))
        return out
    def certificate(self):
        ids = {}; labels = []; representatives = []
        for i in range(K):
            r = self.remainder(1 << i)
            if r == 0: labels.append(0); continue
            if r not in ids:
                ids[r] = len(ids) + 1; representatives.append(r)
            labels.append(ids[r])
        triangles = []
        for a, b, c in itertools.combinations(range(len(representatives)), 3):
            if representatives[a] ^ representatives[b] ^ representatives[c] == 0:
                triangles.append([a + 1, b + 1, c + 1])
        return {'labels': labels, 'triangles': triangles, 'rank': len(self.rows)}

def select_certificate(cert, weights):
    """Selection has ONLY the certificate and current weights, never a matrix."""
    labels = cert['labels']; best = None
    for i, j in itertools.combinations_with_replacement(range(K), 2):
        selected = {labels[i], labels[j]} - {0}
        recover = set(selected)
        if len(selected) == 2:
            for triangle in cert['triangles']:
                if selected.issubset(triangle): recover.update(triangle)
        gain = sum(weights[t] for t in range(K) if labels[t] in recover)
        row = (-gain, i, j)
        if best is None or row < best: best = row
    return [best[1], best[2]]

def extend(space, v):
    return space | frozenset(x ^ v for x in space)

def score(space, weights):
    return sum(weights[i] for i in range(K) if (1 << i) in space)

def oracle(space, weights):
    """Independent exhaustive arbitrary-vector action oracle (not elimination)."""
    best = score(space, weights)
    for a in range(1 << K):
        one = extend(space, a)
        for b in range(a, 1 << K): best = max(best, score(extend(one, b), weights))
    return best

def greedy(space, weights):
    result = []
    for _ in range(2):
        i = max(range(K), key=lambda j: (score(extend(space, 1 << j), weights), -j))
        result.append(i); space = extend(space, 1 << i)
    return result

def all_spaces():
    zero = frozenset([0]); seen = {zero}; todo = [zero]
    while todo:
        s = todo.pop()
        for v in range(1, 1 << K):
            if v in s: continue
            t = extend(s, v)
            if t not in seen: seen.add(t); todo.append(t)
    return sorted(seen, key=lambda s: (len(s), tuple(sorted(s))))

def basis(space):
    result = []; known = frozenset([0])
    for v in sorted(space):
        if v not in known: result.append(v); known = extend(known, v)
    return result

def encode(mask, source):
    value = 0
    for i, b in enumerate(source):
        if mask & (1 << i): value ^= int.from_bytes(b, 'big')
    return value.to_bytes(SIZE, 'big').hex()

def check_hashes(decoded, source):
    for key, value in decoded.items():
        i = int(key)
        if not 0 <= i < K or value != h(source[i]): raise AssertionError('fresh payload mismatch')

class Ledger:
    def __init__(self, path): self.f = open(path, 'x', encoding='utf-8')
    def add(self, x):
        self.f.write(json.dumps(x, sort_keys=True) + '\n'); self.f.flush()
    def close(self): self.f.close()

def serve(outdir):
    out = Path(outdir); auth = sys.stdin.readline(200).strip()
    if len(auth) != 48: raise ValueError('authorization value required on stdin')
    connection = os.environ.get('SSH_CONNECTION', '').split()
    if len(connection) != 4: raise ValueError('explicit SSH peer required')
    allowed, bindhost = connection[0], connection[2]
    signal.signal(signal.SIGALRM, lambda *_: (_ for _ in ()).throw(TimeoutError('server hard cap')))
    signal.alarm(300)
    ledger = Ledger(out / 'ru-raw.jsonl'); start = time.monotonic()
    current = {}; requests = 0; completed = False
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as listener:
            listener.bind((bindhost, 0)); listener.listen(2); listener.settimeout(20)
            print(json.dumps({'ready': True, 'port': listener.getsockname()[1]}), flush=True)
            sock, addr = listener.accept()
            if addr[0] != allowed: sock.close(); raise ValueError('unexpected peer')
            with sock:
                sock.settimeout(25); sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
                wire = Wire(sock)
                hello = wire.recv()
                if not secrets.compare_digest(str(hello.get('auth', '')), auth): raise ValueError('authorization failed')
                wire.send({'authorized': True})
                while requests < 5000:
                    request = wire.recv(); requests += 1
                    op = request.get('op')
                    if op == 'open':
                        rows = request['rows']
                        if len(rows) > K: raise ValueError('initial row budget')
                        current = {p: Decoder(rows) for p in POLICIES}
                        d = current['certificate']; cert = d.certificate()
                        reply = {'certificate': cert, 'recommendation': select_certificate(cert, [1] * K), 'initial_decoded': d.decoded()}
                    elif op == 'repair':
                        repairs = request['repairs']
                        if len(repairs) != 6 or not current: raise ValueError('repair budget/state')
                        counts = {p: 0 for p in POLICIES}
                        for p, m, x in repairs:
                            if p not in current: raise ValueError('policy')
                            counts[p] += 1; current[p].add(m, x)
                        if any(v != 2 for v in counts.values()): raise ValueError('unequal treatment budget')
                        reply = {'decoded': {p: current[p].decoded() for p in POLICIES}}
                    elif op == 'control':
                        rows = request['rows']
                        if len(rows) > 10: raise ValueError('control row budget')
                        reply = {'decoded': Decoder(rows).decoded()}
                    elif op == 'finish':
                        reply = {'finished': True, 'requests': requests, 'rx_application_bytes_before_finish_reply': wire.rx, 'tx_application_bytes_before_finish_reply': wire.tx, 'elapsed_seconds': time.monotonic() - start}
                        wire.send(reply); ledger.add({'request': request, 'reply': reply, 'time_ns': time.time_ns()}); completed = True; break
                    else: raise ValueError('unknown operation')
                    ledger.add({'request': request, 'reply': reply, 'time_ns': time.time_ns()})
                    wire.send(reply)
                if not completed: raise ValueError('request budget exhausted')
    finally:
        signal.alarm(0); ledger.close()
        dump(out / 'ru-exit.json', {'completed': completed, 'requests': requests, 'elapsed_seconds': time.monotonic() - start})

def client_trial(host, port, auth, outdir):
    out = Path(outdir); ledger = Ledger(out / 'mcp-raw.jsonl')
    start = time.monotonic(); results = []; controls = []
    try:
        with socket.create_connection((host, port), timeout=12) as sock:
            sock.settimeout(20); sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
            wire = Wire(sock); wire.send({'auth': auth})
            if wire.recv() != {'authorized': True}: raise ValueError('server authorization handshake')
            def exchange(request): wire.send(request); return wire.recv()
            for name, masks, expected in [('empty_negative', [], 0), ('systematic_positive', [1,2,4,8,16], 5), ('parity_no_repair', [14], 0), ('duplicate_zero', [3,3,0], 0)]:
                source = [secrets.token_bytes(SIZE) for _ in range(K)]
                req = {'op': 'control', 'kind': name, 'rows': [[m, encode(m, source)] for m in masks]}
                rep = exchange(req); check_hashes(rep['decoded'], source)
                if len(rep['decoded']) != expected: raise AssertionError('control failed: ' + name)
                controls.append({'name': name, 'passed': True, 'decoded': len(rep['decoded'])})
                ledger.add({'control': name, 'request': req, 'reply': rep, 'sources': [b.hex() for b in source]})
            spaces = all_spaces()
            cases = [('matched_witness_7', frozenset([0,7]), True), ('matched_witness_28', frozenset([0,28]), True)]
            cases += [('space_%03d' % i, s, False) for i, s in enumerate(spaces)]
            for name, space, fixed in cases:
                if time.monotonic() - start > 240: raise TimeoutError('client hard budget')
                source = [secrets.token_bytes(SIZE) for _ in range(K)]
                coefficients = basis(space)
                opened = exchange({'op': 'open', 'case': name, 'rows': [[m, encode(m, source)] for m in coefficients]})
                feedback_at = time.monotonic_ns()
                # The priorities are genuinely selected AFTER feedback is received.
                weights = [1] * K if fixed else [secrets.choice([1,2,4,8]) for _ in range(K)]
                weights_at = time.monotonic_ns()
                cert = opened['certificate']; selected = select_certificate(cert, weights)
                actions = {'certificate': selected, 'greedy': greedy(space, weights), 'recommendation': opened['recommendation']}
                order = list(POLICIES); secrets.SystemRandom().shuffle(order)
                repairs = [[p, 1 << i, source[i].hex()] for p in order for i in actions[p]]
                reply = exchange({'op': 'repair', 'case': name, 'repairs': repairs})
                scores = {}; recovered = {}
                for p in POLICIES:
                    dec = reply['decoded'][p]; check_hashes(dec, source)
                    expected_space = space
                    for i in actions[p]: expected_space = extend(expected_space, 1 << i)
                    expected = {str(i) for i in range(K) if (1 << i) in expected_space}
                    if set(dec) != expected: raise AssertionError('recoverability mismatch')
                    scores[p] = sum(weights[int(i)] for i in dec); recovered[p] = sorted(map(int, dec))
                optimum = oracle(space, weights)
                if scores['certificate'] != optimum: raise AssertionError('certificate not optimal')
                m = max(cert['labels'], default=0)
                bits = K * max(1, m.bit_length()) + (m*(m-1)*(m-2)//6 if m >= 3 else 0)
                row = {'case': name, 'basis': coefficients, 'weights': weights, 'actions': actions, 'scores': scores, 'oracle_score': optimum, 'recovered': recovered, 'certificate': cert, 'feedback_before_weights': feedback_at <= weights_at, 'certificate_json_bytes': len(json.dumps(cert, separators=(',', ':')).encode()), 'descriptor_raw_bits_excluding_rank_and_framing': bits, 'dense_basis_coefficient_bits_excluding_rank_and_framing': len(coefficients)*K}
                ledger.add({'result': row, 'sources': [b.hex() for b in source], 'opened': opened, 'repair_reply': reply, 'policy_order': order, 'time_ns': time.time_ns()})
                results.append(row)
            finish = exchange({'op': 'finish'})
            ordinary = [r for r in results if r['case'].startswith('space_')]
            summary = {'status': 'passed', 'scope': 'live MCP-to-RU TCP payload reconstruction; controlled finite decoder states, not Internet loss/deadline performance', 'novelty': 'incomplete prior-art check; known algebra; no discovery claim', 'controls': controls, 'distinct_subspaces': len(spaces), 'cases_including_witnesses': len(results), 'certificate_oracle_matches': sum(r['scores']['certificate']==r['oracle_score'] for r in results), 'payload_hash_checks_passed': True, 'after_feedback_priority_checks_passed': all(r['feedback_before_weights'] for r in results), 'certificate_beats_greedy_states': sum(r['scores']['certificate']>r['scores']['greedy'] for r in ordinary), 'certificate_beats_old_recommendation_states': sum(r['scores']['certificate']>r['scores']['recommendation'] for r in ordinary), 'descriptor_smaller_than_dense_basis_states': sum(r['descriptor_raw_bits_excluding_rank_and_framing']<r['dense_basis_coefficient_bits_excluding_rank_and_framing'] for r in ordinary), 'descriptor_larger_than_dense_basis_states': sum(r['descriptor_raw_bits_excluding_rank_and_framing']>r['dense_basis_coefficient_bits_excluding_rank_and_framing'] for r in ordinary), 'witnesses': results[:2], 'client_tx_application_bytes_including_framing': wire.tx, 'client_rx_application_bytes_including_framing': wire.rx, 'elapsed_seconds': time.monotonic()-start, 'server_finish': finish}
            dump(out / 'summary.json', summary)
            return summary
    finally: ledger.close()

def load_ssh():
    import importlib.abc, importlib.util
    with urllib.request.urlopen(WHEEL_URL, timeout=15) as r: b = r.read(1000000)
    if h(b) != WHEEL_SHA: raise ValueError('SSH package checksum')
    z = zipfile.ZipFile(io.BytesIO(b)); names = set(z.namelist())
    class MemoryModules(importlib.abc.MetaPathFinder, importlib.abc.Loader):
        def find_spec(self, n, path=None, target=None):
            p=n.replace('.', '/'); package=p+'/__init__.py' in names
            if (n=='asyncssh' or n.startswith('asyncssh.')) and (package or p+'.py' in names): return importlib.util.spec_from_loader(n,self,is_package=package)
        def create_module(self,spec): return None
        def exec_module(self,m):
            p=m.__name__.replace('.', '/'); p=p+'/__init__.py' if p+'/__init__.py' in names else p+'.py'
            m.__file__='<memory-wheel>/'+p; exec(z.read(p),m.__dict__)
    sys.meta_path.insert(0,MemoryModules())
    import asyncssh
    return asyncssh

async def driver(outdir):
    out=Path(outdir); host=None; process=None; port=None
    for n in ast.parse(Path('/files/VPN/.tools/ru.py').read_text()).body:
        if isinstance(n,ast.Assign) and any(isinstance(t,ast.Name) and t.id=='HOST' for t in n.targets): host=ast.literal_eval(n.value.args[1])
    if host is None: raise ValueError('RU target not resolved')
    ssh=load_ssh(); remote='/tmp/'+out.name; auth=secrets.token_hex(24)
    baseline_commands=['ip route show','ip -6 route show','ip rule show','ip -6 rule show','systemctl show ks-vpn-node ks-vpn-exit ks-vpn-hub ks-vpn-phone ks-admin chaossync-server cham-server -p Id -p ActiveState -p MainPID -p NRestarts']
    async with ssh.connect(host,username='root',client_keys=['/files/VPN/bin/data/ssh_ed25519'],known_hosts='/files/VPN/bin/data/known_hosts',agent_path=None,login_timeout=15) as c:
        async def snapshot():
            result={}
            for cmd in baseline_commands:
                r=await c.run(cmd,timeout=12,check=True); result[cmd]=h(r.stdout.encode())
            return result
        before=await snapshot(); dump(out/'environment-before-hashes.json',before)
        r=await c.run('mkdir -m 700 '+shlex.quote(remote),timeout=12,check=True)
        async with c.start_sftp_client() as sftp:
            await sftp.put(str(Path(__file__).resolve()),remote+'/fec_r2.py')
            await sftp.put(str(out/'protocol.md'),remote+'/protocol.md')
        try:
            process=await c.create_process('python3 -B '+shlex.quote(remote+'/fec_r2.py')+' server '+shlex.quote(remote))
            process.stdin.write(auth+'\n'); await process.stdin.drain()
            ready=json.loads(await asyncio.wait_for(process.stdout.readline(),20)); port=int(ready['port'])
            if ready.get('ready') is not True or not 1024<=port<=65535: raise ValueError('listener readiness')
            print('RU ready; dedicated test listener; generating fresh payloads now',flush=True)
            summary=await asyncio.to_thread(client_trial,host,port,auth,out)
            await asyncio.wait_for(process.wait_closed(),20)
            if process.exit_status != 0: raise RuntimeError('RU server nonzero exit')
            async with c.start_sftp_client() as sftp:
                await sftp.get(remote+'/ru-raw.jsonl',str(out/'ru-raw.jsonl'))
                await sftp.get(remote+'/ru-exit.json',str(out/'ru-exit.json'))
            after=await snapshot(); dump(out/'environment-after-hashes.json',after)
            listeners=await c.run("ss -H -ltn 'sport = :%d'"%port,timeout=10,check=True)
            audit={'core_environment_unchanged':before==after,'listener_closed':not listeners.stdout.strip(),'server_exit':process.exit_status,'code_sha256':h(Path(__file__).read_bytes()),'protocol_sha256':h((out/'protocol.md').read_bytes()),'raw_mcp_sha256':h((out/'mcp-raw.jsonl').read_bytes()),'raw_ru_sha256':h((out/'ru-raw.jsonl').read_bytes()),'remote_artifact_directory':remote,'management_channel_carried_source_symbols':False,'test_transport':'separate TCP connection; addresses visible; application framing bytes are not all on-wire bytes'}
            dump(out/'audit.json',audit)
            if not audit['core_environment_unchanged'] or not audit['listener_closed']: raise AssertionError('post-run environment requires review')
            print(json.dumps({k:v for k,v in summary.items() if k not in ('witnesses','server_finish')},ensure_ascii=False),flush=True)
            print('Cleanup verified; production unchanged',flush=True)
        finally:
            if process is not None and process.exit_status is None:
                process.terminate()
                try: await asyncio.wait_for(process.wait_closed(),10)
                except (TimeoutError,asyncio.TimeoutError): pass

if __name__=='__main__':
    parser=argparse.ArgumentParser(); parser.add_argument('mode',choices=['server','driver']); parser.add_argument('outdir'); a=parser.parse_args()
    if a.mode=='server': serve(a.outdir)
    else:
        status={'status':'failed'}
        try:
            asyncio.run(driver(a.outdir)); status={'status':'completed'}
        except Exception as e:
            import re, traceback
            message=re.sub(r'(?<![\w.])(?:\d{1,3}\.){3}\d{1,3}(?![\w.])','[node address]',str(e))
            status={'status':'failed','error_type':type(e).__name__,'error':message}; print(json.dumps(status),flush=True)
            traceback.print_exc()
        finally: dump(Path(a.outdir)/'driver-exit.json',status)
        if status['status']!='completed': sys.exit(1)
