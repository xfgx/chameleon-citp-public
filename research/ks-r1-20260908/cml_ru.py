import argparse, csv, hashlib, json, math, platform, time
from pathlib import Path
import numpy as np
from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305
import cryptography
ROOT = Path(__file__).resolve().parent
SCALE = 1 << 48
MASK = (1 << 64) - 1
VARIANTS = [('free', 0, 0.0, False), ('fixed1_095', 1, 0.95, False), ('rotate1_095', 1, 0.95, True), ('rotate1_0999', 1, 0.999, True), ('fixed4_095', 4, 0.95, False), ('alternate4_095', 4, 0.95, True), ('all8_075_control', 8, 0.75, False)]

def pub(tag, i):
    return hashlib.sha256(('KS-R1-public-only/' + tag + '/' + str(i)).encode()).digest()

def u64(tag, i):
    return int.from_bytes(pub(tag, i)[:8], 'big')

def mul(a, b):
    return a * b >> 48

def signed(x):
    return x - (1 << 64) if x >= 1 << 63 else x

def word_mul(a, b):
    ab = (a & MASK) * (b & MASK)
    lo = ab & MASK
    hi = ab >> 64 & MASK
    if a < 0:
        hi = hi - (b & MASK) & MASK
    if b < 0:
        hi = hi - (a & MASK) & MASK
    return signed((lo >> 48 | hi << 16) & MASK)

def controls():
    for i in range(10000):
        a = signed(u64('mul-a', i))
        b = signed(u64('mul-b', i))
        assert signed(mul(a, b) & MASK) == word_mul(a, b)
    key = bytes(range(128, 160))
    nonce = bytes.fromhex('070000004041424344454647')
    aad = bytes.fromhex('50515253c0c1c2c3c4c5c6c7')
    plain = b"Ladies and Gentlemen of the class of '99: If I could offer you only one tip for the future, sunscreen would be it."
    expected = bytes.fromhex('d31a8d34648e60db7b86afbc53ef7ec2a4aded51296e08fea9e2b5a736ee62d63dbea45e8ca9671282fafb69da92728b1a71de0a9e060b2905d6a5b67ecd3b3692ddbd7f2d778b8c9803aee328091b58fab324e4fad675945585808b4831d7bc3ff4def08e4b7a9de576d26586cec64b61161ae10b594f09e26a7e902ecbd0600691')
    assert ChaCha20Poly1305(key).encrypt(nonce, plain, aad) == expected
    x = SCALE * 123456789 // 1000000000
    vals = []
    for t in range(20000):
        derivative = 4 * (1 - 2 * x / SCALE)
        if t >= 2048:
            vals.append(math.log2(abs(derivative)))
        x = mul(mul(4 * SCALE, x), SCALE - x)
        assert 0 < x < SCALE
    lam = sum(vals) / len(vals)
    assert abs(lam - 1) < 0.005, lam
    return {'signed_multiplication_cases': 10000, 'rfc8439_2_8_2': 'PASS', 'uncoupled_mu4_lambda_bits': lam, 'uncoupled_mu4_samples': len(vals)}

def step(x, mu, e1, e2):
    f = mul(mul(mu, x), SCALE - x)
    return f + mul(e1, np.roll(f, 1, axis=-1) - f) + mul(e2, np.roll(f, -1, axis=-1) - f)

def fields(n):
    mus = []
    eps1 = []
    eps2 = []
    starts = []
    followers = []
    for k in range(n):
        mus.append([39 * SCALE // 10 + u64('mu-' + str(k), i) % 28147497671065 for i in range(8)])
        eps1.append(u64('eps1', k) % 14073748835533)
        eps2.append(u64('eps2', k) % 14073748835533)
        starts.append([SCALE // 20 + u64('init-' + str(k), i) % (9 * SCALE // 10) for i in range(8)])
        followers.append([SCALE // 20 + u64('follow-' + str(k), i) % (9 * SCALE // 10) for i in range(8)])
    return (np.array(mus, dtype=object), np.array(eps1, dtype=object), np.array(eps2, dtype=object), np.array(starts, dtype=object), np.array(followers, dtype=object))

def experiment_b(out, n, burn, measure):
    mu, e1, e2, x0, y0 = fields(n)
    count = len(VARIANTS)
    field_records = [{'field': i, 'mu_raw': list(map(int, mu[i])), 'eps1_raw': int(e1[i]), 'eps2_raw': int(e2[i]), 'initial_raw': list(map(int, x0[i])), 'observer_initial_raw': list(map(int, y0[i])), 'cycle': list(range(8))} for i in range(n)]
    (out / 'fields.json').write_text(json.dumps(field_records, indent=2))
    x = x0.copy()
    y = np.repeat(y0[:, None, :], count, axis=1)
    mf = np.asarray(mu, dtype=float) / SCALE
    a = np.asarray(e1, dtype=float) / SCALE
    b = np.asarray(e2, dtype=float) / SCALE
    mat = np.zeros((n, 8, 8))
    ii = np.arange(8)
    mat[:, ii, ii] = 1 - a[:, None] - b[:, None]
    mat[:, ii, (ii - 1) % 8] = a[:, None]
    mat[:, ii, (ii + 1) % 8] = b[:, None]
    _, logdet = np.linalg.slogdet(mat)
    logdet /= math.log(2)
    rng = np.random.default_rng(20260908)
    v = rng.normal(size=(n, count, 8))
    v /= np.linalg.norm(v, axis=-1, keepdims=True)
    q = np.repeat(np.eye(8)[None, :, :], n, axis=0)
    logs = np.zeros((n, count))
    detlogs = np.zeros(n)
    qrlogs = np.zeros((n, 8))
    err2 = np.zeros((n, count))
    max_identity_error = 0.0
    err_samples = 0
    c_raw = np.array([int(round(z[2] * 1000)) * SCALE // 1000 for z in VARIANTS], dtype=object)
    c_float = np.asarray(c_raw, dtype=float) / SCALE
    for t in range(burn + measure):
        xf = np.asarray(x, dtype=float) / SCALE
        df = mf * (1 - 2 * xf)
        j = mat * df[:, None, :]
        masks = np.zeros((count, 8), dtype=object)
        for h, (_, k, c, rot) in enumerate(VARIANTS):
            if k == 0:
                continue
            indices = (np.arange(k) * (8 // k) + (t if rot else 0)) % 8
            masks[h, indices] = 1
        d = 1 - np.asarray(masks, dtype=float) * c_float[:, None]
        vv = np.einsum('fij,fsj->fsi', j, v) * d[None, :, :]
        norms = np.linalg.norm(vv, axis=-1)
        assert np.all(norms > 0)
        v = vv / norms[:, :, None]
        q, rr = np.linalg.qr(np.matmul(j, q))
        qlogs = np.log2(np.abs(np.diagonal(rr, axis1=-2, axis2=-1)))
        stepdet = logdet + np.log2(np.abs(df)).sum(axis=-1)
        if t >= burn:
            logs += np.log2(norms)
            detlogs += stepdet
            qrlogs += qlogs
            if t % 257 == 0:
                jc = j[:, None, :, :] * d[None, :, :, None]
                _, ld = np.linalg.slogdet(jc)
                theoretical = stepdet[:, None] + np.log2(d).sum(axis=-1)[None, :]
                max_identity_error = max(max_identity_error, float(np.max(np.abs(ld / math.log(2) - theoretical))))
        xn = step(x, mu, e1[:, None], e2[:, None])
        yn = step(y, mu[:, None, :], e1[:, None, None], e2[:, None, None])
        yn = yn + mul(masks[None, :, :] * c_raw[None, :, None], xn[:, None, :] - yn)
        x, y = (xn, yn)
        assert np.all(x >= 0) and np.all(x <= SCALE)
        assert np.all(y >= 0) and np.all(y <= SCALE)
        if t >= burn + measure - min(1024, measure):
            diff = np.asarray(y - x[:, None, :], dtype=float) / SCALE
            err2 += np.mean(diff * diff, axis=-1)
            err_samples += 1
    rows = []
    for f in range(n):
        for h, (name, k, c, rot) in enumerate(VARIANTS):
            rows.append({'field': f, 'variant': name, 'measure': measure, 'lambda_top_bits': float(logs[f, h] / measure), 'free_top_bits': float(logs[f, 0] / measure), 'free_sum_bits': float(detlogs[f] / measure), 'conditional_sum_bits': float(detlogs[f] / measure + k * math.log2(1 - c_float[h])), 'rms_final_1024': float(math.sqrt(err2[f, h] / err_samples)), 'qr_free_sum_bits': float(qrlogs[f].sum() / measure), 'qr_free_top_bits': float(qrlogs[f, 0] / measure)})

    def write_rows(path, values):
        with path.open('w') as fh:
            wr = csv.DictWriter(fh, fieldnames=list(values[0]))
            wr.writeheader()
            wr.writerows(values)
    write_rows(out / f'cml_{measure}.csv', rows)
    agg = []
    for name, _, _, _ in VARIANTS:
        group = [r for r in rows if r['variant'] == name]
        lam = [r['lambda_top_bits'] for r in group]
        rms = [r['rms_final_1024'] for r in group]
        agg.append({'variant': name, 'fields': n, 'lambda_min': min(lam), 'lambda_median': float(np.median(lam)), 'lambda_max': max(lam), 'rms_median': float(np.median(rms)), 'rms_max': max(rms), 'stable': sum((v < 0 for v in lam)), 'sum_positive': sum((r['conditional_sum_bits'] > 0 for r in group))})
    write_rows(out / f'cml_summary_{measure}.csv', agg)
    qr_error = max((abs(r['free_sum_bits'] - r['qr_free_sum_bits']) for r in rows))
    assert qr_error < 1e-10
    free = np.array([r['lambda_top_bits'] for r in rows if r['variant'] == 'free'])
    all8 = np.array([r['lambda_top_bits'] for r in rows if r['variant'] == 'all8_075_control'])
    shift_error = float(np.max(np.abs(all8 - free + 2)))
    assert shift_error < 0.005
    return {'n_fields': n, 'burn': burn, 'measure': measure, 'variants': count, 'determinant_identity_max_error_bits': max_identity_error, 'qr_sum_max_error_bits': qr_error, 'all8_control_shift_error_bits': shift_error, 'summary': agg}
if __name__ == '__main__':
    import socket
    out=ROOT/'results'; out.mkdir(exist_ok=True)
    for measure in [8192,16384]:
        started=time.time()
        checks=controls()
        result=experiment_b(out,32,2048,measure)
        result['controls']=checks
        result['host']=socket.gethostname()
        result['python']=platform.python_version()
        result['numpy']=np.__version__
        result['elapsed_s']=time.time()-started
        result['script_sha256']=hashlib.sha256(Path(__file__).read_bytes()).hexdigest()
        (out/f'ru_result_{measure}.json').write_text(json.dumps(result,indent=2))
        print(json.dumps(result),flush=True)
