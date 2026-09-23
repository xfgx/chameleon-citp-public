#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Тестовая (ИГРУШЕЧНАЯ) реализация Идеи 8.
Совместный поиск политики расписания/маскировки KS против пассивного
классификатора и активного воздействия, с ОБЯЗАТЕЛЬНОЙ абляцией
ChaosSync -> PRF (пункт D идеи 8).

ЧЕСТНОСТЬ:
- Это симуляция на игрушечной модели, НЕ измерение реального ТСПУ/DPI и
  НЕ изменение боевого KS. Выводы относятся только к модели.
- Детерминированный хаос != криптостойкость. NMSE<0.1 != совпадение ключей.
- EMB_CADENCE (плотность встроенных сэмплов) — единственный подбираемый параметр;
  его мы явно прогоняем (sweep), чтобы не подгонять результат.
"""
import math, random, json, os

N_SLOTS   = 120
N_SAMPLES = 160
SEEDS     = [1, 2, 3]
W         = 12
PROBE     = N_SLOTS // 2
NMSE_MAX  = 0.10
LAT_MAX   = 0.25
LAMBDA    = 0.30
EMB_CADENCE = int(os.environ.get('EMB_CADENCE', '5'))  # шаг сэмплов для embedded M8

GAPS   = ['profile', 'uniform', 'const']
SIZES  = ['profile', 'fixed']
M8S    = ['embedded', 'separate']
REACTS = ['silent', 'burst', 'suspend']

def policies():
    out = []
    for g in GAPS:
        for s in SIZES:
            for m in M8S:
                for r in REACTS:
                    out.append({'gap': g, 'size': s, 'm8': m, 'react': r})
    return out

# ---- Хаотический наблюдатель (игрушечный) -> NMSE ----
def logistic_nmse(cadence, loss, seed=0, r=3.99, n=240, quant=1e-2):
    rng = random.Random(seed * 7919 + cadence * 31 + int(loss * 1000))
    x = 0.3141592
    xs = []
    for _ in range(n):
        x = r * x * (1.0 - x)
        xs.append(x)
    y = 0.5
    ys = []
    for t in range(n):
        if t > 0:
            y = r * y * (1.0 - y)
            if y < 0.0 or y > 1.0: y = 0.5
        if t % cadence == 0:
            if rng.random() > loss:
                y = xs[t] + rng.uniform(-quant, quant)
        ys.append(y)
    mx = sum(xs) / n
    var = sum((v - mx) ** 2 for v in xs) / n
    mse = sum((ys[i] - xs[i]) ** 2 for i in range(n)) / n
    return mse / var if var > 0 else 1.0

def nmse_of(p, seed):
    cadence = 2 if p['m8'] == 'separate' else EMB_CADENCE
    if p['react'] == 'suspend':
        cadence += 2
    loss = {'burst': 0.03, 'silent': 0.15, 'suspend': 0.08}[p['react']]
    return sum(logistic_nmse(cadence, loss, seed=seed*11+k) for k in range(8))/8.0

def latency_of(p):
    return 0.30 if p['react'] == 'suspend' else 0.05

def cost_of(p):
    c = 0.05
    if p['m8'] == 'separate': c += 0.30
    if p['react'] == 'burst': c += 0.20
    if p['size'] == 'profile': c += 0.10
    return c

# ---- Трассы и признаки ----
def bimodal_size(rng):
    if rng.random() < 0.7:
        return 0.90 + rng.uniform(-0.05, 0.05)
    return 0.30 + rng.uniform(-0.05, 0.05)

def gen_trace(p, ours, rng):
    sends, sizes, tiny = [], [], []
    app_react = rng.choice([1.0, 1.4])   # обычные приложения тоже иногда ускоряются
    for t in range(N_SLOTS):
        in_react = PROBE <= t < PROBE + W
        if not ours:
            pr = 0.60 * (app_react if in_react else 1.0)
            do = rng.random() < pr
        else:
            g = p['gap']
            if g == 'const':
                do = (t % 2 == 0)
            elif g == 'uniform':
                do = rng.random() < 0.50
            else:
                do = rng.random() < 0.60
            if in_react:
                rm = p['react']
                if rm == 'burst':
                    if not do and rng.random() < 0.5: do = True
                elif rm == 'suspend':
                    if do and rng.random() < 0.6: do = False
        if do:
            sends.append(t)
            if ours and p['size'] == 'fixed':
                sizes.append(0.70 + rng.uniform(-0.02, 0.02))
            else:
                sizes.append(bimodal_size(rng))
        if ours and p['m8'] == 'separate' and (t % 2 == 0):
            tiny.append(t)
    return sends, sizes, tiny

def features(tr):
    sends, sizes, tiny = tr
    n = len(sends)
    gaps = [sends[i+1]-sends[i] for i in range(n-1)] if n >= 2 else [0.0]
    mg = sum(gaps)/len(gaps)
    vg = sum((x-mg)**2 for x in gaps)/len(gaps)
    sg = math.sqrt(vg)
    if sizes:
        ms = sum(sizes)/len(sizes)
        ss = math.sqrt(sum((x-ms)**2 for x in sizes)/len(sizes))
    else:
        ms, ss = 0.0, 0.0
    if len(gaps) >= 3 and vg > 1e-9:
        a = gaps[:-1]; b = gaps[1:]
        ma = sum(a)/len(a); mb = sum(b)/len(b)
        cov = sum((a[i]-ma)*(b[i]-mb) for i in range(len(a)))/len(a)
        va = sum((x-ma)**2 for x in a)/len(a)
        vb = sum((x-mb)**2 for x in b)/len(b)
        ac = cov/math.sqrt(va*vb) if va > 1e-9 and vb > 1e-9 else 0.0
    else:
        ac = 0.0
    tiny_frac = len(tiny)/max(1, n+len(tiny))
    before = sum(1 for t in sends if PROBE-W <= t < PROBE)/W
    after  = sum(1 for t in sends if PROBE <= t < PROBE+W)/W
    reaction = after-before
    return [mg, sg, ms, ss, ac, tiny_frac, reaction]

# ---- Наивный гауссовский классификатор -> AUC ----
def auc_from_scores(pos, neg):
    allv = [(s,1) for s in pos] + [(s,0) for s in neg]
    allv.sort(key=lambda t: t[0])
    n = len(allv); j = 0; rsum = 0.0
    while j < n:
        k = j
        while k+1 < n and allv[k+1][0] == allv[j][0]:
            k += 1
        avg = (j+k)/2.0 + 1.0
        for m in range(j, k+1):
            if allv[m][1] == 1:
                rsum += avg
        j = k+1
    npos = len(pos); nneg = len(neg)
    U = rsum - npos*(npos+1)/2.0
    return U/(npos*nneg)

def stats(F):
    d = len(F[0]); mu = [0.0]*d
    for x in F:
        for j in range(d): mu[j] += x[j]
    for j in range(d): mu[j] /= len(F)
    var = [0.0]*d
    for x in F:
        for j in range(d): var[j] += (x[j]-mu[j])**2
    for j in range(d): var[j] = var[j]/max(1, len(F)-1) + 1e-9
    return mu, var

def auc_our_vs_app(F1, F0, rng):
    def split(F):
        idx = list(range(len(F))); rng.shuffle(idx)
        h = len(F)//2
        return [F[i] for i in idx[:h]], [F[i] for i in idx[h:]]
    tr1, te1 = split(F1); tr0, te0 = split(F0)
    mu1, var1 = stats(tr1); mu0, var0 = stats(tr0)
    d = len(mu1)
    def score(x):
        s = 0.0
        for j in range(d):
            s += -0.5*math.log(var1[j]) - 0.5*(x[j]-mu1[j])**2/var1[j]
            s -= -0.5*math.log(var0[j]) - 0.5*(x[j]-mu0[j])**2/var0[j]
        return s
    return auc_from_scores([score(x) for x in te1], [score(x) for x in te0])

def dist_of(p):
    Ds = []
    for seed in SEEDS:
        rng = random.Random(1000+seed)
        F0 = [features(gen_trace(p, False, rng)) for _ in range(N_SAMPLES)]
        F1 = [features(gen_trace(p, True,  rng)) for _ in range(N_SAMPLES)]
        Ds.append(2.0*abs(auc_our_vs_app(F1, F0, rng)-0.5))
    return sum(Ds)/len(Ds)

def assess(p, D, prf):
    nmse = 0.0 if prf else sum(nmse_of(p, s) for s in SEEDS)/len(SEEDS)
    lat = latency_of(p); cost = cost_of(p)
    return {'policy': p, 'D': D, 'nmse': nmse, 'latency': lat, 'cost': cost,
            'feasible': (nmse <= NMSE_MAX and lat <= LAT_MAX),
            'J': D + LAMBDA*cost}

def best_feasible(rs):
    feas = [r for r in rs if r['feasible']]
    return min(feas, key=lambda r: r['J']) if feas else None

def fmt(r):
    p = r['policy']
    return ("gap=%-7s size=%-7s m8=%-8s react=%-7s | D=%.3f nmse=%.3f lat=%.2f cost=%.2f J=%.3f %s"
            % (p['gap'], p['size'], p['m8'], p['react'], r['D'], r['nmse'],
               r['latency'], r['cost'], r['J'], 'OK' if r['feasible'] else 'INFEAS'))

def main():
    ps = policies()
    Ds = [dist_of(p) for p in ps]
    res_chaos = [assess(ps[i], Ds[i], False) for i in range(len(ps))]
    res_prf   = [assess(ps[i], Ds[i], True)  for i in range(len(ps))]

    indep = {'gap': 'profile', 'size': 'profile', 'm8': 'separate', 'react': 'silent'}
    res_indep = assess(indep, dist_of(indep), False)

    joint_chaos = best_feasible(res_chaos)
    joint_prf   = best_feasible(res_prf)

    print("=== SIM8 START (EMB_CADENCE=%d) ===" % EMB_CADENCE)
    print("Policies: %d; seeds: %d; window: %d slots; probe at slot %d" %
          (len(ps), len(SEEDS), N_SLOTS, PROBE))
    print("Constraints: NMSE<=%.2f, latency<=%.2f; J=D+%.2f*cost; D=2|AUC-0.5|" %
          (NMSE_MAX, LAT_MAX, LAMBDA))
    print()
    print("[2] Independent tuning (greedy sync=separate, 'normal-looking' masking):")
    print("    " + fmt(res_indep))
    print("[1] Joint search with ChaosSync (idea 8):")
    print("    " + (fmt(joint_chaos) if joint_chaos else "no feasible policy"))
    print("[3] Ablation: PRF instead of ChaosSync (same joint search):")
    print("    " + (fmt(joint_prf) if joint_prf else "no feasible policy"))
    print()

    feas = sorted([r for r in res_chaos if r['feasible']], key=lambda r: r['J'])
    emb_feas = [r for r in feas if r['policy']['m8'] == 'embedded']
    print("Feasible under ChaosSync: %d of %d (of them embedded-M8: %d)" %
          (len(feas), len(ps), len(emb_feas)))
    print("Top-3 feasible (ChaosSync):")
    for r in feas[:3]:
        print("    " + fmt(r))
    print()

    print("=== CONCLUSIONS (about this toy model only) ===")
    if joint_chaos:
        di = res_indep['D']; dj = joint_chaos['D']
        if dj < di - 0.02:
            print("- Joint search LOWERED distinguishability vs independent: D %.3f -> %.3f (dD=%.3f)." % (di, dj, di-dj))
        elif dj > di + 0.02:
            print("- Joint search did NOT beat independent: D %.3f -> %.3f." % (di, dj))
        else:
            print("- Joint search comparable to independent: D %.3f ~ %.3f." % (di, dj))
    if joint_chaos and joint_prf:
        dc = joint_chaos['D']; dp = joint_prf['D']
        cc = joint_chaos['cost']; cp = joint_prf['cost']
        if dp < dc - 0.02 or cp < cc - 0.05:
            print("- Ablation: PRF baseline reaches D=%.3f (cost=%.2f) vs D=%.3f (cost=%.2f) for ChaosSync." % (dp, cp, dc, cc))
            print("  -> In this model the chaotic observer gives NO independent benefit for unobservability.")
        else:
            print("- Ablation: ChaosSync (D=%.3f) not worse than PRF (D=%.3f); chaos at least does not hurt here." % (dc, dp))
    print()

    out = {'emb_cadence': EMB_CADENCE, 'space': len(ps), 'seeds': SEEDS,
           'n_slots': N_SLOTS, 'nmse_max': NMSE_MAX, 'lat_max': LAT_MAX,
           'lambda': LAMBDA, 'independent': res_indep,
           'joint_chaos': joint_chaos, 'joint_prf': joint_prf,
           'n_feasible_chaos': len(feas), 'n_feasible_embedded': len(emb_feas),
           'top3_chaos': feas[:3]}
    with open('sim8-result-emb%d.json' % EMB_CADENCE, 'w') as f:
        json.dump(out, f, ensure_ascii=False, indent=2)
    print("JSON: /files/astra/sim8-result-emb%d.json" % EMB_CADENCE)
    print("=== SIM8 DONE ===")

if __name__ == '__main__':
    main()
