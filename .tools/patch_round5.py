#!/usr/bin/env python3
# Раунд 5: best-of-K выбор генома по fitness (novelty+leverage) + leak-учёт.
import sys

AP = "/files/VPN/cmd/chamd/autopilot.go"

EDITS = []
APPENDS = {}

EDITS.append((AP, """	surrogate   *chameleon.Surrogate // слой 1: обучаемая копия границы DPI
}""", """	surrogate   *chameleon.Surrogate // слой 1: обучаемая копия границы DPI
	genomeHistory []chameleon.Genome // последние применённые геномы (для novelty, ≤64)
	leak          *chameleon.LeakBudget
	leakEpoch     uint64
}"""))

OLD_ROTATE = """func (a *Autopilot) rotateStrategyFor(entry ServerEntry, ok bool) string {
	a.mu.Lock()
	th := a.theta
	a.mu.Unlock()
	if th != nil && ok && entry.CFSeed != "" {
		epoch := chameleon.EpochAt(time.Now(), time.Hour)
		g := chameleon.DeriveGenome(*th, []byte("chameleon-control-fabric:"+entry.CFSeed), epoch, a.m.ClientPubBytes())
		a.m.SetGenomeFlavor(g.Flavor)
		a.mu.Lock()
		a.lastGenome = &g
		a.mu.Unlock()
		desc := fmt.Sprintf("θ-геном эпохи %d (base=%s, jitter=%s, pad=%d..%d)",
			g.Epoch, g.Flavor.Base, g.Flavor.Jitter, g.Flavor.MinPad, g.Flavor.MaxPad)
		if g.Canary {
			desc += " [канарейка]"
		}
		return desc
	}
	return "flavor " + a.m.RotateFlavor()
}"""

NEW_ROTATE = """func (a *Autopilot) rotateStrategyFor(entry ServerEntry, ok bool) string {
	a.mu.Lock()
	th := a.theta
	a.mu.Unlock()
	if th != nil && ok && entry.CFSeed != "" {
		epoch := chameleon.EpochAt(time.Now(), time.Hour)
		seed := []byte("chameleon-control-fabric:" + entry.CFSeed)
		g, detail := a.selectGenome(*th, seed, epoch, a.m.ClientPubBytes())
		a.m.SetGenomeFlavor(g.Flavor)
		a.mu.Lock()
		a.lastGenome = &g
		a.genomeHistory = append(a.genomeHistory, g)
		if len(a.genomeHistory) > 64 {
			a.genomeHistory = a.genomeHistory[len(a.genomeHistory)-64:]
		}
		lb := a.leakBudgetFor(epoch, *th)
		a.mu.Unlock()
		lb.TrySpend(1.0) // применение генома в сети — живая экспозиция эпохи
		desc := fmt.Sprintf("θ-геном эпохи %d (base=%s, jitter=%s, pad=%d..%d; %s; leak %.0f%% бюджета)",
			g.Epoch, g.Flavor.Base, g.Flavor.Jitter, g.Flavor.MinPad, g.Flavor.MaxPad,
			detail, lb.SpentFrac()*100)
		if g.Canary {
			desc += " [канарейка]"
		}
		return desc
	}
	return "flavor " + a.m.RotateFlavor()
}"""

EDITS.append((AP, OLD_ROTATE, NEW_ROTATE))

APPENDS[AP] = """
// leakBudgetFor — leak-бюджет текущей эпохи (вызывается под a.mu).
// Бюджет считает ЖИВУЮ экспозицию: применение генома в сети сообщает цензору
// биты о нас. Офлайн-оценка кандидатов (selectGenome) утечки не создаёт.
func (a *Autopilot) leakBudgetFor(epoch uint64, th chameleon.Theta) *chameleon.LeakBudget {
	if a.leak == nil || a.leakEpoch != epoch {
		a.leak = chameleon.NewLeakBudget(epoch, th.LeakBits)
		a.leakEpoch = epoch
	}
	return a.leak
}

// selectGenome — слои 8+6+2: выбор генома эпохи из θ-распределения.
// Базовая точка — детерминированный DeriveGenome(seed‖epoch‖client). Поверх
// неё офлайн (ноль живых проб) оцениваются K-1 дополнительных кандидатов из θ
// (детерминированная соль client‖i) по fitness: novelty против истории
// применённых геномов (слой 2, популяция без единой сигнатуры) + leverage —
// вложенность в защищённые классы (слой 6, цена ошибки цензора). Приор
// выживаемости из суррогата внутри одной эпохи одинаков для всех кандидатов
// (его вектор — состояние сети, а не параметры генома), поэтому в ранжировании
// он не участвует — он виден в журнале через retrainSurrogate.
func (a *Autopilot) selectGenome(th chameleon.Theta, seed []byte, epoch uint64, pub []byte) (chameleon.Genome, string) {
	base := chameleon.DeriveGenome(th, seed, epoch, pub)
	a.mu.Lock()
	history := append([]chameleon.Genome(nil), a.genomeHistory...)
	a.mu.Unlock()

	w := chameleon.FitnessWeights{Novelty: 0.4, Leverage: 0.6}
	eval := func(g chameleon.Genome) float64 {
		fp := chameleon.FlowProfileFromFlavor(g.Fingerprint, g.Flavor)
		terms := chameleon.FitnessTerms{
			Novelty:  chameleon.NoveltyScore(g, history, 3),
			Leverage: chameleon.LeverageScore(fp, chameleon.DefaultProtectedClasses()),
		}
		return terms.Score(w)
	}

	best, bestScore, bestIdx := base, eval(base), -1
	const extra = 7 // K=8 кандидатов эпохи
	for i := 0; i < extra; i++ {
		cand := chameleon.DeriveGenome(th, seed, epoch, append(append([]byte(nil), pub...), byte(i)))
		if s := eval(cand); s > bestScore {
			best, bestScore, bestIdx = cand, s, i
		}
	}
	detail := fmt.Sprintf("fitness %.2f (лучший из %d кандидатов, соль %d)", bestScore, extra+1, bestIdx)
	return best, detail
}
"""

with open(AP, encoding="utf-8") as f:
    src = f.read()
for old, new in [(e[1], e[2]) for e in EDITS]:
    n = src.count(old)
    if n != 1:
        print("FATAL: якорь встречается %d раз (нужно 1):\n%s" % (n, old[:160]))
        sys.exit(1)
    src = src.replace(old, new)
src = src.rstrip("\n") + "\n" + APPENDS[AP]
with open(AP, "w", encoding="utf-8") as f:
    f.write(src)
print("PATCHED", AP)
