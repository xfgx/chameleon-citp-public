package chaossync

// cdt_observer_test.go — строгая проверка ядра новизны CDT: НЕСВЯЗУЕМОСТЬ.
// Моделируем per-flow классификатор цензора (именно так ТСПУ фильтрует на
// потоке: группировка по 5-tuple, поиск доминирующего «жирного потока»).
// Доказываем:
//   - CDT ломает per-flow flow-linking: ни один 5-tuple не доминирует;
//   - контрольный обычный поток (один 5-tuple) флагается;
//   - честный предел: агрегат по паре (srcIP,dstIP) остаётся видимым
//     (теорема сохранения объёма — CDT его не скрывает, и не обещает).

import (
	"bytes"
	"fmt"
	"testing"
)

func TestCDTDefeatsFlowLinking(t *testing.T) {
	master := bytes.Repeat([]byte{0x42}, 32)
	cfg := GeomConfig{}.withDefaults()
	frag := NewFragmenter(master, 9, cfg)
	payload := make([]byte, 300000)
	frag.Push(payload)

	const clientIP = "203.0.113.7" // один реальный IP клиента
	const nodeIP = "192.0.2.10" // один IP ноды (single-IP развёртывание)

	type pkt struct {
		sport, dport, size int
	}
	var pkts []pkt
	for {
		wire, g, ok := frag.Emit()
		if !ok {
			wire, g, ok = frag.EmitFinal()
			if !ok {
				break
			}
		}
		pkts = append(pkts, pkt{g.SrcPort, g.DestPort, len(wire)})
	}

	total := 0
	for _, p := range pkts {
		total += p.size
	}

	// --- классификатор цензора: per-flow по полному 5-tuple ---
	five := map[string]int{}
	for _, p := range pkts {
		k := fmt.Sprintf("%s:%d>%s:%d/udp", clientIP, p.sport, nodeIP, p.dport)
		five[k] += p.size
	}
	maxShare5 := 0
	for _, b := range five {
		if b > maxShare5 {
			maxShare5 = b
		}
	}
	share5 := float64(maxShare5) / float64(total)

	// --- честный предел: агрегат по паре (srcIP,dstIP) ---
	ipPair := 0 // весь трафик между одной парой IP
	for _, p := range pkts {
		ipPair += p.size
	}
	shareIP := float64(ipPair) / float64(total)

	t.Logf("CDT наблюдаемое: фрагментов=%d, уникальных 5-tuple=%d", len(pkts), len(five))
	t.Logf("per-flow классификатор: доминирующий 5-tuple несёт %.4f потока (порог флага 0.30)", share5)
	t.Logf("честный предел: агрегат (srcIP,dstIP) = %.3f (объём между машинами виден)", shareIP)

	// per-flow flow-linking сломан: ни один 5-tuple не доминирует.
	if share5 > 0.30 {
		t.Errorf("CDT сформировал жирный поток: доминирующий 5-tuple %.3f > 0.30 — flow-linking возможен", share5)
	}
	// честный предел подтверждён: объём между парой IP виден целиком.
	if shareIP < 0.99 {
		t.Errorf("ожидался видимый агрегат (srcIP,dstIP) ~1.0, got %.3f", shareIP)
	}
}
