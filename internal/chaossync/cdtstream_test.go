package chaossync

import (
	"bytes"
	"testing"
	"time"
)

// pump — как в проде: сеть неблокирующая (канал), приём в отдельной горутине.
// Иначе синхронный send ре-ентерит в мьютекс Stream -> deadlock (артефакт теста).
type link struct {
	ch   chan []byte
	drop func() bool
}

func (l *link) send(wire []byte) {
	if !l.drop() {
		l.ch <- wire
	}
}

func pump(ch chan []byte, st *Stream, stop chan struct{}) {
	for {
		select {
		case w := <-ch:
			st.HandlePacket(w)
		case <-stop:
			return
		}
	}
}

func mkPair(t *testing.T, dropFrac int) (*Stream, *Stream, chan struct{}) {
	master := bytes.Repeat([]byte{7}, 32)
	cfg := func(dir string) GeomConfig {
		return GeomConfig{PortBase: 20000, PortCount: 8, MinFrag: 200, MaxFrag: 1400, MinGapUs: 0, MaxGapUs: 0, MinFlow: 1, MaxFlow: 4, Dir: dir}
	}
	var stA, stB *Stream
	chAB, chBA := make(chan []byte, 1<<20), make(chan []byte, 1<<20)
	n := 0
	drop := func() bool {
		if dropFrac <= 0 {
			return false
		}
		n++
		return n%dropFrac == 0
	}
	sendA := func(wire []byte, g PacketGeom) { (&link{chAB, drop}).send(wire) }
	sendB := func(wire []byte, g PacketGeom) { (&link{chBA, drop}).send(wire) }
	stA = NewStream(master, cfg("c2n"), cfg("n2c"), 1<<40, sendA)
	stB = NewStream(master, cfg("n2c"), cfg("c2n"), 1<<40, sendB)
	stop := make(chan struct{})
	go pump(chAB, stB, stop)
	go pump(chBA, stA, stop)
	return stA, stB, stop
}

func drain(st *Stream, buf *[]byte) {
	for {
		m := st.Read()
		if m == nil {
			return
		}
		*buf = append(*buf, m...)
	}
}

// Надёжный поток поверх CDT с 20% потерь: данные доходят целиком и по порядку.
func TestCDTStreamReliableLoss(t *testing.T) {
	stA, stB, stop := mkPair(t, 5) // каждый 5-й дропается = 20%
	defer close(stop)
	data := bytes.Repeat([]byte("chameleon-reliable-stream-"), 300) // ~8100 байт
	stA.Write(data)
	var got []byte
	deadline := time.Now().Add(30 * time.Second)
	for time.Now().Before(deadline) && len(got) < len(data) {
		stA.Tick()
		stB.Tick()
		drain(stB, &got)
		time.Sleep(3 * time.Millisecond)
	}
	if !bytes.Equal(got, data) {
		t.Fatalf("надёжный поток с потерями: got %d/%d байт", len(got), len(data))
	}
	t.Logf("надёжно доставлено %d байт поверх 20%% потерь, in-order; неподтверждено в конце: %d", len(got), stA.Pending())
}

// Двусторонний обмен без потерь: обе стороны пишут, обе читают, целостность.
func TestCDTStreamBidirectional(t *testing.T) {
	stA, stB, stop := mkPair(t, 0)
	defer close(stop)
	a2b := bytes.Repeat([]byte("A2B-"), 500)
	b2a := bytes.Repeat([]byte("B2A-"), 500)
	stA.Write(a2b)
	stB.Write(b2a)
	var gotA, gotB []byte
	deadline := time.Now().Add(15 * time.Second)
	for time.Now().Before(deadline) && (len(gotA) < len(b2a) || len(gotB) < len(a2b)) {
		stA.Tick()
		stB.Tick()
		drain(stA, &gotA)
		drain(stB, &gotB)
		time.Sleep(2 * time.Millisecond)
	}
	if !bytes.Equal(gotB, a2b) {
		t.Fatalf("A->B: got %d want %d", len(gotB), len(a2b))
	}
	if !bytes.Equal(gotA, b2a) {
		t.Fatalf("B->A: got %d want %d", len(gotA), len(b2a))
	}
	t.Logf("двусторонне: A->B %d, B->A %d байт, целы и по порядку", len(gotB), len(gotA))
}
