package chameleon

// virtual_stream_test.go — CST: реассемблер (порядок/дубли/зависимости),
// дедуп-окно датаграмм, семантика knowledge ACK, жизненный цикл VirtualStream.

import (
	"bytes"
	"errors"
	"testing"
	"time"
)

// Перемешанные дельты собираются только после зависимостей; дубли
// идемпотентны; пересечения и dep>offset — протокольные ошибки; окно bounded.
func TestReassemblerOrderDupOverflow(t *testing.T) {
	r := newDeltaReassembler()
	out, _, err := r.push(3, 3, []byte("cd"))
	if err != nil || len(out) != 0 {
		t.Fatal("доставка в обход зависимости")
	}
	if _, _, err := r.push(3, 3, []byte("cd")); err != nil || len(r.pending) != 1 {
		t.Fatal("дубль в pending не идемпотентен")
	}
	out, _, err = r.push(0, 0, []byte("ab"))
	if err != nil || len(out) != 1 || string(out[0]) != "ab" {
		t.Fatal("граничная доставка")
	}
	out, _, err = r.push(2, 2, []byte("X"))
	if err != nil || len(out) != 2 || string(out[0]) != "X" || string(out[1]) != "cd" {
		t.Fatal("дренаж pending после зависимости")
	}
	if _, dup, err := r.push(0, 0, []byte("ab")); err != nil || !dup {
		t.Fatal("дубликат не идемпотентен")
	}
	if _, _, err := r.push(1, 1, []byte("zz")); !errors.Is(err, errVSDep) {
		t.Fatal("частичное пересечение принято")
	}
	if _, _, err := r.push(5, 9, []byte("q")); !errors.Is(err, errVSDep) {
		t.Fatal("dep>offset принят")
	}
	for i := 0; i < 8; i++ {
		off := uint64(100 + i*10)
		if _, _, err := r.push(off, off, []byte("0123456789")); err != nil {
			t.Fatal(err)
		}
	}
	if _, _, err := r.push(1000, 1000, []byte("overflow")); !errors.Is(err, errVSOverflow) {
		t.Fatal("переполнение pending не поймано")
	}
}

// Дедуп-окно: дубль и «ниже окна» подавляются, свежие проходят.
func TestDedupWindow(t *testing.T) {
	w := newDedupWindow(4)
	for _, id := range []uint64{10, 11, 13} {
		if w.seenOrAdd(id) {
			t.Fatal("свежая датаграмма отброшена")
		}
	}
	if !w.seenOrAdd(11) || !w.seenOrAdd(10) {
		t.Fatal("дубль не подавлен")
	}
	for i := uint64(20); i < 30; i++ {
		w.seenOrAdd(i)
	}
	if !w.seenOrAdd(12) {
		t.Fatal("ниже окна не подавлено")
	}
	if w.seenOrAdd(100) {
		t.Fatal("новая сверх окна отброшена")
	}
}

// Белоящичные помощники VirtualStream без ячейки.
func vsTestKL() *KnowledgeLayer {
	return NewKnowledgeLayer(bytes.Repeat([]byte{1}, 32), bytes.Repeat([]byte{2}, 32), nil)
}

func vsTestStream(kl *KnowledgeLayer) *VirtualStream {
	var secret [32]byte
	id := NewFlowID()
	fc := DeriveContinuity(secret[:], kl.clientPub, kl.nodePub, id, "tcp:t:1")
	vs := newVirtualStream(kl, id, fc, "t:1", CSTModeTCP)
	vs.state = VSAttached
	kl.flows[id] = vs
	return vs
}

// ACK монотонен; повтор идемпотентен; сверх границы — закрытие ТОЛЬКО потока;
// replay освобождается строго по ACK.
func TestAckMonotoneTrim(t *testing.T) {
	kl := vsTestKL()
	vs := vsTestStream(kl)
	for i := 0; i < 3; i++ {
		data := bytes.Repeat([]byte{byte(97 + i)}, 3)
		vs.replay = append(vs.replay, replayChunk{off: vs.sendOff, data: data})
		vs.replayBytes += 3
		vs.sendOff += 3
	}
	mkAck := func(n uint64) *CSTAck {
		a := &CSTAck{Version: 1, ID: vs.id, Dir: CSTDirC2S, Gen: 1, Ack: n}
		a.Encode(vs.fc)
		return a
	}
	vs.onAck(mkAck(0))
	if vs.sendAcked != 0 || vs.replayBytes != 9 {
		t.Fatal("старый ACK что-то изменил")
	}
	vs.onAck(mkAck(4))
	if vs.sendAcked != 4 || vs.replayBytes != 5 {
		t.Fatalf("trim: acked=%d replay=%d", vs.sendAcked, vs.replayBytes)
	}
	vs.onAck(mkAck(4))
	if vs.replayBytes != 5 {
		t.Fatal("повторный ACK изменил replay")
	}
	vs.onAck(mkAck(100)) // сверх отправленной границы
	if vs.State() != VSClosed {
		t.Fatal("over-ACK не закрыл поток")
	}
	if kl.HasFlows() {
		t.Fatal("закрытый поток остался в слое")
	}
}

// DETACHED: запись ограниченно буферизуется; дедлайн восстановления истёк —
// поток EXPIRED, чтение и запись ошибочны.
func TestVSDetachWriteExpire(t *testing.T) {
	kl := vsTestKL()
	kl.restoreTimeout = 200 * time.Millisecond
	vs := vsTestStream(kl)
	vs.detach()
	if vs.State() != VSDetached {
		t.Fatal("не DETACHED после смерти ячейки")
	}
	if _, err := vs.Write([]byte("buffered")); err != nil {
		t.Fatal(err)
	}
	time.Sleep(300 * time.Millisecond)
	if _, err := vs.Write([]byte("x")); !errors.Is(err, errVSExpired) {
		t.Fatalf("запись после дедлайна: %v", err)
	}
	if vs.State() != VSExpired {
		t.Fatal("не EXPIRED после дедлайна")
	}
	if _, err := vs.Read(make([]byte, 1)); !errors.Is(err, errVSExpired) {
		t.Fatalf("чтение после дедлайна: %v", err)
	}
}

// Переполнение replay-окна: writer блокируется до дедлайна, затем умирает
// ТОЛЬКО поток (превышение лимита памяти закрывает поток, не Mux).
func TestVSWriteOverflow(t *testing.T) {
	kl := vsTestKL()
	vs := vsTestStream(kl)
	vs.maxReplay = 64
	vs.state = VSDetached
	vs.detachDeadline = time.Now().Add(250 * time.Millisecond)
	start := time.Now()
	if _, err := vs.Write(make([]byte, 100)); !errors.Is(err, errVSExpired) {
		t.Fatalf("переполнение без восстановления: %v", err)
	}
	if time.Since(start) < 200*time.Millisecond {
		t.Fatal("запись не блокировалась до дедлайна")
	}
	if vs.State() != VSExpired {
		t.Fatal("переполненный поток не умер")
	}
}

// Replay-буфер освобождается ТОЛЬКО по knowledge ACK.
func TestReplayFreedOnlyByAck(t *testing.T) {
	kl := vsTestKL()
	vs := vsTestStream(kl)
	vs.replay = append(vs.replay, replayChunk{off: 0, data: []byte("data")})
	vs.replayBytes = 4
	vs.sendOff = 4
	if vs.replayBytes != 4 {
		t.Fatal("replay освобождён без ACK")
	}
	a := &CSTAck{Version: 1, ID: vs.id, Dir: CSTDirC2S, Gen: 1, Ack: 4}
	a.Encode(vs.fc)
	vs.onAck(a)
	if vs.replayBytes != 0 || vs.sendAcked != 4 {
		t.Fatal("replay не освобождён по ACK")
	}
}
