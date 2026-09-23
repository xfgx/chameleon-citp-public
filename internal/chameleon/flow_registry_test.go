package chameleon

// flow_registry_test.go — CST: лимиты реестра, отклонения манифестов,
// attach-гонка, «старая ячейка не пишет», TTL/LRU detached, UDP, snapshot.

import (
	"net"
	"sync"
	"testing"
	"time"
)

// captureAttach — сырая ячейка с перехватом attach-ответов (без knowledge-слоя).
func captureAttach(t *testing.T, m *Mux) (chan struct{}, chan string) {
	t.Helper()
	okCh := make(chan struct{}, 1)
	errCh := make(chan string, 1)
	m.SetCSTBinding(&cstBinding{h: &cstHandlers{
		onAttachOK: func(mx *Mux, p []byte) {
			select {
			case okCh <- struct{}{}:
			default:
			}
		},
		onAttachErr: func(mx *Mux, p []byte) {
			e, err := DecodeCSTErr(p)
			if err == nil {
				select {
				case errCh <- e.Msg:
				default:
				}
			}
		},
	}})
	return okCh, errCh
}

// Лимит потоков на клиента: сверх — отказ (fail closed, без прямого пути).
func TestRegistryPerClientLimit(t *testing.T) {
	limits := DefaultFlowLimits()
	limits.MaxFlowsPerClient = 2
	tn := newCSTTestNode(t, &limits)
	defer tn.Close()
	mux, _ := tn.dial(t)
	kl := tn.newKL()
	kl.BindMux(mux)
	waitFor(t, "negotiate", func() bool { return kl.Active() })
	vs1, err := kl.OpenFlow(tn.echoTarget(), CSTModeTCP)
	if err != nil {
		t.Fatal(err)
	}
	defer vs1.Close()
	vs2, err := kl.OpenFlow(tn.echoTarget(), CSTModeTCP)
	if err != nil {
		t.Fatal(err)
	}
	defer vs2.Close()
	if _, err := kl.OpenFlow(tn.echoTarget(), CSTModeTCP); err == nil {
		t.Fatal("третий поток сверх лимита открыт")
	}
}

// Отклонения манифестов: повторный attach при живой привязке, replay старой
// сессии, битый MAC, чужой клиент, generation rollback.
func TestRegistryAttachRejections(t *testing.T) {
	tn := newCSTTestNode(t, nil)
	defer tn.Close()
	mux1, cc1 := tn.dial(t)
	kl := tn.newKL()
	kl.restoreTimeout = 30 * time.Second // поток не истекает за время теста
	kl.BindMux(mux1)
	waitFor(t, "negotiate", func() bool { return kl.Active() })
	vs, err := kl.OpenFlow(tn.echoTarget(), CSTModeTCP)
	if err != nil {
		t.Fatal(err)
	}
	fc := vs.fc
	flowID := vs.ID()
	oldSeed := mux1.conn.seed
	exp := time.Now().Add(30 * time.Second).UnixMilli()

	// 1) attach при ЖИВОЙ привязке -> отказ.
	muxA, _ := tn.dial(t)
	okA, errA := captureAttach(t, muxA)
	muxA.send(0, smCSTAttach, (&CSTAttach{Version: 1, ID: flowID, NewGen: 2, ExpiryMs: exp}).Encode(fc, muxA.conn.seed))
	select {
	case <-okA:
		t.Fatal("attach при живой привязке принят")
	case <-errA:
	case <-time.After(5 * time.Second):
		t.Fatal("нет attach-err (already attached)")
	}

	// 2) Разрыв: нода переводит поток в DETACHED.
	cc1.Close()
	waitFor(t, "server detach", func() bool {
		_, _, _, _, attached, ok := tn.reg.flowInfo(flowID)
		return ok && !attached
	})

	// 3) Replay манифеста со СТАРЫМ session seed — отклонён.
	muxB, _ := tn.dial(t)
	okB, errB := captureAttach(t, muxB)
	muxB.send(0, smCSTAttach, (&CSTAttach{Version: 1, ID: flowID, NewGen: 2, ExpiryMs: exp}).Encode(fc, oldSeed))
	select {
	case <-okB:
		t.Fatal("replay старого манифеста принят")
	case <-errB:
	case <-time.After(5 * time.Second):
		t.Fatal("нет attach-err (replay)")
	}

	// 4) Битый MAC — отклонён.
	bad := (&CSTAttach{Version: 1, ID: flowID, NewGen: 2, ExpiryMs: exp}).Encode(fc, muxB.conn.seed)
	bad[len(bad)-1] ^= 0xff
	muxB.send(0, smCSTAttach, bad)
	select {
	case <-okB:
		t.Fatal("манифест с битым MAC принят")
	case <-errB:
	case <-time.After(5 * time.Second):
		t.Fatal("нет attach-err (MAC)")
	}

	// 5) Чужой клиент (другая ключевая пара) -> foreign client.
	client2B64, _, err := GenerateNodeKey()
	if err != nil {
		t.Fatal(err)
	}
	cc2, err := DialNode(tn.nodeLn.Addr().String(), tn.nodePubB64, client2B64, 5*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	muxC := NewMuxClient(cc2)
	okC, errC := captureAttach(t, muxC)
	muxC.send(0, smCSTAttach, (&CSTAttach{Version: 1, ID: flowID, NewGen: 2, ExpiryMs: exp}).Encode(fc, muxC.conn.seed))
	select {
	case <-okC:
		t.Fatal("attach чужого клиента принят")
	case e := <-errC:
		if e != "foreign client" {
			t.Fatalf("err %q", e)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("нет attach-err (foreign)")
	}

	// 6) Корректный attach (gen=2) проходит; повтор с тем же gen — rollback.
	muxD, _ := tn.dial(t)
	okD, errD := captureAttach(t, muxD)
	muxD.send(0, smCSTAttach, (&CSTAttach{Version: 1, ID: flowID, NewGen: 2, ExpiryMs: exp}).Encode(fc, muxD.conn.seed))
	select {
	case <-okD:
	case e := <-errD:
		t.Fatalf("корректный attach отклонён: %s", e)
	case <-time.After(5 * time.Second):
		t.Fatal("таймаут attach")
	}
	muxE, _ := tn.dial(t)
	okE, errE := captureAttach(t, muxE)
	muxE.send(0, smCSTAttach, (&CSTAttach{Version: 1, ID: flowID, NewGen: 2, ExpiryMs: exp}).Encode(fc, muxE.conn.seed))
	select {
	case <-okE:
		t.Fatal("generation rollback принят")
	case <-errE:
	case <-time.After(5 * time.Second):
		t.Fatal("нет attach-err (rollback)")
	}
}

// Две сессии одновременно пытаются attach — выигрывает только одна.
func TestRegistryAttachSingleWinner(t *testing.T) {
	tn := newCSTTestNode(t, nil)
	defer tn.Close()
	mux1, cc1 := tn.dial(t)
	kl := tn.newKL()
	kl.restoreTimeout = 30 * time.Second
	kl.BindMux(mux1)
	waitFor(t, "negotiate", func() bool { return kl.Active() })
	vs, err := kl.OpenFlow(tn.echoTarget(), CSTModeTCP)
	if err != nil {
		t.Fatal(err)
	}
	fc, flowID := vs.fc, vs.ID()
	cc1.Close()
	waitFor(t, "server detach", func() bool {
		_, _, _, _, attached, ok := tn.reg.flowInfo(flowID)
		return ok && !attached
	})
	muxA, _ := tn.dial(t)
	muxB, _ := tn.dial(t)
	okA, errA := captureAttach(t, muxA)
	okB, errB := captureAttach(t, muxB)
	exp := time.Now().Add(30 * time.Second).UnixMilli()
	go muxA.send(0, smCSTAttach, (&CSTAttach{Version: 1, ID: flowID, NewGen: 2, ExpiryMs: exp}).Encode(fc, muxA.conn.seed))
	go muxB.send(0, smCSTAttach, (&CSTAttach{Version: 1, ID: flowID, NewGen: 2, ExpiryMs: exp}).Encode(fc, muxB.conn.seed))
	wins, errs := 0, 0
	for i := 0; i < 2; i++ {
		select {
		case <-okA:
			wins++
		case <-okB:
			wins++
		case <-errA:
			errs++
		case <-errB:
			errs++
		case <-time.After(5 * time.Second):
			t.Fatal("таймаут гонки attach")
		}
	}
	if wins != 1 || errs != 1 {
		t.Fatalf("wins=%d errs=%d (ожидалось ровно 1/1)", wins, errs)
	}
}

// Старый Mux после attach не может писать: дельта старого поколения и дельта
// с непривязанной ячейки отбрасываются, граница потока не двигается.
func TestOldMuxCannotWrite(t *testing.T) {
	tn := newCSTTestNode(t, nil)
	defer tn.Close()
	mux1, cc1 := tn.dial(t)
	kl := tn.newKL()
	kl.restoreTimeout = 30 * time.Second
	kl.BindMux(mux1)
	waitFor(t, "negotiate", func() bool { return kl.Active() })
	vs, err := kl.OpenFlow(tn.echoTarget(), CSTModeTCP)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := vs.Write([]byte("aa")); err != nil {
		t.Fatal(err)
	}
	readFull(t, vs, 2)
	waitFor(t, "ack", func() bool { _, acked, _ := vs.Offsets(); return acked == 2 })
	fc, flowID := vs.fc, vs.ID()
	cc1.Close()
	waitFor(t, "detach", func() bool {
		_, _, _, _, attached, ok := tn.reg.flowInfo(flowID)
		return ok && !attached
	})
	// Attach через вторую ячейку (gen=2).
	mux2, _ := tn.dial(t)
	okCh, errCh := captureAttach(t, mux2)
	mux2.send(0, smCSTAttach, (&CSTAttach{Version: 1, ID: flowID, NewGen: 2, ClientS2CAcked: 2, ClientC2SAcked: 2, ExpiryMs: time.Now().Add(30 * time.Second).UnixMilli()}).Encode(fc, mux2.conn.seed))
	select {
	case <-okCh:
	case e := <-errCh:
		t.Fatalf("attach: %s", e)
	case <-time.After(5 * time.Second):
		t.Fatal("таймаут attach")
	}
	// Дельта СТАРОГО поколения на привязанной ячейке — отброшена.
	mux2.send(0, smCSTDelta, (&CSTDelta{Version: 1, ID: flowID, Dir: CSTDirC2S, Gen: 1, Offset: 2, Dep: 2, Payload: []byte("ZZ")}).Encode(fc))
	// Дельта нового поколения с НЕПРИВЯЗАННОЙ (третьей) ячейки — отброшена.
	mux3, _ := tn.dial(t)
	mux3.send(0, smCSTDelta, (&CSTDelta{Version: 1, ID: flowID, Dir: CSTDirC2S, Gen: 2, Offset: 2, Dep: 2, Payload: []byte("YY")}).Encode(fc))
	time.Sleep(300 * time.Millisecond)
	if _, c2s, _, _, _, _ := tn.reg.flowInfo(flowID); c2s != 2 {
		t.Fatalf("старая/чужая ячейка пишет: c2s=%d (ждали 2)", c2s)
	}
}

// TTL detached-потока: уборка в отдельном безопасном цикле.
func TestRegistryDetachedTTL(t *testing.T) {
	limits := DefaultFlowLimits()
	limits.DetachedTTL = 300 * time.Millisecond
	limits.SweepInterval = 50 * time.Millisecond
	tn := newCSTTestNode(t, &limits)
	defer tn.Close()
	mux1, cc1 := tn.dial(t)
	kl := tn.newKL()
	kl.restoreTimeout = 30 * time.Second
	kl.BindMux(mux1)
	waitFor(t, "negotiate", func() bool { return kl.Active() })
	vs, err := kl.OpenFlow(tn.echoTarget(), CSTModeTCP)
	if err != nil {
		t.Fatal(err)
	}
	flowID := vs.ID()
	cc1.Close()
	waitFor(t, "server detach", func() bool {
		_, _, _, _, attached, ok := tn.reg.flowInfo(flowID)
		return ok && !attached
	})
	waitFor(t, "TTL sweep detached", func() bool {
		_, _, _, _, _, ok := tn.reg.flowInfo(flowID)
		return !ok
	})
}

// LRU/предсказуемое вытеснение detached при переполнении (fail closed).
func TestRegistryDetachedLRU(t *testing.T) {
	limits := DefaultFlowLimits()
	limits.MaxDetached = 2
	tn := newCSTTestNode(t, &limits)
	defer tn.Close()
	mux1, cc1 := tn.dial(t)
	kl := tn.newKL()
	kl.restoreTimeout = 30 * time.Second
	kl.BindMux(mux1)
	waitFor(t, "negotiate", func() bool { return kl.Active() })
	for i := 0; i < 3; i++ {
		vs, err := kl.OpenFlow(tn.echoTarget(), CSTModeTCP)
		if err != nil {
			t.Fatal(err)
		}
		defer vs.Close()
	}
	cc1.Close()
	waitFor(t, "вытеснение до лимита detached", func() bool {
		flows, detached, _ := tn.reg.Stats()
		return flows == 2 && detached == 2
	})
}

// UDP-режим: независимые id датаграмм, дедуп окном, порядок не требуется,
// expired не воспроизводятся, лимит размера обязателен.
func TestRegistryUDPMode(t *testing.T) {
	udpLn, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer udpLn.Close()
	var udpMu sync.Mutex
	var got [][]byte
	go func() {
		buf := make([]byte, 4096)
		for {
			n, src, err := udpLn.ReadFrom(buf)
			if err != nil {
				return
			}
			d := append([]byte(nil), buf[:n]...)
			udpMu.Lock()
			got = append(got, d)
			udpMu.Unlock()
			udpLn.WriteTo(d, src)
		}
	}()
	tn := newCSTTestNode(t, nil)
	defer tn.Close()
	mux, _ := tn.dial(t)
	kl := tn.newKL()
	kl.BindMux(mux)
	waitFor(t, "negotiate", func() bool { return kl.Active() })
	vs, err := kl.OpenFlow(udpLn.LocalAddr().String(), CSTModeUDP)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := vs.Write([]byte("ping")); err != nil {
		t.Fatal(err)
	}
	vs.SetReadDeadline(time.Now().Add(3 * time.Second))
	buf := make([]byte, 64)
	n, err := vs.Read(buf)
	if err != nil || string(buf[:n]) != "ping" {
		t.Fatalf("udp echo: %v %q", err, buf[:n])
	}
	vs.SetReadDeadline(time.Time{})
	// Дубль (тот же id датаграммы) подавляется окном: до цели доходит один раз.
	dup := &CSTDelta{Version: 1, ID: vs.ID(), Dir: CSTDirC2S, Flags: CSTFlagDatagram, Gen: 1, Offset: 5, Dep: 5, Payload: []byte("dup!")}
	enc := dup.Encode(vs.fc)
	mux.send(0, smCSTDelta, enc)
	mux.send(0, smCSTDelta, enc)
	time.Sleep(300 * time.Millisecond)
	udpMu.Lock()
	count := 0
	for _, g := range got {
		if string(g) == "dup!" {
			count++
		}
	}
	udpMu.Unlock()
	if count != 1 {
		t.Fatalf("дубль датаграммы дошёл до цели %d раз", count)
	}
	// Expired-датаграмма не воспроизводится вообще.
	ex := &CSTDelta{Version: 1, ID: vs.ID(), Dir: CSTDirC2S, Flags: CSTFlagDatagram, Gen: 1, Offset: 50, Dep: 50, ExpiryMs: time.Now().Add(-time.Second).UnixMilli(), Payload: []byte("old!")}
	mux.send(0, smCSTDelta, ex.Encode(vs.fc))
	time.Sleep(200 * time.Millisecond)
	udpMu.Lock()
	for _, g := range got {
		if string(g) == "old!" {
			t.Fatal("expired-датаграмма воспроизведена")
		}
	}
	udpMu.Unlock()
	vs.Close()
}

// Snapshot/compaction: без payload; replay освобождается по границам после MAC.
func TestSnapshotCompaction(t *testing.T) {
	tn := newCSTTestNode(t, nil)
	defer tn.Close()
	mux, _ := tn.dial(t)
	kl := tn.newKL()
	kl.BindMux(mux)
	waitFor(t, "negotiate", func() bool { return kl.Active() })
	vs, err := kl.OpenFlow(tn.echoTarget(), CSTModeTCP)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := vs.Write([]byte("snap")); err != nil {
		t.Fatal(err)
	}
	// Клиент НЕ читает эхо: ACK нет, нода держит S2C replay (4 байта).
	waitFor(t, "replay накоплен", func() bool {
		_, _, rb := tn.reg.Stats()
		return rb == 4
	})
	_, _, s2cNext, _, _, _ := tn.reg.flowInfo(vs.ID())
	sn := &CSTSnapshot{Version: 1, ID: vs.ID(), Gen: 1, C2SAcked: 4, S2CAcked: s2cNext}
	mux.send(0, smCSTSnapshot, sn.Encode(vs.fc))
	waitFor(t, "compaction освободила replay", func() bool {
		_, _, rb := tn.reg.Stats()
		return rb == 0
	})
	vs.Close()
}

// Shutdown идемпотентен: повторный вызов — не паника, потоки вычищены.
func TestRegistryShutdownIdempotent(t *testing.T) {
	tn := newCSTTestNode(t, nil)
	mux, _ := tn.dial(t)
	kl := tn.newKL()
	kl.BindMux(mux)
	waitFor(t, "negotiate", func() bool { return kl.Active() })
	vs, err := kl.OpenFlow(tn.echoTarget(), CSTModeTCP)
	if err != nil {
		t.Fatal(err)
	}
	tn.reg.Shutdown()
	tn.reg.Shutdown()
	if _, _, _, _, _, ok := tn.reg.flowInfo(vs.ID()); ok {
		t.Fatal("поток пережил Shutdown")
	}
	vs.Close()
	tn.Close()
}
