package chameleon

// cf_mock_modes_test.go — Этап B5: MockCensor в режимах «RST вместо
// block-страницы» и «случайная задержка вердикта», плюс конфигурируемые
// триггер-сигнатуры (B1).

import (
	"testing"
	"time"
)

// RST-режим: вердикт «блок» доставляется обрывом TCP — читатель обязан
// читать его как бит 1, кадр собирается полностью.
func TestCARLoopbackRSTMode(t *testing.T) {
	secret := DeriveSessionSecret([]byte("stage-b-rst"))
	msg := []byte{0x3C}
	book := NewCARCodebookForPayload(secret, len(msg), CARFrameRep)

	car := NewCARChannel("127.0.0.1:0")
	go func() { _ = car.Serve() }()
	carAddr := waitAddr(car.Addr)
	defer func() { _ = car.Shutdown() }()

	censor := NewMockCensor("127.0.0.1:0", "http://"+carAddr, "").WithRSTMode(true)
	go func() { _ = censor.Serve() }()
	censorAddr := waitAddr(censor.Addr)
	defer func() { _ = censor.Shutdown() }()

	if err := car.PublishFrame(book, msg, CARFrameRep); err != nil {
		t.Fatal(err)
	}
	reader := NewCARReader("http://" + censorAddr).WithPacer(fastCARPacer())
	got, err := reader.ReadMessage(book, CARFrameRep)
	if err != nil {
		t.Fatalf("RST-режим: %v", err)
	}
	if len(got) != 1 || got[0] != msg[0] {
		t.Fatalf("RST-режим: got %v want %v", got, msg)
	}
}

// Плавающая задержка вердикта: биты не теряются и не путаются.
func TestCARLoopbackVerdictDelay(t *testing.T) {
	car := NewCARChannel("127.0.0.1:0")
	go func() { _ = car.Serve() }()
	carAddr := waitAddr(car.Addr)
	defer func() { _ = car.Shutdown() }()

	censor := NewMockCensor("127.0.0.1:0", "http://"+carAddr, "").
		WithVerdictDelay(60*time.Millisecond, []byte("delay-seed"))
	go func() { _ = censor.Serve() }()
	censorAddr := waitAddr(censor.Addr)
	defer func() { _ = censor.Shutdown() }()

	want := []uint8{1, 0, 1, 1, 0, 1}
	for i, b := range want {
		car.SetBit(i, b)
	}
	reader := NewCARReader("http://" + censorAddr).WithPacer(fastCARPacer())
	start := time.Now()
	got := reader.ReadBits(0, len(want))
	elapsed := time.Since(start)
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("бит %d при плавающей задержке: got %d want %d", i, got[i], want[i])
		}
	}
	t.Logf("6 бит при задержке вердикта 0..60мс прочитаны за %v", elapsed)
}

// B1: операторский набор триггер-сигнатур заменяет дефолтный benign-токен —
// цензор реагирует на сигнатуру оператора, а на старый токен — нет.
func TestCARTriggerSignaturesOperatorSet(t *testing.T) {
	const sig = "ACME-LAB-TRIGGER-7"

	car := NewCARChannel("127.0.0.1:0").WithTriggerSignatures([]string{sig})
	go func() { _ = car.Serve() }()
	carAddr := waitAddr(car.Addr)
	defer func() { _ = car.Shutdown() }()

	censor := NewMockCensor("127.0.0.1:0", "http://"+carAddr, "").WithTriggerSignatures([]string{sig})
	go func() { _ = censor.Serve() }()
	censorAddr := waitAddr(censor.Addr)
	defer func() { _ = censor.Shutdown() }()

	reader := NewCARReader("http://" + censorAddr).WithPacer(fastCARPacer())
	car.SetBit(0, 0)
	car.SetBit(1, 1)
	bits := reader.ReadBits(0, 2)
	if bits[0] != 0 || bits[1] != 1 {
		t.Fatalf("операторская сигнатура: got %v want [0 1]", bits)
	}

	// Контроль: цензор с чужим набором НЕ реагирует на нашу сигнатуру —
	// триггерность целиком определяется конфигурацией, а не кодом.
	censor2 := NewMockCensor("127.0.0.1:0", "http://"+carAddr, "").WithTriggerSignatures([]string{"OTHER-SIG"})
	go func() { _ = censor2.Serve() }()
	censor2Addr := waitAddr(censor2.Addr)
	defer func() { _ = censor2.Shutdown() }()
	reader2 := NewCARReader("http://" + censor2Addr).WithPacer(fastCARPacer())
	if b := reader2.ReadBit(1); b != 0 {
		t.Fatal("чужой набор сигнатур не должен реагировать на нашу сигнатуру")
	}
}
