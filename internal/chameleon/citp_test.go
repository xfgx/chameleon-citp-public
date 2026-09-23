package chameleon

import (
	"crypto/rand"
	"io"
	"net"
	"sync"
	"testing"
	"time"
)

func TestCITPObjectEncodingAndSigning(t *testing.T) {
	seed := make([]byte, 32)
	_, _ = io.ReadFull(rand.Reader, seed)

	obj := &CITPObject{
		ObjectID:     1001,
		ParentID:     1000,
		StreamID:     42,
		Type:         ObjTypeIntentOpen,
		Mode:         ModeReliableOrdered,
		Flags:        0x01,
		Offset:       1024,
		ExpiryUnixMs: time.Now().Add(10 * time.Second).UnixMilli(),
		MonotonicSeq: 5,
		Payload:      []byte("intent:connect:api.service.internal:443"),
	}

	obj.Sign(seed)
	if !obj.Verify(seed) {
		t.Fatal("подпись только что созданного объекта не прошла валидацию")
	}

	wrongSeed := make([]byte, 32)
	wrongSeed[0] = seed[0] ^ 0xFF
	if obj.Verify(wrongSeed) {
		t.Fatal("подпись валидируется с неверным сидом")
	}

	enc := obj.Encode()
	dec, err := DecodeCITPObject(enc)
	if err != nil {
		t.Fatalf("декодирование CITP объекта провалилось: %v", err)
	}

	if dec.ObjectID != obj.ObjectID || dec.StreamID != obj.StreamID || dec.Type != obj.Type || dec.Mode != obj.Mode {
		t.Fatalf("поля объекта искажены после декодирования: %+v vs %+v", dec, obj)
	}

	if !dec.Verify(seed) {
		t.Fatal("декодированный объект не проходит проверку подписи")
	}

	// Проверка expiry
	expiredObj := &CITPObject{
		ObjectID:     1002,
		ExpiryUnixMs: time.Now().Add(-1 * time.Second).UnixMilli(),
	}
	if !expiredObj.IsExpired(time.Now().UnixMilli()) {
		t.Fatal("просроченный объект должен быть IsExpired = true")
	}
}

func TestMigrationTicketVerification(t *testing.T) {
	seed := make([]byte, 32)
	_, _ = io.ReadFull(rand.Reader, seed)

	// FIND-07: Использование DeriveStreamSecret
	streamSecret := DeriveStreamSecret(seed, 10, 1)

	ticket := NewMigrationTicket(10, 5000, 4800, 30*time.Second, streamSecret)
	ticket.Sign(seed)

	if err := ticket.Verify(seed, time.Now().UnixMilli()); err != nil {
		t.Fatalf("валидный тикет миграции отклонен: %v", err)
	}

	// Подделанный тикет
	tampered := *ticket
	tampered.SendOffset += 1
	if err := tampered.Verify(seed, time.Now().UnixMilli()); err == nil {
		t.Fatal("подделанный тикет миграции прошел проверку")
	}

	// Истекший тикет
	expTicket := NewMigrationTicket(10, 5000, 4800, -1*time.Second, streamSecret)
	expTicket.Sign(seed)
	if err := expTicket.Verify(seed, time.Now().UnixMilli()); err == nil {
		t.Fatal("просроченный тикет миграции прошел проверку")
	}
}

func TestCITPMuxObjectAndResumeFlow(t *testing.T) {
	nodePriv, nodePub, _ := GenerateNodeKey()
	clientKey, _, _ := GenerateNodeKey()
	priv, _ := ParseNodePrivKey(nodePriv)

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()

	var receivedObj *CITPObject
	var objMu sync.Mutex

	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func() {
				sess, _, err := ServerHandshake(c, priv, nil)
				if err != nil {
					return
				}
				conn, err := NewServerConn(c, sess)
				if err != nil {
					return
				}
				ServeMuxWithHandler(conn, 5*time.Second, func(_ *Mux, obj *CITPObject) {
					objMu.Lock()
					receivedObj = obj
					objMu.Unlock()
				})
			}()
		}
	}()

	cc, err := DialNode(ln.Addr().String(), nodePub, clientKey, 5*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	mux := NewMuxClient(cc)

	// Тест передачи CITP-объекта
	obj := &CITPObject{
		ObjectID:     555,
		StreamID:     1,
		Type:         ObjTypePolicyUpdate,
		Mode:         ModeReliableOrdered,
		ExpiryUnixMs: time.Now().Add(5 * time.Second).UnixMilli(),
		Payload:      []byte("policy:allow_all"),
	}

	if err := mux.SendCITPObject(obj); err != nil {
		t.Fatalf("ошибка отправки CITP объекта: %v", err)
	}

	time.Sleep(100 * time.Millisecond)
	objMu.Lock()
	if receivedObj == nil || receivedObj.ObjectID != 555 {
		t.Fatal("CITP объект не был получен или поврежден на стороне ноды")
	}
	objMu.Unlock()
}
