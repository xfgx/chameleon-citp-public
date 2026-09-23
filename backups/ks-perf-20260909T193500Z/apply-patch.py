#!/usr/bin/env python3
# apply-patch.py — KS perf 2026-09-09: применяет точечные замены в ks.go и
# cmd/ks-vpn/main.go. Каждый паттерн должен встретиться ровно один раз; если
# что-то не сошлось — файлы не трогаем. Бит-идентичность wire сохраняется
# (гейт: TestKsGoldenVector).
import pathlib
import sys

ROOT = pathlib.Path('/files/VPN')
KS = ROOT / 'internal/chaossync/ks.go'
MAIN = ROOT / 'cmd/ks-vpn/main.go'

R = []

# ---------- ks.go ----------
R.append((KS, '''import (
	"crypto/cipher"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"time"

	"golang.org/x/crypto/chacha20poly1305"
)''', '''import (
	"crypto/cipher"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"sync"
	"time"

	"golang.org/x/crypto/chacha20poly1305"
)'''))

R.append((KS, '''type KeyGen struct {
	field *FieldParams
	state [Sites]Fxp
	ctr   uint64
}''', '''type KeyGen struct {
	field *FieldParams
	state [Sites]Fxp
	ctr   uint64
	// wbuf/nbuf — scratch-массивы next() (2026-09-09, perf): вход whiten/nonce
	// собирается в структуре с предзаполненным label и хэшируется одним вызовом
	// sha256.Sum256 по фиксированному массиву вместо sha256.New/Write/Sum —
	// ноль heap-аллокаций на позицию. Байты на входе хэша и выдача побитово
	// неизменны (гейт Э1/KS-golden). KeyGen, как и прежде, одногорутинный;
	// внешняя синхронизация — мьютекс в Sender.
	wbuf [len(ksWhitenLabel) + 8 + Sites*8]byte
	nbuf [len(ksNonceLabel) + ksKeyLen]byte
}'''))

R.append((KS, '''	m := dirMaster(master, dir)
	// keystream-класс: хаос-пол (lambda1 >= KeystreamLambdaMin) + свой
	// reseed-поток инициализации (schedule.go).
	return &KeyGen{
		field: DeriveFieldClass(m, epoch, FieldClassKeystream),
		state: EpochInitClass(m, epoch, FieldClassKeystream),
	}
}''', '''	m := dirMaster(master, dir)
	// keystream-класс: хаос-пол (lambda1 >= KeystreamLambdaMin) + свой
	// reseed-поток инициализации (schedule.go).
	k := &KeyGen{
		field: DeriveFieldClass(m, epoch, FieldClassKeystream),
		state: EpochInitClass(m, epoch, FieldClassKeystream),
	}
	copy(k.wbuf[:], ksWhitenLabel)
	copy(k.nbuf[:], ksNonceLabel)
	return k
}'''))

R.append((KS, '''	k.field.Step(&k.state)
	k.ctr++
	var buf [8 + Sites*8]byte
	binary.BigEndian.PutUint64(buf[:8], k.ctr)
	for i := 0; i < Sites; i++ {
		binary.BigEndian.PutUint64(buf[8+i*8:], uint64(k.state[i].Raw()))
	}
	kh := sha256.New()
	kh.Write([]byte(ksWhitenLabel))
	kh.Write(buf[:])
	copy(key[:], kh.Sum(nil))
	nh := sha256.New()
	nh.Write([]byte(ksNonceLabel))
	nh.Write(key[:])
	copy(nonce[:], nh.Sum(nil))
	return key, nonce
}''', '''	k.field.Step(&k.state)
	k.ctr++
	binary.BigEndian.PutUint64(k.wbuf[len(ksWhitenLabel):], k.ctr)
	for i := 0; i < Sites; i++ {
		binary.BigEndian.PutUint64(k.wbuf[len(ksWhitenLabel)+8+i*8:], uint64(k.state[i].Raw()))
	}
	key = sha256.Sum256(k.wbuf[:])
	copy(k.nbuf[len(ksNonceLabel):], key[:])
	nsum := sha256.Sum256(k.nbuf[:])
	copy(nonce[:], nsum[:KsNonceLen])
	return key, nonce
}'''))

R.append((KS, '''	epoch  uint64
	kg     *KeyGen
	aad    []byte
}

// NewRotatingSender''', '''	epoch  uint64
	kg     *KeyGen
	aad    []byte
	// mu защищает kg/epoch (2026-09-09): ks-vpn зовёт Seal из главного цикла
	// tun->net, а TickEpoch+Seal — из keepalive-горутины (ks-hub аналогично).
	// Без блокировки два Seal могли шагнуть решётку одновременно → повтор пары
	// (key, nonce) под разными plaintext (для AEAD критично) либо пропуск
	// позиции. Гонка существовала и до perf-правок; с общими scratch-буферами
	// KeyGen она стала бы заметнее.
	mu     sync.Mutex
}

// NewRotatingSender'''))

R.append((KS, '''func (s *Sender) SetSuite(su Suite) error {
	if _, err := ksAEAD(su, make([]byte, ksKeyLen)); err != nil {
		return err
	}
	s.suite = su
	return nil
}''', '''func (s *Sender) SetSuite(su Suite) error {
	if _, err := ksAEAD(su, make([]byte, ksKeyLen)); err != nil {
		return err
	}
	s.mu.Lock()
	s.suite = su
	s.mu.Unlock()
	return nil
}'''))

R.append((KS, '''func (s *Sender) TickEpoch(now time.Time) {
	if s.T == 0 {
		return
	}''', '''func (s *Sender) TickEpoch(now time.Time) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.T == 0 {
		return
	}'''))

R.append((KS, '''func (s *Sender) Seal(plain []byte) []byte {
	key, nonce := s.kg.next()
	aead, err := ksAEAD(s.suite, key[:])
	if err != nil {
		panic(err) // недостижимо: набор валидируется в SetSuite/конструкторе
	}
	ct := aead.Seal(nil, nonce[:], plain, s.aad)
	out := make([]byte, 0, KsNonceLen+len(ct))
	out = append(out, nonce[:]...)
	out = append(out, ct...)
	return out
}''', '''func (s *Sender) Seal(plain []byte) []byte {
	s.mu.Lock()
	defer s.mu.Unlock()
	key, nonce := s.kg.next()
	aead, err := ksAEAD(s.suite, key[:])
	if err != nil {
		panic(err) // недостижимо: набор валидируется в SetSuite/конструкторе
	}
	// Одна аллокация вместо двух (2026-09-09, perf): nonce пишется в начало
	// выходного буфера, AEAD допечатывает ct в него же через dst. Байты на
	// проводе побитово те же: nonce‖ct.
	out := make([]byte, KsNonceLen, KsNonceLen+len(plain)+aead.Overhead())
	copy(out, nonce[:])
	return aead.Seal(out, nonce[:], plain, s.aad)
}'''))

R.append((KS, '''type ksEpochSink struct {
	kg    *KeyGen
	aad   []byte
	ahead map[string][ksKeyLen]byte
	gen   uint64
	used  uint64
}''', '''type ksEpochSink struct {
	kg    *KeyGen
	aad   []byte
	ahead map[[KsNonceLen]byte][ksKeyLen]byte // ключ-массив: без string-аллокаций (2026-09-09, perf)
	gen   uint64
	used  uint64
}'''))

R.append((KS, '''		ahead: make(map[string][ksKeyLen]byte),''', '''		ahead: make(map[[KsNonceLen]byte][ksKeyLen]byte),'''))

R.append((KS, '''	for s.gen < s.used+window {
		key, nonce := s.kg.next()
		s.ahead[string(nonce[:])] = key
		s.gen++
	}''', '''	for s.gen < s.used+window {
		key, nonce := s.kg.next()
		s.ahead[nonce] = key
		s.gen++
	}'''))

R.append((KS, '''	nonce := wire[:KsNonceLen]
	ct := wire[KsNonceLen:]
	for _, s := range []*ksEpochSink{r.cur, r.prev} {
		if s == nil {
			continue
		}
		s.fill(r.window)
		key, ok := s.ahead[string(nonce)]
		if !ok {
			continue
		}''', '''	nonce := wire[:KsNonceLen]
	ct := wire[KsNonceLen:]
	var nkey [KsNonceLen]byte
	copy(nkey[:], nonce)
	for _, s := range []*ksEpochSink{r.cur, r.prev} {
		if s == nil {
			continue
		}
		s.fill(r.window)
		key, ok := s.ahead[nkey]
		if !ok {
			continue
		}'''))

R.append((KS, '''		delete(s.ahead, string(nonce))''', '''		delete(s.ahead, nkey)'''))

# ---------- cmd/ks-vpn/main.go ----------
R.append((MAIN, '''	"strconv"
	"sync/atomic"
	"time"''', '''	"strconv"
	"sync"
	"sync/atomic"
	"time"'''))

R.append((MAIN, '''type inPkt struct {
	data []byte
	src  *net.UDPAddr
	hit  net.IP // наш локальный адрес, на который пришла датаграмма (v6 pktinfo; nil для v4)
}''', '''type inPkt struct {
	data []byte
	src  *net.UDPAddr
	hit  net.IP  // наш локальный адрес, на который пришла датаграмма (v6 pktinfo; nil для v4)
	buf  *[]byte // владелец data от pktBufPool; nil у пакетов из wirev6/wiresrc6
}

// pktBufPool — буферы входящих датаграмм (2026-09-09, perf): раньше каждая
// датаграмма с провода = свежая аллокация 2К (make+copy из приёмного буфера);
// при десятках тысяч пак/с — постоянное давление на GC. Данные дальше Ingest
// не живут (plain — свежий слайс из AEAD.Open), поэтому буфер возвращается в
// пул сразу после Ingest. Храним указатель на слайс, чтобы не боксировать
// слайс в интерфейс при каждом Get/Put.
var pktBufPool = sync.Pool{New: func() any { b := make([]byte, 2048); return &b }}'''))

R.append((MAIN, '''	go func() {
		buf := make([]byte, 2048)
		for {
			n, cm, src, err := pconn.ReadFrom(buf)
			if err != nil {
				return
			}
			ua, ok := src.(*net.UDPAddr)
			if !ok {
				continue // не UDP-адрес — не для нас
			}
			d := make([]byte, n)
			copy(d, buf[:n])
			var hit net.IP
			if cm != nil && cm.Dst != nil && cm.Dst.To4() == nil {
				hit = cm.Dst
			}
			datch <- inPkt{d, ua, hit}
		}
	}()''', '''	go func() {
		for {
			bp := pktBufPool.Get().(*[]byte)
			n, cm, src, err := pconn.ReadFrom(*bp)
			if err != nil {
				pktBufPool.Put(bp)
				return
			}
			ua, ok := src.(*net.UDPAddr)
			if !ok {
				pktBufPool.Put(bp)
				continue // не UDP-адрес — не для нас
			}
			var hit net.IP
			if cm != nil && cm.Dst != nil && cm.Dst.To4() == nil {
				hit = cm.Dst
			}
			datch <- inPkt{(*bp)[:n], ua, hit, bp}
		}
	}()'''))

R.append((MAIN, '''		for pkt := range datch {
			cUdpRecv.Add(1)
			rx.TickEpoch(time.Now())
			plain, ok := rx.Ingest(pkt.data)
			if !ok {
				cDropped.Add(1) // probe-invisibility: молчим
				continue
			}''', '''		for pkt := range datch {
			cUdpRecv.Add(1)
			rx.TickEpoch(time.Now())
			plain, ok := rx.Ingest(pkt.data)
			if pkt.buf != nil { // пакеты wirev6/wiresrc6 приходят без пула
				pktBufPool.Put(pkt.buf)
			}
			if !ok {
				cDropped.Add(1) // probe-invisibility: молчим
				continue
			}'''))


def main() -> int:
    # сначала проверяем ВСЕ паттерны, потом пишем
    texts = {}
    for path, old, new in R:
        t = texts.setdefault(path, path.read_text(encoding='utf-8'))
        cnt = t.count(old)
        if cnt != 1:
            print(f'FAIL {path.name}: pattern found {cnt} times (need 1): {old[:70]!r}...')
            return 1
    for path, old, new in R:
        texts[path] = texts[path].replace(old, new, 1)
    for path, t in texts.items():
        path.write_text(t, encoding='utf-8')
        print(f'patched {path}')
    print('ALL PATCHES APPLIED')
    return 0


if __name__ == '__main__':
    sys.exit(main())
