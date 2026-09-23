package chaossync

// cdtstream.go — надёжный упорядоченный двунаправленный поток поверх CDT.
//
// CDT-дисперсия — ненадёжный транспорт (UDP-фрагменты, потери). Чтобы нести
// TCP-потоки (SOCKS5/VPN для серфинга+видео), нужна надёжность. Это минимальный
// reliable-datagram-stream: streamSeq + кумулятивный ACK + retransmit по RTO.
// Каждое сообщение — один CDT-фрагмент (packet-aligned). Маскировка (дисперсия
// геометрии, AEAD, ротация эпох) — из проверенного ядра CDT, не трогаем её.
//
// Модель: Stream не владеет сетью. Сетевой насос (cdt-socks) читает UDP и зовёт
// HandlePacket, а Stream отдаёт фрагменты через Send-callback. Направления
// разделены (Dir), как и везде в CDT.

import (
	"encoding/binary"
	"sync"
	"time"
)

const (
	streamHdrLen   = 16 // seq(8) + ack(8)
	streamMaxPay   = 1200
	streamRTO      = 400 * time.Millisecond
	streamAckEvery = 20 * time.Millisecond
)

// Stream — надёжный поток поверх CDT.
type Stream struct {
	frag   *Fragmenter
	defrag *Defragmenter
	send   func(wire []byte, g PacketGeom) // callback в сеть (насос)

	mu       sync.Mutex
	sendSeq  uint64
	unacked  map[uint64]streamMsg // seq -> msg (для retransmit)
	recvNext uint64               // следующий ожидаемый seq от peer'а (in-order)
	recvBuf  map[uint64][]byte    // внепорядковые
	appReady [][]byte             // in-order payload для приложения
	lastAck  time.Time
	now      func() time.Time

	T uint64 // период эпохи (сек), как у фрагментеров
	// автопилот геометрии (EnableGeomAutopilot)
	geomAuto       bool
	stepper        *ClassStepper
	baseOut        GeomConfig          // мой TX базовый конфиг
	baseIn         GeomConfig          // мой RX базовый конфиг (= TX peer-а)
	txClass        int                 // мой текущий класс передачи
	rxClass        int                 // текущий класс приёма (TX peer-а)
	swOut          *geomSw             // моё неподтверждённое переключение
	swIn           *geomSw             // принятое от peer-а (применится на границе)
	extRisk        float64             // внешний риск (DPI-профайлер, SetExtRisk)
	sentTot        uint64              // сообщений отправлено в текущей эпохе
	retxTot        uint64              // из них ретрансляций
	curEpochS      uint64              // эпоха счётчиков
	ctlHookForTest func(p []byte) bool // тестовый крюк: true = проглотить control
}

type streamMsg struct {
	seq     uint64
	payload []byte
	last    time.Time
}

// NewStream — надёжный поток. outCfg/inCfg — геометрия направлений (Dir
// разделены). send — callback, отправляющий фрагмент в сеть (насос CDT).
func NewStream(master []byte, outCfg, inCfg GeomConfig, T uint64, send func([]byte, PacketGeom)) *Stream {
	return &Stream{
		frag:    NewRotatingFragmenter(master, outCfg, T, time.Now()),
		defrag:  NewRotatingDefragmenter(master, inCfg, T, time.Now()),
		send:    send,
		T:       T,
		unacked: map[uint64]streamMsg{},
		recvBuf: map[uint64][]byte{},
		now:     time.Now,
	}
}

// Write — записать байты приложения: режем на сообщения и шлём надёжно.
func (s *Stream) Write(p []byte) {
	s.mu.Lock()
	defer s.mu.Unlock()
	for len(p) > 0 {
		n := len(p)
		if n > streamMaxPay {
			n = streamMaxPay
		}
		s.emitLocked(p[:n])
		p = p[n:]
	}
}

// emitLocked — отправить одно сообщение (уже под lock).
func (s *Stream) emitLocked(payload []byte) {
	seq := s.sendSeq
	s.sendSeq++
	msg := make([]byte, streamHdrLen+len(payload))
	binary.BigEndian.PutUint64(msg, seq)
	binary.BigEndian.PutUint64(msg[8:], s.recvNext) // piggyback ACK
	copy(msg[streamHdrLen:], payload)
	s.unacked[seq] = streamMsg{seq: seq, payload: msg, last: s.now()}
	s.sentTot++
	s.sendFragLocked(msg)
}

// sendFragLocked — через CDT-фрагментер в сеть.
func (s *Stream) sendFragLocked(msg []byte) {
	s.frag.TickEpoch(s.now())
	s.frag.Push(msg)
	if wire, g, ok := s.frag.EmitFinal(); ok {
		s.send(wire, g)
	}
}

// HandlePacket — принять фрагмент из сети (зовёт насос). Обрабатывает ACK и
// доставляет payload по порядку.
func (s *Stream) HandlePacket(wire []byte) {
	chunk, ok := s.defrag.IngestRaw(wire)
	if !ok {
		return // шум/чужой/повреждение
	}
	if len(chunk) < streamHdrLen {
		return
	}
	seq := binary.BigEndian.Uint64(chunk)
	ack := binary.BigEndian.Uint64(chunk[8:16])
	payload := chunk[streamHdrLen:]

	s.mu.Lock()
	// обработать ACK: peer подтвердил всё < ack
	for q := range s.unacked {
		if q < ack {
			delete(s.unacked, q)
		}
	}
	// доставить по порядку
	if len(payload) > 0 {
		switch {
		case seq == s.recvNext:
			s.deliverLocked(payload)
			s.recvNext++
			for {
				next, ok := s.recvBuf[s.recvNext]
				if !ok {
					break
				}
				delete(s.recvBuf, s.recvNext)
				s.deliverLocked(next)
				s.recvNext++
			}
		case seq > s.recvNext:
			if _, dup := s.recvBuf[seq]; !dup {
				s.recvBuf[seq] = payload
			}
		}
		// пора пере-ACK
		if s.now().Sub(s.lastAck) > streamAckEvery {
			s.lastAck = s.now()
			s.sendAckLocked()
		}
	}
	s.mu.Unlock()
}

// sendAckLocked — ACK-only сообщение (без payload): подтверждаю recvNext.
func (s *Stream) sendAckLocked() {
	msg := make([]byte, streamHdrLen)
	binary.BigEndian.PutUint64(msg, s.sendSeq) // seq не тратим (payload пуст)
	binary.BigEndian.PutUint64(msg[8:], s.recvNext)
	s.sendFragLocked(msg)
}

// Read — прочитать in-order байты приложением (nil, если пока нет).
func (s *Stream) Read() []byte {
	s.mu.Lock()
	defer s.mu.Unlock()
	if len(s.appReady) == 0 {
		return nil
	}
	p := s.appReady[0]
	s.appReady = s.appReady[1:]
	return p
}

// Tick — периодический вызов насосом: ротация эпох + retransmit по RTO.
func (s *Stream) Tick() {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.geomAuto {
		s.autopilotLocked()
	}
	s.frag.TickEpoch(s.now())
	s.defrag.TickEpoch(s.now())
	cutoff := s.now().Add(-streamRTO)
	for _, m := range s.unacked {
		if m.last.Before(cutoff) {
			// retransmit: то же сообщение (тот же seq) новым фрагментом
			m.last = s.now()
			s.retxTot++
			s.unacked[m.seq] = m
			// обновить piggyback ACK
			binary.BigEndian.PutUint64(m.payload[8:], s.recvNext)
			s.sendFragLocked(m.payload)
		}
	}
}

// Pending — неподтверждённые сообщения (для метрик/закрытия).
func (s *Stream) Pending() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return len(s.unacked)
}

// --- автопилот геометрии: in-band переключение класса дисперсии -----------
//
// Протокол (по надёжному потоку — REQ ретранслируется до stream-ACK):
//   sender   -> REQ{class, fromEpoch}   «с эпохи fromEpoch я шлю классом class»
//   receiver -> ACK{class, fromEpoch, ok}; ok=1 только если fromEpoch >=
//               текущей+1: sink нового класса создаётся ДО границы, позиции
//               nonce выровнены. Поздний/занятый REQ отклоняется (ok=0),
//               sender переоформляет с новым fromEpoch.
// Sender переключается только после ok=1 -> на границе обе стороны в одном
// классе (lockstep). Peer без автопилота не отвечает ACK: после 5 попыток
// автопилот честно отключается (туннель остаётся на стартовом классе).
//
// Control-кадр — обычное сообщение потока с магическим префиксом; приложению
// не доставляется. Коллизия с app-пейлоадом практически исключена (первые
// байты кадра cdt-socks — счётный streamID).

const geomCtlMagic = "\xffCDTG"

const (
	geomCtlReq = 1
	geomCtlAck = 2
)

// geomSw — незавершённое переключение класса.
type geomSw struct {
	class     int
	fromEpoch uint64
	committed bool
	tries     int
}

// EnableGeomAutopilot — включить авто-подбор дисперсии. baseOut/baseIn —
// базовые конфиги направлений (как в NewStream); класс стартует со
// степпера; дальше класс мутирует на границах эпох по протоколу выше.
// Обе стороны включают с зеркальными базовыми конфигами.
func (s *Stream) EnableGeomAutopilot(step *ClassStepper, baseOut, baseIn GeomConfig) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.geomAuto = true
	s.stepper = step
	s.baseOut = baseOut.withDefaults()
	s.baseIn = baseIn.withDefaults()
	s.txClass = step.Class()
	s.rxClass = step.Class()
	s.curEpochS = EpochFor(s.now(), s.T)
	s.frag.SetGeomProvider(func(ep uint64) GeomConfig {
		return AutopilotGeomClass(s.baseOut, s.txClassAtLocked(ep))
	})
	s.defrag.SetGeomProvider(func(ep uint64) GeomConfig {
		return AutopilotGeomClass(s.baseIn, s.rxClassAtLocked(ep))
	})
}

// SetExtRisk — внешняя оценка риска [0,1] (точка подключения DPI-профайлера).
func (s *Stream) SetExtRisk(r float64) {
	s.mu.Lock()
	s.extRisk = r
	s.mu.Unlock()
}

// GeomClassesNow — текущие классы (TX мой, RX peer-а) для журнала/метрик.
func (s *Stream) GeomClassesNow() (int, int) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.txClass, s.rxClass
}

func (s *Stream) txClassAtLocked(ep uint64) int {
	if s.swOut != nil && s.swOut.committed && ep >= s.swOut.fromEpoch {
		return s.swOut.class
	}
	return s.txClass
}

func (s *Stream) rxClassAtLocked(ep uint64) int {
	if s.swIn != nil && ep >= s.swIn.fromEpoch {
		return s.swIn.class
	}
	return s.rxClass
}

// autopilotLocked — шаг автопилота (под lock, до TickEpoch).
func (s *Stream) autopilotLocked() {
	ep := EpochFor(s.now(), s.T)
	if ep != s.curEpochS {
		s.curEpochS = ep
		s.sentTot, s.retxTot = 0, 0
	}
	// принятый от peer-а класс вступает в силу на его границе
	if s.swIn != nil && ep >= s.swIn.fromEpoch {
		s.rxClass = s.swIn.class
		s.swIn = nil
	}
	risk := RiskFromMetrics(s.extRisk, s.retxRateLocked(), 1.0)
	cls := s.stepper.Step(risk, ep)
	if cls != s.txClass && s.swOut == nil {
		s.swOut = &geomSw{class: cls, fromEpoch: ep + 2}
		s.sendGeomCtlLocked(geomCtlReq, cls, ep+2, 0)
	}
	if s.swOut != nil && s.swOut.committed && ep >= s.swOut.fromEpoch {
		s.txClass = s.swOut.class
		s.swOut = nil
	}
	if s.swOut != nil && !s.swOut.committed && ep >= s.swOut.fromEpoch {
		s.swOut.tries++
		if s.swOut.tries > 5 {
			s.geomAuto = false // peer не подтверждает — честно выключаемся
			s.swOut = nil
		} else {
			s.swOut.fromEpoch = ep + 2
			s.sendGeomCtlLocked(geomCtlReq, s.swOut.class, s.swOut.fromEpoch, 0)
		}
	}
}

func (s *Stream) retxRateLocked() float64 {
	if s.sentTot == 0 {
		return 0
	}
	return float64(s.retxTot) / float64(s.sentTot)
}

// deliverLocked — точка доставки in-order пейлоада: control перехватывается,
// приложению не отдаётся.
func (s *Stream) deliverLocked(payload []byte) {
	if len(payload) >= 5 && payload[0] == 0xff && string(payload[1:5]) == "CDTG" {
		if s.ctlHookForTest != nil && s.ctlHookForTest(payload) {
			return // тестовая потеря control-кадра
		}
		s.handleGeomCtlLocked(payload)
		return
	}
	s.appReady = append(s.appReady, payload)
}

// sendGeomCtlLocked — control-кадр как обычное сообщение потока (seq +
// ретрансляции бесплатно).
func (s *Stream) sendGeomCtlLocked(kind byte, cls int, fromEpoch uint64, ok byte) {
	p := make([]byte, 16)
	copy(p, geomCtlMagic)
	p[5] = kind
	p[6] = byte(cls)
	binary.BigEndian.PutUint64(p[7:15], fromEpoch)
	p[15] = ok
	s.emitLocked(p)
}

func (s *Stream) handleGeomCtlLocked(p []byte) {
	if len(p) < 16 {
		return
	}
	kind := p[5]
	cls := int(p[6])
	fromEpoch := binary.BigEndian.Uint64(p[7:15])
	switch kind {
	case geomCtlReq:
		ok := byte(0)
		curEp := EpochFor(s.now(), s.T)
		if s.geomAuto && s.swIn == nil && cls >= 0 && cls < GeomClasses &&
			fromEpoch >= curEp+1 && fromEpoch <= curEp+16 {
			s.swIn = &geomSw{class: cls, fromEpoch: fromEpoch}
			ok = 1
		}
		s.sendGeomCtlLocked(geomCtlAck, cls, fromEpoch, ok)
	case geomCtlAck:
		if s.swOut != nil && s.swOut.class == cls && s.swOut.fromEpoch == fromEpoch {
			if p[15] == 1 {
				s.swOut.committed = true
			} else {
				// отклонено (поздно/занято): переоформить с запасом
				s.swOut.fromEpoch = EpochFor(s.now(), s.T) + 2
				s.sendGeomCtlLocked(geomCtlReq, s.swOut.class, s.swOut.fromEpoch, 0)
			}
		}
	}
}
