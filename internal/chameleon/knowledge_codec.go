package chameleon

// knowledge_codec.go — CST: проводной формат сообщений knowledge-слоя.
//
// Все CST-кадры едут внутри мультиплексора с sid=0 (командный поток);
// команды — новые опкоды 0x10..0x1B (см. mux.go). Каждое сообщение несёт
// FlowID внутри payload — демультиплексирование по потокам не зависит от
// StreamID и переживает смену transport cell.
//
// Каноничность: декодеры требуют ТОЧНОЙ длины (trailing data отвергается),
// все длины проверяются ДО выделения памяти (allocation bomb исключена),
// multi-byte поля — big-endian. MAC/HMAC покрывают всё тело сообщения.

import (
	"crypto/hmac"
	"encoding/binary"
	"errors"
)

const (
	cstHelloLen      = 4
	cstOpenFixedLen  = 2 + 16 + 32 + 1 + 2 + 2 // без ro/target/mac
	cstOpenMACLen    = 32
	cstOpenOKLen     = 2 + 16 + 4
	cstDeltaHeadLen  = 1 + 16 + 1 + 1 + 4 + 8 + 8 + 8 + 4 // 51
	cstTagLen        = 32
	cstAckHeadLen    = 1 + 16 + 1 + 4 + 8          // 30
	cstAttachHeadLen = 1 + 16 + 4 + 8 + 8 + 8 + 16 // 61
	cstAttachOKLen   = 1 + 16 + 4 + 8 + 8          // 37
	cstDetachHeadLen = 1 + 16 + 4                  // 21
	cstCloseHeadLen  = 1 + 16 + 1                  // 18
	cstSnapHeadLen   = 1 + 16 + 4 + 8 + 8 + 32 + 8 // 77

	// maxCSTPayload — верхний предел payload дельты. Вписывается в
	// muxMaxData (60000) вместе с заголовками: 5 + 51 + 59000 + 32 < 65518.
	maxCSTPayload = 59000
	// maxCSTDatagram — предел полезной части UDP-дейтаграммы.
	maxCSTDatagram = 2048
	maxCSTTarget   = 512
	maxCSTMsg      = 512 // текстовые сообщения ошибок
)

// --- Capability negotiation ---

// CSTHello — объявление возможностей: [u16 ver][u16 flags].
// flags bit0 = сторона поддерживает CST. Клиент шлёт после поднятия mux,
// нода отвечает тем же кадром (только если у неё включён CST).
type CSTHello struct {
	Version uint16
	Flags   uint16
}

const CSTFlagSupported uint16 = 1

func (h *CSTHello) Encode() []byte {
	b := make([]byte, cstHelloLen)
	binary.BigEndian.PutUint16(b[0:2], h.Version)
	binary.BigEndian.PutUint16(b[2:4], h.Flags)
	return b
}

func DecodeCSTHello(b []byte) (*CSTHello, error) {
	if len(b) != cstHelloLen {
		return nil, errors.New("cst: hello: bad length")
	}
	return &CSTHello{Version: binary.BigEndian.Uint16(b[0:2]), Flags: binary.BigEndian.Uint16(b[2:4])}, nil
}

// --- KnowledgeOpen ---

// CSTOpen — открытие логического потока:
// [u16 ver][16B flowID][32B flowSecret][u8 mode][u16 roLen][ro][u16 tgtLen][target][32B mac]
// target — ATYP-кодировка как у smOpen (EncodeTarget) либо UDP-маркер 0xF0.
// ro — опциональный ResolutionObject для DNS-binding (доменные цели).
// mac = HMAC(OpenKey(flowSecret, flowID), body): доказательство владения
// секретом потока; сам секрет едет один раз, внутри AEAD-сеанса.
type CSTOpen struct {
	Version uint16
	ID      FlowID
	Secret  [32]byte
	Mode    uint8
	RO      []byte
	Target  []byte
	MAC     []byte
}

func (o *CSTOpen) body() []byte {
	b := make([]byte, 0, cstOpenFixedLen+len(o.RO)+len(o.Target))
	b = binary.BigEndian.AppendUint16(b, o.Version)
	b = append(b, o.ID[:]...)
	b = append(b, o.Secret[:]...)
	b = append(b, o.Mode)
	b = binary.BigEndian.AppendUint16(b, uint16(len(o.RO)))
	b = append(b, o.RO...)
	b = binary.BigEndian.AppendUint16(b, uint16(len(o.Target)))
	b = append(b, o.Target...)
	return b
}

func (o *CSTOpen) Encode() []byte {
	body := o.body()
	o.MAC = hmacSHA256(OpenKey(o.Secret[:], o.ID), body)
	return append(body, o.MAC...)
}

func DecodeCSTOpen(b []byte) (*CSTOpen, error) {
	if len(b) < cstOpenFixedLen+cstOpenMACLen {
		return nil, errors.New("cst: open: короткий кадр")
	}
	roLen := int(binary.BigEndian.Uint16(b[51:53]))
	tgtOff := 53 + roLen
	if len(b) < tgtOff+2 {
		return nil, errors.New("cst: open: битый ro")
	}
	tgtLen := int(binary.BigEndian.Uint16(b[tgtOff : tgtOff+2]))
	if tgtLen < 1 || tgtLen > maxCSTTarget || roLen > maxOpenPayloadBytes {
		return nil, errors.New("cst: open: невалидные длины")
	}
	if len(b) != tgtOff+2+tgtLen+cstOpenMACLen {
		return nil, errors.New("cst: open: trailing data или усечение")
	}
	o := &CSTOpen{Version: binary.BigEndian.Uint16(b[0:2]), Mode: b[50]}
	copy(o.ID[:], b[2:18])
	copy(o.Secret[:], b[18:50])
	o.RO = append([]byte(nil), b[53:tgtOff]...)
	o.Target = append([]byte(nil), b[tgtOff+2:tgtOff+2+tgtLen]...)
	o.MAC = append([]byte(nil), b[tgtOff+2+tgtLen:]...)
	if o.Mode != CSTModeTCP && o.Mode != CSTModeUDP {
		return nil, errors.New("cst: open: неизвестный режим")
	}
	expected := hmacSHA256(OpenKey(o.Secret[:], o.ID), b[:len(b)-cstOpenMACLen])
	if !hmac.Equal(o.MAC, expected) {
		return nil, errors.New("cst: open: MAC не сошёлся")
	}
	return o, nil
}

// CSTOpenOK — [u16 ver][16B flowID][u32 generation].
type CSTOpenOK struct {
	Version uint16
	ID      FlowID
	Gen     uint32
}

func (m *CSTOpenOK) Encode() []byte {
	b := make([]byte, cstOpenOKLen)
	binary.BigEndian.PutUint16(b[0:2], m.Version)
	copy(b[2:18], m.ID[:])
	binary.BigEndian.PutUint32(b[18:22], m.Gen)
	return b
}

func DecodeCSTOpenOK(b []byte) (*CSTOpenOK, error) {
	if len(b) != cstOpenOKLen {
		return nil, errors.New("cst: open-ok: bad length")
	}
	m := &CSTOpenOK{Version: binary.BigEndian.Uint16(b[0:2]), Gen: binary.BigEndian.Uint32(b[18:22])}
	copy(m.ID[:], b[2:18])
	return m, nil
}

// CSTErr — общий формат ошибок open/attach: [u16 ver][16B flowID][u16 mlen][msg].
type CSTErr struct {
	Version uint16
	ID      FlowID
	Msg     string
}

func (e *CSTErr) Encode() []byte {
	msg := []byte(e.Msg)
	if len(msg) > maxCSTMsg {
		msg = msg[:maxCSTMsg]
	}
	b := make([]byte, 0, 20+len(msg))
	b = binary.BigEndian.AppendUint16(b, e.Version)
	b = append(b, e.ID[:]...)
	b = binary.BigEndian.AppendUint16(b, uint16(len(msg)))
	return append(b, msg...)
}

func DecodeCSTErr(b []byte) (*CSTErr, error) {
	if len(b) < 20 {
		return nil, errors.New("cst: err: короткий кадр")
	}
	mlen := int(binary.BigEndian.Uint16(b[18:20]))
	if len(b) != 20+mlen {
		return nil, errors.New("cst: err: trailing data или усечение")
	}
	e := &CSTErr{Version: binary.BigEndian.Uint16(b[0:2]), Msg: string(b[20:])}
	copy(e.ID[:], b[2:18])
	return e, nil
}

// --- Delta ---

// CSTDelta — логическая дельта потока:
// [u8 ver][16B flowID][u8 dir][u8 flags][u32 gen][u64 offset][u64 dep]
// [i64 expiryMs][u32 payloadLen][payload][32B tag]
// dep — зависимость: конец предыдущего непрерывного диапазона (для TCP
// первой версии dep == offset всегда: строгая последовательность).
// tag = HMAC(DeltaKey(dir, gen), header+payload): аутентификация не зависит
// от транспортного AEAD — дельту можно безопасно повторить в новой сессии.
type CSTDelta struct {
	Version  uint8
	ID       FlowID
	Dir      uint8
	Flags    uint8
	Gen      uint32
	Offset   uint64
	Dep      uint64
	ExpiryMs int64
	Payload  []byte
	Tag      []byte
}

func (d *CSTDelta) head() []byte {
	b := make([]byte, 0, cstDeltaHeadLen+len(d.Payload))
	b = append(b, d.Version)
	b = append(b, d.ID[:]...)
	b = append(b, d.Dir, d.Flags)
	b = binary.BigEndian.AppendUint32(b, d.Gen)
	b = binary.BigEndian.AppendUint64(b, d.Offset)
	b = binary.BigEndian.AppendUint64(b, d.Dep)
	b = binary.BigEndian.AppendUint64(b, uint64(d.ExpiryMs))
	b = binary.BigEndian.AppendUint32(b, uint32(len(d.Payload)))
	return append(b, d.Payload...)
}

func (d *CSTDelta) Encode(fc *FlowContinuity) []byte {
	body := d.head()
	d.Tag = hmacSHA256(fc.DeltaKey(d.Dir, d.Gen), body)
	return append(body, d.Tag...)
}

// DecodeCSTDelta строго декодирует дельту. Проверка HMAC — отдельно
// (VerifyTag), т.к. декодеру недоступен continuity key. Память под payload
// выделяется только после полной проверки длин.
func DecodeCSTDelta(b []byte) (*CSTDelta, error) {
	if len(b) < cstDeltaHeadLen+cstTagLen {
		return nil, errors.New("cst: delta: короткий кадр")
	}
	plen := uint64(binary.BigEndian.Uint32(b[47:51]))
	if plen > maxCSTPayload {
		return nil, errors.New("cst: delta: payload сверх лимита")
	}
	if uint64(len(b)) != uint64(cstDeltaHeadLen)+plen+uint64(cstTagLen) {
		return nil, errors.New("cst: delta: trailing data или усечение")
	}
	d := &CSTDelta{
		Version:  b[0],
		Dir:      b[17],
		Flags:    b[18],
		Gen:      binary.BigEndian.Uint32(b[19:23]),
		Offset:   binary.BigEndian.Uint64(b[23:31]),
		Dep:      binary.BigEndian.Uint64(b[31:39]),
		ExpiryMs: int64(binary.BigEndian.Uint64(b[39:47])),
	}
	copy(d.ID[:], b[1:17])
	d.Payload = append([]byte(nil), b[cstDeltaHeadLen:cstDeltaHeadLen+int(plen)]...)
	d.Tag = append([]byte(nil), b[cstDeltaHeadLen+int(plen):]...)
	if d.Dir != CSTDirC2S && d.Dir != CSTDirS2C {
		return nil, errors.New("cst: delta: неизвестное направление")
	}
	return d, nil
}

// VerifyTag проверяет криптографическую аутентификацию дельты.
func (d *CSTDelta) VerifyTag(fc *FlowContinuity) bool {
	if fc == nil {
		return false
	}
	expected := hmacSHA256(fc.DeltaKey(d.Dir, d.Gen), d.head())
	return hmac.Equal(d.Tag, expected)
}

// Expired — дедлайн дельты истёк (0 = без дедлайна).
func (d *CSTDelta) Expired(nowMs int64) bool {
	return d.ExpiryMs > 0 && nowMs > d.ExpiryMs
}

// --- Knowledge ACK ---

// CSTAck — knowledge ACK: [u8 ver][16B flowID][u8 dir][u32 gen][u64 ack][32B tag].
// Семантика: "все байты направления dir до offset ack криптографически
// проверены, упорядочены и переданы локальному потребителю". Монотонен,
// идемпотентен, не может превышать принятую границу.
type CSTAck struct {
	Version uint8
	ID      FlowID
	Dir     uint8
	Gen     uint32
	Ack     uint64
	Tag     []byte
}

func (a *CSTAck) body() []byte {
	b := make([]byte, 0, cstAckHeadLen)
	b = append(b, a.Version)
	b = append(b, a.ID[:]...)
	b = append(b, a.Dir)
	b = binary.BigEndian.AppendUint32(b, a.Gen)
	return binary.BigEndian.AppendUint64(b, a.Ack)
}

func (a *CSTAck) Encode(fc *FlowContinuity) []byte {
	body := a.body()
	a.Tag = hmacSHA256(fc.AckKey(a.Dir, a.Gen), body)
	return append(body, a.Tag...)
}

func DecodeCSTAck(b []byte) (*CSTAck, error) {
	if len(b) != cstAckHeadLen+cstTagLen {
		return nil, errors.New("cst: ack: bad length")
	}
	a := &CSTAck{
		Version: b[0],
		Dir:     b[17],
		Gen:     binary.BigEndian.Uint32(b[18:22]),
		Ack:     binary.BigEndian.Uint64(b[22:30]),
	}
	copy(a.ID[:], b[1:17])
	a.Tag = append([]byte(nil), b[cstAckHeadLen:]...)
	return a, nil
}

func (a *CSTAck) VerifyTag(fc *FlowContinuity) bool {
	if fc == nil {
		return false
	}
	expected := hmacSHA256(fc.AckKey(a.Dir, a.Gen), a.body())
	return hmac.Equal(a.Tag, expected)
}

// --- Manifest/Attach ---

// CSTAttach — манифест присоединения detached-потока к НОВОЙ физической
// сессии: [u8 ver][16B flowID][u32 newGen][u64 clientS2CAcked]
// [u64 clientC2SAcked][i64 expiryMs][16B clientNonce][32B mac].
// clientS2CAcked — knowledge boundary клиента по входящему направлению
// (нода подрезает свой replay и дошлёт хвост). clientC2SAcked — последний
// ACK ноды, виденный клиенту (информационно, для сверки rollback).
// mac = HMAC(AttachKey, body+sessionSeed): привязка к новой сессии —
// replay манифеста из старой сессии не сходится; FlowSecret в манифесте
// отсутствует.
type CSTAttach struct {
	Version        uint8
	ID             FlowID
	NewGen         uint32
	ClientS2CAcked uint64
	ClientC2SAcked uint64
	ExpiryMs       int64
	Nonce          [16]byte
	MAC            []byte
}

func (m *CSTAttach) body() []byte {
	b := make([]byte, 0, cstAttachHeadLen)
	b = append(b, m.Version)
	b = append(b, m.ID[:]...)
	b = binary.BigEndian.AppendUint32(b, m.NewGen)
	b = binary.BigEndian.AppendUint64(b, m.ClientS2CAcked)
	b = binary.BigEndian.AppendUint64(b, m.ClientC2SAcked)
	b = binary.BigEndian.AppendUint64(b, uint64(m.ExpiryMs))
	return append(b, m.Nonce[:]...)
}

func (m *CSTAttach) Encode(fc *FlowContinuity, sessionSeed []byte) []byte {
	body := m.body()
	m.MAC = hmacSHA256(fc.AttachKey(), append(body, sessionSeed...))
	return append(body, m.MAC...)
}

func DecodeCSTAttach(b []byte) (*CSTAttach, error) {
	if len(b) != cstAttachHeadLen+cstTagLen {
		return nil, errors.New("cst: attach: bad length")
	}
	m := &CSTAttach{
		Version:        b[0],
		NewGen:         binary.BigEndian.Uint32(b[17:21]),
		ClientS2CAcked: binary.BigEndian.Uint64(b[21:29]),
		ClientC2SAcked: binary.BigEndian.Uint64(b[29:37]),
		ExpiryMs:       int64(binary.BigEndian.Uint64(b[37:45])),
	}
	copy(m.ID[:], b[1:17])
	copy(m.Nonce[:], b[45:61])
	m.MAC = append([]byte(nil), b[cstAttachHeadLen:]...)
	return m, nil
}

func (m *CSTAttach) VerifyMAC(fc *FlowContinuity, sessionSeed []byte) bool {
	if fc == nil {
		return false
	}
	expected := hmacSHA256(fc.AttachKey(), append(m.body(), sessionSeed...))
	return hmac.Equal(m.MAC, expected)
}

// CSTAttachOK — ответ ноды: [u8 ver][16B flowID][u32 gen][u64 nodeC2SBoundary]
// [u64 nodeS2CNext][32B mac]. nodeC2SBoundary — сколько байт от клиента нода
// подтвердила (записала в egress); клиент повторяет дельты сверх неё.
// nodeS2CNext — следующий исходящий offset ноды (детект дыр/дублей).
type CSTAttachOK struct {
	Version         uint8
	ID              FlowID
	Gen             uint32
	NodeC2SBoundary uint64
	NodeS2CNext     uint64
	MAC             []byte
}

func (m *CSTAttachOK) body() []byte {
	b := make([]byte, 0, cstAttachOKLen)
	b = append(b, m.Version)
	b = append(b, m.ID[:]...)
	b = binary.BigEndian.AppendUint32(b, m.Gen)
	b = binary.BigEndian.AppendUint64(b, m.NodeC2SBoundary)
	return binary.BigEndian.AppendUint64(b, m.NodeS2CNext)
}

func (m *CSTAttachOK) Encode(fc *FlowContinuity, sessionSeed []byte) []byte {
	body := m.body()
	m.MAC = hmacSHA256(fc.AttachKey(), append(body, sessionSeed...))
	return append(body, m.MAC...)
}

func DecodeCSTAttachOK(b []byte) (*CSTAttachOK, error) {
	if len(b) != cstAttachOKLen+cstTagLen {
		return nil, errors.New("cst: attach-ok: bad length")
	}
	m := &CSTAttachOK{
		Version:         b[0],
		Gen:             binary.BigEndian.Uint32(b[17:21]),
		NodeC2SBoundary: binary.BigEndian.Uint64(b[21:29]),
		NodeS2CNext:     binary.BigEndian.Uint64(b[29:37]),
	}
	copy(m.ID[:], b[1:17])
	m.MAC = append([]byte(nil), b[cstAttachOKLen:]...)
	return m, nil
}

func (m *CSTAttachOK) VerifyMAC(fc *FlowContinuity, sessionSeed []byte) bool {
	if fc == nil {
		return false
	}
	expected := hmacSHA256(fc.AttachKey(), append(m.body(), sessionSeed...))
	return hmac.Equal(m.MAC, expected)
}

// --- Detach / Close / Snapshot ---

// CSTDetach — штатное отсоединение: [u8 ver][16B flowID][u32 gen][32B tag].
type CSTDetach struct {
	Version uint8
	ID      FlowID
	Gen     uint32
	Tag     []byte
}

func (d *CSTDetach) body() []byte {
	b := make([]byte, 0, cstDetachHeadLen)
	b = append(b, d.Version)
	b = append(b, d.ID[:]...)
	return binary.BigEndian.AppendUint32(b, d.Gen)
}

func (d *CSTDetach) Encode(fc *FlowContinuity) []byte {
	body := d.body()
	d.Tag = hmacSHA256(fc.DetachKey(d.Gen), body)
	return append(body, d.Tag...)
}

func DecodeCSTDetach(b []byte) (*CSTDetach, error) {
	if len(b) != cstDetachHeadLen+cstTagLen {
		return nil, errors.New("cst: detach: bad length")
	}
	d := &CSTDetach{Version: b[0], Gen: binary.BigEndian.Uint32(b[17:21])}
	copy(d.ID[:], b[1:17])
	d.Tag = append([]byte(nil), b[cstDetachHeadLen:]...)
	return d, nil
}

func (d *CSTDetach) VerifyTag(fc *FlowContinuity) bool {
	if fc == nil {
		return false
	}
	expected := hmacSHA256(fc.DetachKey(d.Gen), d.body())
	return hmac.Equal(d.Tag, expected)
}

// Причины закрытия потока.
const (
	CSTCloseNormal        uint8 = 0
	CSTCloseEgressLost    uint8 = 1
	CSTClosePolicy        uint8 = 2
	CSTCloseLimits        uint8 = 3
	CSTCloseExpired       uint8 = 4
	CSTCloseProtocolError uint8 = 5
)

// CSTClose — закрытие ТОЛЬКО этого потока: [u8 ver][16B flowID][u8 reason][32B tag].
type CSTClose struct {
	Version uint8
	ID      FlowID
	Reason  uint8
	Tag     []byte
}

func (c *CSTClose) body() []byte {
	b := make([]byte, 0, cstCloseHeadLen)
	b = append(b, c.Version)
	b = append(b, c.ID[:]...)
	return append(b, c.Reason)
}

func (c *CSTClose) Encode(fc *FlowContinuity) []byte {
	body := c.body()
	c.Tag = hmacSHA256(fc.CloseKey(), body)
	return append(body, c.Tag...)
}

func DecodeCSTClose(b []byte) (*CSTClose, error) {
	if len(b) != cstCloseHeadLen+cstTagLen {
		return nil, errors.New("cst: close: bad length")
	}
	c := &CSTClose{Version: b[0], Reason: b[17]}
	copy(c.ID[:], b[1:17])
	c.Tag = append([]byte(nil), b[cstCloseHeadLen:]...)
	return c, nil
}

func (c *CSTClose) VerifyTag(fc *FlowContinuity) bool {
	if fc == nil {
		return false
	}
	expected := hmacSHA256(fc.CloseKey(), c.body())
	return hmac.Equal(c.Tag, expected)
}

// CSTSnapshot — snapshot/compaction: [u8 ver][16B flowID][u32 gen]
// [u64 c2sAcked][u64 s2cAcked][32B windowHash][i64 expiryMs][32B mac].
// Не содержит payload; после проверки MAC обе стороны освобождают
// replay-данные ниже подтверждённых границ.
type CSTSnapshot struct {
	Version    uint8
	ID         FlowID
	Gen        uint32
	C2SAcked   uint64
	S2CAcked   uint64
	WindowHash [32]byte
	ExpiryMs   int64
	MAC        []byte
}

func (s *CSTSnapshot) body() []byte {
	b := make([]byte, 0, cstSnapHeadLen)
	b = append(b, s.Version)
	b = append(b, s.ID[:]...)
	b = binary.BigEndian.AppendUint32(b, s.Gen)
	b = binary.BigEndian.AppendUint64(b, s.C2SAcked)
	b = binary.BigEndian.AppendUint64(b, s.S2CAcked)
	b = append(b, s.WindowHash[:]...)
	return binary.BigEndian.AppendUint64(b, uint64(s.ExpiryMs))
}

func (s *CSTSnapshot) Encode(fc *FlowContinuity) []byte {
	body := s.body()
	s.MAC = hmacSHA256(fc.SnapshotKey(s.Gen), body)
	return append(body, s.MAC...)
}

func DecodeCSTSnapshot(b []byte) (*CSTSnapshot, error) {
	if len(b) != cstSnapHeadLen+cstTagLen {
		return nil, errors.New("cst: snapshot: bad length")
	}
	s := &CSTSnapshot{
		Version:  b[0],
		Gen:      binary.BigEndian.Uint32(b[17:21]),
		C2SAcked: binary.BigEndian.Uint64(b[21:29]),
		S2CAcked: binary.BigEndian.Uint64(b[29:37]),
		ExpiryMs: int64(binary.BigEndian.Uint64(b[69:77])),
	}
	copy(s.ID[:], b[1:17])
	copy(s.WindowHash[:], b[37:69])
	s.MAC = append([]byte(nil), b[cstSnapHeadLen:]...)
	return s, nil
}

func (s *CSTSnapshot) VerifyMAC(fc *FlowContinuity) bool {
	if fc == nil {
		return false
	}
	expected := hmacSHA256(fc.SnapshotKey(s.Gen), s.body())
	return hmac.Equal(s.MAC, expected)
}
