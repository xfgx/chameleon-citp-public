import sys
nl = chr(10)
T = chr(9)

def edit(path, fn):
    s = open(path, encoding='utf-8').read()
    s2 = fn(s)
    open(path, 'w', encoding='utf-8').write(s2)
    print('edited', path)

def rep(s, old, new, cnt=1):
    assert s.count(old) == cnt, 'anchor count %d != %d: %r' % (s.count(old), cnt, old[:70])
    return s.replace(old, new, cnt)

# ============ cdtstream.go: добивка (поля уже вставлены прошлым патчем) ====
def f_stream(s):
    # T в конструкторе (whitespace-терпимый якорь)
    s = rep(s, 'send:    send,', 'send:    send,'+nl+T+T+'T:    T,')
    # счётчик отправок
    s = rep(s, 's.unacked[seq] = streamMsg{seq: seq, payload: msg, last: s.now()}',
            's.unacked[seq] = streamMsg{seq: seq, payload: msg, last: s.now()}'+nl+T+'s.sentTot++')
    # in-order доставка через deliverLocked (2 точки)
    s = rep(s, 's.appReady = append(s.appReady, payload)', 's.deliverLocked(payload)')
    s = rep(s, 's.appReady = append(s.appReady, next)', 's.deliverLocked(next)')
    # автопилот в Tick до ротации
    s = rep(s, 'defer s.mu.Unlock()'+nl+T+'s.frag.TickEpoch(s.now())',
            'defer s.mu.Unlock()'+nl+T+'if s.geomAuto {'+nl+T+T+'s.autopilotLocked()'+nl+T+'}'+nl+T+'s.frag.TickEpoch(s.now())')
    # счётчик ретрансляций
    s = rep(s, 'm.last = s.now()'+nl+T+T+T+'s.unacked[m.seq] = m',
            'm.last = s.now()'+nl+T+T+T+'s.retxTot++'+nl+T+T+T+'s.unacked[m.seq] = m')
    # новый код в конец файла
    s = s + nl + nl.join([
'// --- автопилот геометрии: in-band переключение класса дисперсии -----------',
'//',
'// Протокол (по надёжному потоку — REQ ретранслируется до stream-ACK):',
'//   sender   -> REQ{class, fromEpoch}   «с эпохи fromEpoch я шлю классом class»',
'//   receiver -> ACK{class, fromEpoch, ok}; ok=1 только если fromEpoch >=',
'//               текущей+1: sink нового класса создаётся ДО границы, позиции',
'//               nonce выровнены. Поздний/занятый REQ отклоняется (ok=0),',
'//               sender переоформляет с новым fromEpoch.',
'// Sender переключается только после ok=1 -> на границе обе стороны в одном',
'// классе (lockstep). Peer без автопилота не отвечает ACK: после 5 попыток',
'// автопилот честно отключается (туннель остаётся на стартовом классе).',
'//',
'// Control-кадр — обычное сообщение потока с магическим префиксом; приложению',
'// не доставляется. Коллизия с app-пейлоадом практически исключена (первые',
'// байты кадра cdt-socks — счётный streamID).',
'',
'const geomCtlMagic = "\\xffCDTG"',
'',
'const (',
T+'geomCtlReq = 1',
T+'geomCtlAck = 2',
')',
'',
'// geomSw — незавершённое переключение класса.',
'type geomSw struct {',
T+'class     int',
T+'fromEpoch uint64',
T+'committed bool',
T+'tries     int',
'}',
'',
'// EnableGeomAutopilot — включить авто-подбор дисперсии. baseOut/baseIn —',
'// базовые конфиги направлений (как в NewStream); класс стартует со',
'// степпера; дальше класс мутирует на границах эпох по протоколу выше.',
'// Обе стороны включают с зеркальными базовыми конфигами.',
'func (s *Stream) EnableGeomAutopilot(step *ClassStepper, baseOut, baseIn GeomConfig) {',
T+'s.mu.Lock()',
T+'defer s.mu.Unlock()',
T+'s.geomAuto = true',
T+'s.stepper = step',
T+'s.baseOut = baseOut.withDefaults()',
T+'s.baseIn = baseIn.withDefaults()',
T+'s.txClass = step.Class()',
T+'s.rxClass = step.Class()',
T+'s.curEpochS = EpochFor(s.now(), s.T)',
T+'s.frag.SetGeomProvider(func(ep uint64) GeomConfig {',
T+T+'return AutopilotGeomClass(s.baseOut, s.txClassAtLocked(ep))',
T+'})',
T+'s.defrag.SetGeomProvider(func(ep uint64) GeomConfig {',
T+T+'return AutopilotGeomClass(s.baseIn, s.rxClassAtLocked(ep))',
T+'})',
'}',
'',
'// SetExtRisk — внешняя оценка риска [0,1] (точка подключения DPI-профайлера).',
'func (s *Stream) SetExtRisk(r float64) {',
T+'s.mu.Lock()',
T+'s.extRisk = r',
T+'s.mu.Unlock()',
'}',
'',
'// GeomClassesNow — текущие классы (TX мой, RX peer-а) для журнала/метрик.',
'func (s *Stream) GeomClassesNow() (int, int) {',
T+'s.mu.Lock()',
T+'defer s.mu.Unlock()',
T+'return s.txClass, s.rxClass',
'}',
'',
'func (s *Stream) txClassAtLocked(ep uint64) int {',
T+'if s.swOut != nil && s.swOut.committed && ep >= s.swOut.fromEpoch {',
T+T+'return s.swOut.class',
T+'}',
T+'return s.txClass',
'}',
'',
'func (s *Stream) rxClassAtLocked(ep uint64) int {',
T+'if s.swIn != nil && ep >= s.swIn.fromEpoch {',
T+T+'return s.swIn.class',
T+'}',
T+'return s.rxClass',
'}',
'',
'// autopilotLocked — шаг автопилота (под lock, до TickEpoch).',
'func (s *Stream) autopilotLocked() {',
T+'ep := EpochFor(s.now(), s.T)',
T+'if ep != s.curEpochS {',
T+T+'s.curEpochS = ep',
T+T+'s.sentTot, s.retxTot = 0, 0',
T+'}',
T+'// принятый от peer-а класс вступает в силу на его границе',
T+'if s.swIn != nil && ep >= s.swIn.fromEpoch {',
T+T+'s.rxClass = s.swIn.class',
T+T+'s.swIn = nil',
T+'}',
T+'risk := RiskFromMetrics(s.extRisk, s.retxRateLocked(), 1.0)',
T+'cls := s.stepper.Step(risk, ep)',
T+'if cls != s.txClass && s.swOut == nil {',
T+T+'s.swOut = &geomSw{class: cls, fromEpoch: ep + 2}',
T+T+'s.sendGeomCtlLocked(geomCtlReq, cls, ep+2, 0)',
T+'}',
T+'if s.swOut != nil && s.swOut.committed && ep >= s.swOut.fromEpoch {',
T+T+'s.txClass = s.swOut.class',
T+T+'s.swOut = nil',
T+'}',
T+'if s.swOut != nil && !s.swOut.committed && ep >= s.swOut.fromEpoch {',
T+T+'s.swOut.tries++',
T+T+'if s.swOut.tries > 5 {',
T+T+T+'s.geomAuto = false // peer не подтверждает — честно выключаемся',
T+T+T+'s.swOut = nil',
T+T+'} else {',
T+T+T+'s.swOut.fromEpoch = ep + 2',
T+T+T+'s.sendGeomCtlLocked(geomCtlReq, s.swOut.class, s.swOut.fromEpoch, 0)',
T+T+'}',
T+'}',
'}',
'',
'func (s *Stream) retxRateLocked() float64 {',
T+'if s.sentTot == 0 {',
T+T+'return 0',
T+'}',
T+'return float64(s.retxTot) / float64(s.sentTot)',
'}',
'',
'// deliverLocked — точка доставки in-order пейлоада: control перехватывается,',
'// приложению не отдаётся.',
'func (s *Stream) deliverLocked(payload []byte) {',
T+'if len(payload) >= 5 && payload[0] == 0xff && string(payload[1:5]) == "CDTG" {',
T+T+'if s.ctlHookForTest != nil && s.ctlHookForTest(payload) {',
T+T+T+'return // тестовая потеря control-кадра',
T+T+'}',
T+T+'s.handleGeomCtlLocked(payload)',
T+T+'return',
T+'}',
T+'s.appReady = append(s.appReady, payload)',
'}',
'',
'// sendGeomCtlLocked — control-кадр как обычное сообщение потока (seq +',
'// ретрансляции бесплатно).',
'func (s *Stream) sendGeomCtlLocked(kind byte, cls int, fromEpoch uint64, ok byte) {',
T+'p := make([]byte, 16)',
T+'copy(p, geomCtlMagic)',
T+'p[5] = kind',
T+'p[6] = byte(cls)',
T+'binary.BigEndian.PutUint64(p[7:15], fromEpoch)',
T+'p[15] = ok',
T+'s.emitLocked(p)',
'}',
'',
'func (s *Stream) handleGeomCtlLocked(p []byte) {',
T+'if len(p) < 16 {',
T+T+'return',
T+'}',
T+'kind := p[5]',
T+'cls := int(p[6])',
T+'fromEpoch := binary.BigEndian.Uint64(p[7:15])',
T+'switch kind {',
T+'case geomCtlReq:',
T+T+'ok := byte(0)',
T+T+'curEp := EpochFor(s.now(), s.T)',
T+T+'if s.geomAuto && s.swIn == nil && cls >= 0 && cls < GeomClasses &&',
T+T+T+'fromEpoch >= curEp+1 && fromEpoch <= curEp+16 {',
T+T+T+'s.swIn = &geomSw{class: cls, fromEpoch: fromEpoch}',
T+T+T+'ok = 1',
T+T+'}',
T+T+'s.sendGeomCtlLocked(geomCtlAck, cls, fromEpoch, ok)',
T+'case geomCtlAck:',
T+T+'if s.swOut != nil && s.swOut.class == cls && s.swOut.fromEpoch == fromEpoch {',
T+T+T+'if p[15] == 1 {',
T+T+T+T+'s.swOut.committed = true',
T+T+T+'} else {',
T+T+T+T+'// отклонено (поздно/занято): переоформить с запасом',
T+T+T+T+'s.swOut.fromEpoch = EpochFor(s.now(), s.T) + 2',
T+T+T+T+'s.sendGeomCtlLocked(geomCtlReq, s.swOut.class, s.swOut.fromEpoch, 0)',
T+T+T+'}',
T+T+'}',
T+'}',
'}',
'']) + nl
    return s
edit('internal/chaossync/cdtstream.go', f_stream)

# ============ cdt-socks: флаг -geomauto ============
def f_socks(s):
    s = rep(s, T+'maxGap := flag.Int("maxgap", 100, "макс межпакетный интервал, мкс")'+nl+T+'flag.Parse()',
            T+'maxGap := flag.Int("maxgap", 100, "макс межпакетный интервал, мкс")'+nl+
            T+'geomauto := flag.Bool("geomauto", false, "автопилот дисперсии CDT (класс по риску, переключение на границах эпох)")'+nl+
            T+'flag.Parse()')
    s = rep(s, T+T+'outCfg, inCfg = c2n, n2c'+nl+T+T+'listenBase, listenCount = *n2cPort, 1'+nl+T+'}',
            T+T+'outCfg, inCfg = c2n, n2c'+nl+T+T+'listenBase, listenCount = *n2cPort, 1'+nl+T+'}'+nl+
            T+'listenEff := listenCount'+nl+
            T+'if *geomauto && listenEff > 1 && listenEff < 512 {'+nl+
            T+T+'listenEff = 512 // конверт автопилота: слушаем максимальную ширину класса 3'+nl+
            T+'}')
    s = rep(s, T+'for p := listenBase; p < listenBase+listenCount; p++ {',
            T+'for p := listenBase; p < listenBase+listenEff; p++ {')
    s = rep(s, T+'st := chaossync.NewStream(master, outCfg, inCfg, *rotT, sendWire)',
            T+'st := chaossync.NewStream(master, outCfg, inCfg, *rotT, sendWire)'+nl+
            T+'if *geomauto {'+nl+
            T+T+'st.EnableGeomAutopilot(chaossync.NewClassStepper(0, 2), outCfg, inCfg)'+nl+
            T+T+'log.Printf("автопилот дисперсии включён (классы 0..%d, конверт приёма %d портов)", chaossync.GeomClasses-1, listenEff)'+nl+
            T+'}')
    return s
edit('cmd/cdt-socks/main.go', f_socks)

print('PATCH_CDT_GEOMAUTO2_DONE')
