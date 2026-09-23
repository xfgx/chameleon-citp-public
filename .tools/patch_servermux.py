p = 'internal/chaossync/server.go'
s = open(p, encoding='utf-8').read()
T = chr(9)
nl = chr(10)

anchor = T + 'return ps.proven' + nl + '}'
assert s.count(anchor) == 1, 'handle anchor'

new_methods = anchor + nl + nl + '''// Enqueue — приём c2s-датаграммы в джиттер-буфер наблюдателя (Э5): БЕЗ
// немедленной обработки. Обработка — в TickPeers по локальным часам ноды, что
// отделяет часы сэмплов от сетевого джиттера. Потеря = underrun очереди.
func (m *ServerMux) Enqueue(dat []byte, from string, now time.Time) {
\tps, ok := m.peers[from]
\tif !ok {
\t\tif len(m.peers) >= maxPeers {
\t\t\tif !m.evictOne(now) {
\t\t\t\treturn
\t\t\t}
\t\t}
\t\tps = &peerState{rx: NewEndpoint(m.cfg, "s2c")}
\t\tm.peers[from] = ps
\t}
\tps.lastSeen = now
\tps.rx.EnqueueDatagram(dat, now)
}

// TickPeers — обработать джиттер-очереди всех наблюдателей по локальным часам.
// Возвращает адреса свежеДОКАЗАННЫХ пиров (для логов). Вызывать с периодом
// DatagramInterval().
func (m *ServerMux) TickPeers(now time.Time) []string {
\tvar newly []string
\tfor a, ps := range m.peers {
\t\tps.rx.TickRx(now)
\t\tif !ps.proven && ps.rx.Locked() {
\t\t\tps.proven = true
\t\t\tps.provenAt = now
\t\t\tnewly = append(newly, a)
\t\t}
\t}
\tif len(newly) > 0 {
\t\tsort.Strings(newly)
\t}
\treturn newly
}'''
s = s.replace(anchor, new_methods, 1)
open(p, 'w', encoding='utf-8').write(s)
print('servermux buffered path installed OK')
