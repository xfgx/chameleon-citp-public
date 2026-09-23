import sys

p = 'internal/chaossync/server.go'
s = open(p, encoding='utf-8').read()

# 1) импорт sync
old_imp = 'import (\n\t"sort"\n\t"time"\n)'
assert old_imp in s, 'import anchor'
s = s.replace(old_imp, 'import (\n\t"sort"\n\t"sync"\n\t"time"\n)', 1)

# 2) поле мьютекса в struct
old_struct = 'type ServerMux struct {\n\tcfg   Config\n\ttx    *Endpoint // s2c-осциллятор (RX-часть не используется)\n\tpeers map[string]*peerState\n}'
assert old_struct in s, 'struct anchor'
s = s.replace(old_struct,
    'type ServerMux struct {\n\tcfg   Config\n\ttx    *Endpoint // s2c-осциллятор (RX-часть не используется)\n\tpeers map[string]*peerState\n\tmu    sync.Mutex // единая защита карты peers: read-цикл, тикер и http-метрики — 3 горутины\n}', 1)

# 3) блокируем все публичные методы, трогающие peers/tx.
#    evictOne НЕ блокируем — вызывается из Handle/Enqueue под уже взятым замком.
methods = [
    'func (m *ServerMux) Handle(dat []byte, from string, now time.Time) bool {',
    'func (m *ServerMux) Enqueue(dat []byte, from string, now time.Time) {',
    'func (m *ServerMux) TickPeers(now time.Time) []string {',
    'func (m *ServerMux) Tick(now time.Time) ([]string, []byte) {',
    'func (m *ServerMux) Cleanup(now time.Time) {',
    'func (m *ServerMux) PeerCount() (int, int) {',
    'func (m *ServerMux) PeerSnapshot(from string) *Snapshot {',
    'func (m *ServerMux) PeerFrames(from string) []ParsedFrame {',
    'func (m *ServerMux) PushFrame(payload []byte) error {',
]
for sig in methods:
    assert sig in s, 'method anchor: ' + sig[:50]
    s = s.replace(sig, sig + '\n\tm.mu.Lock()\n\tdefer m.mu.Unlock()', 1)

open(p, 'w', encoding='utf-8').write(s)
print('ServerMux mutex installed on', len(methods), 'methods')
