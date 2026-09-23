import sys

p = 'internal/chaossync/schedule.go'
s = open(p, encoding='utf-8').read()

# 1) импорт sync (sha256 уже есть ради epochSeed)
assert '"crypto/sha256"' in s, 'sha256 import expected'
if '\t"sync"\n' not in s:
    s = s.replace('\t"crypto/sha256"\n', '\t"crypto/sha256"\n\t"sync"\n', 1)

# 2) кэш перед DeriveField + оборачивание тела в deriveFieldUncached
old_sig = 'func DeriveField(master []byte, epoch uint64) *FieldParams {'
assert old_sig in s, 'DeriveField sig'
s = s.replace(old_sig, 'func deriveFieldUncached(master []byte, epoch uint64) *FieldParams {', 1)

cache = '''// fieldCache — кэш выведенных полей по (master, epoch). DeriveField чист и
// детерминирован, но дорог (self-validating зонд сходимости). Без кэша hunt
// КАЖДОГО шумового пира гонял зонд на 3 эпохи -> под фоновым шумом интернета
// (публичный UDP-порт) это истощало пер-тиковый бюджет CPU и реальный пир
// голодал (деградация ноды по аптайму, этап Э5). FieldParams после вывода
// иммутабельны, поэтому из кэша отдаём копию.
const fieldCacheCap = 1024

type fieldCacheKey struct {
\tmaster [32]byte // sha256(master), сам секрет в ключе не держим
\tepoch  uint64
}

var (
\tfieldCacheMu sync.Mutex
\tfieldCache   = make(map[fieldCacheKey]*FieldParams)
)

// DeriveField — кэшированная обёртка над deriveFieldUncached.
func DeriveField(master []byte, epoch uint64) *FieldParams {
\tkey := fieldCacheKey{master: sha256.Sum256(master), epoch: epoch}
\tfieldCacheMu.Lock()
\tif p, ok := fieldCache[key]; ok {
\t\tfieldCacheMu.Unlock()
\t\tcp := *p
\t\treturn &cp
\t}
\tfieldCacheMu.Unlock()

\tp := deriveFieldUncached(master, epoch)

\tfieldCacheMu.Lock()
\tif len(fieldCache) >= fieldCacheCap {
\t\tfieldCache = make(map[fieldCacheKey]*FieldParams)
\t}
\tfieldCache[key] = p
\tfieldCacheMu.Unlock()
\tcp := *p
\treturn &cp
}
'''
s = s.replace('func deriveFieldUncached(master []byte, epoch uint64) *FieldParams {',
              cache + '\nfunc deriveFieldUncached(master []byte, epoch uint64) *FieldParams {', 1)

open(p, 'w', encoding='utf-8').write(s)
print('DeriveField cache installed')
