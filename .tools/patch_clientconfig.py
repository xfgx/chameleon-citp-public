import sys

p = 'cmd/chaossync-client/main.go'
s = open(p, encoding='utf-8').read()

# 1) импорт strings
old_imp = '\t"os"\n\t"time"'
assert old_imp in s, 'import anchor'
s = s.replace(old_imp, '\t"os"\n\t"strings"\n\t"time"', 1)

# 2) вызов applyConfigFile перед flag.Parse()
old_parse = '\tflag.Parse()\n\n\tif *selftest {'
assert old_parse in s, 'parse anchor'
s = s.replace(old_parse,
    '\t// -config файл (key=value / key value), командная строка переопределяет.\n'
    '\tif cp := preScanConfigPath(); cp != "" {\n'
    '\t\tapplyConfigFile(cp)\n'
    '\t}\n'
    '\tflag.Parse()\n\n\tif *selftest {', 1)

# 3) helpers в конец файла (через список строк + chr(10), без '\n' в литералах)
nl = chr(10)
T = chr(9)
helpers = [
    '',
    '// preScanConfigPath ищет -config/--config в argv ДО flag.Parse.',
    'func preScanConfigPath() string {',
    T + 'for i, a := range os.Args {',
    T + T + 'if (a == "-config" || a == "--config") && i+1 < len(os.Args) {',
    T + T + T + 'return os.Args[i+1]',
    T + T + '}',
    T + T + 'if v, ok := strings.CutPrefix(a, "-config="); ok {',
    T + T + T + 'return v',
    T + T + '}',
    T + T + 'if v, ok := strings.CutPrefix(a, "--config="); ok {',
    T + T + T + 'return v',
    T + T + '}',
    T + '}',
    T + 'return ""',
    '}',
    '',
    '// applyConfigFile применяет key=value / "key value" из файла до flag.Parse.',
    '// Порядок приоритета: дефолт < конфиг < командная строка. Fail-closed.',
    'func applyConfigFile(path string) {',
    T + 'raw, err := os.ReadFile(path)',
    T + 'if err != nil {',
    T + T + 'log.Fatalf("fail-closed: конфиг %s: %v", path, err)',
    T + '}',
    T + 'for ln, line := range strings.Split(string(raw), "\\n") {',
    T + T + 'line = strings.TrimSpace(line)',
    T + T + 'if line == "" || strings.HasPrefix(line, "#") {',
    T + T + T + 'continue',
    T + T + '}',
    T + T + 'var k, v string',
    T + T + 'if i := strings.IndexByte(line, \'=\'); i >= 0 {',
    T + T + T + 'k, v = strings.TrimSpace(line[:i]), strings.TrimSpace(line[i+1:])',
    T + T + '} else {',
    T + T + T + 'f := strings.Fields(line)',
    T + T + T + 'if len(f) != 2 {',
    T + T + T + T + 'log.Fatalf("fail-closed: конфиг %s:%d: неверная строка %q", path, ln+1, line)',
    T + T + T + '}',
    T + T + T + 'k, v = f[0], f[1]',
    T + T + '}',
    T + T + 'if err := flag.Set(k, v); err != nil {',
    T + T + T + 'log.Fatalf("fail-closed: конфиг %s:%d: %v", path, ln+1, err)',
    T + T + '}',
    T + '}',
    '}',
]
s = s + nl.join(helpers) + nl
open(p, 'w', encoding='utf-8').write(s)
print('client: -config support added')
