#!/usr/bin/env bash
# antidpi-verify.sh — регрессионная батарея анти-DPI исследований (2026-09-09).
#
# Что проверяет:
#   1. sim8.py компилируется (py_compile).
#   2. Свип sim8 EMB_CADENCE=3..6 бит-в-бит совпадает с baseline JSON
#      (research/antidpi-sim8/baseline/). Любое расхождение = FAIL.
#   3. protocol/reference_parser.py selftest → valid=True.
#   4. internal/chaossync/testdata/ks_r1_fields.json: 32 фикстуры, нужные ключи.
#   5. Статические инварианты: ksWindow=8192 в ks.go; HMAC-SHA256 в cst.go;
#      задокументированный wire-формат nonce‖ct (WARN, не FAIL).
#   6. Инвентарь тестов: chaossync>=58, chameleon>=138 Test-функций
#      (рост разрешён, падение = FAIL).
#   7. Если на ноде есть Go (go в PATH или /usr/local/go/bin/go): сборка
#      chaossync/ks-vpn + TestKsGoldenVector (гейт бит-идентичности ядра KS).
#      Нет Go — SKIP (гейт покрывает CI workflow antidpi-verify.yml).
#
# Выход: 0 при полном OK, 1 при любом FAIL. Лог — stdout с таймстемпами.
# Запуск в фоне по образцу astra-процессов:
#   nohup bash scripts/antidpi-verify.sh > /files/astra/antidpi-verify.log 2>&1 &
set -u
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
SIM="$ROOT/research/antidpi-sim8"
OUT="$SIM/out-$(date +%Y%m%dT%H%M%S)"
FAIL=0
say() { echo "[$(date -Is)] $*"; }
mkdir -p "$OUT"

say "=== ANTIDPI-VERIFY START root=$ROOT out=$OUT ==="

say "STEP1 py_compile sim8.py"
if python3 -m py_compile "$SIM/sim8.py"; then say "OK py_compile"; else say "FAIL py_compile"; FAIL=1; fi

say "STEP2 sim8 sweep cadence 3..6"
( cd "$OUT" && for c in 3 4 5 6; do EMB_CADENCE=$c python3 "$SIM/sim8.py" > "run-emb$c.log" 2>&1; echo "emb$c exit=$?"; done )
python3 - "$SIM" "$OUT" <<'PY'
import json, sys, pathlib
sim, out = pathlib.Path(sys.argv[1]), pathlib.Path(sys.argv[2])
ok = True
for c in (3, 4, 5, 6):
    base = sim / "baseline" / f"sim8-result-emb{c}.json"
    new = out / f"sim8-result-emb{c}.json"
    if not new.exists():
        print(f"FAIL emb{c}: no output file"); ok = False; continue
    a = json.loads(base.read_text()); b = json.loads(new.read_text())
    same = (a == b)
    print(f"emb{c}:", "OK identical" if same else "FAIL differs")
    ok = ok and same
sys.exit(0 if ok else 1)
PY
if [ $? -eq 0 ]; then say "OK sim8 sweep identical to baseline"; else say "FAIL sim8 sweep"; FAIL=1; fi

say "STEP3 reference_parser selftest"
PARSER_OUT=$(python3 "$ROOT/protocol/reference_parser.py" 2>&1)
if echo "$PARSER_OUT" | grep -q 'valid=True'; then say "OK parser: $PARSER_OUT"; else say "FAIL parser: $PARSER_OUT"; FAIL=1; fi

say "STEP4 ks_r1_fields.json fixtures"
python3 - "$ROOT" <<'PY'
import json, sys
d = json.load(open(sys.argv[1] + "/internal/chaossync/testdata/ks_r1_fields.json"))
need = {"field", "mu_raw", "eps1_raw", "eps2_raw", "initial_raw"}
ok = isinstance(d, list) and len(d) == 32 and all(need <= set(r) for r in d)
print("OK 32 fixtures, keys present" if ok else f"FAIL fixtures: type={type(d).__name__} len={len(d) if isinstance(d, list) else '-'}")
sys.exit(0 if ok else 1)
PY
if [ $? -eq 0 ]; then say "OK fixtures"; else say "FAIL fixtures"; FAIL=1; fi

say "STEP5 static invariants"
if grep -q 'ksWindow = 8192' "$ROOT/internal/chaossync/ks.go"; then say "OK ksWindow=8192 (ks.go)"; else say "FAIL ksWindow"; FAIL=1; fi
if grep -q 'hmac.New(sha256.New' "$ROOT/internal/chaossync/cst.go"; then say "OK cst FrameTag HMAC-SHA256 (cst.go)"; else say "FAIL cst hmac"; FAIL=1; fi
if grep -q 'nonce‖ct' "$ROOT/internal/chaossync/ks.go"; then say "OK wire nonce‖ct documented (ks.go)"; else say "WARN nonce‖ct doc line changed"; fi

say "STEP6 test inventory"
C1=$(grep -h '^func Test' "$ROOT"/internal/chaossync/*_test.go 2>/dev/null | wc -l)
C2=$(grep -h '^func Test' "$ROOT"/internal/chameleon/*_test.go 2>/dev/null | wc -l)
C3=$(grep -rh '^func Test' "$ROOT"/research/ "$ROOT"/experiments/ 2>/dev/null | wc -l)
say "tests: chaossync=$C1 chameleon=$C2 research+experiments=$C3 (baseline 58/138/35)"
if [ "$C1" -ge 58 ] && [ "$C2" -ge 138 ]; then say "OK test inventory"; else say "FAIL test count regression"; FAIL=1; fi

say "STEP7 go gates (golden vector)"
GO="$(command -v go 2>/dev/null || true)"
[ -z "$GO" ] && [ -x /usr/local/go/bin/go ] && GO=/usr/local/go/bin/go
if [ -n "$GO" ]; then
  export GOCACHE=/tmp/gocache GOPATH=/tmp/gopath CGO_ENABLED=0 GOPROXY="https://proxy.golang.org,direct"
  GO_OUT=$( cd "$ROOT" && "$GO" test ./internal/chaossync/ -count=1 -run "TestKsGoldenVector" 2>&1 )
  if echo "$GO_OUT" | grep -q '^ok'; then say "OK go: TestKsGoldenVector PASS ($("$GO" version))"; else say "FAIL go golden"; echo "$GO_OUT" | tail -10; FAIL=1; fi
else
  say "SKIP: go toolchain absent on node (covered by CI antidpi-verify.yml)"
fi

say "=== ANTIDPI-VERIFY DONE fail=$FAIL out=$OUT ==="
exit $FAIL
