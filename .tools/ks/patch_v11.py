# patch_v11.py — v11 (fail-closed v6-провод + петлестоп v6).
#
# Урок полевого прогона 14:22 2026-09-04: при туннельном ::/0 и НЕзапиненном
# пуле провода датаграммы v6-провода уходили в наш же ks0, читались обратно
# из TUN и пересылались снова — петля усиления (tunRd 23k за 3с, ~100k пак/с,
# просадка Wintun-адаптера). Правки:
#   1. main.go  — провод включается только при (нативный источник + pin OK).
#   2. main.go  — петлестоп получил v6-плечо (пакеты к пулу провода не входят
#                 в туннель НИКОГДА, даже при выключенном проводе).
#   3. v6rot.go — PinWirePool возвращает error (вызывающий обязан решать).
#   4. v6rotmgr_windows.go — exit 3 печатает кандидатов ::/0 (честный дамп).
#   5. wirev6_test.go — тест петлестопа (v4 и v6 плечи).
import io
import sys

fails = []


def rd(p):
    return io.open(p, encoding="utf-8").read()


def wr(p, s):
    io.open(p, "w", encoding="utf-8", newline="").write(s)


# ---------- 1. main.go: fail-closed gating ----------
P = "cmd/ks-vpn/main.go"
s = rd(P)

A = "\t// \u041a\u043b\u0438\u0435\u043d\u0442\u0441\u043a\u0438\u0439 v6-\u043f\u0440\u043e\u0432\u043e\u0434 \u043a \u043d\u043e\u0434\u0435 \u043f\u043e \u0441\u043b\u0443\u0447\u0430\u0439\u043d\u044b\u043c \u0430\u0434\u0440\u0435\u0441\u0430\u043c \u0435\u0451 routed-\u043f\u0443\u043b\u0430.\n"
B = "\tif len(cleanups) > 0 {"
i, j = s.find(A), s.find(B)
if i < 0 or j < 0 or j < i:
    fails.append("GATE_ANCHOR")
else:
    gate = "\n".join([
        "\t// \u041a\u043b\u0438\u0435\u043d\u0442\u0441\u043a\u0438\u0439 v6-\u041f\u0420\u041e\u0412\u041e\u0414 \u043a \u043d\u043e\u0434\u0435: \u0441\u043b\u0443\u0447\u0430\u0439\u043d\u044b\u0439 \u0438\u0441\u0442\u043e\u0447\u043d\u0438\u043a -> \u0441\u043b\u0443\u0447\u0430\u0439\u043d\u044b\u0439 \u0430\u0434\u0440\u0435\u0441 \u0435\u0451 \u043f\u0443\u043b\u0430.",
        "\t//",
        "\t// FAIL-CLOSED (\u0443\u0440\u043e\u043a \u043f\u043e\u043b\u0435\u0432\u043e\u0433\u043e \u043f\u0440\u043e\u0433\u043e\u043d\u0430 14:22 2026-09-04): \u043f\u0440\u043e\u0432\u043e\u0434 \u0432\u043a\u043b\u044e\u0447\u0430\u0435\u043c",
        "\t// \u0422\u041e\u041b\u042c\u041a\u041e \u043a\u043e\u0433\u0434\u0430 (1) \u0443 \u043c\u0430\u0448\u0438\u043d\u044b \u0435\u0441\u0442\u044c \u043d\u0430\u0442\u0438\u0432\u043d\u044b\u0439 \u0433\u043b\u043e\u0431\u0430\u043b\u044c\u043d\u044b\u0439 v6-\u0430\u0434\u0440\u0435\u0441 \u0434\u043b\u044f",
        "\t// \u0438\u0441\u0442\u043e\u0447\u043d\u0438\u043a\u0430 \u0438 (2) \u043f\u0443\u043b \u043f\u0440\u043e\u0432\u043e\u0434\u0430 \u0434\u043e\u043a\u0430\u0437\u0430\u043d\u043d\u043e \u0443\u0432\u0435\u0434\u0451\u043d \u041c\u0418\u041c\u041e \u0442\u0443\u043d\u043d\u0435\u043b\u044f. \u0418\u043d\u0430\u0447\u0435 \u0435\u0433\u043e",
        "\t// \u0434\u0430\u0442\u0430\u0433\u0440\u0430\u043c\u043c\u044b \u0443\u0445\u043e\u0434\u044f\u0442 \u0432 \u043d\u0430\u0448 \u0436\u0435 ks0 (\u0442\u0443\u043d\u043d\u0435\u043b\u044c\u043d\u044b\u0439 ::/0), \u0447\u0438\u0442\u0430\u044e\u0442\u0441\u044f \u043e\u0431\u0440\u0430\u0442\u043d\u043e",
        "\t// \u0438\u0437 TUN \u0438 \u043f\u0435\u0440\u0435\u0441\u044b\u043b\u0430\u044e\u0442\u0441\u044f \u0441\u043d\u043e\u0432\u0430 \u2014 \u043f\u0435\u0442\u043b\u044f \u0443\u0441\u0438\u043b\u0435\u043d\u0438\u044f (tunRd 23k \u0437\u0430 3\u0441, ~100k",
        "\t// \u043f\u0430\u043a/\u0441, \u043f\u0440\u043e\u0441\u0430\u0434\u043a\u0430 Wintun-\u0430\u0434\u0430\u043f\u0442\u0435\u0440\u0430). \u0427\u0435\u0441\u0442\u043d\u044b\u0439 v4-\u043f\u0440\u043e\u0432\u043e\u0434 \u043b\u0443\u0447\u0448\u0435 \u0432\u0437\u0440\u044b\u0432\u0430.",
        "\tvar w6 *wireV6",
        "\tvar wirePool6 *net.IPNet",
        "\tif *peerPool6 != \"\" {",
        "\t\tif *peerHost == \"\" {",
        "\t\t\tlog.Fatal(\"fail-closed: -peerpool6 \u2014 \u043a\u043b\u0438\u0435\u043d\u0442\u0441\u043a\u0430\u044f \u0440\u043e\u043b\u044c (\u043d\u0443\u0436\u0435\u043d -peerhost \u0434\u043b\u044f v4-\u043e\u0442\u043a\u0430\u0442\u0430)\")",
        "\t\t}",
        "\t\t_, wp, perr := net.ParseCIDR(*peerPool6)",
        "\t\tif perr != nil {",
        "\t\t\tlog.Fatalf(\"fail-closed: -peerpool6 %q: %v\", *peerPool6, perr)",
        "\t\t}",
        "\t\t// \u043f\u0435\u0442\u043b\u0435\u0441\u0442\u043e\u043f\u0443 \u043f\u0443\u043b \u043d\u0443\u0436\u0435\u043d \u0434\u0430\u0436\u0435 \u043f\u0440\u0438 \u0412\u042b\u041a\u041b\u042e\u0427\u0415\u041d\u041d\u041e\u041c \u043f\u0440\u043e\u0432\u043e\u0434\u0435: \u0442\u0443\u043d\u043d\u0435\u043b\u044c\u043d\u044b\u0439",
        "\t\t// ::/0 \u043f\u043e\u0434\u043d\u0438\u043c\u0430\u0435\u0442 \u0440\u043e\u0442\u0430\u0446\u0438\u044f, \u0430 \u043f\u0430\u043a\u0435\u0442\u044b \u043a \u043f\u0443\u043b\u0443 \u0432 \u0442\u0443\u043d\u043d\u0435\u043b\u044c \u0432\u0445\u043e\u0434\u0438\u0442\u044c \u043d\u0435 \u0434\u043e\u043b\u0436\u043d\u044b.",
        "\t\twirePool6 = wp",
        "",
        "\t\t// \u043f\u0443\u043b \u0421\u041b\u0423\u0427\u0410\u0419\u041d\u042b\u0425 \u0418\u0421\u0425\u041e\u0414\u041d\u042b\u0425 \u0430\u0434\u0440\u0435\u0441\u043e\u0432 (wiresrc6.go).",
        "\t\tvar src6 *srcPool6",
        "\t\tsrcReady := *wire6Src == \"\"",
        "\t\tif *wire6Src != \"\" {",
        "\t\t\tif sp, err := newSrcPool6(*wire6Src, ifname, *wire6SrcN, *wire6Rot, datch); err != nil {",
        "\t\t\t\tlog.Printf(\"wire6src: %v\", err)",
        "\t\t\t} else {",
        "\t\t\t\tsrc6 = sp",
        "\t\t\t\tsrcReady = true",
        "\t\t\t\tcleanups = append(cleanups, sp.close)",
        "\t\t\t}",
        "\t\t}",
        "\t\tpinned := true",
        "\t\tif srcReady && rotStarted {",
        "\t\t\tpinned = rot.PinWirePool(wirePool6) == nil",
        "\t\t}",
        "\t\tswitch {",
        "\t\tcase !srcReady:",
        "\t\t\tlog.Printf(\"wire6: FAIL-CLOSED: \u043d\u0430\u0442\u0438\u0432\u043d\u043e\u0433\u043e \u0433\u043b\u043e\u0431\u0430\u043b\u044c\u043d\u043e\u0433\u043e IPv6 \u0443 \u044d\u0442\u043e\u0439 \u043c\u0430\u0448\u0438\u043d\u044b \u043d\u0435\u0442 (\u0434\u0430\u043c\u043f wire6src \u0432\u044b\u0448\u0435) \u2014 v6-\u043f\u0440\u043e\u0432\u043e\u0434 \u041d\u0415 \u0432\u043a\u043b\u044e\u0447\u0451\u043d: \u0441 \u0430\u0434\u0440\u0435\u0441\u0430 \u0442\u0443\u043d\u043d\u0435\u043b\u044f \u0435\u0433\u043e \u0434\u0430\u0442\u0430\u0433\u0440\u0430\u043c\u043c\u044b \u0443\u0448\u043b\u0438 \u0431\u044b \u0432 \u0441\u0430\u043c \u0442\u0443\u043d\u043d\u0435\u043b\u044c \u0438 \u043f\u043e\u0440\u043e\u0434\u0438\u043b\u0438 \u043f\u0435\u0442\u043b\u044e. \u0420\u0430\u0431\u043e\u0442\u0430\u0435\u043c \u043f\u043e v4-\u043f\u0440\u043e\u0432\u043e\u0434\u0443 %s:%d; \u0447\u0442\u043e \u0434\u0435\u043b\u0430\u0442\u044c \u2014 \u0432 README.txt\", *peerHost, *peerPort)",
        "\t\tcase !pinned:",
        "\t\t\tlog.Printf(\"wire6: FAIL-CLOSED: \u043f\u0443\u043b %s \u043d\u0435 \u0443\u0432\u0435\u0434\u0451\u043d \u043c\u0438\u043c\u043e \u0442\u0443\u043d\u043d\u0435\u043b\u044f (\u0441\u0442\u0440\u043e\u043a\u0430 v6rot \u0432\u044b\u0448\u0435) \u2014 v6-\u043f\u0440\u043e\u0432\u043e\u0434 \u041d\u0415 \u0432\u043a\u043b\u044e\u0447\u0451\u043d, \u0438\u043d\u0430\u0447\u0435 \u043f\u0435\u0442\u043b\u044f \u0447\u0435\u0440\u0435\u0437 ks0. \u0420\u0430\u0431\u043e\u0442\u0430\u0435\u043c \u043f\u043e v4-\u043f\u0440\u043e\u0432\u043e\u0434\u0443 %s:%d\", wirePool6, *peerHost, *peerPort)",
        "\t\tdefault:",
        "\t\t\tif w, err := newWireV6(*peerPool6, *peerPort, *wire6Rot, datch, src6); err != nil {",
        "\t\t\t\tlog.Printf(\"wire6: %v \u2014 v6-\u043f\u0440\u043e\u0432\u043e\u0434 \u0432\u044b\u043a\u043b\u044e\u0447\u0435\u043d, \u043e\u0441\u0442\u0430\u0451\u043c\u0441\u044f \u043d\u0430 v4 (%s:%d)\", err, *peerHost, *peerPort)",
        "\t\t\t} else {",
        "\t\t\t\tw6 = w",
        "\t\t\t\tcleanups = append(cleanups, w.close)",
        "\t\t\t}",
        "\t\t}",
        "\t}",
        "",
        "",
    ])
    s = s[:i] + gate + s[j:]

# ---------- 2. main.go: \u043f\u0435\u0442\u043b\u0435\u0441\u0442\u043e\u043f v6 ----------
old_guard = "\t\tif peerIP4 != nil && n >= 20 && buf[0]>>4 == 4 && net.IP(buf[16:20]).Equal(peerIP4) {"
new_guard = "\t\tif loopGuardDrop(buf[:n], peerIP4, wirePool6) {"
if old_guard not in s:
    fails.append("GUARD_ANCHOR")
else:
    s = s.replace(old_guard, new_guard, 1)

helper = "\n".join([
    "",
    "// loopGuardDrop \u2014 \u043f\u0435\u0442\u043b\u0435\u0441\u0442\u043e\u043f: \u043f\u0430\u043a\u0435\u0442\u044b, \u043a\u043e\u0442\u043e\u0440\u044b\u0435 \u0443\u0448\u043b\u0438 \u0431\u044b \u0432 \u043d\u0430\u0448 \u0436\u0435 \u0442\u0443\u043d\u043d\u0435\u043b\u044c \u0438",
    "// \u0432\u0435\u0440\u043d\u0443\u043b\u0438\u0441\u044c \u043e\u0431\u0440\u0430\u0442\u043d\u043e, \u0432 \u0442\u0443\u043d\u043d\u0435\u043b\u044c \u041d\u0415 \u0432\u0445\u043e\u0434\u044f\u0442.",
    "//",
    "//  1. v4: \u043f\u0430\u043a\u0435\u0442 \u043a \u043f\u0440\u043e\u0432\u043e\u0434\u043d\u043e\u043c\u0443 IP \u043d\u043e\u0434\u044b (\u0432\u0437\u0440\u044b\u0432 \u0441\u0447\u0451\u0442\u0447\u0438\u043a\u043e\u0432 2026-09-01).",
    "//  2. v6: \u043f\u0430\u043a\u0435\u0442 \u043a \u043f\u0443\u043b\u0443 v6-\u041f\u0420\u041e\u0412\u041e\u0414\u0410 \u043d\u043e\u0434\u044b. \u0411\u0435\u0437 \u044d\u0442\u043e\u0433\u043e \u043f\u0440\u0438 \u0442\u0443\u043d\u043d\u0435\u043b\u044c\u043d\u043e\u043c ::/0",
    "//     \u0438 \u043d\u0435\u0437\u0430\u043f\u0438\u043d\u0435\u043d\u043d\u043e\u043c \u043f\u0443\u043b\u0435 \u0434\u0430\u0442\u0430\u0433\u0440\u0430\u043c\u043c\u044b \u043f\u0440\u043e\u0432\u043e\u0434\u0430 \u0447\u0438\u0442\u0430\u044e\u0442\u0441\u044f \u043e\u0431\u0440\u0430\u0442\u043d\u043e \u0438\u0437 TUN \u0438",
    "//     \u043f\u0435\u0440\u0435\u0441\u044b\u043b\u0430\u044e\u0442\u0441\u044f \u0441\u043d\u043e\u0432\u0430 \u2014 \u043f\u0435\u0442\u043b\u044f \u0443\u0441\u0438\u043b\u0435\u043d\u0438\u044f (\u043f\u043e\u043b\u0435 14:22 2026-09-04:",
    "//     tunRd 23k \u0437\u0430 3\u0441, ~100k \u043f\u0430\u043a/\u0441, \u043f\u0440\u043e\u0441\u0430\u0434\u043a\u0430 Wintun-\u0430\u0434\u0430\u043f\u0442\u0435\u0440\u0430).",
    "func loopGuardDrop(p []byte, peerIP4 net.IP, wirePool6 *net.IPNet) bool {",
    "\tif len(p) < 20 {",
    "\t\treturn false",
    "\t}",
    "\tswitch p[0] >> 4 {",
    "\tcase 4:",
    "\t\treturn peerIP4 != nil && net.IP(p[16:20]).Equal(peerIP4)",
    "\tcase 6:",
    "\t\treturn wirePool6 != nil && len(p) >= 40 && wirePool6.Contains(net.IP(p[24:40]))",
    "\t}",
    "\treturn false",
    "}",
    "",
])
if "func loopGuardDrop(" in s:
    fails.append("HELPER_DUP")
else:
    s = s.rstrip("\n") + "\n" + helper
wr(P, s)

# ---------- 3. v6rot.go: PinWirePool -> error ----------
P = "cmd/ks-vpn/v6rot.go"
s = rd(P)
sig = "func (r *v6Rotator) PinWirePool(prefix *net.IPNet) {"
i = s.find(sig)
if i < 0:
    fails.append("ROT_SIG")
else:
    j = s.find("\n}\n", i)
    if j < 0:
        fails.append("ROT_END")
    else:
        new = "\n".join([
            "func (r *v6Rotator) PinWirePool(prefix *net.IPNet) error {",
            "\tp, ok := r.mgr.(v6WirePinner)",
            "\tif !ok {",
            "\t\treturn nil // \u043f\u043b\u0430\u0442\u0444\u043e\u0440\u043c\u0430 \u043d\u0435 \u0443\u043c\u0435\u0435\u0442 \u2014 \u0440\u0435\u0448\u0430\u0435\u0442 \u0432\u044b\u0437\u044b\u0432\u0430\u044e\u0449\u0438\u0439",
            "\t}",
            "\tif err := p.PinWirePool(prefix); err != nil {",
            "\t\tlog.Printf(\"v6rot: \u043f\u0443\u043b \u043f\u0440\u043e\u0432\u043e\u0434\u0430 %s \u041d\u0415 \u0443\u0432\u0435\u0434\u0451\u043d \u043c\u0438\u043c\u043e \u0442\u0443\u043d\u043d\u0435\u043b\u044f: %v\", prefix, err)",
            "\t\treturn err",
            "\t}",
            "\treturn nil",
            "}",
        ])
        s = s[:i] + new + s[j + 2:]
        wr(P, s)

# ---------- 4. v6rotmgr_windows.go: \u0434\u0430\u043c\u043f \u043a\u0430\u043d\u0434\u0438\u0434\u0430\u0442\u043e\u0432 \u043d\u0430 exit 3 ----------
P = "cmd/ks-vpn/v6rotmgr_windows.go"
s = rd(P)
old = "if(-not $n){ exit 3 }"
new = ("if(-not $n){ $d=@(); Get-NetRoute -DestinationPrefix '::/0' -PolicyStore ActiveStore "
       "-ErrorAction SilentlyContinue | ForEach-Object { $d += \"cand ::/0 if=$($_.InterfaceAlias) "
       "nh=$($_.NextHop) metric=$($_.RouteMetric)\" }; ($d -join [char]10); exit 3 }")
if old not in s:
    fails.append("WINPIN_ANCHOR")
else:
    wr(P, s.replace(old, new, 1))

# ---------- 5. wirev6_test.go: \u0442\u0435\u0441\u0442 \u043f\u0435\u0442\u043b\u0435\u0441\u0442\u043e\u043f\u0430 ----------
P = "cmd/ks-vpn/wirev6_test.go"
s = rd(P)
if "TestLoopGuardDrop" in s:
    fails.append("TEST_DUP")
else:
    test = "\n".join([
        "",
        "// TestLoopGuardDrop \u2014 \u043f\u0435\u0442\u043b\u0435\u0441\u0442\u043e\u043f \u043e\u0431\u0430 \u043f\u043b\u0435\u0447\u0430: \u043f\u0430\u043a\u0435\u0442\u044b \u043a \u043f\u0440\u043e\u0432\u043e\u0434\u043d\u043e\u043c\u0443 IP \u043d\u043e\u0434\u044b",
        "// (v4) \u0438 \u043a \u043f\u0443\u043b\u0443 v6-\u043f\u0440\u043e\u0432\u043e\u0434\u0430 (v6) \u0432 \u0442\u0443\u043d\u043d\u0435\u043b\u044c \u043d\u0435 \u0432\u0445\u043e\u0434\u044f\u0442; \u043f\u0440\u043e\u0447\u0438\u0435 \u2014 \u0432\u0445\u043e\u0434\u044f\u0442.",
        "func TestLoopGuardDrop(t *testing.T) {",
        "\tpeer := net.ParseIP(\"192.0.2.10\").To4()",
        "\t_, pool, err := net.ParseCIDR(\"2001:db8:2::/48\")",
        "\tif err != nil {",
        "\t\tt.Fatal(err)",
        "\t}",
        "\tv4 := func(dst string) []byte {",
        "\t\tp := make([]byte, 20)",
        "\t\tp[0] = 0x45",
        "\t\tcopy(p[16:20], net.ParseIP(dst).To4())",
        "\t\treturn p",
        "\t}",
        "\tv6 := func(dst string) []byte {",
        "\t\tp := make([]byte, 40)",
        "\t\tp[0] = 0x60",
        "\t\tcopy(p[24:40], net.ParseIP(dst).To16())",
        "\t\treturn p",
        "\t}",
        "\tif !loopGuardDrop(v4(\"192.0.2.10\"), peer, pool) {",
        "\t\tt.Fatal(\"v4-\u043f\u0430\u043a\u0435\u0442 \u043a \u043f\u0440\u043e\u0432\u043e\u0434\u043d\u043e\u043c\u0443 IP \u043d\u043e\u0434\u044b \u043e\u0431\u044f\u0437\u0430\u043d \u043e\u0442\u0431\u0440\u0430\u0441\u044b\u0432\u0430\u0442\u044c\u0441\u044f\")",
        "\t}",
        "\tif loopGuardDrop(v4(\"1.1.1.1\"), peer, pool) {",
        "\t\tt.Fatal(\"\u043e\u0431\u044b\u0447\u043d\u044b\u0439 v4-\u043f\u0430\u043a\u0435\u0442 \u043e\u0442\u0431\u0440\u0430\u0441\u044b\u0432\u0430\u0442\u044c \u043d\u0435\u043b\u044c\u0437\u044f\")",
        "\t}",
        "\tif !loopGuardDrop(v6(\"2001:db8:2:dead::1\"), peer, pool) {",
        "\t\tt.Fatal(\"v6-\u043f\u0430\u043a\u0435\u0442 \u043a \u043f\u0443\u043b\u0443 \u043f\u0440\u043e\u0432\u043e\u0434\u0430 \u043e\u0431\u044f\u0437\u0430\u043d \u043e\u0442\u0431\u0440\u0430\u0441\u044b\u0432\u0430\u0442\u044c\u0441\u044f (\u0438\u043d\u0430\u0447\u0435 \u043f\u0435\u0442\u043b\u044f)\")",
        "\t}",
        "\tif loopGuardDrop(v6(\"2001:4860:4860::8888\"), peer, pool) {",
        "\t\tt.Fatal(\"\u043e\u0431\u044b\u0447\u043d\u044b\u0439 v6-\u043f\u0430\u043a\u0435\u0442 \u043e\u0442\u0431\u0440\u0430\u0441\u044b\u0432\u0430\u0442\u044c \u043d\u0435\u043b\u044c\u0437\u044f\")",
        "\t}",
        "\tif loopGuardDrop(v6(\"2001:db8:2::1\"), peer, nil) {",
        "\t\tt.Fatal(\"\u0431\u0435\u0437 \u043f\u0443\u043b\u0430 \u043f\u0440\u043e\u0432\u043e\u0434\u0430 v6-\u043f\u043b\u0435\u0447\u043e \u043c\u043e\u043b\u0447\u0438\u0442\")",
        "\t}",
        "}",
        "",
    ])
    wr(P, s.rstrip("\n") + "\n" + test)

print("NET_IMPORT_IN_TEST=" + str('"net"' in rd("cmd/ks-vpn/wirev6_test.go")))
print("FAILS=" + (",".join(fails) if fails else "NONE"))
sys.exit(1 if fails else 0)
