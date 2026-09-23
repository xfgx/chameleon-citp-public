#!/usr/bin/env python3
# Поэтапный sync/build/deploy для слоёв 6-8 + 1-3.
# Правила agent.md: секреты не печатаем; деплой = SHA-256 -> rollback ->
# атомарная замена -> restart -> verify (is-active + listeners + journal).
import os
import sys
import time

import paramiko

KEY = "/files/VPN/bin/data/ssh_ed25519"
KH = "/files/VPN/bin/data/known_hosts"
RU = "192.0.2.10"
MY = "198.51.100.10"
NDIR = "/root/vpn-new"
TAR = "/files/VPN/.tools/src-sync.tar.gz"
GOPATH = "/usr/local/go/bin"


def connect(host):
    c = paramiko.SSHClient()
    c.load_host_keys(KH)
    c.set_missing_host_key_policy(paramiko.RejectPolicy())
    c.connect(host, username="root", key_filename=KEY, timeout=25)
    return c


def run(c, cmd, timeout=600):
    _, out, err = c.exec_command(cmd, timeout=timeout)
    o = out.read().decode(errors="replace")
    e = err.read().decode(errors="replace")
    rc = out.channel.recv_exit_status()
    return rc, o, e


def run_long(c, cmd, timeout=3600):
    # Heartbeat-обёртка: канал не простаивает во время долгой тихой сборки.
    hb = "(%s) & p=$!; while kill -0 $p 2>/dev/null; do echo '[...работает...]'; sleep 25; done; wait $p; exit $?" % cmd
    return run(c, hb, timeout)


def show(tag, rc, o, e, tail=4000):
    print("=== %s rc=%d ===" % (tag, rc))
    if o.strip():
        print(o[-tail:])
    if e.strip():
        print("STDERR:", e[-2000:])
    return rc


def stage_sync():
    c = connect(RU)
    rc, o, e = run(c, "test -f %s/internal/chameleon/wsconn.go && echo BASELINE_OK || echo BASELINE_MISSING" % NDIR)
    print("baseline:", o.strip())
    sftp = c.open_sftp()
    sftp.put(TAR, "/root/src-sync.tar.gz")
    sftp.close()
    rc, o, e = run(c, "mkdir -p %s && tar xzf /root/src-sync.tar.gz -C %s && rm -f /root/src-sync.tar.gz && echo EXTRACT_OK" % (NDIR, NDIR))
    show("extract", rc, o, e)
    # Расхождения дерева: файлы на ноде, которых нет в нашем снимке.
    rc, o, e = run(c, "cd %s/internal/chameleon && ls | sort" % NDIR)
    remote = set(o.split())
    local = set(sorted(os.listdir("/files/VPN/internal/chameleon")))
    extra = sorted(remote - local)
    missing = sorted(local - remote)
    print("remote extra files:", extra if extra else "нет")
    print("remote missing files:", missing if missing else "нет")
    c.close()


def stage_test(race=False):
    c = connect(RU)
    g = "export PATH=$PATH:%s && cd %s" % (GOPATH, NDIR)
    rc, o, e = run(c, "%s && go version" % g)
    print("go:", o.strip())
    rc, o, e = run(c, "%s && gofmt -l internal/chameleon cmd tools | head -20; echo GOFMT_DONE" % g)
    show("gofmt -l (пусто=чисто)", rc, o, e)
    rc, o, e = run_long(c, "%s && go vet ./internal/chameleon ./cmd/chamd ./cmd/cham-server" % g)
    show("go vet", rc, o, e)
    if rc != 0:
        c.close()
        sys.exit(1)
    if race:
        rc, o, e = run_long(c, "%s && go test -race ./internal/chameleon -count=1" % g, 1800)
        show("go test -race", rc, o, e)
    else:
        rc, o, e = run_long(c, "%s && go test ./internal/chameleon ./cmd/cham-server ./cmd/chamd -count=1" % g, 1800)
        show("go test", rc, o, e)
    c.close()
    if rc != 0:
        sys.exit(1)


def stage_build():
    c = connect(RU)
    g = "export PATH=$PATH:%s && cd %s" % (GOPATH, NDIR)
    rc, o, e = run_long(c, "%s && bash scripts/build-release.sh" % g, 3600)
    show("build-release.sh", rc, o, e)
    if rc != 0:
        c.close()
        sys.exit(1)
    sup = (
        "%s && "
        "for t in cham-autobypass cham-controlfab cham-detectors cham-flowstats cham-profiler probe fieldtest; do "
        "CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -trimpath -ldflags='-s -w' -o dist/release/$t-linux-amd64 ./tools/$t || exit 1; "
        "CGO_ENABLED=0 GOOS=windows GOARCH=amd64 go build -trimpath -ldflags='-s -w' -o dist/release/$t-windows-amd64.exe ./tools/$t || exit 1; "
        "done && "
        "CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -trimpath -ldflags='-s -w' -o dist/release/bcp38receiver-linux-amd64 ./tools/bcp38receiver && "
        "CGO_ENABLED=0 GOOS=windows GOARCH=amd64 go build -trimpath -ldflags='-s -w' -o dist/release/bcp38test-windows-amd64.exe ./tools/bcp38test && "
        "CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -trimpath -ldflags='-s -w' -o dist/release/cham-deploy-linux-amd64 ./cmd/cham-deploy && "
        "cd dist/release && sha256sum * > SHA256SUMS && echo SUPPLEMENTAL_OK"
    ) % g
    rc, o, e = run_long(c, sup, 3600)
    show("supplemental tools", rc, o, e)
    rc, o, e = run(c, "%s && cat dist/release/SHA256SUMS" % g)
    show("SHA256SUMS", rc, o, e)
    c.close()


def deploy_on(c, label, remote_bin):
    ts = time.strftime("%Y%m%dT%H%M%SZ", time.gmtime())
    steps = [
        ("sha256 new", "sha256sum %s" % remote_bin),
        ("rollback copy", "cp -a /usr/local/bin/cham-server /usr/local/bin/cham-server.rollback-%s" % ts),
        ("atomic swap", "cp %s /usr/local/bin/cham-server.new && chmod 755 /usr/local/bin/cham-server.new && mv -T /usr/local/bin/cham-server.new /usr/local/bin/cham-server" % remote_bin),
        ("restart", "systemctl restart cham-server && sleep 2"),
        ("is-active", "systemctl is-active cham-server"),
        ("listeners", "ss -ltnup | grep -E ':(53|8443|9443|9444|9445|9446)\\b' || true"),
        ("journal", "journalctl -u cham-server -n 12 --no-pager"),
    ]
    ok = True
    for tag, cmd in steps:
        rc, o, e = run(c, cmd)
        show("%s: %s" % (label, tag), rc, o, e, tail=2500)
        if tag in ("rollback copy", "atomic swap", "restart", "is-active") and rc != 0:
            ok = False
            break
        if tag == "is-active" and o.strip() != "active":
            ok = False
            break
    if not ok:
        rc, o, e = run(c, "ls -t /usr/local/bin/cham-server.rollback-* | head -1")
        rb = o.strip()
        print("!!! ДЕПЛОЙ %s НЕ УДАЛСЯ — откат на %s" % (label, rb))
        run(c, "cp -a %s /usr/local/bin/cham-server && systemctl restart cham-server && systemctl is-active cham-server" % rb)
        sys.exit(2)
    print("=== %s: ДЕПЛОЙ OK ===" % label)


def stage_deploy_ru():
    c = connect(RU)
    deploy_on(c, "RU", "%s/dist/release/cham-server-linux-amd64" % NDIR)
    c.close()


def stage_deploy_myserv():
    local_bin = "/files/VPN/dist/release/cham-server-linux-amd64"
    if not os.path.exists(local_bin):
        print("нет локального бинаря — сначала stage pull")
        sys.exit(1)
    c = connect(MY)
    rc, o, e = run(c, "systemctl list-units --type=service --all | grep -i cham || true")
    print("services on myserv:", o.strip())
    sftp = c.open_sftp()
    sftp.put(local_bin, "/root/cham-server-linux-amd64.new")
    sftp.close()
    rc, o, e = run(c, "sha256sum /root/cham-server-linux-amd64.new %s" % local_bin.replace("/files/VPN", "/files/VPN"))
    show("myserv upload sha", rc, o, e)
    deploy_on(c, "MYSERV", "/root/cham-server-linux-amd64.new")
    c.close()


def stage_pull():
    want = [
        "SHA256SUMS",
        "cham-server-linux-amd64", "cham-server-windows-amd64.exe",
        "chamd-windows-amd64.exe",
        "cham-client-linux-amd64", "cham-client-windows-amd64.exe",
        "cham-keygen-windows-amd64.exe",
        "citp-sim-linux-amd64", "citp-sim-windows-amd64.exe",
        "ttl-smuggle-linux-amd64", "ttl-smuggle-windows-amd64.exe",
        "fieldtest-linux-amd64",
    ]
    free = os.statvfs("/files").f_bavail * os.statvfs("/files").f_frsize
    print("свободно на /files: %.0f MB" % (free / 1e6))
    c = connect(RU)
    sftp = c.open_sftp()
    os.makedirs("/files/VPN/dist/release", exist_ok=True)
    for name in want:
        remote = "%s/dist/release/%s" % (NDIR, name)
        local = "/files/VPN/dist/release/%s" % name
        try:
            sz = sftp.stat(remote).st_size
        except FileNotFoundError:
            print("  SKIP (нет на ноде):", name)
            continue
        if os.path.exists(local):
            free += os.path.getsize(local)  # перезапись
        if sz > free - 40e6:
            print("  SKIP (диск):", name)
            continue
        sftp.get(remote, local)
        free -= sz
        print("  pulled", name, sz)
    sftp.close()
    c.close()
    pairs = [
        ("chamd-windows-amd64.exe", "/files/VPN/bin/chamd.exe"),
        ("cham-server-windows-amd64.exe", "/files/VPN/bin/cham-server.exe"),
        ("cham-client-windows-amd64.exe", "/files/VPN/bin/cham-client.exe"),
        ("cham-keygen-windows-amd64.exe", "/files/VPN/bin/cham-keygen.exe"),
    ]
    import shutil
    for src, dst in pairs:
        p = "/files/VPN/dist/release/" + src
        if os.path.exists(p):
            shutil.copyfile(p, dst)
            print("  bin updated:", dst)


if __name__ == "__main__":
    stage = sys.argv[1]
    {"sync": stage_sync,
     "test": stage_test,
     "race": lambda: stage_test(race=True),
     "build": stage_build,
     "deploy-ru": stage_deploy_ru,
     "deploy-myserv": stage_deploy_myserv,
     "pull": stage_pull}[stage]()
