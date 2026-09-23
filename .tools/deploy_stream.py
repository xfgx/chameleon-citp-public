#!/usr/bin/env python3
# Потоковый деплой cham-server на Myserv: RU-нода -> память -> Myserv,
# без записи на заполненный диск контейнера. Процедура правила 10:
# сверка SHA-256 (источник/поток/приёмник) -> rollback -> атомарная замена ->
# restart -> is-active + listeners + journal; при сбое — откат.
import hashlib
import sys
import time

import paramiko

KEY = "/files/VPN/bin/data/ssh_ed25519"
KH = "/files/VPN/bin/data/known_hosts"
RU = "192.0.2.10"
MY = "198.51.100.10"
SRC = "/root/vpn-new/dist/release/cham-server-linux-amd64"
DST = "/root/cham-server-linux-amd64.new"


def connect(host):
    c = paramiko.SSHClient()
    c.load_host_keys(KH)
    c.set_missing_host_key_policy(paramiko.RejectPolicy())
    c.connect(host, username="root", key_filename=KEY, timeout=25)
    return c


def run(c, cmd, timeout=300):
    _, o, e = c.exec_command(cmd, timeout=timeout)
    out = o.read().decode(errors="replace")
    err = e.read().decode(errors="replace")
    return o.channel.recv_exit_status(), out, err


ru = connect(RU)
rc, out, _ = run(ru, "sha256sum " + SRC)
src_hash = out.split()[0]
rc, out, _ = run(ru, "stat -c %s " + SRC)
size = int(out.strip())
print("SRC:", src_hash[:16], size, "bytes")

my = connect(MY)
s_ru = ru.open_sftp()
s_my = my.open_sftp()
f_in = s_ru.file(SRC, "rb")
f_out = s_my.file(DST, "wb")
h = hashlib.sha256()
n = 0
while True:
    chunk = f_in.read(1 << 20)
    if not chunk:
        break
    f_out.write(chunk)
    h.update(chunk)
    n += len(chunk)
f_in.close()
f_out.close()
print("streamed:", n)
if n != size:
    print("SIZE MISMATCH")
    sys.exit(1)

rc, out, _ = run(my, "sha256sum " + DST)
dst_hash = out.split()[0]
print("DST:", dst_hash[:16])
if not (dst_hash == src_hash == h.hexdigest()):
    print("HASH MISMATCH — деплой отменён")
    sys.exit(1)
print("HASH_MATCH OK")

ts = time.strftime("%Y%m%dT%H%M%SZ", time.gmtime())
steps = [
    ("rollback", "cp -a /usr/local/bin/cham-server /usr/local/bin/cham-server.rollback-" + ts),
    ("swap", "cp " + DST + " /usr/local/bin/cham-server.new && chmod 755 /usr/local/bin/cham-server.new && mv -T /usr/local/bin/cham-server.new /usr/local/bin/cham-server"),
    ("restart", "systemctl restart cham-server && sleep 2"),
    ("is-active", "systemctl is-active cham-server"),
    ("listeners", "ss -ltnup | grep -E ':(8443|9443|9444|9445|9446|53)\\b' || true"),
    ("journal", "journalctl -u cham-server -n 12 --no-pager"),
]
ok = True
for tag, cmd in steps:
    rc, o, e = run(my, cmd)
    print("=== MYSERV", tag, "rc=%d" % rc)
    if o.strip():
        print(o[-1800:])
    if e.strip():
        print("STDERR:", e[-600:])
    if tag in ("rollback", "swap", "restart", "is-active") and rc != 0:
        ok = False
        break
    if tag == "is-active" and o.strip() != "active":
        ok = False
        break
if not ok:
    rc, o, e = run(my, "ls -t /usr/local/bin/cham-server.rollback-* | head -1")
    rb = o.strip()
    print("!!! ДЕПЛОЙ MYSERV НЕ УДАЛСЯ — откат на", rb)
    run(my, "cp -a " + rb + " /usr/local/bin/cham-server && systemctl restart cham-server && systemctl is-active cham-server")
    sys.exit(2)
print("=== MYSERV: ДЕПЛОЙ OK ===")
ru.close()
my.close()
