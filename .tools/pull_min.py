#!/usr/bin/env python3
# Минимальная выгрузка артефактов с RU-ноды + сверка SHA-256 с SHA256SUMS
# + обновление bin/*.exe. Пишет через .part с атомарной заменой.
import hashlib
import os

import paramiko

RU = "192.0.2.10"
NDIR = "/root/vpn-new/dist/release"
LOCAL = "/files/VPN/dist/release"
WANT = [
    "SHA256SUMS",
    "cham-server-linux-amd64",
    "cham-server-windows-amd64.exe",
    "chamd-windows-amd64.exe",
    "cham-client-windows-amd64.exe",
    "cham-keygen-windows-amd64.exe",
    "fieldtest-linux-amd64",
]

c = paramiko.SSHClient()
c.load_host_keys("/files/VPN/bin/data/known_hosts")
c.set_missing_host_key_policy(paramiko.RejectPolicy())
c.connect(RU, username="root",
          key_filename="/files/VPN/bin/data/ssh_ed25519", timeout=25)
s = c.open_sftp()
os.makedirs(LOCAL, exist_ok=True)
done = []
for name in WANT:
    remote = "%s/%s" % (NDIR, name)
    local = os.path.join(LOCAL, name)
    try:
        sz = s.stat(remote).st_size
    except FileNotFoundError:
        print("MISSING-ON-NODE", name)
        continue
    free = os.statvfs("/files").f_bavail * os.statvfs("/files").f_frsize
    if os.path.exists(local):
        free += os.path.getsize(local)
    if sz > free - 10e6:
        print("SKIP-DISK", name, sz)
        continue
    tmp = local + ".part"
    s.get(remote, tmp)
    os.replace(tmp, local)
    done.append(name)
    print("PULLED", name, sz)
s.close()
c.close()


def sha256(p):
    h = hashlib.sha256()
    with open(p, "rb") as f:
        for chunk in iter(lambda: f.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


sums = {}
sp = os.path.join(LOCAL, "SHA256SUMS")
if os.path.exists(sp):
    for line in open(sp):
        parts = line.split()
        if len(parts) == 2:
            sums[os.path.basename(parts[1])] = parts[0]

ok = True
for name in done:
    if name == "SHA256SUMS":
        continue
    lh = sha256(os.path.join(LOCAL, name))
    match = (lh == sums.get(name, ""))
    ok = ok and match
    print("VERIFY", name, match, lh[:16])

if ok:
    import shutil
    pairs = [
        ("chamd-windows-amd64.exe", "/files/VPN/bin/chamd.exe"),
        ("cham-server-windows-amd64.exe", "/files/VPN/bin/cham-server.exe"),
        ("cham-client-windows-amd64.exe", "/files/VPN/bin/cham-client.exe"),
        ("cham-keygen-windows-amd64.exe", "/files/VPN/bin/cham-keygen.exe"),
    ]
    for src, dst in pairs:
        p = os.path.join(LOCAL, src)
        if os.path.exists(p):
            shutil.copyfile(p, dst)
            print("BIN-UPDATED", dst)
print("PULL_DONE ok=%s" % ok)
