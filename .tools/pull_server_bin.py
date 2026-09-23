#!/usr/bin/env python3
# Минимальная выгрузка только linux-бинарника cham-server + SHA256SUMS
# с RU-ноды. Windows-.exe в контейнер НЕ копируются (по указанию владельца).
import hashlib
import os

import paramiko

NDIR = "/root/vpn-new/dist/release"
LOCAL = "/files/VPN/dist/release"
WANT = ["SHA256SUMS", "cham-server-linux-amd64"]

c = paramiko.SSHClient()
c.load_host_keys("/files/VPN/bin/data/known_hosts")
c.set_missing_host_key_policy(paramiko.RejectPolicy())
c.connect("192.0.2.10", username="root",
          key_filename="/files/VPN/bin/data/ssh_ed25519", timeout=25)
s = c.open_sftp()
os.makedirs(LOCAL, exist_ok=True)
for name in WANT:
    remote = "%s/%s" % (NDIR, name)
    local = os.path.join(LOCAL, name)
    tmp = local + ".part"
    s.get(remote, tmp)
    os.replace(tmp, local)
    print("PULLED", name, os.path.getsize(local))
s.close()
c.close()

sums = {}
for line in open(os.path.join(LOCAL, "SHA256SUMS")):
    p = line.split()
    if len(p) == 2:
        sums[os.path.basename(p[1])] = p[0]

name = "cham-server-linux-amd64"
h = hashlib.sha256()
with open(os.path.join(LOCAL, name), "rb") as f:
    for chunk in iter(lambda: f.read(1 << 20), b""):
        h.update(chunk)
lh = h.hexdigest()
ok = lh == sums.get(name, "")
print("VERIFY", name, ok, lh)
print("PULL_SERVER_OK" if ok else "PULL_SERVER_FAIL")
