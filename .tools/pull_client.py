#!/usr/bin/env python3
# Тянет с RU-ноды свежий chamd-windows-amd64.exe + SHA256SUMS, сверяет хэш,
# обновляет bin/chamd.exe. Старый dist-файл удаляется ДО загрузки (диск 100%).
import hashlib
import os

import paramiko

LOCAL = "/files/VPN/dist/release"

c = paramiko.SSHClient()
c.load_host_keys("/files/VPN/bin/data/known_hosts")
c.set_missing_host_key_policy(paramiko.RejectPolicy())
c.connect("192.0.2.10", username="root",
          key_filename="/files/VPN/bin/data/ssh_ed25519", timeout=25)
s = c.open_sftp()

sums_remote = "/root/vpn-new/dist/release/SHA256SUMS"
sums_local = os.path.join(LOCAL, "SHA256SUMS")
s.get(sums_remote, sums_local + ".part")
os.replace(sums_local + ".part", sums_local)
want = {}
for line in open(sums_local):
    p = line.split()
    if len(p) == 2:
        want[os.path.basename(p[1])] = p[0]

name = "chamd-windows-amd64.exe"
local = os.path.join(LOCAL, name)
if os.path.exists(local):
    os.remove(local)  # освобождаем место до загрузки
s.get("/root/vpn-new/dist/release/" + name, local + ".part")
os.replace(local + ".part", local)
s.close()
c.close()

h = hashlib.sha256()
with open(local, "rb") as f:
    for chunk in iter(lambda: f.read(1 << 20), b""):
        h.update(chunk)
ok = h.hexdigest() == want.get(name, "")
print("VERIFY", name, ok, h.hexdigest()[:16])
if not ok:
    raise SystemExit(1)

import shutil
shutil.copyfile(local, "/files/VPN/bin/chamd.exe")
print("BIN-UPDATED /files/VPN/bin/chamd.exe")
print("PULL_CLIENT_OK")
