#!/usr/bin/env python3
# put_file.py <host> <local> <remote> — SFTP-загрузка одного файла.
import sys

import paramiko

host, local, remote = sys.argv[1], sys.argv[2], sys.argv[3]
c = paramiko.SSHClient()
c.load_host_keys("/files/VPN/bin/data/known_hosts")
c.set_missing_host_key_policy(paramiko.RejectPolicy())
c.connect(host, username="root",
          key_filename="/files/VPN/bin/data/ssh_ed25519", timeout=25)
s = c.open_sftp()
s.put(local, remote)
s.close()
c.close()
print("PUT_OK", remote)
