#!/usr/bin/env python3
# get_file.py <host> <remote> <local> — SFTP-скачивание одного файла.
import sys

import paramiko

host, remote, local = sys.argv[1], sys.argv[2], sys.argv[3]
c = paramiko.SSHClient()
c.load_host_keys("/files/VPN/bin/data/known_hosts")
c.set_missing_host_key_policy(paramiko.RejectPolicy())
c.connect(host, username="root",
          key_filename="/files/VPN/bin/data/ssh_ed25519", timeout=25)
s = c.open_sftp()
s.get(remote, local)
s.close()
c.close()
print("GET_OK", local)
