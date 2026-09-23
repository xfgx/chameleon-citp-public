#!/usr/bin/env python3
# Быстрый foreground-запуск команды на ноде: ssh_run.py <host> <cmd>
import sys

import paramiko

host = sys.argv[1]
cmd = sys.argv[2]
timeout = int(sys.argv[3]) if len(sys.argv) > 3 else 120

c = paramiko.SSHClient()
c.load_host_keys("/files/VPN/bin/data/known_hosts")
c.set_missing_host_key_policy(paramiko.RejectPolicy())
c.connect(host, username="root",
          key_filename="/files/VPN/bin/data/ssh_ed25519", timeout=25)
_, o, e = c.exec_command(cmd, timeout=timeout)
out = o.read().decode(errors="replace")
err = e.read().decode(errors="replace")
rc = o.channel.recv_exit_status()
print("RC=%d" % rc)
if out.strip():
    print(out)
if err.strip():
    print("STDERR:", err)
c.close()
