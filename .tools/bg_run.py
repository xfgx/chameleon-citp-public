#!/usr/bin/env python3
# bg_run.py <host> <name> <cmd> — фоновый запуск команды на ноде:
# лог в /root/<name>.log, по завершении RC дописывается в лог и создаётся
# маркер /root/<name>.done.
import sys

import paramiko

host, name, cmd = sys.argv[1], sys.argv[2], sys.argv[3]
log = "/root/%s.log" % name
done = "/root/%s.done" % name

c = paramiko.SSHClient()
c.load_host_keys("/files/VPN/bin/data/known_hosts")
c.set_missing_host_key_policy(paramiko.RejectPolicy())
c.connect(host, username="root",
          key_filename="/files/VPN/bin/data/ssh_ed25519", timeout=25)
remote = ("rm -f %s %s; nohup sh -c '(%s) > %s 2>&1; echo BG_RC=$? >> %s; touch %s' "
          "> /dev/null 2>&1 < /dev/null & sleep 1; echo BG_STARTED") % (log, done, cmd, log, log, done)
t = c.get_transport().open_session()
t.settimeout(8)
t.exec_command(remote)
try:
    out = t.recv(4096).decode(errors="replace")
except Exception:
    out = "(no immediate output)"
print(out.strip())
c.close()
