#!/usr/bin/env python3
"""SSH/SFTP helper for the RU build node (192.0.2.10).

The OpenSSH private key is read from the project secrets file at runtime and
is never printed, logged, or embedded anywhere. Usage:

  python3 ru.py run "<remote command>" [timeout_sec]
  python3 ru.py put <local_path> <remote_path>
  python3 ru.py get <remote_path> <local_path>
  python3 ru.py fingerprint

Env overrides: RU_HOST, RU_PORT, RU_USER, VPN_SECRETS.
"""
import hashlib
import io
import os
import re
import sys

import paramiko

SECRETS = os.environ.get("VPN_SECRETS", "/files/VPN-secrets-20260826.txt")
HOST = os.environ.get("RU_HOST", "192.0.2.10")
PORT = int(os.environ.get("RU_PORT", "22"))
USER = os.environ.get("RU_USER", "root")


def load_key():
    with open(SECRETS, "r", encoding="utf-8", errors="replace") as f:
        txt = f.read()
    m = re.search(
        r"-----BEGIN OPENSSH PRIVATE KEY-----.*?-----END OPENSSH PRIVATE KEY-----",
        txt,
        re.S,
    )
    if not m:
        raise SystemExit("ru.py: no OpenSSH private key block in secrets file")
    return paramiko.Ed25519Key.from_private_key(io.StringIO(m.group(0) + "\n"))


def connect():
    key = load_key()
    c = paramiko.SSHClient()
    c.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    c.connect(
        HOST,
        PORT,
        USER,
        pkey=key,
        timeout=25,
        banner_timeout=25,
        auth_timeout=25,
        allow_agent=False,
        look_for_keys=False,
    )
    return c


def host_fingerprint(c):
    t = c.get_transport()
    if t is None:
        return "<no transport>"
    fp = hashlib.sha256(t.get_remote_server_key().asbytes()).digest()
    import base64

    return "SHA256:" + base64.b64encode(fp).decode().rstrip("=")


def main():
    if len(sys.argv) < 2:
        raise SystemExit(__doc__)
    op = sys.argv[1]
    c = connect()
    try:
        fp = host_fingerprint(c)
        if op == "run":
            cmd = sys.argv[2]
            timeout = int(sys.argv[3]) if len(sys.argv) > 3 else 600
            stdin, stdout, stderr = c.exec_command(cmd, timeout=timeout)
            out = stdout.read().decode("utf-8", "replace")
            err = stderr.read().decode("utf-8", "replace")
            rc = stdout.channel.recv_exit_status()
            sys.stdout.write(out)
            if err:
                sys.stderr.write(err)
            sys.stderr.write(f"\n[ru.py] exit={rc} hostkey={fp}\n")
            sys.exit(rc)
        elif op == "put":
            sftp = c.open_sftp()
            sftp.put(sys.argv[2], sys.argv[3])
            sftp.close()
            print(f"[ru.py] put ok hostkey={fp}")
        elif op == "get":
            sftp = c.open_sftp()
            sftp.get(sys.argv[2], sys.argv[3])
            sftp.close()
            print(f"[ru.py] get ok hostkey={fp}")
        elif op == "fingerprint":
            print(fp)
        else:
            raise SystemExit(f"ru.py: unknown op {op!r}")
    finally:
        c.close()


if __name__ == "__main__":
    main()
