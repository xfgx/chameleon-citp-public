#!/usr/bin/env python3
# UDP-приёмник на наборе портов: логирует, на какой порт пришёл пакет.
import socket, select, sys, time

ports = [123, 500, 443, 4500, 51820, 853, 1194]
socks = []
for p in ports:
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        s.bind(("0.0.0.0", p))
        s.setblocking(False)
        socks.append((p, s))
    except Exception as e:
        sys.stdout.write("BIND_FAIL %d %s\n" % (p, e)); sys.stdout.flush()
sys.stdout.write("LISTENING " + ",".join(str(p) for p, _ in socks) + "\n")
sys.stdout.flush()

t0 = time.time()
while time.time() - t0 < 90:
    r, _, _ = select.select([s for _, s in socks], [], [], 1.0)
    for s in r:
        try:
            data, addr = s.recvfrom(2048)
            port = s.getsockname()[1]
            sys.stdout.write("GOT port=%d from=%s len=%d\n" % (port, addr, len(data)))
            sys.stdout.flush()
        except Exception:
            pass
sys.stdout.write("PROBE_DONE\n"); sys.stdout.flush()
