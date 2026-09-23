#!/usr/bin/env python3
# Флудер фонового шума: шлёт мусорные UDP-датаграммы на :4500 с множества
# source-портов — имитация 2часового фонового радиационного фона интернета.
# Мусор не синхронизируется (чужой ключ) -> пиры остаются недоказанными и крутятся.
import socket, os, sys, time

RU = "192.0.2.10"
PORT = 4500
NSOCK = int(sys.argv[1]) if len(sys.argv) > 1 else 400
DUR = float(sys.argv[2]) if len(sys.argv) > 2 else 120.0

socks = []
for _ in range(NSOCK):
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        s.bind(("0.0.0.0", 0))  # уникальный ephemeral source-port
    except Exception:
        pass
    s.setblocking(False)
    socks.append(s)

payload = os.urandom(8)
t0 = time.time()
n = 0
while time.time() - t0 < DUR:
    for s in socks:
        try:
            s.sendto(payload, (RU, PORT))
            n += 1
        except Exception:
            pass
sys.stdout.write("flood done, sent ~%d datagrams from %d sources\n" % (n, len(socks)))
sys.stdout.flush()
