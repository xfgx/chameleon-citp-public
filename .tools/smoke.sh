#!/bin/bash
# chaossync loopback smoke: server+client на 127.0.0.1, кадр с эхо.
cd /root/build || exit 9
if [ -f srv.pid ]; then kill "$(cat srv.pid)" 2>/dev/null; fi
rm -f loop.key server.log client.log srv.pid
./chaossync-server -genkey -keyfile loop.key || exit 1
./chaossync-server -keyfile loop.key -listen 127.0.0.1:15353 -metrics 127.0.0.1:19090 -T 8 -c 0.85 -rate 1000 -S 32 -batch 4 > server.log 2>&1 &
echo $! > srv.pid
sleep 2
./chaossync-client -keyfile loop.key -node 127.0.0.1:15353 -T 8 -c 0.85 -rate 1000 -S 32 -batch 4 -send ping-over-chaos -dur 100s -sync-timeout 40s > client.log 2>&1
RC=$?
kill "$(cat srv.pid)" 2>/dev/null
echo "CLIENT_RC=$RC"
echo '=== client tail ==='
tail -18 client.log
echo '=== server tail ==='
tail -12 server.log
