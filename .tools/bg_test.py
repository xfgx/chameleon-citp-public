#!/usr/bin/env python3
# Запускает gofmt/vet/test на RU-ноде в фоне с логами в /root/layers-*.log.
import sys

import paramiko

c = paramiko.SSHClient()
c.load_host_keys("/files/VPN/bin/data/known_hosts")
c.set_missing_host_key_policy(paramiko.RejectPolicy())
c.connect("192.0.2.10", username="root",
          key_filename="/files/VPN/bin/data/ssh_ed25519", timeout=25)

remote = (
    "export PATH=$PATH:/usr/local/go/bin && cd /root/vpn-new && rm -f /root/layers-done && "
    "(gofmt -l internal/chameleon cmd tools > /root/layers-gofmt.log 2>&1; "
    "go vet ./internal/chameleon ./cmd/chamd ./cmd/cham-server > /root/layers-vet.log 2>&1; "
    "echo VET_RC=$? >> /root/layers-vet.log; "
    "go test ./internal/chameleon ./cmd/cham-server ./cmd/chamd -count=1 > /root/layers-test.log 2>&1; "
    "echo TEST_RC=$? >> /root/layers-test.log; "
    "echo DONE > /root/layers-done) > /dev/null 2>&1 & echo STARTED"
)
_, o, e = c.exec_command(remote, timeout=30)
print(o.read().decode().strip(), e.read().decode().strip())
c.close()
