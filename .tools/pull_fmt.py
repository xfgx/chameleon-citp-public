#!/usr/bin/env python3
# Тянет с RU-ноды gofmt-форматированные версии изменённых исходников,
# чтобы /files оставался каноническим деревом (раунды 2+3+4+5+6).
import os

import paramiko

FILES = [
    # раунд 2: модули слоёв + обвязка автопилота
    "internal/chameleon/cf_exogenous.go",
    "internal/chameleon/cf_collateral.go",
    "internal/chameleon/cf_theta.go",
    "internal/chameleon/cf_surrogate.go",
    "internal/chameleon/cf_exogenous_test.go",
    "internal/chameleon/cf_collateral_test.go",
    "internal/chameleon/cf_theta_test.go",
    "internal/chameleon/cf_surrogate_test.go",
    "cmd/chamd/autopilot_layers_test.go",
    # раунд 3: рассылка θ/карты дорогих зон
    "internal/chameleon/cf_board_client.go",
    "internal/chameleon/cf_board_channels_test.go",
    "internal/chameleon/control_fabric.go",
    "internal/chameleon/cf_integration_hints.go",
    "cmd/cham-server/main.go",
    "cmd/cham-server/cf_broadcast.go",
    "cmd/cham-server/cf_broadcast_test.go",
    # раунд 4: суррогат в автопилоте + двусторонние канарейки
    "cmd/chamd/autopilot_surrogate_test.go",
    # раунд 5: best-of-K выбор генома по fitness + leak-бюджет
    "cmd/chamd/autopilot_fitness_test.go",
    # раунд 6: кастомные порты слушателей
    "cmd/chamd/listen.go",
    "cmd/chamd/listen_test.go",
    "cmd/chamd/socks.go",
    "cmd/chamd/web.go",
    "cmd/chamd/dns.go",
    # общие для раундов 4-6:
    "cmd/chamd/autopilot.go",
    "cmd/chamd/manager.go",
    "cmd/chamd/main.go",
]

c = paramiko.SSHClient()
c.load_host_keys("/files/VPN/bin/data/known_hosts")
c.set_missing_host_key_policy(paramiko.RejectPolicy())
c.connect("192.0.2.10", username="root",
          key_filename="/files/VPN/bin/data/ssh_ed25519", timeout=25)
s = c.open_sftp()
for rel in FILES:
    remote = "/root/vpn-new/" + rel
    local = "/files/VPN/" + rel
    s.get(remote, local + ".part")
    os.replace(local + ".part", local)
    print("SYNCED", rel, os.path.getsize(local))
s.close()
c.close()
print("FMT_PULL_OK")
