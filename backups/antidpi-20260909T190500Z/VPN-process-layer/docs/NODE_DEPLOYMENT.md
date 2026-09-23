# Chameleon node: build, deployment, and operation

## Verified release artifacts (2026-08-22)

Built with Go 1.26.3 from the current `/files/VPN` source after the Priority-0 fixes.

| Platform | Artifact | SHA-256 |
|---|---|---|
| Linux amd64 node | `dist/release/cham-server-linux-amd64` | `01045b7812b2ef7f655bf6189771fb9b54b8d31d4643e6d03dc612dc774b7b00` |
| Windows amd64 node | `dist/release/cham-server-windows-amd64.exe` | `741987fe4bdc9eba0d6e799ad2aba6d7cd02480216913bea4c1ef9fef506a664` |

Copies are also installed as `bin/cham-server-linux` and `bin/cham-server.exe`.

Verify after copying:

```bash
sha256sum cham-server-linux-amd64
```

```powershell
Get-FileHash .\cham-server-windows-amd64.exe -Algorithm SHA256
```

## Linux node

### 1. Install

```bash
sudo install -d -m 0750 /etc/chameleon
sudo install -m 0755 cham-server-linux-amd64 /usr/local/bin/cham-server
```

Generate the node key only for a new node. Do not overwrite an existing key:

```bash
sudo /usr/local/bin/cham-server -genkey -keyfile /etc/chameleon/server.key
sudo chmod 0600 /etc/chameleon/server.key
```

Put one approved client public key on each line:

```bash
sudoedit /etc/chameleon/clients.txt
sudo chmod 0600 /etc/chameleon/clients.txt
```

### 2. systemd service

Create `/etc/systemd/system/cham-server.service`:

```ini
[Unit]
Description=Chameleon CITP Node
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
ExecStart=/usr/local/bin/cham-server -listen 0.0.0.0:8443 -keyfile /etc/chameleon/server.key -allowfile /etc/chameleon/clients.txt -cbr 40ms -flavor auto -max-connections 1024
Restart=always
RestartSec=3
LimitNOFILE=65536
NoNewPrivileges=true
PrivateTmp=true
ProtectSystem=strict
ProtectHome=true
ReadOnlyPaths=/etc/chameleon

[Install]
WantedBy=multi-user.target
```

Activate and verify:

```bash
sudo systemctl daemon-reload
sudo systemctl enable --now cham-server
sudo systemctl is-active cham-server
sudo journalctl -u cham-server -n 50 --no-pager
sudo ss -lntp | grep ':8443'
```

Open TCP/8443 in the provider firewall and, if UFW is enabled:

```bash
sudo ufw allow 8443/tcp
```

### 3. Safe update with rollback

```bash
set -e
STAMP=$(date -u +%Y%m%dT%H%M%SZ)
sudo install -m 0755 cham-server-linux-amd64 /usr/local/bin/cham-server.new
sudo systemctl stop cham-server
sudo cp -a /usr/local/bin/cham-server "/usr/local/bin/cham-server.backup-$STAMP"
sudo mv /usr/local/bin/cham-server.new /usr/local/bin/cham-server
sudo systemctl start cham-server
sudo systemctl is-active cham-server
sudo journalctl -u cham-server -n 20 --no-pager
```

If startup fails:

```bash
sudo systemctl stop cham-server
sudo cp -a /usr/local/bin/cham-server.backup-<TIMESTAMP> /usr/local/bin/cham-server
sudo systemctl start cham-server
```

## Windows node

Run PowerShell as Administrator.

### 1. Install and configure

```powershell
New-Item -ItemType Directory -Force C:\ProgramData\Chameleon | Out-Null
Copy-Item .\cham-server-windows-amd64.exe C:\ProgramData\Chameleon\cham-server.exe
```

Generate the key only for a new node:

```powershell
C:\ProgramData\Chameleon\cham-server.exe -genkey -keyfile C:\ProgramData\Chameleon\server.key
```

Create `C:\ProgramData\Chameleon\clients.txt` with one approved client public key per line.

Test in the foreground:

```powershell
C:\ProgramData\Chameleon\cham-server.exe `
  -listen 0.0.0.0:8443 `
  -keyfile C:\ProgramData\Chameleon\server.key `
  -allowfile C:\ProgramData\Chameleon\clients.txt `
  -cbr 40ms -flavor auto -max-connections 1024
```

Allow the port:

```powershell
New-NetFirewallRule -DisplayName 'Chameleon node 8443' -Direction Inbound -Protocol TCP -LocalPort 8443 -Action Allow
```

### 2. Install as a Windows service

Use a service wrapper such as WinSW or NSSM. Example with NSSM:

```powershell
nssm install ChameleonNode C:\ProgramData\Chameleon\cham-server.exe
nssm set ChameleonNode AppParameters '-listen 0.0.0.0:8443 -keyfile C:\ProgramData\Chameleon\server.key -allowfile C:\ProgramData\Chameleon\clients.txt -cbr 40ms -flavor auto -max-connections 1024'
nssm set ChameleonNode AppDirectory C:\ProgramData\Chameleon
nssm set ChameleonNode Start SERVICE_AUTO_START
nssm start ChameleonNode
Get-Service ChameleonNode
```

## Connecting clients

The client needs:

1. Public node address, for example `node.example.com:8443`.
2. The node public key printed when the server key is generated.
3. Its own private client key, which must never be copied to the server.
4. The corresponding client public key added to the server's `clients.txt`.

Windows client:

```powershell
.\chamd.exe
```

Dashboard: `http://127.0.0.1:8080`; SOCKS5: `127.0.0.1:1080`.
For system-wide TUN mode, run an elevated terminal:

```powershell
.\chamd.exe -tun
```

After editing `clients.txt`, restart the node:

```bash
sudo systemctl restart cham-server
```

## Current production deployment

On 2026-08-22 the Linux node was updated through SSH with checksum verification and rollback protection.

- Service: `cham-server.service`
- Listen address: `0.0.0.0:8443`
- State after deployment: `active`
- Installed SHA-256: `01045b7812b2ef7f655bf6189771fb9b54b8d31d4643e6d03dc612dc774b7b00`
- Remote rollback copy: `/root/cham-server.backup-20260822T110157Z`
- Deployment log: `dist/release/linux-deploy.log`
