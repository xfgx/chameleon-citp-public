import paramiko, time, json, io, subprocess

K='/files/VPN/bin/data/ssh_ed25519'; H='/files/VPN/bin/data/known_hosts'
RU='192.0.2.10'; MS='198.51.100.10'

def conn(ip):
    last=None
    for i in range(4):
        try:
            c=paramiko.SSHClient(); c.load_host_keys(H); c.set_missing_host_key_policy(paramiko.RejectPolicy())
            c.connect(ip,username='root',key_filename=K,timeout=30); return c
        except Exception as ex:
            last=ex; time.sleep(5)
    raise SystemExit('ssh fail %s: %r'%(ip,last))

def run(c,cmd,t=120):
    _,o,e=c.exec_command(cmd,timeout=t)
    out=o.read().decode(errors='replace'); err=e.read().decode(errors='replace')
    return out,err

ru=conn(RU); ms=conn(MS)

# 1) RU node public key from /root/cham-server.key
helper='''package main

import (
	"fmt"
	"os"
	"strings"

	"chameleon/internal/chameleon"
)

func main() {
	b, err := os.ReadFile(os.Args[1])
	if err != nil {
		panic(err)
	}
	k, err := chameleon.ParseNodePrivKey(strings.TrimSpace(string(b)))
	if err != nil {
		panic(err)
	}
	fmt.Println(chameleon.EncodePub(k))
}
'''
# EncodePub may not exist; use base64 directly
helper=helper.replace('fmt.Println(chameleon.EncodePub(k))','fmt.Println(base64.RawURLEncoding.EncodeToString(k.PublicKey().Bytes()))').replace('"fmt"','"encoding/base64"\n\t"fmt"')
sf=ru.open_sftp()
try: sf.mkdir('/root/vpn/cmd/tmp-pubof')
except Exception: pass
with sf.open('/root/vpn/cmd/tmp-pubof/main.go','w') as f: f.write(helper)
sf.close()
env='export HOME=/root GOPATH=/root/go GOMODCACHE=/root/go/pkg/mod GOCACHE=/root/.cache/go-build PATH=/usr/local/go/bin:/usr/bin:/bin GOTOOLCHAIN=local GOPROXY=off GOSUMDB=off;'
out,err=run(ru,env+' cd /root/vpn && go run ./cmd/tmp-pubof /root/cham-server.key',t=240)
rupub=out.strip().splitlines()[-1].strip() if out.strip() else ''
print('RU_PUB=',rupub,'ERR',err[-300:])
run(ru,'rm -rf /root/vpn/cmd/tmp-pubof')
if not rupub:
    raise SystemExit('no RU pubkey')

# 2) pinned known_hosts entry for Myserv, copied from the container pin
hk=paramiko.HostKeys(H)
ent=hk.lookup(MS)
live=ms.get_transport().get_remote_server_key()
if ent is None:
    raise SystemExit('no pinned host key for myserv')
match=[ (n,k) for n,k in ent.items() if k.get_base64()==live.get_base64() ]
print('PINNED_TYPES',list(ent.keys()),'LIVE',live.get_name(),'MATCH',bool(match))
if not match:
    raise SystemExit('live host key does not match pin')
kh_text=MS+' '+live.get_name()+' '+live.get_base64()+'\n'

# 3) RU: /etc/chameleon + node policy + console ssh key
ru_policy=json.dumps({
  "id":"ru",
  "allow_file":"/root/cham-allow.txt",
  "cham_unit":"cham-server.service",
  "hub_key_dir":"/root/build/users",
  "hub_unit":"ks-vpn-hub.service",
  "hub_status":"/run/ks-hub/status.json",
  "units":["cham-server.service","ks-vpn-hub.service","ks-vpn-node.service","ks-vpn-phone.service","ks-vpn-exit.service"]
},ensure_ascii=False,indent=2)+'\n'
ms_policy=json.dumps({
  "id":"myserv",
  "allow_file":"/root/cham-clients.txt",
  "cham_unit":"cham-server.service",
  "units":["cham-server.service","ks-vpn-exit.service"]
},ensure_ascii=False,indent=2)+'\n'

sf=ru.open_sftp()
run(ru,'mkdir -p /etc/chameleon && chmod 0750 /etc/chameleon')
with sf.open('/etc/chameleon/node-agent.json','w') as f: f.write(ru_policy)
run(ru,'chmod 0640 /etc/chameleon/node-agent.json')
with sf.open('/root/.ssh/console-known-hosts','w') as f: f.write(kh_text)
run(ru,'chmod 0600 /root/.ssh/console-known-hosts')
out,err=run(ru,'test -f /root/.ssh/console-myserv || ssh-keygen -t ed25519 -N "" -C console@ru -f /root/.ssh/console-myserv >/dev/null; cat /root/.ssh/console-myserv.pub')
console_pub=out.strip()
print('CONSOLE_PUB=',console_pub[:60],'...')

# 4) Myserv: agent binary + wrapper + policy + restricted authorized_keys
rsf=ru.open_sftp(); msf=ms.open_sftp()
src=rsf.open('/root/build/ks-admin','rb'); src.prefetch()
dst=msf.open('/usr/local/bin/ks-admin-console.new','wb')
n=0
while True:
    chunk=src.read(1<<20)
    if not chunk: break
    dst.write(chunk); n+=len(chunk)
src.close(); dst.close()
print('COPIED_BYTES',n)
msf.chmod('/usr/local/bin/ks-admin-console.new',0o755)
run(ms,'mv -f /usr/local/bin/ks-admin-console.new /usr/local/bin/ks-admin-console')
wrapper='#!/bin/sh\nexec /usr/local/bin/ks-admin-console -node-op -node-config /etc/chameleon/node-agent.json\n'
with msf.open('/usr/local/bin/vpn-node-agent','w') as f: f.write(wrapper)
msf.chmod('/usr/local/bin/vpn-node-agent',0o755)
run(ms,'mkdir -p /etc/chameleon && chmod 0750 /etc/chameleon')
with msf.open('/etc/chameleon/node-agent.json','w') as f: f.write(ms_policy)
run(ms,'chmod 0640 /etc/chameleon/node-agent.json')
run(ms,'touch /root/cham-clients.txt; chmod 0600 /root/cham-clients.txt')
entry='command="/usr/local/bin/vpn-node-agent",restrict '+console_pub+'\n'
out,err=run(ms,'grep -q "console@ru" /root/.ssh/authorized_keys && echo EXISTS || echo MISSING')
if 'MISSING' in out:
    run(ms,'cp -a /root/.ssh/authorized_keys /root/.ssh/authorized_keys.bak-20260919; printf %s '+json.dumps(entry)+' >> /root/.ssh/authorized_keys')
out,err=run(ms,'tail -1 /root/.ssh/authorized_keys | cut -c1-80; wc -l /root/.ssh/authorized_keys; ls -l /usr/local/bin/vpn-node-agent /usr/local/bin/ks-admin-console /etc/chameleon/node-agent.json')
print('MYSERV SETUP:',out,err[-300:])
rsf.close(); msf.close()

# 5) RU: cluster config
nodes=[
 {"id":"ru","name":"RU нода — Chameleon + KS-хаб","role":"entry","address":"192.0.2.10:9443","public_key":rupub,"supports_ks":True,"local_config":"/etc/chameleon/node-agent.json"},
 {"id":"myserv","name":"Зарубежный выход — Myserv","role":"exit","address":"198.51.100.10:8443","public_key":"hCs_ISiKS_DPbsA3mD2xhcHaIDa9d1G_AbYGBkBlAnc","supports_ks":False,"ssh_host":"root@198.51.100.10","ssh_key":"/root/.ssh/console-myserv","known_hosts":"/root/.ssh/console-known-hosts"}
]
with sf.open('/etc/chameleon/console-nodes.json','w') as f: f.write(json.dumps(nodes,ensure_ascii=False,indent=2)+'\n')
run(ru,'chmod 0640 /etc/chameleon/console-nodes.json')
sf.close()

# 6) verify agent over ssh from RU, then restart console
out,err=run(ru,'echo \'{"action":"status"}\' | timeout 20 ssh -T -o BatchMode=yes -o StrictHostKeyChecking=yes -o IdentitiesOnly=yes -o ConnectTimeout=6 -o UserKnownHostsFile=/root/.ssh/console-known-hosts -i /root/.ssh/console-myserv root@198.51.100.10 2>&1 | head -3',t=90)
print('MYSERV AGENT STATUS:',out,err[-200:])
out,err=run(ru,'systemctl restart ks-admin.service; sleep 5; systemctl is-active ks-admin.service; journalctl -u ks-admin.service -n 8 --no-pager --output=cat; curl -sk -o /dev/null -w "login:%{http_code}\\n" https://127.0.0.1:51843/login',t=120)
print('CONSOLE:',out,err[-300:])
ru.close(); ms.close()
print('SETUP DONE')
