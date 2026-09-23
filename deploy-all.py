import paramiko, time
K='/files/VPN/bin/data/ssh_ed25519'; H='/files/VPN/bin/data/known_hosts'
RU='192.0.2.10'; MS='198.51.100.10'
OUT='/root/build/full-rebuild-20260919-full'

def conn(ip):
    last=None
    for i in range(4):
        try:
            c=paramiko.SSHClient(); c.load_host_keys(H); c.set_missing_host_key_policy(paramiko.RejectPolicy())
            c.connect(ip,username='root',key_filename=K,timeout=30); return c
        except Exception as ex:
            last=ex; time.sleep(6)
    raise SystemExit('ssh fail %s: %r'%(ip,last))

def run(c,cmd,t=180):
    _,o,e=c.exec_command(cmd,timeout=t)
    return o.read().decode(errors='replace'), e.read().decode(errors='replace')

ru=conn(RU); ms=conn(MS)
rsf=ru.open_sftp(); msf=ms.open_sftp()

def stream(src_path, dst_sftp, dst_tmp):
    s=rsf.open(src_path,'rb'); s.prefetch()
    d=dst_sftp.open(dst_tmp,'wb'); n=0
    while True:
        ch=s.read(1<<20)
        if not ch: break
        d.write(ch); n+=len(ch)
    s.close(); d.close(); return n

# --- Myserv: cham-server + node agent binary
print('MYSERV upload', stream(OUT+'/cham-server', msf, '/root/cham-server.new'))
print('MYSERV agent upload', stream(OUT+'/ks-admin', msf, '/usr/local/bin/ks-admin-console.new'))
out,err=run(ms,'''
set -e
TS=$(date -u +%Y%m%dT%H%M%SZ)
chmod 0755 /root/cham-server.new /usr/local/bin/ks-admin-console.new
cp -a /root/cham-server /root/cham-server.rollback-$TS
mv -f /root/cham-server.new /root/cham-server
mv -f /usr/local/bin/ks-admin-console.new /usr/local/bin/ks-admin-console
systemctl restart cham-server.service
sleep 4
systemctl is-active cham-server.service
sha256sum /root/cham-server
ss -ltnp | grep -E "8443|9444|9445" | head -5
journalctl -u cham-server.service -n 6 --no-pager --output=cat
''')
print('MYSERV DEPLOY:',out,'ERR',err[-600:])

# --- RU: cham-server + ks-admin
out,err=run(ru,'''
set -e
TS=$(date -u +%Y%m%dT%H%M%SZ)
cp -a /usr/local/bin/cham-server /usr/local/bin/cham-server.rollback-$TS
install -m 0755 %s/cham-server /usr/local/bin/cham-server
cp -a /root/build/ks-admin /root/build/ks-admin.rollback-$TS
install -m 0755 %s/ks-admin /root/build/ks-admin
systemctl restart cham-server.service
sleep 4
systemctl restart ks-admin.service
sleep 4
systemctl is-active cham-server.service ks-admin.service
sha256sum /usr/local/bin/cham-server /root/build/ks-admin
ss -ltnp | grep -E "9443|9444|9445|9446|51843"
journalctl -u cham-server.service -n 8 --no-pager --output=cat
journalctl -u ks-admin.service -n 4 --no-pager --output=cat
curl -sk -o /dev/null -w "console_login:%%{http_code}\n" https://127.0.0.1:51843/login
echo '{"action":"status"}' | /root/build/ks-admin -node-op -node-config /etc/chameleon/node-agent.json
'''%(OUT,OUT))
print('RU DEPLOY:',out,'ERR',err[-800:])

# --- verify console sees both nodes (remote agent via restricted ssh)
out,err=run(ru,'''echo '{"action":"status"}' | timeout 20 ssh -T -o BatchMode=yes -o StrictHostKeyChecking=yes -o IdentitiesOnly=yes -o ConnectTimeout=6 -o UserKnownHostsFile=/root/.ssh/console-known-hosts -i /root/.ssh/console-myserv root@198.51.100.10''')
print('MYSERV AGENT VIA CONSOLE KEY:',out,err[-300:])
rsf.close(); msf.close(); ru.close(); ms.close()
print('DEPLOY DONE')
