#!/usr/bin/env python3
"""One IPv6 Router Solicitation; collect RAs only, do not configure networking.
Run on an explicitly selected owned Linux interface. Neighbor advertisements
are not authenticated allocation evidence and are never automatically applied.
"""
import argparse,datetime,ipaddress,json,pathlib,socket,struct,subprocess,time

def decode_ra(data,source,hoplimit):
    if len(data)<16 or data[0]!=134 or data[1]!=0 or hoplimit!=255:
        raise ValueError('invalid RA header / hop limit')
    if not ipaddress.ip_address(source.split('%')[0]).is_link_local:
        raise ValueError('source is not link-local')
    answer={'source':source,'hop_limit':hoplimit,'managed':bool(data[5]&128),'other':bool(data[5]&64),
            'router_lifetime':struct.unpack('!H',data[6:8])[0],'prefixes':[]}
    i=16
    while i<len(data):
        if i+2>len(data) or data[i+1]==0:raise ValueError('invalid option length')
        size=data[i+1]*8
        if i+size>len(data):raise ValueError('truncated option')
        if data[i]==3:
            if size!=32:raise ValueError('invalid prefix option')
            p=data[i:i+size];prefixlen=p[2];flags=p[3]
            if prefixlen>128:raise ValueError('invalid prefix length')
            valid,preferred=struct.unpack('!II',p[4:12])
            network=ipaddress.IPv6Network((ipaddress.IPv6Address(p[16:32]),prefixlen),strict=False)
            answer['prefixes'].append({'prefix':str(network),'autonomous':bool(flags&64),'on_link':bool(flags&128),
                'valid_seconds':valid,'preferred_seconds':preferred,'slaac_candidate_only':bool(flags&64) and prefixlen==64 and preferred<=valid and valid>0 and network.network_address.is_global})
        i+=size
    return answer

def observe(iface,seconds):
    if not 1<=seconds<=15:raise ValueError('seconds outside 1..15')
    idx=socket.if_nametoindex(iface)
    addresses=json.loads(subprocess.check_output(['ip','-j','-6','addr','show','dev',iface]))
    ll=next(a['local'] for row in addresses for a in row['addr_info'] if a.get('scope')=='link')
    mac=bytes.fromhex((pathlib.Path('/sys/class/net')/iface/'address').read_text().strip().replace(':',''))
    if len(mac)!=6:raise ValueError('Ethernet interface required')
    result={'interface':iface,'started_utc':datetime.datetime.now(datetime.timezone.utc).isoformat(),
            'window_seconds':seconds,'solicitations_sent':0,'router_advertisements':[],
            'configuration_applied':False,'warning':'Observation only; absence is not proof that static IPv6 is unavailable; RAs are unauthenticated.'}
    with socket.socket(socket.AF_INET6,socket.SOCK_RAW,socket.IPPROTO_ICMPV6) as s:
        s.setsockopt(socket.SOL_SOCKET,socket.SO_BINDTODEVICE,iface.encode()+b'\0')
        s.setsockopt(socket.IPPROTO_IPV6,socket.IPV6_MULTICAST_IF,idx)
        s.setsockopt(socket.IPPROTO_IPV6,socket.IPV6_MULTICAST_HOPS,255)
        s.setsockopt(socket.IPPROTO_IPV6,socket.IPV6_UNICAST_HOPS,255)
        s.setsockopt(socket.IPPROTO_IPV6,socket.IPV6_RECVHOPLIMIT,1)
        # Linux icmp6_filter bitmap: pass only ICMPv6 type 134.
        words=[0xffffffff]*8;words[134>>5]&=~(1<<(134&31))
        s.setsockopt(socket.IPPROTO_ICMPV6,1,struct.pack('=8I',*words))
        s.bind(('::',0,0,idx))
        s.setsockopt(socket.IPPROTO_IPV6,socket.IPV6_JOIN_GROUP,socket.inet_pton(socket.AF_INET6,'ff02::1')+struct.pack('@I',idx))
        s.sendto(struct.pack('!BBHI',133,0,0,0)+bytes([1,1])+mac,('ff02::2',0,0,idx))
        result['solicitations_sent']=1
        end=time.monotonic()+seconds
        while time.monotonic()<end:
            s.settimeout(max(0.001,end-time.monotonic()))
            try:data,anc,_,addr=s.recvmsg(4096,256)
            except socket.timeout:break
            hops=next((struct.unpack('i',v)[0] for level,kind,v in anc if level==socket.IPPROTO_IPV6 and kind==socket.IPV6_HOPLIMIT),None)
            try:result['router_advertisements'].append(decode_ra(data,addr[0],hops))
            except ValueError:pass
    return result

if __name__=='__main__':
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('--interface',required=True);p.add_argument('--seconds',type=int,default=6)
    a=p.parse_args();print(json.dumps(observe(a.interface,a.seconds),indent=2))
