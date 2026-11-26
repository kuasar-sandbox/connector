#!/usr/bin/env python3
"""Native Geneve parser, immutable identity and active capacity acceptance.

Uses configuration files, SIGHUP and real UDP sockets. Requires a disposable root
executor; all namespaces, links and processes belong to this invocation.
"""
import argparse
import copy
import hashlib
import signal
import json
import os
from pathlib import Path
import select
import socket
import struct
import subprocess
import sys
import time
import traceback


def checksum(data):
    if len(data) % 2:
        data += b'\0'
    value = sum(struct.unpack('!%dH' % (len(data) // 2), data))
    while value >> 16:
        value = (value & 65535) + (value >> 16)
    return (~value) & 65535


def inner_address(slot):
    # Each Area pair overlaps, while the population exercises native NAT
    # worker selection across many source addresses and both port partitions.
    return socket.inet_ntoa(struct.pack('!I', int.from_bytes(socket.inet_aton('10.7.0.2'), 'big')+slot//2))


def ip_packet(payload, protocol=17, ident=1, fragment=0x4000, ttl=64, source='10.7.0.2'):
    header = struct.pack('!BBHHHBBH4s4s', 0x45, 0, 20+len(payload), ident,
                         fragment, ttl, protocol, 0,
                         socket.inet_aton(source), socket.inet_aton('198.18.1.1'))
    return header[:10] + struct.pack('!H', checksum(header)) + header[12:] + payload


def geneve(slot, area, generation, inner, locator):
    option = bytes.fromhex('01028101') + struct.pack('!I', slot) if locator == 'tlv' else b''
    vni = (slot << 12) | area if locator == 'vni' else area
    header = struct.pack('!BBH', len(option)//4, 0x40 if option else 0, 0x6558)
    header += vni.to_bytes(3, 'big') + b'\0' + option
    return header + bytes.fromhex('02000000000102fe') + struct.pack('!I', generation) + b'\x08\0' + inner


def decode_wire(data):
    option_len = (data[0] & 63) * 4
    offset = 8 + option_len
    assert data[2:4] == b'\x65\x58' and data[offset+12:offset+14] == b'\x08\0'
    inner = data[offset+14:]
    ihl = (inner[0] & 15)*4
    length = int.from_bytes(inner[2:4], 'big')
    assert checksum(inner[:ihl]) == 0 and length == len(inner)
    return dict(vni=int.from_bytes(data[4:7], 'big'), mac=data[offset:offset+6].hex(),
                options=data[8:offset].hex(), inner=inner, ihl=ihl,
                fragment=int.from_bytes(inner[6:8], 'big'), protocol=inner[9])


def peer_process(config):
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, 4 << 20)
    sock.bind((config.get('address','198.18.0.2'), 6081))
    nonce = 0

    def exchange(q):
        nonlocal nonce, sock
        nonce += 1
        slot, flow = q.get('slot', 0), q.get('flow', 0)
        area = q.get('area', 7 + slot % 2)
        marker = struct.pack('!4sHHI', b'EGW'+bytes([config.get('index',0)]), slot & 0xffff, flow, nonce)
        destination_port = (q.get('outer_port',50000+slot) if config['locator']=='port' else 6081)
        if config['locator']=='port' and sock.getsockname()[1]!=destination_port:
            sock.close();sock=socket.socket(socket.AF_INET,socket.SOCK_DGRAM)
            sock.bind((config.get('address','198.18.0.2'),destination_port))
        payload = marker + bytes.fromhex(q.get('extra', ''))
        udp = struct.pack('!HHHH', 31000+flow, 53, 8+len(payload), 0) + payload
        source_ip = q.get('inner_ip',inner_address(slot))
        protocol = 17
        if q.get('tcp'):
            protocol = 6
            tcp = struct.pack('!HHIIBBHHH', 31000+flow, 53, 1, 0, 0x50, 2, 65535, 0, 0)
            pseudo = socket.inet_aton(source_ip)+socket.inet_aton('198.18.1.1')+b'\0\x06'+struct.pack('!H', len(tcp))
            udp = tcp[:16]+struct.pack('!H', checksum(pseudo+tcp))+tcp[18:]
        if q.get('ip_protocol'):
            protocol=q['ip_protocol'];udp=payload
        inner = ip_packet(udp, protocol=protocol, ident=nonce & 65535, fragment=0x4000 if q.get('df', True) else 0, ttl=q.get('ttl', 64), source=source_ip)
        packets = [inner]
        if q.get('fragment_inner'):
            packets = [ip_packet(udp[:24], ident=nonce & 65535, fragment=0x2000, source=source_ip),
                       ip_packet(udp[24:], ident=nonce & 65535, fragment=3, source=source_ip)]
            packets.reverse()  # Native reassembly must handle out-of-order input.
        packets = [geneve(slot, area, q.get('generation', 1), p, config['locator']) for p in packets]
        if q.get('mutations'):
            data = bytearray(packets[0])
            for offset, value in q['mutations']:
                data[offset] = value
            packets = [bytes(data)]
        if q.get('opaque'):
            data = bytearray(packets[0]); offset = 8+(data[0] & 63)*4
            data[offset:offset] = bytes.fromhex('1234020101020304')
            data[0] += 2; packets = [bytes(data)]
        if q.get('max_options'):
            data=bytearray(packets[0]);offset=8+(data[0]&63)*4
            extra=252-(data[0]&63)*4
            data[offset:offset]=bytes.fromhex('12340200')*(extra//4)
            data[0]=63;packets=[bytes(data)]
        if q.get('critical'):
            data = bytearray(packets[0]); offset = 8+(data[0] & 63)*4
            data[offset:offset] = bytes.fromhex('12348200')
            data[0] += 1; data[1] |= 0x40; packets = [bytes(data)]
        outer = None
        if q.get('fragment_outer'):
            payload = struct.pack('!HHHH', 6081, destination_port, 8+len(packets[0]), 0)+packets[0]
            fragments = []
            for offset, data in [(0, payload[:32]), (32, payload[32:])]:
                header = struct.pack('!BBHHHBBH4s4s', 0x45, 0, 20+len(data), nonce & 65535,
                    0x2000 if offset == 0 else offset//8, 64, 17, 0,
                    socket.inet_aton(config.get('address','198.18.0.2')), socket.inet_aton(config.get('gateway','198.18.0.1')))
                fragments.append(header[:10]+struct.pack('!H', checksum(header))+header[12:]+data)
            packets = list(reversed(fragments))
            outer = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_RAW)
        sock.setblocking(False)
        try:
            while True:
                sock.recv(65535)
        except BlockingIOError:
            pass
        result = []
        expect = q.get('expect', True)
        for attempt in range(3 if expect else 1):
            for packet in packets:
                (outer or sock).sendto(packet, (config.get('gateway','198.18.0.1'), destination_port))
            if outer:
                outer.close(); outer = None
            deadline = time.monotonic() + (1 if expect else .25)
            fragments = {}
            while time.monotonic() < deadline:
                sock.settimeout(max(.001, deadline-time.monotonic()))
                try:
                    data, sender = sock.recvfrom(65535)
                except socket.timeout:
                    break
                wire = decode_wire(data)
                inner = wire['inner']
                fragment = wire['fragment']
                if fragment & 0x3fff:
                    fragments[(fragment & 0x1fff)*8] = (inner[wire['ihl']:], bool(fragment & 0x2000))
                    next_offset = 0; pieces = []
                    while next_offset in fragments:
                        part, more = fragments[next_offset]; pieces.append(part); next_offset += len(part)
                        if not more:
                            break
                    else:
                        continue
                    if more:
                        continue
                    body = b''.join(pieces)
                else:
                    body = inner[wire['ihl']:]
                if q.get('ip_protocol') and wire['protocol']==q['ip_protocol'] and body[:12]==marker:
                    assert wire['mac']=='02fe'+struct.pack('!I',q.get('generation',1)).hex()
                    return {'ok':True,'snat':socket.inet_ntoa(body[-4:]),'attempt':attempt}
                if wire['protocol'] == 1:
                    assert checksum(body) == 0
                    if q.get('icmp'):
                        return {'ok': True, 'type': body[0], 'code': body[1], 'mtu': int.from_bytes(body[6:8], 'big'),
                                'quote': body[8:].hex(), 'mac': wire['mac'], 'source':socket.inet_ntoa(inner[12:16])}
                    continue
                if wire['protocol'] != 17 or body[8:20] != marker:
                    continue
                assert expect, ('unexpected authorized return', q)
                source, target, length, csum = struct.unpack('!HHHH', body[:8])
                assert (source, target) == (53, 31000+flow)
                assert inner[12:16] == socket.inet_aton('198.18.1.1')
                assert inner[16:20] == socket.inet_aton(source_ip)
                if csum:
                    assert checksum(inner[12:20]+b'\0\x11'+struct.pack('!H', length)+body[:length]) == 0
                assert wire['mac'] == '02fe'+struct.pack('!I', q.get('generation', 1)).hex()
                assert wire['vni']==((slot<<12)|area if config['locator']=='vni' else area)
                if config['locator']=='tlv':assert wire['options']=='01028101'+struct.pack('!I',slot).hex()
                return {'ok': True, 'peer': [socket.inet_ntoa(body[length-6:length-2]), int.from_bytes(body[length-2:length], 'big')],
                        'options': wire['options'], 'fragments': len(fragments), 'payload_bytes': length-14, 'attempt': attempt}
            if not expect:
                return {'ok': True, 'rejected': True}
        raise AssertionError(('no valid return', q, result))

    for line in sys.stdin:
        q = json.loads(line); started = time.monotonic()
        try:
            if q.get('op') == 'keepalive':
                until=time.monotonic()+q['seconds'];count=0
                while time.monotonic()<until:
                    exchange({'slot':q['slot']});count+=1
                result=dict(ok=True,echoed=count)
            elif q.get('op') == 'stage':
                count = retries = 0; tuples = set()
                for slot in range(q['contexts']):
                    for flow in range(q['flows']):
                        item = exchange({'slot': slot, 'flow': flow})
                        count += 1; retries += item['attempt']; tuples.add(tuple(item['peer']))
                result = dict(ok=True, echoed=count, retries=retries, public_tuples=len(tuples))
            else:
                result = exchange(q)
        except Exception:
            result = dict(ok=False, error=traceback.format_exc())
        result['elapsed'] = time.monotonic()-started
        print(json.dumps(result), flush=True)


def backend_process():
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.setsockopt(socket.IPPROTO_IP, 10, 0)  # IP_MTU_DISCOVER: permit fragmentation.
    sock.bind(('203.0.113.11', 18080))
    direct = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    direct.bind(('198.18.1.1', 53))
    listener = socket.socket(); listener.bind(('203.0.113.11', 18080)); listener.listen(32)
    raw = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_TCP)
    errors = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_ICMP)
    other=socket.socket(socket.AF_INET,socket.SOCK_RAW,253);other.bind(('198.18.1.1',0))
    while True:
        ready, _, _ = select.select([sock, direct, raw, other], [], [])
        if other in ready:
            packet=other.recv(65535);ihl=(packet[0]&15)*4
            if packet[16:20]==socket.inet_aton('198.18.1.1'):
                other.sendto(packet[ihl:]+packet[12:16],(socket.inet_ntoa(packet[12:16]),0))
        if raw in ready:
            packet = raw.recv(65535); ihl = (packet[0] & 15)*4
            if packet[16:20] == socket.inet_aton('203.0.113.11') and packet[ihl+13] & 2:
                message = b'\x03\x01\0\0\0\0\0\0' + packet[:ihl+8]
                message = message[:2]+struct.pack('!H', checksum(message))+message[4:]
                errors.sendto(message, (socket.inet_ntoa(packet[12:16]), 0))
        for udp in (sock,direct):
            if udp in ready:
                data, peer = udp.recvfrom(65535)
                if data[12:13] == b'L':
                    data = data[:12] + b'z'*int.from_bytes(data[13:15], 'big')
                udp.sendto(data + socket.inet_aton(peer[0]) + struct.pack('!H', peer[1]), peer)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--ctl', required=True)
    parser.add_argument('--runtime', required=True, help='Connector bin directory containing connector-vpp and vpp-runtime.json')
    parser.add_argument('--output', required=True)
    parser.add_argument('--contexts', type=int, default=32)
    parser.add_argument('--flows', type=int, default=16)
    parser.add_argument('--locator', choices=['port','vni', 'tlv'], default='vni')
    args = parser.parse_args()
    assert os.geteuid() == 0 and 2 <= args.contexts <= 65536
    peer_keys=['p'+str(i) for i in range(max(2,(args.contexts+4095)//4096))]
    out = Path(args.output).resolve(); out.mkdir(mode=0o700, parents=True, exist_ok=False)
    tag = 'w'+str(os.getpid()); namespaces = {key: tag+key for key in ['eg', *peer_keys, 'out']}
    children = []; files = []; commands = []; checks = []; metrics = {}
    result = dict(pass_=False, architecture=os.uname().machine, contexts=args.contexts, flows=args.flows,
                  locator=args.locator, checks=checks, metrics=metrics)

    def run(*command, check=True, timeout=30):
        p = subprocess.run(list(map(str, command)), capture_output=True, text=True, timeout=timeout)
        commands.append(dict(argv=list(map(str, command)), rc=p.returncode, stdout=p.stdout, stderr=p.stderr))
        if check and p.returncode:
            raise RuntimeError(commands[-1])
        return p

    def check(name, condition, actual=None):
        checks.append(dict(name=name, passed=bool(condition), actual=actual)); print(name, bool(condition), flush=True)
        if not condition:
            raise AssertionError(checks[-1])

    def status():
        return json.loads((out/'runtime/status.json').read_text())
    def check_static_native(phase):
        pid = status()['native_pid']
        executable = Path('/proc', str(pid), 'exe').resolve()
        check('selected static dataplane executable ('+phase+')',
              executable == runtime/'connector-vpp', str(executable))
        mappings = Path('/proc', str(pid), 'maps').read_text()
        (out/('native-maps-'+phase+'.txt')).write_text(mappings)
        foreign = []
        for line in mappings.splitlines():
            fields = line.split(None, 5)
            if len(fields) != 6 or not fields[5].startswith('/'):
                continue
            path = fields[5].removesuffix(' (deleted)')
            if path != str(executable) and ('x' in fields[1] or '.so' in Path(path).name):
                foreign.append(line)
        check('no shared libraries mapped ('+phase+')', not foreign, foreign)
    def wait_status(predicate, timeout=20):
        until=time.monotonic()+timeout; st={}
        while time.monotonic()<until:
            if gateway.poll() is not None:raise RuntimeError((out/'gateway.log').read_text())
            try:
                st=status()
                if st.get('pid')==gateway.pid and predicate(st):return st
            except (FileNotFoundError,json.JSONDecodeError):pass
            time.sleep(.05)
        raise AssertionError(('state timeout',st))
    def reload_config(value, timeout=20, yaml=False):
        before=status()['configuration_generation']
        tmp=config.with_suffix('.next');tmp.write_text('# Main YAML\n'+''.join(k+': '+json.dumps(v)+'\n' for k,v in value.items()) if yaml else json.dumps(value));tmp.replace(config)
        gateway.send_signal(signal.SIGHUP)
        return wait_status(lambda st: st['configuration_generation']>before,timeout=timeout)
    def reject_reload(value):
        before=status()['configuration_generation']
        tmp=config.with_suffix('.next');tmp.write_text(json.dumps(value));tmp.replace(config)
        gateway.send_signal(signal.SIGHUP)
        return wait_status(lambda st: st['configuration_generation']==before and bool(st.get('reload_error')))
    def area_update(value):
        current=copy.deepcopy(cfg)
        current['areas']=[value if a['vni']==value['vni'] else a for a in cfg['areas']]
        reload_config(current)
        cfg.update(current)
    def expire_all():
        saved=copy.deepcopy(cfg['timeouts'])
        cfg['timeouts']={key:2 for key in saved};reload_config(cfg)
        st=wait_status(lambda st: st['contexts']==0 and st['connections']==0,timeout=40)
        cfg['timeouts']=saved;reload_config(cfg)
        return st

    def spawn(command, log=None, env=None):
        if log:
            output = (out/log).open('w'); files.append(output)
            p = subprocess.Popen(command, stdout=output, stderr=output, env=env, text=True)
        else:
            p = subprocess.Popen(command, stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE, env=env, text=True)
        children.append(p); return p

    def query(peer, **q):
        peer.stdin.write(json.dumps(q)+'\n'); peer.stdin.flush()
        answer = json.loads(peer.stdout.readline())
        if not answer['ok']:
            raise AssertionError(answer)
        return answer

    try:
        run(sys.executable, Path(__file__).with_name('runtime.py'), 'validate',
            '--arch', os.uname().machine, '--runtime', args.runtime)
        for name in namespaces.values():
            run('ip', 'netns', 'add', name); run('ip', '-n', name, 'link', 'set', 'lo', 'up')
        for index, key in enumerate([*peer_keys, 'out']):
            local, peer = tag+'i'+str(index), tag+'p'+str(index)
            run('ip', 'link', 'add', local, 'type', 'veth', 'peer', 'name', peer)
            run('ip', 'link', 'set', local, 'netns', namespaces['eg']); run('ip', 'link', 'set', peer, 'netns', namespaces[key])
            mtu = 1500 if key == 'out' else 9000
            for ns, dev in [(namespaces['eg'], local), (namespaces[key], peer)]:
                run('ip', '-n', ns, 'link', 'set', dev, 'mtu', mtu, 'up')
                run('ip', 'netns', 'exec', ns, 'ethtool', '-K', dev, 'tx', 'off', 'rx', 'off', 'gso', 'off', 'gro', 'off', 'tso', 'off')
            run('ip', '-n', namespaces[key], 'addr', 'add', '192.0.2.2/24' if key == 'out' else '198.18.0.2/24', 'dev', peer)
        run('ip', '-n', namespaces['out'], 'addr', 'add', '203.0.113.11/32', 'dev', 'lo')
        run('ip','-n',namespaces['out'],'addr','add','198.18.1.1/32','dev','lo')
        run('ip', 'netns', 'exec', namespaces['out'], 'sysctl', '-qw', 'net.ipv4.conf.all.arp_announce=2')
        runtime = Path(args.runtime).resolve()
        cpus = sorted(os.sched_getaffinity(0))
        if len(cpus)<2:raise RuntimeError('native acceptance requires at least two CPUs')
        result['workers']=min(2,len(cpus)-1)
        cfg = dict(name=tag, runtime_dir=str(out/'runtime'), vpp=str(runtime/'connector-vpp'),
                   main_core=cpus[0], workers=cpus[1:3],
                   timeouts=dict(udp=900,tcp_transitory=900,tcp_established=900,icmp=900), interfaces=[], attachments=[], areas=[])
        for index in range(len(peer_keys)+1):
            cfg['interfaces'].append(dict(name=tag+'i'+str(index), address='192.0.2.1/24' if index == len(peer_keys) else '198.18.0.%d/24'%(1+index*2), mtu=1500 if index == len(peer_keys) else 9000))
        wide_policy = args.locator == 'tlv' and args.contexts == 32
        if wide_policy:
            extra_addresses = ['198.51.%d.%d' % (i//256,i%256) for i in range(1,258)]
            run('ip','-n',namespaces['out'],'route','add','198.51.0.0/16','via','192.0.2.1')
        for area in [7, 8]:
            cfg['areas'].append(dict(vni=area, pools=[dict(name='public',interface=tag+'i'+str(len(peer_keys)),next_hop='192.0.2.2',addresses=['192.0.2.'+str(i) for i in ([1,4,6,8] if area==7 else [3,5,7,9])], max_connections=args.flows)],
                acl=[dict(destination='198.18.1.1/32', protocol='any', action='allow')], routes=[dict(destination='0.0.0.0/0',pool='public')],
                dnat=[dict(destination='198.18.1.1/32', protocol=protocol, pool='public', target='203.0.113.11', target_port=18080) for protocol in ['udp','tcp']]))
        for index, peer in enumerate(peer_keys):
            attachment=dict(name=peer, interface=tag+'i'+str(index),peer=['198.18.0.2'],locator=args.locator,mtu=1500)
            if args.locator=='tlv':attachment.update(tlv_class=258,tlv_type=129)
            cfg['attachments'].append(attachment)
        config = out/'gateway.json'; config.write_text(json.dumps(cfg))
        gateway = spawn(['ip', 'netns', 'exec', namespaces['eg'], args.ctl, 'egress', 'serve', '--config', str(config)], 'gateway.log')
        wait_status(lambda st: st['configuration_generation']==1,timeout=120)
        check_static_native('startup')
        spawn(['ip', 'netns', 'exec', namespaces['out'], sys.executable, __file__, 'backend'], 'backend.log')
        peers = [spawn(['ip', 'netns', 'exec', namespaces[key], sys.executable, __file__, 'peer', json.dumps({'locator': args.locator,'index':index,'gateway':'198.18.0.%d'%(1+index*2)})]) for index,key in enumerate(peer_keys)]
        a = query(peers[0]); b = query(peers[1])
        check('same peer locator and inner IP at different gateway IPs remain independent', a['peer'] != b['peer'], [a, b])
        generation=query(peers[0],generation=2)
        check('new generation is learned automatically and keeps its own return marker',generation['peer']!=a['peer'])
        check('previous forwarding context keeps its original return marker',query(peers[0])['peer']==a['peer'])
        generic=query(peers[0],ip_protocol=253)
        check('ordinary IPv4 protocol uses selected SNAT Pool',generic['snat'] in cfg['areas'][0]['pools'][0]['addresses'],generic)
        opaque = query(peers[0], opaque=True)
        check('opaque noncritical options are not reflected', opaque['options'] == ('0102810100000000' if args.locator == 'tlv' else ''), opaque)
        check('full protocol option length accepts opaque noncritical metadata',query(peers[0],max_options=True)['ok'])
        for label, mutations in [('version', [[0, 0x40]]), ('reserved flags', [[1, 1]]), ('reserved byte', [[7, 1]]), ('unknown Area', [[6, 9]])]:
            query(peers[0], mutations=mutations, expect=False); check('reject '+label, True)
        query(peers[0], critical=True, expect=False); check('reject unknown critical option', True)
        check('native outer reassembly accepts out-of-order UDP fragments',query(peers[0],fragment_outer=True)['ok'])
        fragmented = query(peers[0], fragment_inner=True, extra=(b'x'*80).hex())
        check('native inner reassembly retains session identity', fragmented['ok'])
        large = query(peers[0], extra=(b'L'+struct.pack('!H', 2000)).hex())
        check('large return reassembles and fragments within tunnel MTU', large['fragments'] >= 2 and large['payload_bytes'] == 2012, large)
        before = wait_status(lambda st: st['connections']>=3)
        pmtu = query(peers[0], flow=20, extra=(b'p'*1700).hex(), icmp=True)
        check('pre-NAT DF error contains original tuple', pmtu['type'] == 3 and pmtu['code'] == 4 and pmtu['mtu'] == 1500 and pmtu['source']=='198.18.0.1' and bytes.fromhex(pmtu['quote'])[12:16] == socket.inet_aton('10.7.0.2'), pmtu)
        time.sleep(1.2); after = status()
        check('PMTU failure does not reserve quota', sum(p['current'] for p in before['pools']) == sum(p['current'] for p in after['pools']))
        quoted = query(peers[0], flow=21, tcp=True, icmp=True)
        quote = bytes.fromhex(quoted['quote'])
        check('native ICMP translates an eight-byte TCP quote', quoted['type'] == 3 and quoted['code'] == 1 and len(quote) == 28 and quote[12:16] == socket.inet_aton('10.7.0.2') and quote[16:20] == socket.inet_aton('198.18.1.1') and struct.unpack('!HH',quote[20:24]) == (31021,53) and checksum(quote[:20]) == 0, quoted)
        original_area=copy.deepcopy(cfg['areas'][0])
        changed = copy.deepcopy(original_area); changed['dnat'][0]['target_port'] = 18081
        area_update(changed)
        check('DNAT reload preserves established mapping',query(peers[0])['peer']==a['peer'])
        query(peers[0],flow=22,expect=False)
        check('new flows use reloaded DNAT target',True)
        area_update(original_area)
        changed=copy.deepcopy(original_area);changed['pools'][0]['addresses']=['192.0.2.3']
        area_update(changed)
        check('SNAT reload preserves established public tuple',query(peers[0])['peer']==a['peer'])
        check('new mapping uses reloaded SNAT resource',query(peers[0],flow=23)['peer'][0]=='192.0.2.3')
        area_update(original_area)
        if args.locator=='tlv':
            ids=[5000,0x80000000,0xffffffff]
            tuples=[query(peers[0],slot=i,area=7)['peer'] for i in ids]
            check('arbitrary 32-bit TLV locators retain independent return identities',len({tuple(x) for x in tuples})==len(ids),ids)
        elif args.locator=='port':
            for slot in [5000,15535]:query(peers[0],slot=slot,area=7)
            query(peers[0],slot=100,area=7,outer_port=1234)
            check('UDP locators outside the vSwitch port block are accepted and reflected',True)
        empty=expire_all();check('idle forwarding contexts and NAT expire without release',empty['reclaimed']>=3,empty)
        if args.contexts<=32:
            timeouts=copy.deepcopy(cfg['timeouts'])
            cfg['timeouts']={key:2 for key in timeouts};reload_config(cfg)
            query(peers[0],slot=1)
            start=status()['reclaimed']
            peers[1].stdin.write(json.dumps(dict(op='keepalive',slot=1,seconds=15))+'\n');peers[1].stdin.flush()
            observed=wait_status(lambda st: st['contexts']==1 and st['connections']==1 and st['reclaimed']>start,timeout=12)
            active=json.loads(peers[1].stdout.readline())
            check('idle context is reclaimed while another peer continuously exchanges traffic',active['ok'] and active['echoed']>=100,dict(status=observed,traffic=active))
            expire_all()
            cfg['timeouts']=timeouts;reload_config(cfg)
        # Exercise the original user-facing defaults using YAML main/Area
        # files and a real SNAT CIDR, not only a parser or native CLI fixture.
        source=copy.deepcopy(cfg)
        source['area_files']=['original-area.yaml']
        policy={'vni':10,'pools':[dict(name='default',interface=tag+'i'+str(len(peer_keys)),
                    next_hop='192.0.2.2',addresses=['192.0.2.12/31','192.0.2.12-192.0.2.13'])]}
        area_source=out/'original-area.yaml'
        def publish_original():
            area_source.write_text('# Original Area contract\n'+''.join(k+': '+json.dumps(v)+'\n' for k,v in policy.items()))
            reload_config(source,yaml=True)
        publish_original()
        original_default=query(peers[0],slot=12,area=10)['peer']
        check('YAML omitted ACL and single-Pool omitted routes forward through a CIDR Pool',
              original_default[0] in ['192.0.2.12','192.0.2.13'],original_default)
        policy['acl']=[];publish_original()
        check('empty ACL allows and reload retains the established mapping',
              query(peers[0],slot=12,area=10)['peer']==original_default)
        policy['acl']=[dict(destination='203.0.113.0/24',protocol=['tcp','udp'],ports=[53,'8000-8002'],action='deny')]
        publish_original()
        check('unmatched nonempty ACL retains default allow',query(peers[0],slot=12,area=10)['peer']==original_default)
        policy['acl'].insert(0,dict(destination='198.18.1.1',protocol='udp',ports=53,action='deny'))
        publish_original();query(peers[0],slot=12,area=10,expect=False)
        check('collection deny revokes an established default-allowed mapping',True)
        policy['acl']=[dict(action='allow'),dict(action='deny')];policy['routes']=[]
        publish_original();query(peers[0],slot=12,area=10,flow=1,expect=False)
        check('explicit empty routes suppress ordinary forwarding',True)
        policy['dnat']=[dict(destination='198.18.1.1-198.18.1.1',protocol=['tcp','udp'],ports='53-53',pool='default',target='203.0.113.11',target_port=18080)]
        publish_original();query(peers[0],slot=12,area=10,flow=2)
        check('DNAT collections still forward with explicit empty ordinary routes',True)
        reload_config(cfg);expire_all()
        # Aggregate multiple unchanged 4096-slot switch locators. No registration
        # calls and no artificial gateway-wide 4096 limit are used.
        def process_memory():
            pid=status()['native_pid']
            lines=Path('/proc/'+str(pid)+'/status').read_text().splitlines()
            return {line.split(':')[0]:line.split(':')[1].strip() for line in lines if line.startswith(('VmRSS:','VmHWM:','VmSize:','Threads:'))}
        metrics['memory_before_capacity']=process_memory()
        capacity_started=time.monotonic()
        active=[];left=args.contexts
        for peer in peers:
            count=min(left,4096)
            if not count:break
            row=query(peer,op='stage',contexts=count,flows=args.flows)
            active.append(row);left-=count
            print('active contexts',args.contexts-left,flush=True)
        metrics['traffic']=active
        metrics['capacity_seconds']=time.monotonic()-capacity_started
        metrics['memory_at_capacity']=process_memory()
        check('every active connection completes real echo',sum(row['echoed'] for row in active)==args.contexts*args.flows and sum(row['public_tuples'] for row in active)==args.contexts*args.flows,active)
        state=wait_status(lambda st: st['contexts']==args.contexts and st['connections']==args.contexts*args.flows)
        (out/'active-status.json').write_text(json.dumps(state))
        check('native active contexts exceed a single switch capacity when requested',state['contexts']==args.contexts,state['contexts'])
        check('native quota equals simultaneous active mappings',sum(p['current'] for p in state['pools'])==args.contexts*args.flows)
        original=query(peers[0])['peer']
        low=copy.deepcopy(cfg['areas'][0]);low['pools'][0]['max_connections']=1
        started=time.monotonic();area_update(low);metrics['policy_update_seconds']=time.monotonic()-started
        check('lower quota retains established public tuple',query(peers[0])['peer']==original)
        query(peers[0],flow=args.flows,expect=False);check('lower quota blocks only new mappings',True)
        deny=copy.deepcopy(low);deny['acl']=[dict(action='deny')];area_update(deny)
        query(peers[0],expect=False);check('ACL revocation blocks established forward mapping',True)
        query(peers[0],slot=1);check('other Area retains live mapping',True)
        state=wait_status(lambda st: st['connections']==(args.contexts//2)*args.flows)
        check('only revoked Area mappings are released',state['connections']==(args.contexts//2)*args.flows,state['connections'])
        second=copy.deepcopy(cfg['areas'][1]);second['acl']=[dict(action='deny')];area_update(second)
        state=wait_status(lambda st: st['contexts']==0 and st['connections']==0)
        check('ACL revocation releases contexts and quota automatically',state['reclaimed']>=args.contexts,state)
        area_update(original_area)
        query(peers[0],generation=2)
        check('reused resource accepts valid traffic without a new control-plane identity',True)
        # VNI selects the configured Area, with no per-Area attachment entry.
        retained=query(peers[0],generation=2)['peer']
        new_area=copy.deepcopy(original_area);new_area['vni']=9
        cfg['areas'].append(new_area);reload_config(cfg)
        area9=query(peers[0],area=9)['peer']
        check('new Area is usable through the existing ingress without registration',area9!=retained)
        broken=copy.deepcopy(cfg);broken['areas'][0]['acl']=[dict(action='deny')];broken['areas'][-1]['routes'][0]['pool']='missing'
        rejected=reject_reload(broken)
        check('invalid later Area leaves the whole previous configuration active',
              query(peers[0],generation=2)['peer']==retained and query(peers[0],area=9)['peer']==area9,rejected['reload_error'])
        cfg['areas']=cfg['areas'][:-1];reload_config(cfg)
        query(peers[0],area=9,expect=False)
        check('Area removal revokes only that VNI',query(peers[0],generation=2)['peer']==retained)
        # One source range can admit many distinct actual peers, then revoke
        # one without changing another peer or gateway's established mapping.
        run('ip','-n',namespaces[peer_keys[0]],'addr','add','198.18.0.20/24','dev',tag+'p0')
        changed_peer=spawn(['ip','netns','exec',namespaces[peer_keys[0]],sys.executable,__file__,'peer',
                           json.dumps({'locator':args.locator,'index':0,'address':'198.18.0.20'})])
        query(changed_peer,expect=False)
        cfg['attachments'][0]['peer']='198.18.0.2-198.18.0.20';reload_config(cfg)
        second_source=query(changed_peer)['peer']
        check('source range admits distinct actual peer identities',second_source!=retained)
        del cfg['attachments'][0]['peer'];reload_config(cfg)
        check('omitted peer preserves the actual peer and return mapping',query(changed_peer)['peer']==second_source)
        cfg['attachments'][0]['peer']=['198.18.0.2','198.18.0.20'];reload_config(cfg)
        check('multiple allowed IPs preserve existing peer mappings',query(peers[0],generation=2)['peer']==retained)
        cfg['attachments'][0]['peer']=['198.18.0.2'];reload_config(cfg)
        query(changed_peer,expect=False)
        check('source admission removal preserves another peer mapping',query(peers[0],generation=2)['peer']==retained)
        # All inner IPs of one outer identity share its Pool quota.
        for i in range(args.flows):
            query(peers[0],slot=625,area=7,inner_ip='10.99.%d.%d'%(i//250,i%250+1))
        query(peers[0],slot=625,area=7,inner_ip='10.98.0.1',expect=False)
        query(peers[0],slot=625,area=7,generation=2,inner_ip='10.98.0.1',expect=False)
        query(peers[0],slot=626,area=7,inner_ip='10.98.0.1')
        check('multiple inner IPs share one access allowance while another locator is independent',True)
        # Moving a Pool to an already admitted transit interface exercises
        # both resource versioning and unambiguous ingress/exit sharing.
        run('ip','netns','exec',namespaces[peer_keys[0]],'sysctl','-qw','net.ipv4.conf.all.arp_announce=2')
        run('ip','-n',namespaces[peer_keys[0]],'addr','add','203.0.113.11/32','dev','lo')
        run('ip','-n',namespaces[peer_keys[0]],'addr','add','198.18.1.1/32','dev','lo')
        spawn(['ip','netns','exec',namespaces[peer_keys[0]],sys.executable,__file__,'backend'],'shared-backend.log')
        changed=copy.deepcopy(cfg['areas'][0]);changed['pools'][0].update(interface=tag+'i0',next_hop='198.18.0.2',addresses=['198.18.0.10'])
        area_update(changed)
        check('Pool interface reload retains old connection exit',query(peers[0],generation=2)['peer']==retained)
        new_exit=query(peers[0],slot=627,area=7)['peer']
        check('new connections use a shared ingress and exit interface',new_exit[0]=='198.18.0.10',new_exit)
        area_update(original_area)
        check('old shared-interface mapping survives restoration of Pool definition',query(peers[0],slot=627,area=7)['peer']==new_exit)
        for profile in cfg['attachments']:
            if profile['interface']==cfg['attachments'][0]['interface']:profile['mtu']=1400
        reload_config(cfg)
        mtu_return=query(peers[0],generation=2,extra=(b'L'+struct.pack('!H',2000)).hex())
        check('attachment MTU reload applies while retaining the mapping',mtu_return['peer']==retained and mtu_return['fragments']>=2)
        expire_all();check('reload-created contexts are reclaimed without lifecycle notification',True)
        # A newly admitted VTEP cannot steal a still-live public NAT address.
        # Rejection is atomic, and the same config can load after idle expiry.
        if args.contexts <= 32:
            saved=copy.deepcopy(cfg)
            first=copy.deepcopy(cfg['areas'][0]);first['pools'][0]['addresses']=['192.0.2.1'];area_update(first)
            old_public=query(peers[0],generation=2)['peer']
            assert old_public[0]=='192.0.2.1'
            first['pools'][0]['addresses']=['192.0.2.4'];area_update(first)
            candidate=copy.deepcopy(cfg)
            candidate['attachments'].append(dict(name='new-vtep',interface=tag+'i'+str(len(peer_keys)),peer=['192.0.2.2']))
            rejected=reject_reload(candidate)
            check('reload rejects VTEP overlap with a retained SNAT mapping atomically',
                  'retained' in rejected['reload_error'] and query(peers[0],generation=2)['peer']==old_public,
                  rejected['reload_error'])
            expire_all();reload_config(candidate)
            check('VTEP address becomes available after old NAT mappings expire',True)
            cfg=saved;reload_config(cfg)
        if wide_policy:
            retained = query(peers[0],generation=2)['peer']
            baseline = copy.deepcopy(cfg)
            wide = copy.deepcopy(cfg)
            area = wide['areas'][0]
            area['pools'][0]['addresses'] += extra_addresses
            area['pools'] += [dict(name='pool-'+str(i),interface=tag+'i'+str(len(peer_keys)),next_hop='192.0.2.2',addresses=['192.0.2.1'],max_connections=1)
                              for i in range(1,1025)]
            area['pools'].append(dict(name='large-name-4294967295',interface=tag+'i'+str(len(peer_keys)),next_hop='192.0.2.2',addresses=['192.0.2.1'],max_connections=1))
            area['acl'] = [dict(destination='10.%d.%d.0/24' % (i//256,i%256),protocol='any',action='deny')
                           for i in range(4097)] + area['acl']
            area['routes'] = [dict(destination='10.%d.%d.0/24' % (i//256,i%256),pool='large-name-4294967295')
                              for i in range(4097)] + [dict(destination='0.0.0.0/0',pool='large-name-4294967295')]
            area['dnat'] = [dict(destination='10.%d.%d.0/24' % (i//256,i%256),protocol='udp',pool='large-name-4294967295',
                                target='203.0.113.11',target_port=18080) for i in range(4097)] + area['dnat']
            for rule in area['dnat']: rule['pool']='large-name-4294967295'
            for i in range(257):
                extra=copy.deepcopy(original_area);extra['vni']=1000+i;wide['areas'].append(extra)
                profile=copy.deepcopy(wide['attachments'][0]);profile.update(name='wide-'+str(i),peer=['198.51.%d.%d'%(i//250,i%250+1)])
                wide['attachments'].append(profile)
            reload_config(wide,timeout=120);cfg=wide
            check('large policy preserves established Pool mapping',query(peers[0],generation=2)['peer']==retained)
            query(peers[0],slot=5000)
            query(peers[0],slot=5000,flow=1,expect=False)
            query(peers[0],slot=5001,area=7)
            query(peers[0],area=1256)
            check('dynamic Areas named Pools source ranges rules and TLV IDs exceed prior fixed limits',True,
                  dict(areas=len(wide['areas']),attachments=len(wide['attachments']),
                       pools=len(area['pools']),acl=len(area['acl']),dnat=len(area['dnat']),routes=len(area['routes']),
                       pool_name='large-name-4294967295',tlv_locator=5000,snat_addresses=len(area['pools'][0]['addresses'])))
            area['pools'].reverse();reload_config(wide,timeout=120)
            query(peers[0],slot=5000,flow=1,expect=False)
            check('Pool reorder retains named quota and old flows',query(peers[0],generation=2)['peer']==retained)
            area['pools']=[p for p in area['pools'] if p['name']!='large-name-4294967295']
            for rule in [*area['routes'],*area['dnat']]:rule['pool']='pool-1'
            reload_config(wide,timeout=120)
            query(peers[0],slot=5000)
            check('removed named Pool releases mappings without affecting other Pools',query(peers[0],generation=2)['peer']==retained)
            cfg=baseline;reload_config(cfg)
            query(peers[0],slot=5000)
            expire_all()
            check('dynamic policy shrink reclaims forwarding state',status()['connections']==0)
        check_static_native('traffic')
        result['pass_'] = True
    except Exception:
        result['error'] = traceback.format_exc(); raise
    finally:
        for p in reversed(children):
            if p.poll() is None:
                p.terminate()
                try:
                    p.wait(timeout=4)
                except subprocess.TimeoutExpired:
                    p.kill(); p.wait()
        for name in namespaces.values():
            run('ip', 'netns', 'del', name, check=False)
        for f in files:
            f.close()
        result['pass'] = result.pop('pass_')
        (out/'result.json').write_text(json.dumps(result, indent=2))
        (out/'commands.json').write_text(json.dumps(commands, indent=2))


if __name__ == '__main__':
    if len(sys.argv) > 1 and sys.argv[1] == 'peer':
        peer_process(json.loads(sys.argv[2]))
    elif len(sys.argv) > 1 and sys.argv[1] == 'backend':
        backend_process()
    else:
        main()
