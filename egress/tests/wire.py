#!/usr/bin/env python3
"""Native Geneve parser, immutable identity and active capacity acceptance.

Uses the public control API and real UDP sockets. Requires a disposable root
executor; all namespaces, links and processes belong to this invocation.
"""
import argparse
import copy
import hashlib
import http.client
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
    sock.bind(('198.18.0.2', 6081))
    nonce = 0

    def exchange(q):
        nonlocal nonce
        nonce += 1
        slot, flow = q.get('slot', 0), q.get('flow', 0)
        area = q.get('area', 7 + slot % 2)
        marker = struct.pack('!4sHHI', b'EGWT', slot, flow, nonce)
        payload = marker + bytes.fromhex(q.get('extra', ''))
        udp = struct.pack('!HHHH', 31000+flow, 53, 8+len(payload), 0) + payload
        protocol = 17
        if q.get('tcp'):
            protocol = 6
            tcp = struct.pack('!HHIIBBHHH', 31000+flow, 53, 1, 0, 0x50, 2, 65535, 0, 0)
            pseudo = socket.inet_aton('10.7.0.2')+socket.inet_aton('198.18.1.1')+b'\0\x06'+struct.pack('!H', len(tcp))
            udp = tcp[:16]+struct.pack('!H', checksum(pseudo+tcp))+tcp[18:]
        inner = ip_packet(udp, protocol=protocol, ident=nonce & 65535, fragment=0x4000 if q.get('df', True) else 0, ttl=q.get('ttl', 64), source=inner_address(slot))
        packets = [inner]
        if q.get('fragment_inner'):
            packets = [ip_packet(udp[:24], ident=nonce & 65535, fragment=0x2000, source=inner_address(slot)),
                       ip_packet(udp[24:], ident=nonce & 65535, fragment=3, source=inner_address(slot))]
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
        if q.get('critical'):
            data = bytearray(packets[0]); offset = 8+(data[0] & 63)*4
            data[offset:offset] = bytes.fromhex('12348200')
            data[0] += 1; data[1] |= 0x40; packets = [bytes(data)]
        outer = None
        if q.get('fragment_outer'):
            payload = struct.pack('!HHHH', 6081, 6081, 8+len(packets[0]), 0)+packets[0]
            fragments = []
            for offset, data in [(0, payload[:32]), (32, payload[32:])]:
                header = struct.pack('!BBHHHBBH4s4s', 0x45, 0, 20+len(data), nonce & 65535,
                    0x2000 if offset == 0 else offset//8, 64, 17, 0,
                    socket.inet_aton('198.18.0.2'), socket.inet_aton('198.18.0.1'))
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
                (outer or sock).sendto(packet, ('198.18.0.1', 6081))
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
                if wire['protocol'] == 1:
                    assert checksum(body) == 0
                    if q.get('icmp'):
                        return {'ok': True, 'type': body[0], 'code': body[1], 'mtu': int.from_bytes(body[6:8], 'big'),
                                'quote': body[8:].hex(), 'mac': wire['mac']}
                    continue
                if wire['protocol'] != 17 or body[8:20] != marker:
                    continue
                assert expect, ('unexpected authorized return', q)
                source, target, length, csum = struct.unpack('!HHHH', body[:8])
                assert (source, target) == (53, 31000+flow)
                assert inner[12:16] == socket.inet_aton('198.18.1.1')
                assert inner[16:20] == socket.inet_aton(inner_address(slot))
                if csum:
                    assert checksum(inner[12:20]+b'\0\x11'+struct.pack('!H', length)+body[:length]) == 0
                assert wire['mac'] == '02fe'+struct.pack('!I', q.get('generation', 1)).hex()
                return {'ok': True, 'peer': [socket.inet_ntoa(body[length-6:length-2]), int.from_bytes(body[length-2:length], 'big')],
                        'options': wire['options'], 'fragments': len(fragments), 'payload_bytes': length-14, 'attempt': attempt}
            if not expect:
                return {'ok': True, 'rejected': True}
        raise AssertionError(('no valid return', q, result))

    for line in sys.stdin:
        q = json.loads(line); started = time.monotonic()
        try:
            if q.get('op') == 'stage':
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
    listener = socket.socket(); listener.bind(('203.0.113.11', 18080)); listener.listen(32)
    raw = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_TCP)
    errors = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_ICMP)
    while True:
        ready, _, _ = select.select([sock, raw], [], [])
        if raw in ready:
            packet = raw.recv(65535); ihl = (packet[0] & 15)*4
            if packet[16:20] == socket.inet_aton('203.0.113.11') and packet[ihl+13] & 2:
                message = b'\x03\x01\0\0\0\0\0\0' + packet[:ihl+8]
                message = message[:2]+struct.pack('!H', checksum(message))+message[4:]
                errors.sendto(message, (socket.inet_ntoa(packet[12:16]), 0))
        if sock in ready:
            data, peer = sock.recvfrom(65535)
            if data[12:13] == b'L':
                data = data[:12] + b'z'*int.from_bytes(data[13:15], 'big')
            sock.sendto(data + socket.inet_aton(peer[0]) + struct.pack('!H', peer[1]), peer)


class UnixHTTP(http.client.HTTPConnection):
    def __init__(self, path):
        super().__init__('localhost', timeout=120); self.path = str(path)

    def connect(self):
        self.sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        self.sock.settimeout(self.timeout); self.sock.connect(self.path)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--ctl', required=True)
    parser.add_argument('--vpp-build', required=True)
    parser.add_argument('--output', required=True)
    parser.add_argument('--contexts', type=int, default=32)
    parser.add_argument('--flows', type=int, default=16)
    parser.add_argument('--locator', choices=['vni', 'tlv'], default='vni')
    args = parser.parse_args()
    assert os.geteuid() == 0 and 2 <= args.contexts <= 4096
    out = Path(args.output).resolve(); out.mkdir(mode=0o700, parents=True, exist_ok=False)
    tag = 'w'+str(os.getpid()); namespaces = {key: tag+key for key in ['eg', 'a', 'b', 'out']}
    children = []; files = []; commands = []; checks = []; grants = {}; metrics = {}
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

    def api(method, path, value=None, expect=True):
        connection = UnixHTTP(out/'runtime/control.sock')
        try:
            connection.request(method, '/v1/'+path, body=json.dumps(value or {}).encode(), headers={'Content-Type': 'application/json'})
            response = connection.getresponse(); value = json.loads(response.read())
            if expect and response.status != 200:
                raise RuntimeError((path, response.status, value))
            return value if response.status == 200 else None
        finally:
            connection.close()

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

    def open_session(slot, name=None, attachment=None, generation=1):
        name = name or 'sandbox'+str(slot)
        grant = api('POST', 'sessions', dict(id=name, attachment=attachment or 'a'+str(7+slot%2), slot=slot,
                    generation=generation, inner_ip=inner_address(slot), return_mac='02:00:00:00:80:01', lease_seconds=300))
        grants[name] = grant; return grant

    def close_all():
        for name, grant in list(grants.items()):
            api('DELETE', 'sessions/'+name, {'token': grant['token']})
        grants.clear()
        for _ in range(100):
            status = api('GET', 'status')
            if not status['sessions']:
                return status
            time.sleep(.05)
        raise AssertionError('retired native state was not reclaimed')

    try:
        for name in namespaces.values():
            run('ip', 'netns', 'add', name); run('ip', '-n', name, 'link', 'set', 'lo', 'up')
        for index, key in enumerate(['a', 'b', 'out']):
            local, peer = tag+'i'+str(index), tag+'p'+str(index)
            run('ip', 'link', 'add', local, 'type', 'veth', 'peer', 'name', peer)
            run('ip', 'link', 'set', local, 'netns', namespaces['eg']); run('ip', 'link', 'set', peer, 'netns', namespaces[key])
            mtu = 1500 if key == 'out' else 9000
            for ns, dev in [(namespaces['eg'], local), (namespaces[key], peer)]:
                run('ip', '-n', ns, 'link', 'set', dev, 'mtu', mtu, 'up')
                run('ip', 'netns', 'exec', ns, 'ethtool', '-K', dev, 'tx', 'off', 'rx', 'off', 'gso', 'off', 'gro', 'off', 'tso', 'off')
            run('ip', '-n', namespaces[key], 'addr', 'add', '192.0.2.2/24' if key == 'out' else '198.18.0.2/24', 'dev', peer)
        run('ip', '-n', namespaces['out'], 'addr', 'add', '203.0.113.11/32', 'dev', 'lo')
        run('ip', 'netns', 'exec', namespaces['out'], 'sysctl', '-qw', 'net.ipv4.conf.all.arp_announce=2')
        build = Path(args.vpp_build); lib = next((build/'lib').glob('*-linux-gnu'))
        cpus = sorted(os.sched_getaffinity(0))
        cfg = dict(name=tag, runtime_dir=str(out/'runtime'), vpp=str(build/'bin/vpp'), vppctl=str(build/'bin/vppctl'),
                   plugin_path=str(lib/'vpp_plugins'), library_path=str(lib), main_core=cpus[0], workers=cpus[1:3],
                   max_connections=65536, interfaces=[], exits=[], attachments=[], areas=[])
        for index in range(3):
            cfg['interfaces'].append(dict(name=tag+'i'+str(index), address='192.0.2.1/24' if index == 2 else '198.18.0.1/24', mtu=1500 if index == 2 else 9000))
        cfg['exits'] = [dict(name='public', interface=tag+'i2', next_hop='192.0.2.2', addresses=['192.0.2.1', '192.0.2.3'])]
        for area in [7, 8]:
            cfg['areas'].append(dict(vni=area, pools=[dict(id=0, exit='public', addresses=['192.0.2.1' if area == 7 else '192.0.2.3'], max_connections=args.flows)],
                acl=[dict(destination='198.18.1.1/32', protocol='any', action='allow')], routes=[],
                dnat=[dict(destination='198.18.1.1/32', protocol=protocol, pool=0, target='203.0.113.11', target_port=18080) for protocol in ['udp','tcp']]))
            for index, peer in enumerate(['a', 'b']):
                cfg['attachments'].append(dict(name=peer+str(area), interface=tag+'i'+str(index), peer='198.18.0.2', area=area,
                    locator=args.locator, tlv_class=258, tlv_type=129, encapsulation='ether', generation_bits=4, gateway='10.7.0.1', mtu=1500))
        config = out/'gateway.json'; config.write_text(json.dumps(cfg))
        gateway = spawn(['ip', 'netns', 'exec', namespaces['eg'], args.ctl, 'egress', 'serve', '--config', str(config)], 'gateway.log')
        for _ in range(500):
            if (out/'runtime/control.sock').exists():
                break
            if gateway.poll() is not None:
                raise RuntimeError((out/'gateway.log').read_text())
            time.sleep(.02)
        spawn(['ip', 'netns', 'exec', namespaces['out'], sys.executable, __file__, 'backend'], 'backend.log')
        peers = [spawn(['ip', 'netns', 'exec', namespaces[key], sys.executable, __file__, 'peer', json.dumps({'locator': args.locator})]) for key in ['a', 'b']]
        open_session(0); open_session(0, 'other-peer', 'b7')
        a = query(peers[0]); b = query(peers[1])
        check('overlapping outer and inner identities remain independent', a['peer'] != b['peer'], [a, b])
        query(peers[0], generation=2, expect=False)
        check('unregistered generation cannot create or renew state', len(api('GET', 'status')['sessions']) == 2)
        opaque = query(peers[0], opaque=True)
        check('opaque noncritical options are not reflected', opaque['options'] == ('0102810100000000' if args.locator == 'tlv' else ''), opaque)
        for label, mutations in [('version', [[0, 0x40]]), ('reserved flags', [[1, 1]]), ('reserved byte', [[7, 1]]), ('unknown Area', [[6, 9]])]:
            query(peers[0], mutations=mutations, expect=False); check('reject '+label, True)
        query(peers[0], critical=True, expect=False); check('reject unknown critical option', True)
        query(peers[0], fragment_outer=True, expect=False)
        guard = run('env', 'LD_LIBRARY_PATH='+str(lib), str(build/'bin/vppctl'), '-s', out/'runtime/vpp.sock', 'show errors')
        check('outer fragments reach the explicit rejection guard', 'unsupported outer UDP fragments' in guard.stdout, guard.stdout)
        fragmented = query(peers[0], fragment_inner=True, extra=(b'x'*80).hex())
        check('native inner reassembly retains session identity', fragmented['ok'])
        large = query(peers[0], extra=(b'L'+struct.pack('!H', 2000)).hex())
        check('large return reassembles and fragments within tunnel MTU', large['fragments'] >= 2 and large['payload_bytes'] == 2012, large)
        before = api('GET', 'status')
        pmtu = query(peers[0], flow=20, extra=(b'p'*1700).hex(), icmp=True)
        check('pre-NAT DF error contains original tuple', pmtu['type'] == 3 and pmtu['code'] == 4 and pmtu['mtu'] == 1500 and bytes.fromhex(pmtu['quote'])[12:16] == socket.inet_aton('10.7.0.2'), pmtu)
        after = api('GET', 'status')
        check('PMTU failure does not reserve quota', sum(p['current'] for p in before['pools']) == sum(p['current'] for p in after['pools']))
        quoted = query(peers[0], flow=21, tcp=True, icmp=True)
        quote = bytes.fromhex(quoted['quote'])
        check('native ICMP translates an eight-byte TCP quote', quoted['type'] == 3 and quoted['code'] == 1 and len(quote) == 28 and quote[12:16] == socket.inet_aton('10.7.0.2') and quote[16:20] == socket.inet_aton('198.18.1.1') and struct.unpack('!HH',quote[20:24]) == (31021,53) and checksum(quote[:20]) == 0, quoted)
        changed = copy.deepcopy(cfg['areas'][0]); changed['dnat'][0]['target_port'] = 18081
        api('PUT', 'areas/7', changed)
        check('changed DNAT target retires existing UDP mapping', sum(p['current'] for p in api('GET','status')['pools']) <= 1)
        query(peers[0], expect=False)
        api('PUT', 'areas/7', cfg['areas'][0]); query(peers[0])
        changed = copy.deepcopy(cfg['areas'][0]); changed['pools'][0]['addresses'] = ['192.0.2.3']
        api('PUT', 'areas/7', changed)
        check('SNAT replacement allocates only the newly selected resource', query(peers[0])['peer'][0] == '192.0.2.3')
        api('PUT', 'areas/7', cfg['areas'][0])
        check('restored resource uses a fresh authorized mapping', query(peers[0])['peer'][0] == '192.0.2.1')
        close_all()
        # Capacity uses actual authorized sessions and actual bidirectional
        # application datagrams, with both Areas sharing an external interface.
        started = time.monotonic()
        for slot in range(args.contexts):
            open_session(slot)
            if slot % 256 == 255:
                print('registered', slot+1, flush=True)
        metrics['registration_seconds'] = time.monotonic()-started
        check('all authorized contexts loaded', len(api('GET', 'status')['sessions']) == args.contexts)
        if args.contexts == 4096:
            check('resident budget rejects context 4097', api('POST', 'sessions', dict(id='overflow', attachment='a7', slot=0, generation=2, inner_ip='10.7.0.2', return_mac='02:00:00:00:80:01', lease_seconds=300), expect=False) is None)
        active = query(peers[0], op='stage', contexts=args.contexts, flows=args.flows); metrics['traffic'] = active
        check('every active connection completes real echo', active['echoed'] == args.contexts*args.flows and active['public_tuples'] == args.contexts*args.flows, active)
        status = api('GET', 'status'); (out/'active-status.json').write_text(json.dumps(status))
        native = run('env', 'LD_LIBRARY_PATH='+str(lib), str(build/'bin/vppctl'), '-s', out/'runtime/vpp.sock', 'show nat44 summary')
        (out/'active-native-summary.txt').write_text(native.stdout)
        check('native quota equals real active mappings', sum(p['current'] for p in status['pools']) == args.contexts*args.flows)
        original = query(peers[0])['peer']
        low = copy.deepcopy(cfg['areas'][0]); low['pools'][0]['max_connections'] = 1
        started = time.monotonic(); api('PUT', 'areas/7', low); metrics['policy_update_seconds'] = time.monotonic()-started
        check('lower quota retains established public tuple', query(peers[0])['peer'] == original)
        query(peers[0], flow=args.flows, expect=False); check('lower quota blocks only new mappings', True)
        deny = copy.deepcopy(low); deny['acl'] = []
        api('PUT', 'areas/7', deny)
        query(peers[0], expect=False); check('revocation blocks old forward mapping', True)
        query(peers[0], slot=1); check('other Area retains live mapping', True)
        remaining = sum(p['current'] for p in api('GET', 'status')['pools'])
        check('only revoked Area mappings are released', remaining == (args.contexts//2)*args.flows, remaining)
        second = copy.deepcopy(cfg['areas'][1]); second['acl'] = []
        api('PUT', 'areas/8', second)
        status = api('GET', 'status')
        check('mapping reservations and releases balance', sum(p['current'] for p in status['pools']) == 0 and sum(p['created'] for p in status['pools']) == sum(p['released'] for p in status['pools']))
        close_all(); check('retired interfaces and policy contexts reclaimed', not api('GET', 'status')['pools'])
        api('PUT', 'areas/7', cfg['areas'][0]); open_session(0, generation=2)
        query(peers[0], generation=1, expect=False)
        query(peers[0], generation=2)
        check('reused capacity accepts current generation and rejects old generation', True)
        result['pass_'] = True
    except Exception:
        result['error'] = traceback.format_exc(); raise
    finally:
        if 'lib' in locals() and (out/'runtime/vpp.sock').exists():
            for command in ['show errors', 'show nat44 summary', 'show egress-geneve', 'show memory main-heap']:
                p = run('env', 'LD_LIBRARY_PATH='+str(lib), str(build/'bin/vppctl'), '-s', out/'runtime/vpp.sock', command, check=False)
                (out/(command.replace(' ', '-')+'.txt')).write_text(p.stdout+p.stderr)
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
