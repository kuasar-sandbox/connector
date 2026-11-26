#!/usr/bin/env python3
"""Owned real TC/eBPF -> local veth -> VPP/NAT -> Linux socket acceptance.

Run as root in an isolated test executor with the pinned Egress build. Every
namespace and interface name is unique to this run. Physical NICs are not used.
"""
import argparse
import copy
import json
import os
from pathlib import Path
import signal
import socket
import subprocess
import sys
import time
import traceback

SERVER = r'''
import json,socket,threading
def udp(ip):
 s=socket.socket(socket.AF_INET,socket.SOCK_DGRAM);s.bind((ip,18080))
 while True:
  data,peer=s.recvfrom(65535)
  s.sendto(json.dumps({'data':data.decode(),'backend':ip,'peer':peer}).encode(),peer)
def tcp(ip):
 s=socket.socket();s.setsockopt(socket.SOL_SOCKET,socket.SO_REUSEADDR,1);s.bind((ip,18080));s.listen(128)
 while True:
  c,p=s.accept()
  with c:
   chunks=[]
   while True:
    chunk=c.recv(65535)
    if not chunk:break
    chunks.append(chunk)
   d=b''.join(chunks);reply={'data':d.decode(),'backend':ip,'peer':p}
   if d.startswith(b'EGRESS-BULK:'):reply['bulk']='x'*int(d.split(b':',2)[1])
   c.sendall(json.dumps(reply).encode())
for ip in ('203.0.113.11','203.0.113.12'):
 for f in (udp,tcp):threading.Thread(target=f,args=(ip,),daemon=True).start()
threading.Event().wait()
'''
CLIENT = r'''
import json,socket,sys,time,uuid
sessions={}
for line in sys.stdin:
 q=json.loads(line);out={}
 try:
  key=q['key'];protocol=q.get('protocol','udp')
  if key not in sessions:
   s=socket.socket(type=socket.SOCK_STREAM if protocol=='tcp' else socket.SOCK_DGRAM)
   s.setsockopt(socket.SOL_SOCKET,socket.SO_REUSEADDR,1);s.bind(('10.7.0.2',q['source']));s.settimeout(2 if protocol=='tcp' else .4)
   if protocol=='tcp':s.connect((q['target'],q.get('port',18080)))
   sessions[key]=s
  s=sessions[key];data=(uuid.uuid4().hex+':'+q.get('data','probe')).encode()
  if protocol=='tcp':
   if q.get('response_bytes'):data=b'EGRESS-BULK:'+str(q['response_bytes']).encode()+b':'+data
   peer=s.getpeername();s.settimeout(10);s.sendall(data);s.shutdown(socket.SHUT_WR);chunks=[]
   while True:
    chunk=s.recv(65535)
    if not chunk:break
    chunks.append(chunk)
   payload=b''.join(chunks);s.close();del sessions[key]
  else:
   s.sendto(data,(q['target'],q.get('port',18080)))
   deadline=time.monotonic()+.4
   # A reply queued during the earlier link failure must not satisfy a later
   # policy assertion. Only this request's echo counts, within one deadline.
   while True:
    remaining=deadline-time.monotonic()
    if remaining<=0:raise TimeoutError('no matching UDP reply')
    s.settimeout(remaining);payload,peer=s.recvfrom(65535)
    if json.loads(payload).get('data')==data.decode():break
  reply=json.loads(payload)
  if q.get('response_bytes'):
   bulk=reply.pop('bulk');assert bulk=='x'*q['response_bytes'];reply['bulk_bytes']=len(bulk)
  out={'ok':True,'peer':peer,'reply':reply}
 except Exception as e:out={'ok':False,'error':str(e)}
 print(json.dumps(out),flush=True)
'''

def main():
    ap=argparse.ArgumentParser()
    ap.add_argument('--ctl',required=True)
    ap.add_argument('--runtime',required=True,help='Connector bin directory containing connector-vpp and vpp-runtime.json')
    ap.add_argument('--output',required=True)
    ap.add_argument('--locator',choices=['port','vni','tlv'],default='port')
    ap.add_argument('--encap',choices=['ether','ip'],default='ether')
    ap.add_argument('--workers',type=int,default=min(2,len(os.sched_getaffinity(0))-1))
    ap.add_argument('--legacy',action='store_true')
    ap.add_argument('--remote',action='store_true',help='Use externally owned routed transit instead of local managed pair')
    args=ap.parse_args()
    output=Path(args.output).resolve();output.mkdir(parents=True,exist_ok=True)
    tag='e'+str(os.getpid())
    names={n:tag+n for n in ['ow','eg','sw','pn','ga','gb','out','rt']}
    switch=tag+'s';transit=tag+'t';gateway=tag+'g'
    children=[];files=[];commands=[];checks=[];clients={}
    runtime_dir=output/'runtime';runtime_dir.mkdir(mode=0o700,exist_ok=True)
    link={'name':tag,'owner_netns':names['ow'],'gateway_netns':names['eg'],
          'switch_netns':names['sw'],'switch':switch,'transit':transit,'gateway':gateway,
          'mtu':9000,'state_dir':str(output/'link-state'),'gateway_runtime_dir':str(runtime_dir)}
    link_file=output/'link.json';link_file.write_text(json.dumps(link))
    def run(*cmd,check=True,timeout=30):
        p=subprocess.run(list(map(str,cmd)),capture_output=True,text=True,timeout=timeout)
        commands.append({'argv':list(map(str,cmd)),'rc':p.returncode,'stdout':p.stdout,'stderr':p.stderr})
        if check and p.returncode:raise RuntimeError(commands[-1])
        return p
    def ctl(*cmd,**kw):return run(args.ctl,*cmd,**kw)
    def start_switch():
        if args.remote:return run('nsenter','--net=/run/netns/'+names['ow'],args.ctl,'vswitch','start','--config',swfile,'--mode=veth')
        return ctl('egress','link','start','--config',link_file,'--switch-config',swfile,'--mode=veth')
    def stop_switch(check=True):
        if args.remote:return run('nsenter','--net=/run/netns/'+names['ow'],args.ctl,'vswitch','stop',switch,check=check)
        return ctl('egress','link','stop','--config',link_file,check=check)
    def switch_state():
        if not args.remote:return json.loads(ctl('egress','link','check','--config',link_file).stdout)
        for ns in [names['sw'],names['ow']]:
            if run('ip','-n',ns,'link','show',transit,check=False).returncode==0:return {'pair_valid':True,'switch_endpoint':ns}
        return {'pair_valid':False,'switch_endpoint':None}
    def check(name,condition,actual=None):
        checks.append({'name':name,'pass':bool(condition),'actual':actual})
        (output/'checks.json').write_text(json.dumps(checks,indent=2))
        print(name, bool(condition),flush=True)
        if not condition:raise AssertionError((name,actual))
    def status():
        return json.loads((runtime_dir/'status.json').read_text())
    def check_static_native(phase):
        pid = status()['native_pid']
        executable = Path('/proc', str(pid), 'exe').resolve()
        check('selected static dataplane executable ('+phase+')',
              executable == runtime/'connector-vpp', str(executable))
        mappings = Path('/proc', str(pid), 'maps').read_text()
        (output/('native-maps-'+phase+'.txt')).write_text(mappings)
        foreign = []
        for line in mappings.splitlines():
            fields = line.split(None, 5)
            if len(fields) != 6 or not fields[5].startswith('/'):
                continue
            path = fields[5].removesuffix(' (deleted)')
            if path != str(executable) and ('x' in fields[1] or '.so' in Path(path).name):
                foreign.append(line)
        check('no shared libraries mapped ('+phase+')', not foreign, foreign)
    def wait_status(predicate, timeout=15):
        until=time.monotonic()+timeout; current={}
        while time.monotonic()<until:
            if service.poll() is not None:raise RuntimeError('gateway stopped; inspect gateway log')
            try:
                current=status()
                if current.get('pid')==service.pid and predicate(current):return current
            except (FileNotFoundError,json.JSONDecodeError):pass
            time.sleep(.05)
        raise AssertionError(('diagnostic state timeout',current))
    def write_json(path,value):
        tmp=path.with_suffix('.next');tmp.write_text(json.dumps(value));tmp.replace(path)
    def reload_area(value, ok=True):
        before=status()['configuration_generation'];write_json(areafile,value)
        service.send_signal(signal.SIGHUP)
        return wait_status(lambda st: st['configuration_generation']>before if ok else bool(st['reload_error']))
    def reload_config(value):
        before=status()['configuration_generation'];write_json(cfgfile,value)
        service.send_signal(signal.SIGHUP)
        return wait_status(lambda st: st['configuration_generation']>before)
    def spawn(command,log):
        f=(output/log).open('w');files.append(f)
        p=subprocess.Popen(command,stdout=f,stderr=f,text=True);children.append(p);return p
    def call(who,key,source,target,**kw):
        p=clients[who];p.stdin.write(json.dumps(dict(key=key,source=source,target=target,**kw))+'\n');p.stdin.flush()
        line=p.stdout.readline()
        if not line:raise RuntimeError('client stopped: '+who)
        return json.loads(line)
    def attach(who,port,generation):
        ctl('vswitch','attach',switch,'--port='+str(port),'--to-netns='+names[who],
            '--inner-ip=10.7.0.2','--generation='+str(generation),'--transit-gateway-ip=198.18.0.1','--transit-geneve-vni=7')
        dev=switch+'-p'+str(port)
        run('ip','-n',names[who],'addr','add','10.7.0.2/24','dev',dev)
        run('ip','-n',names[who],'link','set',dev,'up')
        run('ip','-n',names[who],'route','add','default','via','10.7.0.1')
        p=subprocess.Popen(['ip','netns','exec',names[who],'python3','-u','-c',CLIENT],stdin=subprocess.PIPE,stdout=subprocess.PIPE,stderr=subprocess.PIPE,text=True)
        children.append(p);clients[who]=p
    try:
        run(sys.executable, Path(__file__).with_name('runtime.py'), 'validate',
            '--arch', os.uname().machine, '--runtime', args.runtime)
        check('root executor',os.geteuid()==0)
        if not Path('/sys/fs/bpf').is_mount():run('mount','-t','bpf','bpf','/sys/fs/bpf')
        if args.remote:
            for key in ['ow','eg','rt']:
                run('ip','netns','add',names[key]);run('ip','-n',names[key],'link','set','lo','up')
            for ns,dev,peer,address in [(names['ow'],transit,tag+'rs','198.18.1.1/24'),(names['eg'],gateway,tag+'rg','198.18.0.2/24')]:
                run('ip','link','add',dev,'type','veth','peer','name',peer)
                run('ip','link','set',dev,'netns',ns);run('ip','link','set',peer,'netns',names['rt'])
                run('ip','-n',ns,'link','set',dev,'mtu','9000')
                if ns==names['eg']:run('ip','-n',ns,'link','set',dev,'up')
                run('ip','-n',names['rt'],'link','set',peer,'mtu','9000','up')
                run('ip','-n',names['rt'],'addr','add',address,'dev',peer)
                for owner,device in [(ns,dev),(names['rt'],peer)]:run('ip','netns','exec',owner,'ethtool','-K',device,'tx','off','rx','off','gso','off','gro','off','tso','off')
            run('ip','netns','exec',names['rt'],'sysctl','-qw','net.ipv4.ip_forward=1')
        else:
            first=json.loads(ctl('egress','link','prepare','--config',link_file).stdout)
            second=json.loads(ctl('egress','link','prepare','--config',link_file).stdout)
            check('repeat prepare preserves owned pair',first['pair_valid'] and second['pair_valid'],second)
        for key in ['sw','pn','ga','gb','out']:
            run('ip','netns','add',names[key]);run('ip','-n',names[key],'link','set','lo','up')
        # The loopback backend addresses are routed through either NIC. ARP
        # requests must use the on-link address after an interface flap.
        run('ip','netns','exec',names['out'],'sysctl','-qw','net.ipv4.conf.all.arp_announce=2')
        for n,network in enumerate(['192.0.2','198.19.0']):
            a=tag+'x'+str(n);b=tag+'b'+str(n)
            run('ip','link','add',a,'type','veth','peer','name',b)
            run('ip','link','set',a,'netns',names['eg']);run('ip','link','set',b,'netns',names['out'])
            for ns,dev in [(names['eg'],a),(names['out'],b)]:
                run('ip','-n',ns,'link','set',dev,'up')
            run('ip','-n',names['out'],'addr','add',network+'.2/24','dev',b)
        run('ip','-n',names['out'],'addr','add','203.0.113.11/32','dev','lo')
        run('ip','-n',names['out'],'addr','add','203.0.113.12/32','dev','lo')
        spawn(['ip','netns','exec',names['out'],'python3','-u','-c',SERVER],'backend.log')
        runtime=Path(args.runtime).resolve()
        area={'vni':7,'pools':[{'name':'primary','interface':tag+'x0','next_hop':'192.0.2.2','addresses':['192.0.2.1'],'max_connections':2},
                               {'name':'secondary','interface':tag+'x1','next_hop':'198.19.0.2','addresses':['198.19.0.1'],'max_connections':1}],
              'acl':[{'destination':'203.0.113.0/24','protocol':'any','action':'allow'},
                     {'destination':'198.18.1.1/32','protocol':'udp','action':'allow'}, {'action':'deny'}],
              'routes':[{'destination':'0.0.0.0/0','pool':'primary'},{'destination':'203.0.113.12/32','pool':'secondary'}],
              'dnat':[{'destination':'198.18.1.1/32','protocol':'udp','pool':'secondary','target':'203.0.113.11','target_port':18080}]}
        bits=4 if args.encap=='ether' and not args.legacy else 0
        cfg={'name':tag,'runtime_dir':str(runtime_dir),
             'interfaces':[{'name':gateway,'address':'198.18.0.1/24','mtu':9000},
                           {'name':tag+'x0','address':'192.0.2.1/24','mtu':1500},
                           {'name':tag+'x1','address':'198.19.0.1/24','mtu':1500}],
             'attachments':[{'name':'local','interface':gateway,'peer':['198.18.0.2'],'locator':args.locator}],
             'area_files':['area.yaml']}
        if args.locator=='tlv':cfg['attachments'][0].update(tlv_class=258,tlv_type=129)
        if args.remote:
            if args.locator=='vni':del cfg['attachments'][0]['peer']
            else:cfg['attachments'][0]['peer']=['198.18.1.0/24']
            cfg['attachments'][0]['next_hop']='198.18.0.2'
        cpus=sorted(os.sched_getaffinity(0))
        if len(cpus)<args.workers+1:raise RuntimeError('not enough CPUs for requested workers')
        cfg['main_core']=cpus[0];cfg['workers']=cpus[1:args.workers+1]
        areafile=output/'area.yaml';areafile.write_text('# Area policy\n'+''.join(key+': '+json.dumps(value)+'\n' for key,value in area.items()))
        cfgfile=output/'gateway.yaml';cfgfile.write_text('# Gateway configuration\n'+''.join(key+': '+json.dumps(value)+'\n' for key,value in cfg.items()))
        ctl('egress','validate','--config',cfgfile)
        service=spawn(['ip','netns','exec',names['eg'],args.ctl,'egress','serve','--config',str(cfgfile)],'gateway.log')
        ready=wait_status(lambda st: st['configuration_generation']==1)
        check('file-configured gateway started',ready['contexts']==0,ready)
        check_static_native('startup')
        check('no management socket is created',not any(p.is_socket() for p in runtime_dir.iterdir()))
        listeners=run('ip','netns','exec',names['eg'],'ss','-H','-lntup').stdout+run('ip','netns','exec',names['eg'],'ss','-H','-lx').stdout
        check('no TCP UDP or Unix management listener',not listeners.strip(),listeners)
        shm=list(Path('/dev/shm').glob('connector-egress-'+str(service.pid)+'*'))
        check('no named shared-memory API transport',not shm,[str(p) for p in shm])
        swcfg={'switch_name':switch,'switch_netns':names['sw'],'port_netns':names['pn'],'num_ports':2,
               'mac_addr':'02:00:00:00:00:01','floating_ip_base':'100.100.96.0','generation_bits':bits,'transit_dev_mtu':'auto',
               'transit_dev':transit,'transit_dev_addr':'198.18.0.2/24:198.18.0.1','geneve_locator':args.locator,
               'geneve_encap_eth':args.encap=='ether'}
        if args.locator=='port':swcfg['geneve_port_base']=51000
        if args.locator=='tlv':swcfg['geneve_tlv_locator']='0102:81'
        if args.remote:swcfg['transit_dev_addr']='198.18.1.2/24:198.18.1.1'
        swfile=output/'switch.json';swfile.write_text(json.dumps(swcfg))
        start_switch()
        state=switch_state()
        check('stable owner handed transit to switch',state['switch_endpoint']==names['sw'] and state['pair_valid'],state)
        attach('ga',1,1 if bits else 0);attach('gb',2,2 if bits else 0)
        for attempt in range(5):
            a1=call('ga','a1',31000,'203.0.113.11')
            if a1.get('ok'):break
            time.sleep(.2)
        check('traffic automatically creates context and NAT UDP roundtrip',a1.get('ok') and a1['reply']['peer'][0]=='192.0.2.1',a1)
        a2=call('ga','a2',31001,'203.0.113.11')
        check('second mapping consumes final Pool quota',a2.get('ok'),a2)
        full=call('ga','a3',31002,'203.0.113.11')
        check('per-sandbox Pool quota rejects excess',not full['ok'],full)
        other=call('gb','b1',31000,'203.0.113.11')
        check('other sandbox has independent quota',other.get('ok'),other)
        another=call('ga','y1',31100,'203.0.113.12')
        check('LPM selects independent second Pool',another.get('ok') and another['reply']['peer'][0]=='198.19.0.1',another)
        run('ip','-n',names['out'],'link','set',tag+'b0','down')
        check('failed Pool does not fall back',not call('ga','a1',31000,'203.0.113.11')['ok'])
        check('independent Pool survives other exit failure',call('ga','y1',31100,'203.0.113.12')['ok'])
        state=wait_status(lambda st: any(i['interface']==tag+'x0' and not i['carrier'] for i in st['interfaces']))
        check('diagnostics distinguish exit carrier failure',True,state)
        run('ip','-n',names['out'],'link','set',tag+'b0','up')
        denied=call('gb','deny',31200,'203.0.112.11')
        check('explicit final deny ACL',not denied['ok'],denied)
        dnat=call('gb','dnat',31300,'198.18.1.1',port=53)
        check('DNAT fixes Pool and restores original tuple',dnat.get('ok') and dnat['peer']==['198.18.1.1',53] and dnat['reply']['peer'][0]=='198.19.0.1',dnat)
        tcp=call('gb','tcp',31400,'203.0.113.11',protocol='tcp',response_bytes=1<<20)
        check('native TCP large return with default backend offloads',tcp.get('ok') and tcp['reply'].get('bulk_bytes')==1<<20,tcp)
        wait_status(lambda st: 'GSO packets segmented' in st['native_errors'])
        check('large return exercises native GSO segmentation',True)
        before=status();(output/'status-before.json').write_text(json.dumps(before,indent=2))
        lower=copy.deepcopy(area);lower['pools'][0]['max_connections']=1
        reload_area(lower)
        kept=call('ga','a1',31000,'203.0.113.11',data='still-authorized')
        check('lowering quota preserves established mapping',kept.get('ok') and kept['reply']['peer']==a1['reply']['peer'],kept)
        invalid=copy.deepcopy(lower);invalid['routes'][0]['pool']='missing'
        failure=reload_area(invalid,ok=False)
        check('invalid file reload is rejected',bool(failure['reload_error']),failure['reload_error'])
        after_failure=call('ga','a1',31000,'203.0.113.11')
        check('failed update retains prior policy',after_failure.get('ok'),after_failure)
        revoke=copy.deepcopy(lower);revoke['acl'].insert(0,{'destination':'203.0.113.11/32','protocol':'any','action':'deny'})
        reload_area(revoke)
        revoked=call('ga','a1',31000,'203.0.113.11')
        check('ACL revocation terminates existing mapping',not revoked['ok'],revoked)
        unaffected=call('ga','y1',31100,'203.0.113.12')
        check('unaffected Pool connection survives update',unaffected.get('ok'),unaffected)
        service.terminate();service.wait(timeout=5)
        check('stopped Egress has no uncontrolled fallback',not call('ga','y1',31100,'203.0.113.12')['ok'])
        service=spawn(['ip','netns','exec',names['eg'],args.ctl,'egress','serve','--config',str(cfgfile)],'gateway-restart.log')
        wait_status(lambda st: st['configuration_generation']==1)
        check('file ACL revocation survives restart',not call('ga','a1',31000,'203.0.113.11')['ok'])
        check('first packet after restart automatically restores forwarding',call('ga','y1',31100,'203.0.113.12')['ok'])
        cfg['timeouts']={'udp':2,'icmp':2,'tcp_transitory':2,'tcp_established':2}
        cfg['context_idle_seconds']=1
        reload_config(cfg)
        empty=wait_status(lambda st: st['contexts']==0 and st['connections']==0,timeout=20)
        check('protocol timeout automatically reclaims NAT and contexts',empty['reclaimed']>0,empty)
        check('traffic recreates an idle context without registration',call('ga','y1',31100,'203.0.113.12')['ok'])
        busy=stop_switch(check=False)
        check('normal stop refuses active sandboxes',busy.returncode!=0)
        for who,port in [('ga',1),('gb',2)]:ctl('vswitch','detach',switch,'--port='+str(port),'--from-netns='+names[who])
        stop_switch()
        state=switch_state()
        check('stop returns original pair to stable owner',state['pair_valid'] and state['switch_endpoint']==names['ow'],state)
        start_switch();stop_switch()
        check('same attachment supports second Start Stop cycle',switch_state()['pair_valid'])
        check_static_native('traffic')
        if args.remote:
            service.terminate();service.wait(timeout=5)
            check('remote shutdown preserves external transit and Pool interfaces',all(run('ip','-n',ns,'link','show',dev,check=False).returncode==0 for ns,dev in [(names['ow'],transit),(names['eg'],gateway),(names['eg'],tag+'x0'),(names['rt'],tag+'rg')]))
            (output/'result.json').write_text(json.dumps({'pass':True,'checks':len(checks),'uname':list(os.uname()),'locator':args.locator,'encap':args.encap,'workers':args.workers,'remote':True},indent=2))
            return
        start_switch()
        clients['ga'].terminate();clients['ga'].wait(timeout=3)
        attach('ga',1,3 if bits else 0)
        old_index=json.loads(run('ip','-n',names['eg'],'-j','link','show',gateway).stdout)[0]['ifindex']
        run('ip','-n',names['eg'],'link','del',gateway)
        wait_status(lambda st: any(i['interface']==gateway and 'error' in i for i in st['interfaces']))
        check('single lost interface does not stop unrelated dataplane paths',service.poll() is None)
        wait_status(lambda st: st['disabled_interfaces'].get(gateway))
        run('ip','-n',names['eg'],'link','add',gateway,'type','dummy')
        run('ip','-n',names['eg'],'link','set',gateway,'mtu','9000','up')
        observed=wait_status(lambda st: any(i['interface']==gateway and i.get('up') for i in st['interfaces']) and st['disabled_interfaces'].get(gateway))
        check('same-name replacement remains disabled despite administrative UP',True,observed['disabled_interfaces'])
        run('ip','-n',names['eg'],'link','del',gateway)
        service.terminate();service.wait(timeout=5)
        check('damaged pair is not silently adopted',ctl('egress','link','prepare','--config',link_file,check=False).returncode!=0)
        check('repair refuses active sandbox before replacing pair',ctl('egress','link','repair','--config',link_file,'--switch-config',swfile,'--mode=veth',check=False).returncode!=0)
        ctl('vswitch','detach',switch,'--port=1','--from-netns='+names['ga'])
        ctl('egress','link','repair','--config',link_file,'--switch-config',swfile,'--mode=veth')
        new_index=json.loads(run('ip','-n',names['eg'],'-j','link','show',gateway).stdout)[0]['ifindex']
        check('drained repair recreates pair and switch identity',new_index!=old_index)
        service=spawn(['ip','netns','exec',names['eg'],args.ctl,'egress','serve','--config',str(cfgfile)],'gateway-repair.log')
        wait_status(lambda st: st['configuration_generation']==1)
        clients['ga'].terminate();clients['ga'].wait(timeout=3)
        attach('ga',1,4 if bits else 0)
        check('reattachment after repair restores real return path',call('ga','repaired',31500,'203.0.113.12')['ok'])
        check_static_native('repair')
        ctl('vswitch','detach',switch,'--port=1','--from-netns='+names['ga'])
        stop_switch()
        if args.locator=='port' and args.encap=='ether' and not args.legacy:
            # A stopped native process remains alive but cannot answer the
            # supervisor's periodic diagnostics. A poisoned stream must make
            # the supervisor fail and reap that child for service recovery.
            native_pid=status()['native_pid']
            os.kill(native_pid,signal.SIGSTOP)
            service.wait(timeout=40)
            check('diagnostic stream timeout terminates the supervisor',service.returncode!=0)
            check('failed supervisor reaps the unresponsive native process',not Path('/proc',str(native_pid)).exists())
        else:
            service.terminate();service.wait(timeout=5)
        check('uninstall preserves Pool-owned interfaces',ctl('egress','link','uninstall','--config',link_file,check=False).returncode!=0 and run('ip','-n',names['eg'],'link','show',tag+'x0',check=False).returncode==0)
        for n in [0,1]:run('ip','-n',names['eg'],'link','del',tag+'x'+str(n))
        ctl('egress','link','uninstall','--config',link_file)
        check('safe uninstall removes owned pair and namespaces',run('ip','netns','list').stdout.find(names['eg']+' ')==-1)
        (output/'result.json').write_text(json.dumps({'pass':True,'checks':len(checks),'uname':list(os.uname()),'locator':args.locator,'encap':args.encap,'workers':args.workers,'legacy':args.legacy},indent=2))
    except Exception:
        for command in [['vswitch','show','slots',switch],['vswitch','stats',switch]]:
            diagnostic=ctl(*command,check=False)
            (output/('-'.join(command[:-1])+'.json')).write_text(diagnostic.stdout+diagnostic.stderr)
        (output/'result.json').write_text(json.dumps({'pass':False,'checks':checks,'error':traceback.format_exc()},indent=2))
        raise
    finally:
        for p in reversed(children):
            if p.poll() is None:
                p.terminate()
                try:p.wait(timeout=4)
                except subprocess.TimeoutExpired:p.kill();p.wait()
        ctl('vswitch','stop',switch,'--force',check=False)
        for name in names.values():run('ip','netns','del',name,check=False)
        for f in files:f.close()
        (output/'commands.json').write_text(json.dumps(commands,indent=2))

if __name__=='__main__':main()
