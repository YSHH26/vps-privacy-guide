#!/usr/bin/env python3
"""Root-only, repeatable server stages. Operational output never contains secrets."""
import datetime, fcntl, hashlib, ipaddress, json, os, pathlib, shutil, subprocess, sys, tarfile, tempfile, time
ROOT=pathlib.Path(__file__).resolve().parents[1]
ETC=pathlib.Path('/etc/sui-vps')
STATE=ETC/'state.json'
ACME_CONFIG=ETC/'acme'
ACME_WORK=pathlib.Path('/var/lib/sui-vps-acme')
ACME_LOGS=pathlib.Path('/var/log/sui-vps-acme')
COMPOSE=['docker','compose','-f',str(ROOT/'deploy/compose.yaml')]

def run(args, *, check=True, **kwargs):
    p=subprocess.run(args,stdout=subprocess.PIPE,stderr=subprocess.PIPE,**kwargs)
    if check and p.returncode:
        if ETC.is_dir():
            write(ETC/'last-error.txt','program='+args[0]+'\n'+p.stderr.decode(errors='replace'))
        raise RuntimeError('命令失败：'+args[0]+'；退出码 '+str(p.returncode)+'；详细错误保存在服务器受限 last-error.txt')
    return p

def write(path, data, mode=0o600):
    path=pathlib.Path(path);path.parent.mkdir(parents=True,exist_ok=True,mode=0o700)
    fd,tmp=tempfile.mkstemp(dir=path.parent)
    try:
        with os.fdopen(fd,'w') as f:f.write(data)
        os.chmod(tmp,mode);os.replace(tmp,path)
    finally:
        if os.path.exists(tmp):os.unlink(tmp)

def save(path, value):write(path,json.dumps(value,ensure_ascii=False,indent=2))
def load(path):return json.loads(pathlib.Path(path).read_text())

def claim_state(directory):
    directory=pathlib.Path(directory)
    marker=directory/'.managed'
    if directory.is_symlink():raise RuntimeError('状态目录不能是链接')
    if marker.exists():
        if marker.is_symlink() or marker.read_text()!='sui-vps-v1\n':raise RuntimeError('状态目录归属不符')
    elif directory.exists() and any(p.name!='target.json' for p in directory.iterdir()):
        raise RuntimeError('拒绝覆盖不属于本工具的状态目录')
    established=marker.exists() and directory.stat().st_mode & 0o777 == 0o710
    directory.mkdir(parents=True,exist_ok=True,mode=0o700);directory.chmod(0o710 if established else 0o700)
    write(marker,'sui-vps-v1\n')

def state():return load(STATE)
def record(s):save(STATE,s)

def target_check(s):
    ipaddress.IPv4Address(s['ip'])
    ips=run(['ip','-j','-4','addr','show','scope','global']).stdout
    found=[v['local'] for i in json.loads(ips) for v in i['addr_info']]
    if s['ip'] not in found:raise RuntimeError('目标 IP 与服务器地址不符')
    osr=pathlib.Path('/etc/os-release').read_text()
    if not ('ID=ubuntu' in osr and any('VERSION_ID="'+v+'"' in osr for v in ['22.04','24.04','26.04'])):
        raise RuntimeError('目前只支持 Ubuntu 22.04/24.04/26.04')
    if os.uname().machine not in ['x86_64','aarch64']:raise RuntimeError('架构不支持')

MANAGED_PREFIX='# Managed by sui-vps.\n'

def write_managed(path, contents, mode=0o644):
    path=pathlib.Path(path)
    if path.is_symlink() or (path.exists() and not path.read_text().startswith(MANAGED_PREFIX)):
        raise RuntimeError('拒绝覆盖其他项目的文件：'+str(path))
    write(path,contents if contents.startswith(MANAGED_PREFIX) else MANAGED_PREFIX+contents,mode)

def nginx_config(path, contents):
    path=pathlib.Path(path)
    previous=path.read_text() if path.exists() and not path.is_symlink() else None
    write_managed(path,contents)
    try:
        run(['nginx','-t']);systemctl('reload','nginx')
    except Exception:
        if previous is None:path.unlink(missing_ok=True)
        else:write(path,previous,0o644)
        run(['nginx','-t']);systemctl('reload','nginx')
        raise

def unit(name, contents):write_managed('/etc/systemd/system/'+name,contents)
def systemctl(*args):return run(['systemctl',*args])

def harden_ssh(keys=pathlib.Path('/root/.ssh/authorized_keys'), snippet=pathlib.Path('/etc/ssh/sshd_config.d/01-sui-vps.conf')):
    keys=pathlib.Path(keys);snippet=pathlib.Path(snippet)
    if keys.is_symlink() or not keys.is_file() or not keys.read_text().strip():raise RuntimeError('确认密钥登录后才能关闭 SSH 密码登录')
    policy='# Managed by sui-vps\nPubkeyAuthentication yes\nPasswordAuthentication no\nKbdInteractiveAuthentication no\nPermitRootLogin prohibit-password\n'
    previous=snippet.read_text() if snippet.exists() else None
    if previous and not previous.startswith('# Managed by sui-vps\n'):raise RuntimeError('拒绝覆盖其他 SSH 策略')
    write(snippet,policy,0o600)
    try:
        run(['/usr/sbin/sshd','-t'])
        effective=run(['/usr/sbin/sshd','-T']).stdout.decode()
        if 'passwordauthentication no' not in effective or 'pubkeyauthentication yes' not in effective:raise RuntimeError('SSH 策略被更早的设置覆盖')
        systemctl('reload','ssh')
    except Exception:
        if previous is None:snippet.unlink(missing_ok=True)
        else:write(snippet,previous,0o600)
        raise

def check_firewall_activation(tcp,udp,*,active,ssh_ports):
    if active:return
    expected_tcp=set(ssh_ports)|{80,443,2443,8443,9443,9444}
    for text,allowed in [(tcp,expected_tcp),(udp,{68,546})]:
        for line in text.splitlines():
            endpoint=line.split()[3];host,port=endpoint.rsplit(':',1)
            host=host.strip('[]').split('%')[0]
            try:local=ipaddress.ip_address(host).is_loopback
            except ValueError:local=False
            if not local and int(port) not in allowed:
                raise RuntimeError('UFW 尚未启用且检测到其他公网服务；先保留其访问规则再部署，不自动改变防火墙状态')

APT_LOCKS=('/var/lib/dpkg/lock-frontend','/var/lib/dpkg/lock','/var/lib/apt/lists/lock','/var/cache/apt/archives/lock')

def wait_for_apt(timeout=900, locks=APT_LOCKS, sleep=time.sleep):
    """Fresh provider images may run first-boot apt jobs; wait instead of failing on their locks."""
    deadline=time.monotonic()+timeout
    while True:
        busy=False
        for path in locks:
            if not os.path.exists(path):continue
            with open(path,'a') as handle:
                try:fcntl.lockf(handle,fcntl.LOCK_EX|fcntl.LOCK_NB)
                except OSError:busy=True;break
                fcntl.lockf(handle,fcntl.LOCK_UN)
        if not busy:return
        if time.monotonic()>=deadline:raise RuntimeError('系统软件包管理器长时间被其他任务占用；稍后重跑 base')
        sleep(5)

APT=['apt-get','-o','DPkg::Lock::Timeout=600']

def base():
    s=state();target_check(s)
    sshports=[int(line.split()[1]) for line in run(['/usr/sbin/sshd','-T']).stdout.decode().splitlines() if line.startswith('port ')]
    if not sshports:raise RuntimeError('无法确认 SSH 端口')
    ufw_status=run(['ufw','status'],env={**os.environ,'LC_ALL':'C'}).stdout.decode() if shutil.which('ufw') else ''
    check_firewall_activation(run(['ss','-H','-lnt']).stdout.decode(),run(['ss','-H','-lnu']).stdout.decode(),active='Status: active' in ufw_status,ssh_ports=sshports)
    # Refuse unfamiliar listeners before installing or touching firewall.
    if not s.get('base_done'):
        data=run(['ss','-H','-lnt']).stdout.decode()
        occupied={int(line.split()[3].rsplit(':',1)[1]) for line in data.splitlines()}
        conflicts=occupied & {80,443,2443,8443,9443,9444,2095,2096,8090,8317}
        if s.get('base_started') and conflicts=={80}:
            listeners=run(['ss','-H','-lntp','sport = :80']).stdout.decode()
            if 'nginx' in listeners:conflicts=set()
        if conflicts:raise RuntimeError('部署端口已有服务；不覆盖，请先检查')
    s['base_started']=True;record(s)
    wait_for_apt()
    run(APT+['update'])
    run(APT+['install','-y','ca-certificates','curl','nginx','python3-venv','openssl','ufw','docker.io','docker-compose-v2'],env={**os.environ,'DEBIAN_FRONTEND':'noninteractive'})
    systemctl('enable','--now','docker','nginx')
    # Validate timezone through timedatectl rather than interpolating into config.
    run(['timedatectl','set-timezone',s.get('timezone','Etc/UTC')]);run(['timedatectl','set-ntp','true'])
    write_managed('/etc/sysctl.d/90-sui-vps.conf','net.core.default_qdisc=fq\nnet.ipv4.tcp_congestion_control=bbr\n',0o644)
    run(['sysctl','--load','/etc/sysctl.d/90-sui-vps.conf'])
    sshports=[]
    for line in run(['/usr/sbin/sshd','-T']).stdout.decode().splitlines():
        if line.startswith('port '):sshports.append(int(line.split()[1]))
    if not sshports:raise RuntimeError('无法确认 SSH 端口')
    for port in sorted(set(sshports+[80,443,2443,8443,9443,9444])):run(['ufw','allow',str(port)+'/tcp'])
    # Existing UFW policies are not reset or replaced. Docker publishes only intended node ports.
    run(['ufw','--force','enable'])
    harden_ssh()
    s['base_done']=True;record(s)
    if (ETC/'export.json').exists():share_export()

def cert_validate(directory, min_seconds=3600):
    cert=pathlib.Path(directory)/'fullchain.pem';key=pathlib.Path(directory)/'privkey.pem'
    run(['openssl','x509','-in',str(cert),'-noout','-checkend',str(int(min_seconds))])
    public=run(['openssl','x509','-in',str(cert),'-pubkey','-noout']).stdout
    private=run(['openssl','pkey','-in',str(key),'-pubout']).stdout
    if public!=private:raise RuntimeError('证书与私钥不匹配')

def sync_pair(source, destination, *, validate=cert_validate, reload=None):
    source=pathlib.Path(source);destination=pathlib.Path(destination);validate(source)
    destination.mkdir(parents=True,exist_ok=True,mode=0o700)
    old={name:(destination/name).read_bytes() if (destination/name).exists() else None for name in ['fullchain.pem','privkey.pem']}
    def put(name,content):
        fd,tmp=tempfile.mkstemp(dir=destination)
        with os.fdopen(fd,'wb') as f:f.write(content)
        os.chmod(tmp,0o600 if name=='privkey.pem' else 0o644);os.replace(tmp,destination/name)
    try:
        for name in old:put(name,(source/name).read_bytes())
        if reload:reload()
    except Exception:
        for name,content in old.items():
            if content is not None:put(name,content)
            else:(destination/name).unlink(missing_ok=True)
        if reload and all(x is not None for x in old.values()):reload()
        raise

def check_loaded_certificates(expected_der, ports, *, fetch):
    for port in ports:
        if fetch(port)!=expected_der:raise RuntimeError('服务尚未加载当前证书：TCP '+str(port))

def tls_peer(port):
    import socket,ssl
    s=state()
    with socket.create_connection(('127.0.0.1',port),timeout=15) as connection:
        with ssl.create_default_context().wrap_socket(connection,server_hostname=s['ip']) as tls:
            return tls.getpeercert(binary_form=True)

def restart_tls():
    run(['nginx','-t']);systemctl('reload','nginx')
    p=run(COMPOSE+['ps','--status','running','-q'],check=False)
    if p.returncode==0 and p.stdout.strip():
        run(COMPOSE+['restart','s-ui']);wait_panel()
        expected=run(['openssl','x509','-in',str(ROOT/'deploy/state/cert/fullchain.pem'),'-outform','DER']).stdout
        check_loaded_certificates(expected,[9443,9444,2443,8443],fetch=tls_peer)

def cert_sync():
    s=state();source=ACME_CONFIG/'live/sui-vps'
    cert_validate(source)
    run(['openssl','x509','-in',str(source/'fullchain.pem'),'-noout','-checkip',s['ip']])
    sync_pair(source,ROOT/'deploy/state/cert',reload=restart_tls)

def https_config(s):
    cert=str(ROOT/'deploy/state/cert')
    return f'''# Managed by sui-vps. Token-bearing paths are never logged.
map $http_upgrade $sui_connection_upgrade {{ default upgrade; '' close; }}
server {{
 listen 9443 ssl;
 server_name {s['ip']};
 ssl_certificate {cert}/fullchain.pem;
 ssl_certificate_key {cert}/privkey.pem;
 access_log off;
 error_log /dev/null;
 add_header Referrer-Policy no-referrer always;
 location /app/ {{ proxy_pass http://127.0.0.1:2095; proxy_set_header Host $http_host; proxy_set_header X-Forwarded-Proto https; }}
 location /s/ {{ proxy_pass http://127.0.0.1:8090; }}
 location / {{ return 404; }}
}}
server {{
 listen 9444 ssl;
 server_name {s['ip']};
 ssl_certificate {cert}/fullchain.pem;
 ssl_certificate_key {cert}/privkey.pem;
 access_log off;
 error_log /dev/null;
 location = /management.html {{ alias /usr/local/lib/sui-cliproxy/static/management.html; }}
 location / {{
  proxy_pass http://127.0.0.1:8317;
  proxy_http_version 1.1;
  proxy_set_header Host $http_host;
  proxy_set_header X-Forwarded-Proto https;
  proxy_set_header Upgrade $http_upgrade;
  proxy_set_header Connection $sui_connection_upgrade;
  proxy_buffering off;
  proxy_read_timeout 3600s;
  proxy_send_timeout 3600s;
 }}
}}
'''

ACME_CARRY=pathlib.Path('/var/lib/sui-vps-acme-carry')

def adopt_carried_acme(s, carry=ACME_CARRY, target=ACME_CONFIG, validate=cert_validate):
    """Reuse a lineage saved before reinstall when it is for this IP and valid for at least a day."""
    carry=pathlib.Path(carry);target=pathlib.Path(target)
    if not carry.is_dir():return False
    try:
        if (target/'live/sui-vps/fullchain.pem').exists():return False
        source=carry/'acme'
        live=source/'live/sui-vps'
        for name in ['fullchain.pem','privkey.pem']:
            resolved=(live/name).resolve()
            if not resolved.is_file() or source.resolve() not in resolved.parents:raise RuntimeError('携带的证书链接指向目录之外')
        validate(live,min_seconds=86400)
        run(['openssl','x509','-in',str(live/'fullchain.pem'),'-noout','-checkip',s['ip']])
        if not (source/'renewal/sui-vps.conf').is_file():raise RuntimeError('携带的证书缺少续期配置')
        if target.exists():shutil.rmtree(target)
        shutil.move(str(source),str(target));target.chmod(0o700)
        print('复用重装前保存的 IP 证书。',flush=True)
        return True
    except Exception as e:
        print('不复用保存的证书，改为申请新证书：'+(str(e) if isinstance(e,RuntimeError) else type(e).__name__),flush=True)
        return False
    finally:
        shutil.rmtree(carry,ignore_errors=True)

def cert():
    s=state();adopt_carried_acme(s);web=pathlib.Path('/var/www/sui-vps-acme');web.mkdir(parents=True,exist_ok=True,mode=0o755);web.chmod(0o755)
    ACME_CONFIG.mkdir(parents=True,exist_ok=True,mode=0o700);ACME_CONFIG.chmod(0o700)
    acme='/etc/nginx/conf.d/sui-vps-acme.conf'
    nginx_config(acme,f'''server {{ listen 80; server_name {s['ip']}; access_log off; error_log /dev/null;
location ^~ /.well-known/acme-challenge/ {{ root {web}; }}
location / {{ return 404; }} }}\n''')
    env=pathlib.Path('/opt/sui-vps-certbot')
    if not (env/'bin/certbot').exists():
        run(['python3','-m','venv',str(env)])
        run([str(env/'bin/pip'),'install','certbot==5.4.0'])
    source=ACME_CONFIG/'live/sui-vps'
    valid=False
    try:cert_validate(source);valid=True
    except Exception:pass
    if not valid:
        run([str(env/'bin/certbot'),'--config-dir',str(ACME_CONFIG),'--work-dir',str(ACME_WORK),'--logs-dir',str(ACME_LOGS),'certonly','--no-directory-hooks','--non-interactive','--agree-tos','--register-unsafely-without-email','--webroot','-w',str(web),'--ip-address',s['ip'],'--cert-name','sui-vps','--preferred-profile','shortlived','--key-type','ecdsa','--preferred-challenges','http'])
    cert_sync()
    nginx_config('/etc/nginx/conf.d/sui-vps-https.conf',https_config(s))
    write(ACME_CONFIG/'renewal-hooks/deploy/40-sui-vps','#!/bin/sh\nset -eu\n[ "$RENEWED_LINEAGE" = /etc/sui-vps/acme/live/sui-vps ] || exit 0\nexec /usr/bin/python3 /opt/sui-vps/scripts/server.py cert-sync\n',0o700)
    unit('sui-vps-renew.service','[Unit]\nDescription=Renew trusted IP certificate; failures visible in journal\n[Service]\nType=oneshot\nExecStart=/opt/sui-vps-certbot/bin/certbot --config-dir /etc/sui-vps/acme --work-dir /var/lib/sui-vps-acme --logs-dir /var/log/sui-vps-acme renew --cert-name sui-vps --no-random-sleep-on-renew\n')
    unit('sui-vps-renew.timer','[Unit]\nDescription=Check IP certificate every six hours\n[Timer]\nOnCalendar=*-*-* 00,06,12,18:00:00 UTC\nRandomizedDelaySec=300\nPersistent=true\n[Install]\nWantedBy=timers.target\n')
    systemctl('daemon-reload');systemctl('enable','--now','sui-vps-renew.timer')

def cert_dry_run():
    run(['/opt/sui-vps-certbot/bin/certbot','--config-dir',str(ACME_CONFIG),'--work-dir',str(ACME_WORK),'--logs-dir',str(ACME_LOGS),'renew','--cert-name','sui-vps','--dry-run','--no-directory-hooks','--no-random-sleep-on-renew'])
    checks=load(ETC/'lifecycle.json') if (ETC/'lifecycle.json').exists() else {}
    checks['certificate_dry_run']={'result':'通过','checked_at':datetime.datetime.now(datetime.timezone.utc).isoformat(),
                                    'sync_and_load':'未由 dry-run 验证'}
    save(ETC/'lifecycle.json',checks)

def restore_check():
    import recovery
    archives=sorted(p for p in claim_backup_directory('/var/backups/sui-vps').glob('*.tar.gz') if p.is_file() and not p.is_symlink())
    if not archives:raise RuntimeError('没有本项目备份可供检查')
    # Extraction/validation occurs in an isolated staging directory; no host restore implied.
    report=recovery.restore_check(archives[-1], expected_ip=state()['ip'], output=ETC/'restore-check.json')
    if not report.get('valid'):raise RuntimeError('备份完整性检查失败；查看受限 restore-check.json')

def restore():
    import argparse,recovery
    parser=argparse.ArgumentParser(prog='server.py restore')
    parser.add_argument('--archive',required=True);parser.add_argument('--confirm-target',required=True)
    args=parser.parse_args(sys.argv[2:])
    directory=claim_backup_directory('/var/backups/sui-vps')
    archive=pathlib.Path(args.archive)
    if archive.parent!=directory or archive.is_symlink() or not archive.is_file() or archive.stat().st_uid!=0 or archive.stat().st_mode & 0o077:
        raise RuntimeError('恢复仅接受项目备份目录下归属 root、权限 600 的普通归档')
    current=state();target_check(current)
    def prepare(root,prior):
        recovery.system_permissions(root,prior);share_export()
    def health(root,prior):
        if prior.get('s-ui'):
            wait_panel()
            import panel as manager
            restored=state();api=manager.PanelAPI()
            api.call('login',{'user':restored['panel']['username'],'pass':restored['panel']['password']})
            if api.call('status?r=sbd').get('sbd',{}).get('running') is not True:raise RuntimeError('恢复后核心未运行')
        recovery.system_health(root,prior)
        expected=run(['openssl','x509','-in',str(ROOT/'deploy/state/cert/fullchain.pem'),'-outform','DER']).stdout
        ports=[2443,8443] if prior.get('s-ui') else []
        if run(['systemctl','is-active','nginx'],check=False).returncode==0:ports += [9443,9444]
        check_loaded_certificates(expected,ports,fetch=tls_peer)
    def rollback(root,prior):prepare(root,prior);health(root,prior)
    report=recovery.restore_archive(archive,expected_ip=current['ip'],confirm_target=args.confirm_target,
                                    prepare=prepare,post_restore=health,post_rollback=rollback)
    save(ETC/'restore-result.json',report)
    if report.get('status')!='committed':raise RuntimeError('恢复未成功；已记录回滚结果，请查看 restore-result.json')
    export=load(ETC/'export.json')
    export.setdefault('verification',{})['lifecycle']='已恢复文件与先前运行的服务；节点网络、真客户端及防泄露须重新检查'
    for key in ['network','clients','leaks','clean_os']:export['verification'][key]='恢复后未测试'
    save(ETC/'export.json',export);share_export()
    print('文件与原先运行的服务已恢复；请重新运行 verify、network 和 export。')

def wait_panel():
    for i in range(30):
        if run(COMPOSE+['exec','-T','s-ui','./sui','healthcheck'],check=False).returncode==0:return
        time.sleep(2)
    raise RuntimeError('S-UI 健康检查超时')

def panel():
    for p in ['db','cert']:(ROOT/'deploy/state'/p).mkdir(parents=True,exist_ok=True,mode=0o700)
    versions=load(ROOT/'versions.json')
    previous=state().get('versions',{})
    if previous.get('s_ui_image') and previous['s_ui_image']!=versions['s_ui_image']:
        receipt=load(ETC/'source-update-backup.json') if (ETC/'source-update-backup.json').exists() else {}
        if receipt.get('versions',{}).get('s_ui_image')!=previous['s_ui_image'] or not pathlib.Path(receipt.get('archive','/nonexistent')).is_file():
            raise RuntimeError('升级前缺少匹配旧版本的源码与状态备份；从本机部署入口重新执行')
        save(ETC/'previous-version.json',previous)
    compose=(ROOT/'deploy/compose.yaml').read_text()
    if versions['s_ui_image'] not in compose or '@sha256:' not in versions['s_ui_image']:raise RuntimeError('镜像清单与 Compose 不一致')
    run(COMPOSE+['config','--quiet']);run(COMPOSE+['pull']);run(COMPOSE+['up','-d']);wait_panel()
    import panel as manager
    s=state();s['versions']=versions;s['public_base_url']='https://'+s['ip']+':9443';record(s)
    manager.configure(str(STATE),export_path=str(ETC/'export.json'))
    export=load(ETC/'export.json');export['public_base_url']=s['public_base_url'];save(ETC/'export.json',export)
    share_export()

def subscription_snapshot(export):
    return {key:export[key] for key in ['nodes','subscriptions','public_base_url','traffic'] if key in export}

def share_export():
    export_path=ETC/'export.json'
    export_path.chmod(0o600)
    run(['chown','root:root',str(export_path)])
    if run(['id','-u','sui-sub'],check=False).returncode==0:
        public=ETC/'subscription-export.json'
        save(public,subscription_snapshot(load(export_path)))
        run(['chgrp','sui-sub',str(ETC),str(public)]);ETC.chmod(0o710);public.chmod(0o640)
    for p in [ETC/'kiwivm.json',ETC/'state.json',ETC/'traffic.json']:
        if p.exists():run(['chown','root:root',str(p)]);p.chmod(0o600)

def rotate_subscriptions(client='all'):
    import secrets, subscription
    if client not in ['all',*subscription.CLIENTS]:raise RuntimeError('请选择 surge、v2ray、clash、shadowrocket 或 all')
    export=load(ETC/'export.json')
    clients=list(subscription.CLIENTS) if client=='all' else [client]
    for name in clients:export['subscriptions'][name]=secrets.token_urlsafe(32)
    save(ETC/'export.json',export);share_export()
    print('订阅令牌已轮换；请重新导出本机账号页并更新相应客户端。')

def interface_counters():
    routes=json.loads(run(['ip','-j','route','show','default']).stdout or b'[]')
    devices={r.get('dev') for r in routes if r.get('dev')}
    if len(devices)!=1:raise RuntimeError('无法确定唯一的默认出口网卡')
    device=devices.pop()
    if not device.replace('-','').replace('.','').replace('_','').isalnum():raise RuntimeError('网卡名称异常')
    base=pathlib.Path('/sys/class/net')/device/'statistics'
    return int((base/'rx_bytes').read_text()),int((base/'tx_bytes').read_text())

def current_traffic(calibrate_gb=None):
    import subscription
    if (ETC/'kiwivm.json').exists():
        if calibrate_gb is not None:raise RuntimeError('已使用搬瓦工官方读数，不需要校准本机统计')
        return subscription.traffic_snapshot(ETC/'kiwivm.json',ETC/'traffic.json')
    target=load(ETC/'target.json')
    return subscription.local_traffic_snapshot(ETC/'traffic-local.json',interface_counters(),target,calibrate_gb=calibrate_gb)

def traffic(calibrate_gb=None):
    export=load(ETC/'export.json')
    export['traffic']=current_traffic(calibrate_gb)
    save(ETC/'export.json',export);share_export()

def traffic_calibrate():
    if len(sys.argv)!=3:raise RuntimeError('用法：traffic-calibrate 本月已用GB')
    try:value=float(sys.argv[2])
    except ValueError:raise RuntimeError('已用量必须是数字') from None
    traffic(value)
    print('本机流量统计已按 '+str(value)+' GB 校准。')

RULES=pathlib.Path('/var/lib/sui-vps/rules')

def fetch_rule_file(url, limit=64*1024*1024):
    import urllib.request
    opener=urllib.request.build_opener(urllib.request.ProxyHandler({}))
    with opener.open(urllib.request.Request(url,headers={'User-Agent':'sui-vps-rules/1'}),timeout=60) as r:
        data=r.read(limit+1)
    if len(data)>limit:raise RuntimeError('规则文件过大')
    return data

def rules(fetch=fetch_rule_file, directory=RULES):
    """Mirror public rule data; keep the previous copy whenever download or checksum fails."""
    source=load(ROOT/'versions.json')['rule_data']
    base=source['base_url']
    if not base.startswith('https://github.com/MetaCubeX/meta-rules-dat/releases/download/') or not base.endswith('/'):
        raise RuntimeError('规则数据来源不符')
    directory=pathlib.Path(directory)
    directory.mkdir(parents=True,exist_ok=True,mode=0o755);directory.chmod(0o755)
    updated=[]
    for name in source['files']:
        if name not in ('geosite.dat','geoip.metadb','GeoLite2-ASN.mmdb'):raise RuntimeError('未知规则文件')
        data=fetch(base+name)
        digest=fetch(base+name+'.sha256sum',limit=4096).decode().split()
        if not data or not digest or digest[0].lower()!=hashlib.sha256(data).hexdigest():
            raise RuntimeError('规则文件校验失败：'+name+'；保留上一份')
        fd,tmp=tempfile.mkstemp(dir=directory)
        try:
            with os.fdopen(fd,'wb') as f:f.write(data)
            os.chmod(tmp,0o644);os.replace(tmp,directory/name)
        finally:
            if os.path.exists(tmp):os.unlink(tmp)
        updated.append(name)
    save(ETC/'rules.json',{'updated_at':datetime.datetime.now(datetime.timezone.utc).isoformat(),'files':updated,'source':base})

def services():
    import cliproxy, subscription
    s=state();extra=cliproxy.install(s)
    # Installer may generate new credentials; persist before returning control.
    record(s)
    export=load(ETC/'export.json');export['cli_proxy']=extra
    tokens=export.setdefault('subscriptions',{})
    for client in subscription.CLIENTS:tokens.setdefault(client,subscription.new_token())
    export.setdefault('verification',{})
    export['verification'].update({key:'未测试' for key in ['network','clients','leaks','lifecycle','clean_os'] if key not in export['verification']})
    try:export['traffic']=current_traffic()
    except (RuntimeError,OSError,ValueError):export['traffic']={'source':'local-interface','status':'unavailable'}
    save(ETC/'export.json',export)
    # Dedicated identity sees only node facts and quota snapshot, never administration/provider secrets.
    run(['id','sui-sub'],check=False)
    if run(['id','-u','sui-sub'],check=False).returncode:run(['useradd','--system','--no-create-home','--shell','/usr/sbin/nologin','sui-sub'])
    share_export()
    unit('sui-vps-sub.service',f'''[Unit]
Description=Private client subscriptions
After=network-online.target
[Service]
User=sui-sub
Group=sui-sub
ExecStart=/usr/bin/python3 {ROOT}/scripts/subscription.py --export /etc/sui-vps/subscription-export.json --no-provider
Restart=on-failure
NoNewPrivileges=true
ProtectSystem=strict
ProtectHome=true
PrivateTmp=true
[Install]
WantedBy=multi-user.target
''')
    # /opt source must be traversable by service identity; private state remains separately restricted.
    ROOT.chmod(0o755)
    systemctl('daemon-reload');systemctl('enable','--now','sui-vps-sub');systemctl('restart','sui-vps-sub')

def backup_paths():
    paths=[ETC,ROOT/'scripts',ROOT/'deploy',ROOT/'versions.json',
           pathlib.Path('/var/lib/sui-cliproxy'),pathlib.Path('/usr/local/lib/sui-cliproxy')]
    paths += [pathlib.Path('/etc/nginx/conf.d')/('sui-vps-'+name+'.conf') for name in ['acme','https']]
    paths += [pathlib.Path('/etc/sysctl.d/90-sui-vps.conf'),pathlib.Path('/etc/ssh/sshd_config.d/01-sui-vps.conf')]
    paths += list(pathlib.Path('/etc/systemd/system').glob('sui-vps-*'))
    paths.append(pathlib.Path('/etc/systemd/system/sui-cliproxy.service'))
    return [p for p in paths if not p.is_symlink()]

def claim_backup_directory(directory):
    directory=pathlib.Path(directory)
    if any(p.is_symlink() for p in [directory,*directory.parents]):raise RuntimeError('备份目录不能是符号链接')
    marker=directory/'.managed'
    if directory.exists():
        if not directory.is_dir() or directory.stat().st_uid!=os.geteuid():raise RuntimeError('备份目录归属不符')
        if any(directory.iterdir()) and (marker.is_symlink() or not marker.is_file() or marker.read_text()!='sui-vps-backups-v1\n'):
            raise RuntimeError('拒绝清理不属于本项目的备份目录')
    directory.mkdir(parents=True,exist_ok=True,mode=0o700);directory.chmod(0o700)
    write(marker,'sui-vps-backups-v1\n')
    return directory

def backup():
    directory=claim_backup_directory('/var/backups/sui-vps')
    dest=directory/(datetime.datetime.now(datetime.timezone.utc).strftime('%Y%m%dT%H%M%S.%fZ')+'.tar.gz')
    panel_running=bool(run(COMPOSE+['ps','--status','running','-q','s-ui']).stdout.strip())
    cli_running=run(['systemctl','is-active','sui-cliproxy'],check=False).returncode==0
    try:
        if panel_running:run(COMPOSE+['stop','s-ui'])
        if cli_running:systemctl('stop','sui-cliproxy')
        with tempfile.TemporaryDirectory(dir=directory) as d:
            temp=pathlib.Path(d)/'backup.tar.gz'
            with tarfile.open(temp,'w:gz') as t:
                for p in backup_paths():
                    if p.exists():t.add(p,arcname=str(p).lstrip('/'))
            temp.chmod(0o600);os.replace(temp,dest)
    finally:
        # Restart each prior service even if restarting the other fails.
        try:
            if panel_running:run(COMPOSE+['start','s-ui'])
        finally:
            if cli_running:systemctl('start','sui-cliproxy')
    if panel_running:wait_panel()
    save(ETC/'last-backup.json',{'archive':str(dest),'versions':state().get('versions',{}),'source_sha256':state().get('source_sha256')})
    import re
    archives=[p for p in directory.glob('*.tar.gz') if p.is_file() and not p.is_symlink() and re.fullmatch(r'[0-9]{8}T[0-9]{6}(?:\.[0-9]{6})?Z\.tar\.gz',p.name)]
    for old in sorted(archives)[:-7]:old.unlink()

def maint():
    unit('sui-vps-traffic.service',f'[Unit]\nDescription=Refresh official traffic privately\n[Service]\nType=oneshot\nExecStart=/usr/bin/python3 {ROOT}/scripts/server.py traffic\n')
    unit('sui-vps-traffic.timer','[Unit]\nDescription=Refresh official quota every ten minutes\n[Timer]\nOnBootSec=2min\nOnUnitActiveSec=10min\n[Install]\nWantedBy=timers.target\n')
    systemctl('daemon-reload');systemctl('enable','--now','sui-vps-traffic.timer')
    unit('sui-vps-backup.service',f'[Unit]\nDescription=Private daily state backup\n[Service]\nType=oneshot\nExecStart=/usr/bin/python3 {ROOT}/scripts/server.py backup\n')
    unit('sui-vps-backup.timer','[Unit]\nDescription=Daily backup\n[Timer]\nOnCalendar=daily\nPersistent=true\n[Install]\nWantedBy=timers.target\n')
    systemctl('daemon-reload');systemctl('enable','--now','sui-vps-backup.timer')
    unit('sui-vps-rules.service',f'[Unit]\nDescription=Mirror Clash rule data; keeps previous copy on failure\nAfter=network-online.target\n[Service]\nType=oneshot\nExecStart=/usr/bin/python3 {ROOT}/scripts/server.py rules\n')
    unit('sui-vps-rules.timer','[Unit]\nDescription=Refresh Clash rule data daily\n[Timer]\nOnCalendar=daily\nRandomizedDelaySec=1h\nPersistent=true\n[Install]\nWantedBy=timers.target\n')
    systemctl('daemon-reload');systemctl('enable','sui-vps-rules.timer');systemctl('start','sui-vps-rules.timer')
    # First mirror now; a failed download is reported by verify instead of blocking deployment.
    try:rules()
    except Exception as e:print('规则镜像暂未完成：'+(str(e) if isinstance(e,RuntimeError) else type(e).__name__),flush=True)

def verify():
    import ssl, socket, urllib.request, urllib.error
    import cliproxy, panel as manager, subscription
    s=state();results={};export=load(ETC/'export.json')
    def check(name, fn):
        try:fn();results[name]='通过'
        except Exception:results[name]='失败'
    def must(value):
        if not value:raise RuntimeError('检查结果不符合预期')
    check('target',lambda:target_check(s))
    check('panel_health',wait_panel)
    def fixed_runtime():
        versions=load(ROOT/'versions.json')
        container=run(COMPOSE+['ps','-q','s-ui']).stdout.decode().strip()
        must(bool(container) and not any(x.isspace() for x in container))
        image=run(['docker','inspect','--format','{{.Config.Image}}',container]).stdout.decode().strip()
        must(image==versions['s_ui_image'])
        runtime=run(COMPOSE+['exec','-T','s-ui','./sui','-v']).stdout.decode()
        must(versions['s_ui_version'].lstrip('v') in runtime and 'v'+versions['s_ui_core_version'] in runtime)
    check('fixed_image_and_core_runtime',fixed_runtime)
    check('certificate_pair',lambda:cert_validate(ROOT/'deploy/state/cert'))
    check('nginx',lambda:run(['nginx','-t']))
    def bbr_check():
        sysctl=lambda key:pathlib.Path('/proc/sys/'+key.replace('.','/')).read_text().strip()
        must(sysctl('net.ipv4.tcp_congestion_control')=='bbr' and sysctl('net.core.default_qdisc')=='fq')
    check('bbr',bbr_check)
    for service in ['sui-vps-sub','sui-cliproxy','sui-vps-renew.timer','sui-vps-backup.timer','sui-vps-rules.timer']:
        check(service,lambda service=service:systemctl('is-active',service))
    def api_check():
        api=manager.PanelAPI()
        api.call('login',{'user':s['panel']['username'],'pass':s['panel']['password']})
        must(api.call('status?r=sbd').get('sbd',{}).get('running') is True)
        actual=api.call('singbox-config',raw=True)
        must({x['tag'] for x in actual['inbounds']} >= {'sui-vps-reality','sui-vps-vless-tls','sui-vps-anytls'})
        wrong=manager.PanelAPI()
        try:wrong.call('login',{'user':'admin','pass':'admin'})
        except manager.PanelTransportError:raise
        except manager.PanelError:return
        raise RuntimeError('默认管理员仍可登录')
    check('core_and_admin',api_check)
    def port_check():
        lines=run(['ss','-H','-lnt']).stdout.decode().splitlines()
        for port in [2095,2096,8090,8317]:
            endpoints=[line.split()[3] for line in lines if line.split()[3].endswith(':'+str(port))]
            must(bool(endpoints) and all(x.startswith('127.0.0.1:') for x in endpoints))
        must('443:443/udp' not in (ROOT/'deploy/compose.yaml').read_text())
    check('private_listeners',port_check)
    def https_get(url):
        opener=urllib.request.build_opener(urllib.request.ProxyHandler({}))
        with opener.open(url,timeout=15) as r:return r.status,r.read()
    def subscriptions_check():
        urls=subscription.subscription_urls(export)
        for kind,url in urls.items():
            code,body=https_get(url);must(code==200 and bool(body))
            expected=subscription.RENDERERS[kind](export)
            must(body.decode()==expected)
        for name in subscription.FILENAMES.values():
            try:https_get(export['public_base_url']+'/s/'+'A'*43+'/'+name)
            except urllib.error.HTTPError as e:must(e.code==404)
            else:raise RuntimeError('错误令牌返回配置')
    check('authenticated_https_subscriptions',subscriptions_check)
    def rules_check():
        base=subscription.subscription_urls(export)['clash'].rsplit('/',1)[0]+'/geo/'
        for name in subscription.GEO_FILES:
            local=(RULES/name).read_bytes();must(len(local)>1024)
            code,body=https_get(base+name);must(code==200 and body==local)
            try:https_get(export['public_base_url']+'/s/'+'A'*43+'/geo/'+name)
            except urllib.error.HTTPError as e:must(e.code==404)
            else:raise RuntimeError('错误令牌返回规则文件')
    check('rules_mirror',rules_check)
    def ipv4_egress():
        actual=manager.PanelAPI();actual.call('login',{'user':s['panel']['username'],'pass':s['panel']['password']})
        manager.check_ipv4_only(actual.call('singbox-config',raw=True))
    check('ipv4_only_egress_config',ipv4_egress)
    check('public_panel',lambda:must(https_get(export['panel']['url'])[0]==200))
    def cert_loaded():
        context=ssl.create_default_context()
        with socket.create_connection((s['ip'],9443),timeout=10) as sock:
            with context.wrap_socket(sock,server_hostname=s['ip']) as conn:loaded=conn.getpeercert(binary_form=True)
        disk=run(['openssl','x509','-in',str(ROOT/'deploy/state/cert/fullchain.pem'),'-outform','DER']).stdout
        must(loaded==disk)
        check_loaded_certificates(disk,[9444,2443,8443],fetch=tls_peer)
    check('trusted_certificate_loaded',cert_loaded)
    def reality_fallback():
        # Unauthenticated TLS on the Reality port must be relayed to this server's own certificate.
        disk=run(['openssl','x509','-in',str(ROOT/'deploy/state/cert/fullchain.pem'),'-outform','DER']).stdout
        check_loaded_certificates(disk,[int(s.get('ports',{}).get('reality',443))],fetch=tls_peer)
    # Deployments created before self fallback keep their external target; nothing to check there.
    if s.get('reality',{}).get('target')=='self':check('reality_self_fallback',reality_fallback)
    check('cliproxy_authentication',lambda:cliproxy.verify(s))
    report={'checked_at':datetime.datetime.now(datetime.timezone.utc).isoformat(),
            'source_sha256':s.get('source_sha256'),'checks':results,
            'service':'通过' if all(x=='通过' for x in results.values()) else '失败',
            'network':'未测试','clients':'未测试','leaks':'未测试','lifecycle':'未测试','clean_os':'未测试'}
    save(ETC/'verification.json',report)
    export.setdefault('verification',{})['service']=report['service']
    export['verification']['service_details']=results
    save(ETC/'export.json',export);share_export()
    print('服务检查：'+report['service']+'；其他验收层级未测试。结果已写入私有记录。')
    if report['service']!='通过':raise RuntimeError('服务检查未通过；查看 verification.json 的失败项目')

def main():
    if os.geteuid()!=0:raise RuntimeError('请由 root 运行服务器阶段')
    phase=sys.argv[1]
    if phase not in ['deploy','base','cert','cert-sync','cert-dry-run','restore-check','restore','rotate-subscriptions','panel','services','maint','backup','traffic','traffic-calibrate','rules','verify']:raise RuntimeError('未知阶段')
    # Serialize phases, renew hooks and backups to prevent partial competing updates.
    with open('/run/sui-vps.lock','w') as lock:
        fcntl.flock(lock,fcntl.LOCK_EX)
        if phase=='deploy' or phase=='base':
            claim_state(ETC)
            if not STATE.exists():
                s=load(ETC/'target.json');s['deployed_at']=datetime.datetime.now(datetime.timezone.utc).isoformat();record(s)
        if phase in ['deploy','base','cert','panel','services','maint'] and STATE.exists():
            current=state();target=load(ETC/'target.json')
            if current['ip']!=target['ip'] or current.get('ssh_alias')!=target.get('ssh_alias'):
                raise RuntimeError('已有状态与本次目标不同；拒绝覆盖')
            current['source_sha256']=target['source_sha256'];record(current)
        phases=['base','cert','panel','services','maint','verify'] if phase=='deploy' else [phase]
        for step in phases:
            print('正在执行：'+step,flush=True)
            if step=='rotate-subscriptions':rotate_subscriptions(sys.argv[2] if len(sys.argv)>2 else 'all')
            else:globals()[step.replace('-','_')]()
            print('阶段完成：'+step,flush=True)

if __name__=='__main__':
    try:main()
    except Exception as e:
        print('停止：'+str(e) if isinstance(e,RuntimeError) else '停止：'+type(e).__name__+'；未输出含凭据的命令结果',file=sys.stderr);sys.exit(1)
