#!/usr/bin/env python3
"""Local SSH orchestrator; provider credentials travel only over curl stdin."""
import argparse
import hashlib
import getpass
import io
import ipaddress
import json
import os
from pathlib import Path
import re
import secrets
import shlex
import shutil
import stat
import subprocess
import sys
import tarfile
import tempfile
import time
import urllib.parse
import warnings

ROOT = Path(__file__).resolve().parents[1]
SOURCE_FILES = ('scripts/server.py', 'scripts/panel.py', 'scripts/subscription.py',
                'scripts/cliproxy.py', 'scripts/probe.py', 'scripts/recovery.py', 'deploy/compose.yaml', 'versions.json')
API_METHODS = {'getServiceInfo', 'getLiveServiceInfo', 'getAvailableOS', 'getSshKeys',
               'updateSshKeys', 'stop', 'start', 'reinstallOS', 'basicShell/exec'}
OWNER_MARK = '/opt/sui-vps/.managed'


WINDOWS = os.name == 'nt'
NULL_DEVICE = os.devnull  # 'nul' on Windows, '/dev/null' elsewhere


def restrict_windows(path):
    """Windows has no Unix modes: strip inherited ACLs and grant only the current user (OpenSSH demands this for keys)."""
    if not WINDOWS: return
    path = Path(path)
    grant = getpass.getuser()+(':(OI)(CI)F' if path.is_dir() else ':F')
    result = subprocess.run(['icacls', str(path), '/inheritance:r', '/grant:r', grant], capture_output=True)
    if result.returncode != 0: raise ValueError('Could not restrict Windows permissions on a private path')


def secure_path(path, exists=True):
    path = Path(path).expanduser().absolute()
    # Reject symlinks anywhere, including an ancestor. Files live beneath a private parent.
    for part in [path, *path.parents]:
        if part.is_symlink() and str(part) not in {'/var', '/tmp', '/etc'}:
            raise ValueError('Private paths must not contain symlinks')
    parent = path.parent
    if WINDOWS:
        # Unix mode/owner bits are meaningless on NTFS; enforce owner-only ACLs instead.
        if not parent.is_dir(): raise ValueError('Private parent directory is missing')
        restrict_windows(parent)
        if exists:
            if not path.is_file(): raise ValueError('Private file is missing')
            restrict_windows(path)
        elif path.exists():
            secure_path(path)
        return path
    if not parent.is_dir() or parent.stat().st_mode & 0o077:
        raise ValueError('Private parent directory must have mode 700')
    if parent.stat().st_uid != os.getuid(): raise ValueError('Private directory ownership mismatch')
    if exists:
        info = path.stat()
        if not stat.S_ISREG(info.st_mode) or info.st_mode & 0o077 or info.st_uid != os.getuid():
            raise ValueError('Private file must be owned by you and have mode 600')
    elif path.exists():
        secure_path(path)
    return path


def private_json(path):
    return json.loads(secure_path(path).read_text())


def write_private(path, data):
    path = Path(path).expanduser().absolute()
    if not path.parent.exists():
        path.parent.mkdir(parents=True, mode=0o700); restrict_windows(path.parent)
    path = secure_path(path, exists=False)
    fd, tmp = tempfile.mkstemp(prefix='.'+path.name+'-', dir=path.parent)
    try:
        with os.fdopen(fd, 'wb') as f:
            f.write(data); f.flush(); os.fsync(f.fileno())
        os.replace(tmp, path)
        restrict_windows(path)
    finally:
        if os.path.exists(tmp): os.unlink(tmp)


def save(path, value):
    write_private(path, (json.dumps(value, ensure_ascii=False, indent=2)+'\n').encode())


def run(args, **kwargs):
    return subprocess.run(args, check=True, **kwargs)


def validate(s):
    ipaddress.IPv4Address(s['ip'])
    if not re.fullmatch(r'[a-zA-Z][a-zA-Z0-9-]*', s['ssh_alias']):
        raise ValueError('Invalid SSH alias')
    cfg = run(['ssh', '-G', s['ssh_alias']], capture_output=True, text=True).stdout
    pairs = dict(line.split(' ', 1) for line in cfg.splitlines() if ' ' in line)
    if pairs.get('hostname') != s['ip'] or pairs.get('user') != 'root':
        raise ValueError('SSH alias target mismatch')
    if s.get('identity_file'): secure_path(s['identity_file'])
    s.setdefault('ssh_port',int(pairs.get('port','22')))
    if 'ssh_port' in s and not 1 <= int(s['ssh_port']) <= 65535:
        raise ValueError('Invalid SSH port')
    if 'traffic_quota_gb' in s and not 0 < float(s['traffic_quota_gb']) <= 1_000_000:
        raise ValueError('traffic_quota_gb must be a positive number of GiB')
    if 'traffic_reset_day' in s and not 1 <= int(s['traffic_reset_day']) <= 28:
        raise ValueError('traffic_reset_day must be 1-28')
    if s.get('traffic_count', 'both') not in ('both', 'out', 'in', 'max'):
        raise ValueError('traffic_count must be both, out, in or max')
    return pairs


def ssh_args(s, *, password=False):
    args = ['ssh']
    if password or s.get('_isolated_auth'):
        # Authentication proof must not silently fall back to another configured key/agent.
        args += ['-F', NULL_DEVICE, '-l', 'root']
    args += ['-o', 'BatchMode='+('no' if password else 'yes'),
             '-o', 'StrictHostKeyChecking=yes', '-o', 'CheckHostIP=yes',
             '-o', 'ConnectTimeout=10', '-o', 'ServerAliveInterval=20']
    if s.get('known_hosts_file'):
        known = secure_path(s['known_hosts_file'])
        args += ['-o', 'UserKnownHostsFile='+str(known), '-o', 'GlobalKnownHostsFile='+NULL_DEVICE]
    elif password or s.get('_isolated_auth'):
        raise ValueError('Bootstrap requires an explicit trusted known_hosts file')
    if s.get('ssh_port'): args += ['-p', str(s['ssh_port'])]
    if password:
        args += ['-o', 'PreferredAuthentications=password,keyboard-interactive',
                 '-o', 'PubkeyAuthentication=no', '-o', 'NumberOfPasswordPrompts=1']
    elif s.get('identity_file'):
        args += ['-i', str(secure_path(s['identity_file'])), '-o', 'IdentitiesOnly=yes',
                 '-o', 'IdentityAgent=none', '-o', 'PreferredAuthentications=publickey']
    return args+[s['ip'] if password or s.get('_isolated_auth') else s['ssh_alias']]


def ssh(s, command, **kwargs):
    kwargs.setdefault('capture_output', True)
    return run(ssh_args(s)+[command], **kwargs)


def openssh_version():
    try: out = subprocess.run(['ssh', '-V'], capture_output=True, text=True).stderr
    except OSError: return None
    m = re.search(r'OpenSSH_(?:for_Windows_)?(\d+)\.(\d+)', out)
    return (int(m.group(1)), int(m.group(2))) if m else None


def _askpass_script(directory, password_file):
    """A helper OpenSSH runs to read the password; it only prints the private password file."""
    ssh_path = (shutil.which('ssh') or '').lower()
    if WINDOWS and 'system32' in ssh_path:
        # Win32-OpenSSH starts the helper with CreateProcess, so it must be a .cmd file.
        script = directory/'askpass.cmd'
        script.write_text('@echo off\r\ntype "%SUI_PW_FILE%"\r\n')
    else:
        # macOS, Linux, and Git-for-Windows (MSYS) ssh all run a POSIX shell script.
        script = directory/'askpass.sh'
        script.write_text('#!/bin/sh\ncat "$SUI_PW_FILE"\n')
        script.chmod(0o700)
    restrict_windows(script)
    return script


def password_ssh(s, command, password, **kwargs):
    if not password or '\n' in password or '\r' in password or '\0' in password or len(password.encode()) > 4096:
        raise ValueError('Password must be a nonempty single line of at most 4096 bytes')
    version = openssh_version()
    if not version or version < (8, 4):
        raise ValueError('Password login needs OpenSSH 8.4 or newer on this computer (ssh -V); on Windows install Git for Windows and use its ssh')
    args = ssh_args(s, password=True)+[command]
    # SSH_ASKPASS_REQUIRE=force (OpenSSH 8.4+) replaces sshpass: the password sits only in a private temp file.
    base = Path(s['known_hosts_file']).parent
    directory = Path(tempfile.mkdtemp(prefix='.askpass-', dir=base))
    try:
        restrict_windows(directory)
        password_file = directory/'pw'
        fd = os.open(password_file, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        with os.fdopen(fd, 'w') as f: f.write(password+'\n')
        restrict_windows(password_file)
        script = _askpass_script(directory, password_file)
        env = {k:v for k,v in os.environ.items() if k not in {'SSHPASS','SSH_ASKPASS','SSH_ASKPASS_REQUIRE'}}
        env.update(SSH_ASKPASS=str(script), SSH_ASKPASS_REQUIRE='force', SUI_PW_FILE=str(password_file))
        env.setdefault('DISPLAY', 'none')
        kwargs.setdefault('capture_output', True)
        if 'input' not in kwargs: kwargs.setdefault('stdin', subprocess.DEVNULL)
        return run(args, env=env, **kwargs)
    finally:
        shutil.rmtree(directory, ignore_errors=True)


def dedicated_key(s, state_path):
    if s.get('identity_file'):
        key = secure_path(s['identity_file'])
    else:
        directory = state_path.parent/'ssh'
        if directory.is_symlink(): raise ValueError('Key directory must not be a symlink')
        directory.mkdir(mode=0o700, exist_ok=True); restrict_windows(directory)
        if not WINDOWS and directory.stat().st_mode & 0o077: raise ValueError('Key directory must have mode 700')
        key = secure_path(directory/'id_ed25519', exists=False)
        if not key.exists():
            if key.with_suffix('.pub').exists() or key.with_suffix('.pub').is_symlink():
                raise ValueError('Public key path already exists without its private key')
            run(['ssh-keygen','-q','-t','ed25519','-N','','-C','sui-vps-local','-f',str(key)], capture_output=True)
            key.chmod(0o600); restrict_windows(key)
            public = key.with_suffix('.pub')
            if public.exists(): public.chmod(0o600); restrict_windows(public)
    public = ' '.join(run(['ssh-keygen','-y','-f',str(key)], capture_output=True, text=True).stdout.split()[:2])
    if not re.fullmatch(r'(ssh-ed25519|ssh-rsa|ecdsa-sha2-nistp(?:256|384|521)) [A-Za-z0-9+/]+={0,3}',public):
        raise ValueError('Invalid local SSH public key')
    return key, public


def api(s, method, **params):
    if method not in API_METHODS: raise ValueError('Unsupported provider endpoint')
    c = private_json(s['provider_file'])
    if set(c) != {'veid', 'api_key'} or str(c['veid']) != str(s['veid']):
        raise ValueError('Provider credentials/VEID mismatch')
    query = urllib.parse.urlencode({**c, **params})
    # A config on stdin hides the credential-bearing URL from the process list.
    config = 'url = '+json.dumps('https://api.64clouds.com/v1/'+method+'?'+query)+'\n'
    try:
        response = run(['curl', '--disable', '--silent', '--show-error', '--fail',
                        '--max-time', '45', '--proto', '=https', '--config', '-'],
                       input=config, capture_output=True, text=True)
        result = json.loads(response.stdout)
    except (subprocess.SubprocessError, ValueError, OSError):
        raise RuntimeError('Provider request failed; no credential-bearing diagnostics printed') from None
    if not isinstance(result, dict) or result.get('error') != 0:
        raise RuntimeError('Provider returned an error; response withheld')
    return result


def source():
    data = io.BytesIO(); digest = hashlib.sha256()
    with tarfile.open(fileobj=data, mode='w:gz') as archive:
        for relative in SOURCE_FILES:
            path = ROOT/relative
            if path.is_symlink() or not path.is_file() or path.resolve().is_relative_to(ROOT.resolve()) is False:
                raise ValueError('Deployment source missing, symlinked or outside repository: '+relative)
            if any((ROOT/part).is_symlink() for part in Path(relative).parents if str(part) != '.'):
                raise ValueError('Deployment source ancestor is symlinked')
            content = path.read_bytes(); digest.update(relative.encode()+b'\0'+content)
            info = tarfile.TarInfo(relative); info.size = len(content); info.mode = 0o644
            archive.addfile(info, io.BytesIO(content))
    return data.getvalue(), digest.hexdigest()


def target_info(s):
    result = api(s, 'getServiceInfo')
    if s['ip'] not in result.get('ip_addresses', []): raise ValueError('Provider IP mismatch')
    return result


def wait_provider(s, desired, timeout=600):
    deadline = time.monotonic()+timeout
    while True:
        result = api(s, 'getLiveServiceInfo')
        if result.get('ve_status') == desired: return result
        if time.monotonic() >= deadline: raise RuntimeError('Provider state timed out; retry status before proceeding')
        time.sleep(10)


def check_backup(path, expected_sha256=None):
    path = secure_path(path)
    with path.open('rb') as handle: head = handle.read(64)
    if path.stat().st_size < 100 or not (head.startswith(b'age-encryption.org/v1\n') or head.startswith(b'-----BEGIN AGE ENCRYPTED FILE-----')):
        raise ValueError('Expected an age-encrypted backup; confirm restore separately')
    if expected_sha256 is not None:
        if not re.fullmatch(r'[0-9a-f]{64}',expected_sha256): raise ValueError('Encrypted backup SHA256 invalid')
        digest=hashlib.sha256()
        with path.open('rb') as handle:
            for chunk in iter(lambda:handle.read(1024*1024),b''): digest.update(chunk)
        if digest.hexdigest() != expected_sha256:
            raise ValueError('Encrypted backup changed since preservation; refusing reinstall')


API_ORIGIN = 'https://api.64clouds.com/v1/'
PROOF_ENDPOINT = API_ORIGIN+'basicShell/exec'
READ_CAPABILITIES = {'getServiceInfo','getLiveServiceInfo','getAvailableOS','getSshKeys','basicShell/exec'}


def provider_target_digest(s):
    value = {key:str(s[key]) for key in ('ip','veid','ssh_alias')}
    return hashlib.sha256(json.dumps(value,sort_keys=True,separators=(',',':')).encode()).hexdigest()


def proof_message(message,nonce):
    if not isinstance(message,str): raise ValueError('Provider proof must have a string message')
    lines = message.strip().splitlines()
    if len(lines) != 3 or lines[0] != 'sui-provider-proof-v1:'+nonce:
        raise ValueError('Provider proof response nonce or shape mismatch')
    if not re.fullmatch(r'[0-9a-f-]{36}',lines[1]): raise ValueError('Provider proof boot identity invalid')
    parts = lines[2].split()
    if len(parts) < 2 or parts[0] != 'ssh-ed25519' or not re.fullmatch(r'[A-Za-z0-9+/]+={0,3}',parts[1]):
        raise ValueError('Provider proof Ed25519 public key invalid')
    return lines[1], ' '.join(parts[:2])


def require_provider_readiness(s):
    cap = s.get('provider_capabilities',{})
    required = (cap.get('contract_kind') == 'verified-provider-api' and cap.get('source') == API_ORIGIN
                and cap.get('target_sha256') == provider_target_digest(s)
                and cap.get('trusted_ssh_baseline') is True
                and READ_CAPABILITIES.issubset(set(cap.get('observed_read_endpoints',[]))))
    age = time.time()-cap.get('checked_at',0)
    if not required or not 0 <= age <= 3600:
        raise ValueError('Run provider-proof against the trusted old SSH host before reinstall')
    for key in ('nonce_sha256','baseline_host_key_sha256'):
        if not re.fullmatch(r'[0-9a-f]{64}',cap.get(key,'')):
            raise ValueError('Provider capability proof is incomplete')
    if not re.fullmatch(r'[0-9a-f-]{36}',cap.get('baseline_boot_id','')):
        raise ValueError('Provider capability baseline boot identity missing')


def provider_proof(s,state_path):
    info = target_info(s)
    if info.get('vm_type') != 'kvm': raise ValueError('Provider proof currently supports the verified KVM contract only')
    live = api(s,'getLiveServiceInfo')
    if s['ip'] not in live.get('ip_addresses',[]) or live.get('ve_status') != 'running':
        raise ValueError('Provider live target is not the expected running VM')
    port = int(live.get('ssh_port',0))
    if not 1 <= port <= 65535: raise ValueError('Provider returned no usable SSH port')
    available = api(s,'getAvailableOS');keys = api(s,'getSshKeys')
    if not isinstance(available.get('installed'),str) or not isinstance(available.get('templates'),list) or not available['templates'] or not all(isinstance(x,str) and x for x in available['templates']):
        raise ValueError('Provider OS catalog contract invalid')
    preferred = keys.get('ssh_keys_preferred')
    if not isinstance(preferred,(str,list)) or (isinstance(preferred,list) and not all(isinstance(x,str) for x in preferred)):
        raise ValueError('Provider SSH vault contract invalid')
    nonce = secrets.token_hex(24)
    command = "printf '%s\\n' "+shlex.quote('sui-provider-proof-v1:'+nonce)+"; cat /proc/sys/kernel/random/boot_id; cat /etc/ssh/ssh_host_ed25519_key.pub"
    reply = api(s,'basicShell/exec',command=command)
    boot,key = proof_message(reply.get('message'),nonce)
    pending = bool(s.get('reinstall_pending'))
    # First contact with a brand-new server: no dedicated key exists yet, so the official HTTPS API is the only
    # trusted source of the host key. This proof only feeds `init`; it never grants reinstall capabilities.
    first_access = not pending and not s.get('identity_file') and not s.get('bootstrap_boot_id')
    if pending:
        require_provider_readiness(s)
        if not s.get('reinstall_at') or boot == s.get('pre_reinstall_boot_id'):
            raise ValueError('Reinstalled provider proof must show a new boot identity')
    elif first_access:
        pass
    else:
        observed = ssh(s,command,text=True).stdout
        if proof_message(observed,nonce) != (boot,key):
            raise ValueError('Provider API host identity differs from trusted SSH baseline')
    now = time.time();target_hash = provider_target_digest(s)
    proof = {'source':'provider-api','endpoint':PROOF_ENDPOINT,'ip':s['ip'],'veid':str(s['veid']),
             'target_sha256':target_hash,'captured_at':now,'nonce_sha256':hashlib.sha256(nonce.encode()).hexdigest(),
             'boot_id':boot,'ssh_port':port,'host_public_keys':[key]}
    if s.get('reinstall_at'): proof['reinstall_at'] = s['reinstall_at']
    proof_path = state_path.parent/'provider-proof.json'
    save(proof_path,proof)
    updated = dict(s);updated['bootstrap_proof_file'] = str(proof_path)
    if first_access:
        save(state_path,updated)
        save(state_path.parent/'available-os.json',available)
        print('First-access host key read from the official provider API; run init next.')
        return
    if not pending:
        updated['provider_capabilities'] = {'contract_kind':'verified-provider-api','source':API_ORIGIN,
            'target_sha256':target_hash,'checked_at':now,'trusted_ssh_baseline':True,
            'baseline_boot_id':boot,'baseline_host_key_sha256':hashlib.sha256(key.encode()).hexdigest(),
            'nonce_sha256':proof['nonce_sha256'],'observed_read_endpoints':sorted(READ_CAPABILITIES),
            'observed_fields':{'getServiceInfo':['ip_addresses','vm_type'],
                'getLiveServiceInfo':['ip_addresses','ve_status','ssh_port'],
                'getAvailableOS':['installed','templates'],'getSshKeys':['ssh_keys_preferred'],
                'basicShell/exec':['error=0','message=nonce+boot_id+ed25519_public_key']},
            'destructive_contracts':{'updateSshKeys':'pending-live-test','stop':'pending-live-test','reinstallOS':'pending-live-test'}}
    save(state_path,updated)
    save(state_path.parent/'available-os.json',available)
    print('Official provider read capabilities and private host proof verified; destructive contracts are recorded separately.')


ACME_CARRY = 'acme-carry.tar.gz'


def save_acme(s, state_path):
    """Copy this project's ACME lineage (account, certificate, key) to the private dir before reinstall.

    Reusing a still-valid certificate avoids Let's Encrypt's 5-per-week limit for the same IP.
    """
    present = ssh(s, 'test -f /etc/sui-vps/acme/live/sui-vps/fullchain.pem && echo yes || echo no', text=True).stdout.strip()
    if present != 'yes':
        return False
    archive = ssh(s, 'set -eu; test ! -L /etc/sui-vps/acme; tar -C /etc/sui-vps -czf - acme').stdout
    if len(archive) < 100 or len(archive) > 16*1024*1024:
        raise ValueError('Unexpected ACME archive size')
    with tarfile.open(fileobj=io.BytesIO(archive), mode='r:gz') as bundle:
        for member in bundle.getmembers():
            parts = Path(member.name).parts
            if not parts or parts[0] != 'acme' or '..' in parts or member.name.startswith('/') or not (member.isfile() or member.isdir() or member.issym()):
                raise ValueError('Unexpected ACME archive member')
    write_private(state_path.parent/ACME_CARRY, archive)
    save(state_path.parent/'acme-carry.json', {'ip': s['ip'], 'saved_at': time.time(),
                                                'sha256': hashlib.sha256(archive).hexdigest()})
    return True


def restore_acme(s, state_path):
    """Stage a saved ACME lineage for the same IP; the server validates it before adopting it."""
    archive_path, meta_path = state_path.parent/ACME_CARRY, state_path.parent/'acme-carry.json'
    if not archive_path.exists() or not meta_path.exists():
        return False
    meta = private_json(meta_path)
    archive = secure_path(archive_path).read_bytes()
    if meta.get('ip') != s['ip'] or meta.get('sha256') != hashlib.sha256(archive).hexdigest():
        return False
    ssh(s, 'set -eu; test ! -e /etc/sui-vps/acme/live/sui-vps/fullchain.pem || exit 0; '
           'rm -rf /var/lib/sui-vps-acme-carry; install -d -m 700 /var/lib/sui-vps-acme-carry; '
           'tar --no-same-owner --no-same-permissions -xzf - -C /var/lib/sui-vps-acme-carry', input=archive)
    return True


def reinstall(s, state_path, template, confirmation, discard_existing_data=False):
    expected = f"{s['ssh_alias']}:{s['ip']}:{s['veid']}"
    if confirmation != expected: raise ValueError('Explicit target confirmation required')
    require_provider_readiness(s)
    before = target_info(s)
    available = api(s, 'getAvailableOS')
    if not template or template not in available.get('templates', []):
        raise ValueError('OS template not in provider response')
    if discard_existing_data:
        # Owner explicitly chose to lose all data on this target; record it instead of faking a backup.
        s['backup_waived'] = {'at': time.time(), 'reason': 'owner-discarded-existing-data'}
        s.pop('backup_restore_verified', None)
    else:
        check_backup(s['encrypted_backup'],s.get('encrypted_backup_sha256'))
        # The caller must keep a restore-tested backup; format alone cannot prove recoverability.
        if not s.get('backup_restore_verified'): raise ValueError('Record a successful backup restore test first')
    boot = ssh(s, 'cat /proc/sys/kernel/random/boot_id', text=True).stdout.strip()
    if not re.fullmatch(r'[0-9a-f-]{36}', boot): raise ValueError('Cannot record old boot identity')
    if boot != s['provider_capabilities']['baseline_boot_id']:
        raise ValueError('Old host boot identity changed since provider-proof')
    # Keep the certificate even when other data is discarded; failure here only means a new issuance.
    try:
        if save_acme(s, state_path): print('Existing IP certificate saved privately for reuse after reinstall.')
    except (subprocess.CalledProcessError, ValueError, OSError, tarfile.TarError):
        print('Existing IP certificate could not be saved; deployment will request a new one.')
    public = run(['ssh-keygen', '-y', '-f', str(secure_path(s['identity_file']))], capture_output=True, text=True).stdout.strip()
    keys = api(s, 'getSshKeys'); save(state_path.parent/'provider-old-keys.json', keys)
    old = keys.get('ssh_keys_preferred', '')
    if isinstance(old, list): old = '\n'.join(old)
    if not isinstance(old, str): raise ValueError('Unexpected provider SSH keys response')
    if public not in old.splitlines():
        api(s, 'updateSshKeys', ssh_keys=old+'\n'+public)
        s['provider_capabilities']['destructive_contracts']['updateSshKeys'] = 'observed-error-zero'
        save(state_path,s)
    save(state_path.parent/'pre-reinstall.json', before)
    s['pre_reinstall_boot_id'] = boot; s['reinstall_pending'] = True; save(state_path, s)
    api(s, 'stop'); wait_provider(s, 'stopped')
    s['provider_capabilities']['destructive_contracts']['stop'] = 'observed-error-zero-and-stopped'
    save(state_path,s)
    response = api(s, 'reinstallOS', os=template)
    save(state_path.parent/'reinstall-response.json', response)  # May contain the one-time root password.
    s['provider_capabilities']['destructive_contracts']['reinstallOS'] = 'observed-error-zero-request-accepted-not-yet-boot-verified'
    s['reinstall_at'] = time.time(); s['os_template'] = template; save(state_path, s)
    print('OS reinstall requested. Private response saved; bootstrap must verify new host identity.')


def bootstrap_target(s, state_path, initial):
    if initial and s.get('reinstall_pending'):
        raise ValueError('Use bootstrap with fresh provider proof after reinstall')
    if not initial:
        if not s.get('reinstall_at') or not s.get('pre_reinstall_boot_id'):
            raise ValueError('Bootstrap requires a recorded reinstall')
        if not s.get('bootstrap_proof_file'):
            raise ValueError('Save trusted provider-console proof for this reinstall first')
        target_info(s); wait_provider(s,'running')
    proof_file = s.get('bootstrap_proof_file')
    if not proof_file:
        if not initial or not s.get('known_hosts_file'):
            raise ValueError('Initial bootstrap requires trusted known_hosts or provider-console proof')
        secure_path(s['known_hosts_file'])
        return dict(s), None
    proof = private_json(proof_file)
    if proof.get('ip') != s['ip'] or (not initial and str(proof.get('veid')) != str(s['veid'])):
        raise ValueError('Bootstrap proof target mismatch')
    if not initial and proof.get('reinstall_at') != s['reinstall_at']:
        raise ValueError('Bootstrap proof is not tied to this reinstall')
    if proof.get('source') == 'provider-api':
        age=time.time()-proof.get('captured_at',0)
        if (proof.get('endpoint') != PROOF_ENDPOINT or proof.get('target_sha256') != provider_target_digest(s)
                or not 0 <= age <= 900 or not re.fullmatch(r'[0-9a-f]{64}',proof.get('nonce_sha256',''))):
            raise ValueError('Provider API host proof is stale, unbound or from an untrusted origin')
    elif proof.get('source') != 'provider-console':
        raise ValueError('Unsupported trusted host proof source')
    boot = proof.get('boot_id', '')
    if not re.fullmatch(r'[0-9a-f-]{36}', boot) or (not initial and boot == s['pre_reinstall_boot_id']):
        raise ValueError('Bootstrap must prove a changed boot identity')
    port = int(proof['ssh_port'])
    if not 1 <= port <= 65535: raise ValueError('Invalid provider-proven SSH port')
    keys = proof.get('host_public_keys', [])
    if not isinstance(keys, list) or not keys: raise ValueError('Missing provider-proven host public keys')
    entries = []
    for key in keys:
        if not re.fullmatch(r'(ssh-ed25519|ssh-rsa|ecdsa-sha2-nistp(?:256|384|521)) [A-Za-z0-9+/]+={0,3}', key):
            raise ValueError('Invalid host public key')
        entries.append(f"{s['ip'] if port == 22 else '['+s['ip']+']:'+str(port)} {key}")
    known = state_path.parent/'known_hosts'
    write_private(known, ('\n'.join(entries)+'\n').encode())
    return {**s, 'ssh_port': port, 'known_hosts_file': str(known)}, boot


KEY_INSTALL = """set -eu
[ "$(id -u)" = 0 ]
umask 077
IFS= read -r key
test ! -L /root/.ssh
install -d -m 700 /root/.ssh
test ! -L /root/.ssh/authorized_keys
touch /root/.ssh/authorized_keys
chmod 600 /root/.ssh/authorized_keys
grep -qxF "$key" /root/.ssh/authorized_keys || printf '\n%s\n' "$key" >> /root/.ssh/authorized_keys
cat /proc/sys/kernel/random/boot_id
"""


def bootstrap(s, state_path, *, initial=False, password_file=None, ask_password=False):
    trial, expected_boot = bootstrap_target(s,state_path,initial)
    password_path = password_file or s.get('initial_password_file')
    if password_path and ask_password: raise ValueError('Choose a password file or secure prompt, not both')
    key, public = dedicated_key(s,state_path)
    password = None
    if password_path:
        password_path = secure_path(password_path)
        reserved = [state_path, key, Path(trial['known_hosts_file'])]
        if s.get('bootstrap_proof_file'): reserved.append(Path(s['bootstrap_proof_file']))
        if any(password_path.resolve() == p.resolve() for p in reserved):
            raise ValueError('Password file must be separate from state, key and host proof')
        with password_path.open('r') as handle: password = handle.read(4098).rstrip('\r\n')
    elif ask_password:
        if not sys.stdin.isatty(): raise ValueError('Secure password prompt requires a local terminal')
        with warnings.catch_warnings():
            warnings.simplefilter('error',getpass.GetPassWarning)
            try: password = getpass.getpass('SSH initial password (not saved): ')
            except getpass.GetPassWarning:
                raise ValueError('Secure password terminal unavailable; use a restricted password file') from None
    if password is not None:
        installed = password_ssh(trial,KEY_INSTALL,password,input=(public+'\n').encode(),text=False)
        password = None
    elif s.get('identity_file'):
        installed = ssh(trial,KEY_INSTALL,input=(public+'\n').encode())
    else:
        # Existing key/agent access may install the new dedicated key; confirmation below is isolated.
        installed = ssh(trial,KEY_INSTALL,input=(public+'\n').encode())
    observed = installed.stdout.decode().strip() if isinstance(installed.stdout,bytes) else installed.stdout.strip()
    if not re.fullmatch(r'[0-9a-f-]{36}',observed) or (expected_boot and observed != expected_boot):
        raise ValueError('Password/key bootstrap boot identity differs from trusted proof')
    trial.update(identity_file=str(key), _isolated_auth=True)
    confirmed = ssh(trial,'cat /proc/sys/kernel/random/boot_id',text=True).stdout.strip()
    if confirmed != observed: raise ValueError('Independent new-key SSH boot identity mismatch')
    trial.pop('_isolated_auth',None)
    trial.pop('initial_password_file',None)
    trial['reinstall_pending'] = False; trial['bootstrap_boot_id'] = confirmed
    for name in list(trial):
        if name.startswith('preflight_'): trial.pop(name)
    save(state_path,trial)
    if password_path:
        secure_path(password_path).unlink()
    print('Trusted host and independent SSH key verified; initial password file removed if supplied.')


SECRET_PROMPTS = {
    'password': '服务器 root 密码',
    'api-key': '搬瓦工 API Key（KiwiVM「API」页）',
}
DIALOG_TITLE = '部署需要的登录信息'
DIALOG_MESSAGE = '填好后点「好」。内容只存进本机 private 文件夹，不会显示，也不会发给 AI。'
FIELD_SEPARATOR = '\x1e'

# One NSAlert with a hidden-input field per secret; prints a JSON list, or nothing when cancelled.
MAC_FORM = r"""
ObjC.import('Cocoa');
function run(argv) {
  const labels = JSON.parse(argv[0]);
  const app = $.NSApplication.sharedApplication;
  app.setActivationPolicy($.NSApplicationActivationPolicyAccessory);
  const alert = $.NSAlert.alloc.init;
  alert.messageText = argv[1];
  alert.informativeText = argv[2];
  alert.addButtonWithTitle('好');
  alert.addButtonWithTitle('取消');
  const h = labels.length * 52;
  const view = $.NSView.alloc.initWithFrame($.NSMakeRect(0, 0, 320, h));
  const fields = [];
  labels.forEach((text, i) => {
    const y = h - (i + 1) * 52;
    const label = $.NSTextField.labelWithString(text);
    label.frame = $.NSMakeRect(0, y + 28, 320, 18);
    view.addSubview(label);
    const field = $.NSSecureTextField.alloc.initWithFrame($.NSMakeRect(0, y + 2, 320, 24));
    view.addSubview(field);
    fields.push(field);
  });
  alert.accessoryView = view;
  alert.window.initialFirstResponder = fields[0];
  app.activateIgnoringOtherApps(true);
  if (alert.runModal != $.NSAlertFirstButtonReturn) return '';
  return JSON.stringify(fields.map(f => f.stringValue.js));
}
"""


# WinForms dialog with one masked TextBox per secret. Labels arrive via env (never argv); exit 1 means cancelled.
WINDOWS_FORM = r"""
Add-Type -AssemblyName System.Windows.Forms
[Console]::OutputEncoding = [Text.UTF8Encoding]::new($false)
$labels = ConvertFrom-Json $env:SUI_FORM_LABELS
$h = 110 + 52 * $labels.Count
$f = New-Object Windows.Forms.Form -Property @{ Text = $env:SUI_FORM_TITLE; Width = 440; Height = $h; StartPosition = 'CenterScreen'; TopMost = $true; FormBorderStyle = 'FixedDialog'; MaximizeBox = $false; MinimizeBox = $false }
$msg = New-Object Windows.Forms.Label -Property @{ Text = $env:SUI_FORM_MESSAGE; Left = 12; Top = 10; Width = 400; Height = 34 }
$f.Controls.Add($msg)
$boxes = @()
$y = 48
foreach ($text in $labels) {
  $l = New-Object Windows.Forms.Label -Property @{ Text = $text; Left = 12; Top = $y; Width = 400 }
  $t = New-Object Windows.Forms.TextBox -Property @{ Left = 12; Top = ($y + 22); Width = 400; UseSystemPasswordChar = $true }
  $f.Controls.Add($l); $f.Controls.Add($t); $boxes += $t; $y += 52
}
$ok = New-Object Windows.Forms.Button -Property @{ Text = '好'; Left = 256; Top = $y + 4; Width = 75; DialogResult = 'OK' }
$no = New-Object Windows.Forms.Button -Property @{ Text = '取消'; Left = 337; Top = $y + 4; Width = 75; DialogResult = 'Cancel' }
$f.Controls.Add($ok); $f.Controls.Add($no); $f.AcceptButton = $ok; $f.CancelButton = $no
if ($f.ShowDialog() -ne 'OK') { exit 1 }
[Console]::Out.Write((ConvertTo-Json -Compress @($boxes | ForEach-Object { $_.Text })))
"""


class DialogCancelled(Exception):
    pass


def _has_display():
    return bool(os.environ.get('DISPLAY') or os.environ.get('WAYLAND_DISPLAY'))


def _mac_form(labels):
    result = subprocess.run(['osascript', '-l', 'JavaScript', '-e', MAC_FORM, json.dumps(labels, ensure_ascii=False),
                             DIALOG_TITLE, DIALOG_MESSAGE], capture_output=True, text=True, timeout=600)
    if result.returncode != 0: return None
    out = result.stdout.strip()
    if not out: raise DialogCancelled
    values = json.loads(out)
    return values if isinstance(values, list) and len(values) == len(labels) else None


def _windows_form(labels):
    shell = shutil.which('powershell.exe') or shutil.which('powershell')
    if not shell: return None
    env = dict(os.environ, SUI_FORM_LABELS=json.dumps(labels, ensure_ascii=False),
               SUI_FORM_TITLE=DIALOG_TITLE, SUI_FORM_MESSAGE=DIALOG_MESSAGE)
    # WSL only forwards variables listed in WSLENV to Windows processes.
    env['WSLENV'] = ':'.join(x for x in [os.environ.get('WSLENV'), 'SUI_FORM_LABELS', 'SUI_FORM_TITLE', 'SUI_FORM_MESSAGE'] if x)
    result = subprocess.run([shell, '-NoProfile', '-STA', '-NonInteractive', '-Command', WINDOWS_FORM],
                            capture_output=True, env=env, timeout=600)
    if result.returncode == 1: raise DialogCancelled
    if result.returncode != 0: return None
    values = json.loads(result.stdout.decode('utf-8-sig').strip() or 'null')
    if isinstance(values, str): values = [values]
    return values if isinstance(values, list) and len(values) == len(labels) else None


def _zenity_form(labels):
    command = ['zenity', '--forms', '--title', DIALOG_TITLE, '--text', DIALOG_MESSAGE, '--separator', FIELD_SEPARATOR]
    for label in labels: command += ['--add-password', label]
    result = subprocess.run(command, capture_output=True, text=True, timeout=600)
    if result.returncode == 1: raise DialogCancelled
    if result.returncode != 0: return None
    values = result.stdout.rstrip('\r\n').split(FIELD_SEPARATOR)
    return values if len(values) == len(labels) else None


def _tk_form(labels):
    try:
        import tkinter
    except Exception:
        return None
    try:
        root = tkinter.Tk()
    except Exception:
        return None
    answer = {}
    try:
        root.title(DIALOG_TITLE)
        tkinter.Label(root, text=DIALOG_MESSAGE, wraplength=320, justify='left').pack(padx=12, pady=(12, 6), anchor='w')
        entries = []
        for label in labels:
            tkinter.Label(root, text=label).pack(padx=12, anchor='w')
            entry = tkinter.Entry(root, show='*', width=40); entry.pack(padx=12, pady=(0, 8)); entries.append(entry)
        def ok(*_): answer['values'] = [e.get() for e in entries]; root.destroy()
        buttons = tkinter.Frame(root); buttons.pack(pady=(0, 12))
        tkinter.Button(buttons, text='好', command=ok).pack(side='left', padx=6)
        tkinter.Button(buttons, text='取消', command=root.destroy).pack(side='left', padx=6)
        root.bind('<Return>', ok); entries[0].focus_set()
        root.attributes('-topmost', True)
        root.mainloop()
    except Exception:
        return None
    if 'values' not in answer: raise DialogCancelled
    return answer['values']


def _form_methods():
    if sys.platform == 'darwin': return [_mac_form, _tk_form]
    if WINDOWS: return [_windows_form, _tk_form]
    # WSL: Windows' own PowerShell can still show a dialog on the user's desktop.
    methods = [_windows_form] if shutil.which('powershell.exe') else []
    if not _has_display(): return methods
    if shutil.which('zenity'): methods.append(_zenity_form)
    return methods + [_tk_form]


def ask_secret_values(kinds):
    """Collect every requested secret in a single dialog; values never reach stdout or argv."""
    labels = [SECRET_PROMPTS[k] for k in kinds]
    values = None
    for method in _form_methods():
        try:
            values = method(labels)
        except DialogCancelled:
            raise ValueError('输入框被取消，没有保存任何东西') from None
        except (OSError, subprocess.SubprocessError, ValueError):
            values = None
        if values is not None: break
    if values is None and sys.stdin.isatty():
        values = []
        with warnings.catch_warnings():
            warnings.simplefilter('error', getpass.GetPassWarning)
            try:
                for label in labels: values.append(getpass.getpass(label+'（输入时不显示）: '))
            except getpass.GetPassWarning:
                values = None
    if values is None:
        raise ValueError('这台电脑弹不出输入框；请用编辑器把'+'和'.join(labels)+'写进权限 600 的 private 文件，见 docs/deployment.md')
    values = [v.rstrip('\r\n') for v in values]
    empty = [labels[i] for i, v in enumerate(values) if not v]
    if empty: raise ValueError('没有填：'+'、'.join(empty)+'；没有保存任何东西')
    return dict(zip(kinds, values))


def ask_secrets(s, state_path, which):
    kinds = ['password', 'api-key'] if which == 'all' else [which]
    if which == 'all' and not s.get('veid'): kinds.remove('api-key')
    if 'api-key' in kinds and not re.fullmatch(r'[0-9]+', str(s.get('veid', ''))):
        raise ValueError('先在目标状态里写好 veid，再输入 API Key')
    if s.get('ip'): ipaddress.IPv4Address(s['ip'])
    values = ask_secret_values(kinds)
    if 'api-key' in values and re.search(r'\s', values['api-key']):
        raise ValueError('API Key 里不应有空格或换行；没有保存任何东西')
    if 'password' in values:
        target = state_path.parent/'initial-password'
        write_private(target, (values['password']+'\n').encode())
        s['initial_password_file'] = str(target)
    if 'api-key' in values:
        target = state_path.parent/'provider.json'
        save(target, {'veid': str(s['veid']), 'api_key': values['api-key']})
        s['provider_file'] = str(target)
    values = None
    save(state_path, s)
    print('已保存到本机 private 文件夹：'+'、'.join(SECRET_PROMPTS[k] for k in kinds))


def preflight(s, path):
    command = "set -eu; uname -m; cat /etc/os-release; cat /proc/sys/kernel/random/boot_id; ip -4 addr show scope global; free -m; ss -lntup; command -v docker >/dev/null && docker ps || true; command -v ufw >/dev/null && ufw status || true"
    result = ssh(s, command, text=True)
    write_private(path.parent/'preflight.txt', result.stdout.encode())
    # Confirm expected IP on guest independently of local SSH config.
    address = ssh(s, 'ip -4 -o addr show scope global', text=True).stdout
    if s['ip'] not in re.findall(r'\binet (\d+\.\d+\.\d+\.\d+)/', address):
        raise ValueError('Guest public address mismatch; NAT targets need explicit implementation')
    boot = ssh(s,'cat /proc/sys/kernel/random/boot_id',text=True).stdout.strip()
    if not re.fullmatch(r'[0-9a-f-]{36}',boot): raise ValueError('Invalid remote boot identity')
    _,digest = source()
    s.update(preflight_at=time.time(),preflight_ip=s['ip'],preflight_boot_id=boot,
             preflight_source_sha256=digest,preflight_target_sha256=target_digest(s))
    save(path, s)
    print('Read-only preflight saved privately; review existing services and port conflicts before deploy.')


def target_digest(s):
    keys = ('ip','ssh_alias','ssh_port','identity_file','known_hosts_file','timezone','veid',
            'provider_file','os_template','reinstall_at')
    values = {key:s[key] for key in keys if key in s}
    return hashlib.sha256(json.dumps(values,sort_keys=True,separators=(',',':')).encode()).hexdigest()


def require_preflight(s,digest):
    age = time.time()-s.get('preflight_at',0)
    if s.get('preflight_ip') != s['ip'] or age < 0 or age > 3600:
        raise ValueError('Run fresh read-only preflight first')
    if s.get('preflight_target_sha256') != target_digest(s):
        raise ValueError('Target configuration changed; run preflight again')
    if s.get('preflight_source_sha256') != digest:
        raise ValueError('Deployment source changed; run preflight again')
    boot = ssh(s,'cat /proc/sys/kernel/random/boot_id',text=True).stdout.strip()
    if boot != s.get('preflight_boot_id'):
        raise ValueError('Remote boot identity changed; run preflight again')


def receipt_copy_code(directory='/etc/sui-vps'):
    """Python transported as public code; it never prints backup/state contents."""
    return "import pathlib\nroot=pathlib.Path("+repr(str(directory))+")\n"+        """import json,os,stat,tempfile
source=root/'last-backup.json'
target=root/'source-update-backup.json'
if source.is_symlink() or target.is_symlink(): raise RuntimeError('Backup receipt must not be a symlink')
info=source.stat()
if not stat.S_ISREG(info.st_mode) or info.st_uid!=os.geteuid() or info.st_mode & 0o077:
    raise RuntimeError('Backup receipt permissions invalid')
receipt=json.loads(source.read_text())
if set(receipt)!={'archive','versions','source_sha256'} or not isinstance(receipt['archive'],str) or not isinstance(receipt['versions'],dict):
    raise RuntimeError('Backup receipt structure invalid')
fd,temporary=tempfile.mkstemp(prefix='.source-update-backup-',dir=root)
try:
    with os.fdopen(fd,'w') as stream:
        json.dump(receipt,stream);stream.flush();os.fsync(stream.fileno())
    os.replace(temporary,target)
finally:
    if os.path.exists(temporary):os.unlink(temporary)
"""


def restore_command(s,archive,confirmation):
    if confirmation != s['ip']: raise ValueError('Restore requires exact target IP confirmation')
    if not archive or any(c in archive for c in ('\n','\r','\0')):
        raise ValueError('Restore requires a server backup archive path')
    path = Path(archive)
    if not path.is_absolute() or path.parent != Path('/var/backups/sui-vps') or '..' in path.parts:
        raise ValueError('Restore archive must be directly inside /var/backups/sui-vps')
    return 'set -eu; test "$(cat '+OWNER_MARK+')" = sui-vps-v1; python3 /opt/sui-vps/scripts/server.py restore --archive '+shlex.quote(archive)+' --confirm-target '+shlex.quote(confirmation)


def upload(s, prepared=None):
    payload, digest = prepared if prepared is not None else source()
    # Only this project may own the destination; never overwrite an unrelated directory.
    guard = """set -eu
for base in /opt/sui-vps /etc/sui-vps; do
    test ! -L "$base"
    if [ -e "$base/.managed" ]; then
        test ! -L "$base/.managed"
        test "$(cat "$base/.managed")" = sui-vps-v1
    elif [ -d "$base" ]; then
        test -z "$(ls -A "$base")"
    fi
    if [ ! -d "$base" ]; then install -d -m 700 "$base"; fi
    if [ "$base" = /opt/sui-vps ]; then chmod 755 "$base"; fi
    printf 'sui-vps-v1\n' > "$base/.managed"
done
for part in scripts deploy; do test ! -L "/opt/sui-vps/$part"; done
"""
    for relative in SOURCE_FILES:
        guard += 'test ! -L '+shlex.quote('/opt/sui-vps/'+relative)+'\n'
    check = "import json,pathlib; p=pathlib.Path('/etc/sui-vps/state.json'); s=json.loads(p.read_text()); active=s.get('base_done') or any(pathlib.Path('/opt/sui-vps/deploy/state/db').glob('*')); print('yes' if active and s.get('source_sha256') != "+repr(digest)+" else 'no')"
    guard += "if [ -f /etc/sui-vps/state.json ]; then\n"
    guard += '    backup_needed=$(python3 -c '+shlex.quote(check)+')\n'
    guard += '    if [ "$backup_needed" = yes ]; then\n        python3 /opt/sui-vps/scripts/server.py backup\n'
    guard += '        python3 -c '+shlex.quote(receipt_copy_code())+'\n    fi\nfi\n'
    guard += "exec 9>/run/sui-vps.lock\nflock -x 9\nstaging=$(mktemp -d /opt/sui-vps/.upload.XXXXXXXX)\n"
    guard += "trap 'rm -rf -- \"$staging\"' EXIT\ntar -xzf - -C \"$staging\"\n"
    # Rename each complete source file atomically so a starting cron job cannot read half a Python file.
    for relative in SOURCE_FILES:
        parent = str(Path('/opt/sui-vps',relative).parent)
        guard += 'install -d -m 755 '+shlex.quote(parent)+'\n'
        guard += 'mv -f -- "$staging/'+relative+'" '+shlex.quote('/opt/sui-vps/'+relative)+'\n'

    ssh(s, guard, input=payload)
    config = {k:s[k] for k in ['ip','ssh_alias','timezone','os_template','reinstall_at','ssh_port',
                               'traffic_quota_gb','traffic_reset_day','traffic_count'] if k in s}
    config['source_sha256'] = digest
    ssh(s, 'umask 077; cat > /etc/sui-vps/target.json', input=json.dumps(config).encode())
    if s.get('provider_file'):
        # Validate exact credential structure/target before forwarding it.
        c = private_json(s['provider_file'])
        if set(c) != {'veid','api_key'} or str(c['veid']) != str(s['veid']): raise ValueError('Provider target mismatch')
        ssh(s, 'umask 077; cat > /etc/sui-vps/kiwivm.json', input=json.dumps(c).encode())
    if globals().get('CURRENT_STATE_PATH') is not None and restore_acme(s, CURRENT_STATE_PATH):
        print('Saved IP certificate staged; the server adopts it only if it is valid for this IP.')
    return digest


def fetch_export(s, state_path):
    result = ssh(s,'cat /etc/sui-vps/export.json')
    data = json.loads(result.stdout)
    if not isinstance(data,dict) or data.get('server',{}).get('host') != s['ip']:
        raise ValueError('Credential export target mismatch')
    out = state_path.parent/'export.json'
    write_private(out,result.stdout if isinstance(result.stdout,bytes) else result.stdout.encode())
    return out,data


def probe_module():
    import importlib.util
    spec = importlib.util.spec_from_file_location('sui_local_probe',ROOT/'scripts/probe.py')
    module = importlib.util.module_from_spec(spec);spec.loader.exec_module(module)
    return module


def merge_network(config, report_path):
    # Never accept a server's claim about a local network/client test.
    config.setdefault('verification',{})['network'] = '未测试（本机）'
    report_path = Path(report_path)
    if not report_path.exists() and not report_path.is_symlink(): return config
    report = private_json(report_path)
    current = probe_module().fingerprint(config)
    if report.get('scope') != 'local_fixed_core_network' or report.get('node_fingerprint') != current:
        config['verification']['network'] = '未测试（旧网络报告与当前节点不匹配）'
        return config
    passed = report.get('status') == 'passed'
    rows = report.get('nodes',[])
    passed = passed and len(rows) == 3 and all(row.get('status') == 'passed' and
        row.get('wrong_credentials') == 'rejected' and row.get('exit_matches_server') is True for row in rows)
    config['verification']['network'] = ('通过' if passed else '未通过')+'（本机固定核心逐节点测试；真客户端、防泄露与 UDP 未测试）'
    config['verification']['network_checked_at'] = report.get('checked_at','未记录')
    return config


def merge_surge(config, report_path):
    verification=config.setdefault('verification',{})
    suffix='；v2rayN / v2rayNG：未测试'
    verification['clients']='Surge AnyTLS：未测试'+suffix
    report_path=Path(report_path)
    if not report_path.exists() and not report_path.is_symlink():return config
    report=private_json(report_path)
    if (report.get('scope') != 'Native Surge Mac AnyTLS HTTPS request only'
            or report.get('protocol') != 'anytls'
            or report.get('configuration_mutations_performed') is not False
            or report.get('capability_only') is True
            or report.get('export_fingerprint') != probe_module().fingerprint(config)):
        verification['clients']='Surge AnyTLS：未测试（报告范围不符或节点已变更）'+suffix
        return config
    client=report.get('client',{})
    version=client.get('version','');build=client.get('build','')
    if (client.get('bundle_identifier') != 'com.nssurge.surge-mac'
            or client.get('name') != 'Surge Mac'
            or not isinstance(version,str) or not re.fullmatch(r'[0-9][0-9A-Za-z.+-]{0,63}',version)
            or not isinstance(build,str) or not re.fullmatch(r'[0-9][0-9.]{0,31}',build)):
        verification['clients']='Surge AnyTLS：未测试（无法确认实际客户端版本与 build）'+suffix
        return config
    labels={'passed':'通过','failed':'未通过','inconclusive':'无法确认','startup_failed':'未完成'}
    result=report.get('result')
    if result == 'passed' and report.get('offline_profile_check') != 'passed':result='inconclusive'
    label=labels.get(result,'未测试')
    checks = {row.get('phase'): row for row in report.get('checks', [])}
    if result == 'inconclusive' and all(
        checks.get(phase, {}).get('status') == 200
        and checks[phase].get('exit_matches') is True
        for phase in ('valid', 'restored')
    ):
        label = '连通和出口通过，错误凭据拒绝的原因无法确认'
    verification['clients']='Surge Mac '+version+'（build '+build+'）AnyTLS：'+label+suffix
    verification['surge_checked_at']=report.get('checked_at','未记录')
    # This report does not establish TUN, DNS, IPv6, WebRTC or failure behavior.
    return config


def merge_pilot(config, report_path):
    report_path = Path(report_path)
    if not report_path.exists():
        return config
    report = private_json(report_path)
    if report.get('node_fingerprint') != probe_module().fingerprint(config):
        return config
    verification = config.setdefault('verification', {})
    for key in ('static', 'core', 'lifecycle', 'clean_os'):
        if isinstance(report.get(key), str):
            verification[key] = report[key]
    return config


def diagnostics(result):
    pieces = []
    for value in (result.stdout, result.stderr):
        if value: pieces.append(value.encode() if isinstance(value, str) else value)
    return b''.join(pieces)


def remote_stage(s, command, state_path, name):
    """Persist diagnostics privately, including partial output of failed commands."""
    try:
        result = ssh(s, command)
    except subprocess.CalledProcessError as error:
        output = diagnostics(error)
        write_private(state_path.parent/('stage-'+name+'.log'), output)
        raise RuntimeError('Remote stage failed; private stage log saved') from None
    write_private(state_path.parent/('stage-'+name+'.log'), diagnostics(result))
    return result


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--state', required=True)
    parser.add_argument('stage', choices=['preflight','deploy','base','cert','panel','services','maint','verify','export','provider-info','provider-proof','reinstall','bootstrap','init','backup','cert-sync','cert-dry-run','restore-check','network','rotate-subscriptions','restore','surge','rules','traffic-calibrate','ask-secrets'])
    parser.add_argument('--network-backend',choices=['docker','native'],help='Network probe backend (default: docker)')
    parser.add_argument('--core-bin',help='Verified private native core; requires network --network-backend native')
    parser.add_argument('--archive')
    parser.add_argument('--client',choices=['surge','v2ray','clash','shadowrocket','all'],default=None)
    parser.add_argument('--used-gb',type=float,help='traffic-calibrate only: GiB already used this period per the provider panel')
    parser.add_argument('--password-file'); parser.add_argument('--ask-password',action='store_true')
    parser.add_argument('--os-template'); parser.add_argument('--confirm-target'); parser.add_argument('--output')
    parser.add_argument('--secret',choices=['password','api-key','all'],help='ask-secrets only: which secret to enter in a local hidden-input dialog (default: all)')
    parser.add_argument('--discard-existing-data',action='store_true',help='reinstall only: skip the backup requirement because the owner accepts losing all data')
    args = parser.parse_args()
    if (args.network_backend is not None or args.core_bin is not None) and args.stage != 'network':
        parser.error('Network backend options apply only to network')
    backend=args.network_backend or 'docker'
    if backend == 'native' and not args.core_bin:
        parser.error('Native network backend requires --core-bin')
    if args.core_bin is not None and backend != 'native':
        parser.error('--core-bin requires explicit --network-backend native')
    if (args.password_file or args.ask_password) and args.stage not in {'init','bootstrap'}:
        parser.error('Password options apply only to init/bootstrap')
    if args.client and args.stage != 'rotate-subscriptions': parser.error('--client applies only to rotate-subscriptions')
    if args.archive and args.stage != 'restore': parser.error('--archive applies only to restore')
    if (args.used_gb is not None) != (args.stage == 'traffic-calibrate'): parser.error('traffic-calibrate requires --used-gb, and only it accepts it')
    if args.used_gb is not None and not 0 <= args.used_gb <= 1_000_000: parser.error('--used-gb must be between 0 and 1000000')
    if args.discard_existing_data and args.stage != 'reinstall': parser.error('--discard-existing-data applies only to reinstall')
    if args.secret and args.stage != 'ask-secrets': parser.error('--secret applies only to ask-secrets')
    path = secure_path(args.state); s = private_json(path)
    if args.stage == 'ask-secrets':
        ask_secrets(s, path, args.secret or 'all'); return
    validate(s)
    global CURRENT_STATE_PATH, CURRENT_STAGE
    CURRENT_STATE_PATH, CURRENT_STAGE = path, args.stage
    if args.stage == 'preflight': preflight(s, path)
    elif args.stage == 'provider-info':
        save(path.parent/'provider-info.json', target_info(s))
        save(path.parent/'available-os.json', api(s,'getAvailableOS'))
        print('Provider target verified; details saved privately')
    elif args.stage == 'provider-proof': provider_proof(s,path)
    elif args.stage == 'reinstall': reinstall(s, path, args.os_template, args.confirm_target, args.discard_existing_data)
    elif args.stage in {'bootstrap','init'}:
        bootstrap(s,path,initial=args.stage=='init',password_file=args.password_file,ask_password=args.ask_password)
    elif args.stage == 'network':
        out,_ = fetch_export(s,path)
        report = path.parent/'network.json';secure_path(report,exists=False)
        command=[sys.executable,str(ROOT/'scripts/probe.py'),'--input',str(out),'--output',str(report),'--backend',backend]
        if backend == 'native':command += ['--core-bin',args.core_bin]
        run(command,capture_output=True)
        print('Local network report saved; real clients, leaks and UDP remain untested')
    elif args.stage == 'surge':
        out,_=fetch_export(s,path)
        report=path.parent/'surge.json';secure_path(report,exists=False)
        run([sys.executable,str(ROOT/'scripts/surge_probe.py'),'--export',str(out),'--output',str(report)],capture_output=True)
        print('Native Surge AnyTLS report saved; other clients and leak protection remain untested')
    elif args.stage == 'export':
        _,config = fetch_export(s,path)
        config = merge_network(config,path.parent/'network.json')
        config = merge_surge(config,path.parent/'surge.json')
        config = merge_pilot(config,path.parent/'pilot-verified.json')
        out = path.parent/'delivery-input.json';save(out,config)
        target = Path(args.output).absolute() if args.output else path.parent/'accounts.html'
        secure_path(target, exists=False)
        run([sys.executable,str(ROOT/'scripts/delivery.py'),'--input',str(out),'--output',str(target)], capture_output=True)
        restrict_windows(target)
        print('Private local account page generated')
    elif args.stage == 'restore':
        command=restore_command(s,args.archive,args.confirm_target)
        remote_stage(s,command,path,'restore')
        print('Restore stage completed; run verify and local network/client checks again')
    elif args.stage in {'backup','cert-sync','cert-dry-run','restore-check','rotate-subscriptions','rules','traffic-calibrate'}:
        command = 'set -eu; test "$(cat '+OWNER_MARK+')" = sui-vps-v1; python3 /opt/sui-vps/scripts/server.py '+args.stage
        if args.stage == 'rotate-subscriptions': command += ' '+(args.client or 'all')
        if args.stage == 'traffic-calibrate': command += ' '+repr(float(args.used_gb))
        remote_stage(s,command,path,args.stage)
        print('Maintenance stage completed using the installed deployment source')
    elif args.stage == 'verify':
        remote_stage(s, 'test -f '+OWNER_MARK+'; python3 /opt/sui-vps/scripts/server.py verify', path, 'verify')
        report = ssh(s, 'cat /etc/sui-vps/verification.json')
        write_private(path.parent/'verification.json', report.stdout)
        print('Remote checks completed; inspect private server verification results')
    else:
        if s.get('reinstall_pending'): raise ValueError('Complete bootstrap before deployment')
        prepared = source()
        require_preflight(s,prepared[1])
        s['source_sha256'] = upload(s,prepared); save(path,s)
        remote_stage(s,'python3 /opt/sui-vps/scripts/server.py '+shlex.quote(args.stage),path,args.stage)
        print('Stage completed; no unperformed client checks implied')


if __name__ == '__main__':
    try: main()
    except Exception as error:
        if isinstance(error, subprocess.CalledProcessError) and globals().get('CURRENT_STATE_PATH'):
            output = diagnostics(error)
            if isinstance(output, str): output = output.encode()
            try: write_private(CURRENT_STATE_PATH.parent/('stage-'+CURRENT_STAGE+'.log'),output)
            except (OSError, ValueError): pass
        # Never expose subprocess stderr/provider bodies/URLs on failure.
        print('停止：'+str(error) if isinstance(error,(ValueError,RuntimeError)) else '停止：'+type(error).__name__+'；当前阶段失败，秘密诊断未输出',file=sys.stderr)
        sys.exit(1)
