#!/usr/bin/env python3
"""Check a private sui-vps backup; --apply explicitly restores owned paths.

Without --apply extraction uses only a fresh private temporary directory.
Apply requires matching target confirmation, markers and reviewed versions,
and retains previous files for rollback. Active connections are interrupted.
"""
import argparse
import configparser
import hashlib
import ipaddress
import json
import os
from pathlib import Path, PurePosixPath
import posixpath
import re
import shutil
import sqlite3
import subprocess
import fcntl
import secrets
import tarfile
import tempfile
import time

MAX_MEMBERS = 50000
MAX_BYTES = 2 * 1024 ** 3
ROOTS = ('etc/sui-vps', 'opt/sui-vps/deploy', 'opt/sui-vps/scripts',
         'var/lib/sui-cliproxy', 'usr/local/lib/sui-cliproxy')
EXACT = {'opt/sui-vps/versions.json',
         'etc/nginx/conf.d/sui-vps-acme.conf', 'etc/nginx/conf.d/sui-vps-https.conf',
         'etc/sysctl.d/90-sui-vps.conf', 'etc/ssh/sshd_config.d/01-sui-vps.conf',
         'etc/systemd/system/sui-cliproxy.service'}


class RecoveryError(RuntimeError):
    pass


def allowed(name):
    return (name in EXACT or any(name == root or name.startswith(root + '/') for root in ROOTS)
            or bool(re.fullmatch(r'etc/systemd/system/sui-vps-[a-z0-9-]+\.(?:service|timer)', name)))


def normalized(name):
    if not name or name.startswith('/') or '\\' in name or any(ord(c) < 32 for c in name):
        raise RecoveryError('Archive contains an unsafe path')
    parts = PurePosixPath(name).parts
    if '..' in parts:
        raise RecoveryError('Archive path traversal rejected')
    result = str(PurePosixPath(name))
    if not allowed(result):
        raise RecoveryError('Archive includes files outside this deployment')
    return result


def extract_private(archive_path, staging):
    staging = Path(staging)
    if staging.is_symlink() or staging.exists() and (not staging.is_dir() or any(staging.iterdir())):
        raise RecoveryError('Extraction requires a fresh private directory')
    staging.mkdir(mode=0o700, parents=True, exist_ok=True)
    staging.chmod(0o700)
    with tarfile.open(archive_path, 'r:*') as archive:
        members, total = {}, 0
        for member in archive:
            name = normalized(member.name)
            if name in members:
                raise RecoveryError('Duplicate archive paths rejected')
            if not (member.isdir() or member.isfile() or member.issym()):
                raise RecoveryError('Archive special files and hardlinks rejected')
            if member.size < 0:
                raise RecoveryError('Invalid archive member size')
            total += member.size
            members[name] = member
            if len(members) > MAX_MEMBERS or total > MAX_BYTES:
                raise RecoveryError('Backup exceeds inspection limits')
        for name, member in members.items():
            for ancestor in PurePosixPath(name).parents:
                existing = members.get(str(ancestor))
                if existing and not existing.isdir():
                    raise RecoveryError('Archive file used as a parent directory')
            if member.issym():
                match = re.fullmatch(r'etc/sui-vps/acme/live/sui-vps/(cert|chain|fullchain|privkey)\.pem', name)
                if not match or not re.fullmatch(r'\.\./\.\./archive/sui-vps/' + match.group(1) + r'[0-9]+\.pem', member.linkname):
                    raise RecoveryError('Unexpected certificate symlink rejected')
                target = posixpath.normpath(posixpath.join(posixpath.dirname(name), member.linkname))
                if target not in members or not members[target].isfile():
                    raise RecoveryError('Certificate symlink target absent from backup')
        # Never call extract/extractall. Create only ordinary files first, with
        # fixed private permissions and no archived ownership, modes or xattrs.
        for name, member in members.items():
            destination = staging / name
            destination.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
            if member.isdir():
                destination.mkdir(mode=0o700, exist_ok=True)
            elif member.isfile():
                descriptor = os.open(destination, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
                with os.fdopen(descriptor, 'wb') as output, archive.extractfile(member) as source:
                    shutil.copyfileobj(source, output, length=1024 * 1024)
        for name, member in members.items():
            if member.issym():
                os.symlink(member.linkname, staging / name)


def command(args):
    result = subprocess.run(args, capture_output=True, timeout=30, stdin=subprocess.DEVNULL)
    if result.returncode:
        raise RecoveryError('Certificate validation failed')
    return result.stdout


def validate_certificates(directory, expected_ip, *, ca_file=None):
    directory = Path(directory)
    cert, key = directory / 'fullchain.pem', directory / 'privkey.pem'
    command(['openssl', 'x509', '-in', str(cert), '-noout', '-checkend', '3600'])
    command(['openssl', 'x509', '-in', str(cert), '-noout', '-checkip', expected_ip])
    public = command(['openssl', 'x509', '-in', str(cert), '-pubkey', '-noout'])
    private = command(['openssl', 'pkey', '-in', str(key), '-pubout'])
    if public != private:
        raise RecoveryError('Certificate and key do not match')
    # OpenSSL verifies the leaf against the OS public trust store; remaining
    # certificates in fullchain may supply intermediates. Tests use an explicit
    # local CA through this Python-only argument, never disable verification.
    args = ['openssl', 'verify', '-purpose', 'sslserver', '-verify_ip', expected_ip,
            '-untrusted', str(cert)]
    if ca_file:
        args += ['-CAfile', str(ca_file)]
    command(args + [str(cert)])


def validate_staging(staging, expected_ip, expected_versions, *, certificate_check=validate_certificates):
    staging = Path(staging)
    expected_ip = str(ipaddress.IPv4Address(expected_ip))
    checks = {}
    def check(name, function):
        try:
            function()
            checks[name] = '通过'
        except Exception:
            checks[name] = '失败'
    def require(condition):
        if not condition:
            raise RecoveryError('Required backup fact not satisfied')
    def marker():
        require((staging / 'etc/sui-vps/.managed').read_text() == 'sui-vps-v1\n')
    def state_check():
        state = json.loads((staging / 'etc/sui-vps/state.json').read_text())
        require(state['ip'] == expected_ip)
        versions = json.loads((staging / 'opt/sui-vps/versions.json').read_text())
        require(reviewed_versions(versions) == reviewed_versions(expected_versions))
        require(reviewed_versions(state['versions']) == reviewed_versions(versions))
        for key in ('s_ui_image', 'sing_box_image'):
            require(bool(re.search(r'@sha256:[0-9a-f]{64}$', versions[key])))
        require(versions['s_ui_image'] in (staging / 'opt/sui-vps/deploy/compose.yaml').read_text())
    def database_check():
        database = staging / 'opt/sui-vps/deploy/state/db/s-ui.db'
        require(database.is_file())
        # All writes, including potential SQLite WAL handling, stay in staging.
        connection = sqlite3.connect(database.as_uri() + '?mode=ro', uri=True)
        try:
            require(connection.execute('PRAGMA integrity_check').fetchall() == [('ok',)])
            require(bool(connection.execute("SELECT name FROM sqlite_master WHERE type='table'").fetchall()))
        finally:
            connection.close()
    def certificate_match():
        for filename in ('fullchain.pem', 'privkey.pem'):
            require((staging / 'opt/sui-vps/deploy/state/cert' / filename).read_bytes() ==
                    (staging / 'etc/sui-vps/acme/live/sui-vps' / filename).read_bytes())
        require((staging / 'etc/sui-vps/acme/renewal/sui-vps.conf').is_file())
    def acme_account():
        settings = configparser.RawConfigParser()
        settings.read_string('[lineage]\n' + (staging / 'etc/sui-vps/acme/renewal/sui-vps.conf').read_text())
        expected = {'archive_dir': '/etc/sui-vps/acme/archive/sui-vps',
                    **{name: '/etc/sui-vps/acme/live/sui-vps/' + name + '.pem'
                       for name in ('cert', 'chain', 'fullchain', 'privkey')}}
        for key, value in expected.items():
            require(settings['lineage'].get(key) == value)
        identity = settings['renewalparams'].get('account', '')
        require(bool(re.fullmatch(r'[a-fA-F0-9]{16,64}', identity)))
        candidates = [path for path in (staging / 'etc/sui-vps/acme/accounts').rglob(identity) if path.is_dir()]
        require(len(candidates) == 1)
        for filename in ('private_key.json', 'regr.json', 'meta.json'):
            payload = json.loads((candidates[0] / filename).read_text())
            require(isinstance(payload, dict) and bool(payload))
    def cli_config():
        require((staging / 'var/lib/sui-cliproxy/config.yaml').is_file())
    check('ownership_marker', marker)
    check('target_and_fixed_versions', state_check)
    check('sqlite_integrity', database_check)
    check('deployed_certificate', lambda: certificate_check(staging / 'opt/sui-vps/deploy/state/cert', expected_ip))
    check('renewal_certificate', lambda: certificate_check(staging / 'etc/sui-vps/acme/live/sui-vps', expected_ip))
    check('certificate_copies_match', certificate_match)
    check('project_acme_account_present', acme_account)
    check('cliproxy_config_present', cli_config)
    return {'valid': all(result == '通过' for result in checks.values()), 'checks': checks,
            'restore_applied': False, 'lifecycle': '未测试',
            'limitations': ['仅完成私有暂存目录检查，未替换服务器文件或重启服务。',
                            '此操作没有执行应用恢复；真实客户端、防泄露和续期仍需单独验证。']}


def check_archive(archive, expected_ip, expected_versions, *, certificate_check=validate_certificates):
    with tempfile.TemporaryDirectory(prefix='sui-restore-check-') as temporary:
        staging = Path(temporary) / 'staging'
        try:
            extract_private(archive, staging)
        except (OSError, tarfile.TarError, RecoveryError):
            return {'valid': False, 'checks': {'archive_safety': '失败'},
                    'restore_applied': False, 'lifecycle': '未测试'}
        report = validate_staging(staging, expected_ip, expected_versions, certificate_check=certificate_check)
        report['checks']['archive_safety'] = '通过'
        return report


def restore_check(archive, *, expected_ip, output=None, versions=None):
    versions = versions or json.loads((Path(__file__).resolve().parents[1] / 'versions.json').read_text())
    report = check_archive(archive, expected_ip, versions)
    if output:
        output = Path(output)
        output.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
        descriptor, temporary = tempfile.mkstemp(prefix='.restore-report-', dir=output.parent)
        try:
            with os.fdopen(descriptor, 'w') as stream:
                json.dump(report, stream, ensure_ascii=False, indent=2)
                stream.write('\n')
            os.replace(temporary, output)
        finally:
            if os.path.exists(temporary):
                os.unlink(temporary)
    return report


# Every replaced path is fixed below, or an exact owned configuration file.
PAYLOADS = ('etc/sui-vps', 'opt/sui-vps/deploy', 'opt/sui-vps/scripts',
            'opt/sui-vps/versions.json', 'var/lib/sui-cliproxy', 'usr/local/lib/sui-cliproxy')
MANAGED_LINES = {'# Managed by sui-vps.', '# Managed by sui-vps'}


def no_symlink_parent(path, root):
    path, root = Path(path), Path(root)
    if path.is_symlink():
        raise RecoveryError('Restore destination is a symlink')
    for parent in path.parents:
        if parent == root:
            break
        if parent.is_symlink():
            raise RecoveryError('Restore destination has a symlink parent')
    if root not in path.parents:
        raise RecoveryError('Restore destination is outside the target root')


def reviewed_versions(versions):
    return {key: value for key, value in versions.items() if key != 'reviewed_on'}


def owned_configuration(path):
    text = path.read_text()
    if text.splitlines() and text.splitlines()[0] in MANAGED_LINES:
        return True
    # The separately pinned installer writes this exact reviewed unit without
    # the server.py managed prefix. No other unmarked units are accepted.
    if path.name == 'sui-cliproxy.service':
        try:
            import cliproxy
            return text == cliproxy.unit_text()
        except ImportError:
            return False
    return False


def payload_modes(path, relative):
    public = relative.startswith(('opt/sui-vps/scripts', 'usr/local/lib/sui-cliproxy'))
    for current in [path] + list(path.rglob('*')) if path.is_dir() else [path]:
        if current.is_symlink():
            continue
        if current.is_dir():
            current.chmod(0o755 if public else 0o700)
        else:
            mode = 0o644 if public or relative == 'opt/sui-vps/versions.json' else 0o600
            if relative.startswith('usr/local/lib/sui-cliproxy') and current.name == 'cli-proxy-api':
                mode = 0o755
            if 'renewal-hooks' in current.parts:
                mode = 0o700
            current.chmod(mode)


def json_report(path, report):
    path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    fd, temporary = tempfile.mkstemp(prefix='.recovery-', dir=path.parent)
    try:
        with os.fdopen(fd, 'w') as stream:
            json.dump(report, stream, ensure_ascii=False, indent=2)
            stream.write('\n')
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary, path)
    finally:
        if os.path.exists(temporary):
            os.unlink(temporary)


class SystemServices:
    """System controller used only for the real root and an explicit apply."""
    compose = ['docker', 'compose', '-f', '/opt/sui-vps/deploy/compose.yaml']

    def run(self, args, check=True):
        reply = subprocess.run(args, capture_output=True, timeout=90)
        if check and reply.returncode:
            raise RecoveryError('Restore service operation failed')
        return reply

    def panel_state(self):
        identifiers = self.run(self.compose + ['ps', '-a', '-q', 's-ui']).stdout.decode().split()
        if not identifiers:
            return {}
        if len(identifiers) != 1:
            raise RecoveryError('Unexpected number of managed S-UI containers')
        return json.loads(self.run(['docker', 'inspect', '--format', '{{json .State}}', identifiers[0]]).stdout)

    def unit_state(self, name):
        return self.run(['systemctl', 'is-active', name], check=False).stdout.decode().strip()

    def snapshot(self):
        panel = self.panel_state()
        if panel.get('Paused'):
            raise RecoveryError('Unpause or explicitly stop the managed S-UI container before restoring')
        result = {'s-ui': bool(panel.get('Running') or panel.get('Restarting'))}
        units = list(Path('/etc/systemd/system').glob('sui-vps-*.service'))
        units += list(Path('/etc/systemd/system').glob('sui-vps-*.timer'))
        units += [Path('/etc/systemd/system/sui-cliproxy.service')]
        for unit in units:
            if unit.is_file() and not unit.is_symlink():
                if not owned_configuration(unit):
                    raise RecoveryError('Project service name belongs to an unowned unit')
                state = self.unit_state(unit.name)
                if state == 'deactivating':
                    raise RecoveryError('Wait for the project service to finish stopping')
                active = state in ('active', 'reloading', 'activating')
                if active and unit.name.endswith('.service') and unit.name not in ('sui-vps-sub.service', 'sui-cliproxy.service'):
                    raise RecoveryError('Wait for the active project maintenance job before restoring')
                result[unit.name] = active
        return result

    def stop(self, snapshot):
        # Stop every known unit, including a prior inactive service that raced
        # with a timer or was activating. Verify quiescence before file swaps.
        order = sorted(snapshot, key=lambda name: (not name.endswith('.timer'), name))
        for name in order:
            self.run(self.compose + ['stop', 's-ui'] if name == 's-ui' else ['systemctl', 'stop', name])
        panel = self.panel_state()
        if panel.get('Running') or panel.get('Restarting'):
            raise RecoveryError('Managed S-UI is not quiescent')
        for name in snapshot:
            if name != 's-ui' and self.unit_state(name) in ('active', 'reloading', 'activating', 'deactivating'):
                raise RecoveryError('Managed service is not quiescent')

    def restore(self, snapshot):
        self.run(['systemctl', 'daemon-reload'])
        for name, active in snapshot.items():
            action = 'start' if active else 'stop'
            self.run(self.compose + [action, 's-ui'] if name == 's-ui' else ['systemctl', action, name])


def system_permissions(root, prior):
    import pwd
    import grp
    cli = pwd.getpwnam('sui-cliproxy')
    data = root / 'var/lib/sui-cliproxy'
    for path in [data] + list(data.rglob('*')):
        if not path.is_symlink():
            os.chown(path, cli.pw_uid, cli.pw_gid)
    subgroup = grp.getgrnam('sui-sub').gr_gid
    etc = root / 'etc/sui-vps'
    os.chown(etc, 0, subgroup)
    etc.chmod(0o710)
    share = etc / 'subscription-export.json'
    export = etc / 'export.json'
    if export.exists():
        document = json.loads(export.read_text())
        sanitized = {key: document[key] for key in ('nodes', 'subscriptions', 'public_base_url', 'traffic') if key in document}
        json_report(share, sanitized)
    if share.exists():
        os.chown(share, 0, subgroup)
        share.chmod(0o640)
    control = SystemServices()
    control.run(['nginx', '-t'])
    control.run(['/usr/sbin/sshd', '-t'])
    control.run(['sysctl', '--load', '/etc/sysctl.d/90-sui-vps.conf'])
    for unit in ('nginx', 'ssh'):
        if control.run(['systemctl', 'is-active', unit], check=False).returncode == 0:
            control.run(['systemctl', 'reload', unit])


def health_once(root, prior):
    control = SystemServices()
    for name, active in prior.items():
        if not active:
            continue
        if name == 's-ui':
            control.run(control.compose + ['exec', '-T', 's-ui', './sui', 'healthcheck'])
        else:
            control.run(['systemctl', 'is-active', name])
    if prior.get('sui-cliproxy.service'):
        import cliproxy
        state = json.loads((root / 'etc/sui-vps/state.json').read_text())
        cliproxy.verify(state)


def system_health(root, prior):
    for attempt in range(30):
        try:
            health_once(root, prior)
            return
        except RecoveryError:
            if attempt == 29:
                raise
            time.sleep(1)


def system_rollback(root, prior):
    # Restoring files alone does not undo an earlier Nginx/SSH/sysctl reload.
    system_permissions(root, prior)
    system_health(root, prior)


def restore_archive(archive, *, expected_ip, confirm_target, root='/', versions=None,
                    services=None, post_restore=None, post_rollback=None,
                    prepare=None, certificate_check=validate_certificates):
    """Apply a validated snapshot; rollback all replaced files on any failure.

    The caller must serialize this with deployment/renewal/backup (server.py
    holds /run/sui-vps.lock). Direct CLI obtains that lock itself. Per-path
    private sibling directories retain the previous files on successful apply.
    A journal records progress; power-loss recovery still requires inspection.
    """
    expected_ip = str(ipaddress.IPv4Address(expected_ip))
    if confirm_target != expected_ip:
        raise RecoveryError('Explicit target confirmation does not match')
    root = Path(root).absolute()
    if root.is_symlink():
        raise RecoveryError('Restore root cannot be a symlink')
    root = root.resolve()
    if root == Path('/') and os.geteuid() != 0:
        raise RecoveryError('Host restoration requires root')
    if root != Path('/') and (services is None or post_restore is None or post_rollback is None):
        raise RecoveryError('Isolated restoration requires explicit test controllers')
    services = services or SystemServices()
    post_restore = post_restore or system_health
    post_rollback = post_rollback or system_rollback
    prepare = prepare or (system_permissions if root == Path('/') else lambda *args: None)
    versions = versions or json.loads((Path(__file__).resolve().parents[1] / 'versions.json').read_text())
    for relative in ('etc/sui-vps', 'opt/sui-vps'):
        destination = root / relative
        no_symlink_parent(destination, root)
        marker = destination / '.managed'
        if marker.is_symlink() or not marker.is_file() or marker.read_text() != 'sui-vps-v1\n':
            raise RecoveryError('Existing target ownership marker is missing')
    no_symlink_parent(root / 'etc/sui-vps/state.json', root)
    no_symlink_parent(root / 'opt/sui-vps/versions.json', root)
    current = json.loads((root / 'etc/sui-vps/state.json').read_text())
    if current['ip'] != expected_ip:
        raise RecoveryError('Existing target IP differs from confirmed target')
    current_versions = json.loads((root / 'opt/sui-vps/versions.json').read_text())
    if reviewed_versions(current_versions) != reviewed_versions(versions) or reviewed_versions(current['versions']) != reviewed_versions(versions):
        raise RecoveryError('Existing target uses different reviewed versions')
    wrappers, swaps = [], []
    transaction = secrets.token_hex(12)
    journal_path = root / 'var/backups/sui-vps/restore-transactions' / (transaction + '.json')
    no_symlink_parent(journal_path, root)
    journal = {'transaction_id': transaction, 'status': 'preparing', 'paths': [], 'restore_applied': False}
    with tempfile.TemporaryDirectory(prefix='sui-restore-check-') as temporary:
        staged = Path(temporary) / 'staging'
        extract_private(archive, staged)
        validation = validate_staging(staged, expected_ip, versions, certificate_check=certificate_check)
        if not validation['valid']:
            raise RecoveryError('Backup validation failed; no services were stopped')
        paths = list(PAYLOADS)
        for candidate in staged.rglob('*'):
            relative = str(candidate.relative_to(staged))
            if relative in EXACT and relative not in PAYLOADS or re.fullmatch(r'etc/systemd/system/sui-vps-[a-z0-9-]+\.(?:service|timer)', relative):
                if candidate.is_file() and not candidate.is_symlink():
                    paths.append(relative)
        paths = list(dict.fromkeys(paths))
        try:
            # Prepare all same-filesystem replacements before stopping anything.
            for relative in paths:
                source, destination = staged / relative, root / relative
                if not source.exists() or source.is_symlink():
                    raise RecoveryError('Required restore payload is missing')
                no_symlink_parent(destination, root)
                if relative not in PAYLOADS:
                    if not owned_configuration(source) or destination.exists() and not owned_configuration(destination):
                        raise RecoveryError('Refusing to replace an unowned configuration file')
                if not destination.parent.is_dir():
                    raise RecoveryError('Restore destination parent is absent')
                wrapper = Path(tempfile.mkdtemp(prefix='.sui-restore-' + transaction + '-', dir=destination.parent))
                wrapper.chmod(0o700)
                wrappers.append(wrapper)
                new, old = wrapper / 'new', wrapper / 'previous'
                if source.is_dir():
                    shutil.copytree(source, new, symlinks=True)
                else:
                    shutil.copyfile(source, new)
                payload_modes(new, relative)
                swaps.append({'destination': destination, 'new': new, 'old': old, 'relative': relative,
                              'had_old': destination.exists(), 'old_moved': False, 'new_moved': False})
        except Exception:
            for wrapper in wrappers:
                shutil.rmtree(wrapper)
            raise
        snapshot = services.snapshot()
        journal['prior_services'] = snapshot
        journal['paths'] = [{'path': row['relative'], 'previous': str(row['old'].relative_to(root))} for row in swaps]
        json_report(journal_path, journal)
        try:
            services.stop({name: True for name in snapshot})
            journal['status'] = 'replacing'
            json_report(journal_path, journal)
            for row in swaps:
                # Recheck immediately before mutating to reject changed parents.
                no_symlink_parent(row['destination'], root)
                if row['had_old']:
                    os.replace(row['destination'], row['old'])
                    row['old_moved'] = True
                os.replace(row['new'], row['destination'])
                row['new_moved'] = True
                journal['replaced'] = [item['relative'] for item in swaps if item['new_moved']]
                json_report(journal_path, journal)
            prepare(root, snapshot)
            services.restore(snapshot)
            post_restore(root, snapshot)
        except Exception:
            rollback_errors = []
            try:
                services.stop({name: True for name in snapshot})
            except Exception:
                journal.update(status='rollback_failed', restore_applied=False, rolled_back=False,
                               rollback_errors=['stop'], lifecycle='无法确认服务已停止；保留候选文件及旧快照，需人工处理')
                json_report(journal_path, journal)
                raise RecoveryError('Cannot safely stop candidate services; files and previous snapshots retained without rollback') from None
            for row in reversed(swaps):
                try:
                    if row['new_moved']:
                        os.replace(row['destination'], row['new'])
                    if row['old_moved']:
                        os.replace(row['old'], row['destination'])
                except Exception:
                    rollback_errors.append('files')
            if rollback_errors:
                journal.update(status='rollback_failed', restore_applied=False, rolled_back=False,
                               rollback_errors=rollback_errors, lifecycle='文件回滚不完整；服务保持停止，需人工处理')
                json_report(journal_path, journal)
                raise RecoveryError('Filesystem rollback incomplete; services remain stopped for manual recovery') from None
            try:
                services.restore(snapshot)
                post_rollback(root, snapshot)
            except Exception:
                rollback_errors.append('services_or_health')
            journal.update(status='rollback_failed' if rollback_errors else 'rolled_back',
                           restore_applied=False, rolled_back=not rollback_errors,
                           rollback_errors=rollback_errors, lifecycle='恢复失败，已回滚' if not rollback_errors else '回滚需要人工检查')
            json_report(journal_path, journal)
            if rollback_errors:
                raise RecoveryError('Restore rollback incomplete; inspect the private transaction journal') from None
            return journal
        journal.update(status='committed', restore_applied=True, rolled_back=False,
                       previous_snapshot_retained=True, lifecycle='文件与先前运行服务已恢复；真实客户端与防泄露未测试')
        json_report(journal_path, journal)
        return journal


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--archive', type=Path, required=True)
    parser.add_argument('--expected-ip')
    parser.add_argument('--output', type=Path)
    parser.add_argument('--apply', action='store_true', help='Replace owned deployment files; interrupts active connections')
    parser.add_argument('--confirm-target', help='Required IP confirmation for --apply')
    parser.add_argument('--state', type=Path, default=Path('/etc/sui-vps/state.json'))
    args = parser.parse_args()
    try:
        if args.apply:
            if os.geteuid() != 0:
                raise RecoveryError('Host restoration requires root')
            if args.state.is_symlink() or args.state.absolute() != Path('/etc/sui-vps/state.json'):
                raise RecoveryError('Apply must use this host project state file')
            state_ip = json.loads(args.state.read_text())['ip']
            if args.expected_ip and args.expected_ip != state_ip:
                raise RecoveryError('Command target differs from this host state')
            with open('/run/sui-vps.lock', 'a') as lock:
                fcntl.flock(lock, fcntl.LOCK_EX)
                report = restore_archive(args.archive, expected_ip=state_ip, confirm_target=args.confirm_target)
            if args.output:
                json_report(args.output, report)
            print(json.dumps(report, ensure_ascii=False))
            return 0 if report['restore_applied'] else 1
        if not args.expected_ip:
            raise RecoveryError('Read-only check requires an expected IP')
        report = restore_check(args.archive, expected_ip=args.expected_ip, output=args.output)
        print(json.dumps(report, ensure_ascii=False))
        return 0 if report['valid'] else 1
    except Exception:
        print('备份检查或恢复未完成；请查看私有恢复记录，未输出归档内容。')
        return 1


if __name__ == '__main__':
    raise SystemExit(main())
