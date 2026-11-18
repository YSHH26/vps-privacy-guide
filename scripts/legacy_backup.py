#!/usr/bin/env python3
"""Preserve an existing, provider-verified legacy instance before reinstalling.

Uses only the installed trusted legacy backup command. Plaintext crosses an
SSH->age pipe and an age->private external staging pipe; no plaintext archive
is saved locally. This verifies file preservation, not business-service restore.
"""
import argparse
import datetime
import gzip
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import posixpath
import re
import shlex
import sqlite3
import subprocess
import tarfile
import tempfile

MAX_MEMBERS = 50000
MAX_BYTES = 2 * 1024 ** 3
SCOPE = 'decryption+isolated_regular_file_restore+sqlite_integrity; external links inert; business services untested'
ROOTS = ('etc/xxd-vps', 'etc/cliproxyapi', 'etc/cliproxy-auto-update',
         'etc/nginx/sites-available', 'etc/nginx/conf.d', 'etc/letsencrypt',
         'etc/ssh/sshd_config.d', 'etc/ufw', 'etc/systemd/system',
         'var/lib/cliproxyapi/auth', 'var/lib/cliproxyapi/plugins')
EXACT = ('etc/x-ui/x-ui.db', 'etc/sysctl.d/99-xxd-vps.conf',
         'var/lib/xxd-vps/rules-state.json', 'usr/local/x-ui/bin/config.json')
TRUSTED_BACKUP = '''set -eu
test "$(readlink -f /usr/local/sbin/xxd-vps)" = /opt/xxd-vps/tool/xxd-vps.py
test -f /opt/xxd-vps/tool/xxd-vps.py
test ! -L /opt/xxd-vps/tool/xxd-vps.py
/usr/local/sbin/xxd-vps backup
'''


class LegacyBackupError(RuntimeError):
    pass


def backup_filename(output):
    if isinstance(output, bytes):
        output = output.decode('utf-8', errors='replace')
    matches = re.findall(r'(?<![A-Za-z0-9_./-])/var/backups/xxd-vps/config-[0-9]{8}T[0-9]{6}Z\.tar\.gz(?![A-Za-z0-9_./-])', output)
    if len(matches) != 1:
        raise LegacyBackupError('Legacy backup did not return one recognized archive filename')
    return matches[0]


def allowed(name):
    return name in EXACT or any(name == root or name.startswith(root+'/') for root in ROOTS)


def normalized(name):
    parts = PurePosixPath(name).parts
    if not name or name.startswith('/') or '\\' in name or '..' in parts or any(ord(c) < 32 for c in name):
        raise LegacyBackupError('Unsafe archive member path')
    result = str(PurePosixPath(name))
    if not allowed(result):
        raise LegacyBackupError('Archive contains a path outside the reviewed legacy backup manifest')
    return result


def digest_file(path):
    digest = hashlib.sha256()
    with Path(path).open('rb') as stream:
        for chunk in iter(lambda: stream.read(1024*1024), b''):
            digest.update(chunk)
    return digest.hexdigest()


def extract_restore(compressed_stream, staging):
    """Restore ordinary files privately; external links remain inert metadata."""
    staging = Path(staging)
    if staging.is_symlink() or staging.exists() and (not staging.is_dir() or any(staging.iterdir())):
        raise LegacyBackupError('Restoration requires a fresh private staging directory')
    staging.mkdir(mode=0o700, parents=True, exist_ok=True)
    staging.chmod(0o700)
    members, files, links, total = {}, [], [], 0
    with gzip.GzipFile(fileobj=compressed_stream) as decompressed:
        with tarfile.open(fileobj=decompressed, mode='r|') as archive:
            for member in archive:
                name = normalized(member.name)
                if name in members or len(members) >= MAX_MEMBERS:
                    raise LegacyBackupError('Duplicate archive member or archive member limit exceeded')
                if not (member.isdir() or member.isfile() or member.issym()) or member.islnk():
                    raise LegacyBackupError('Archive hardlinks, devices and special files are rejected')
                if member.size < 0 or member.size > MAX_BYTES-total:
                    raise LegacyBackupError('Archive exceeds restoration size limit')
                total += member.size
                members[name] = {'type': 'directory' if member.isdir() else 'file' if member.isfile() else 'symlink',
                                 'mode': member.mode, 'size': member.size}
                destination = staging/name
                destination.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
                if member.isdir():
                    destination.mkdir(mode=0o700, exist_ok=True)
                elif member.isfile():
                    checksum = hashlib.sha256()
                    fd = os.open(destination, os.O_WRONLY|os.O_CREAT|os.O_EXCL, 0o600)
                    with os.fdopen(fd, 'wb') as output, archive.extractfile(member) as source:
                        for chunk in iter(lambda: source.read(1024*1024), b''):
                            checksum.update(chunk)
                            output.write(chunk)
                    if destination.stat().st_size != member.size or digest_file(destination) != checksum.hexdigest():
                        raise LegacyBackupError('Restored file differs from archived bytes')
                    files.append({'path': name, 'size': member.size, 'mode': member.mode, 'sha256': checksum.hexdigest()})
                else:
                    if not member.linkname or any(ord(c) < 32 for c in member.linkname) or '\\' in member.linkname:
                        raise LegacyBackupError('Unsafe symbolic link metadata')
                    links.append({'path': name, 'target': member.linkname, 'mode': member.mode})
        # Read the gzip trailer, so truncated/corrupt gzip cannot pass when tar
        # reached its end marker early. A normal tar has only small zero padding.
        remaining = decompressed.read(1024*1024+1)
        if len(remaining) > 1024*1024 or any(remaining):
            raise LegacyBackupError('Unexpected data after the tar end marker')
    for name in members:
        for parent in PurePosixPath(name).parents:
            if str(parent) in members and members[str(parent)]['type'] != 'directory':
                raise LegacyBackupError('Archive file or symlink used as a parent directory')
    link_by_name = {row['path']: row for row in links}
    def target_name(row):
        target = row['target']
        return posixpath.normpath(target.lstrip('/') if target.startswith('/') else posixpath.join(posixpath.dirname(row['path']), target))
    def contained(name, seen=None):
        seen = set() if seen is None else seen
        if name not in members or name in seen or name == '..' or name.startswith('../'):
            return False
        if members[name]['type'] != 'symlink':
            return True
        return contained(target_name(link_by_name[name]), seen|{name})
    for row in links:
        target = target_name(row)
        row['restored'] = contained(target)
        if row['restored']:
            # Absolute in-archive links become relative, never host-root links.
            safe_target = posixpath.relpath(target, posixpath.dirname(row['path']))
            os.symlink(safe_target, staging/row['path'])
        else:
            row['preservation'] = 'inert_metadata_only'
    return {'regular_files': files, 'symlinks': links,
            'member_count': len(members), 'uncompressed_file_bytes': total}


def validate_restored(staging, manifest, *, expected_ip):
    staging = Path(staging)
    try:
        deploy = json.loads((staging/'etc/xxd-vps/deploy.json').read_text())
        credentials = json.loads((staging/'etc/xxd-vps/credentials.json').read_text())
        if deploy.get('ip') != expected_ip or not isinstance(credentials, dict) or not credentials:
            raise ValueError()
        config = staging/'etc/cliproxyapi/config.yaml'
        auth = staging/'var/lib/cliproxyapi/auth'
        if not config.is_file() or not config.stat().st_size or not auth.is_dir() or auth.is_symlink():
            raise ValueError()
        for row in manifest['regular_files']:
            file = staging/row['path']
            if file.is_symlink() or digest_file(file) != row['sha256']:
                raise ValueError()
        database = staging/'etc/x-ui/x-ui.db'
        connection = sqlite3.connect(database.resolve().as_uri()+'?mode=ro&immutable=1', uri=True)
        try:
            if connection.execute('PRAGMA integrity_check').fetchall() != [('ok',)]:
                raise ValueError()
            tables = {row[0] for row in connection.execute("SELECT name FROM sqlite_master WHERE type='table'")}
            if not {'settings', 'inbounds'}.issubset(tables):
                raise ValueError()
        finally:
            connection.close()
    except (OSError, ValueError, TypeError, KeyError, sqlite3.Error):
        raise LegacyBackupError('Isolated legacy files, target, CLI preservation or SQLite integrity check failed') from None
    return {'regularfiles_restore': 'passed', 'files_restore': 'passed', 'sqlite': 'passed',
            'legacy_config': 'passed', 'cli_config_preservation': 'passed',
            'cli_auth_preservation': 'passed',
            'cli_auth_regular_file_count': sum(1 for row in manifest['regular_files'] if row['path'].startswith('var/lib/cliproxyapi/auth/')),
            'external_links_preserved_as_metadata': sum(not row['restored'] for row in manifest['symlinks'])}


def identity_recipient(identity):
    identity = Path(identity)
    if identity.is_symlink():
        raise LegacyBackupError('Age identity must not be a symlink')
    if not identity.exists():
        fd, temporary = tempfile.mkstemp(prefix='.legacy-age-', dir=identity.parent)
        os.close(fd)
        os.unlink(temporary)  # age-keygen requires a new output filename.
        try:
            result = subprocess.run(['age-keygen', '-o', temporary], capture_output=True, timeout=30)
            if result.returncode:
                raise LegacyBackupError('Age identity generation failed')
            os.chmod(temporary, 0o600)
            # Hard-linking commits without replacing a concurrently created key.
            os.link(temporary, identity)
        finally:
            if os.path.exists(temporary):
                os.unlink(temporary)
    if identity.stat().st_mode & 0o077 or identity.stat().st_uid != os.getuid():
        raise LegacyBackupError('Age identity must be owned by you with mode 600')
    result = subprocess.run(['age-keygen', '-y', str(identity)], capture_output=True, timeout=30)
    recipient = result.stdout.decode().strip()
    if result.returncode or not re.fullmatch(r'age1[0-9a-z]{58}', recipient):
        raise LegacyBackupError('Age identity is invalid')
    return recipient


def encrypt_remote(state, remote, recipient, destination):
    import vps
    # Both stderr streams remain private descriptors and are never printed.
    command = 'set -eu; test ! -L '+shlex.quote(remote)+'; test -f '+shlex.quote(remote)+'; exec cat -- '+shlex.quote(remote)
    ssh_process = age_process = None
    try:
        with tempfile.TemporaryFile() as ssh_error, tempfile.TemporaryFile() as age_error, Path(destination).open('wb') as encrypted:
            os.chmod(destination, 0o600)
            ssh_process = subprocess.Popen(vps.ssh_args(state)+[command], stdout=subprocess.PIPE, stderr=ssh_error)
            age_process = subprocess.Popen(['age', '-r', recipient], stdin=ssh_process.stdout,
                                           stdout=encrypted, stderr=age_error)
            ssh_process.stdout.close()
            age_status = age_process.wait(timeout=600)
            ssh_status = ssh_process.wait(timeout=30)
            if age_status or ssh_status:
                raise LegacyBackupError('Legacy archive encryption stream failed')
            encrypted.flush()
            os.fsync(encrypted.fileno())
    except (OSError, subprocess.SubprocessError):
        raise LegacyBackupError('SSH or age encryption stream failed') from None
    finally:
        for process in (age_process, ssh_process):
            if process is not None and process.poll() is None:
                process.kill()
                process.wait()
            if process is not None and process.stdout is not None:
                process.stdout.close()


def verify_ciphertext(encrypted, identity, expected_ip):
    process = None
    try:
        with tempfile.TemporaryDirectory(prefix='sui-legacy-restore-', dir='/tmp') as temporary, tempfile.TemporaryFile() as errors:
            process = subprocess.Popen(['age', '--decrypt', '-i', str(identity), str(encrypted)],
                                       stdout=subprocess.PIPE, stderr=errors)
            staging = Path(temporary)/'files'
            manifest = extract_restore(process.stdout, staging)
            # Consume authenticated age EOF before accepting any restored file.
            while process.stdout.read(1024*1024):
                pass
            process.stdout.close()
            if process.wait(timeout=30):
                raise LegacyBackupError('Age decryption authentication failed')
            return validate_restored(staging, manifest, expected_ip=expected_ip), manifest
    except (OSError, EOFError, gzip.BadGzipFile, tarfile.TarError, subprocess.SubprocessError):
        raise LegacyBackupError('Encrypted legacy backup could not be safely restored in isolation') from None
    finally:
        if process is not None:
            if process.poll() is None:
                process.kill()
                process.wait()
            if process.stdout is not None:
                process.stdout.close()


def preserve(state_path, *, ops=None, transport=encrypt_remote):
    if ops is None:
        import vps as ops
    state_path = ops.secure_path(state_path)
    state = ops.private_json(state_path)
    ops.validate(state)
    ops.target_info(state)
    # A failed new preservation run must not leave a stale approval for reinstall.
    state['backup_restore_verified'] = False
    state['backup_restore_scope'] = SCOPE
    ops.save(state_path, state)
    identity = state_path.parent/'legacy-backup-age.key'
    recipient = identity_recipient(identity)
    output = ops.ssh(state, TRUSTED_BACKUP)
    remote = backup_filename(output.stdout)
    stamp = datetime.datetime.now(datetime.timezone.utc).strftime('%Y%m%dT%H%M%SZ')+'-'+os.urandom(4).hex()
    encrypted = state_path.parent/('legacy-config-'+stamp+'.tar.gz.age')
    report_path = state_path.parent/('legacy-preservation-'+stamp+'.json')
    manifest_path = state_path.parent/('legacy-manifest-'+stamp+'.json')
    fd, partial = tempfile.mkstemp(prefix='.legacy-encrypted-', dir=state_path.parent)
    os.close(fd)
    try:
        transport(state, remote, recipient, partial)
        checks, manifest = verify_ciphertext(partial, identity, state['ip'])
        os.chmod(partial, 0o600)
        os.replace(partial, encrypted)
        ops.save(manifest_path, manifest)
        report = {'scope': 'old_instance_file_preservation',
                  'checked_at': datetime.datetime.now(datetime.timezone.utc).isoformat(),
                  'encrypted_backup_sha256': digest_file(encrypted),
                  'business_service_restore': 'untested', 'lifecycle': 'untested',
                  'manifest_sha256': digest_file(manifest_path), **checks}
        ops.save(report_path, report)
        state.update(encrypted_backup=str(encrypted.absolute()), backup_restore_verified=True,
                     backup_restore_scope=SCOPE, encrypted_backup_sha256=report['encrypted_backup_sha256'],
                     legacy_backup_identity=str(identity.absolute()), legacy_backup_report=str(report_path.absolute()),
                     legacy_backup_manifest=str(manifest_path.absolute()))
        ops.save(state_path, state)
        return report
    finally:
        if os.path.exists(partial):
            os.unlink(partial)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--state', required=True)
    args = parser.parse_args()
    try:
        preserve(args.state)
    except Exception:
        print('旧实例保全失败；未批准重装，未输出归档、凭据或命令错误内容。', file=__import__('sys').stderr)
        return 1
    print('旧实例已加密保全；隔离文件恢复和 SQLite 检查通过，业务服务恢复未测试。')
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
