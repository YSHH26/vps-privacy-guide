import base64
import importlib.util
import io
import json
import os
from pathlib import Path
import sqlite3
import subprocess
import tarfile
import tempfile
import unittest
from types import SimpleNamespace

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location('legacy_backup', ROOT/'scripts/legacy_backup.py')
legacy = importlib.util.module_from_spec(spec)
spec.loader.exec_module(legacy)


def fixture_archive(*, corrupt_db=False, missing_auth=False, extra=None):
    with tempfile.TemporaryDirectory() as tmp:
        database = Path(tmp)/'x-ui.db'
        connection = sqlite3.connect(database)
        connection.execute('CREATE TABLE settings (key TEXT, value TEXT)')
        connection.execute('CREATE TABLE inbounds (id INTEGER PRIMARY KEY)')
        connection.commit()
        connection.close()
        files = {
            'etc/x-ui/x-ui.db': b'bad database' if corrupt_db else database.read_bytes(),
            'etc/xxd-vps/deploy.json': b'{"ip":"192.0.2.10","alias":"__SSH_ALIAS__"}',
            'etc/xxd-vps/credentials.json': b'{"panel_password":"__TEST_PASSWORD__"}',
            'etc/cliproxyapi/config.yaml': b'oauth:\n  auth-dir: /var/lib/cliproxyapi/auth\n',
            'etc/letsencrypt/archive/test/fullchain1.pem': b'__TEST_CERTIFICATE__',
        }
        buffer = io.BytesIO()
        with tarfile.open(fileobj=buffer, mode='w:gz') as archive:
            for name, content in files.items():
                member = tarfile.TarInfo(name)
                member.size = len(content)
                archive.addfile(member, io.BytesIO(content))
            if not missing_auth:
                member = tarfile.TarInfo('var/lib/cliproxyapi/auth')
                member.type = tarfile.DIRTYPE
                archive.addfile(member)
            link = tarfile.TarInfo('etc/letsencrypt/live/test/fullchain.pem')
            link.type, link.linkname = tarfile.SYMTYPE, '../../archive/test/fullchain1.pem'
            archive.addfile(link)
            link = tarfile.TarInfo('etc/systemd/system/multi-user.target.wants/example.service')
            link.type, link.linkname = tarfile.SYMTYPE, '/usr/lib/systemd/system/example.service'
            archive.addfile(link)
            if extra:
                member, content = extra
                archive.addfile(member, io.BytesIO(content))
        return buffer.getvalue()


class LegacyBackupTests(unittest.TestCase):
    def test_restores_regular_files_and_keeps_external_links_inert(self):
        with tempfile.TemporaryDirectory() as tmp:
            staging = Path(tmp)/'restored'
            manifest = legacy.extract_restore(io.BytesIO(fixture_archive()), staging)
            checks = legacy.validate_restored(staging, manifest, expected_ip='192.0.2.10')
            self.assertEqual('passed', checks['sqlite'])
            self.assertEqual(1, checks['external_links_preserved_as_metadata'])
            self.assertTrue((staging/'etc/letsencrypt/live/test/fullchain.pem').is_symlink())
            self.assertFalse((staging/'etc/systemd/system/multi-user.target.wants/example.service').exists())
            self.assertEqual(0o600, (staging/'etc/xxd-vps/credentials.json').stat().st_mode & 0o777)

    def test_rejects_traversal_hardlink_and_device(self):
        bad = [tarfile.TarInfo('../../escape'), tarfile.TarInfo('etc/xxd-vps/hard'), tarfile.TarInfo('etc/xxd-vps/device')]
        bad[1].type, bad[1].linkname = tarfile.LNKTYPE, 'etc/xxd-vps/credentials.json'
        bad[2].type = tarfile.CHRTYPE
        for member in bad:
            with self.subTest(type=member.type), tempfile.TemporaryDirectory() as tmp:
                with self.assertRaises(legacy.LegacyBackupError):
                    legacy.extract_restore(io.BytesIO(fixture_archive(extra=(member, b''))), Path(tmp)/'restored')

    def test_missing_auth_and_corrupt_database_do_not_verify(self):
        for payload in (fixture_archive(missing_auth=True), fixture_archive(corrupt_db=True)):
            with tempfile.TemporaryDirectory() as tmp:
                staging = Path(tmp)/'restored'
                manifest = legacy.extract_restore(io.BytesIO(payload), staging)
                with self.assertRaises(legacy.LegacyBackupError):
                    legacy.validate_restored(staging, manifest, expected_ip='192.0.2.10')

    def test_target_mismatch_in_restored_deploy_rejected(self):
        with tempfile.TemporaryDirectory() as tmp:
            staging = Path(tmp)/'restored'
            manifest = legacy.extract_restore(io.BytesIO(fixture_archive()), staging)
            with self.assertRaises(legacy.LegacyBackupError):
                legacy.validate_restored(staging, manifest, expected_ip='192.0.2.99')

    @unittest.skipUnless(__import__('shutil').which('age') and __import__('shutil').which('age-keygen'), 'age tools required')
    def test_encrypted_stream_is_decrypted_restored_and_scope_is_explicit(self):
        with tempfile.TemporaryDirectory() as tmp:
            directory = Path(tmp)
            state = directory/'target.json'
            state.write_text('{"ip":"192.0.2.10","ssh_alias":"__SSH_ALIAS__","veid":"__VEID__"}')
            state.chmod(0o600)
            calls = []
            class Ops:
                def private_json(self, path):
                    return json.loads(Path(path).read_text())
                def secure_path(self, path, exists=True):
                    return Path(path)
                def save(self, path, value):
                    Path(path).write_text(json.dumps(value))
                    Path(path).chmod(0o600)
                def validate(self, value):
                    calls.append('validate')
                def target_info(self, value):
                    calls.append('provider')
                    return {'ip_addresses': ['192.0.2.10']}
                def ssh(self, value, command):
                    calls.append(command)
                    return SimpleNamespace(stdout='备份完成：/var/backups/xxd-vps/config-20261117T000000Z.tar.gz（保留最近 7 份）'.encode())
            def transport(value, remote, recipient, destination):
                encrypted = subprocess.run(['age', '-r', recipient], input=fixture_archive(), capture_output=True, check=True).stdout
                Path(destination).write_bytes(encrypted)
                Path(destination).chmod(0o600)
            result = legacy.preserve(state, ops=Ops(), transport=transport)
            stored = json.loads(state.read_text())
            self.assertTrue(stored['backup_restore_verified'])
            self.assertIn('external links inert; business services untested', stored['backup_restore_scope'])
            self.assertEqual('old_instance_file_preservation', result['scope'])
            self.assertEqual('passed', result['regularfiles_restore'])
            self.assertEqual('untested', result['business_service_restore'])
            self.assertEqual(0o600, Path(stored['encrypted_backup']).stat().st_mode & 0o777)
            self.assertEqual(0o600, Path(stored['legacy_backup_identity']).stat().st_mode & 0o777)
            self.assertIn('readlink -f /usr/local/sbin/xxd-vps', calls[-1])
            self.assertEqual(['validate', 'provider'], calls[:2])
            self.assertFalse(list(directory.glob('*.tar.gz')))

    @unittest.skipUnless(__import__('shutil').which('age') and __import__('shutil').which('age-keygen'), 'age tools required')
    def test_age_authentication_failure_cannot_verify_plaintext_prefix(self):
        with tempfile.TemporaryDirectory() as tmp:
            identity = Path(tmp)/'identity.key'
            recipient = legacy.identity_recipient(identity)
            original = identity.read_bytes()
            self.assertEqual(recipient, legacy.identity_recipient(identity))
            self.assertEqual(original, identity.read_bytes())
            cipher = bytearray(subprocess.run(['age', '-r', recipient], input=fixture_archive(), capture_output=True, check=True).stdout)
            cipher[-1] ^= 1
            encrypted = Path(tmp)/'corrupt.age'
            encrypted.write_bytes(cipher)
            with self.assertRaises(legacy.LegacyBackupError):
                legacy.verify_ciphertext(encrypted, identity, '192.0.2.10')

    @unittest.skipUnless(__import__('shutil').which('age') and __import__('shutil').which('age-keygen'), 'age tools required')
    def test_failed_new_backup_clears_prior_reinstall_confirmation(self):
        with tempfile.TemporaryDirectory() as tmp:
            state = Path(tmp)/'target.json'
            state.write_text('{"ip":"192.0.2.10","ssh_alias":"__SSH_ALIAS__","backup_restore_verified":true}')
            state.chmod(0o600)
            def save(path, value):
                Path(path).write_text(json.dumps(value))
            ops = SimpleNamespace(secure_path=lambda path: Path(path),
                                  private_json=lambda path: json.loads(Path(path).read_text()),
                                  save=save, validate=lambda value: None, target_info=lambda value: None,
                                  ssh=lambda value, command: SimpleNamespace(stdout=b'/var/backups/xxd-vps/config-20261117T000000Z.tar.gz'))
            def broken(*args):
                raise legacy.LegacyBackupError('Mock encrypted stream failure')
            with self.assertRaises(legacy.LegacyBackupError):
                legacy.preserve(state, ops=ops, transport=broken)
            self.assertFalse(json.loads(state.read_text())['backup_restore_verified'])
            self.assertFalse(list(Path(tmp).glob('.legacy-encrypted-*')))

    def test_backup_output_path_parser_rejects_multiple_or_unexpected_paths(self):
        for value in ('/tmp/var/backups/xxd-vps/config-20261117T000000Z.tar.gz', '/var/backups/xxd-vps/config-20261117T000000Z.tar.gz.evil', '/tmp/config-20261117T000000Z.tar.gz', '/var/backups/xxd-vps/config-a.tar.gz',
                      '/var/backups/xxd-vps/config-20261117T000000Z.tar.gz /var/backups/xxd-vps/config-20261118T000000Z.tar.gz'):
            with self.assertRaises(legacy.LegacyBackupError):
                legacy.backup_filename(value)


if __name__ == '__main__':
    unittest.main()
