"""Restore validation uses only synthetic private temporary fixtures."""
import io
import json
from pathlib import Path
import sqlite3
import subprocess
import shutil
import sys
import tarfile
import tempfile
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'scripts'))
import recovery


class FakeServices:
    def __init__(self):
        self.original = {'s-ui': True, 'sui-cliproxy': False, 'sui-vps-sub': True}
        self.current = dict(self.original)
        self.calls = []
    def snapshot(self):
        return dict(self.current)
    def stop(self, snapshot):
        self.calls.append('stop')
        self.current = {key: False for key in snapshot}
    def restore(self, snapshot):
        self.calls.append('restore')
        self.current = dict(snapshot)


class RecoveryTests(unittest.TestCase):
    def tar(self, path, entries):
        with tarfile.open(path, 'w:gz') as archive:
            for name, kind, value in entries:
                member = tarfile.TarInfo(name)
                if kind == 'link':
                    member.type = tarfile.SYMTYPE
                    member.linkname = value
                    archive.addfile(member)
                elif kind == 'hardlink':
                    member.type = tarfile.LNKTYPE
                    member.linkname = value
                    archive.addfile(member)
                else:
                    member.size = len(value)
                    archive.addfile(member, io.BytesIO(value))

    def test_malicious_archive_rejected_before_extract(self):
        cases = [('/etc/sui-vps/state.json', 'file', b'{}'),
                 ('etc/sui-vps/../../escape', 'file', b'x'),
                 ('etc/shadow', 'file', b'x'),
                 ('etc/sui-vps/state.json', 'hardlink', 'etc/shadow'),
                 ('etc/sui-vps/link', 'link', '/etc/shadow'),
                 ('etc/sui-vps/acme/live/sui-vps/fullchain.pem', 'link', '../../archive/other/fullchain1.pem')]
        for entry in cases:
            with self.subTest(entry=entry[0]), tempfile.TemporaryDirectory() as tmp:
                archive, staging = Path(tmp) / 'backup.tar.gz', Path(tmp) / 'stage'
                self.tar(archive, [entry])
                with self.assertRaises(recovery.RecoveryError):
                    recovery.extract_private(archive, staging)
                self.assertFalse((Path(tmp) / 'escape').exists())

    def test_relative_cert_links_allowed_only_to_archived_regular_files(self):
        with tempfile.TemporaryDirectory() as tmp:
            archive, staging = Path(tmp) / 'backup.tar.gz', Path(tmp) / 'stage'
            target = 'etc/sui-vps/acme/archive/sui-vps/fullchain1.pem'
            link = 'etc/sui-vps/acme/live/sui-vps/fullchain.pem'
            self.tar(archive, [(target, 'file', b'synthetic cert'),
                               (link, 'link', '../../archive/sui-vps/fullchain1.pem')])
            recovery.extract_private(archive, staging)
            self.assertEqual((staging / link).read_bytes(), b'synthetic cert')
            self.assertEqual(staging.stat().st_mode & 0o777, 0o700)
            self.assertEqual((staging / target).stat().st_mode & 0o777, 0o600)
            self.tar(archive, [(link, 'link', '../../archive/sui-vps/fullchain1.pem')])
            with self.assertRaises(recovery.RecoveryError):
                recovery.extract_private(archive, Path(tmp) / 'missing-target')

    def test_duplicates_and_extraction_into_existing_data_rejected(self):
        with tempfile.TemporaryDirectory() as tmp:
            archive, staging = Path(tmp) / 'backup.tar.gz', Path(tmp) / 'stage'
            self.tar(archive, [('etc/sui-vps/state.json', 'file', b'{}')] * 2)
            with self.assertRaises(recovery.RecoveryError):
                recovery.extract_private(archive, staging)
            staging.mkdir(exist_ok=True)
            (staging / 'do-not-touch').write_text('preserve')
            with self.assertRaises(recovery.RecoveryError):
                recovery.extract_private(archive, staging)
            self.assertEqual((staging / 'do-not-touch').read_text(), 'preserve')

    def fixture(self, root):
        versions = {'s_ui_image': 'example:v1@sha256:' + 'a' * 64,
                    'sing_box_image': 'example:v1@sha256:' + 'b' * 64,
                    'cli_proxy_version': 'v8.0.76', 'cli_proxy_management': {'version': 'v1.28.1'}}
        def write(name, value):
            path = root / name
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text(value)
        write('etc/sui-vps/.managed', 'sui-vps-v1\n')
        write('etc/sui-vps/state.json', json.dumps({'ip': '192.0.2.1', 'versions': versions}))
        write('opt/sui-vps/versions.json', json.dumps(versions))
        write('opt/sui-vps/deploy/compose.yaml', 'image: ' + versions['s_ui_image'])
        database = root / 'opt/sui-vps/deploy/state/db/s-ui.db'
        database.parent.mkdir(parents=True)
        with sqlite3.connect(database) as connection:
            connection.execute('CREATE TABLE synthetic_test (id INTEGER PRIMARY KEY)')
        for name in ['fullchain.pem', 'privkey.pem']:
            write('opt/sui-vps/deploy/state/cert/' + name, 'synthetic')
            write('etc/sui-vps/acme/live/sui-vps/' + name, 'synthetic')
        write('etc/sui-vps/acme/renewal/sui-vps.conf',
              'archive_dir = /etc/sui-vps/acme/archive/sui-vps\n' +
              ''.join(name + ' = /etc/sui-vps/acme/live/sui-vps/' + name + '.pem\n'
                      for name in ('cert', 'chain', 'fullchain', 'privkey')) +
              '[renewalparams]\naccount = ' + 'a' * 32 + '\n')
        for filename in ('private_key.json', 'regr.json', 'meta.json'):
            write('etc/sui-vps/acme/accounts/acme.example.test/directory/' + 'a' * 32 + '/' + filename,
                  '{"synthetic": true}')
        write('var/lib/sui-cliproxy/config.yaml', 'synthetic config')
        write('opt/sui-vps/scripts/server.py', '# synthetic source')
        write('usr/local/lib/sui-cliproxy/cli-proxy-api', 'synthetic binary')
        write('usr/local/lib/sui-cliproxy/static/management.html', 'synthetic page')
        return versions

    def test_staged_validation_checks_ip_versions_sqlite_and_reports_no_restore(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            versions = self.fixture(root)
            called = []
            def certificates(directory, ip):
                called.append((directory, ip))
            report = recovery.validate_staging(root, '192.0.2.1', versions, certificate_check=certificates)
            self.assertTrue(report['valid'])
            self.assertFalse(report['restore_applied'])
            self.assertEqual(len(called), 2)
            self.assertNotIn('192.0.2.1', json.dumps(report))
            self.assertFalse(recovery.validate_staging(root, '192.0.2.2', versions, certificate_check=certificates)['valid'])
            wrong = dict(versions, cli_proxy_version='other-version')
            self.assertFalse(recovery.validate_staging(root, '192.0.2.1', wrong, certificate_check=certificates)['valid'])
            (root / 'opt/sui-vps/deploy/state/db/s-ui.db').write_bytes(b'corrupted database')
            report = recovery.validate_staging(root, '192.0.2.1', versions, certificate_check=certificates)
            self.assertEqual(report['checks']['sqlite_integrity'], '失败')

    def test_system_controller_stops_inactive_activating_and_restarting_services(self):
        class Controller(recovery.SystemServices):
            def __init__(self):
                self.calls = []
                self.states = {'sui-vps-sub.service': 'activating', 'sui-cliproxy.service': 'inactive'}
                self.panel = {'Running': False, 'Restarting': True}
            def run(self, args, check=True):
                self.calls.append(args)
                if args[-2:] == ['stop', 's-ui']:
                    self.panel = {'Running': False, 'Restarting': False}
                elif args[:2] == ['systemctl', 'stop']:
                    self.states[args[-1]] = 'inactive'
                return type('Reply', (), {'returncode': 0, 'stdout': b''})()
            def panel_state(self):
                return self.panel
            def unit_state(self, name):
                return self.states[name]
        controller = Controller()
        controller.stop({'s-ui': False, 'sui-vps-sub.service': False, 'sui-cliproxy.service': False})
        self.assertIn(['systemctl', 'stop', 'sui-vps-sub.service'], controller.calls)
        self.assertIn(['systemctl', 'stop', 'sui-cliproxy.service'], controller.calls)
        self.assertIn(controller.compose + ['stop', 's-ui'], controller.calls)
        self.assertFalse(controller.panel['Restarting'])

    def test_acme_account_absence_and_renewal_path_escape_rejected(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            versions = self.fixture(root)
            account = next((root / 'etc/sui-vps/acme/accounts').rglob('private_key.json'))
            account.unlink()
            report = recovery.validate_staging(root, '192.0.2.1', versions, certificate_check=lambda *a: None)
            self.assertEqual(report['checks']['project_acme_account_present'], '失败')
            account.write_text('{"synthetic": true}')
            renewal = root / 'etc/sui-vps/acme/renewal/sui-vps.conf'
            renewal.write_text(renewal.read_text().replace('/etc/sui-vps/acme/archive/sui-vps', '/etc/another-project'))
            self.assertEqual(recovery.validate_staging(root, '192.0.2.1', versions,
                certificate_check=lambda *a: None)['checks']['project_acme_account_present'], '失败')

    def prepared_restore(self, root):
        source, target = root / 'source', root / 'target'
        versions = self.fixture(source)
        self.fixture(target)
        (target / 'opt/sui-vps/.managed').write_text('sui-vps-v1\n')
        (source / 'etc/sui-vps/instance-note').write_text('backup value')
        (target / 'etc/sui-vps/instance-note').write_text('current value')
        foreign = target / 'etc/nginx/conf.d/foreign.conf'
        foreign.parent.mkdir(parents=True)
        foreign.write_text('unrelated project must stay')
        archive = root / 'backup.tar.gz'
        with tarfile.open(archive, 'w:gz') as tar:
            for path in source.rglob('*'):
                if path.is_file():
                    tar.add(path, arcname=path.relative_to(source))
        return archive, target, versions, foreign

    def test_transaction_success_preserves_service_state_and_unrelated_files(self):
        with tempfile.TemporaryDirectory() as tmp:
            archive, target, versions, foreign = self.prepared_restore(Path(tmp))
            services = FakeServices()
            health = []
            report = recovery.restore_archive(archive, expected_ip='192.0.2.1', confirm_target='192.0.2.1',
                root=target, versions=versions, services=services,
                certificate_check=lambda *a: None,
                post_restore=lambda root, prior: health.append('passed'), post_rollback=lambda *a: None)
            self.assertTrue(report['restore_applied'])
            self.assertEqual((target / 'etc/sui-vps/instance-note').read_text(), 'backup value')
            self.assertEqual(foreign.read_text(), 'unrelated project must stay')
            self.assertEqual(services.current, services.original)
            self.assertEqual(health, ['passed'])
            self.assertEqual((target / 'usr/local/lib/sui-cliproxy/cli-proxy-api').stat().st_mode & 0o777, 0o755)
            self.assertEqual((target / 'etc/sui-vps/state.json').stat().st_mode & 0o777, 0o600)
            self.assertTrue(report['previous_snapshot_retained'])

    def test_posthealth_failure_rolls_back_all_files_and_services(self):
        with tempfile.TemporaryDirectory() as tmp:
            archive, target, versions, foreign = self.prepared_restore(Path(tmp))
            services = FakeServices()
            def health(*args):
                self.assertEqual((target / 'etc/sui-vps/instance-note').read_text(), 'backup value')
                raise RuntimeError('synthetic health failure')
            report = recovery.restore_archive(archive, expected_ip='192.0.2.1', confirm_target='192.0.2.1',
                root=target, versions=versions, services=services, certificate_check=lambda *a: None,
                post_restore=health, post_rollback=lambda *a: None)
            self.assertFalse(report['restore_applied'])
            self.assertTrue(report['rolled_back'])
            self.assertEqual((target / 'etc/sui-vps/instance-note').read_text(), 'current value')
            self.assertEqual(foreign.read_text(), 'unrelated project must stay')
            self.assertEqual(services.current, services.original)

    def test_restore_requires_confirmation_markers_and_no_symlink_parent(self):
        with tempfile.TemporaryDirectory() as tmp:
            archive, target, versions, _ = self.prepared_restore(Path(tmp))
            kwargs = dict(expected_ip='192.0.2.1', root=target, versions=versions,
                          services=FakeServices(), certificate_check=lambda *a: None,
                          post_restore=lambda *a: None, post_rollback=lambda *a: None)
            with self.assertRaises(recovery.RecoveryError):
                recovery.restore_archive(archive, confirm_target='192.0.2.2', **kwargs)
            (target / 'opt/sui-vps/.managed').unlink()
            with self.assertRaises(recovery.RecoveryError):
                recovery.restore_archive(archive, confirm_target='192.0.2.1', **kwargs)
            (target / 'opt/sui-vps/.managed').write_text('sui-vps-v1\n')
            shutil.rmtree(target / 'usr/local/lib/sui-cliproxy')
            (target / 'usr/local/lib/sui-cliproxy').symlink_to(Path(tmp) / 'source/usr/local/lib/sui-cliproxy')
            with self.assertRaises(recovery.RecoveryError):
                recovery.restore_archive(archive, confirm_target='192.0.2.1', **kwargs)
            self.assertEqual(kwargs['services'].calls, [])

    def test_existing_foreign_configuration_is_not_overwritten(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            archive, target, versions, _ = self.prepared_restore(root)
            source = root / 'source'
            config = source / 'etc/nginx/conf.d/sui-vps-https.conf'
            config.parent.mkdir(parents=True)
            config.write_text('# Managed by sui-vps.\nserver {}')
            destination = target / 'etc/nginx/conf.d/sui-vps-https.conf'
            destination.write_text('belongs to another project')
            with tarfile.open(archive, 'w:gz') as tar:
                for path in source.rglob('*'):
                    if path.is_file():
                        tar.add(path, arcname=path.relative_to(source))
            services = FakeServices()
            with self.assertRaises(recovery.RecoveryError):
                recovery.restore_archive(archive, expected_ip='192.0.2.1', confirm_target='192.0.2.1',
                    root=target, versions=versions, services=services, certificate_check=lambda *a: None,
                    post_restore=lambda *a: None, post_rollback=lambda *a: None)
            self.assertEqual(destination.read_text(), 'belongs to another project')
            self.assertEqual(services.calls, [])

    def test_candidate_stop_failure_does_not_swap_files_back_or_restart(self):
        with tempfile.TemporaryDirectory() as tmp:
            archive, target, versions, _ = self.prepared_restore(Path(tmp))
            class RefuseStop(FakeServices):
                def stop(self, snapshot):
                    if self.calls.count('stop'):
                        self.calls.append('failed-stop')
                        raise RuntimeError('synthetic stop failure')
                    super().stop(snapshot)
            services = RefuseStop()
            def health(*args):
                raise RuntimeError('synthetic health failure')
            with self.assertRaises(recovery.RecoveryError):
                recovery.restore_archive(archive, expected_ip='192.0.2.1', confirm_target='192.0.2.1',
                    root=target, versions=versions, services=services, certificate_check=lambda *a: None,
                    post_restore=health, post_rollback=lambda *a: None)
            # A still-running candidate must retain its matching candidate data.
            self.assertEqual((target / 'etc/sui-vps/instance-note').read_text(), 'backup value')
            self.assertEqual(services.calls, ['stop', 'restore', 'failed-stop'])
            journal = json.loads(next((target / 'var/backups/sui-vps/restore-transactions').glob('*.json')).read_text())
            self.assertEqual(journal['status'], 'rollback_failed')
            old = next(row for row in journal['paths'] if row['path'] == 'etc/sui-vps')['previous']
            self.assertEqual((target / old / 'instance-note').read_text(), 'current value')

    def test_partial_filesystem_swap_failure_rolls_back(self):
        with tempfile.TemporaryDirectory() as tmp:
            archive, target, versions, _ = self.prepared_restore(Path(tmp))
            replace = recovery.os.replace
            def fail(source, destination):
                if Path(source).name == 'new' and Path(destination).name == 'scripts':
                    raise OSError('synthetic filesystem failure')
                return replace(source, destination)
            services = FakeServices()
            with patch.object(recovery.os, 'replace', fail):
                report = recovery.restore_archive(archive, expected_ip='192.0.2.1', confirm_target='192.0.2.1',
                    root=target, versions=versions, services=services, certificate_check=lambda *a: None,
                    post_restore=lambda *a: None, post_rollback=lambda *a: None)
            self.assertTrue(report['rolled_back'])
            self.assertEqual((target / 'etc/sui-vps/instance-note').read_text(), 'current value')
            self.assertEqual(services.current, services.original)

    @unittest.skipUnless(shutil.which('openssl'), 'OpenSSL required')
    def test_restore_reopens_real_sqlite_and_validates_restored_certificate(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            archive, target, versions, _ = self.prepared_restore(root)
            source = root / 'source'
            cert, key = root / 'trust.pem', root / 'key.pem'
            subprocess.run(['openssl', 'req', '-x509', '-newkey', 'ec', '-pkeyopt',
                            'ec_paramgen_curve:P-256', '-nodes', '-days', '1',
                            '-subj', '/CN=synthetic-restored-test', '-addext',
                            'subjectAltName=IP:192.0.2.1', '-keyout', str(key), '-out', str(cert)],
                           capture_output=True, check=True)
            for directory in ('opt/sui-vps/deploy/state/cert', 'etc/sui-vps/acme/live/sui-vps'):
                (source / directory / 'fullchain.pem').write_bytes(cert.read_bytes())
                (source / directory / 'privkey.pem').write_bytes(key.read_bytes())
            with sqlite3.connect(source / 'opt/sui-vps/deploy/state/db/s-ui.db') as connection:
                connection.execute('INSERT INTO synthetic_test VALUES (42)')
            with tarfile.open(archive, 'w:gz') as tar:
                for path in source.rglob('*'):
                    if path.is_file():
                        tar.add(path, arcname=path.relative_to(source))
            def certificates(directory, ip):
                recovery.validate_certificates(directory, ip, ca_file=cert)
            def health(root, prior):
                certificates(root / 'opt/sui-vps/deploy/state/cert', '192.0.2.1')
                with sqlite3.connect(root / 'opt/sui-vps/deploy/state/db/s-ui.db') as connection:
                    self.assertEqual(connection.execute('SELECT id FROM synthetic_test').fetchall(), [(42,)])
            report = recovery.restore_archive(archive, expected_ip='192.0.2.1', confirm_target='192.0.2.1',
                root=target, versions=versions, services=FakeServices(), certificate_check=certificates,
                post_restore=health, post_rollback=lambda *a: None)
            self.assertTrue(report['restore_applied'])

    @unittest.skipUnless(shutil.which('openssl'), 'OpenSSL required for cryptographic certificate checks')
    def test_actual_certificate_pair_ip_and_trust_validation(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            cert, key = root / 'fullchain.pem', root / 'privkey.pem'
            subprocess.run(['openssl', 'req', '-x509', '-newkey', 'ec', '-pkeyopt',
                            'ec_paramgen_curve:P-256', '-nodes', '-days', '1',
                            '-subj', '/CN=synthetic-recovery-test', '-addext',
                            'subjectAltName=IP:192.0.2.1', '-keyout', str(key), '-out', str(cert)],
                           capture_output=True, check=True)
            recovery.validate_certificates(root, '192.0.2.1', ca_file=cert)
            with self.assertRaises(recovery.RecoveryError):
                recovery.validate_certificates(root, '192.0.2.2', ca_file=cert)
            with self.assertRaises(recovery.RecoveryError):
                recovery.validate_certificates(root, '192.0.2.1')
            key.write_text('invalid synthetic key')
            with self.assertRaises(recovery.RecoveryError):
                recovery.validate_certificates(root, '192.0.2.1', ca_file=cert)

    def test_archive_check_cleans_staging_and_never_modifies_original(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            source = root / 'original'
            versions = self.fixture(source)
            archive = root / 'backup.tar.gz'
            with tarfile.open(archive, 'w:gz') as tar:
                for path in source.rglob('*'):
                    if path.is_file():
                        tar.add(path, arcname=path.relative_to(source))
            before = archive.read_bytes()
            report = recovery.check_archive(archive, '192.0.2.1', versions, certificate_check=lambda *a: None)
            self.assertTrue(report['valid'])
            self.assertEqual(before, archive.read_bytes())
            self.assertEqual(sorted(p.name for p in root.iterdir()), ['backup.tar.gz', 'original'])


if __name__ == '__main__':
    unittest.main()
