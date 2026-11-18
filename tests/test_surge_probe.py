import copy
import json
import os
import shutil
import subprocess
from pathlib import Path
import sys
import tempfile
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'scripts'))
sys.path.insert(0, str(Path(__file__).resolve().parent))
import surge_probe
from test_delivery import fixture


METADATA = {'name': 'Surge Mac', 'version': '6.5.0', 'build': '10960',
            'bundle_identifier': 'com.nssurge.surge-mac'}


def results(wrong='auth_rejected'):
    return [{'phase': 'valid', 'status': 200, 'exit_matches': True, 'error_category': None, 'response_received': True},
            {'phase': 'wrong', 'status': None, 'exit_matches': False, 'error_category': wrong, 'response_received': False},
            {'phase': 'restored', 'status': 200, 'exit_matches': True, 'error_category': None, 'response_received': True}]


class NativeSurgeTests(unittest.TestCase):
    def test_strict_three_phase_results(self):
        self.assertEqual(surge_probe.assess(results()), 'passed')
        for reason in ('timeout', 'transport_error', 'unsupported'):
            self.assertEqual(surge_probe.assess(results(reason)), 'inconclusive')
        wrong_succeeds = results()
        wrong_succeeds[1].update(status=200, exit_matches=True, response_received=True, error_category=None)
        self.assertEqual(surge_probe.assess(wrong_succeeds), 'failed')
        error_after_response = results()
        error_after_response[1]['response_received'] = True
        self.assertEqual(surge_probe.assess(error_after_response), 'inconclusive')
        broken_restored = results()
        broken_restored[2]['exit_matches'] = False
        self.assertEqual(surge_probe.assess(broken_restored), 'failed')
        self.assertEqual(surge_probe.assess(results()[:2]), 'inconclusive')

    @unittest.skipUnless(os.environ.get('RUN_SURGE_INTEGRATION') == '1',
                         'Set RUN_SURGE_INTEGRATION=1 for no-network native Surge JS checks')
    def test_generated_js_classifies_auth_failures_and_timeouts_without_network(self):
        script = surge_probe.native_script(fixture()['nodes'][0], 'https://api.ipify.org', '192.0.2.1')
        function = script[script.index('function category('):script.index('function step(')]
        samples = ['AnyTLS authentication failed', 'invalid password', 'authentication timeout',
                   'connection reset by peer', 'unknown protocol', 'Read stream EOF']
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / 'classifier.js'
            path.write_text(function + '\nconsole.log(JSON.stringify({marker:' + json.dumps(surge_probe.MARKER) +
                            ',categories:' + json.dumps(samples) + '.map(category)}));$done();')
            path.chmod(0o600)
            output = surge_probe.run_cli([surge_probe.CLI, '--raw', 'script', 'evaluate', path, 'cron', '30'])
        self.assertEqual(surge_probe.script_record(output)['categories'],
                         ['auth_rejected', 'auth_rejected', 'timeout', 'transport_error', 'unsupported', 'transport_error'])

    @unittest.skipUnless(os.environ.get('RUN_SURGE_INTEGRATION') == '1',
                         'Set RUN_SURGE_INTEGRATION=1 for no-network native Surge JS checks')
    def test_full_generated_js_uses_three_isolated_phases_with_offline_mock(self):
        # Run generated JS in the real native engine, replacing its one HTTP
        # call target with an in-memory fixture. This test never opens a socket.
        script = surge_probe.native_script(fixture()['nodes'][0], 'https://api.ipify.org', '192.0.2.1')
        script = script.replace('$httpClient.get', 'offlineFixture.get')
        fake = """const offlineFixture = {index: 0, get(options, callback) {
          if (this.index++ === 1) callback('AnyTLS authentication failed', null, null);
          else callback(null, {status: 200}, '192.0.2.1');
        }};\n"""
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / 'offline-control-flow.js'
            path.write_text(fake + script); path.chmod(0o600)
            output = surge_probe.run_cli([surge_probe.CLI, '--raw', 'script', 'evaluate', path, 'cron', '30'])
        record = surge_probe.script_record(output)
        self.assertEqual(surge_probe.assess(record['results']), 'passed')

    def test_temporary_policy_descriptor_contains_the_full_named_proxy_line(self):
        script = surge_probe.native_script(fixture()['nodes'][0], 'https://api.ipify.org', '192.0.2.1')
        policies = json.loads(script.split('const policies=', 1)[1].split(';\n', 1)[0])
        self.assertEqual(len(policies), 3)
        for policy in policies:
            self.assertTrue(policy.startswith('NativeDiagnostic = anytls, '))
        self.assertEqual(policies[0], policies[2])
        self.assertNotEqual(policies[0], policies[1])

    def test_actual_envelope_parser_does_not_accept_missing_or_duplicate_marker(self):
        record = {'marker': surge_probe.MARKER, 'results': results()}
        output = '20:32:38.469016 ' + json.dumps(record) + '\n20:32:38 [Script Completed]\n'
        self.assertEqual(surge_probe.script_record(json.dumps({'result': None, 'output': output}).encode())['results'], results())
        for body in (b'{"error":"engine unavailable"}', b'{"output":""}', json.dumps({'output': output + output}).encode()):
            with self.assertRaises(surge_probe.SurgeProbeError):
                surge_probe.script_record(body)

    def test_private_script_credential_safe_argv_and_fingerprint_bound_report(self):
        cfg = fixture()
        calls = []
        def runner(args, **kwargs):
            calls.append(args)
            if '--help' in args:
                output = b'script evaluate <script-js-path>\n--check/-c <path>'
            elif '-c' in args:
                output = b'OK'
            else:
                path = Path(args[args.index('evaluate') + 1])
                self.assertEqual(path.stat().st_mode & 0o777, 0o600)
                script = path.read_text()
                self.assertIn('policy-descriptor', script)
                self.assertIn('reuse=false', script)
                self.assertIn('skip-cert-verify=false', script)
                self.assertNotIn('test-password', ' '.join(args))
                self.assertNotIn('switch-profile', ' '.join(args))
                output = json.dumps({'result': None, 'output': '12:34:56 ' + json.dumps({'marker': surge_probe.MARKER, 'results': results()})}).encode()
            return type('Reply', (), {'returncode': 0, 'stdout': output, 'stderr': b''})()
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            source = root / 'export.json'
            source.write_text(json.dumps(cfg)); source.chmod(0o600)
            output = root / 'result.json'
            report = surge_probe.probe_export(source, output, runner=runner,
                metadata_reader=lambda cli: METADATA)
            self.assertEqual(report['result'], 'passed')
            self.assertEqual(report['client']['version'], '6.5.0')
            self.assertEqual(report['protocol'], 'anytls')
            self.assertEqual(report['leak_protection'], '未测试')
            self.assertEqual(output.stat().st_mode & 0o777, 0o600)
            self.assertNotIn('test-password', output.read_text())
            before = report['export_fingerprint']
            cfg['nodes'][0]['port'] = 9445
            self.assertNotEqual(before, surge_probe.fingerprint(cfg))
            for arguments in calls:
                if 'evaluate' in arguments:
                    self.assertFalse(Path(arguments[arguments.index('evaluate') + 1]).exists())
        self.assertEqual(len(calls), 3)

    def test_insecure_or_nonprivate_input_is_rejected_before_cli(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            source = root / 'export.json'
            cfg = fixture()
            source.write_text(json.dumps(cfg)); source.chmod(0o644)
            with self.assertRaises(surge_probe.SurgeProbeError):
                surge_probe.probe_export(source, root / 'output.json', runner=lambda *a, **k: self.fail('CLI must not run'))
            source.chmod(0o600)
            cfg['nodes'][0]['insecure'] = True
            source.write_text(json.dumps(cfg))
            with self.assertRaises(surge_probe.SurgeProbeError):
                surge_probe.probe_export(source, root / 'output.json', runner=lambda *a, **k: self.fail('CLI must not run'))

    def test_engine_startup_failure_is_reported_not_auth_rejection(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            source = root / 'export.json'
            source.write_text(json.dumps(fixture())); source.chmod(0o600)
            def runner(args, **kwargs):
                if '--help' in args:
                    reply = b'script evaluate <script-js-path>\n--check/-c <path>'
                elif '-c' in args:
                    reply = b'OK'
                else:
                    reply = b'{"error":"engine unavailable"}'
                return type('Reply', (), {'returncode': 0, 'stdout': reply, 'stderr': b''})()
            report = surge_probe.probe_export(source, root / 'result.json', runner=runner, metadata_reader=lambda cli: METADATA)
            self.assertEqual(report['result'], 'startup_failed')
            self.assertNotIn('checks', report)


if __name__ == '__main__':
    unittest.main()
