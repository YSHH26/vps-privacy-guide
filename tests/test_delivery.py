"""Synthetic fixtures only: subscriptions and local private delivery."""
import base64
import contextlib
import copy
import io
import json
import os
from pathlib import Path
import sys
import tempfile
import threading
import unittest
from urllib.error import HTTPError
from urllib.request import urlopen

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'scripts'))
import subscription
from unittest.mock import patch
import delivery


def fixture():
    return {'server': {'host': '192.0.2.1', 'ssh_alias': 'test-host', 'timezone': 'UTC'},
            'public_base_url': 'https://192.0.2.1:9443',
            'subscriptions': {'surge': 'A' * 43, 'v2ray': 'B' * 43},
            'nodes': [
                {'type': 'anytls', 'name': 'AnyTLS', 'server': '192.0.2.1', 'port': 8443,
                 'password': 'test-password', 'server_name': '192.0.2.1'},
                {'type': 'vless-reality', 'name': 'Reality', 'server': '192.0.2.1', 'port': 443,
                 'uuid': '11111111-1111-4111-8111-111111111111', 'server_name': 'example.com',
                 'public_key': 'C' * 43, 'short_id': '12345678', 'flow': 'xtls-rprx-vision'},
                {'type': 'vless-tls', 'name': 'TLS', 'server': '192.0.2.1', 'port': 2443,
                 'uuid': '11111111-1111-4111-8111-111111111111', 'server_name': '192.0.2.1'}],
            'panel': {'url': 'https://192.0.2.1:9443/panel/', 'username': 'test', 'password': 'secret'},
            'cli_proxy': {}, 'verification': {}}


class SubscriptionTests(unittest.TestCase):
    def test_client_protocols_and_strict_tls(self):
        cfg = fixture()
        surge = subscription.surge_config(cfg)
        self.assertIn('= anytls, 192.0.2.1, 8443, password=test-password', surge)
        self.assertIn('skip-cert-verify=false', surge)
        self.assertNotIn('vless', surge.lower())
        self.assertIn('FINAL,PROXY', surge)
        self.assertTrue(surge.startswith('#!MANAGED-CONFIG https://192.0.2.1:9443/s/'))
        self.assertIn('interval=86400', surge)
        links = base64.b64decode(subscription.v2ray_subscription(cfg)).decode()
        self.assertEqual(links.count('vless://'), 2)
        self.assertIn('security=reality', links)
        self.assertIn('security=tls', links)
        self.assertNotIn('allowInsecure=1', links)
        self.assertNotIn('anytls://', links)

    def test_invalid_node_cannot_inject_surge_directive(self):
        cfg = fixture()
        cfg['nodes'][0]['password'] = 'pw\n[Rule]\nFINAL,DIRECT'
        with self.assertRaises(ValueError):
            subscription.surge_config(cfg)

    def test_rejects_insecure_settings(self):
        cfg = fixture()
        cfg['nodes'][0]['insecure'] = True
        with self.assertRaises(ValueError):
            subscription.surge_config(cfg)

    def test_http_auth_rotation_no_secret_logs(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / 'export.json'
            path.write_text(json.dumps(fixture()))
            server = subscription.make_server(path, port=0)
            thread = threading.Thread(target=server.serve_forever, daemon=True)
            thread.start()
            base = 'http://127.0.0.1:' + str(server.server_port)
            try:
                with contextlib.redirect_stderr(io.StringIO()) as logs:
                    response = urlopen(base + '/s/' + 'A' * 43 + '/surge.conf')
                    self.assertIn(b'anytls', response.read())
                    self.assertEqual(response.headers['Cache-Control'], 'no-store')
                    for suffix in ['/s/wrong/surge.conf', '/export.json', '/s/' + 'A' * 43 + '/v2ray.txt']:
                        with self.assertRaises(HTTPError) as error:
                            urlopen(base + suffix)
                        self.assertEqual(error.exception.code, 404)
                    cfg = fixture()
                    cfg['subscriptions']['surge'] = 'D' * 43
                    path.write_text(json.dumps(cfg))
                    with self.assertRaises(HTTPError):
                        urlopen(base + '/s/' + 'A' * 43 + '/surge.conf')
                self.assertEqual(logs.getvalue(), '')
            finally:
                server.shutdown()
                server.server_close()
                thread.join()

    def test_provider_uses_get_config_stdin_not_process_args(self):
        captured = {}
        def command(args, **kwargs):
            captured.update(args=args, **kwargs)
            return type('Reply', (), {'returncode': 0, 'stdout': b'{"error":0}'})()
        with patch.object(subscription.subprocess, 'run', command):
            result = subscription.provider_fetch('https://api.64clouds.com/v1/getServiceInfo', {'api_key': 'synthetic-secret'})
        self.assertEqual(result['error'], 0)
        self.assertNotIn('synthetic-secret', ' '.join(captured['args']))
        self.assertIn('synthetic-secret', captured['input'].decode())
        self.assertIn('GET', captured['input'].decode())

    def test_traffic_rejects_wrong_ip_target(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            creds = root / 'kiwivm.json'
            creds.write_text(json.dumps({'veid': '123', 'api_key': 'synthetic', 'ip': '192.0.2.1'}))
            def fetch(*args):
                return {'error': 0, 'plan_monthly_data': 2000, 'data_counter': 10,
                        'data_next_reset': 1800000000, 'ip_addresses': ['192.0.2.2']}
            result = subscription.traffic_snapshot(creds, root / 'cache.json', fetch=fetch)
            self.assertEqual(result['status'], 'unavailable')
            self.assertNotIn('total_bytes', result)

    def test_nondefault_provider_multiplier_is_explicitly_unsupported(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            creds = root / 'kiwivm.json'
            creds.write_text(json.dumps({'veid': '123', 'api_key': 'synthetic'}))
            def fetch(*args):
                return {'error': 0, 'plan_monthly_data': 2000, 'data_counter': 10,
                        'data_next_reset': 1800000000, 'monthly_data_multiplier': 2}
            result = subscription.traffic_snapshot(creds, root / 'cache.json', fetch=fetch)
            self.assertEqual(result['status'], 'unsupported_multiplier')
            self.assertNotIn('total_bytes', result)

    def test_no_provider_flag_uses_only_embedded_snapshot(self):
        captured = {}
        class Server:
            def serve_forever(self):
                raise KeyboardInterrupt()
            def server_close(self):
                pass
        def server(*args, **kwargs):
            captured.update(kwargs)
            return Server()
        with patch.object(sys, 'argv', ['subscription.py', '--export', '/synthetic/sanitized.json', '--no-provider']):
            with patch.object(subscription, 'make_server', server):
                subscription.main()
        self.assertIsNone(captured['traffic_credentials'])
        self.assertIsNone(captured['traffic_cache'])

    def test_cannot_bind_public_interface(self):
        with self.assertRaises(ValueError):
            subscription.make_server(Path('/unused'), host='0.0.0.0')

    def test_official_traffic_failure_preserves_stale_truth(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            credentials = root / 'kiwivm.json'
            credentials.write_text(json.dumps({'veid': '123', 'api_key': 'synthetic'}))
            cache = root / 'traffic.json'
            calls = []
            def fetch(url, data):
                calls.append((url, data))
                return {'error': 0, 'plan_monthly_data': 200000, 'data_counter': 12345,
                        'data_next_reset': 1800000000}
            first = subscription.traffic_snapshot(credentials, cache, fetch=fetch, now=1000)
            self.assertEqual(first['total_bytes'], 200000)
            self.assertEqual(first['used_bytes'], 12345)
            self.assertEqual(first['status'], 'ok')
            self.assertEqual(subscription.traffic_snapshot(credentials, cache, fetch=fetch, now=1100), first)
            self.assertEqual(len(calls), 1)
            def fail(*args):
                raise OSError('provider unavailable')
            stale = subscription.traffic_snapshot(credentials, cache, fetch=fail, now=2000)
            self.assertEqual(stale['status'], 'stale')
            self.assertEqual(stale['total_bytes'], 200000)
            cache.unlink()
            missing = subscription.traffic_snapshot(credentials, cache, fetch=fail, now=2000)
            self.assertEqual(missing['status'], 'unavailable')
            self.assertNotIn('total_bytes', missing)


class DeliveryTests(unittest.TestCase):
    def test_private_offline_escaped_and_unverified(self):
        cfg = fixture()
        cfg['server']['ssh_alias'] = '</script><img src=x onerror=alert(1)>'
        html = delivery.render_html(cfg, qr_renderer=lambda url: '<svg data-test="local-qr"></svg>')
        self.assertNotIn('</script><img', html)
        self.assertIn('&lt;/script&gt;', html)
        self.assertIn('type="password"', html)
        self.assertIn('未测试', html)
        self.assertIn('execCommand', html)
        self.assertNotIn('<script src=', html)
        self.assertNotIn('<link ', html)
        self.assertNotIn('fetch(', html)
        self.assertEqual(html.count('data-test="local-qr"'), 5)
        with tempfile.TemporaryDirectory() as tmp:
            target = Path(tmp) / 'private' / 'delivery.html'
            delivery.write_private(target, html)
            self.assertEqual(target.stat().st_mode & 0o777, 0o600)
            self.assertEqual(target.parent.stat().st_mode & 0o777, 0o700)

    def test_rejects_newline_in_subscription_origin(self):
        cfg = fixture()
        cfg['public_base_url'] = 'https://example.com\n'
        with self.assertRaises(ValueError):
            delivery.render_html(cfg, qr_renderer=lambda url: '<svg/>')

    def test_rejects_plaintext_subscription(self):
        cfg = fixture()
        cfg['public_base_url'] = 'http://192.0.2.1'
        with self.assertRaises(ValueError):
            delivery.render_html(cfg, qr_renderer=lambda url: '<svg/>')


if __name__ == '__main__':
    unittest.main()
