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
            'subscriptions': {'surge': 'A' * 43, 'v2ray': 'B' * 43, 'clash': 'E' * 43, 'shadowrocket': 'F' * 43},
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
        rules = surge.split('[Rule]\n', 1)[1].strip().splitlines()
        self.assertEqual(rules[0], 'IP-CIDR,192.0.2.1/32,DIRECT,no-resolve')
        self.assertIn('IP-CIDR,192.168.0.0/16,DIRECT,no-resolve', rules)
        self.assertIn('IP-CIDR6,fc00::/7,DIRECT,no-resolve', rules)
        self.assertIn('DOMAIN-SUFFIX,chatgpt.com,AI', rules)
        self.assertIn('DOMAIN-SUFFIX,claude.ai,AI', rules)
        # AI rules must win over China rules, and FINAL must be last.
        self.assertLess(rules.index('DOMAIN-SUFFIX,claude.ai,AI'), rules.index('GEOIP,CN,DIRECT'))
        self.assertIn('IP-ASN,132203,DIRECT,no-resolve', rules)
        self.assertEqual(rules[-1], 'FINAL,PROXY,dns-failed')
        self.assertIn('\nAI = select, PROXY, AnyTLS-1\n', surge)
        self.assertTrue(surge.startswith('#!MANAGED-CONFIG https://192.0.2.1:9443/s/'))
        self.assertIn('interval=86400', surge)
        links = base64.b64decode(subscription.v2ray_subscription(cfg)).decode()
        self.assertEqual(links.count('vless://'), 2)
        self.assertIn('security=reality', links)
        self.assertIn('security=tls', links)
        self.assertNotIn('allowInsecure=1', links)
        self.assertNotIn('anytls://', links)

    def clash(self, cfg=None):
        text = subscription.clash_config(cfg or fixture())
        self.assertTrue(text.startswith('# Managed by sui-vps.'))
        return json.loads(''.join(line for line in text.splitlines(True) if not line.startswith('#')))

    def test_clash_profile_nodes_rules_and_dns(self):
        profile = self.clash()
        proxies = {p['type'] + ('-reality' if 'reality-opts' in p else ''): p for p in profile['proxies']}
        self.assertEqual({'anytls', 'vless', 'vless-reality'}, set(proxies))
        for proxy in profile['proxies']:
            self.assertIs(proxy['skip-cert-verify'], False)
        self.assertEqual({'public-key': 'C' * 43, 'short-id': '12345678'}, proxies['vless-reality']['reality-opts'])
        self.assertEqual('xtls-rprx-vision', proxies['vless-reality']['flow'])
        self.assertEqual('192.0.2.1', proxies['vless']['servername'])
        self.assertEqual('192.0.2.1', proxies['anytls']['sni'])
        groups = {g['name']: g for g in profile['proxy-groups']}
        self.assertEqual(['Reality', 'TLS', 'AnyTLS'], groups['AUTO']['proxies'])
        self.assertEqual('fallback', groups['AUTO']['type'])
        rules = profile['rules']
        self.assertEqual('MATCH,PROXY', rules[-1])
        self.assertLess(rules.index('GEOSITE,category-ai-!cn,AI'), rules.index('GEOSITE,cn,DIRECT'))
        self.assertLess(rules.index('GEOSITE,google-play@cn,DIRECT'), rules.index('GEOSITE,cn,DIRECT'))
        self.assertEqual('IP-ASN,132203,DIRECT,no-resolve', rules[-2])
        self.assertTrue(profile['geox-url']['asn'].endswith('/geo/GeoLite2-ASN.mmdb'))
        for rule in rules:
            if rule.startswith(('IP-CIDR', 'GEOIP', 'IP-ASN')):
                self.assertTrue(rule.endswith(',no-resolve'), rule)
        self.assertEqual('fake-ip', profile['dns']['enhanced-mode'])
        self.assertIs(profile['dns']['respect-rules'], True)
        self.assertIs(profile['dns']['ipv6'], False)
        self.assertIs(profile['ipv6'], True)
        self.assertEqual('https://192.0.2.1:9443/s/' + 'E' * 43 + '/geo/geosite.dat', profile['geox-url']['geosite'])

    def test_clash_rejects_injection_and_shared_tokens(self):
        cfg = fixture()
        cfg['nodes'][0]['name'] = 'x,DIRECT'
        with self.assertRaises(ValueError):
            subscription.clash_config(cfg)
        cfg = fixture()
        cfg['subscriptions']['clash'] = cfg['subscriptions']['surge']
        with self.assertRaises(ValueError):
            subscription.clash_config(cfg)

    def test_local_traffic_accumulates_across_reboot_and_period(self):
        old = os.environ.get('TZ')
        os.environ['TZ'] = 'UTC'
        __import__('time').tzset()
        try:
            with tempfile.TemporaryDirectory() as tmp:
                state = Path(tmp) / 'traffic-local.json'
                target = {'traffic_quota_gb': 1000, 'traffic_reset_day': 5, 'traffic_count': 'both'}
                day = 1_700_000_000  # 2023-11-14 UTC
                first = subscription.local_traffic_snapshot(state, (100, 50), target, now=day)
                self.assertEqual(0, first['used_bytes'])
                self.assertEqual(1000 * 1024 ** 3, first['total_bytes'])
                self.assertEqual(1701734400, first['reset_at'])  # 2023-12-05 00:00 UTC
                self.assertEqual(200, subscription.local_traffic_snapshot(state, (200, 150), target, now=day + 60)['used_bytes'])
                rebooted = subscription.local_traffic_snapshot(state, (10, 5), target, now=day + 120)
                self.assertEqual(215, rebooted['used_bytes'])
                for mode, expected in [('out', 105), ('in', 110), ('max', 110)]:
                    snap = subscription.local_traffic_snapshot(state, (10, 5), {**target, 'traffic_count': mode}, now=day + 130)
                    self.assertEqual(expected, snap['used_bytes'])
                calibrated = subscription.local_traffic_snapshot(state, (10, 5), target, now=day + 140, calibrate_gb=2)
                self.assertEqual(2 * 1024 ** 3, calibrated['used_bytes'])
                self.assertEqual(2 * 1024 ** 3 + 30, subscription.local_traffic_snapshot(state, (30, 15), target, now=day + 150)['used_bytes'])
                after_reset = subscription.local_traffic_snapshot(state, (40, 20), target, now=1701734400 + 10)
                self.assertEqual(15, after_reset['used_bytes'])
                with self.assertRaises(ValueError):
                    subscription.local_traffic_snapshot(state, (1, 1), {'traffic_reset_day': 31})
        finally:
            if old is None:
                os.environ.pop('TZ', None)
            else:
                os.environ['TZ'] = old
            __import__('time').tzset()

    def test_shadowrocket_has_vless_and_anytls_with_verification(self):
        links = base64.b64decode(subscription.shadowrocket_subscription(fixture())).decode().split()
        self.assertEqual(['anytls', 'vless', 'vless'], sorted(x.split('://')[0] for x in links))
        anytls = next(x for x in links if x.startswith('anytls://'))
        self.assertTrue(anytls.startswith('anytls://test-password@192.0.2.1:8443?'))
        self.assertIn('insecure=0', anytls)
        self.assertIn('sni=192.0.2.1', anytls)
        self.assertNotIn('allowInsecure=1', '\n'.join(links))
        cfg = fixture()
        cfg['subscriptions']['shadowrocket'] = cfg['subscriptions']['v2ray']
        with self.assertRaises(ValueError):
            subscription.subscription_urls(cfg)

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
                    with urlopen(base + '/s/' + 'A' * 43 + '/surge.conf') as response:
                        self.assertIn(b'anytls', response.read())
                        self.assertEqual(response.headers['Cache-Control'], 'no-store')
                    for suffix in ['/s/wrong/surge.conf', '/export.json', '/s/' + 'A' * 43 + '/v2ray.txt']:
                        with self.assertRaises(HTTPError) as error:
                            urlopen(base + suffix)
                        with error.exception as response:
                            self.assertEqual(response.code, 404)
                    cfg = fixture()
                    cfg['subscriptions']['surge'] = 'D' * 43
                    path.write_text(json.dumps(cfg))
                    with self.assertRaises(HTTPError) as error:
                        urlopen(base + '/s/' + 'A' * 43 + '/surge.conf')
                    with error.exception as response:
                        self.assertEqual(response.code, 404)
                self.assertEqual(logs.getvalue(), '')
            finally:
                server.shutdown()
                server.server_close()
                thread.join()

    def test_http_serves_clash_profile_and_token_bound_rule_data(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / 'export.json'
            path.write_text(json.dumps(fixture()))
            rules = Path(tmp) / 'rules'
            rules.mkdir()
            (rules / 'geosite.dat').write_bytes(b'geosite-bytes')
            server = subscription.make_server(path, port=0, rules_dir=rules)
            thread = threading.Thread(target=server.serve_forever, daemon=True)
            thread.start()
            base = 'http://127.0.0.1:' + str(server.server_port) + '/s/'
            try:
                with urlopen(base + 'E' * 43 + '/clash.yaml') as response:
                    self.assertIn(b'"proxy-groups"', response.read())
                    self.assertEqual('24', response.headers['Profile-Update-Interval'])
                with urlopen(base + 'E' * 43 + '/geo/geosite.dat') as response:
                    self.assertEqual(b'geosite-bytes', response.read())
                with urlopen(base + 'F' * 43 + '/shadowrocket.txt') as response:
                    self.assertIn(b'dmxlc3M6Ly', response.read())
                for suffix, code in [('A' * 43 + '/geo/geosite.dat', 404), ('E' * 43 + '/geo/other.dat', 404),
                                     ('A' * 43 + '/clash.yaml', 404), ('E' * 43 + '/geo/geoip.metadb', 503),
                                     ('F' * 43 + '/geo/geosite.dat', 404), ('E' * 43 + '/shadowrocket.txt', 404)]:
                    with self.assertRaises(HTTPError) as error:
                        urlopen(base + suffix)
                    with error.exception as response:
                        self.assertEqual(code, response.code, suffix)
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
        self.assertEqual(html.count('data-test="local-qr"'), 7)
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


@unittest.skipUnless(os.environ.get('VALIDATE_CORE') == '1', 'Set VALIDATE_CORE=1 with Docker to parse the Clash profile using pinned mihomo')
class ClashCoreTests(unittest.TestCase):
    def test_pinned_mihomo_accepts_generated_profile(self):
        import hashlib
        import subprocess
        versions = json.loads((Path(__file__).resolve().parents[1] / 'versions.json').read_text())
        image, source = versions['mihomo_image'], versions['rule_data']
        self.assertIn('@sha256:', image)
        with tempfile.TemporaryDirectory() as tmp:
            directory = Path(tmp)
            for name in source['files']:
                with urlopen(source['base_url'] + name, timeout=60) as response:
                    data = response.read()
                with urlopen(source['base_url'] + name + '.sha256sum', timeout=60) as response:
                    self.assertEqual(response.read().decode().split()[0], hashlib.sha256(data).hexdigest())
                # Mihomo's local file name for the ASN database differs from the published asset.
                (directory / ('ASN.mmdb' if name == 'GeoLite2-ASN.mmdb' else name)).write_bytes(data)
            (directory / 'config.yaml').write_text(subscription.clash_config(fixture()))
            directory.chmod(0o755)
            result = subprocess.run(['docker', 'run', '--rm', '--network', 'none', '-v', f'{directory}:/root/.config/mihomo:ro',
                                     image, '-t', '-d', '/root/.config/mihomo', '-f', '/root/.config/mihomo/config.yaml'],
                                    capture_output=True, text=True, timeout=180)
            self.assertEqual(0, result.returncode, result.stdout[-2000:] + result.stderr[-2000:])
            self.assertIn('test is successful', result.stdout + result.stderr)
