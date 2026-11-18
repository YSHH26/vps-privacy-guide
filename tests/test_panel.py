import copy
import importlib.util
import json
import os
import threading
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path
import tempfile
import subprocess
import time
import uuid
import unittest

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location('panel', ROOT / 'scripts/panel.py')
panel = importlib.util.module_from_spec(spec)
spec.loader.exec_module(panel)


class FakeAPI:
    """S-UI v1.6.6 public API shapes, not database fixtures."""
    def __init__(self):
        self.credentials = ('admin', 'admin')
        self.objects = {'tls': [], 'inbounds': [], 'clients': [], 'outbounds': []}
        self.settings = {}
        self.config = {'dns': {'servers': []}, 'route': {'rules': []}}
        self.writes = 0

    def call(self, action, form=None, raw=False):
        if action == 'login':
            if (form['user'], form['pass']) != self.credentials:
                raise panel.PanelError('S-UI login rejected')
            return None
        if action == 'changePass':
            self.credentials = (form['newUsername'], form['newPass'])
            return None
        if action == 'keypairs?k=reality':
            return ['PrivateKey: ' + 'A'*43, 'PublicKey: ' + 'B'*43]
        if action == 'save':
            self.writes += 1
            obj, data = form['object'], json.loads(form['data'])
            if obj == 'config':
                self.config = data
                return {'config': self.config}
            if obj == 'settings':
                self.settings.update(data)
                return {'settings': self.settings}
            if form['action'] == 'new':
                if obj == 'clients' and 'links' not in data:
                    raise panel.PanelError('Missing links array required by S-UI')
                data['id'] = len(self.objects[obj]) + 1
                self.objects[obj].append(data)
            else:
                self.objects[obj] = [data if x['id'] == data['id'] else x for x in self.objects[obj]]
            return copy.deepcopy(self.objects)
        if action == 'config':
            return {'config': copy.deepcopy(self.config)}
        if action == 'settings':
            return copy.deepcopy(self.settings)
        if action == 'status?r=sbd':
            return {'sbd': {'running': True}}
        if action == 'singbox-config':
            tls = {x['id']: x for x in self.objects['tls']}
            result = []
            for x in self.objects['inbounds']:
                item = {k: v for k, v in x.items() if k not in ('id', 'tls_id', 'addrs', 'out_json')}
                item['tls'] = copy.deepcopy(tls[x['tls_id']]['server'])
                item['users'] = [copy.deepcopy(c['config'][x['type']]) for c in self.objects['clients'] if x['id'] in c['inbounds']]
                result.append(item)
            return {'inbounds': result, 'route': copy.deepcopy(self.config.get('route', {}))}
        if action.startswith('clients?id='):
            return {'clients': copy.deepcopy([x for x in self.objects['clients'] if x['id'] == int(action.split('=')[1])])}
        if action.startswith('inbounds?id='):
            return {'inbounds': copy.deepcopy([x for x in self.objects['inbounds'] if x['id'] == int(action.split('=')[1])])}
        if action in self.objects:
            data = copy.deepcopy(self.objects[action])
            # List endpoint intentionally omits credentials/options upstream.
            if action == 'clients':
                for row in data:
                    row.pop('config', None)
            return {action: data}
        raise AssertionError(action)


class PanelTests(unittest.TestCase):
    def test_configure_is_idempotent_and_exports_only_readback(self):
        with tempfile.TemporaryDirectory() as tmp:
            state = Path(tmp) / 'state.json'
            state.write_text(json.dumps({'ip': '192.0.2.10', 'ssh_alias': '__SSH_ALIAS__', 'public_base_url': 'https://192.0.2.10:9443'}))
            api = FakeAPI()
            panel.configure(state, api=api)
            first = json.loads(state.read_text())
            writes = api.writes
            panel.configure(state, api=api)
            self.assertEqual(writes, api.writes)
            self.assertEqual(first['client'], json.loads(state.read_text())['client'])
            self.assertEqual(0o600, state.stat().st_mode & 0o777)
            output = Path(tmp) / 'export.json'
            self.assertEqual(0o600, output.stat().st_mode & 0o777)
            exported = json.loads(output.read_text())
            self.assertEqual([443, 2443, 8443], [n['port'] for n in exported['nodes']])
            self.assertNotIn('private_key', json.dumps(exported))
            self.assertEqual('https://192.0.2.10:9443/app/', exported['panel']['url'])
            for node in exported['nodes']:
                self.assertNotIn('insecure', node)

    def test_reality_falls_back_to_own_https_and_legacy_target_is_kept(self):
        with tempfile.TemporaryDirectory() as tmp:
            state = Path(tmp) / 'state.json'
            state.write_text(json.dumps({'ip': '192.0.2.10'}))
            api = FakeAPI()
            panel.configure(state, api=api)
            tls = next(x for x in api.objects['tls'] if x['name'] == 'sui-vps-reality')
            self.assertNotIn('server_name', tls['server'])
            self.assertEqual({'server': '192.0.2.10', 'server_port': 9443}, tls['server']['reality']['handshake'])
            self.assertEqual('192.0.2.10', tls['client']['server_name'])
            node = json.loads((Path(tmp) / 'export.json').read_text())['nodes'][0]
            self.assertEqual(('192.0.2.10', 'self'), (node['server_name'], node['reality_target']))
            self.assertEqual('self', json.loads(state.read_text())['reality']['target'])
        with tempfile.TemporaryDirectory() as tmp:
            state = Path(tmp) / 'state.json'
            state.write_text(json.dumps({'ip': '192.0.2.10', 'reality': {'private_key': 'p' * 43, 'public_key': 'P' * 43,
                                                                         'short_id': '0123456789abcdef', 'server_name': 'www.example.com'}}))
            api = FakeAPI()
            panel.configure(state, api=api)
            tls = next(x for x in api.objects['tls'] if x['name'] == 'sui-vps-reality')
            self.assertEqual({'server': 'www.example.com', 'server_port': 443}, tls['server']['reality']['handshake'])
            self.assertEqual('www.example.com', json.loads((Path(tmp) / 'export.json').read_text())['nodes'][0]['server_name'])

    def test_ipv4_only_egress_is_idempotent_and_keeps_operator_resolver(self):
        fresh = panel.apply_ipv4_only({})
        self.assertEqual({'server': 'sui-vps-resolver', 'strategy': 'ipv4_only'}, fresh['route']['default_domain_resolver'])
        self.assertEqual([panel.IPV6_REJECT], fresh['route']['rules'])
        again = panel.apply_ipv4_only(json.loads(json.dumps(fresh)))
        self.assertEqual(fresh, again)
        legacy = panel.apply_ipv4_only({'dns': {'servers': [{'tag': 'sui-vps-resolver'}]},
                                        'route': {'default_domain_resolver': 'sui-vps-resolver', 'rules': [{'x': 1}]}})
        self.assertEqual('ipv4_only', legacy['route']['default_domain_resolver']['strategy'])
        self.assertEqual([panel.IPV6_REJECT, {'x': 1}], legacy['route']['rules'])
        operator = panel.apply_ipv4_only({'dns': {'servers': [{'tag': 'mine'}]}, 'route': {'default_domain_resolver': 'mine'}})
        self.assertEqual('mine', operator['route']['default_domain_resolver'])
        with self.assertRaises(panel.PanelError):
            panel.check_ipv4_only({'route': operator['route']})
        panel.check_ipv4_only({'route': fresh['route']})

    def test_refuses_core_without_ipv4_only_readback(self):
        class NoRoute(FakeAPI):
            def call(self, action, form=None, raw=False):
                result = super().call(action, form, raw)
                if action == 'singbox-config':
                    result['route'] = {}
                return result
        with tempfile.TemporaryDirectory() as tmp:
            state = Path(tmp) / 'state.json'
            state.write_text('{"ip":"192.0.2.10"}')
            with self.assertRaisesRegex(panel.PanelError, 'IPv4'):
                panel.configure(state, api=NoRoute())

    def test_refuses_inconsistent_core_readback(self):
        class BadAPI(FakeAPI):
            def call(self, action, form=None, raw=False):
                result = super().call(action, form, raw)
                if action == 'singbox-config':
                    result['inbounds'][0]['users'] = []
                return result
        with tempfile.TemporaryDirectory() as tmp:
            state = Path(tmp) / 'state.json'
            state.write_text('{"ip":"192.0.2.10"}')
            with self.assertRaises(panel.PanelError):
                panel.configure(state, api=BadAPI())
            self.assertFalse((Path(tmp)/'export.json').exists())

    def test_http_api_uses_upstream_cookie_form_and_rejects_error_body(self):
        seen = []
        class Handler(BaseHTTPRequestHandler):
            def log_message(self, *args):
                pass
            def do_POST(self):
                body = self.rfile.read(int(self.headers['Content-Length'])).decode()
                seen.append((self.path, body, self.headers.get('X-Requested-With')))
                self.send_response(200)
                self.send_header('Set-Cookie', 's-ui=test-session; Path=/')
                self.end_headers()
                self.wfile.write(b'{"success":true,"obj":null}')
            def do_GET(self):
                seen.append((self.path, self.headers.get('Cookie')))
                self.send_response(200)
                self.end_headers()
                if self.path.endswith('settings'):
                    self.wfile.write(b'{"success":true,"obj":{"timeLocation":"UTC"}}')
                else:
                    self.wfile.write(b'{"success":false,"msg":"secret-must-not-echo"}')
        server = HTTPServer(('127.0.0.1', 0), Handler)
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        try:
            api = panel.PanelAPI('http://127.0.0.1:%d/app/' % server.server_port)
            api.call('login', {'user': 'test', 'pass': 'test-password'})
            self.assertEqual({'timeLocation': 'UTC'}, api.call('settings'))
            with self.assertRaises(panel.PanelError) as caught:
                api.call('inbounds')
            self.assertNotIn('secret-must-not-echo', str(caught.exception))
            self.assertEqual(('/app/api/login', 'user=test&pass=test-password', 'XMLHttpRequest'), seen[0])
            self.assertEqual(('/app/api/settings', 's-ui=test-session'), seen[1])
        finally:
            server.shutdown()
            server.server_close()
            thread.join()

    def test_refuses_remote_api_and_symlink_state(self):
        with self.assertRaises(panel.PanelError):
            panel.PanelAPI('http://192.0.2.10:2095/app/')
        with tempfile.TemporaryDirectory() as tmp:
            target = Path(tmp)/'target'
            target.write_text('{}')
            link = Path(tmp)/'state.json'
            link.symlink_to(target)
            with self.assertRaises(panel.PanelError):
                panel.configure(link, api=FakeAPI())
            self.assertEqual('{}', target.read_text())


@unittest.skipUnless(os.environ.get('RUN_PANEL_INTEGRATION') == '1',
                     'Set RUN_PANEL_INTEGRATION=1 for digest-pinned local Docker API test')
class PanelRuntimeTests(unittest.TestCase):
    def test_real_api_persistence_credentials_and_idempotence(self):
        image = json.loads((ROOT / 'versions.json').read_text())['s_ui_image']
        name = 'sui-api-test-' + uuid.uuid4().hex[:10]
        def run(*args):
            return subprocess.run(args, check=True, stdout=subprocess.PIPE,
                                  stderr=subprocess.PIPE, text=True).stdout.strip()
        with tempfile.TemporaryDirectory(prefix='sui-api-test-') as tmp:
            directory = Path(tmp)
            cert = directory / 'cert'
            cert.mkdir()
            # A local CA signs this TEST leaf. Never used as deployment trust.
            run('openssl', 'req', '-x509', '-newkey', 'rsa:2048', '-nodes',
                '-keyout', str(directory/'ca.key'), '-out', str(directory/'ca.pem'),
                '-days', '1', '-subj', '/CN=S-UI local test CA')
            run('openssl', 'req', '-newkey', 'rsa:2048', '-nodes',
                '-keyout', str(cert/'privkey.pem'), '-out', str(directory/'leaf.csr'),
                '-subj', '/CN=192.0.2.10', '-addext', 'subjectAltName=IP:192.0.2.10')
            run('openssl', 'x509', '-req', '-in', str(directory/'leaf.csr'),
                '-CA', str(directory/'ca.pem'), '-CAkey', str(directory/'ca.key'),
                '-CAcreateserial', '-copy_extensions', 'copy', '-out', str(cert/'fullchain.pem'), '-days', '1')
            state = directory/'state.json'
            # The fallback HTTPS site lives in the panel container's namespace for this isolated test.
            panel.secure_json(state, {'ip': '192.0.2.10', 'timezone': 'UTC', 'reality_fallback_host': '127.0.0.1'})
            try:
                run('docker', 'run', '-d', '--name', name,
                    '-p', '127.0.0.1::2095', '-p', '127.0.0.1::1080', '-v', str(cert)+':/app/cert:ro', image)
                address = run('docker', 'port', name, '2095/tcp')
                api = panel.PanelAPI('http://' + address + '/app/')
                def wait_ready():
                    for attempt in range(60):
                        try:
                            run('docker', 'exec', name, './sui', 'healthcheck')
                            return
                        except subprocess.CalledProcessError:
                            time.sleep(0.25)
                    self.fail('Isolated panel did not become healthy')
                wait_ready()
                versions = run('docker', 'exec', name, './sui', '-v')
                self.assertIn('1.6.6', versions)
                self.assertIn('v1.14.4', versions)
                output = panel.configure(state, api=api)
                self.assertEqual(3, len(output['nodes']))
                with self.assertRaises(panel.PanelError):
                    api.call('login', {'user': 'admin', 'pass': 'admin'})
                # Observe actual API writes instead of trusting a stage marker.
                writes = []
                original_call = api.call
                def tracked(action, form=None, raw=False):
                    if action == 'save':
                        writes.append(form['object'])
                    return original_call(action, form, raw)
                api.call = tracked
                panel.configure(state, api=api)
                self.assertEqual([], writes)
                before = json.loads(state.read_text())
                run('docker', 'restart', name)
                wait_ready()
                api.base_url = 'http://' + run('docker', 'port', name, '2095/tcp') + '/app/'
                panel.configure(state, api=api)
                self.assertEqual([], writes)
                self.assertEqual(before['client'], json.loads(state.read_text())['client'])
                self.assertEqual(before['panel'], json.loads(state.read_text())['panel'])
                self.assertEqual(before['reality'], json.loads(state.read_text())['reality'])
                if os.environ.get('RUN_PANEL_NETWORK') == '1':
                    self.check_network(run, name, directory, output)
            finally:
                subprocess.run(['docker', 'rm', '-f', name], stdout=subprocess.DEVNULL,
                               stderr=subprocess.DEVNULL, check=False)

    def check_network(self, run, server_name, directory, exported):
        """Force one outbound at a time and retain TLS verification throughout."""
        image = json.loads((ROOT/'versions.json').read_text())['sing_box_image']
        run('docker', 'pull', image)
        socks_address = run('docker', 'port', server_name, '1080/tcp')
        # Reality relays every handshake to its target, so a reachable TLS site must exist on 127.0.0.1:9443.
        panel.secure_json(directory/'fallback.json', {'log': {'level': 'error'}, 'inbounds': [
            {'type': 'http', 'listen': '127.0.0.1', 'listen_port': 9443,
             'tls': {'enabled': True, 'certificate_path': '/cert/fullchain.pem', 'key_path': '/cert/privkey.pem'}}],
            'outbounds': [{'type': 'block'}]})
        directory.chmod(0o755)
        for item in [directory/'fallback.json', directory/'ca.pem']:
            item.chmod(0o644)
        fallback_name = 'sui-fallback-test-' + uuid.uuid4().hex[:10]
        run('docker', 'run', '-d', '--name', fallback_name, '--network', 'container:'+server_name,
            '-v', str(directory)+':/work:ro', '-v', str(directory/'cert')+':/cert:ro', image, 'run', '-c', '/work/fallback.json')
        self.addCleanup(subprocess.run, ['docker', 'rm', '-f', fallback_name], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, check=False)
        for node in exported['nodes']:
            outbound = {'type': 'anytls' if node['type'] == 'anytls' else 'vless',
                        'tag': 'selected', 'server': '127.0.0.1', 'server_port': node['port'],
                        'tls': {'enabled': True, 'server_name': node['server_name']}}
            if node['type'] == 'anytls':
                outbound['password'] = node['password']
            else:
                outbound.update(uuid=node['uuid'], flow=node.get('flow', ''))
            if node['type'] == 'vless-reality':
                outbound['tls'].update(utls={'enabled': True, 'fingerprint': 'chrome'},
                                       reality={'enabled': True, 'public_key': node['public_key'], 'short_id': node['short_id']})
            else:
                outbound['tls']['certificate_path'] = '/work/ca.pem'
            for valid in (True, False):
                candidate = copy.deepcopy(outbound)
                if not valid:
                    if node['type'] == 'anytls':
                        candidate['password'] = 'wrong-password-for-rejection-test'
                    else:
                        candidate['uuid'] = '00000000-0000-4000-8000-000000000000'
                config = {'log': {'level': 'error'},
                          'inbounds': [{'type': 'socks', 'tag': 'test', 'listen': '0.0.0.0', 'listen_port': 1080}],
                          'outbounds': [candidate], 'route': {'final': 'selected'}}
                panel.secure_json(directory/'client.json', config)
                client_name = 'sui-client-test-' + uuid.uuid4().hex[:10]
                try:
                    run('docker', 'run', '-d', '--name', client_name, '--network', 'container:'+server_name,
                        '-v', str(directory)+':/work:ro', image, 'run', '-c', '/work/client.json')
                    # Wait for the sole local SOCKS listener; no fallback outbound exists.
                    ready = False
                    for attempt in range(40):
                        import socket
                        try:
                            host, port = socks_address.rsplit(':', 1)
                            with socket.create_connection((host, int(port)), timeout=0.2) as probe:
                                probe.sendall(b'\x05\x01\x00')
                                if probe.recv(2) == b'\x05\x00':
                                    ready = True
                                    break
                            time.sleep(0.1)
                        except OSError:
                            time.sleep(0.1)
                    self.assertTrue(ready, 'Client SOCKS5 listener did not become ready')
                    request = subprocess.run(['curl', '--silent', '--show-error', '--fail', '--max-time', '15',
                                              '--proxy', 'socks5h://'+socks_address, '--noproxy', '',
                                              'https://example.com/'], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
                    if valid:
                        if request.returncode:
                            client_logs = subprocess.run(['docker', 'logs', client_name], stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True).stdout
                            server_logs = subprocess.run(['docker', 'logs', '--tail', '12', server_name], stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True).stdout
                            diagnostic = request.stderr.decode(errors='replace') + client_logs + server_logs
                            for value in list(node.values()) + list(json.loads((directory/'state.json').read_text())['panel'].values()):
                                if isinstance(value, str) and len(value) > 10:
                                    diagnostic = diagnostic.replace(value, '[REDACTED]')
                            self.fail(node['type']+' authenticated HTTPS request failed: '+diagnostic)

                        self.assertIn(b'Example Domain', request.stdout)
                    else:
                        self.assertNotEqual(0, request.returncode, node['type']+' accepted wrong credentials')
                finally:
                    subprocess.run(['docker', 'rm', '-f', client_name], stdout=subprocess.DEVNULL,
                                   stderr=subprocess.DEVNULL, check=False)


if __name__ == '__main__':
    unittest.main()
