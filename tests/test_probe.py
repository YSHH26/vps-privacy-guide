import contextlib
import importlib.util
import json
import os
import copy
import socket
import socketserver
import ssl
import select
import subprocess
import threading
from unittest.mock import patch
from pathlib import Path
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location('probe', ROOT/'scripts/probe.py')
probe = importlib.util.module_from_spec(spec)
spec.loader.exec_module(probe)


def exported():
    return {'server': {'host': '192.0.2.10'}, 'nodes': [
        {'type': 'vless-reality', 'server': '192.0.2.10', 'port': 443,
         'uuid': 'fe38cb43-3046-426e-88b4-cf8f3bc9ae36', 'flow': 'xtls-rprx-vision',
         'server_name': 'www.microsoft.com', 'public_key': 'A'*43, 'short_id': '12345678'},
        {'type': 'vless-tls', 'server': '192.0.2.10', 'port': 2443,
         'uuid': 'fe38cb43-3046-426e-88b4-cf8f3bc9ae36', 'server_name': '192.0.2.10'},
        {'type': 'anytls', 'server': '192.0.2.10', 'port': 8443,
         'password': '__TEST_ANYTLS_PASSWORD__', 'server_name': '192.0.2.10'}]}


class FakeBackend:
    def __init__(self, fail_wrong_start=False, accept_wrong=False, wrong_timeout=False):
        self.configs = []
        self.fail_wrong_start = fail_wrong_start
        self.accept_wrong = accept_wrong
        self.wrong_timeout = wrong_timeout
        self.ipv6_reachable = False
    def prepare(self, image):
        if '@sha256:' not in image:
            raise AssertionError('Unpinned image')
    @contextlib.contextmanager
    def session(self, config):
        self.configs.append(config)
        # Per node: valid baseline, wrong credentials, valid restoration.
        wrong = (len(self.configs) - 1) % 3 == 1
        if wrong and self.fail_wrong_start:
            raise probe.ProbeError('client_start_failed')
        backend = self
        class Session:
            def request(self, url):
                if wrong:
                    if backend.wrong_timeout:
                        return {'ok': False, 'error': 'request_timeout'}
                    if not backend.accept_wrong:
                        return {'ok': False, 'error': 'proxy_rejected'}
                if url in probe.IPV6_URLS and not backend.ipv6_reachable:
                    return {'ok': False, 'error': 'proxy_rejected'}
                return {'ok': True, 'status': 200, 'body': b'192.0.2.10' if 'ipify' in url else b'Example Domain'}
            def healthy(self):
                return True
        yield Session()


class ProbeTests(unittest.TestCase):
    def test_reachable_ipv6_egress_fails_the_node(self):
        backend = FakeBackend()
        backend.ipv6_reachable = True
        result = self.run_probe(backend)
        self.assertEqual('failed', result['status'])
        self.assertTrue(all(n['ipv6_egress'] == 'reachable' for n in result['nodes']))

    def run_probe(self, backend):
        with tempfile.TemporaryDirectory() as tmp:
            directory = Path(tmp)
            source = directory/'export.json'
            source.write_text(json.dumps(exported()))
            source.chmod(0o600)
            output = directory/'network.json'
            result = probe.probe(source, output, backend=backend)
            self.assertEqual(0o600, output.stat().st_mode & 0o777)
            self.assertEqual(result, json.loads(output.read_text()))
            for node in exported()['nodes']:
                for key in ('uuid', 'password', 'public_key', 'short_id'):
                    if key in node:
                        self.assertNotIn(node[key], output.read_text())
            return result

    def test_passes_only_for_forced_per_node_valid_wrong_restored(self):
        backend = FakeBackend()
        result = self.run_probe(backend)
        self.assertEqual('passed', result['status'])
        self.assertEqual(9, len(backend.configs))
        for config in backend.configs:
            self.assertEqual(1, len(config['outbounds']))
            self.assertEqual('selected', config['route']['final'])
            outbound = config['outbounds'][0]
            self.assertNotIn('insecure', outbound['tls'])
            self.assertNotIn('certificate_path', outbound['tls'])

    def test_wrong_client_start_failure_never_counts_as_auth_rejection(self):
        result = self.run_probe(FakeBackend(fail_wrong_start=True))
        self.assertEqual('failed', result['status'])
        self.assertTrue(all(n['wrong_credentials'] != 'rejected' for n in result['nodes']))

    def test_wrong_credentials_success_and_timeout_both_fail(self):
        for backend in (FakeBackend(accept_wrong=True), FakeBackend(wrong_timeout=True)):
            with self.subTest(backend=backend):
                self.assertEqual('failed', self.run_probe(backend)['status'])

    def test_input_permissions_and_insecure_export_rejected(self):
        with tempfile.TemporaryDirectory() as tmp:
            source = Path(tmp)/'export.json'
            source.write_text(json.dumps(exported()))
            source.chmod(0o644)
            with self.assertRaises(probe.ProbeError):
                probe.probe(source, Path(tmp)/'output.json', backend=FakeBackend())
        node = exported()['nodes'][1]
        node['insecure'] = True
        with self.assertRaises(probe.ProbeError):
            probe.client_config(node)

    def test_exit_ip_mismatch_fails(self):
        class OtherExit(FakeBackend):
            @contextlib.contextmanager
            def session(self, config):
                with super().session(config) as session:
                    original = session.request
                    session.request = lambda url: {'ok': True, 'status': 200, 'body': b'192.0.2.99'} if 'ipify' in url else original(url)
                    yield session
        self.assertEqual('failed', self.run_probe(OtherExit())['status'])


class FingerprintTests(unittest.TestCase):
    def test_ignores_delivery_metadata_but_binds_nodes_and_deployment(self):
        config = exported()
        original = probe.fingerprint(config)
        config.update(traffic={'used_bytes': 123}, panel={'password': '__UNRELATED__'})
        self.assertEqual(original, probe.fingerprint(config))
        config['nodes'][0]['uuid'] = '00000000-0000-4000-8000-000000000000'
        self.assertNotEqual(original, probe.fingerprint(config))
        config = exported()
        config['server']['deployed_at'] = '2026-11-17T00:00:00Z'
        self.assertNotEqual(original, probe.fingerprint(config))


class NativeHTTPSTests(unittest.TestCase):
    def test_socks_tunnel_uses_https_verification(self):
        from http.server import BaseHTTPRequestHandler, HTTPServer
        class Handler(BaseHTTPRequestHandler):
            def log_message(self, *args):
                pass
            def do_GET(self):
                self.send_response(200)
                self.end_headers()
                self.wfile.write(b'local HTTPS fixture')
        with tempfile.TemporaryDirectory() as tmp:
            cert, key = Path(tmp)/'cert.pem', Path(tmp)/'key.pem'
            subprocess.run(['openssl', 'req', '-x509', '-newkey', 'rsa:2048', '-nodes',
                            '-keyout', str(key), '-out', str(cert), '-days', '1',
                            '-subj', '/CN=localhost', '-addext', 'subjectAltName=DNS:localhost'],
                           check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            server = HTTPServer(('127.0.0.1', 0), Handler)
            context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
            context.load_cert_chain(cert, key)
            server.socket = context.wrap_socket(server.socket, server_side=True)
            thread = threading.Thread(target=server.serve_forever, daemon=True)
            thread.start()
            class Socks(socketserver.BaseRequestHandler):
                def handle(self):
                    upstream = None
                    try:
                        if probe.receive(self.request, 3) != b'\x05\x01\x00':
                            return
                        self.request.sendall(b'\x05\x00')
                        header = probe.receive(self.request, 4)
                        if header != b'\x05\x01\x00\x03':
                            return
                        probe.receive(self.request, probe.receive(self.request, 1)[0])
                        probe.receive(self.request, 2)
                        upstream = socket.create_connection(('127.0.0.1', server.server_port))
                        self.request.sendall(b'\x05\x00\x00\x01\x7f\x00\x00\x01\x00\x00')
                        while True:
                            ready, _, _ = select.select([self.request, upstream], [], [], 3)
                            if not ready:
                                return
                            for source in ready:
                                data = source.recv(65536)
                                if not data:
                                    return
                                (upstream if source is self.request else self.request).sendall(data)
                    except (OSError, EOFError):
                        pass
                    finally:
                        if upstream:
                            upstream.close()
            proxy = socketserver.ThreadingTCPServer(('127.0.0.1', 0), Socks)
            proxy.daemon_threads = True
            proxy_thread = threading.Thread(target=proxy.serve_forever, daemon=True)
            proxy_thread.start()
            class Backend:
                timeout = 3
                def command(self, args):
                    return 'true'
            try:
                session = probe.LocalSession(Backend(), 'fixture', '127.0.0.1:'+str(proxy.server_address[1]))
                self.assertTrue(session.healthy())
                url = 'https://localhost:'+str(server.server_port)+'/'
                with patch.dict(os.environ, {'SSL_CERT_FILE': str(cert)}):
                    result = session.request(url)
                    self.assertTrue(result['ok'])
                    self.assertEqual(b'local HTTPS fixture', result['body'])
                # The same untrusted fixture must fail with normal system roots.
                with patch.dict(os.environ):
                    os.environ.pop('SSL_CERT_FILE', None)
                    result = session.request(url)
                self.assertFalse(result['ok'])
                self.assertEqual('https_certificate_rejected', result['error'])
            finally:
                proxy.shutdown()
                proxy.server_close()
                server.shutdown()
                server.server_close()
                thread.join()
                proxy_thread.join()


@unittest.skipUnless(os.environ.get('RUN_PROBE_INTEGRATION') == '1',
                     'Set RUN_PROBE_INTEGRATION=1 for a fixed-core Docker startup test')
class DockerStartupTests(unittest.TestCase):
    def test_closed_destination_is_not_client_start_failure_or_success(self):
        versions = json.loads((ROOT/'versions.json').read_text())
        backend = probe.DockerBackend(timeout=2, expected_version=versions['sing_box_version'])
        backend.prepare(versions['sing_box_image'])
        node = exported()['nodes'][2]
        node.update(server='127.0.0.1', port=1)
        with backend.session(probe.client_config(node)) as session:
            self.assertTrue(session.healthy())
            result = session.request('https://example.com/')
            self.assertFalse(result['ok'])
            self.assertTrue(session.healthy())
        malformed = probe.client_config(node)
        malformed['inbounds'][0]['type'] = '__INVALID_CORE_INBOUND__'
        with self.assertRaises(probe.ProbeError):
            with backend.session(malformed):
                self.fail('Malformed fixed-core config started')


class NativeBackendTests(unittest.TestCase):
    def test_binary_digest_rejected_before_execution(self):
        with tempfile.TemporaryDirectory() as tmp:
            binary = Path(tmp)/'sing-box'
            binary.write_bytes(b'__UNTRUSTED_TEST_BINARY__')
            binary.chmod(0o700)
            backend = probe.NativeBackend(binary, {'binary_sha256': '0'*64}, '1.14.4')
            with patch.object(probe.subprocess, 'run') as run:
                with self.assertRaises(probe.ProbeError):
                    backend.prepare(None)
                run.assert_not_called()

    def test_native_requested_explicitly_and_requires_binary(self):
        with tempfile.TemporaryDirectory() as tmp:
            source = Path(tmp)/'export.json'
            source.write_text(json.dumps(exported()))
            source.chmod(0o600)
            with self.assertRaises(probe.ProbeError):
                probe.probe(source, Path(tmp)/'network.json', backend='native')

    @unittest.skipUnless(os.environ.get('RUN_NATIVE_PROBE_INTEGRATION') == '1',
                         'Set RUN_NATIVE_PROBE_INTEGRATION=1 and NATIVE_CORE_BIN for verified native client test')
    def test_verified_native_ready_closed_destination_and_cleanup(self):
        versions = json.loads((ROOT/'versions.json').read_text())
        asset = versions['sing_box_client_assets']['darwin-arm64']
        backend = probe.NativeBackend(os.environ['NATIVE_CORE_BIN'], asset, versions['sing_box_version'], timeout=2)
        backend.prepare(None)
        node = exported()['nodes'][2]
        node.update(server='127.0.0.1', port=1)
        with backend.session(probe.client_config(node)) as session:
            process = session.process
            self.assertTrue(session.healthy())
            self.assertEqual('127.0.0.1', session.address[0])
            result = session.request('https://example.com/')
            self.assertFalse(result['ok'])
            self.assertTrue(session.healthy())
        self.assertIsNotNone(process.poll())
        malformed = probe.client_config(node)
        malformed['inbounds'][0]['type'] = '__INVALID_CORE_INBOUND__'
        with self.assertRaises(probe.ProbeError):
            with backend.session(malformed):
                self.fail('Invalid native configuration started')


class HTTPSRootsTests(unittest.TestCase):
    def test_empty_store_requires_clear_dependency_error(self):
        empty = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        self.assertEqual(0, empty.cert_store_stats()['x509_ca'])
        with patch.object(probe.ssl, 'create_default_context', return_value=empty), patch.dict(__import__('sys').modules, {'certifi': None}):
            with self.assertRaisesRegex(probe.ProbeError, 'requirements-local'):
                probe.https_context()

    @unittest.skipUnless(__import__('importlib.util').util.find_spec('certifi'), 'Install requirements-local.txt for pinned CA regression')
    def test_real_empty_store_loads_pinned_mozilla_roots_with_verification(self):
        import certifi
        if certifi.__version__ != '2026.10.23':
            self.skipTest('Pinned local certifi release required')
        empty = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        self.assertEqual(0, empty.cert_store_stats()['x509_ca'])
        with patch.object(probe.ssl, 'create_default_context', return_value=empty):
            context = probe.https_context()
        self.assertGreater(context.cert_store_stats()['x509_ca'], 100)
        self.assertEqual(ssl.CERT_REQUIRED, context.verify_mode)
        self.assertTrue(context.check_hostname)

    def test_existing_trust_context_does_not_import_extra_roots(self):
        # Existing system roots, or a deliberately scoped test CA, are retained.
        class Context:
            verify_mode = ssl.CERT_REQUIRED
            check_hostname = True
            def cert_store_stats(self):
                return {'x509_ca': 1}
            def load_verify_locations(self, *args, **kwargs):
                raise AssertionError('Existing trust must not be expanded')
        context = Context()
        with patch.object(probe.ssl, 'create_default_context', return_value=context), patch.dict(__import__('sys').modules, {'certifi': None}):
            self.assertIs(context, probe.https_context())


if __name__ == '__main__':
    unittest.main()
