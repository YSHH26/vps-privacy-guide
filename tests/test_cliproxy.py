import hashlib
import io
import json
from pathlib import Path
import sys
import tarfile
import tempfile
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'scripts'))
import cliproxy


class CLIProxyTests(unittest.TestCase):
    def archive(self):
        stream = io.BytesIO()
        with tarfile.open(fileobj=stream, mode='w:gz') as archive:
            entry = tarfile.TarInfo('cli-proxy-api')
            data = b'synthetic-test-binary'
            entry.size = len(data)
            archive.addfile(entry, io.BytesIO(data))
        return stream.getvalue()

    def test_install_preserves_secrets_and_user_configuration(self):
        binary = self.archive()
        panel = b'<!doctype html><title>synthetic management</title>'
        versions = {'cli_proxy_version': 'v8.0.76', 'cli_proxy_assets': {'amd64': {
            'url': 'https://github.com/router-for-me/CLIProxyAPI/releases/download/v8.0.76/test.tar.gz',
            'sha256': hashlib.sha256(binary).hexdigest()}}, 'cli_proxy_management': {
            'version': 'v1.28.1',
            'url': 'https://github.com/router-for-me/Cli-Proxy-API-Management-Center/releases/download/v1.28.1/management.html',
            'sha256': hashlib.sha256(panel).hexdigest()}}
        def fetch(url):
            return panel if url.endswith('.html') else binary
        commands = []
        def run(args, **kwargs):
            commands.append(args)
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            state = {'ip': '192.0.2.1'}
            path = root / 'state.json'
            exported = cliproxy.install(state, state_path=path, root=root, versions=versions,
                                       fetch=fetch, run=run, check_health=False, arch='amd64')
            self.assertNotEqual(exported['management_key'], exported['api_key'])
            self.assertEqual(exported['api_base_url'], 'https://192.0.2.1:9444/v1')
            config_path = root / 'var/lib/sui-cliproxy/config.yaml'
            cfg = json.loads(config_path.read_text())
            self.assertEqual(cfg['server']['host'], '127.0.0.1')
            self.assertTrue(cfg['management']['disable-auto-update-panel'])
            self.assertTrue(cfg['management']['disable-control-panel'])
            self.assertNotIn('api-keys', cfg.get('providers', {}))
            cfg['custom-upstream-for-test'] = 'preserve me'
            config_path.write_text(json.dumps(cfg))
            again = cliproxy.install(state, state_path=path, root=root, versions=versions,
                                    fetch=fetch, run=run, check_health=False, arch='amd64')
            self.assertEqual(again, exported)
            self.assertIn('preserve me', config_path.read_text())
            self.assertEqual(path.stat().st_mode & 0o777, 0o600)
            self.assertEqual(config_path.stat().st_mode & 0o777, 0o600)
            unit = (root / 'etc/systemd/system/sui-cliproxy.service').read_text()
            self.assertIn('User=sui-cliproxy', unit)
            self.assertIn('NoNewPrivileges=true', unit)
            self.assertIn('/usr/local/lib/sui-cliproxy/cli-proxy-api', unit)
            self.assertNotIn(exported['management_key'], unit)
            self.assertEqual(sum(c[:2] == ['systemctl', 'restart'] for c in commands), 1)
            self.assertEqual((root / 'usr/local/lib/sui-cliproxy').stat().st_mode & 0o777, 0o755)
            executable = root / 'usr/local/lib/sui-cliproxy/cli-proxy-api'
            executable.write_bytes(b'tampered')
            with self.assertRaises(cliproxy.CLIProxyError):
                cliproxy.install(state, state_path=path, root=root, versions=versions,
                                 fetch=fetch, run=run, check_health=False, arch='amd64')

    def test_download_digest_and_tar_member_fail_closed(self):
        with self.assertRaises(cliproxy.CLIProxyError):
            cliproxy.verify_download({'url': 'https://example.com/asset', 'sha256': '0' * 64}, lambda url: b'corrupt')
        stream = io.BytesIO()
        with tarfile.open(fileobj=stream, mode='w:gz') as archive:
            entry = tarfile.TarInfo('../cli-proxy-api')
            entry.size = 1
            archive.addfile(entry, io.BytesIO(b'x'))
        with self.assertRaises(cliproxy.CLIProxyError):
            cliproxy.binary_from_archive(stream.getvalue())

    def test_health_requires_valid_and_invalid_auth(self):
        calls = []
        def request(path, key):
            calls.append((path, key))
            if path == '/management.html':
                return 404, b''
            return (200, b'{"data":[]}') if key == 'valid-key' else (401, b'{}')
        cliproxy.verify_health('valid-key', request=request)
        self.assertEqual(len(calls), 2)
        with self.assertRaises(cliproxy.CLIProxyError):
            cliproxy.verify_health('valid-key', request=lambda *a: (200, b'{"data":[]}'))


# Opt-in real binary test. It uses only synthetic keys and local isolated Docker.
import os
import secrets
import subprocess
import time
from urllib.error import HTTPError, URLError
from urllib.request import Request, ProxyHandler, build_opener


@unittest.skipUnless(os.environ.get('RUN_CLIPROXY_INTEGRATION') == '1',
                     'Set RUN_CLIPROXY_INTEGRATION=1 for pinned local CLIProxyAPI Docker checks')
class CLIProxyRuntimeTests(unittest.TestCase):
    def test_actual_binary_empty_upstream_client_and_management_auth(self):
        versions = json.loads((Path(__file__).resolve().parents[1] / 'versions.json').read_text())
        architecture = subprocess.run(['docker', 'info', '--format', '{{.Architecture}}'],
                                      capture_output=True, text=True, check=True).stdout.strip()
        architecture = {'aarch64': 'arm64', 'arm64': 'arm64', 'x86_64': 'amd64'}.get(architecture, architecture)
        asset = versions['cli_proxy_assets'][architecture]
        binary = cliproxy.binary_from_archive(cliproxy.verify_download(asset))
        keys = {'api_key': secrets.token_urlsafe(32), 'management_key': secrets.token_urlsafe(32)}
        name = 'sui-cliproxy-local-test-' + secrets.token_hex(6)
        opener = build_opener(ProxyHandler({}))
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / 'cli-proxy-api').write_bytes(binary)
            (root / 'cli-proxy-api').chmod(0o755)
            cfg = cliproxy.initial_config(keys)
            # Container-only test overrides: Docker forwards via its interface;
            # the host published port remains 127.0.0.1 with a random port.
            cfg['server']['host'] = '0.0.0.0'
            cfg['management']['allow-remote'] = True
            cfg['oauth']['auth-dir'] = '/tmp/auth'
            (root / 'config.json').write_text(json.dumps(cfg))
            try:
                subprocess.run(['docker', 'run', '-d', '--name', name,
                    '--user', str(os.getuid()) + ':' + str(os.getgid()), '--read-only',
                    '--tmpfs', '/tmp:rw,noexec,nosuid,size=32m', '--cap-drop', 'ALL',
                    '--security-opt', 'no-new-privileges', '-p', '127.0.0.1::8317',
                    '--mount', 'type=bind,source=' + str(root) + ',target=/sandbox',
                    '--entrypoint', '/sandbox/cli-proxy-api', versions['sing_box_image'],
                    '--config', '/sandbox/config.json', '--local-model'],
                    capture_output=True, check=True)
                address = subprocess.run(['docker', 'port', name, '8317/tcp'],
                                         capture_output=True, text=True, check=True).stdout.strip()
                base = 'http://' + address
                def request(path, key):
                    try:
                        req = Request(base + path, headers={'Authorization': 'Bearer ' + key})
                        with opener.open(req, timeout=3) as response:
                            return response.status, response.read()
                    except HTTPError as error:
                        return error.code, error.read()
                for attempt in range(60):
                    try:
                        code, body = request('/v1/models', keys['api_key'])
                        if code == 200:
                            break
                    except (URLError, OSError):
                        pass
                    time.sleep(1)
                else:
                    self.fail('Pinned local CLIProxyAPI failed to become ready; no server deployment tested')
                self.assertEqual(json.loads(body)['data'], [])
                self.assertIn(request('/v1/models', 'synthetic-wrong-key')[0], (401, 403))
                self.assertEqual(request('/v0/management/config', keys['management_key'])[0], 200)
                self.assertIn(request('/v0/management/config', 'synthetic-wrong-management')[0], (401, 403))
                self.assertEqual(request('/management.html', '')[0], 404)
            finally:
                subprocess.run(['docker', 'rm', '-f', name], capture_output=True)


if __name__ == '__main__':
    unittest.main()
