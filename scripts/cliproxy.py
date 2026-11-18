#!/usr/bin/env python3
"""Pinned CLIProxyAPI v8 installer, invoked on the server by server.py.

Schema verified at router-for-me/CLIProxyAPI v8.0.76 commit
7df56074b252384d878ec4fca840552c6fb5236e, config.example.yaml.
management.html is pinned independently and served by Nginx; the application
panel downloader is disabled. No upstream credentials are seeded or removed.
"""
import hashlib
import io
import ipaddress
import json
import os
from pathlib import Path
import platform
import re
import secrets
import subprocess
import tarfile
import tempfile
import time
from urllib.error import HTTPError, URLError
from urllib.request import ProxyHandler, Request, build_opener


class CLIProxyError(RuntimeError):
    pass


def save_bytes(path, content, mode=0o600):
    path = Path(path)
    if path.is_symlink():
        raise CLIProxyError('Refusing symlink installation path')
    path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    if path.exists() and path.read_bytes() == content:
        path.chmod(mode)
        return False
    fd, temporary = tempfile.mkstemp(prefix='.cliproxy-', dir=path.parent)
    try:
        os.fchmod(fd, mode)
        with os.fdopen(fd, 'wb') as stream:
            stream.write(content)
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary, path)
    finally:
        if os.path.exists(temporary):
            os.unlink(temporary)
    return True


def save_state(path, state):
    save_bytes(path, (json.dumps(state, ensure_ascii=False, indent=2) + '\n').encode())


def download(url):
    reply = subprocess.run(['curl', '--disable', '--fail', '--silent', '--show-error',
                            '--location', '--proto', '=https', '--proto-redir', '=https',
                            '--max-time', '180', url], capture_output=True, timeout=190)
    if reply.returncode:
        raise CLIProxyError('Pinned release download failed')
    return reply.stdout


def verify_download(asset, fetch=download):
    url, digest = asset['url'], asset['sha256']
    if not url.startswith('https://github.com/router-for-me/') or '/releases/download/' not in url:
        raise CLIProxyError('Release asset is outside the reviewed upstream')
    if not re.fullmatch('[a-f0-9]{64}', digest):
        raise CLIProxyError('Pinned release digest missing')
    content = fetch(url)
    if hashlib.sha256(content).hexdigest() != digest:
        raise CLIProxyError('Pinned release digest mismatch')
    return content


def binary_from_archive(content):
    try:
        with tarfile.open(fileobj=io.BytesIO(content), mode='r:gz') as archive:
            matches = [entry for entry in archive.getmembers() if entry.name in ('cli-proxy-api', './cli-proxy-api')]
            if len(matches) != 1 or not matches[0].isfile() or matches[0].size > 200 * 1024 * 1024:
                raise CLIProxyError('Unexpected CLIProxyAPI archive layout')
            return archive.extractfile(matches[0]).read()
    except (tarfile.TarError, OSError):
        raise CLIProxyError('Invalid CLIProxyAPI archive') from None


def local_request(path, key):
    # Explicitly bypass proxy environment variables for local credentials.
    opener = build_opener(ProxyHandler({}))
    request = Request('http://127.0.0.1:8317' + path, headers={'Authorization': 'Bearer ' + key})
    try:
        with opener.open(request, timeout=5) as response:
            return response.status, response.read(1024 * 1024)
    except HTTPError as error:
        return error.code, b''
    except (URLError, OSError):
        return 0, b''


def verify_health(api_key, request=local_request):
    status, body = request('/v1/models', api_key)
    try:
        data = json.loads(body)
    except ValueError:
        data = None
    if status != 200 or not isinstance(data, dict) or not isinstance(data.get('data'), list):
        raise CLIProxyError('CLIProxyAPI authenticated models health check failed')
    wrong_status, _ = request('/v1/models', secrets.token_urlsafe(32))
    if wrong_status not in (401, 403):
        raise CLIProxyError('CLIProxyAPI accepted an invalid API key')


def verify(state):
    verify_health(state['cli_proxy']['api_key'])
    return True


def unit_text():
    return '''[Unit]
Description=Private CLIProxyAPI (pinned release)
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
User=sui-cliproxy
Group=sui-cliproxy
WorkingDirectory=/var/lib/sui-cliproxy
ExecStart=/usr/local/lib/sui-cliproxy/cli-proxy-api --config /var/lib/sui-cliproxy/config.yaml --local-model
Restart=on-failure
RestartSec=5
UMask=0077
NoNewPrivileges=true
PrivateTmp=true
PrivateDevices=true
ProtectSystem=strict
ProtectHome=true
ReadWritePaths=/var/lib/sui-cliproxy
ProtectKernelTunables=true
ProtectKernelModules=true
ProtectControlGroups=true
RestrictSUIDSGID=true
CapabilityBoundingSet=
LockPersonality=true

[Install]
WantedBy=multi-user.target
'''


def initial_config(keys):
    # JSON is valid YAML and avoids introducing a YAML serializer dependency.
    return {'config-version': 8,
            'server': {'host': '127.0.0.1', 'port': 8317, 'discovery': {'enabled': False}, 'trusted-proxies': []},
            'management': {'allow-remote': False, 'secret-key': keys['management_key'],
                           'disable-control-panel': True, 'disable-auto-update-panel': True},
            'access': {'api-keys': [keys['api_key']]},
            'oauth': {'auth-dir': '/var/lib/sui-cliproxy/auth'},
            'plugins': {'enabled': False},
            'observability': {'logs': {'debug': False, 'request-log': False, 'logging-to-file': False},
                              'usage': {'usage-statistics-enabled': False}, 'pprof': {'enable': False}}}


def install(state, *, state_path='/etc/sui-vps/state.json', root='/', versions=None,
            fetch=download, run=subprocess.run, check_health=True, arch=None):
    """Install only when explicitly invoked by deployment; never auto-upgrade."""
    root = Path(root)
    if versions is None:
        versions = json.loads((Path(__file__).resolve().parents[1] / 'versions.json').read_text())
    architecture = arch or {'x86_64': 'amd64', 'aarch64': 'arm64'}.get(platform.machine())
    if architecture not in versions['cli_proxy_assets']:
        raise CLIProxyError('Unsupported CLIProxyAPI architecture')
    host = str(ipaddress.IPv4Address(state['ip']))
    keys = state.setdefault('cli_proxy', {})
    keys.setdefault('management_key', secrets.token_urlsafe(32))
    keys.setdefault('api_key', secrets.token_urlsafe(32))
    version = versions['cli_proxy_version']
    if keys.get('version') and keys['version'] != version:
        raise CLIProxyError('CLIProxyAPI version changed; back up and perform an explicit reviewed upgrade')
    if keys['management_key'] == keys['api_key']:
        raise CLIProxyError('Management and API keys must be independent')
    keys['version'] = version
    save_state(state_path, state)  # Crash recovery before installing credential-bearing config.

    def command(args):
        run(args, check=True, capture_output=True)

    app = root / 'usr/local/lib/sui-cliproxy'
    data = root / 'var/lib/sui-cliproxy'
    app.mkdir(parents=True, mode=0o755, exist_ok=True)
    (app / 'static').mkdir(mode=0o755, exist_ok=True)
    app.chmod(0o755)
    (app / 'static').chmod(0o755)
    data.mkdir(parents=True, mode=0o700, exist_ok=True)
    (data / 'auth').mkdir(mode=0o700, exist_ok=True)
    command(['sh', '-c', 'id -u sui-cliproxy >/dev/null 2>&1 || useradd --system --user-group --home-dir /var/lib/sui-cliproxy --shell /usr/sbin/nologin sui-cliproxy'])
    binary_path, management_path = app / 'cli-proxy-api', app / 'static/management.html'
    changed = False
    # Download only missing assets. Existing binaries are checked against their
    # recorded installed hash; a modified binary is never quietly trusted.
    if binary_path.exists():
        if not keys.get('binary_sha256') or hashlib.sha256(binary_path.read_bytes()).hexdigest() != keys['binary_sha256']:
            raise CLIProxyError('Installed CLIProxyAPI binary differs from saved digest')
    else:
        binary = binary_from_archive(verify_download(versions['cli_proxy_assets'][architecture], fetch))
        keys['binary_sha256'] = hashlib.sha256(binary).hexdigest()
        save_state(state_path, state)
        changed |= save_bytes(binary_path, binary, 0o755)
        save_state(state_path, state)
    pinned_management = versions['cli_proxy_management']
    if not management_path.exists() or hashlib.sha256(management_path.read_bytes()).hexdigest() != pinned_management['sha256']:
        changed |= save_bytes(management_path, verify_download(pinned_management, fetch), 0o644)
    config_path = data / 'config.yaml'
    if not config_path.exists():
        changed |= save_bytes(config_path, (json.dumps(initial_config(keys), indent=2) + '\n').encode())
    if config_path.is_symlink() or binary_path.is_symlink() or management_path.is_symlink():
        raise CLIProxyError('Refusing symlink service files')
    config_path.chmod(0o600)
    command(['chown', '-R', 'sui-cliproxy:sui-cliproxy', str(data)])
    changed |= save_bytes(root / 'etc/systemd/system/sui-cliproxy.service', unit_text().encode(), 0o644)
    command(['systemctl', 'daemon-reload'])
    command(['systemctl', 'enable', 'sui-cliproxy.service'])
    command(['systemctl', 'restart' if changed else 'start', 'sui-cliproxy.service'])
    if check_health:
        for attempt in range(30):
            try:
                verify_health(keys['api_key'])
                break
            except CLIProxyError:
                if attempt == 29:
                    raise
                time.sleep(1)
    keys.update(version=version, management_version=pinned_management['version'])
    save_state(state_path, state)
    return {'management_url': f'https://{host}:9444/management.html',
            'management_key': keys['management_key'], 'api_base_url': f'https://{host}:9444/v1', 'api_key': keys['api_key']}
