#!/usr/bin/env python3
"""Private client subscriptions derived from verified S-UI export facts.

Run behind the deployment's HTTPS reverse proxy. Never log token-bearing URLs.
Surge syntax: https://manual.nssurge.com/policies/anytls.html
TLS syntax: https://manual.nssurge.com/policies/tls.html
"""
import argparse
import base64
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import hmac
import ipaddress
import json
import os
from pathlib import Path
import re
import secrets
import subprocess
import tempfile
import threading
import time
from urllib.parse import quote, urlencode, urlsplit
from urllib.request import Request, urlopen
import uuid

TOKEN_RE = re.compile(r'[A-Za-z0-9_-]{43,128}\Z')
TRAFFIC_LOCK = threading.Lock()


def new_token():
    return secrets.token_urlsafe(32)


def private_json(path, value):
    path = Path(path)
    path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    fd, temporary = tempfile.mkstemp(dir=path.parent, prefix='.private-')
    try:
        with os.fdopen(fd, 'w') as handle:
            json.dump(value, handle, ensure_ascii=False)
            handle.write('\n')
        os.replace(temporary, path)
    finally:
        if os.path.exists(temporary):
            os.unlink(temporary)


def atom(value):
    value = str(value)
    if not value or any(c in value for c in '\r\n\x00,=\"\\') or any(ord(c) < 32 for c in value):
        raise ValueError('Unsafe subscription field')
    return value


def checked_node(node):
    if node.get('insecure') or node.get('skip-cert-verify') or node.get('allowInsecure'):
        raise ValueError('Certificate verification must stay enabled')
    host = atom(node['server'])
    try:
        ipaddress.ip_address(host)
    except ValueError:
        if not re.fullmatch(r'[A-Za-z0-9.-]+', host):
            raise ValueError('Invalid node host') from None
    port = int(node['port'])
    if not 1 <= port <= 65535:
        raise ValueError('Invalid node port')
    return host, port, atom(node.get('server_name') or host)


def surge_config(config):
    lines, names = [], []
    for index, node in enumerate(config['nodes']):
        if node['type'] != 'anytls':
            continue
        host, port, sni = checked_node(node)
        # Stable ASCII names avoid Surge delimiter/rule injection via panel remarks.
        name = 'AnyTLS-' + str(index + 1)
        names.append(name)
        lines.append(f'{name} = anytls, {host}, {port}, password={atom(node["password"])}, sni={sni}, skip-cert-verify=false')
    if not names:
        raise ValueError('No AnyTLS node exported by S-UI')
    return ('#!MANAGED-CONFIG ' + subscription_urls(config)['surge'] + ' interval=86400 strict=true\n'
            '# AnyTLS only; official minimum Mac 6.4.3 / iOS 5.17.0.\n'
            '# Client connections, DNS, IPv6, WebRTC and failure behavior still need testing.\n'
            '[General]\nloglevel = notify\n\n[Proxy]\n' + '\n'.join(lines) +
            '\n\n[Proxy Group]\nPROXY = select, ' + ', '.join(names) +
            '\n\n[Rule]\nFINAL,PROXY\n')


def vless_links(config):
    links = []
    for node in config['nodes']:
        if node['type'] not in ('vless-reality', 'vless-tls'):
            continue
        host, port, sni = checked_node(node)
        identity = str(uuid.UUID(node['uuid']))
        security = 'reality' if node['type'] == 'vless-reality' else 'tls'
        query = {'encryption': 'none', 'security': security, 'type': 'tcp', 'sni': sni, 'allowInsecure': '0'}
        if security == 'reality':
            key, short_id = atom(node['public_key']), str(node['short_id'])
            if not re.fullmatch(r'[A-Za-z0-9_-]{43}', key) or not re.fullmatch(r'(?:[0-9a-fA-F]{2}){0,8}', short_id):
                raise ValueError('Invalid Reality public key or short ID')
            query.update(pbk=key, sid=short_id, fp='chrome', flow=node.get('flow') or 'xtls-rprx-vision')
        elif node.get('flow'):
            query['flow'] = atom(node['flow'])
        authority = f'[{host}]' if ':' in host else host
        name = quote(str(node.get('name') or node['type']), safe='')
        links.append(f'vless://{identity}@{authority}:{port}?{urlencode(query)}#{name}')
    if not links:
        raise ValueError('No VLESS nodes exported by S-UI')
    return links


def v2ray_subscription(config):
    return base64.b64encode(('\n'.join(vless_links(config)) + '\n').encode()).decode() + '\n'


def subscription_urls(config):
    base = str(config['public_base_url']).rstrip('/')
    if any(char.isspace() or ord(char) < 32 for char in base):
        raise ValueError('Invalid subscription origin')
    parts = urlsplit(base)
    if parts.scheme != 'https' or not parts.hostname or parts.username or parts.password or parts.query or parts.fragment or parts.path not in ('', '/'):
        raise ValueError('Subscription base must be an HTTPS origin')
    tokens = config['subscriptions']
    for client in ('surge', 'v2ray'):
        if not TOKEN_RE.fullmatch(tokens[client]):
            raise ValueError('Subscription token must contain at least 256 random bits')
    if tokens['surge'] == tokens['v2ray']:
        raise ValueError('Use independent client subscription tokens')
    return {'surge': f'{base}/s/{tokens["surge"]}/surge.conf',
            'v2ray': f'{base}/s/{tokens["v2ray"]}/v2ray.txt'}


def provider_fetch(url, data):
    # Official API accepts GET. Feed its secret URL via curl config stdin,
    # never argv; use the system trust store without disabling verification.
    if url != 'https://api.64clouds.com/v1/getServiceInfo':
        raise ValueError('Unsupported provider endpoint')
    target = url + '?' + urlencode(data)
    config = 'url = ' + json.dumps(target) + '\nrequest = "GET"\n'
    reply = subprocess.run(['curl', '--disable', '--config', '-', '--fail', '--silent',
                            '--show-error', '--max-time', '20'], input=config.encode(),
                           capture_output=True, timeout=25)
    if reply.returncode:
        raise OSError('Provider traffic request failed')
    return json.loads(reply.stdout)


def traffic_snapshot(credentials, cache, *, fetch=provider_fetch, now=None):
    """KiwiVM account-wide quota, not per-device counters; cache failures too."""
    now = time.time() if now is None else now
    with TRAFFIC_LOCK:
        try:
            previous = json.loads(Path(cache).read_text())
        except (OSError, ValueError):
            previous = {}
        if 0 <= now - previous.get('checked_at', -100000) < 600:
            return previous
        try:
            auth = json.loads(Path(credentials).read_text())
            result = fetch('https://api.64clouds.com/v1/getServiceInfo', {'veid': auth['veid'], 'api_key': auth['api_key']})
            if auth.get('ip') and auth['ip'] not in result.get('ip_addresses', []):
                raise ValueError('Provider target mismatch')
            if result.get('error') != 0:
                raise ValueError('Provider rejected traffic request')
            multiplier = float(result.get('monthly_data_multiplier', 1))
            if multiplier != 1:
                snapshot = {'source': 'KiwiVM getServiceInfo', 'status': 'unsupported_multiplier',
                            'monthly_data_multiplier': multiplier, 'updated_at': now, 'checked_at': now}
                private_json(cache, snapshot)
                return snapshot
            total, used, reset = (int(result[key]) for key in ('plan_monthly_data', 'data_counter', 'data_next_reset'))
            if min(total, used, reset) < 0 or total == 0:
                raise ValueError('Invalid provider traffic values')
            snapshot = {'source': 'KiwiVM getServiceInfo', 'status': 'ok', 'total_bytes': total,
                        'used_bytes': used, 'reset_at': reset, 'updated_at': now, 'checked_at': now}
        except (OSError, ValueError, KeyError, TypeError, subprocess.SubprocessError):
            snapshot = {**previous, 'source': 'KiwiVM getServiceInfo',
                        'status': 'stale' if 'total_bytes' in previous else 'unavailable', 'checked_at': now}
        private_json(cache, snapshot)
        return snapshot


def make_server(export_path, host='127.0.0.1', port=8090, traffic_credentials=None, traffic_cache=None):
    if host != '127.0.0.1':
        raise ValueError('Subscription backend must bind 127.0.0.1')
    export_path = Path(export_path)

    class Handler(BaseHTTPRequestHandler):
        server_version = 'PrivateSubscription'
        sys_version = ''

        def log_message(self, *args):
            pass

        def log_error(self, *args):
            pass

        def do_GET(self):
            try:
                cfg = json.loads(export_path.read_text())
                subscription_urls(cfg)  # Validate tokens and HTTPS origin before serving.
                match = re.fullmatch(r'/s/([A-Za-z0-9_-]{43,128})/(surge\.conf|v2ray\.txt)', self.path)
                if not match:
                    self.reply(404, b'Not found\n')
                    return
                token, filename = match.groups()
                client = 'surge' if filename == 'surge.conf' else 'v2ray'
                if not hmac.compare_digest(token, cfg['subscriptions'][client]):
                    self.reply(404, b'Not found\n')
                    return
                content = surge_config(cfg) if client == 'surge' else v2ray_subscription(cfg)
                traffic = traffic_snapshot(traffic_credentials, traffic_cache) if traffic_credentials and traffic_cache else cfg.get('traffic', {})
                self.reply(200, content.encode(), traffic)
            except (OSError, ValueError, KeyError, TypeError):
                self.reply(503, b'Subscription temporarily unavailable\n')

        def do_HEAD(self):
            self.reply(405, b'')

        def reply(self, code, content, traffic=None):
            self.send_response(code)
            self.send_header('Content-Type', 'text/plain; charset=utf-8')
            self.send_header('Content-Length', str(len(content)))
            self.send_header('Cache-Control', 'no-store')
            self.send_header('X-Content-Type-Options', 'nosniff')
            self.send_header('Referrer-Policy', 'no-referrer')
            # Account quota is shared by all protocols; stale data is never advertised as live.
            if traffic and traffic.get('status') == 'ok':
                try:
                    used, total, reset = (int(traffic[k]) for k in ('used_bytes', 'total_bytes', 'reset_at'))
                    self.send_header('Subscription-Userinfo', f'upload=0; download={used}; total={total}')
                except (ValueError, KeyError, TypeError):
                    pass
            self.end_headers()
            self.wfile.write(content)

    return ThreadingHTTPServer((host, port), Handler)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--export', type=Path, default=Path('/etc/sui-vps/export.json'))
    parser.add_argument('--port', type=int, default=8090)
    parser.add_argument('--no-provider', action='store_true', help='Use the embedded root-refreshed traffic snapshot; never read provider credentials')
    parser.add_argument('--traffic-credentials', type=Path, default=Path('/etc/sui-vps/kiwivm.json'))
    parser.add_argument('--traffic-cache', type=Path, default=Path('/etc/sui-vps/traffic.json'))
    args = parser.parse_args()
    server = make_server(args.export, port=args.port,
                         traffic_credentials=None if args.no_provider else args.traffic_credentials,
                         traffic_cache=None if args.no_provider else args.traffic_cache)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        server.server_close()


if __name__ == '__main__':
    main()
