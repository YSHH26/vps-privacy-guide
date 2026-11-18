#!/usr/bin/env python3
"""Private client subscriptions derived from verified S-UI export facts.

Run behind the deployment's HTTPS reverse proxy. Never log token-bearing URLs.
Surge syntax: https://manual.nssurge.com/policies/anytls.html
TLS syntax: https://manual.nssurge.com/policies/tls.html
Mihomo syntax: https://wiki.metacubex.one/en/config/
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
CLIENTS = ('surge', 'v2ray', 'clash')
FILENAMES = {'surge': 'surge.conf', 'v2ray': 'v2ray.txt', 'clash': 'clash.yaml'}
RULES_DIR = Path('/var/lib/sui-vps/rules')
GEO_FILES = ('geosite.dat', 'geoip.metadb')
PRIVATE_CIDRS = ('10.0.0.0/8', '100.64.0.0/10', '127.0.0.0/8', '169.254.0.0/16', '172.16.0.0/12',
                 '192.168.0.0/16', 'fc00::/7', 'fe80::/10')
GIB = 1024 ** 3


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


def clash_proxies(config):
    proxies = []
    for node in config['nodes']:
        host, port, sni = checked_node(node)
        if node['type'] in ('vless-reality', 'vless-tls'):
            proxy = {'name': atom(node.get('name') or node['type']), 'type': 'vless', 'server': host, 'port': port,
                     'uuid': str(uuid.UUID(node['uuid'])), 'network': 'tcp', 'udp': True, 'tls': True,
                     'servername': sni, 'skip-cert-verify': False, 'client-fingerprint': 'chrome'}
            flow = node.get('flow') or ('xtls-rprx-vision' if node['type'] == 'vless-reality' else '')
            if flow:
                proxy['flow'] = atom(flow)
            if node['type'] == 'vless-reality':
                key, short_id = atom(node['public_key']), str(node['short_id'])
                if not re.fullmatch(r'[A-Za-z0-9_-]{43}', key) or not re.fullmatch(r'(?:[0-9a-fA-F]{2}){0,8}', short_id):
                    raise ValueError('Invalid Reality public key or short ID')
                proxy['reality-opts'] = {'public-key': key, 'short-id': short_id}
        elif node['type'] == 'anytls':
            proxy = {'name': atom(node.get('name') or node['type']), 'type': 'anytls', 'server': host, 'port': port,
                     'password': atom(node['password']), 'udp': True, 'sni': sni,
                     'skip-cert-verify': False, 'client-fingerprint': 'chrome'}
        else:
            continue
        proxies.append(proxy)
    if len(proxies) != 3 or len({p['name'] for p in proxies}) != 3:
        raise ValueError('Clash needs three distinctly named exported nodes')
    return proxies


def clash_config(config):
    """Mihomo profile. JSON is valid YAML, so json.dumps does all quoting/escaping."""
    urls = subscription_urls(config)
    server = str(ipaddress.IPv4Address(config['nodes'][0]['server']))
    proxies = clash_proxies(config)
    names = [p['name'] for p in proxies]
    order = {'vless-reality': 0, 'vless-tls': 1, 'anytls': 2}
    fallback = [n['name'] if n.get('name') else n['type'] for n in sorted(config['nodes'], key=lambda n: order[n['type']])]
    geo = urls['clash'].rsplit('/', 1)[0] + '/geo/'
    foreign_doh = ['https://1.1.1.1/dns-query', 'https://8.8.8.8/dns-query']
    china_doh = ['https://223.5.5.5/dns-query', 'https://120.53.53.53/dns-query']
    rules = [f'IP-CIDR,{server}/32,DIRECT,no-resolve']
    rules += [('IP-CIDR6,' if ':' in cidr else 'IP-CIDR,') + cidr + ',DIRECT,no-resolve' for cidr in PRIVATE_CIDRS]
    rules += ['GEOSITE,category-ai-!cn,AI', 'GEOSITE,cn,DIRECT', 'GEOIP,CN,DIRECT,no-resolve', 'MATCH,PROXY']
    profile = {
        'mixed-port': 7890, 'allow-lan': False, 'mode': 'rule', 'log-level': 'warning',
        # Keep IPv6 on so a TUN captures it; DNS returns no AAAA and the server rejects IPv6 egress.
        'ipv6': True, 'unified-delay': True,
        'geodata-mode': False, 'geo-auto-update': True, 'geo-update-interval': 24,
        'geox-url': {'geosite': geo + 'geosite.dat', 'mmdb': geo + 'geoip.metadb'},
        'dns': {'enable': True, 'ipv6': False, 'enhanced-mode': 'fake-ip', 'fake-ip-range': '198.18.0.1/16',
                'fake-ip-filter': ['+.lan', '+.local', '+.msftconnecttest.com', '+.msftncsi.com'],
                'respect-rules': True, 'default-nameserver': ['223.5.5.5', '120.53.53.53'],
                'proxy-server-nameserver': china_doh, 'nameserver': foreign_doh,
                'nameserver-policy': {'geosite:cn': china_doh}},
        'proxies': proxies,
        'proxy-groups': [
            {'name': 'PROXY', 'type': 'select', 'proxies': ['AUTO', *names]},
            {'name': 'AUTO', 'type': 'fallback', 'proxies': fallback,
             'url': 'https://www.gstatic.com/generate_204', 'interval': 300, 'lazy': True},
            {'name': 'AI', 'type': 'select', 'proxies': ['PROXY', *names]}],
        'rules': rules}
    return ('# Managed by sui-vps. Rule mode + TUN is required for WebRTC/DNS protection.\n'
            '# Real clients, DNS, IPv6, WebRTC and failure behavior still need testing.\n'
            + json.dumps(profile, ensure_ascii=False, indent=1) + '\n')


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
    for client in CLIENTS:
        if not TOKEN_RE.fullmatch(tokens[client]):
            raise ValueError('Subscription token must contain at least 256 random bits')
    if len({tokens[client] for client in CLIENTS}) != len(CLIENTS):
        raise ValueError('Use independent client subscription tokens')
    return {client: f'{base}/s/{tokens[client]}/{FILENAMES[client]}' for client in CLIENTS}


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


def period_bounds(now, reset_day):
    """Local-time period start/next reset for a monthly reset day (1-28)."""
    local = time.localtime(now)
    year, month = local.tm_year, local.tm_mon
    if local.tm_mday < reset_day:
        year, month = (year - 1, 12) if month == 1 else (year, month - 1)
    start = time.mktime((year, month, reset_day, 0, 0, 0, 0, 0, -1))
    ny, nm = (year + 1, 1) if month == 12 else (year, month + 1)
    return start, time.mktime((ny, nm, reset_day, 0, 0, 0, 0, 0, -1))


def traffic_settings(target):
    quota = float(target.get('traffic_quota_gb', 1000))
    reset_day = int(target.get('traffic_reset_day', 1))
    count = target.get('traffic_count', 'both')
    if not 0 < quota <= 1_000_000 or not 1 <= reset_day <= 28 or count not in ('both', 'out', 'in', 'max'):
        raise ValueError('Invalid local traffic settings')
    return quota, reset_day, count


def local_traffic_snapshot(state_path, counters, target, *, now=None, calibrate_gb=None):
    """Interface byte counters accumulated across reboots; resets on the configured day."""
    now = time.time() if now is None else now
    quota, reset_day, count = traffic_settings(target)
    rx, tx = (int(x) for x in counters)
    if rx < 0 or tx < 0:
        raise ValueError('Invalid interface counters')
    with TRAFFIC_LOCK:
        try:
            state = json.loads(Path(state_path).read_text())
        except (OSError, ValueError):
            state = {}
        start, reset_at = period_bounds(now, reset_day)
        if state.get('period_start') != start:
            # Keep the last raw counters so bytes since the previous sample count toward the new period.
            state = {'period_start': start, 'rx': 0, 'tx': 0, 'calibrated_bytes': 0,
                     **{k: state[k] for k in ('last_rx', 'last_tx') if k in state}}
        for key, value in (('rx', rx), ('tx', tx)):
            last = state.get('last_' + key)
            # A smaller counter means the interface or host restarted: count from zero.
            delta = value if last is None or value < last else value - last
            state[key] = int(state.get(key, 0)) + (delta if last is not None else 0)
            state['last_' + key] = value
        if calibrate_gb is not None:
            if not 0 <= float(calibrate_gb) <= 1_000_000:
                raise ValueError('Invalid calibration')
            state.update(rx=0, tx=0, calibrated_bytes=int(float(calibrate_gb) * GIB), calibrated_at=now)
        measured = {'both': state['rx'] + state['tx'], 'out': state['tx'], 'in': state['rx'],
                    'max': max(state['rx'], state['tx'])}[count]
        private_json(state_path, state)
    return {'source': 'local-interface', 'status': 'ok', 'count': count,
            'total_bytes': int(quota * GIB), 'used_bytes': int(state.get('calibrated_bytes', 0)) + measured,
            'reset_at': int(reset_at), 'updated_at': now, 'checked_at': now}


def make_server(export_path, host='127.0.0.1', port=8090, traffic_credentials=None, traffic_cache=None,
                rules_dir=RULES_DIR):
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
                geo = re.fullmatch(r'/s/([A-Za-z0-9_-]{43,128})/geo/(geosite\.dat|geoip\.metadb)', self.path)
                if geo:
                    if not hmac.compare_digest(geo.group(1), cfg['subscriptions']['clash']):
                        self.reply(404, b'Not found\n')
                        return
                    data = (Path(rules_dir) / geo.group(2)).read_bytes()
                    if not data:
                        raise ValueError('Empty rule data')
                    self.reply(200, data, content_type='application/octet-stream')
                    return
                match = re.fullmatch(r'/s/([A-Za-z0-9_-]{43,128})/(surge\.conf|v2ray\.txt|clash\.yaml)', self.path)
                if not match:
                    self.reply(404, b'Not found\n')
                    return
                token, filename = match.groups()
                client = next(name for name, value in FILENAMES.items() if value == filename)
                if not hmac.compare_digest(token, cfg['subscriptions'][client]):
                    self.reply(404, b'Not found\n')
                    return
                content = {'surge': surge_config, 'v2ray': v2ray_subscription, 'clash': clash_config}[client](cfg)
                traffic = traffic_snapshot(traffic_credentials, traffic_cache) if traffic_credentials and traffic_cache else cfg.get('traffic', {})
                self.reply(200, content.encode(), traffic, clash=client == 'clash')
            except (OSError, ValueError, KeyError, TypeError):
                self.reply(503, b'Subscription temporarily unavailable\n')

        def do_HEAD(self):
            self.reply(405, b'')

        def reply(self, code, content, traffic=None, *, content_type='text/plain; charset=utf-8', clash=False):
            self.send_response(code)
            self.send_header('Content-Type', content_type)
            if clash:
                self.send_header('Profile-Update-Interval', '24')
                self.send_header('Content-Disposition', 'attachment; filename="sui-vps.yaml"')
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
