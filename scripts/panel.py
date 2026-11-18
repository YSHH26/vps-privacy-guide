#!/usr/bin/env python3
"""Configure S-UI v1.6.6 through its authenticated local HTTP API only.

Contract verified against alireza0/s-ui v1.6.6, commit
 d50238fe4cb17bac34b17141421f2111b70014cd:
 api/apiService.go (form fields, response envelopes), api/apiHandler.go,
 database/model/{model,inbounds}.go (public API objects), service/client.go,
 service/server.go (Reality keypair), middleware/csrf.go.
 go.mod pins the embedded sing-box to v1.14.4. This source fact does not
 substitute for a deployment's image/binary or end-to-end verification.

Only state/export paths contain credentials. CLI prints no API response bodies.
"""
import argparse
import http.cookiejar
import ipaddress
import json
import os
from pathlib import Path
import secrets
import tempfile
import time
import urllib.error
import urllib.parse
import urllib.request
import uuid


class PanelError(RuntimeError):
    pass


class PanelTransportError(PanelError):
    pass


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        raise PanelError('S-UI unexpectedly redirected; check its configured web path')


class PanelAPI:
    def __init__(self, base_url='http://127.0.0.1:2095/app/'):
        parsed = urllib.parse.urlsplit(base_url)
        if parsed.scheme != 'http' or parsed.hostname not in ('127.0.0.1', '::1') or parsed.username or parsed.password or parsed.query or parsed.fragment:
            raise PanelError('The S-UI API must use a literal loopback HTTP address')
        self.base_url = base_url.rstrip('/') + '/'
        self.opener = urllib.request.build_opener(
            urllib.request.ProxyHandler({}),
            urllib.request.HTTPCookieProcessor(http.cookiejar.CookieJar()), NoRedirect())

    def call(self, action, form=None, raw=False):
        data = urllib.parse.urlencode(form).encode() if form is not None else None
        req = urllib.request.Request(self.base_url + 'api/' + action, data=data,
                                     headers={'X-Requested-With': 'XMLHttpRequest',
                                              'Accept': 'application/json'})
        try:
            with self.opener.open(req, timeout=30) as response:
                obj = json.load(response)
        except (urllib.error.URLError, ValueError, OSError) as exc:
            # The upstream error may contain user input or secrets: never echo it.
            raise PanelTransportError('S-UI API request failed for ' + action.split('?')[0]) from None
        if raw:
            return obj
        if not isinstance(obj, dict) or obj.get('success') is not True:
            raise PanelError('S-UI rejected action ' + action.split('?')[0])
        return obj.get('obj')


def login(api, username, password):
    # The upstream container healthcheck can pass before HTTP initialization.
    # Retry only transport failures; never hammer rejected passwords.
    for attempt in range(20):
        try:
            return api.call('login', {'user': username, 'pass': password})
        except PanelTransportError:
            if attempt == 19:
                raise
            time.sleep(0.25)


def secure_json(path, data):
    path = Path(path)
    if path.is_symlink():
        raise PanelError('Refusing a symlink as a state/export file')
    path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    fd, temporary = tempfile.mkstemp(prefix='.' + path.name, dir=path.parent)
    try:
        os.fchmod(fd, 0o600)
        with os.fdopen(fd, 'w') as stream:
            json.dump(data, stream, indent=2, ensure_ascii=False)
            stream.write('\n')
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary, path)
    finally:
        if os.path.exists(temporary):
            os.unlink(temporary)


def rows(api, obj):
    result = api.call(obj)
    return result.get(obj, []) or []


def same_subset(existing, wanted):
    return all(existing.get(k) == v for k, v in wanted.items())


def upsert(api, obj, wanted, identity):
    matches = [x for x in rows(api, obj) if x.get(identity) == wanted[identity]]
    if len(matches) > 1:
        raise PanelError('Duplicate managed S-UI object: ' + obj)
    existing = matches[0] if matches else None
    if existing and obj in ('inbounds', 'clients'):
        existing = (api.call(obj + '?id=' + str(existing['id']))[obj] or [])[0]
    if existing and same_subset(existing, wanted):
        return existing
    data = dict(existing or {})
    data.update(wanted)
    if obj == 'clients' and not existing:
        data.setdefault('links', [])  # Required RawMessage by v1.6.6 link regeneration.
    api.call('save', {'object': obj, 'action': 'edit' if existing else 'new',
                      'data': json.dumps(data), 'initUsers': ''})
    matches = [x for x in rows(api, obj) if x.get(identity) == wanted[identity]]
    if len(matches) != 1:
        raise PanelError('S-UI object could not be read back: ' + obj)
    return matches[0]


RESOLVER_TAG = 'sui-vps-resolver'
IPV6_REJECT = {'ip_cidr': ['::/0'], 'action': 'reject'}


def apply_ipv4_only(base_config):
    """Proxy egress uses IPv4 only: resolve A records and reject literal IPv6 destinations.

    Only values this tool created are rewritten; an operator's own resolver is kept as-is.
    """
    dns = base_config.setdefault('dns', {})
    if not dns.get('servers'):
        dns['servers'] = [{'type': 'udp', 'tag': RESOLVER_TAG, 'server': '1.1.1.1'}]
    route = base_config.setdefault('route', {})
    resolver = route.get('default_domain_resolver')
    if resolver is None:
        resolver = dns['servers'][0]['tag']
    if isinstance(resolver, str):
        route['default_domain_resolver'] = {'server': resolver, 'strategy': 'ipv4_only'} if resolver == RESOLVER_TAG else resolver
    route.setdefault('final', 'sui-vps-direct')
    rules = route.setdefault('rules', [])
    if IPV6_REJECT not in rules:
        rules.insert(0, dict(IPV6_REJECT))
    return base_config


def check_ipv4_only(core_config):
    route = core_config.get('route', {})
    resolver = route.get('default_domain_resolver')
    if not isinstance(resolver, dict) or resolver.get('strategy') != 'ipv4_only':
        raise PanelError('Generated core does not resolve proxy destinations as IPv4 only')
    if IPV6_REJECT not in route.get('rules', []):
        raise PanelError('Generated core does not reject IPv6 destinations')


def configure(state_path='/etc/sui-vps/state.json', *, api=None,
              base_url='http://127.0.0.1:2095/app/',
              cert_path='/app/cert/fullchain.pem', key_path='/app/cert/privkey.pem',
              export_path=None):
    state_path = Path(state_path)
    if state_path.is_symlink():
        raise PanelError('Refusing a symlink state file')
    state = json.loads(state_path.read_text())
    try:
        host = str(ipaddress.ip_address(state['ip']))
    except (ValueError, KeyError):
        raise PanelError('state.json requires a valid public server IP') from None
    panel = state.setdefault('panel', {'username': 'admin_' + secrets.token_hex(8),
                                       'password': secrets.token_urlsafe(32),
                                       'initialized': False})
    state.setdefault('client', {'name': 'owner_' + secrets.token_hex(12),
                                'uuid': str(uuid.uuid4()), 'password': secrets.token_urlsafe(32)})
    secure_json(state_path, state)  # Persist BEFORE changing credentials (crash recovery).
    api = api or PanelAPI(base_url)
    try:
        login(api, panel['username'], panel['password'])
    except PanelError:
        if panel.get('initialized'):
            raise
        login(api, 'admin', 'admin')
        api.call('changePass', {'oldPass': 'admin', 'newUsername': panel['username'],
                                'newPass': panel['password']})
        login(api, panel['username'], panel['password'])
    panel['initialized'] = True
    secure_json(state_path, state)
    if 'reality' not in state:
        pair = api.call('keypairs?k=reality')
        if not isinstance(pair, list) or len(pair) != 2 or not pair[0].startswith('PrivateKey: ') or not pair[1].startswith('PublicKey: '):
            raise PanelError('Unexpected S-UI Reality keypair response')
        state['reality'] = {'private_key': pair[0].split(': ', 1)[1],
                            'public_key': pair[1].split(': ', 1)[1],
                            'short_id': secrets.token_hex(8),
                            'server_name': 'www.microsoft.com'}
        secure_json(state_path, state)
    reality, client = state['reality'], state['client']
    settings = api.call('settings')
    public_base = state.get('public_base_url', 'https://' + ('[' + host + ']' if ':' in host else host) + ':9443').rstrip('/')
    desired_settings = {'timeLocation': state.get('timezone', 'UTC'),
                        'webURI': public_base + '/app/', 'subShowInfo': 'false'}
    if not same_subset(settings, desired_settings):
        api.call('save', {'object': 'settings', 'action': 'edit', 'data': json.dumps(desired_settings)})
    # Keep the operator's other base settings; fill only missing defaults.
    upsert(api, 'outbounds', {'type': 'direct', 'tag': 'sui-vps-direct'}, 'tag')
    base_config = api.call('config')['config']
    original_config = json.dumps(base_config, sort_keys=True)
    apply_ipv4_only(base_config)
    if json.dumps(base_config, sort_keys=True) != original_config:
        api.call('save', {'object': 'config', 'action': 'edit', 'data': json.dumps(base_config)})
    tls_objects = [
        {'name': 'sui-vps-reality',
         'server': {'enabled': True, 'server_name': reality['server_name'],
                    'reality': {'enabled': True, 'handshake': {'server': reality['server_name'], 'server_port': 443},
                                'private_key': reality['private_key'], 'short_id': [reality['short_id']]}},
         'client': {'enabled': True, 'server_name': reality['server_name'],
                    'utls': {'enabled': True, 'fingerprint': 'chrome'},
                    'reality': {'enabled': True, 'public_key': reality['public_key'], 'short_id': reality['short_id']}}},
        {'name': 'sui-vps-trusted-tls',
         'server': {'enabled': True, 'certificate_path': cert_path, 'key_path': key_path},
         'client': {'enabled': True, 'server_name': host}},
    ]
    tls_ids = [upsert(api, 'tls', item, 'name')['id'] for item in tls_objects]
    ports = state.get('ports', {})
    specs = [('vless', 'sui-vps-reality', int(ports.get('reality', 443)), tls_ids[0]),
             ('vless', 'sui-vps-vless-tls', int(ports.get('vless_tls', 2443)), tls_ids[1]),
             ('anytls', 'sui-vps-anytls', int(ports.get('anytls', 8443)), tls_ids[1])]
    if len({x[2] for x in specs}) != 3 or any(not 1 <= x[2] <= 65535 for x in specs):
        raise PanelError('Node TCP ports must be distinct valid ports')
    inbounds = []
    for kind, tag, port, tls_id in specs:
        # Publishing addresses are explicit; internal API Host is loopback.
        wanted = {'type': kind, 'tag': tag, 'listen': '::', 'listen_port': port,
                  'tls_id': tls_id, 'addrs': [{'server': host, 'server_port': port}], 'out_json': {}}
        # out_json is generated by S-UI, so exclude it from equality detection.
        matches = [x for x in rows(api, 'inbounds') if x['tag'] == tag]
        if matches:
            full = api.call('inbounds?id=' + str(matches[0]['id']))['inbounds'][0]
            wanted['out_json'] = full.get('out_json') or {}
        inbounds.append(upsert(api, 'inbounds', wanted, 'tag'))
    user_config = {'vless': {'name': client['name'], 'uuid': client['uuid'], 'flow': 'xtls-rprx-vision'},
                   'anytls': {'name': client['name'], 'password': client['password']}}
    upsert(api, 'clients', {'name': client['name'], 'enable': True, 'config': user_config,
                            'inbounds': [x['id'] for x in inbounds], 'volume': 0, 'expiry': 0}, 'name')
    # Export only facts read through the panel's generated core configuration.
    core_config = api.call('singbox-config', raw=True)
    check_ipv4_only(core_config)
    actual = {x['tag']: x for x in core_config.get('inbounds', [])}
    nodes = []
    for (kind, tag, port, tls_id), node_type in zip(specs, ('vless-reality', 'vless-tls', 'anytls')):
        inbound = actual.get(tag, {})
        users = [x for x in inbound.get('users', []) if x.get('name') == client['name']]
        if inbound.get('type') != kind or inbound.get('listen_port') != port or len(users) != 1:
            raise PanelError('Generated S-UI configuration failed readback verification')
        user, tls = users[0], inbound.get('tls', {})
        expected_tls = tls_objects[0 if node_type == 'vless-reality' else 1]['server']
        if not same_subset(tls, expected_tls) or not same_subset(user, user_config[kind]):
            raise PanelError('Generated S-UI credentials/TLS differ from intended configuration')
        node = {'type': node_type, 'name': tag, 'server': host, 'port': inbound['listen_port']}
        if kind == 'vless':
            node.update(uuid=user['uuid'], flow=user.get('flow', ''))
        else:
            node['password'] = user['password']
        if node_type == 'vless-reality':
            node.update(server_name=tls['server_name'], public_key=reality['public_key'],
                        short_id=tls['reality']['short_id'][0])
        else:
            node['server_name'] = host
        nodes.append(node)
    status = api.call('status?r=sbd')
    if status.get('sbd', {}).get('running') is not True:
        raise PanelError('S-UI reports that its embedded core is stopped')
    export_path = Path(export_path) if export_path else state_path.with_name('export.json')
    if export_path.is_symlink():
        raise PanelError('Refusing a symlink export file')
    exported = json.loads(export_path.read_text()) if export_path.exists() else {}
    exported.update(server={'host': host, 'ssh_alias': state.get('ssh_alias', ''),
                            'timezone': state.get('timezone', 'UTC'),
                            'deployed_at': state.get('deployed_at', ''),
                            'versions': state.get('versions', {})},
                    nodes=nodes, panel={'url': public_base + '/app/',
                                        'username': panel['username'], 'password': panel['password']})
    secure_json(export_path, exported)
    return exported


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--state', default='/etc/sui-vps/state.json')
    parser.add_argument('--base-url', default='http://127.0.0.1:2095/app/')
    parser.add_argument('--cert-path', default='/app/cert/fullchain.pem')
    parser.add_argument('--key-path', default='/app/cert/privkey.pem')
    parser.add_argument('--export')
    args = parser.parse_args()
    try:
        configure(args.state, base_url=args.base_url, cert_path=args.cert_path,
                  key_path=args.key_path, export_path=args.export)
    except PanelError as exc:
        # PanelError messages are authored locally, never upstream bodies.
        print(str(exc), file=__import__('sys').stderr)
        return 1
    except (OSError, ValueError, KeyError):
        print('S-UI configuration failed; check state and certificate paths.', file=__import__('sys').stderr)
        return 1
    print('S-UI configuration and private export verified.')
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
