#!/usr/bin/env python3
"""Validate exported nodes locally with the repository's digest-pinned client core.

No host proxy settings are changed. A temporary Docker client has exactly one
outbound; each node is tested with valid credentials, invalid credentials and
restored credentials. HTTPS retains system trust and loads the pinned Mozilla bundle only if Python
has no trusted CA roots. Proxy TLS uses the reviewed core normal trust store.
Reports cover these network requests only, not real clients or leak prevention.
"""
import argparse
import contextlib
import datetime
import http.client
import hashlib
import ipaddress
import json
import os
import platform
from pathlib import Path
import re
import secrets
import socket
import ssl
import stat
import struct
import subprocess
import tempfile
import time
from urllib.parse import urlsplit
import uuid

ROOT = Path(__file__).resolve().parents[1]
TYPES = ('vless-reality', 'vless-tls', 'anytls')


class ProbeError(RuntimeError):
    """Locally authored, credential-free diagnostic."""


def private_file(path, *, existing=True):
    path = Path(path).expanduser().absolute()
    if any(part.is_symlink() and str(part) not in ('/tmp', '/var', '/etc') for part in (path, *path.parents)):
        raise ProbeError('Private files must not be symlinks')
    if existing:
        info = path.stat()
        if not stat.S_ISREG(info.st_mode) or info.st_mode & 0o077 or info.st_uid != os.getuid():
            raise ProbeError('Input must be your private regular file with mode 600')
    return path


def write_report(path, report):
    path = private_file(path, existing=False)
    path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    if path.parent.stat().st_uid != os.getuid() or path.parent.stat().st_mode & 0o077:
        raise ProbeError('Report parent directory must be owned by you with mode 700')
    fd, temporary = tempfile.mkstemp(dir=path.parent, prefix='.'+path.name+'-')
    try:
        with os.fdopen(fd, 'w') as output:
            json.dump(report, output, ensure_ascii=False, indent=2)
            output.write('\n')
            output.flush()
            os.fsync(output.fileno())
        os.replace(temporary, path)
    finally:
        if os.path.exists(temporary):
            os.unlink(temporary)


def endpoint(url):
    if not isinstance(url, str) or any(ord(char) < 33 for char in url):
        raise ProbeError('Probe endpoints must be valid HTTPS URLs')
    parsed = urlsplit(url)
    if parsed.scheme != 'https' or not parsed.hostname or parsed.username or parsed.password or parsed.fragment:
        raise ProbeError('Probe endpoints require HTTPS without credentials or fragments')
    try:
        port = parsed.port or 443
        if not 1 <= port <= 65535:
            raise ValueError()
        parsed.hostname.encode('idna')
    except (ValueError, UnicodeError):
        raise ProbeError('Invalid HTTPS endpoint host or port') from None
    return parsed


def fingerprint(config):
    """Bind observations to the exact nodes, deployment and recorded versions."""
    try:
        facts = {'nodes': config['nodes'],
                 'server': {key: config['server'].get(key) for key in ('host', 'deployed_at', 'versions')}}
        canonical = json.dumps(facts, sort_keys=True, separators=(',', ':'), ensure_ascii=False).encode()
    except (KeyError, TypeError, ValueError):
        raise ProbeError('Cannot fingerprint malformed exported node facts') from None
    return hashlib.sha256(canonical).hexdigest()


def client_config(node, *, wrong=False):
    if node.get('type') not in TYPES:
        raise ProbeError('Unsupported exported node type')
    if any(node.get(key) for key in ('insecure', 'skip-cert-verify', 'allowInsecure')):
        raise ProbeError('Export disables certificate verification')
    try:
        host = str(ipaddress.IPv4Address(node['server']))
        port = int(node['port'])
        if not 1 <= port <= 65535:
            raise ValueError()
        server_name = str(node['server_name'])
        if not server_name or any(ord(c) < 33 for c in server_name):
            raise ValueError()
        outbound = {'type': 'anytls' if node['type'] == 'anytls' else 'vless',
                    'tag': 'selected', 'server': host, 'server_port': port,
                    'tls': {'enabled': True, 'server_name': server_name}}
        if node['type'] == 'anytls':
            if not isinstance(node['password'], str) or not node['password']:
                raise ValueError()
            outbound['password'] = secrets.token_urlsafe(32) if wrong else node['password']
        else:
            identity = str(uuid.UUID(node['uuid']))
            outbound['uuid'] = str(uuid.uuid4()) if wrong else identity
            if node.get('flow'):
                if node['flow'] != 'xtls-rprx-vision':
                    raise ValueError()
                outbound['flow'] = node['flow']
        if node['type'] == 'vless-reality':
            if not re.fullmatch(r'[A-Za-z0-9_-]{43}', node['public_key']) or not re.fullmatch(r'(?:[0-9a-fA-F]{2}){1,8}', node['short_id']):
                raise ValueError()
            outbound['tls'].update(utls={'enabled': True, 'fingerprint': 'chrome'},
                                   reality={'enabled': True, 'public_key': node['public_key'], 'short_id': node['short_id']})
    except (KeyError, TypeError, ValueError):
        raise ProbeError('Invalid exported node fields') from None
    return {'log': {'level': 'error'},
            'inbounds': [{'type': 'mixed', 'tag': 'local', 'listen': '0.0.0.0', 'listen_port': 1080}],
            'outbounds': [outbound], 'route': {'final': 'selected'}}


def https_context():
    """Retain existing trust; populate an empty Python store with pinned roots."""
    context = ssl.create_default_context()
    if context.cert_store_stats().get('x509_ca', 0) == 0:
        try:
            import certifi
        except ImportError:
            raise ProbeError('Python HTTPS trust store is empty; install requirements-local.txt in the project virtual environment') from None
        if certifi.__version__ != '2026.10.23':
            raise ProbeError('Empty Python HTTPS trust store requires the pinned certifi in requirements-local.txt')
        try:
            context.load_verify_locations(cafile=certifi.where())
        except (OSError, ssl.SSLError):
            raise ProbeError('Pinned Mozilla CA bundle could not be loaded') from None
        if context.cert_store_stats().get('x509_ca', 0) == 0:
            raise ProbeError('Pinned Mozilla CA bundle did not populate Python HTTPS trust')
    if context.verify_mode != ssl.CERT_REQUIRED or not context.check_hostname:
        raise ProbeError('HTTPS certificate and hostname verification must stay enabled')
    return context


def receive(stream, length):
    result = b''
    while len(result) < length:
        part = stream.recv(length-len(result))
        if not part:
            raise EOFError()
        result += part
    return result


class LocalSession:
    def __init__(self, backend, name, address):
        self.backend, self.name = backend, name
        host, port = address.rsplit(':', 1)
        if host != '127.0.0.1':
            raise ProbeError('Client proxy was not published exclusively on loopback')
        self.address = (host, int(port))

    def healthy(self):
        running = self.backend.command(['inspect', '--format', '{{.State.Running}}', self.name])
        if running.strip() != 'true':
            return False
        try:
            with socket.create_connection(self.address, timeout=0.5) as stream:
                stream.sendall(b'\x05\x01\x00')
                return receive(stream, 2) == b'\x05\x00'
        except (OSError, EOFError):
            return False

    def request(self, url):
        target = endpoint(url)
        stream = None
        stage = 'proxy'
        try:
            stream = socket.create_connection(self.address, timeout=self.backend.timeout)
            stream.sendall(b'\x05\x01\x00')
            if receive(stream, 2) != b'\x05\x00':
                return {'ok': False, 'error': 'proxy_unhealthy'}
            stage = 'connect'
            try:
                literal = ipaddress.ip_address(target.hostname)
            except ValueError:
                literal = None
            if literal is not None:
                # Literal addresses use SOCKS address types so the server sees an IP destination.
                kind = b'\x01' if literal.version == 4 else b'\x04'
                stream.sendall(b'\x05\x01\x00' + kind + literal.packed + struct.pack('!H', target.port or 443))
            else:
                hostname = target.hostname.encode('idna')
                if len(hostname) > 255:
                    raise ProbeError('HTTPS hostname exceeds SOCKS5 limit')
                stream.sendall(b'\x05\x01\x00\x03' + bytes([len(hostname)]) + hostname + struct.pack('!H', target.port or 443))
            reply = receive(stream, 4)
            if reply[0] != 5:
                return {'ok': False, 'error': 'proxy_invalid_reply'}
            if reply[1] != 0:
                return {'ok': False, 'error': 'proxy_rejected'}
            if reply[3] == 1:
                receive(stream, 4)
            elif reply[3] == 4:
                receive(stream, 16)
            elif reply[3] == 3:
                receive(stream, receive(stream, 1)[0])
            else:
                return {'ok': False, 'error': 'proxy_invalid_reply'}
            receive(stream, 2)
            stage = 'tls'
            stream = https_context().wrap_socket(stream, server_hostname=target.hostname)
            stage = 'https'
            host_header = target.netloc.encode('idna').decode('ascii')
            path = target.path or '/'
            if target.query:
                path += '?' + target.query
            stream.sendall(('GET '+path+' HTTP/1.1\r\nHost: '+host_header+'\r\nConnection: close\r\nUser-Agent: sui-vps-network-probe/1\r\n\r\n').encode('ascii'))
            response = http.client.HTTPResponse(stream)
            response.begin()
            body = response.read(65537)
            if len(body) > 65536:
                return {'ok': False, 'error': 'response_too_large'}
            return {'ok': 200 <= response.status < 300, 'status': response.status,
                    'body': body, **({} if 200 <= response.status < 300 else {'error': 'https_status'})}
        except socket.timeout:
            return {'ok': False, 'error': 'request_timeout'}
        except ssl.SSLCertVerificationError:
            return {'ok': False, 'error': 'https_certificate_rejected'}
        except (EOFError, ConnectionResetError, ssl.SSLEOFError):
            return {'ok': False, 'error': 'proxy_closed' if stage == 'connect' else 'tls_transport_closed' if stage == 'tls' else 'connection_closed'}
        except (OSError, ssl.SSLError, http.client.HTTPException, ValueError, UnicodeError):
            return {'ok': False, 'error': 'request_failed'}
        finally:
            if stream is not None:
                stream.close()


class DockerBackend:
    def __init__(self, timeout=20, expected_version=None):
        self.timeout = timeout
        self.expected_version = expected_version
        self.observed_version = None
        self.image = None

    def command(self, args, *, timeout=60):
        try:
            process = subprocess.run(['docker', *args], stdout=subprocess.PIPE,
                                     stderr=subprocess.PIPE, timeout=timeout, check=False)
        except FileNotFoundError:
            raise ProbeError('Docker CLI is required; install and start Docker before probing') from None
        except (OSError, subprocess.TimeoutExpired):
            raise ProbeError('Docker command failed or timed out') from None
        if process.returncode:
            raise ProbeError('Docker command failed: '+args[0])
        return process.stdout.decode(errors='replace').strip()

    def prepare(self, image):
        if not re.fullmatch(r'[^\s@]+@sha256:[a-f0-9]{64}', image):
            raise ProbeError('The client core image must be pinned by SHA256 digest')
        try:
            self.command(['info', '--format', '{{.ServerVersion}}'])
        except ProbeError:
            raise ProbeError('Docker CLI and running Docker daemon are required; no fallback core is used') from None
        self.command(['pull', image], timeout=240)
        actual = self.command(['run', '--rm', '--network', 'none', image, 'version'])
        match = re.search(r'sing-box version (\S+)', actual)
        if not match or self.expected_version and match[1] != self.expected_version:
            raise ProbeError('Fixed client image runtime version does not match versions.json')
        self.observed_version = match[1]
        self.image = image

    @contextlib.contextmanager
    def session(self, config):
        name = 'sui-probe-' + uuid.uuid4().hex[:12]
        with tempfile.TemporaryDirectory(prefix='sui-probe-') as directory:
            path = Path(directory)/'client.json'
            write_report(path, config)
            # The bind mount contains a private directory and file. Match their
            # owner so a capability-free process can read them on Linux.
            common = ['--user', f'{os.getuid()}:{os.getgid()}',
                      '--cap-drop', 'ALL', '--security-opt', 'no-new-privileges',
                      '--read-only', '--pids-limit', '128', '--tmpfs', '/tmp:rw,noexec,nosuid,size=16m',
                      '-v', directory+':/work:ro']
            # A malformed/unsupported config must fail before any authentication assertion.
            self.command(['run', '--rm', '--network', 'none', *common,
                          self.image, 'check', '-c', '/work/client.json'])
            try:
                self.command(['run', '-d', '--name', name, '-p', '127.0.0.1::1080', *common,
                              self.image, 'run', '-c', '/work/client.json'])
                address = self.command(['port', name, '1080/tcp'])
                session = LocalSession(self, name, address)
                ready = False
                for attempt in range(80):
                    if session.healthy():
                        ready = True
                        break
                    time.sleep(0.1)
                if not ready:
                    raise ProbeError('client_start_failed')
                yield session
            finally:
                # Never print logs/configs: either may contain subscription credentials.
                try:
                    self.command(['rm', '-f', name])
                except ProbeError:
                    raise ProbeError('Temporary client cleanup failed; inspect containers named sui-probe-*') from None


class NativeSession(LocalSession):
    def __init__(self, backend, process, address):
        super().__init__(backend, 'native-client', address)
        self.process = process

    def healthy(self):
        if self.process.poll() is not None:
            return False
        try:
            with socket.create_connection(self.address, timeout=0.5) as stream:
                stream.sendall(b'\x05\x01\x00')
                return receive(stream, 2) == b'\x05\x00' and self.process.poll() is None
        except (OSError, EOFError):
            return False


class NativeBackend:
    """Explicit, pinned Darwin client only; never changes host proxy or TUN."""
    def __init__(self, core_bin, asset, expected_version, timeout=20):
        self.core_bin = Path(core_bin).expanduser().absolute()
        self.asset = asset
        self.expected_version = expected_version
        self.timeout = timeout
        self.observed_version = None

    def prepare(self, image=None):
        if platform.system() != 'Darwin' or platform.machine() != 'arm64':
            raise ProbeError('The reviewed native backend supports Darwin arm64 only')
        path = private_file(self.core_bin)
        if not os.access(path, os.X_OK):
            raise ProbeError('Reviewed native client binary must be executable')
        expected = self.asset.get('binary_sha256', '')
        if not re.fullmatch(r'[a-f0-9]{64}', expected) or hashlib.sha256(path.read_bytes()).hexdigest() != expected:
            raise ProbeError('Native client binary digest does not match the reviewed official asset')
        actual = self.command(['version'])
        match = re.search(r'sing-box version (\S+)', actual)
        if not match or match[1] != self.expected_version:
            raise ProbeError('Native client version does not match versions.json')
        self.observed_version = match[1]

    def command(self, args, timeout=30):
        try:
            result = subprocess.run([str(self.core_bin), *args], stdout=subprocess.PIPE,
                                    stderr=subprocess.PIPE, timeout=timeout, check=False)
        except (OSError, subprocess.SubprocessError):
            raise ProbeError('Native client command failed or timed out') from None
        if result.returncode:
            raise ProbeError('Native client configuration or version check failed')
        return result.stdout.decode(errors='replace')

    @contextlib.contextmanager
    def session(self, config):
        if not self.observed_version:
            raise ProbeError('Native client must be verified before starting')
        # Choose an ephemeral loopback port without changing the caller's config.
        local_config = json.loads(json.dumps(config))
        if len(local_config.get('outbounds', [])) != 1 or local_config.get('route', {}).get('final') != 'selected':
            raise ProbeError('Native probe requires exactly one forced outbound')
        inbounds = local_config.get('inbounds', [])
        if len(inbounds) != 1 or inbounds[0].get('type') != 'mixed':
            raise ProbeError('Native probe accepts only its generated mixed client listener')
        with socket.socket() as reservation:
            reservation.bind(('127.0.0.1', 0))
            port = reservation.getsockname()[1]
        local_config['inbounds'] = [{'type': 'mixed', 'tag': 'local', 'listen': '127.0.0.1', 'listen_port': port}]
        with tempfile.TemporaryDirectory(prefix='sui-native-probe-') as directory:
            path = Path(directory)/'client.json'
            write_report(path, local_config)
            self.command(['check', '-c', str(path)])
            process = None
            try:
                # Private logs remain temporary and are never emitted or persisted.
                with tempfile.TemporaryFile() as logs:
                    process = subprocess.Popen([str(self.core_bin), 'run', '-c', str(path)],
                                               stdin=subprocess.DEVNULL, stdout=logs, stderr=logs)
                    session = NativeSession(self, process, '127.0.0.1:'+str(port))
                    stable = 0
                    for attempt in range(100):
                        if process.poll() is not None:
                            raise ProbeError('Native client exited before readiness')
                        stable = stable+1 if session.healthy() else 0
                        if stable >= 3:
                            break
                        time.sleep(0.1)
                    if stable < 3:
                        raise ProbeError('Native client SOCKS5 readiness failed')
                    yield session
            except OSError:
                raise ProbeError('Native client could not be started') from None
            finally:
                if process is not None:
                    if process.poll() is None:
                        process.terminate()
                        try:
                            process.wait(timeout=5)
                        except subprocess.TimeoutExpired:
                            process.kill()
                            process.wait(timeout=5)
                    else:
                        process.wait()


# One AAAA-only hostname and one literal IPv6 address; the server must reach neither.
IPV6_URLS = ('https://ipv6.icanhazip.com/', 'https://[2606:4700:4700::1111]/')


def summarize(result):
    return {key: result[key] for key in ('ok', 'status', 'error') if key in result}


def probe(input_path, output_path, *, url='https://example.com/',
          exit_url='https://api.ipify.org/', timeout=20, backend=None,
          versions_path=None, core_bin=None, ipv6_urls=IPV6_URLS):
    targets = {'https': endpoint(url), 'exit': endpoint(exit_url)}
    targets.update({'ipv6_' + str(i + 1): endpoint(u) for i, u in enumerate(ipv6_urls)})
    if not 1 <= timeout <= 120:
        raise ProbeError('Request timeout must be between 1 and 120 seconds')
    source = private_file(input_path)
    if source == Path(output_path).expanduser().absolute():
        raise ProbeError('Network report must not overwrite the credential export')
    try:
        export_bytes = source.read_bytes()
        exported = json.loads(export_bytes)
        expected_ip = str(ipaddress.IPv4Address(exported['server']['host']))
        nodes = exported['nodes']
        if len(nodes) != 3 or {n['type'] for n in nodes} != set(TYPES):
            raise ValueError()
        if len({int(n['port']) for n in nodes}) != 3:
            raise ValueError()
        for node in nodes:
            if str(ipaddress.IPv4Address(node['server'])) != expected_ip:
                raise ValueError()
            client_config(node)
        versions = json.loads(Path(versions_path or ROOT/'versions.json').read_text())
        image = versions['sing_box_image']
    except (KeyError, TypeError, ValueError):
        raise ProbeError('Export must contain the server IPv4 and exactly three valid matching nodes') from None
    report = {'schema': 1, 'scope': 'local_fixed_core_network',
              'checked_at': datetime.datetime.now(datetime.timezone.utc).isoformat(),
              'status': 'failed', 'server_ipv4': expected_ip,
              'source_sha256': hashlib.sha256(export_bytes).hexdigest(),
              'endpoints': {key: {'host': value.hostname, 'port': value.port or 443,
                                  'path': value.path or '/'} for key, value in targets.items()},
              'certificate_verification': True,
              'node_fingerprint': fingerprint(exported),
              'core': {'version': versions['sing_box_version'], 'image': image}, 'nodes': [],
              'not_tested': ['Surge', 'v2rayN', 'v2rayNG', 'DNS leaks', 'IPv6 leaks',
                             'WebRTC', 'client failure behavior', 'UDP forwarding']}
    if backend == 'native':
        if not core_bin:
            raise ProbeError('Explicit native backend requires --core-bin with a reviewed private binary')
        asset = versions.get('sing_box_client_assets', {}).get('darwin-arm64')
        if not asset:
            raise ProbeError('No reviewed Darwin arm64 client asset is recorded')
        backend = NativeBackend(core_bin, asset, versions['sing_box_version'], timeout)
        report['core'] = {'backend': 'native', 'version': versions['sing_box_version'],
                          'asset_url': asset['url'], 'asset_sha256': asset['sha256'],
                          'binary_sha256': asset['binary_sha256']}
    elif backend in (None, 'docker'):
        if core_bin:
            raise ProbeError('--core-bin requires explicitly selecting the native backend')
        backend = DockerBackend(timeout, versions['sing_box_version'])
        report['core']['backend'] = 'docker'
    elif isinstance(backend, str):
        raise ProbeError('Unknown client backend')
    try:
        backend.prepare(image)
        if getattr(backend, 'observed_version', None):
            report['core']['observed_version'] = backend.observed_version
        for index, node in enumerate(nodes):
            row = {'index': index+1, 'type': node['type'], 'port': int(node['port']),
                   'status': 'failed', 'wrong_credentials': 'not_tested'}
            report['nodes'].append(row)
            try:
                with backend.session(client_config(node)) as session:
                    good = session.request(url)
                    row['authenticated_https'] = summarize(good)
                    if not good['ok']:
                        continue
                    observed = session.request(exit_url)
                    row['exit_https'] = summarize(observed)
                    try:
                        address = str(ipaddress.IPv4Address(observed.get('body', b'').decode().strip()))
                    except (ValueError, UnicodeError):
                        address = None
                    row['exit_ipv4'] = address
                    row['exit_matches_server'] = observed['ok'] and address == expected_ip
                    if not row['exit_matches_server']:
                        continue
                    attempts = [summarize(session.request(u)) for u in ipv6_urls]
                    row['ipv6_requests'] = attempts
                    row['ipv6_egress'] = 'reachable' if any(a['ok'] for a in attempts) else 'blocked'
                try:
                    with backend.session(client_config(node, wrong=True)) as session:
                        wrong = session.request(url)
                        row['wrong_request'] = summarize(wrong)
                        # Timeouts, TLS trust failures and dead clients are inconclusive.
                        rejected = not wrong['ok'] and wrong.get('error') in ('proxy_rejected', 'proxy_closed', 'tls_transport_closed') and session.healthy()
                        row['wrong_credentials'] = 'rejected' if rejected else 'accepted' if wrong['ok'] else 'inconclusive'
                except ProbeError as exc:
                    row['wrong_client_error'] = str(exc)
                with backend.session(client_config(node)) as session:
                    restored = session.request(url)
                    row['restored_https'] = summarize(restored)
                if restored['ok'] and row['wrong_credentials'] == 'rejected' and row.get('ipv6_egress') == 'blocked':
                    row['status'] = 'passed'
            except ProbeError as exc:
                row['error'] = str(exc)
        if report['nodes'] and all(n['status'] == 'passed' for n in report['nodes']):
            report['status'] = 'passed'
    except ProbeError as exc:
        report['error'] = str(exc)
    write_report(output_path, report)
    return report


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--input', required=True, help='Private S-UI export JSON, mode 600')
    parser.add_argument('--output', required=True, help='Private network report JSON')
    parser.add_argument('--url', default='https://example.com/')
    parser.add_argument('--exit-url', default='https://api.ipify.org/')
    parser.add_argument('--timeout', type=int, default=20)
    parser.add_argument('--backend', choices=('docker', 'native'), default='docker')
    parser.add_argument('--core-bin', help='Private verified Darwin arm64 client binary; native backend only')
    args = parser.parse_args()
    try:
        report = probe(args.input, args.output, url=args.url, exit_url=args.exit_url, timeout=args.timeout, backend=args.backend, core_bin=args.core_bin)
    except ProbeError as exc:
        print('Network probe stopped: '+str(exc), file=__import__('sys').stderr)
        return 1
    except (OSError, ValueError):
        print('Network probe stopped: check private input/output files.', file=__import__('sys').stderr)
        return 1
    print('Network probe '+report['status']+'; private report saved. Real clients and leaks remain untested.')
    return 0 if report['status'] == 'passed' else 1


if __name__ == '__main__':
    raise SystemExit(main())
