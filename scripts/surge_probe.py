#!/usr/bin/env python3
"""Native Surge Mac AnyTLS diagnostics through temporary scripting policies.

Uses script evaluate + $httpClient policy-descriptor, never switches profiles or
changes System Proxy/TUN. Input/output must be private local files. The temporary
JS contains credentials and is created mode 600 in a mode 700 directory, then
removed. No proxy credentials occur in process arguments or printed output.

Primary API: https://manual.nssurge.com/scripting/api.html
AnyTLS: https://manual.nssurge.com/policies/anytls.html
"""
import argparse
import datetime
import ipaddress
import json
import os
from pathlib import Path
import plistlib
import re
import secrets
import subprocess
import tempfile

from probe import ProbeError, private_file, write_report, fingerprint, endpoint, client_config
from subscription import atom

CLI = Path('/Applications/Surge.app/Contents/Applications/surge-cli')
MARKER = 'SUI_SURGE_NATIVE_PROBE_V1'
CAPABILITY_MARKER = 'SUI_SURGE_NO_NETWORK_V1'
CATEGORIES = {None, 'auth_rejected', 'timeout', 'transport_error', 'unsupported'}


class SurgeProbeError(RuntimeError):
    pass


def app_metadata(cli=CLI):
    cli = Path(cli)
    if not cli.is_file() or not os.access(cli, os.X_OK):
        raise SurgeProbeError('Native Surge CLI is unavailable')
    try:
        with (cli.parents[1] / 'Info.plist').open('rb') as stream:
            info = plistlib.load(stream)
        if info['CFBundleIdentifier'] != 'com.nssurge.surge-mac':
            raise ValueError()
        return {'name': 'Surge Mac', 'version': str(info['CFBundleShortVersionString']),
                'build': str(info['CFBundleVersion']), 'bundle_identifier': info['CFBundleIdentifier']}
    except (OSError, ValueError, KeyError, plistlib.InvalidFileException):
        raise SurgeProbeError('Cannot verify the installed Surge application version') from None


def run_cli(arguments, runner=subprocess.run, timeout=40):
    try:
        result = runner([str(argument) for argument in arguments], capture_output=True, timeout=timeout)
    except (OSError, subprocess.SubprocessError):
        raise SurgeProbeError('Native Surge CLI did not complete') from None
    if result.returncode != 0 or len(result.stdout) > 1024 * 1024:
        raise SurgeProbeError('Native Surge CLI failed or returned an oversized result')
    return result.stdout


def check_help(cli, runner):
    help_text = run_cli([cli, '--help'], runner).decode(errors='replace')
    if 'script evaluate' not in help_text or '-c' not in help_text:
        raise SurgeProbeError('Installed CLI lacks required scripting or offline validation')


def script_record(output, marker=MARKER):
    try:
        envelope = json.loads(output)
        if not isinstance(envelope, dict) or envelope.get('error') or not isinstance(envelope.get('output'), str):
            raise ValueError()
        records = []
        # Surge 6.5 wraps console output in a JSON envelope and prefixes each
        # console.log line with a timestamp. Ignore unrelated text completely.
        for line in envelope['output'].splitlines():
            start = line.find('{')
            if start < 0:
                continue
            try:
                record = json.loads(line[start:])
            except ValueError:
                continue
            if isinstance(record, dict) and record.get('marker') == marker:
                records.append(record)
        if len(records) != 1:
            raise ValueError()
        return records[0]
    except (ValueError, TypeError, UnicodeError):
        raise SurgeProbeError('Surge engine or diagnostic script did not return a complete result') from None


def descriptor(node, password=None):
    try:
        client_config(node)  # Reuse strict exported-node TLS/field validation.
        if node['type'] != 'anytls':
            raise ValueError()
        host = str(ipaddress.IPv4Address(node['server']))
        return (f'anytls, {host}, {int(node["port"])}, password={atom(password or node["password"])}, '
                f'sni={atom(node["server_name"])}, skip-cert-verify=false, reuse=false')
    except (ProbeError, ValueError, KeyError, TypeError):
        raise SurgeProbeError('Exported AnyTLS node is invalid or disables verification') from None


def native_script(node, url, expected_ip):
    endpoint(url)
    # The scripting API requires the complete named [Proxy] line. A bare
    # 'anytls, ...' descriptor passes the profile parser but Surge 6.5 returns
    # 'Invalid policy descriptor.' when it is used by $httpClient.
    right = 'NativeDiagnostic = ' + descriptor(node)
    wrong_password = secrets.token_urlsafe(32)
    while wrong_password == node['password']:
        wrong_password = secrets.token_urlsafe(32)
    wrong = 'NativeDiagnostic = ' + descriptor(node, wrong_password)
    # JSON literals ensure panel names/credentials cannot inject JavaScript.
    setup = ('const marker=' + json.dumps(MARKER) + ';\nconst url=' + json.dumps(url) + ';\n'
             'const expected=' + json.dumps(expected_ip) + ';\nconst policies=' + json.dumps([right, wrong, right]) + ';\n')
    return setup + r'''
const phases = ['valid', 'wrong', 'restored'];
const observations = [];
function category(error) {
  if (!error) return null;
  const text = String(error);
  if (/timed?\s*out|timeout/i.test(text)) return 'timeout';
  if (/unsupported|unknown\s+(?:policy|protocol)|invalid\s+(?:policy|descriptor)/i.test(text)) return 'unsupported';
  // Generic connection errors never establish that authentication was rejected.
  if (/authentication\s+(?:failed|failure|rejected)|invalid\s+(?:password|credentials)|incorrect\s+password|bad\s+password|unauthori[sz]ed/i.test(text)) return 'auth_rejected';
  return 'transport_error';
}
function step(index) {
  if (index === phases.length) {
    console.log(JSON.stringify({marker: marker, results: observations}));
    $done(); return;
  }
  $httpClient.get({url: url, 'policy-descriptor': policies[index], timeout: 8,
    insecure: false, 'auto-redirect': false, 'auto-cookie': false}, (error, response, body) => {
      const status = response && Number(response.status) || null;
      observations.push({phase: phases[index], status: status,
        response_received: !!response,
        exit_matches: !error && status === 200 && String(body || '').trim() === expected,
        error_category: category(error)});
      step(index + 1);
    });
}
step(0);
'''


def sanitized_results(value):
    if not isinstance(value, list):
        return []
    output = []
    for item in value:
        if not isinstance(item, dict):
            return []
        phase = item.get('phase')
        status = item.get('status')
        category = item.get('error_category')
        if (phase not in ('valid', 'wrong', 'restored') or
                not (category is None or isinstance(category, str) and category in CATEGORIES) or
                status is not None and (type(status) is not int or not 100 <= status <= 599) or
                type(item.get('exit_matches')) is not bool or type(item.get('response_received')) is not bool):
            return []
        output.append({'phase': phase, 'status': status, 'exit_matches': item['exit_matches'],
                       'response_received': item['response_received'], 'error_category': category})
    return output


def assess(observations):
    values = sanitized_results(observations)
    if len(values) != 3 or [item['phase'] for item in values] != ['valid', 'wrong', 'restored']:
        return 'inconclusive'
    first, wrong, last = values
    for good in (first, last):
        if not (good['status'] == 200 and good['exit_matches'] and good['response_received'] and good['error_category'] is None):
            return 'failed'
    if wrong['exit_matches'] or wrong['status'] == 200 or wrong['response_received'] and wrong['error_category'] is None:
        return 'failed'
    if wrong['error_category'] == 'auth_rejected' and not wrong['response_received'] and wrong['status'] is None:
        return 'passed'
    return 'inconclusive'


def probe_export(export_path, output_path, *, cli=CLI, url='https://api.ipify.org',
                 runner=subprocess.run, metadata_reader=app_metadata):
    try:
        source = private_file(export_path)
        target = private_file(output_path, existing=False)
        if source == target:
            raise ValueError()
        config = json.loads(source.read_text())
        expected = str(ipaddress.IPv4Address(config['server']['host']))
        if not isinstance(config['nodes'], list) or not all(isinstance(node, dict) for node in config['nodes']):
            raise ValueError()
        nodes = [node for node in config['nodes'] if node.get('type') == 'anytls']
        if len(nodes) != 1:
            raise ValueError()
        descriptor(nodes[0])
        endpoint(url)
        binding = fingerprint(config)
    except (ProbeError, ValueError, KeyError, TypeError, OSError):
        raise SurgeProbeError('Use a private valid export with exactly one verified AnyTLS node') from None
    report = {'checked_at': datetime.datetime.now(datetime.timezone.utc).isoformat(),
              'export_fingerprint': binding, 'protocol': 'anytls', 'result': 'startup_failed',
              'scope': 'Native Surge Mac AnyTLS HTTPS request only',
              'configuration_mutations_performed': False, 'leak_protection': '未测试',
              'other_clients': '未测试'}
    try:
        report['client'] = metadata_reader(cli)
        check_help(cli, runner)
        with tempfile.TemporaryDirectory(prefix='sui-native-surge-') as temporary:
            directory = Path(temporary)
            directory.chmod(0o700)
            profile = directory / 'offline.conf'
            profile.write_text('[General]\nloglevel = notify\n[Proxy]\nNative = ' + descriptor(nodes[0]) + '\n[Rule]\nFINAL,Native\n')
            profile.chmod(0o600)
            checked = run_cli([cli, '-c', profile], runner)
            # Actual Mac 6.5.0 checker returns exactly OK with exit status 0.
            if checked.strip() != b'OK':
                raise SurgeProbeError('Installed Surge rejected the isolated AnyTLS profile')
            script = directory / 'probe.js'
            script.write_text(native_script(nodes[0], url, expected))
            script.chmod(0o600)
            raw = run_cli([cli, '--raw', 'script', 'evaluate', script, 'cron', '30'], runner)
            record = script_record(raw)
            report['checks'] = sanitized_results(record.get('results'))
            report['result'] = assess(report['checks'])
            report['offline_profile_check'] = 'passed'
    except (SurgeProbeError, OSError, ValueError, TypeError):
        # Native errors can contain node or active-profile details. Emit only a
        # locally authored category; never persist raw native stdout/stderr.
        report['result'] = 'startup_failed'
        report.pop('checks', None)
        report['reason'] = 'Native CLI, offline parser or script engine did not produce a complete diagnostic'
    try:
        write_report(target, report)
    except (ProbeError, OSError):
        raise SurgeProbeError('Cannot write the private native-client report') from None
    return report


def capability_probe(output_path, *, cli=CLI, runner=subprocess.run):
    report = {'client': app_metadata(cli), 'network_requests_performed': False,
              'configuration_mutations_performed': False, 'capability_only': True}
    check_help(cli, runner)
    with tempfile.TemporaryDirectory(prefix='sui-surge-capability-') as temporary:
        script = Path(temporary) / 'capability.js'
        script.write_text('console.log(JSON.stringify({marker:' + json.dumps(CAPABILITY_MARKER) +
                          ',http_client:typeof $httpClient==="object",http_get:typeof $httpClient!=="undefined"&&typeof $httpClient.get==="function"}));$done();')
        script.chmod(0o600)
        raw = run_cli([cli, '--raw', 'script', 'evaluate', script, 'cron', '30'], runner)
        record = script_record(raw, CAPABILITY_MARKER)
    report['http_client_available'] = record.get('http_client') is True and record.get('http_get') is True
    write_report(output_path, report)
    return report


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--export', type=Path)
    parser.add_argument('--output', type=Path, required=True)
    parser.add_argument('--capability-only', action='store_true', help='Evaluate a no-network capability script only')
    args = parser.parse_args()
    try:
        if args.capability_only:
            if args.export:
                parser.error('Capability-only mode does not read an export')
            report = capability_probe(args.output)
            print('Surge 本机无联网能力检查已保存。')
            return 0 if report['http_client_available'] else 1
        if not args.export:
            parser.error('Native network diagnostics require --export')
        report = probe_export(args.export, args.output)
        print('Surge AnyTLS 检查：' + report['result'] + '；私有结果已保存，其他客户端与防泄露未测试。')
        return 0 if report['result'] == 'passed' else 2 if report['result'] == 'inconclusive' else 1
    except (SurgeProbeError, ProbeError, OSError):
        print('Surge 本机检查未完成；请检查应用、私有文件权限和结果文件，不会打印凭据。')
        return 1


if __name__ == '__main__':
    raise SystemExit(main())
