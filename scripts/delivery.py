#!/usr/bin/env python3
"""Render a private offline HTML account sheet locally; never host this file.

Install local QR support: python3 -m pip install 'qrcode==8.2'
Usage: python3 scripts/delivery.py --input private/export.json --output private/accounts.html
"""
import argparse
from datetime import datetime, timezone
import html
import io
import json
import os
from pathlib import Path
import tempfile

try:
    from . import subscription
except ImportError:
    import subscription


LEVELS = {'static': '静态检查', 'core': '核心配置解析', 'service': '服务健康',
          'network': '三个节点网络访问', 'clients': '真实客户端', 'leaks': '防泄露',
          'lifecycle': '续期、备份和重建', 'clean_os': '干净系统复验'}


def esc(value):
    if isinstance(value, (dict, list)):
        value = json.dumps(value, ensure_ascii=False)
    return html.escape(str(value), quote=True)


def offline_qr(value):
    try:
        import qrcode
        import qrcode.image.svg
    except ImportError:
        raise RuntimeError("本机缺少二维码库；在本机虚拟环境安装 qrcode==8.2 后重试") from None
    code = qrcode.make(value, image_factory=qrcode.image.svg.SvgPathImage, box_size=4, border=4)
    output = io.BytesIO()
    code.save(output)
    svg = output.getvalue().decode()
    # qrcode emits only its own vector path; data is not interpolated into SVG.
    return svg[svg.index('<svg'):]


def render_html(config, qr_renderer=offline_qr):
    urls = subscription.subscription_urls(config)
    # Validate all outputs before creating a sheet that would advertise broken nodes.
    subscription.surge_config(config)
    subscription.clash_config(config)
    links = subscription.vless_links(config)
    count = 0

    def field(label, value, secret=True):
        nonlocal count
        if value is None or value == '':
            value = '未提供'
        count += 1
        identifier = 'field-' + str(count)
        kind = 'password' if secret else 'text'
        return (f'<div class="field"><label for="{identifier}">{esc(label)}</label>'
                f'<div class="controls"><input id="{identifier}" type="{kind}" value="{esc(value)}" readonly autocomplete="off" spellcheck="false">'
                f'<button type="button" data-action="reveal" data-target="{identifier}" aria-label="显示或隐藏{esc(label)}">显示</button>'
                f'<button type="button" data-action="copy" data-target="{identifier}">复制</button></div></div>')

    server = config.get('server', {})
    panel, cli = config.get('panel', {}), config.get('cli_proxy', {})
    parts = ['<!doctype html><html lang="zh-CN"><head><meta charset="utf-8">',
             '<meta name="viewport" content="width=device-width,initial-scale=1">',
             '<meta name="referrer" content="no-referrer">',
             '<meta http-equiv="Content-Security-Policy" content="default-src \'none\'; style-src \'unsafe-inline\'; script-src \'unsafe-inline\'; img-src data:; connect-src \'none\'; base-uri \'none\'; form-action \'none\'">',
             '<title>你的服务器 · 私有账号</title><style>',
             ':root{font-family:system-ui,sans-serif;color:#e9eef7;background:#101726;line-height:1.65}*{box-sizing:border-box}body{margin:0}main{max-width:960px;margin:auto;padding:32px 20px 80px}h1{font-size:32px}h2{font-size:21px;margin-top:0}section{padding:24px;margin:22px 0;border:1px solid #344158;border-radius:14px;background:#172136}.note{color:#f2ce8a}label{display:block;color:#bac8dc;font-size:14px}.field{margin:14px 0}.controls{display:flex;gap:8px}input{min-width:0;flex:1;background:#101726;color:#e9eef7;border:1px solid #52617a;border-radius:6px;padding:10px;font:inherit}button,summary{cursor:pointer}button{border:1px solid #778cac;border-radius:6px;padding:8px 12px;color:#e9eef7;background:#293d5b}button:focus-visible,input:focus-visible,summary:focus-visible{outline:3px solid #85b9ff}details{margin:16px 0}summary{color:#b7d6ff}.qr{background:#fff;display:inline-block;padding:8px;max-width:100%;overflow:auto}.qr svg{display:block;max-width:100%;height:auto}table{width:100%;border-collapse:collapse}th,td{text-align:left;border-bottom:1px solid #344158;padding:9px;overflow-wrap:anywhere}p,li,td{overflow-wrap:anywhere}#status{position:fixed;bottom:12px;left:12px;right:12px;text-align:center;background:#233a56;border-radius:8px;padding:8px}#status:empty{display:none}@media(max-width:520px){main{padding:18px 12px 80px}section{padding:16px}.controls{flex-wrap:wrap}.controls input{flex-basis:100%}}',
             '</style></head><body><main><h1>你的服务器与账号</h1>',
             '<p class="note">只保存在你本机。这份 HTML 含明文密码和订阅令牌；遮挡只能防旁观。不要上传到网盘公开目录、网站或 Git。旧实例资料在重装后失效。</p>',
             '<section><h2>服务器</h2>']
    for label, key in [('SSH 名称', 'ssh_alias'), ('主机', 'host'), ('服务器时区', 'timezone'), ('部署时间', 'deployed_at'), ('组件版本', 'versions')]:
        parts.append(field(label, server.get(key, '未记录'), secret=False))
    parts.append('</section><section><h2>订阅与导入</h2><p>订阅通过你的服务器 HTTPS 更新，不经过第三方转换。二维码包含秘密地址，只有点击后才显示。把订阅交给别人就等于把节点交给别人。</p>')
    clients = [('Clash Verge Rev / OpenClash', 'clash', 'Reality、VLESS TLS、AnyTLS 三个节点，带分流规则：国内网站直连，AI 服务单独一组，其他走代理；AUTO 组在主节点不通时换下一个。复制地址，在 Clash Verge Rev 的「订阅」里粘贴并导入，模式选「规则」，再打开「虚拟网卡模式」（TUN）；只开系统代理时 WebRTC 会暴露本地 IP。OpenClash 在「配置订阅」添加同一地址，关闭在线订阅转换。规则文件从你自己的服务器下载。需要 Mihomo 内核支持 AnyTLS（较新的 Clash Verge Rev 自带）。真客户端结果见下方。'),
               ('Surge', 'surge', 'AnyTLS；官方格式最低为 Mac 6.4.3 / iOS 5.17.0，当前设备能否连接以本页实测记录为准。复制地址，在 Surge 的配置列表中从 URL 下载配置；需要时在配置详情更新。此配置将 FINAL 流量送到代理，没有国内直连或 AI 分流规则。'),
               ('v2rayN', 'v2ray', 'VLESS Reality 与 VLESS TLS。复制地址，在订阅分组设置中添加分组和 URL，再更新订阅。分别选择两个节点测试。实际应用和内核版本未记录时，按未测试处理。'),
               ('v2rayNG', 'v2ray', 'VLESS Reality 与 VLESS TLS。复制地址，在订阅分组设置中添加 URL，再更新订阅；也可扫描单节点二维码。安卓真机结果见下方。')]
    for name, key, instructions in clients:
        parts.append('<h3>' + name + '</h3>' + field(name + ' HTTPS 订阅', urls[key]))
        parts.append('<p>' + esc(instructions) + '</p><details><summary>显示 ' + name + ' 订阅二维码</summary><div class="qr">' + qr_renderer(urls[key]) + '</div></details>')
    parts.append('<p>导入后保持证书验证开启。订阅导入成功不代表节点连接或防泄露已经通过；TUN、DNS、IPv6、WebRTC 和断线行为需要逐项检查。</p></section><section><h2>节点参数</h2>')
    for node in config['nodes']:
        parts.append('<h3>' + esc(node.get('name', node['type'])) + '</h3>')
        for key in ('type', 'server', 'port', 'server_name', 'uuid', 'password', 'public_key', 'short_id', 'flow'):
            if key in node:
                parts.append(field(key, node[key], secret=key in ('uuid', 'password', 'public_key', 'short_id')))
    for index, link in enumerate(links):
        parts.append(field('VLESS 单节点链接 ' + str(index + 1), link))
        parts.append('<details><summary>显示单节点二维码</summary><div class="qr">' + qr_renderer(link) + '</div></details>')
    parts.append('</section><section><h2>S-UI 面板</h2><p>复制面板地址到浏览器，再使用独立面板账号登录。</p>')
    for label, key in [('面板 HTTPS 地址', 'url'), ('用户名', 'username'), ('密码', 'password')]:
        parts.append(field(label, panel.get(key)))
    parts.append('</section><section><h2>CLIProxyAPI 与管理中心</h2><p>管理中心初始没有上游账号。你可以在登录后添加自己的账号或供应商 Key。管理 Key 和 API 调用 Key 用途不同。</p>')
    for label, key in [('管理中心地址', 'management_url'), ('管理 Key', 'management_key'), ('API Base URL', 'api_base_url'), ('调用 Key', 'api_key')]:
        parts.append(field(label, cli.get(key)))
    traffic = config.get('traffic') or {'source': '未配置', 'status': '未查询'}
    if traffic.get('source') == 'local-interface':
        parts.append('</section><section><h2>流量（本机网卡统计）</h2><p>没有配置搬瓦工 API 时，按服务器默认出口网卡的收发字节累计，计费方式和每月重置日来自目标文件。它和服务商的计费可能有出入，可以用 traffic-calibrate 按后台已用量校准。表示整台 VPS 的用量，并非某一个节点。客户端是否显示统计取决于应用，需实测。</p><table>')
    else:
        parts.append('</section><section><h2>搬瓦工官方流量</h2><p>来源为 KiwiVM getServiceInfo，表示整台 VPS 的共享用量，并非某一个节点的用量。服务缓存至少 10 分钟；缓存过期且查询失败时标记 stale，未知时不填固定额度。客户端是否显示统计取决于应用，需实测。</p><table>')
    for key, value in traffic.items():
        parts.append('<tr><th>' + esc(key) + '</th><td>' + esc(value) + '</td></tr>')
    parts.append('</table></section><section><h2>这一轮实际检查</h2><p>下表只记录真实完成的层级；服务健康不能替代客户端与防泄露检查。</p><table><tr><th>检查</th><th>结果</th></tr>')
    verification = config.get('verification', {})
    for key, label in LEVELS.items():
        parts.append('<tr><th>' + esc(label) + '</th><td>' + esc(verification.get(key, '未测试')) + '</td></tr>')
    for key, value in verification.items():
        if key not in LEVELS:
            parts.append('<tr><th>' + esc(key) + '</th><td>' + esc(value) + '</td></tr>')
    parts.append('</table></section><p>导出时间（UTC）：' + esc(datetime.now(timezone.utc).isoformat()) + '</p></main><div id="status" role="status" aria-live="polite"></div>')
    # Values stay in escaped HTML attributes: no data is inserted into JavaScript.
    parts.append('''<script>
const status = document.getElementById('status');
function announce(message) { status.textContent = message; }
function fallback(input) {
  const original = input.type;
  input.type = 'text'; input.focus(); input.select(); input.setSelectionRange(0, input.value.length);
  let copied = false;
  try { copied = document.execCommand('copy'); } catch (_) {}
  if (copied) { input.type = original; announce('已复制。剪贴板中含秘密，请妥善处理。'); }
  else { announce('自动复制未成功。内容已显示并选中，请用 Ctrl/Cmd+C 复制，完成后点击隐藏。');
    const toggle = document.querySelector('[data-action="reveal"][data-target="' + input.id + '"]');
    if (toggle) toggle.textContent = '隐藏'; }
}
document.addEventListener('click', async event => {
  const button = event.target.closest('button[data-action]'); if (!button) return;
  const input = document.getElementById(button.dataset.target); if (!input) return;
  if (button.dataset.action === 'reveal') {
    input.type = input.type === 'password' ? 'text' : 'password';
    button.textContent = input.type === 'password' ? '显示' : '隐藏'; return;
  }
  try {
    if (!navigator.clipboard || !navigator.clipboard.writeText) { fallback(input); return; }
    await navigator.clipboard.writeText(input.value); announce('已复制。剪贴板中含秘密，请妥善处理。');
  } catch (_) { fallback(input); }
});
</script></body></html>''')
    return ''.join(parts)


def write_private(path, content):
    path = Path(path).expanduser().absolute()
    path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    fd, temporary = tempfile.mkstemp(dir=path.parent, prefix='.delivery-')
    try:
        with os.fdopen(fd, 'w', encoding='utf-8') as handle:
            handle.write(content)
        os.replace(temporary, path)
    finally:
        if os.path.exists(temporary):
            os.unlink(temporary)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--input', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    try:
        content = render_html(json.loads(args.input.read_text()))
        write_private(args.output, content)
    except (OSError, ValueError, KeyError, RuntimeError):
        parser.exit(1, '交付页生成失败：请检查私有 JSON、HTTPS 地址、节点字段和本机 qrcode 安装；不会打印凭据。\n')


if __name__ == '__main__':
    main()
