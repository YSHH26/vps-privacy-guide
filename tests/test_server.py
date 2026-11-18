import importlib.util
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

ROOT=Path(__file__).resolve().parents[1]
class ServerTest(unittest.TestCase):
    def module(self):
        self.assertTrue((ROOT/'scripts/server.py').exists(), 'server stage runner missing')
        import sys
        if str(ROOT/'scripts') not in sys.path:sys.path.insert(0,str(ROOT/'scripts'))  # As when run as a script.
        spec=importlib.util.spec_from_file_location('server',ROOT/'scripts/server.py')
        m=importlib.util.module_from_spec(spec);spec.loader.exec_module(m);return m
    def test_preexisting_unowned_state_refused(self):
        m=self.module()
        with tempfile.TemporaryDirectory() as d:
            p=Path(d);(p/'state.json').write_text('{}')
            with self.assertRaises(RuntimeError):m.claim_state(p)
    def test_claim_is_repeatable_and_private(self):
        m=self.module()
        with tempfile.TemporaryDirectory() as d:
            p=Path(d);m.claim_state(p);m.claim_state(p)
            self.assertEqual(p.stat().st_mode&0o777,0o700)
            self.assertEqual((p/'.managed').read_text(),'sui-vps-v1\n')
    def test_certificate_pair_rollback_on_failed_reload(self):
        m=self.module()
        with tempfile.TemporaryDirectory() as d:
            p=Path(d);live=p/'live';old=p/'old';live.mkdir();old.mkdir()
            for n in ['fullchain.pem','privkey.pem']:
                (live/n).write_text('new-'+n);(old/n).write_text('old-'+n)
            calls=[]
            def reload():
                calls.append(1)
                if len(calls)==1:raise RuntimeError('health failure')
            with self.assertRaises(RuntimeError):
                m.sync_pair(live,old,validate=lambda p:None,reload=reload)
            self.assertEqual((old/'privkey.pem').read_text(),'old-privkey.pem')
            self.assertEqual(len(calls),2)
    def test_public_proxy_does_not_expose_raw_subscription_or_log_tokens(self):
        m=self.module();s={'ip':'192.0.2.1'}
        conf=m.https_config(s)
        self.assertIn('listen 9443 ssl',conf);self.assertIn('listen 9444 ssl',conf)
        self.assertIn('location /app/',conf);self.assertIn('location /s/',conf)
        self.assertNotIn('2096',conf);self.assertIn('access_log off',conf)
        self.assertIn('proxy_buffering off',conf)
    def test_ssh_hardening_requires_existing_key_and_rolls_back_invalid_policy(self):
        m=self.module()
        with tempfile.TemporaryDirectory() as d:
            p=Path(d); keys=p/'authorized_keys';snippet=p/'01-sui-vps.conf'
            with self.assertRaises(RuntimeError):m.harden_ssh(keys,snippet)
            keys.write_text('ssh-ed25519 AAAATEST owner\n')
            def failed(args,**kw):raise RuntimeError('invalid policy')
            with patch.object(m,'run',failed):
                with self.assertRaises(RuntimeError):m.harden_ssh(keys,snippet)
            self.assertFalse(snippet.exists())
    def test_subscription_snapshot_excludes_admin_and_provider_secrets(self):
        m=self.module()
        full={'nodes':[], 'subscriptions':{},'public_base_url':'https://192.0.2.1:9443','traffic':{},'panel':{'password':'secret'},'cli_proxy':{'management_key':'secret'},'server':{}}
        self.assertEqual(set(m.subscription_snapshot(full)),{'nodes','subscriptions','public_base_url','traffic'})
    def test_managed_files_refuse_unrelated_content(self):
        m=self.module()
        with tempfile.TemporaryDirectory() as d:
            p=Path(d)/'config';p.write_text('other project')
            with self.assertRaises(RuntimeError):m.write_managed(p,'new')
            self.assertEqual(p.read_text(),'other project')
    def test_nginx_configuration_failure_restores_previous_file(self):
        m=self.module()
        with tempfile.TemporaryDirectory() as d:
            p=Path(d)/'nginx.conf';p.write_text('# Managed by sui-vps.\nold')
            def run(args,**kw):
                if p.read_text().endswith('new'):raise RuntimeError('bad nginx config')
            with patch.object(m,'run',run),patch.object(m,'systemctl'):
                with self.assertRaises(RuntimeError):m.nginx_config(p,'new')
            self.assertEqual(p.read_text(),'# Managed by sui-vps.\nold')
    def test_backup_manifest_excludes_other_certificate_projects(self):
        m=self.module()
        paths={str(p) for p in m.backup_paths()}
        self.assertNotIn('/etc/letsencrypt',paths)
        self.assertNotIn('/etc/letsencrypt/accounts',paths)
        self.assertIn('/etc/sui-vps',paths)
        self.assertFalse(any(x.startswith('/etc/letsencrypt/') for x in paths))
    def test_token_rotation_changes_only_selected_client(self):
        m=self.module()
        with tempfile.TemporaryDirectory() as d:
            p=Path(d);m.save(p/'export.json',{'subscriptions':{'surge':'a'*43,'v2ray':'b'*43}})
            with patch.object(m,'ETC',p),patch.object(m,'share_export'):
                m.rotate_subscriptions('surge')
            result=m.load(p/'export.json')['subscriptions']
            self.assertNotEqual(result['surge'],'a'*43)
            self.assertEqual(result['v2ray'],'b'*43)
            with self.assertRaises(RuntimeError):m.rotate_subscriptions('unknown')
    def test_clash_token_rotates_independently(self):
        m=self.module()
        with tempfile.TemporaryDirectory() as d:
            p=Path(d);m.save(p/'export.json',{'subscriptions':{'surge':'a'*43,'v2ray':'b'*43,'clash':'c'*43}})
            with patch.object(m,'ETC',p),patch.object(m,'share_export'):
                m.rotate_subscriptions('clash')
            result=m.load(p/'export.json')['subscriptions']
            self.assertNotEqual(result['clash'],'c'*43)
            self.assertEqual((result['surge'],result['v2ray']),('a'*43,'b'*43))
    def test_rule_mirror_checks_digest_and_keeps_previous_copy(self):
        import hashlib
        m=self.module()
        good={'geosite.dat':b'site'*400,'geoip.metadb':b'ip'*900,'GeoLite2-ASN.mmdb':b'asn'*500}
        def fetch(files):
            def inner(url,limit=0):
                name=url.rsplit('/',1)[1]
                if name.endswith('.sha256sum'):
                    base=name[:-len('.sha256sum')]
                    return (hashlib.sha256(good[base]).hexdigest()+'  '+base+'\n').encode()
                return files[name]
            return inner
        with tempfile.TemporaryDirectory() as d:
            etc=Path(d)/'etc';etc.mkdir();rules=Path(d)/'rules'
            with patch.object(m,'ETC',etc):
                m.rules(fetch=fetch(good),directory=rules)
                self.assertEqual(good['geosite.dat'],(rules/'geosite.dat').read_bytes())
                with self.assertRaisesRegex(RuntimeError,'校验失败'):
                    m.rules(fetch=fetch({**good,'geosite.dat':b'tampered'}),directory=rules)
                self.assertEqual(good['geosite.dat'],(rules/'geosite.dat').read_bytes())
                def broken(url,limit=0):raise OSError('offline')
                with self.assertRaises(OSError):m.rules(fetch=broken,directory=rules)
                self.assertEqual(good['geoip.metadb'],(rules/'geoip.metadb').read_bytes())
                self.assertEqual(sorted(good),sorted(m.load(etc/'rules.json')['files']))
    def test_apt_wait_blocks_while_lock_held_then_times_out(self):
        import fcntl
        m=self.module()
        with tempfile.TemporaryDirectory() as d:
            lock=Path(d)/'lock';lock.touch()
            m.wait_for_apt(timeout=1,locks=[str(lock),str(Path(d)/'missing')],sleep=lambda s:None)
            import subprocess,sys
            holder=subprocess.Popen([sys.executable,'-c','import fcntl,sys,time;f=open(sys.argv[1],"a");fcntl.lockf(f,fcntl.LOCK_EX);print("held",flush=True);time.sleep(30)',str(lock)],stdout=subprocess.PIPE,text=True)
            try:
                self.assertEqual('held',holder.stdout.readline().strip())
                with self.assertRaisesRegex(RuntimeError,'占用'):
                    m.wait_for_apt(timeout=0,locks=[str(lock)],sleep=lambda s:None)
            finally:
                holder.kill();holder.wait()
    def test_carried_acme_adopted_only_when_valid_for_this_ip(self):
        import os
        m=self.module()
        def lineage(root, escape=False, renewal=True):
            acme=root/'carry'/'acme';archive=acme/'archive/sui-vps';live=acme/'live/sui-vps'
            archive.mkdir(parents=True);live.mkdir(parents=True)
            for name in ['fullchain1.pem','privkey1.pem']:(archive/name).write_text(name)
            outside=root/'outside.pem';outside.write_text('x')
            os.symlink(str(outside) if escape else '../../archive/sui-vps/fullchain1.pem',live/'fullchain.pem')
            os.symlink('../../archive/sui-vps/privkey1.pem',live/'privkey.pem')
            if renewal:(acme/'renewal').mkdir();(acme/'renewal/sui-vps.conf').write_text('conf')
            return root/'carry'
        calls=[]
        ok=lambda d,min_seconds=0:calls.append(min_seconds)
        with tempfile.TemporaryDirectory() as d:
            root=Path(d);carry=lineage(root);target=root/'etc/acme'
            with patch.object(m,'run') as run:
                self.assertTrue(m.adopt_carried_acme({'ip':'192.0.2.1'},carry=carry,target=target,validate=ok))
            self.assertIn('-checkip',run.call_args.args[0])
            self.assertEqual([86400],calls)
            self.assertEqual('fullchain1.pem',(target/'live/sui-vps/fullchain.pem').read_text())
            self.assertFalse(carry.exists())
            carry=lineage(root/'again')
            self.assertFalse(m.adopt_carried_acme({'ip':'192.0.2.1'},carry=carry,target=target,validate=ok))
            self.assertFalse(carry.exists())
        for kwargs in [{'escape':True},{'renewal':False}]:
            with tempfile.TemporaryDirectory() as d:
                root=Path(d);carry=lineage(root,**kwargs);target=root/'etc/acme'
                with patch.object(m,'run'):
                    self.assertFalse(m.adopt_carried_acme({'ip':'192.0.2.1'},carry=carry,target=target,validate=ok))
                self.assertFalse(target.exists());self.assertFalse(carry.exists())
        def expired(d,min_seconds=0):raise RuntimeError('证书即将过期')
        with tempfile.TemporaryDirectory() as d:
            root=Path(d);carry=lineage(root);target=root/'etc/acme'
            self.assertFalse(m.adopt_carried_acme({'ip':'192.0.2.1'},carry=carry,target=target,validate=expired))
            self.assertFalse(target.exists())
    def test_tls_loaded_check_compares_actual_peer_certificates(self):
        m=self.module()
        calls=[]
        def peer(port):calls.append(port);return b'current' if port!=8443 else b'previous'
        with self.assertRaises(RuntimeError):
            m.check_loaded_certificates(b'current',[9443,2443,8443],fetch=peer)
        self.assertEqual(calls,[9443,2443,8443])
    def test_firewall_activation_preserves_unrelated_public_services(self):
        m=self.module()
        ssh='LISTEN 0 128 0.0.0.0:22 0.0.0.0:*\n'
        local='LISTEN 0 128 127.0.0.1:5432 0.0.0.0:*\n'
        m.check_firewall_activation(ssh+local,'',active=False,ssh_ports=[22])
        with self.assertRaises(RuntimeError):
            m.check_firewall_activation(ssh+'LISTEN 0 128 0.0.0.0:8080 0.0.0.0:*\n','',active=False,ssh_ports=[22])
        m.check_firewall_activation(ssh+'LISTEN 0 128 0.0.0.0:8080 0.0.0.0:*\n','',active=True,ssh_ports=[22])
    def test_backup_directory_cannot_redirect_or_delete_unowned_archives(self):
        m=self.module()
        with tempfile.TemporaryDirectory() as d:
            p=Path(d);other=p/'other';other.mkdir();(other/'keep.tar.gz').write_text('data')
            link=p/'backups';link.symlink_to(other,target_is_directory=True)
            with self.assertRaises(RuntimeError):m.claim_backup_directory(link)
            with self.assertRaises(RuntimeError):m.claim_backup_directory(other)
            self.assertEqual((other/'keep.tar.gz').read_text(),'data')
