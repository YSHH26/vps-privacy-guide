"""Orchestrator guardrails: all remote/provider access is mocked."""
import importlib.util
import io
import json
import os
from pathlib import Path
import subprocess
import tarfile
import tempfile
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location('vps', ROOT / 'scripts/vps.py')
vps = importlib.util.module_from_spec(spec)
spec.loader.exec_module(vps)


class OrchestratorTests(unittest.TestCase):
    def test_atomic_private_save_rejects_symlink(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp); root.chmod(0o700)
            p = root/'value.json'
            vps.save(p, {'secret': 'private'})
            self.assertEqual(p.stat().st_mode & 0o777, 0o600)
            p.unlink(); victim = root/'victim'; victim.write_text('keep')
            p.symlink_to(victim)
            with self.assertRaises(ValueError): vps.save(p, {'secret': 'changed'})
            self.assertEqual(victim.read_text(), 'keep')

    def test_rejects_readable_secret_and_unsafe_parent(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp); root.chmod(0o700); p = root/'state.json'
            p.write_text('{}'); p.chmod(0o644)
            with self.assertRaises(ValueError): vps.private_json(p)
            p.chmod(0o600); root.chmod(0o755)
            with self.assertRaises(ValueError): vps.private_json(p)

    def test_api_secrets_only_in_curl_stdin(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp); root.chmod(0o700)
            p = root/'provider.json'; vps.save(p, {'veid': 1, 'api_key': 'private-key'})
            s = {'provider_file': str(p), 'veid': 1}
            response = subprocess.CompletedProcess([], 0, '{"error":0}', '')
            with patch.object(vps, 'run', return_value=response) as run:
                vps.api(s, 'getServiceInfo')
            args, kwargs = run.call_args
            self.assertNotIn('private-key', ' '.join(args[0]))
            self.assertIn('private-key', kwargs['input'])
            self.assertNotIn('--insecure', args[0])
            self.assertNotIn('--location', args[0])

    def test_archive_excludes_private_and_rejects_symlink(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            for relative in vps.SOURCE_FILES:
                p=root/relative; p.parent.mkdir(parents=True, exist_ok=True); p.write_text('public')
            (root/'scripts/secret.json').write_text('secret')
            with patch.object(vps, 'ROOT', root): payload, digest=vps.source()
            with tarfile.open(fileobj=io.BytesIO(payload)) as archive:
                self.assertEqual(set(archive.getnames()), set(vps.SOURCE_FILES))
            self.assertEqual(len(digest), 64)
            target=root/vps.SOURCE_FILES[0]; target.unlink(); target.symlink_to(root/'scripts/secret.json')
            with patch.object(vps,'ROOT',root):
                with self.assertRaises(ValueError): vps.source()

    def test_ssh_requires_known_host_and_private_bootstrap_file(self):
        with tempfile.TemporaryDirectory() as tmp:
            root=Path(tmp); root.chmod(0o700); known=root/'known_hosts'; known.write_text('key'); known.chmod(0o600)
            s={'ssh_alias':'my-vps','ip':'192.0.2.1','ssh_port':2222,'known_hosts_file':str(known)}
            with patch.object(vps,'run') as run: vps.ssh(s,'true')
            args=run.call_args.args[0]
            self.assertIn('StrictHostKeyChecking=yes',args)
            self.assertIn('UserKnownHostsFile='+str(known),args)
            self.assertIn('2222',args)

    def test_bootstrap_requires_reinstall_and_trusted_proof(self):
        with self.assertRaises(ValueError): vps.bootstrap({},Path('unused'))
        state={'reinstall_at':1,'pre_reinstall_boot_id':'old'}
        with patch.object(vps,'api',return_value={'error':0,'state':'running','ssh_port':22}), patch.object(vps,'wait_provider'):
            with self.assertRaises(ValueError): vps.bootstrap(state,Path('unused'))

    def test_encrypted_backup_requires_real_envelope(self):
        with tempfile.TemporaryDirectory() as tmp:
            root=Path(tmp); root.chmod(0o700); p=root/'backup.age'
            p.write_bytes(b'plaintext'*200); p.chmod(0o600)
            with self.assertRaises(ValueError): vps.check_backup(p)
            p.write_bytes(b'age-encryption.org/v1\n'+b'x'*200)
            vps.check_backup(p)

    def test_text_and_byte_diagnostics_preserve_no_output_case(self):
        result=subprocess.CompletedProcess([],1,'partial','')
        self.assertEqual(vps.diagnostics(result),b'partial')
        result=subprocess.CompletedProcess([],1,None,b'error')
        self.assertEqual(vps.diagnostics(result),b'error')

    def test_stage_failure_keeps_diagnostics_private(self):
        with tempfile.TemporaryDirectory() as tmp:
            root=Path(tmp); root.chmod(0o700)
            error=subprocess.CalledProcessError(1,['ssh'],output=b'private output',stderr=b'private token')
            with patch.object(vps,'ssh',side_effect=error):
                with self.assertRaisesRegex(RuntimeError,'private stage log'):
                    vps.remote_stage({},'command',root/'target.json','verify')
            log=root/'stage-verify.log'
            self.assertIn(b'private token',log.read_bytes())
            self.assertEqual(log.stat().st_mode & 0o777,0o600)

    def test_bootstrap_checks_trusted_key_and_new_boot_before_recording(self):
        with tempfile.TemporaryDirectory() as tmp:
            root=Path(tmp); root.chmod(0o700)
            boot='12345678-1234-1234-1234-123456789abc'
            s={'ip':'192.0.2.1','veid':1,'ssh_alias':'my-vps','reinstall_at':123,
               'pre_reinstall_boot_id':'00000000-0000-0000-0000-000000000000',
               'bootstrap_proof_file':str(root/'proof.json')}
            vps.save(root/'proof.json',{'ip':s['ip'],'veid':1,'reinstall_at':123,
                     'source':'provider-console','boot_id':boot,'ssh_port':2222,
                     'host_public_keys':['ssh-ed25519 AAAATEST']})
            result=subprocess.CompletedProcess([],0,boot+'\n','')
            with patch.object(vps,'target_info'),patch.object(vps,'wait_provider'),patch.object(vps,'ssh',return_value=result) as ssh:
                vps.bootstrap(s,root/'target.json')
            trial=ssh.call_args.args[0]
            self.assertEqual(trial['ssh_port'],2222)
            self.assertIn('[192.0.2.1]:2222',Path(trial['known_hosts_file']).read_text())
            saved=vps.private_json(root/'target.json')
            self.assertFalse(saved['reinstall_pending'])
            self.assertEqual(saved['bootstrap_boot_id'],boot)

    def test_reinstall_rejects_unverified_backup_before_any_mutation(self):
        with tempfile.TemporaryDirectory() as tmp:
            root=Path(tmp); root.chmod(0o700);backup=root/'backup.age'
            backup.write_bytes(b'age-encryption.org/v1\n'+b'x'*200);backup.chmod(0o600)
            s={'ssh_alias':'my-vps','ip':'192.0.2.1','veid':1,'encrypted_backup':str(backup)}
            with patch.object(vps,'require_provider_readiness'),patch.object(vps,'target_info'),patch.object(vps,'api',return_value={'templates':['ubuntu-test']}) as api:
                with self.assertRaisesRegex(ValueError,'restore test'):
                    vps.reinstall(s,root/'target.json','ubuntu-test','my-vps:192.0.2.1:1')
            self.assertEqual([call.args[1] for call in api.call_args_list],['getAvailableOS'])

    def test_reinstall_discard_skips_backup_only_when_explicit(self):
        with tempfile.TemporaryDirectory() as tmp:
            root=Path(tmp); root.chmod(0o700)
            s={'ssh_alias':'my-vps','ip':'192.0.2.1','veid':1,'backup_restore_verified':True,
               'identity_file':str(root/'key'),'provider_capabilities':{'baseline_boot_id':'b','destructive_contracts':{}}}
            with patch.object(vps,'require_provider_readiness'),patch.object(vps,'target_info'),patch.object(vps,'api',return_value={'templates':['ubuntu-test']}):
                with self.assertRaises(KeyError):
                    vps.reinstall(dict(s),root/'target.json','ubuntu-test','my-vps:192.0.2.1:1')
                with patch.object(vps,'ssh',side_effect=RuntimeError('stop-here')):
                    with self.assertRaisesRegex(RuntimeError,'stop-here'):
                        vps.reinstall(s,root/'target.json','ubuntu-test','my-vps:192.0.2.1:1',discard_existing_data=True)
            self.assertEqual(s['backup_waived']['reason'],'owner-discarded-existing-data')
            self.assertNotIn('backup_restore_verified',s)

    def test_reinstall_requires_fresh_bound_provider_readiness(self):
        s={'ssh_alias':'my-vps','ip':'192.0.2.1','veid':1}
        with patch.object(vps,'api') as api:
            with self.assertRaisesRegex(ValueError,'provider-proof'):
                vps.reinstall(s,Path('unused'),'ubuntu','my-vps:192.0.2.1:1')
        api.assert_not_called()
        cap=self.capability(s);s['provider_capabilities']=cap
        vps.require_provider_readiness(s)
        for field,value in [('source','https://example.com/'),('target_sha256','wrong'),('checked_at',0),('trusted_ssh_baseline',False)]:
            with self.subTest(field=field):
                altered={**s,'provider_capabilities':{**cap,field:value}}
                with self.assertRaises(ValueError):vps.require_provider_readiness(altered)

    def test_password_ssh_uses_inherited_descriptor_and_strict_host(self):
        with tempfile.TemporaryDirectory() as tmp:
            root=Path(tmp);root.chmod(0o700);known=root/'known_hosts';known.write_text('key');known.chmod(0o600)
            s={'ip':'192.0.2.1','ssh_alias':'my-vps','ssh_port':22,'known_hosts_file':str(known)}
            def inspect(args,**kwargs):
                self.assertEqual(args[0],'sshpass');self.assertEqual(args[1],'-d')
                fd=int(args[2]);self.assertIn(fd,kwargs['pass_fds'])
                self.assertEqual(os.read(fd,4096),b'private-password\n')
                self.assertNotIn('private-password',' '.join(args))
                self.assertNotIn('SSHPASS',kwargs.get('env',{}))
                self.assertIn('StrictHostKeyChecking=yes',args)
                self.assertIn('PubkeyAuthentication=no',args)
                return subprocess.CompletedProcess(args,0,b'boot',b'')
            with patch.object(vps,'run',side_effect=inspect),patch.object(vps.shutil,'which',return_value='/usr/bin/sshpass'):
                vps.password_ssh(s,'command','private-password',input=b'public key')

    def test_password_bootstrap_failed_key_confirmation_preserves_state_and_password(self):
        with tempfile.TemporaryDirectory() as tmp:
            root=Path(tmp);root.chmod(0o700);known=root/'known_hosts';known.write_text('key');known.chmod(0o600)
            password=root/'password';password.write_text('private-password');password.chmod(0o600)
            state=root/'target.json';s={'ip':'192.0.2.1','ssh_alias':'my-vps','known_hosts_file':str(known),'initial_password_file':str(password)}
            vps.save(state,s);original=state.read_bytes()
            ok=subprocess.CompletedProcess([],0,'12345678-1234-1234-1234-123456789abc\n','')
            with patch.object(vps,'dedicated_key',return_value=(root/'new-key','ssh-ed25519 AAAATEST')),patch.object(vps,'password_ssh',return_value=ok),patch.object(vps,'ssh',side_effect=subprocess.CalledProcessError(255,['ssh'])):
                with self.assertRaises(subprocess.CalledProcessError):vps.bootstrap(s,state,initial=True)
            self.assertEqual(state.read_bytes(),original);self.assertTrue(password.exists())

    def test_initial_bootstrap_success_removes_password_only_after_key_works(self):
        with tempfile.TemporaryDirectory() as tmp:
            root=Path(tmp);root.chmod(0o700);known=root/'known_hosts';known.write_text('key');known.chmod(0o600)
            password=root/'password';password.write_text('private-password');password.chmod(0o600)
            key=root/'key';key.write_text('private key');key.chmod(0o600)
            state=root/'target.json';s={'ip':'192.0.2.1','ssh_alias':'my-vps','known_hosts_file':str(known),'initial_password_file':str(password)}
            boot='12345678-1234-1234-1234-123456789abc';ok=subprocess.CompletedProcess([],0,boot+'\n','')
            def confirm(trial,command,**kwargs):
                self.assertTrue(password.exists());self.assertTrue(trial['_isolated_auth']);self.assertEqual(trial['identity_file'],str(key));return ok
            with patch.object(vps,'dedicated_key',return_value=(key,'ssh-ed25519 AAAATEST')),patch.object(vps,'password_ssh',return_value=ok),patch.object(vps,'ssh',side_effect=confirm):vps.bootstrap(s,state,initial=True)
            saved=vps.private_json(state);self.assertEqual(saved['identity_file'],str(key));self.assertNotIn('initial_password_file',saved);self.assertFalse(password.exists());self.assertNotIn('_isolated_auth',saved)

    def test_initial_bootstrap_never_uses_password_without_host_proof(self):
        with patch.object(vps,'password_ssh') as password:
            with self.assertRaises(ValueError):vps.bootstrap({'ip':'192.0.2.1'},Path('unused'),initial=True)
        password.assert_not_called()

    def test_backup_header_is_streamed(self):
        with tempfile.TemporaryDirectory() as tmp:
            p=Path(tmp)/'backup.age';p.write_bytes(b'age-encryption.org/v1\n'+b'x'*200);p.chmod(0o600)
            with patch.object(Path,'read_bytes',side_effect=AssertionError('must stream header')):vps.check_backup(p)

    def test_preflight_rejects_new_boot_or_changed_target_or_source(self):
        s={'ip':'192.0.2.1','ssh_alias':'my-vps','preflight_at':vps.time.time(),'preflight_ip':'192.0.2.1','preflight_boot_id':'old','preflight_source_sha256':'digest'}
        s['preflight_target_sha256']=vps.target_digest(s)
        with patch.object(vps,'ssh',return_value=subprocess.CompletedProcess([],0,'new\n','')):
            with self.assertRaisesRegex(ValueError,'boot'):vps.require_preflight(s,'digest')
        changed={**s,'ssh_port':2222}
        with self.assertRaises(ValueError):vps.require_preflight(changed,'digest')
        with self.assertRaises(ValueError):vps.require_preflight(s,'changed')

    def test_network_results_bind_to_current_nodes_not_metadata(self):
        with tempfile.TemporaryDirectory() as tmp:
            root=Path(tmp);root.chmod(0o700);report=root/'network.json'
            config={'server':{'host':'192.0.2.1','deployed_at':'today','versions':{}},'nodes':[{'uuid':'current'}], 'verification':{'clients':'未测试','network':'server claim'}}
            fingerprint=vps.probe_module().fingerprint(config)
            vps.save(report,{'scope':'local_fixed_core_network','node_fingerprint':fingerprint,'status':'passed','checked_at':'today','nodes':[{'status':'passed','wrong_credentials':'rejected','exit_matches_server':True}]*3})
            merged=vps.merge_network(config,report);self.assertTrue(merged['verification']['network'].startswith('通过'))
            self.assertEqual(merged['verification']['clients'],'未测试')
            config['nodes'][0]['uuid']='rotated'
            self.assertTrue(vps.merge_network(config,report)['verification']['network'].startswith('未测试'))

    def test_upload_backup_precedes_locked_source_extraction(self):
        with patch.object(vps,'ssh') as ssh:
            vps.upload({'ip':'192.0.2.1'},(b'archive','a'*64))
        command=ssh.call_args_list[0].args[1]
        self.assertLess(command.index('server.py backup'),command.index('flock -x 9'))
        self.assertLess(command.index('flock -x 9'),command.index('tar -xzf'))
        self.assertIn('source_sha256',command)
        self.assertIn('staging=$(mktemp -d',command)
        self.assertIn('mv -f --',command)
        parsed=subprocess.run(['sh','-n'],input=command,text=True,capture_output=True)
        self.assertEqual(parsed.returncode,0,parsed.stderr)

    def test_export_target_symlink_and_world_readable_path_refused(self):
        with tempfile.TemporaryDirectory() as tmp:
            root=Path(tmp);root.chmod(0o700);target=root/'accounts.html';other=root/'other'
            other.write_text('keep');other.chmod(0o600);target.symlink_to(other)
            with self.assertRaises(ValueError):vps.secure_path(target,exists=False)
            self.assertEqual(other.read_text(),'keep')
            target.unlink();target.write_text('old');target.chmod(0o644)
            with self.assertRaises(ValueError):vps.secure_path(target,exists=False)

    def test_password_prompt_refuses_echo_fallback(self):
        with tempfile.TemporaryDirectory() as tmp:
            root=Path(tmp);root.chmod(0o700);known=root/'known_hosts';known.write_text('key');known.chmod(0o600)
            s={'ip':'192.0.2.1','ssh_alias':'my-vps','known_hosts_file':str(known)}
            with patch.object(vps,'dedicated_key',return_value=(root/'key','ssh-ed25519 AAAATEST')),patch.object(vps.sys.stdin,'isatty',return_value=True),patch.object(vps.getpass,'getpass',side_effect=vps.getpass.GetPassWarning):
                with self.assertRaisesRegex(ValueError,'Secure password terminal'):vps.bootstrap(s,root/'target.json',initial=True,ask_password=True)

    def test_maintenance_uses_installed_source_without_upload_or_preflight(self):
        with tempfile.TemporaryDirectory() as tmp:
            root=Path(tmp);root.chmod(0o700);state=root/'target.json';vps.save(state,{'ssh_alias':'my-vps','ip':'192.0.2.1'})
            with patch.object(vps.sys,'argv',['vps.py','--state',str(state),'rotate-subscriptions','--client','surge']),patch.object(vps,'validate'),patch.object(vps,'remote_stage') as remote,patch.object(vps,'source') as source,patch.object(vps,'upload') as upload:
                vps.main()
            source.assert_not_called();upload.assert_not_called()
            self.assertTrue(remote.call_args.args[1].endswith('rotate-subscriptions surge'))

    def test_password_session_disables_configured_keys_and_aliases(self):
        with tempfile.TemporaryDirectory() as tmp:
            root=Path(tmp);root.chmod(0o700);known=root/'known_hosts';known.write_text('key');known.chmod(0o600)
            s={'ip':'192.0.2.1','ssh_alias':'my-vps','ssh_port':2222,'known_hosts_file':str(known)}
            args=vps.ssh_args(s,password=True)
            self.assertEqual(args[args.index('-F')+1],'/dev/null');self.assertEqual(args[-1],s['ip'])
            self.assertIn('2222',args);self.assertNotIn('my-vps',args)

    def test_generated_key_is_private_and_reused(self):
        with tempfile.TemporaryDirectory() as tmp:
            root=Path(tmp);root.chmod(0o700)
            first,public=vps.dedicated_key({},root/'target.json')
            before=first.read_bytes();second,again=vps.dedicated_key({},root/'target.json')
            self.assertEqual(first,second);self.assertEqual(public,again);self.assertEqual(before,second.read_bytes())
            self.assertEqual(first.stat().st_mode & 0o777,0o600);self.assertEqual(first.parent.stat().st_mode & 0o777,0o700)

    def test_backup_receipt_is_copied_atomically_private_before_source_replacement(self):
        with tempfile.TemporaryDirectory() as tmp:
            root=Path(tmp);root.chmod(0o700)
            receipt={'archive':'/var/backups/sui-vps/state.tar.gz','versions':{'s_ui_version':'old'},'source_sha256':'old-source'}
            vps.save(root/'last-backup.json',receipt)
            exec(vps.receipt_copy_code(root),{})
            target=root/'source-update-backup.json'
            self.assertEqual(vps.private_json(target),receipt);self.assertEqual(target.stat().st_mode & 0o777,0o600)
            target.unlink();outside=root/'outside';outside.write_text('keep');outside.chmod(0o600);target.symlink_to(outside)
            with self.assertRaises(RuntimeError):exec(vps.receipt_copy_code(root),{})
            self.assertEqual(outside.read_text(),'keep')
        with patch.object(vps,'ssh') as ssh:vps.upload({'ip':'192.0.2.1'},(b'archive','a'*64))
        command=ssh.call_args_list[0].args[1]
        self.assertLess(command.index('server.py backup'),command.index('source-update-backup.json'))
        self.assertLess(command.index('source-update-backup.json'),command.index('tar -xzf'))

    def test_restore_forwards_only_installed_source_and_exact_quoted_arguments(self):
        with tempfile.TemporaryDirectory() as tmp:
            root=Path(tmp);root.chmod(0o700);state=root/'target.json';vps.save(state,{'ssh_alias':'my-vps','ip':'192.0.2.1'})
            archive='/var/backups/sui-vps/state selected.tar.gz'
            with patch.object(vps.sys,'argv',['vps.py','--state',str(state),'restore','--archive',archive,'--confirm-target','192.0.2.1']),patch.object(vps,'validate'),patch.object(vps,'remote_stage') as remote,patch.object(vps,'source') as source,patch.object(vps,'upload') as upload:
                vps.main()
            source.assert_not_called();upload.assert_not_called()
            parts=vps.shlex.split(remote.call_args.args[1])
            self.assertEqual(parts[-5:],['restore','--archive',archive,'--confirm-target','192.0.2.1'])

    def test_restore_rejects_missing_confirmation_and_paths_outside_backup_directory(self):
        for archive,confirmation in [('/var/backups/sui-vps/state.tar.gz',None),('/tmp/state.tar.gz','192.0.2.1'),('/var/backups/sui-vps/../other.tar.gz','192.0.2.1')]:
            with self.assertRaises(ValueError):vps.restore_command({'ip':'192.0.2.1'},archive,confirmation)

    def capability(self,s):
        return {'contract_kind':'verified-provider-api','source':'https://api.64clouds.com/v1/',
                'target_sha256':vps.provider_target_digest(s),'checked_at':vps.time.time(),
                'trusted_ssh_baseline':True,'baseline_boot_id':'12345678-1234-1234-1234-123456789abc',
                'baseline_host_key_sha256':'b'*64,'nonce_sha256':'a'*64,
                'observed_read_endpoints':['getServiceInfo','getLiveServiceInfo','getAvailableOS','getSshKeys','basicShell/exec']}

    def test_provider_proof_requires_nonce_and_matches_trusted_old_ssh(self):
        with tempfile.TemporaryDirectory() as tmp:
            root=Path(tmp);root.chmod(0o700);state=root/'target.json'
            s={'ip':'192.0.2.1','veid':1,'ssh_alias':'my-vps'}
            message='sui-provider-proof-v1:'+'a'*48+'\n12345678-1234-1234-1234-123456789abc\nssh-ed25519 AAAATEST root@host\n'
            responses={'getServiceInfo':{'ip_addresses':[s['ip']],'vm_type':'kvm'},
                       'getLiveServiceInfo':{'ip_addresses':[s['ip']],'ve_status':'running','ssh_port':2222},
                       'getAvailableOS':{'installed':'old','templates':['ubuntu-test']},
                       'getSshKeys':{'ssh_keys_preferred':'ssh-ed25519 AAAATEST'},
                       'basicShell/exec':{'message':message}}
            def api(state,method,**kwargs):return {'error':0,**responses[method]}
            with patch.object(vps,'api',side_effect=api),patch.object(vps.secrets,'token_hex',return_value='a'*48),patch.object(vps,'ssh',return_value=subprocess.CompletedProcess([],0,message,'')):
                vps.provider_proof(s,state)
            saved=vps.private_json(state);proof=vps.private_json(saved['bootstrap_proof_file'])
            self.assertEqual(proof['source'],'provider-api');self.assertEqual(proof['ssh_port'],2222)
            self.assertEqual(proof['host_public_keys'],['ssh-ed25519 AAAATEST'])
            self.assertTrue(saved['provider_capabilities']['trusted_ssh_baseline'])
            self.assertEqual(saved['provider_capabilities']['destructive_contracts']['reinstallOS'],'pending-live-test')
            original=state.read_bytes()
            responses['basicShell/exec']['message']=message.replace('a'*48,'old-replayed-nonce')
            with patch.object(vps,'api',side_effect=api),patch.object(vps.secrets,'token_hex',return_value='a'*48),patch.object(vps,'ssh'):
                with self.assertRaises(ValueError):vps.provider_proof(s,state)
            self.assertEqual(state.read_bytes(),original)

    def test_provider_api_bootstrap_rejects_unproven_origin_and_stale_proof(self):
        with tempfile.TemporaryDirectory() as tmp:
            root=Path(tmp);root.chmod(0o700);path=root/'target.json'
            s={'ip':'192.0.2.1','veid':1,'ssh_alias':'my-vps','reinstall_at':123,'pre_reinstall_boot_id':'00000000-0000-0000-0000-000000000000','bootstrap_proof_file':str(root/'proof.json')}
            proof={'source':'provider-api','endpoint':'https://api.64clouds.com/v1/basicShell/exec',
                   'target_sha256':vps.provider_target_digest(s),'ip':s['ip'],'veid':1,'reinstall_at':123,
                   'captured_at':vps.time.time(),'nonce_sha256':'a'*64,'boot_id':'12345678-1234-1234-1234-123456789abc','ssh_port':22,'host_public_keys':['ssh-ed25519 AAAATEST']}
            for changes in [{'endpoint':'https://example.com/v1/basicShell/exec'},{'captured_at':0},{'target_sha256':'wrong'},{'nonce_sha256':''},{'reinstall_at':122}]:
                vps.save(root/'proof.json',{**proof,**changes})
                with patch.object(vps,'target_info'),patch.object(vps,'wait_provider'):
                    with self.assertRaises(ValueError):vps.bootstrap_target(s,path,False)
            vps.save(root/'proof.json',proof)
            with patch.object(vps,'target_info'),patch.object(vps,'wait_provider'):
                trial,boot=vps.bootstrap_target(s,path,False)
            self.assertEqual(boot,proof['boot_id']);self.assertIn('known_hosts_file',trial)

    def test_backup_preservation_digest_is_verified_by_streaming(self):
        with tempfile.TemporaryDirectory() as tmp:
            root=Path(tmp);root.chmod(0o700);path=root/'backup.age'
            content=b'age-encryption.org/v1\n'+b'x'*200;path.write_bytes(content);path.chmod(0o600)
            digest=vps.hashlib.sha256(content).hexdigest()
            with patch.object(Path,'read_bytes',side_effect=AssertionError('must stream')):vps.check_backup(path,digest)
            path.write_bytes(content+b'tampered')
            with self.assertRaisesRegex(ValueError,'changed since preservation'):vps.check_backup(path,digest)

    def test_surge_merge_is_scoped_versioned_bound_and_preserves_leaks(self):
        with tempfile.TemporaryDirectory() as tmp:
            root=Path(tmp);root.chmod(0o700);path=root/'surge.json'
            config={'server':{'host':'192.0.2.1','deployed_at':'today','versions':{}},'nodes':[{'type':'anytls','password':'current'}],'verification':{'leaks':'未测试'}}
            report={'export_fingerprint':vps.probe_module().fingerprint(config),
                    'protocol':'anytls','result':'passed','scope':'Native Surge Mac AnyTLS HTTPS request only',
                    'configuration_mutations_performed':False,'offline_profile_check':'passed',
                    'client':{'name':'Surge Mac','version':'6.5.0','build':'10960','bundle_identifier':'com.nssurge.surge-mac'}}
            vps.save(path,report);merged=vps.merge_surge(config,path)
            self.assertIn('6.5.0',merged['verification']['clients']);self.assertIn('10960',merged['verification']['clients'])
            self.assertIn('AnyTLS：通过',merged['verification']['clients']);self.assertIn('v2rayN / v2rayNG：未测试',merged['verification']['clients'])
            self.assertEqual(merged['verification']['leaks'],'未测试')
            for result,expected in [('failed','未通过'),('inconclusive','无法确认'),('startup_failed','未完成')]:
                vps.save(path,{**report,'result':result});self.assertIn(expected,vps.merge_surge(config,path)['verification']['clients'])
            vps.save(path,report);config['nodes'][0]['password']='rotated'
            self.assertNotIn('AnyTLS：通过',vps.merge_surge(config,path)['verification']['clients'])

    def test_surge_report_without_native_version_or_wrong_scope_never_passes(self):
        with tempfile.TemporaryDirectory() as tmp:
            root=Path(tmp);root.chmod(0o700);path=root/'surge.json'
            config={'server':{'host':'192.0.2.1'},'nodes':[]}
            binding=vps.probe_module().fingerprint(config)
            for report in [{'export_fingerprint':binding,'result':'passed','capability_only':True},
                           {'export_fingerprint':binding,'result':'passed','protocol':'anytls','scope':'Native Surge Mac AnyTLS HTTPS request only','configuration_mutations_performed':False}]:
                vps.save(path,report);self.assertNotIn('AnyTLS：通过',vps.merge_surge(config,path)['verification']['clients'])

    def test_pilot_report_does_not_follow_a_different_deployment(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / 'pilot-verified.json'
            export = {'server': {'host': '192.0.2.1', 'deployed_at': 'first'},
                      'nodes': [], 'verification': {'clean_os': '未测试', 'leaks': '未测试'}}
            vps.save(path, {'node_fingerprint': vps.probe_module().fingerprint(export),
                            'clean_os': '通过', 'leaks': '通过'})
            changed = {**export, 'server': {**export['server'], 'deployed_at': 'second'}}
            self.assertEqual(vps.merge_pilot(changed, path)['verification']['clean_os'], '未测试')
            self.assertEqual(vps.merge_pilot(export, path)['verification'],
                             {'clean_os': '通过', 'leaks': '未测试'})

    def test_surge_stage_fetches_fresh_export_and_runs_only_local_script(self):
        with tempfile.TemporaryDirectory() as tmp:
            root=Path(tmp);root.chmod(0o700);state=root/'target.json';vps.save(state,{'ip':'192.0.2.1','ssh_alias':'my-vps'})
            exported=root/'export.json';vps.save(exported,{})
            with patch.object(vps.sys,'argv',['vps.py','--state',str(state),'surge']),patch.object(vps,'validate'),patch.object(vps,'fetch_export',return_value=(exported,{})) as fetched,patch.object(vps,'run') as run,patch.object(vps,'upload') as upload:
                vps.main()
            fetched.assert_called_once();upload.assert_not_called()
            self.assertEqual(run.call_args.args[0],[vps.sys.executable,str(vps.ROOT/'scripts/surge_probe.py'),'--export',str(exported),'--output',str(root/'surge.json')])

    def test_network_native_backend_forwards_explicit_core_without_global_changes(self):
        with tempfile.TemporaryDirectory() as tmp:
            root=Path(tmp);root.chmod(0o700);state=root/'target.json';vps.save(state,{'ip':'192.0.2.1','ssh_alias':'my-vps'})
            exported=root/'export.json';vps.save(exported,{})
            for extra,expected in [([],['--backend','docker']),(['--network-backend','native','--core-bin','private/native-client/sing-box'],['--backend','native','--core-bin','private/native-client/sing-box'])]:
                with patch.object(vps.sys,'argv',['vps.py','--state',str(state),'network',*extra]),patch.object(vps,'validate'),patch.object(vps,'fetch_export',return_value=(exported,{})),patch.object(vps,'run') as run,patch.object(vps,'upload') as upload:
                    vps.main()
                upload.assert_not_called()
                self.assertEqual(run.call_args.args[0],[vps.sys.executable,str(vps.ROOT/'scripts/probe.py'),'--input',str(exported),'--output',str(root/'network.json'),*expected])

    def test_network_backend_options_reject_implicit_or_wrong_stage_native_core(self):
        import contextlib
        for stage,extra in [('network',['--network-backend','native']),('network',['--core-bin','private/core']),('network',['--network-backend','docker','--core-bin','private/core']),('export',['--network-backend','native','--core-bin','private/core']),('verify',['--network-backend','docker'])]:
            with self.subTest(stage=stage,extra=extra),patch.object(vps.sys,'argv',['vps.py','--state','unused',stage,*extra]),contextlib.redirect_stderr(io.StringIO()):
                with self.assertRaises(SystemExit) as error:vps.main()
                self.assertEqual(error.exception.code,2)


if __name__=='__main__': unittest.main()
