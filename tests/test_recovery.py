"""Synthetic portable recovery, never native credentials or personal stores."""
import copy
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch
try:
    from privacy_cleanup import recovery
except ImportError:
    raise unittest.SkipTest('Recovery tests require encryption dependencies')
from privacy_cleanup.vault import Vault, SessionVault
from privacy_cleanup.cases import Cases
from privacy_cleanup.execution import Execution
from privacy_cleanup.domain import RuleError
from test_private import MemoryKeys, PROFILE, PASS, FAST, TMP
from test_privacy_modes import connect
SECRET = 'synthetic backup recovery secret'

class RecoveryTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(dir=TMP); self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name); self.keys = MemoryKeys()
        self.vault = self.open(self.root/'original', self.keys); self.addCleanup(self.vault.close)
        self.token = self.vault.unlock(PASS, create=True)['session']
        self.vault.save(self.token, PROFILE, 0)
        self.cases = Cases(self.vault)
        self.cases.create(self.token, 'spokeo', 'https://www.spokeo.com/synthetic', 'Synthetic', True)
        self.manifest = recovery.snapshot(self.vault,self.token)
        self.fast = patch('privacy_cleanup.recovery._key',side_effect=lambda secret,salt: Vault._kek(salt,FAST,recovery.passphrase_bytes(secret,setting=True)))
        self.fast.start(); self.addCleanup(self.fast.stop)
    def open(self,path,keys): return Vault(path,keys,kdf_log2n=FAST)
    def restore(self,blob=None,dest='restored',keys=None):
        keys = keys if keys is not None else MemoryKeys()
        recovery.restore(blob or recovery.seal(self.manifest,SECRET),SECRET,self.root/dest,keys,PASS,open_vault=self.open)
        v=self.open(self.root/dest,keys);self.addCleanup(v.close)
        return v,v.unlock(PASS)['session'],keys
    def test_portable_restore_lock_restart_delete_without_original_keys(self):
        connect(self.vault)
        blob=recovery.seal(recovery.snapshot(self.vault,self.token),SECRET)
        self.assertNotIn(b'synthetic-refresh',blob);self.keys.values.clear()
        v,t,keys=self.restore(blob)
        self.assertEqual(v.read(t)['profile'],PROFILE)
        self.assertFalse(v.db.execute("SELECT 1 FROM records WHERE id='sender'").fetchone())
        with self.assertRaises(RuleError): recovery.require_reconciled(v)
        with self.assertRaisesRegex(RuleError, 'Restored history'): recovery.snapshot(v,t)
        recovery.reconcile(v,t,'RECONCILED');recovery.require_reconciled(v)
        self.assertTrue(recovery.snapshot(v,t)['records'])
        version=v.read(t)['version'];v.lock()
        with self.assertRaises(RuleError): v.read(t)
        t=v.unlock(PASS)['session'];v.delete(t,'DELETE',version)
        self.assertEqual(v.db.execute('SELECT count(*) FROM records').fetchone()[0],0)
        self.assertTrue((self.root/'restored/vault.sqlite3').exists());self.assertEqual(keys.values,{})
    def test_authentication_version_and_resource_limits(self):
        blob=recovery.seal(self.manifest,SECRET)
        for bad in [b'',blob[:-1],blob+b'x',bytes([blob[0]^1])+blob[1:],blob[:30]+bytes([blob[30]^1])+blob[31:],b'x'*(recovery.MAX_BYTES+1)]:
            with self.assertRaises(RuleError): recovery.unseal(bad,SECRET)
        with self.assertRaises(RuleError): recovery.unseal(blob,'wrong synthetic passphrase')
        for k,v in [('schema',999),('format',True),('records',[]),('created_at','invalid')]:
            m=copy.deepcopy(self.manifest);m[k]=v
            with self.assertRaises(RuleError): recovery.unseal(recovery.seal(m,SECRET),SECRET)
        for row in [{'id':'sender','revision':1,'body':{}},{'id':'profile','revision':True,'body':{}}]:
            m=copy.deepcopy(self.manifest);m['records'].append(row)
            with self.assertRaises(RuleError): recovery.unseal(recovery.seal(m,SECRET),SECRET)
        nested={};cursor=nested
        for _ in range(30): cursor['x']={};cursor=cursor['x']
        m=copy.deepcopy(self.manifest);m['records'][0]['body']=nested
        with self.assertRaises(RuleError): recovery.unseal(recovery.seal(m,SECRET),SECRET)
    def test_corrupt_shape_fails_before_destination(self):
        self.manifest['records'][0]['body']={'schema':1,'id':self.manifest['records'][0]['id'][5:]}
        with self.assertRaises(RuleError): self.restore()
        self.assertFalse((self.root/'restored').exists())
    def test_malformed_history_refused_before_destination_or_keys(self):
        original = copy.deepcopy(self.manifest)
        for field in ('past_requests', 'past_attempts', 'past_executions', 'history'):
            for value in (42, {}, [42], [{}]):
                if field == 'history' and value == [{}]: continue
                self.manifest = copy.deepcopy(original)
                case = next(r['body'] for r in self.manifest['records'] if r['id'].startswith('case/'))
                case[field] = value
                keys = MemoryKeys()
                with self.assertRaises(RuleError): self.restore(keys=keys)
                self.assertFalse((self.root/'restored').exists()); self.assertEqual(keys.values,{})

    def test_export_atomic_encrypted_and_no_overwrite(self):
        target=self.root/'backup.velum';recovery.export(self.vault,self.token,target,SECRET)
        original=target.read_bytes();self.assertEqual(target.stat().st_mode&0o777,0o600)
        self.assertEqual(recovery.unseal(recovery.read_archive(target),SECRET)['records'],self.manifest['records'])
        with self.assertRaises(FileExistsError): recovery.export(self.vault,self.token,target,SECRET)
        self.assertEqual(target.read_bytes(),original)
        with patch('privacy_cleanup.recovery.os.link',side_effect=OSError('Synthetic interruption')),self.assertRaises(OSError):
            recovery.export(self.vault,self.token,self.root/'interrupted.velum',SECRET)
        self.assertFalse((self.root/'interrupted.velum').exists());self.assertFalse(list(self.root.glob('.velum-backup-*')))
    def test_restore_overwrite_refusal_and_transaction_rollback(self):
        with self.assertRaises(FileExistsError): self.restore(dest='original')
        self.assertEqual(self.vault.read(self.token)['profile'],PROFILE)
        keys=MemoryKeys();original=Vault._write_record
        def interrupted(v,*args):
            original(v,*args)
            if v.store=='vault': raise RuntimeError('Synthetic interruption')
        with patch.object(Vault,'_write_record',interrupted),self.assertRaises(RuntimeError): self.restore(keys=keys)
        self.assertEqual(keys.values,{})
        v=self.open(self.root/'restored',keys);self.addCleanup(v.close)
        self.assertEqual(v._meta()[1],'empty');self.assertEqual(v.db.execute('SELECT count(*) FROM records').fetchone()[0],0)
    def test_paused_queue_preserved_uncertainty_and_outbound_gate(self):
        case=self.cases._load()[0]
        with self.vault.db:
            case['attempt']={'id':'synthetic','fingerprint':'synthetic','state':'uncertain','started_at':'2026-10-17T00:00:00Z'}
            self.vault._write_record('case/'+case['id'],{k:v for k,v in case.items() if k!='version'},case['version']+1)
            self.vault._write_record('workflow',{'schema':1,'paused':False,'case_ids':[case['id']],'external':[],'history':[]},1)
        self.manifest=recovery.snapshot(self.vault,self.token);v,t,_=self.restore()
        from privacy_cleanup.workflow import read
        self.assertTrue(read(v)[0]['paused']);c=Cases(v)._load()[0]
        self.assertEqual(c['attempt']['state'],'uncertain')
        with self.assertRaisesRegex(RuleError,'Restored history'):
            Cases(v).command(t,c['id'],c['version'],'approve',{'fingerprint':'x','acknowledged':True})
        with self.assertRaisesRegex(RuleError,'Restored history'):
            Execution(v,Cases(v),None).dispatch(t,c['id'],c['version'],'x')
        with self.assertRaises(RuleError): recovery.reconcile(v,t,'no')
    def test_session_lock_and_symlink_refusal(self):
        s=SessionVault();self.addCleanup(s.close)
        with self.assertRaises(RuleError): recovery.snapshot(s,s.start()['session'])
        self.vault.lock()
        with self.assertRaises(RuleError): recovery.snapshot(self.vault,self.token)
        target=self.root/'link';target.symlink_to(self.root/'original/vault.sqlite3')
        with self.assertRaises(OSError): recovery.read_archive(target)
    def test_production_kdf_roundtrip(self):
        self.fast.stop();blob=recovery.seal(self.manifest,SECRET)
        self.assertEqual(recovery.unseal(blob,SECRET),self.manifest)

    def test_existing_approved_email_and_dispatching_history_restore_conservatively(self):
        import test_execution
        journey=test_execution.ExecutionTests();journey.setUp();self.addCleanup(journey.doCleanups)
        journey.ready('apollo')
        self.manifest=recovery.snapshot(journey.vault,journey.session)
        v,t,_=self.restore()
        cases=Cases(v);Execution(v,cases,None)
        a=next(c for c in cases._load() if c['broker']=='apollo')
        self.assertIsNone(a['execution']['approval'])
        self.assertTrue(a['execution']['revoked'])
        recovery.reconcile(v,t,'RECONCILED')
        from privacy_cleanup.workflow import read
        self.assertTrue(read(v)[0]['paused'])
        with self.assertRaises(RuleError): cases.execution.dispatch(t,a['id'],a['version'],a['execution']['fingerprint'])
        with journey.vault.db:
            stored=next(c for c in journey.cases._load() if c['broker']=='apollo')
            stored['execution']['state']='dispatching'
            journey.cases._save(stored)
        self.manifest=recovery.snapshot(journey.vault,journey.session)
        v,t,_=self.restore(dest='interrupted')
        restored=next(c for c in Cases(v)._load() if c['broker']=='apollo')
        self.assertEqual(restored['execution']['state'],'uncertain')
        self.assertEqual(restored['execution']['approval'],stored['execution']['approval'])

    def test_manual_approval_invalidated_but_history_preserved(self):
        import test_cases
        journey=test_cases.CasesTests();journey.setUp();self.addCleanup(journey.doCleanups)
        journey.approve();before=journey.current()
        self.manifest=recovery.snapshot(journey.vault,journey.session)
        v,t,_=self.restore();case=Cases(v)._load()[0]
        self.assertIsNone(case['request']['approval']);self.assertTrue(case['request']['revoked'])
        self.assertEqual(case['history'],before['history'])
        recovery.reconcile(v,t,'RECONCILED')
        with self.assertRaises(RuleError):
            Cases(v).command(t,case['id'],case['version'],'handoff',{'fingerprint':case['request']['fingerprint'],'dry_run':False})

    def test_snapshot_serializes_with_save_and_retains_its_own_revision(self):
        import threading
        entered,done=threading.Event(),threading.Event()
        updated=copy.deepcopy(PROFILE);updated['names'][0]['full_name']='Different Synthetic Example'
        def save():
            entered.set();self.vault.save(self.token,updated,1);done.set()
        with self.vault.mutex:
            worker=threading.Thread(target=save);worker.start();self.assertTrue(entered.wait(1))
            snap=recovery.snapshot(self.vault,self.token)
            self.assertFalse(done.is_set())
        worker.join(3);self.assertTrue(done.is_set())
        profile=next(r for r in snap['records'] if r['id']=='profile')
        self.assertEqual(profile['revision'],1);self.assertEqual(profile['body']['profile'],PROFILE)
        self.assertEqual(self.vault.read(self.token)['profile'],updated)

    def test_key_store_failure_leaves_no_active_store(self):
        keys=MemoryKeys()
        with patch.object(keys,'put',side_effect=RuleError('Synthetic key failure')),self.assertRaises(RuleError): self.restore(keys=keys)
        v=self.open(self.root/'restored',keys);self.addCleanup(v.close)
        self.assertEqual(v._meta()[1],'empty');self.assertEqual(keys.values,{})

    def test_bad_header_refused_before_kdf_and_fifo_refused(self):
        with patch('privacy_cleanup.recovery._key') as key:
            with self.assertRaises(RuleError): recovery.unseal(b'bad'*100,SECRET)
            key.assert_not_called()
        import os
        path=self.root/'pipe';os.mkfifo(path,0o600)
        with self.assertRaises(RuleError): recovery.read_archive(path)

    def test_cli_hidden_secret_export_restore_and_cancellation(self):
        import contextlib,io,sys
        self.vault.close()
        target=self.root/'cli.velum';keys=MemoryKeys()
        def run(action,directory,answers,store):
            args=['velum',action,'--synthetic-workspace','--data-dir',str(directory),'--archive',str(target)]
            with patch.object(sys,'argv',args),patch.object(sys,'platform','darwin'),patch('privacy_cleanup.key_store.MacKeyStore',return_value=store),patch('privacy_cleanup.network.install'),patch('getpass.getpass',side_effect=answers),contextlib.redirect_stdout(io.StringIO()):
                recovery.main()
        run('export',self.root/'original',[PASS,SECRET,SECRET],self.keys)
        run('restore',self.root/'cli-restored',[SECRET,PASS,PASS],keys)
        v=self.open(self.root/'cli-restored',keys);self.addCleanup(v.close)
        self.assertEqual(v.unlock(PASS)['profile'],PROFILE)
        with self.assertRaises(SystemExit): run('restore',self.root/'cancelled',[KeyboardInterrupt()],keys)
        self.assertFalse((self.root/'cancelled').exists())
