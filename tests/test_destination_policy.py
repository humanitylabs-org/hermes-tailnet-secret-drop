"""Destination policy gates: fixtures only, no provider calls or live secrets."""
from __future__ import annotations
import importlib.util
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

SPEC=importlib.util.spec_from_file_location('destination_secret_drop',Path(__file__).resolve().parents[1]/'src/secret_drop.py')
assert SPEC and SPEC.loader
sd=importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(sd)

class DestinationPolicyTests(unittest.TestCase):
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory()
        self.root=Path(self.temp.name)
        self.env=self.root/'host.env'
        self.config={'state_dir':str(self.root/'state'),'env_path':str(self.env),
                     'socket_path':str(self.root/'drop.sock'),'public_base_url':'https://host.example.ts.net',
                     'encryption_key_path':str(self.root/'key.pem'),'allowed_env_keys':['TINFOIL_API_KEY']}
    def tearDown(self):
        self.temp.cleanup()
    def request(self,key='TINFOIL_API_KEY'):
        return sd.create_request(self.config,key,'Host Voice key','opaque',15)
    def test_allowed_key_delivers_only_to_configured_host_file(self):
        r=self.request()
        sd.consume_request(self.config,r['request_id'],'fixture-only-not-a-credential')
        self.assertIn('TINFOIL_API_KEY=',self.env.read_text())
        self.assertEqual(self.env.stat().st_mode&0o777,0o600)
    def test_wrong_agent_key_cannot_mint_request_or_touch_state(self):
        with self.assertRaises(sd.SecretDropError) as e:self.request('OPENAI_API_KEY')
        self.assertEqual(e.exception.status,403)
        self.assertFalse((self.root/'state').exists())
        self.assertFalse(self.env.exists())
    def test_provider_adapter_cannot_bypass_policy(self):
        with self.assertRaises(sd.SecretDropError):
            sd.create_request(self.config,None,None,None,15,adapter='openrouter-hermes')
        self.assertFalse(self.env.exists())
    def test_bundle_rejects_all_if_one_key_is_not_allowed(self):
        fields=[{'env_key':key,'label':'Fixture','validator':'opaque'} for key in ['TINFOIL_API_KEY','OPENAI_API_KEY']]
        with self.assertRaises(sd.SecretDropError):sd.create_bundle_request(self.config,'Fixture',fields,15)
        self.assertFalse((self.root/'state').exists())
        self.assertFalse(self.env.exists())
    def test_existing_legacy_request_rechecked_before_validation(self):
        del self.config['allowed_env_keys']
        r=self.request('OPENAI_API_KEY')
        self.config['allowed_env_keys']=['TINFOIL_API_KEY']
        with patch.dict(sd.VALIDATORS,{'opaque':(lambda _:self.fail('validator must not run'),'fixture')}):
            with self.assertRaises(sd.SecretDropError):sd.consume_request(self.config,r['request_id'],'fixture-only')
        self.assertFalse(self.env.exists())
    def test_recheck_under_commit_lock_after_validation(self):
        r=self.request()
        def revoke(value):
            self.config['allowed_env_keys']=[]
            return value
        with patch.dict(sd.VALIDATORS,{'opaque':(revoke,'fixture')}):
            with self.assertRaises(sd.SecretDropError):sd.consume_request(self.config,r['request_id'],'fixture-only')
        self.assertFalse(self.env.exists())
    def test_missing_policy_preserves_legacy_intake(self):
        del self.config['allowed_env_keys']
        self.assertEqual(self.request('OPENAI_API_KEY')['status'],'pending')
    def test_empty_policy_disables_intake_but_not_demo(self):
        self.config['allowed_env_keys']=[]
        with self.assertRaises(sd.SecretDropError):self.request()
        self.assertEqual(sd.create_request(self.config,None,None,None,15,demo=True)['mode'],'demo')
    def test_malformed_policy_fails_closed_without_normalizing_identifiers(self):
        for value in [None,False,'TINFOIL_API_KEY',{},['TINFOIL_API_KEY','TINFOIL_API_KEY'],[3],[' TINFOIL_API_KEY'],['PATH']]:
            with self.subTest(value=value):
                self.config['allowed_env_keys']=value
                with self.assertRaises(sd.SecretDropError):self.request()
                self.assertFalse(self.env.exists())

if __name__=='__main__':unittest.main()
