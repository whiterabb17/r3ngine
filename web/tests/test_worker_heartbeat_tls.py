"""The remote worker verifies the master's certificate before sending its token."""
from unittest import TestCase
from unittest.mock import patch

from scanEngine.management.commands.run_temporal_orchestrator import master_tls_verify


class MasterTlsVerifyTests(TestCase):

    def test_verifies_by_default(self):
        with patch.dict('os.environ', {}, clear=True):
            self.assertIs(master_tls_verify(), True)

    def test_uses_the_ca_bundle_when_given(self):
        with patch.dict('os.environ', {'MASTER_CA_BUNDLE': '/certs/rootCA.pem', 'MASTER_TLS_VERIFY': '0'}, clear=True):
            self.assertEqual(master_tls_verify(), '/certs/rootCA.pem')

    def test_can_be_turned_off_explicitly(self):
        for value in ('0', 'false', 'No '):
            with patch.dict('os.environ', {'MASTER_TLS_VERIFY': value}, clear=True):
                self.assertIs(master_tls_verify(), False, value)
