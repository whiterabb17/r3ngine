"""An operator switch for email security as a whole.

MasterScanWorkflow schedules the email security activity whenever `port_scan`
is in the task list, with no condition of its own, so before this there was no
way to turn the feature off short of dropping the port scan. The switch is read
inside the activity rather than in the workflow: a branch in the workflow would
change the recorded command sequence and need a `workflow.patched()` guard for
scans already in flight.
"""
from unittest import TestCase

from reNgine.task_plan import _mailbox_verification_planned, email_security_enabled


class TestEmailSecurityEnabled(TestCase):

    def test_absent_config_leaves_it_on(self):
        """Existing engines have no such key and must behave as they did."""
        self.assertTrue(email_security_enabled({}))

    def test_absent_section_leaves_it_on(self):
        self.assertTrue(email_security_enabled({'port_scan': {}}))

    def test_section_without_the_key_leaves_it_on(self):
        self.assertTrue(
            email_security_enabled({'email_security': {'mailbox_verification': {'enabled': True}}})
        )

    def test_explicitly_disabled(self):
        self.assertFalse(email_security_enabled({'email_security': {'enabled': False}}))

    def test_explicitly_enabled(self):
        self.assertTrue(email_security_enabled({'email_security': {'enabled': True}}))

    def test_malformed_section_leaves_it_on(self):
        """A string or list where a mapping was expected must not disable it."""
        self.assertTrue(email_security_enabled({'email_security': 'yes'}))
        self.assertTrue(email_security_enabled({'email_security': []}))

    def test_non_mapping_configuration(self):
        self.assertTrue(email_security_enabled(None))
        self.assertTrue(email_security_enabled('not a mapping'))


class TestMailboxVerificationFollowsTheSwitch(TestCase):
    """Turning the feature off must also drop its timeline row."""

    def test_disabled_email_security_drops_mailbox_verification(self):
        self.assertFalse(
            _mailbox_verification_planned(
                ['port_scan'],
                {'email_security': {'enabled': False, 'mailbox_verification': {'enabled': True}}},
            )
        )

    def test_enabled_email_security_keeps_mailbox_verification(self):
        self.assertTrue(
            _mailbox_verification_planned(['port_scan'], {'email_security': {'enabled': True}})
        )

    def test_mailbox_verification_can_be_dropped_on_its_own(self):
        self.assertFalse(
            _mailbox_verification_planned(
                ['port_scan'],
                {'email_security': {'mailbox_verification': {'enabled': False}}},
            )
        )

    def test_still_needs_a_port_scan(self):
        self.assertFalse(_mailbox_verification_planned([], {'email_security': {'enabled': True}}))
