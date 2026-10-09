"""WHOIS contact addresses reach the keys save_domain_info_to_db stores.

The parser used to copy `street`, `province` and `postal_code` under those
names while the save read `address`, `state` and `zip_code`, so every contact's
address, state and postal code were dropped.
"""
from unittest import TestCase

from reNgine.common_func.whois_info import parse_registration_info


class ParseRegistrationInfoTests(TestCase):

    def test_address_fields_use_the_saved_names(self):
        domain_info = {}
        parse_registration_info(domain_info, {
            'name': 'Registrant Example',
            'street': '1 Example Street',
            'province': 'Example State',
            'postal_code': '00000',
            'city': 'Example City',
            'email': 'Contact: owner@example.test',
            'unrelated': 'ignored',
        }, 'registrant')

        self.assertEqual(domain_info['registrant_address'], '1 Example Street')
        self.assertEqual(domain_info['registrant_state'], 'Example State')
        self.assertEqual(domain_info['registrant_zip_code'], '00000')
        self.assertEqual(domain_info['registrant_city'], 'Example City')
        self.assertEqual(domain_info['registrant_email'], 'owner@example.test')
        self.assertNotIn('registrant_street', domain_info)
        self.assertNotIn('registrant_unrelated', domain_info)

    def test_administrative_role_is_stored_as_admin(self):
        domain_info = {}
        parse_registration_info(domain_info, {'province': 'Example State'}, 'administrative')
        self.assertEqual(domain_info, {'admin_state': 'Example State'})
