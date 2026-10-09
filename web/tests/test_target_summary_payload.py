"""The `domain_info` block of /api/target-summary/ (WHOIS and Domain Info tabs).

All domains, hosts and users here are anonymised (RFC 2606 / RFC 5737 ranges).
"""
from django.contrib.auth import get_user_model
from django.db import connection
from django.test import TestCase
from django.test.utils import CaptureQueriesContext
from django.urls import reverse
from django.utils import timezone
from rest_framework.test import APIClient
from rolepermissions.roles import assign_role

from dashboard.models import Project
from targetApp.models import (
    DNSRecord, Domain, DomainInfo, DomainRegistration, Registrar, WhoisStatus,
)

User = get_user_model()


class TargetSummaryDomainInfoTests(TestCase):
    def setUp(self) -> None:
        self.client = APIClient()
        self.user = User.objects.create_user(
            username='target-summary-user', password='pass', email='ts@example.test',
            is_staff=True, is_superuser=True,
        )
        self.client.force_authenticate(user=self.user)
        # A session login too: the login-required middleware runs before DRF auth.
        self.client.force_login(self.user)
        assign_role(self.user, 'sys_admin')
        self.project = Project.objects.create(
            name='target-summary', slug='target-summary', insert_date=timezone.now()
        )
        self.domain = Domain.objects.create(
            name='ts.example.test', project=self.project, insert_date=timezone.now()
        )

    @property
    def url(self) -> str:
        return reverse(
            'api:target_summary_api',
            kwargs={'slug': self.project.slug, 'id': self.domain.id},
        )

    def _payload(self) -> dict:
        response = self.client.get(self.url)
        self.assertEqual(response.status_code, 200)
        return response.json()

    def _cost(self) -> int:
        with CaptureQueriesContext(connection) as captured:
            response = self.client.get(self.url)
            self.assertEqual(response.status_code, 200)
        return len(captured)

    def _attach_domain_info(self, **kwargs) -> DomainInfo:
        info = DomainInfo.objects.create(**kwargs)
        self.domain.domain_info = info
        self.domain.save(update_fields=['domain_info'])
        return info

    def test_domain_info_is_null_without_a_lookup(self) -> None:
        self.assertIsNone(self._payload()['domain_info'])

    def test_whois_block_and_boolean_dnssec(self) -> None:
        info = self._attach_domain_info(
            dnssec=True,
            registrar=Registrar.objects.create(name='Example Registrar'),
            tech=DomainRegistration.objects.create(name='NOC', email='noc@example.test'),
            whois_raw={'domain': 'ts.example.test'},
        )
        info.status.add(WhoisStatus.objects.create(name='ok'))
        info.dns_records.add(DNSRecord.objects.create(name='192.0.2.1', type='a'))

        domain_info = self._payload()['domain_info']
        self.assertIs(domain_info['dnssec'], True)
        self.assertEqual(domain_info['dns_records'], [{'type': 'a', 'name': '192.0.2.1'}])
        self.assertEqual(domain_info['registrar']['name'], 'Example Registrar')
        self.assertEqual(domain_info['whois']['statuses'], ['ok'])
        self.assertEqual(domain_info['whois']['tech']['email'], 'noc@example.test')
        self.assertIsNone(domain_info['whois']['registrant'])
        self.assertEqual(domain_info['whois']['raw'], {'domain': 'ts.example.test'})

    def test_whois_contacts_are_joined_not_queried(self) -> None:
        info = self._attach_domain_info()
        self.client.get(self.url)
        without_contacts = self._cost()

        info.registrar = Registrar.objects.create(name='R')
        for role in ('registrant', 'admin', 'tech'):
            setattr(info, role, DomainRegistration.objects.create(name=f'{role} contact'))
        info.save()
        self.assertEqual(without_contacts, self._cost())

    def test_cost_does_not_grow_with_domain_rows(self) -> None:
        info = self._attach_domain_info()
        info.dns_records.add(DNSRecord.objects.create(name='192.0.2.1', type='a'))
        info.status.add(WhoisStatus.objects.create(name='status1'))
        self.client.get(self.url)
        one = self._cost()

        for index in range(2, 12):
            info.dns_records.add(DNSRecord.objects.create(name=f'192.0.2.{index}', type='a'))
            info.status.add(WhoisStatus.objects.create(name=f'status{index}'))
        self.assertEqual(one, self._cost())
