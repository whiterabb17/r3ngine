"""The ``domain_info`` block shared by the scan summary and target summary endpoints."""
from typing import Any, Optional

from targetApp.models import DomainInfo, DomainRegistration

# Relations `build_domain_info_summary` reads through a foreign key. Callers add
# them to `select_related` (prefixed with the path to the DomainInfo) so the block
# costs no query per contact.
DOMAIN_INFO_RELATIONS = ('registrar', 'registrant', 'admin', 'tech')

_CONTACT_FIELDS = (
    'name', 'organization', 'email', 'phone', 'fax',
    'address', 'city', 'state', 'zip_code', 'country',
)


def domain_info_select_related(prefix: str) -> list[str]:
    """`select_related` paths for the DomainInfo reached through ``prefix``."""
    return [prefix] + [f'{prefix}__{relation}' for relation in DOMAIN_INFO_RELATIONS]


def build_domain_info_summary(domain_info: Optional[DomainInfo]) -> Optional[dict[str, Any]]:
    """Serialise a target's DomainInfo for the summary endpoints' Domain Info and WHOIS tabs.

    ``whois`` carries what the WHOIS lookup (`save_domain_info_to_db`) and the
    domain recon tools (`jswhois` / `whoisdomain`, stored in ``whois_raw``) persist.
    """
    if domain_info is None:
        return None

    registrar = domain_info.registrar
    name_servers = list(domain_info.name_servers.values_list('name', flat=True)[:10])
    return {
        'dnssec': domain_info.dnssec,
        'geolocation_iso': domain_info.geolocation_iso,
        'created': domain_info.created,
        'updated': domain_info.updated,
        'expires': domain_info.expires,
        'whois_server': domain_info.whois_server,
        'registrar': {
            'name': registrar.name if registrar else None,
            'phone': registrar.phone if registrar else None,
            'email': registrar.email if registrar else None,
            'url': registrar.url if registrar else None,
        },
        'dns_records': list(domain_info.dns_records.values('type', 'name')[:20]),
        'name_servers': [{'name': name} for name in name_servers],
        'nameservers': name_servers,
        'historical_ips': list(
            domain_info.historical_ips.values('ip', 'location', 'owner', 'last_seen')[:10]
        ),
        'whois': {
            'statuses': list(domain_info.status.values_list('name', flat=True)[:20]),
            'registrant': _contact(domain_info.registrant),
            'admin': _contact(domain_info.admin),
            'tech': _contact(domain_info.tech),
            'raw': domain_info.whois_raw,
        },
    }


def _contact(registration: Optional[DomainRegistration]) -> Optional[dict[str, Optional[str]]]:
    if registration is None:
        return None
    contact = {field: getattr(registration, field) for field in _CONTACT_FIELDS}
    # `save_domain_info_to_db` stores a row even when the lookup had no such
    # contact (name ''), which is no contact as far as the tab is concerned.
    return contact if any(contact.values()) else None
