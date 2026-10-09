"""WHOIS / domain-info extraction, formatting and persistence, plus viewdns.info lookups.

Split out of the former reNgine/common_func.py; re-exported by
reNgine.common_func for backward compatibility.
"""
import logging

import requests
from bs4 import BeautifulSoup
from django.utils import timezone
from dotted_dict import DottedDict

from reNgine.definitions import EMAIL_REGEX
from targetApp.models import (
	DNSRecord,
	Domain,
	DomainInfo,
	DomainRegistration,
	HistoricalIP,
	NameServer,
	Registrar,
	RelatedDomain,
	WhoisStatus,
)

logger = logging.getLogger(__name__)


def reverse_whois(lookup_keyword):
	domains = []
	'''
		This function will use viewdns to fetch reverse whois info
		Input: lookup keyword like email or registrar name
		Returns a list of domains as string.
	'''
	logger.info('Querying reverse whois for %s', lookup_keyword)
	url = f"https://viewdns.info:443/reversewhois/?q={lookup_keyword}"
	headers = {
		"Sec-Ch-Ua": "\" Not A;Brand\";v=\"99\", \"Chromium\";v=\"104\"",
		"Sec-Ch-Ua-Mobile": "?0",
		"Sec-Ch-Ua-Platform": "\"Linux\"",
		"Upgrade-Insecure-Requests": "1",
		"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/104.0.5112.102 Safari/537.36",
		"Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.9",
		"Sec-Fetch-Site": "same-origin",
		"Sec-Fetch-Mode": "navigate",
		"Sec-Fetch-User": "?1",
		"Sec-Fetch-Dest": "document",
		"Referer": "https://viewdns.info/",
		"Accept-Encoding": "gzip, deflate",
		"Accept-Language": "en-GB,en-US;q=0.9,en;q=0.8"
	}
	# Reached synchronously from the ReverseWhois API view — without a timeout a
	# slow viewdns.info parks a web worker indefinitely.
	response = requests.get(url, headers=headers, timeout=30)
	soup = BeautifulSoup(response.content, 'lxml')
	table = soup.find("table", {"border" : "1"})
	try:
		for row in table or []:
			dom = row.findAll('td')[0].getText()
			# created_on = row.findAll('td')[1].getText() TODO: add this in 3.0
			if dom == 'Domain Name':
				continue
			domains.append(dom)
	except Exception as e:
		logger.error('Error while fetching reverse whois info: %s', e)
	return domains


def get_domain_historical_ip_address(domain):
	ips = []
	'''
		This function will use viewdns to fetch historical IP address
		for a domain
	'''
	logger.info('Fetching historical IP address for domain %s', domain)
	url = f"https://viewdns.info/iphistory/?domain={domain}"
	headers = {
		"Sec-Ch-Ua": "\" Not A;Brand\";v=\"99\", \"Chromium\";v=\"104\"",
		"Sec-Ch-Ua-Mobile": "?0",
		"Sec-Ch-Ua-Platform": "\"Linux\"",
		"Upgrade-Insecure-Requests": "1",
		"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/104.0.5112.102 Safari/537.36",
		"Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.9",
		"Sec-Fetch-Site": "same-origin",
		"Sec-Fetch-Mode": "navigate",
		"Sec-Fetch-User": "?1",
		"Sec-Fetch-Dest": "document",
		"Referer": "https://viewdns.info/",
		"Accept-Encoding": "gzip, deflate",
		"Accept-Language": "en-GB,en-US;q=0.9,en;q=0.8"
	}
	# Same as above: DomainIPHistory calls this straight from the request path.
	response = requests.get(url, headers=headers, timeout=30)
	soup = BeautifulSoup(response.content, 'lxml')
	table = soup.find("table", {"border" : "1"}) 
	for row in table or []:
		ip = row.findAll('td')[0].getText()
		location = row.findAll('td')[1].getText()
		owner = row.findAll('td')[2].getText()
		last_seen = row.findAll('td')[2].getText()
		if ip == 'IP Address':
			continue
		ips.append(
			{
				'ip': ip,
				'location': location,
				'owner': owner,
				'last_seen': last_seen,
			}
		)
	return ips


def get_domain_info_from_db(target):
	"""
		Retrieves the Domain object from the database using the target domain name.

		Args:
			target (str): The domain name to search for.

		Returns:
			Domain: The Domain object if found, otherwise None.
	"""
	try:
		domain = Domain.objects.get(name=target)
		if not domain.insert_date:
			domain.insert_date = timezone.now()
			domain.save()
		return extract_domain_info(domain)
	except Domain.DoesNotExist:
		return None


def extract_domain_info(domain):
	"""
		Extract domain info from the domain_info_db.
		Args:
			domain: Domain object

		Returns:
			DottedDict: The domain info object.
	"""
	if not domain:
		return DottedDict()
	
	domain_name = domain.name
	domain_info_db = domain.domain_info
	
	try:
		domain_info = DottedDict({
			'dnssec': domain_info_db.dnssec,
			'created': domain_info_db.created,
			'updated': domain_info_db.updated,
			'expires': domain_info_db.expires,
			'geolocation_iso': domain_info_db.geolocation_iso,
			'status': [status.name for status in domain_info_db.status.all()],
			'whois_server': domain_info_db.whois_server,
			'ns_records': [ns.name for ns in domain_info_db.name_servers.all()],
		})

		# Extract registrar info
		registrar = domain_info_db.registrar
		if registrar:
			domain_info.update({
				'registrar_name': registrar.name,
				'registrar_phone': registrar.phone,
				'registrar_email': registrar.email,
				'registrar_url': registrar.url,
			})

		# Extract registration info (registrant, admin, tech)
		for role in ['registrant', 'admin', 'tech']:
			registration = getattr(domain_info_db, role)
			if registration:
				domain_info.update({
					f'{role}_{key}': getattr(registration, key)
					for key in ['name', 'id_str', 'organization', 'city', 'state', 'zip_code', 
								'country', 'phone', 'fax', 'email', 'address']
				})

		# Extract DNS records
		dns_records = domain_info_db.dns_records.all()
		for record_type in ['a', 'txt', 'mx']:
			domain_info[f'{record_type}_records'] = [
				record.name for record in dns_records if record.type == record_type
			]

		# Extract related domains and TLDs
		domain_info.update({
			'related_tlds': [domain.name for domain in domain_info_db.related_tlds.all()],
			'related_domains': [domain.name for domain in domain_info_db.related_domains.all()],
		})

		# Extract historical IPs
		domain_info['historical_ips'] = [
			{
				'ip': ip.ip,
				'owner': ip.owner,
				'location': ip.location,
				'last_seen': ip.last_seen
			}
			for ip in domain_info_db.historical_ips.all()
		]

		domain_info['target'] = domain_name
	except Exception as e:
		logger.error('Error while extracting domain info: %s', e)
		domain_info = DottedDict()

	return domain_info


def format_whois_response(domain_info):
	"""
		Format the domain info for the whois response.
		Args:
			domain_info (DottedDict): The domain info object.
		Returns:
			dict: The formatted whois response.	
	"""
	return {
		'status': True,
		'target': domain_info.get('target'),
		'dnssec': domain_info.get('dnssec'),
		'created': domain_info.get('created'),
		'updated': domain_info.get('updated'),
		'expires': domain_info.get('expires'),
		'geolocation_iso': domain_info.get('registrant_country'),
		'domain_statuses': domain_info.get('status'),
		'whois_server': domain_info.get('whois_server'),
		'dns': {
			'a': domain_info.get('a_records'),
			'mx': domain_info.get('mx_records'),
			'txt': domain_info.get('txt_records'),
		},
		'registrar': {
			'name': domain_info.get('registrar_name'),
			'phone': domain_info.get('registrar_phone'),
			'email': domain_info.get('registrar_email'),
			'url': domain_info.get('registrar_url'),
		},
		'registrant': {
			'name': domain_info.get('registrant_name'),
			'id': domain_info.get('registrant_id'),
			'organization': domain_info.get('registrant_organization'),
			'address': domain_info.get('registrant_address'),
			'city': domain_info.get('registrant_city'),
			'state': domain_info.get('registrant_state'),
			'zipcode': domain_info.get('registrant_zip_code'),
			'country': domain_info.get('registrant_country'),
			'phone': domain_info.get('registrant_phone'),
			'fax': domain_info.get('registrant_fax'),
			'email': domain_info.get('registrant_email'),
		},
		'admin': {
			'name': domain_info.get('admin_name'),
			'id': domain_info.get('admin_id'),
			'organization': domain_info.get('admin_organization'),
			'address':domain_info.get('admin_address'),
			'city': domain_info.get('admin_city'),
			'state': domain_info.get('admin_state'),
			'zipcode': domain_info.get('admin_zip_code'),
			'country': domain_info.get('admin_country'),
			'phone': domain_info.get('admin_phone'),
			'fax': domain_info.get('admin_fax'),
			'email': domain_info.get('admin_email'),
		},
		'technical_contact': {
			'name': domain_info.get('tech_name'),
			'id': domain_info.get('tech_id'),
			'organization': domain_info.get('tech_organization'),
			'address': domain_info.get('tech_address'),
			'city': domain_info.get('tech_city'),
			'state': domain_info.get('tech_state'),
			'zipcode': domain_info.get('tech_zip_code'),
			'country': domain_info.get('tech_country'),
			'phone': domain_info.get('tech_phone'),
			'fax': domain_info.get('tech_fax'),
			'email': domain_info.get('tech_email'),
		},
		'nameservers': domain_info.get('ns_records'),
		'related_domains': domain_info.get('related_domains'),
		'related_tlds': domain_info.get('related_tlds'),
		'historical_ips': domain_info.get('historical_ips'),
	}


def parse_whois_data(domain_info, whois_data):
	"""Parse WHOIS data and update domain_info."""
	whois = whois_data.get('whois', {})
	dns = whois_data.get('dns', {})

	# Parse basic domain information
	domain_info.update({
		'created': whois.get('created_date', None),
		'expires': whois.get('expiration_date', None),
		'updated': whois.get('updated_date', None),
		'whois_server': whois.get('whois_server', None),
		'dnssec': bool(whois.get('dnssec', False)),
		'status': whois.get('status', []),
	})

	# Parse registrar information
	parse_registrar_info(domain_info, whois.get('registrar', {}))

	# Parse registration information
	for role in ['registrant', 'administrative', 'technical']:
		parse_registration_info(domain_info, whois.get(role, {}), role)

	# Parse DNS records
	parse_dns_records(domain_info, dns)

	# Parse name servers
	domain_info.ns_records = dns.get('ns', [])


def parse_registrar_info(domain_info, registrar):
	"""Parse registrar information."""
	domain_info.update({
		'registrar_name': registrar.get('name', None),
		'registrar_email': registrar.get('email', None),
		'registrar_phone': registrar.get('phone', None),
		'registrar_url': registrar.get('url', None),
	})


# WHOIS contact fields -> the DomainRegistration field names save_domain_info_to_db reads.
_REGISTRATION_KEYS = {
	'name': 'name', 'id': 'id', 'organization': 'organization', 'street': 'address',
	'city': 'city', 'province': 'state', 'postal_code': 'zip_code', 'country': 'country',
	'phone': 'phone', 'fax': 'fax',
}


def parse_registration_info(domain_info, registration, role):
	"""Parse registration information for registrant, admin, and tech contacts."""
	role_prefix = role if role != 'administrative' else 'admin'
	domain_info.update({
		f'{role_prefix}_{_REGISTRATION_KEYS[key]}': value
		for key, value in registration.items()
		if key in _REGISTRATION_KEYS
	})

	# Handle email separately to apply regex
	email = registration.get('email')
	if email:
		email_match = EMAIL_REGEX.search(str(email))
		domain_info[f'{role_prefix}_email'] = email_match.group(0) if email_match else None


def parse_dns_records(domain_info, dns):
	"""Parse DNS records."""
	domain_info.update({
		'mx_records': dns.get('mx', []),
		'txt_records': dns.get('txt', []),
		'a_records': dns.get('a', []),
		'ns_records': dns.get('ns', []),
	})


def save_domain_info_to_db(target, domain_info):
	"""Save domain info to the database."""
	if Domain.objects.filter(name=target).exists():
		domain, _ = Domain.objects.get_or_create(name=target)
		
		# Create or update DomainInfo
		domain_info_obj, created = DomainInfo.objects.get_or_create(domain=domain)
		
		# Update basic domain information
		domain_info_obj.dnssec = domain_info.get('dnssec', False)
		domain_info_obj.created = domain_info.get('created')
		domain_info_obj.updated = domain_info.get('updated')
		domain_info_obj.expires = domain_info.get('expires')
		domain_info_obj.whois_server = domain_info.get('whois_server')
		domain_info_obj.geolocation_iso = domain_info.get('registrant_country')

		# Save or update Registrar
		registrar, _ = Registrar.objects.get_or_create(
			name=domain_info.get('registrar_name', ''),
			defaults={
				'email': domain_info.get('registrar_email'),
				'phone': domain_info.get('registrar_phone'),
				'url': domain_info.get('registrar_url'),
			}
		)
		domain_info_obj.registrar = registrar

		# Save or update Registrations (registrant, admin, tech)
		for role in ['registrant', 'admin', 'tech']:
			registration, _ = DomainRegistration.objects.get_or_create(
				name=domain_info.get(f'{role}_name', ''),
				defaults={
					'organization': domain_info.get(f'{role}_organization'),
					'address': domain_info.get(f'{role}_address'),
					'city': domain_info.get(f'{role}_city'),
					'state': domain_info.get(f'{role}_state'),
					'zip_code': domain_info.get(f'{role}_zip_code'),
					'country': domain_info.get(f'{role}_country'),
					'email': domain_info.get(f'{role}_email'),
					'phone': domain_info.get(f'{role}_phone'),
					'fax': domain_info.get(f'{role}_fax'),
					'id_str': domain_info.get(f'{role}_id'),
				}
			)
			setattr(domain_info_obj, role, registration)

		# Save domain statuses
		domain_info_obj.status.clear()
		for status in domain_info.get('status', []):
			status_obj, _ = WhoisStatus.objects.get_or_create(name=status)
			domain_info_obj.status.add(status_obj)

		# Save name servers
		domain_info_obj.name_servers.clear()
		for ns in domain_info.get('ns_records', []):
			ns_obj, _ = NameServer.objects.get_or_create(name=ns)
			domain_info_obj.name_servers.add(ns_obj)

		# Save DNS records
		domain_info_obj.dns_records.clear()
		for record_type in ['a', 'mx', 'txt']:
			for record in domain_info.get(f'{record_type}_records', []):
				dns_record, _ = DNSRecord.objects.get_or_create(
					name=record,
					type=record_type
				)
				domain_info_obj.dns_records.add(dns_record)

		# Save related domains and TLDs
		domain_info_obj.related_domains.clear()
		for related_domain in domain_info.get('related_domains', []):
			related_domain_obj, _ = RelatedDomain.objects.get_or_create(name=related_domain)
			domain_info_obj.related_domains.add(related_domain_obj)

		domain_info_obj.related_tlds.clear()
		for related_tld in domain_info.get('related_tlds', []):
			related_tld_obj, _ = RelatedDomain.objects.get_or_create(name=related_tld)
			domain_info_obj.related_tlds.add(related_tld_obj)

		# Save historical IPs
		domain_info_obj.historical_ips.clear()
		for ip_info in domain_info.get('historical_ips', []):
			historical_ip, _ = HistoricalIP.objects.get_or_create(
				ip=ip_info['ip'],
				defaults={
					'owner': ip_info.get('owner'),
					'location': ip_info.get('location'),
					'last_seen': ip_info.get('last_seen'),
				}
			)
			domain_info_obj.historical_ips.add(historical_ip)

		# Save the DomainInfo object
		domain_info_obj.save()

		# Update the Domain object with the new DomainInfo
		domain.domain_info = domain_info_obj
		domain.save()

		return domain_info_obj
