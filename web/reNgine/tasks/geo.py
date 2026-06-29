import logging
import json
import concurrent.futures
import tldextract

from reNgine.common_func import *
from reNgine.definitions import *
from reNgine.utils.task import run_command
from startScan.models import CountryISO, IpAddress

logger = logging.getLogger(__name__)


def geo_localize(host, ip_id=None, scan_id=None, activity_id=None):
	"""Uses geoiplookup to find location associated with host.

	Args:
		host (str): Hostname.
		ip_id (int): IpAddress object id.
		scan_id (int): ScanHistory object id.
		activity_id (int): ScanActivity object id.

	Returns:
		startScan.models.CountryISO: CountryISO object from DB or None.
	"""
	import ipaddress
	import re

	geo_object = None
	country_iso = "Unknown"
	country_name = "Unknown Location"

	# Check if IP is private
	try:
		ip_obj = ipaddress.ip_address(host)
		if ip_obj.is_private:
			country_iso = "PV"
			country_name = "Private Network"
		elif ip_obj.version == 6:
			# geoiplookup often doesn't support IPv6 in the default DB
			# We'll mark it as Unknown (IPv6) for now
			country_iso = "IPv6"
			country_name = "IPv6 Address"
	except ValueError:
		# Not a valid IP (could be a hostname)
		pass

	if country_iso == "Unknown":
		cmd = f'geoiplookup {host}'
		_, out = run_command(cmd, scan_id=scan_id, activity_id=activity_id)
		if 'IP Address not found' not in out and "can't resolve hostname" not in out and ':' in out:
			try:
				# Use regex for more robust parsing of geoiplookup output
				# Typical format: "GeoIP Country Edition: US, United States"
				# We look for the line containing "Country Edition" for precision
				match = re.search(r"Country Edition:\s*([A-Z0-9]{2,}),\s*(.*)", out)
				if match:
					country_iso = match.group(1).strip()
					country_name = match.group(2).strip()
				else:
					# Fallback to general colon-based split if specific line not found
					parts = out.split(':')[1].strip().split(',')
					country_iso = parts[0].strip()
					country_name = parts[1].strip() if len(parts) > 1 else country_iso
			except Exception as e:
				logger.error(f"Error parsing geoiplookup output for {host}: {e}")
		else:
			logger.info(f'Geo IP lookup failed for host "{host}"')

	geo_object, _ = CountryISO.objects.get_or_create(
		iso=country_iso,
		defaults={'name': country_name}
	)

	if ip_id:
		IpAddress.objects.filter(id=ip_id).update(geo_iso=geo_object)

	return geo_object


def query_whois(target, force_reload_whois=False, scan_id=None, activity_id=None):
	"""Query WHOIS information for an IP or a domain name.

	Args:
		target (str): IP address or domain name.
		save_domain (bool): Whether to save domain or not, default False
	Returns:
		dict: WHOIS information.
	"""
	try:
		# TODO: Implement cache whois only for 48 hours otherwise get from whois server
		# TODO: in 3.0
		if not force_reload_whois:
			logger.info(f'Querying WHOIS information for {target} from db...')
			domain_info = get_domain_info_from_db(target)
			if domain_info:
				return format_whois_response(domain_info)

		# Query WHOIS information as not found in db
		logger.info(f'Whois info not found in db')
		logger.info(f'Querying WHOIS information for {target} from WHOIS server...')

		domain_info = DottedDict()
		domain_info.target = target

		whois_data = None
		related_domains = []

		with concurrent.futures.ThreadPoolExecutor(max_workers=4) as executor:
			futures_func = {
				executor.submit(get_domain_historical_ip_address, target): 'historical_ips',
				executor.submit(fetch_related_tlds_and_domains, target, scan_id=scan_id, activity_id=activity_id): 'related_tlds_and_domains',
				executor.submit(reverse_whois, target): 'reverse_whois',
				executor.submit(fetch_whois_data_using_netlas, target, scan_id=scan_id, activity_id=activity_id): 'whois_data',
			}

			for future in concurrent.futures.as_completed(futures_func):
				func_name = futures_func[future]
				try:
					result = future.result()
					if func_name == 'historical_ips':
						domain_info.historical_ips = result
					elif func_name == 'related_tlds_and_domains':
						domain_info.related_tlds, tlsx_related_domain = result
					elif func_name == 'reverse_whois':
						related_domains = result
					elif func_name == 'whois_data':
						whois_data = result

					logger.debug('*'*100)
					logger.info(f'Task {func_name} finished for target {target}')
					logger.debug(result)
					logger.debug('*'*100)

				except Exception as e:
					logger.error(f'An error occurred while fetching {func_name} for {target}: {str(e)}')
					continue

		logger.info(f'All concurrent whosi lookup tasks finished for target {target}')

		if 'tlsx_related_domain' in locals():
			related_domains += tlsx_related_domain

		whois_data = whois_data.get('data', {})

		# related domains can also be fetched from whois_data
		whois_related_domains = whois_data.get('related_domains', [])
		related_domains += whois_related_domains

		# remove duplicate ones
		related_domains = list(set(related_domains))
		domain_info.related_domains = related_domains

		parse_whois_data(domain_info, whois_data)
		saved_domain_info = save_domain_info_to_db(target, domain_info)
		return format_whois_response(domain_info)
	except Exception as e:
		logger.error(f'An error occurred while querying WHOIS information for {target}: {str(e)}')
		return {
			'status': False,
			'target': target,
			'result': f'An error occurred while querying WHOIS information for {target}: {str(e)}'
		}


def fetch_related_tlds_and_domains(domain, scan_id=None, activity_id=None):
	"""
	Fetch related TLDs and domains using TLSx.
	related domains are those that are not part of related TLDs.

	Args:
		domain (str): The domain to find related TLDs and domains for.

	Returns:
		tuple: A tuple containing two lists (related_tlds, related_domains).
	"""
	logger.info(f"Fetching related TLDs and domains for {domain}")
	related_tlds = set()
	related_domains = set()

	# Extract the base domain
	extracted = tldextract.extract(domain)
	base_domain = f"{extracted.domain}.{extracted.suffix}"

	cmd = f'tlsx -san -cn -silent -ro -host {domain}'
	_, result = run_command(cmd, shell=True, scan_id=scan_id, activity_id=activity_id)

	for line in result.splitlines():
		try:
				line = line.strip()
				if line == "":
					continue
				extracted_result = tldextract.extract(line)
				full_domain = f"{extracted_result.domain}.{extracted_result.suffix}"

				if extracted_result.domain == extracted.domain:
					if full_domain != base_domain:
						related_tlds.add(full_domain)
				elif extracted_result.domain != extracted.domain or extracted_result.subdomain:
					related_domains.add(line)
		except Exception as e:
			logger.error(f"An error occurred while fetching related TLDs and domains for {domain}: {str(e)}")
			continue

	logger.info(f"Found {len(related_tlds)} related TLDs and {len(related_domains)} related domains for {domain}")
	return list(related_tlds), list(related_domains)


def fetch_whois_data_using_netlas(target, scan_id=None, activity_id=None):
	"""
		Fetch WHOIS data using netlas.
		Args:
			target (str): IP address or domain name.
		Returns:
			dict: WHOIS information.
	"""
	logger.info(f'Fetching WHOIS data for {target} using Netlas...')
	command = f'netlas host {target} -f json'
	netlas_key = get_netlas_key()
	if netlas_key:
		command += f' -a {netlas_key}'

	try:
		_, result = run_command(command, remove_ansi_sequence=True, scan_id=scan_id, activity_id=activity_id)

		# catch errors
		if 'Failed to parse response data' in result:
			return {
				'status': False,
				'message': 'Netlas limit exceeded.'
			}

		if 'api key doesn\'t exist' in result:
			return {
				'status': False,
				'message': 'Invalid Netlas API Key!'
			}

		if 'Request limit' in result:
			return {
				'status': False,
				'message': 'Netlas request limit exceeded.'
			}

		data = json.loads(result)

		if not data:
			return {
				'status': False,
				'message': 'No data available for the given domain or IP.'
			}

		return {
			'status': True,
			'data': data
		}

	except json.JSONDecodeError:
		return {
			'status': False,
			'message': 'Failed to parse JSON response from Netlas.'
		}
	except Exception as e:
		return {
			'status': False,
			'message': f'An error occurred while fetching WHOIS data: {str(e)}'
		}


def query_reverse_whois(lookup_keyword):
	"""Queries Reverse WHOIS information for an organization or email address.

	Args:
		lookup_keyword (str): Registrar Name or email
	Returns:
		dict: Reverse WHOIS information.
	"""

	return reverse_whois(lookup_keyword)


def query_ip_history(domain):
	"""Queries the IP history for a domain

	Args:
		domain (str): domain_name
	Returns:
		list: list of historical ip addresses
	"""

	return get_domain_historical_ip_address(domain)
