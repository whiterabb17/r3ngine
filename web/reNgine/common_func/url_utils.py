"""Pure URL / domain / IP parsing and filtering helpers (no database access).

Split out of the former reNgine/common_func.py; re-exported by
reNgine.common_func for backward compatibility.
"""
import ipaddress
import re
import logging

import tldextract
import validators
from urllib.parse import urlparse, parse_qs

from reNgine.utilities import is_valid_url

logger = logging.getLogger(__name__)


def get_subdomain_from_url(url):
	"""Get subdomain from HTTP URL.

	Args:
		url (str): HTTP URL.

	Returns:
		str: Subdomain name.
	"""
	# Check if the URL has a scheme. If not, add a temporary one to prevent empty netloc.
	if "://" not in url:
		url = "http://" + url

	url_obj = urlparse(url.strip())
	return url_obj.netloc.split(':')[0]


def get_domain_from_subdomain(subdomain):
	"""Get domain from subdomain.

	Args:
		subdomain (str): Subdomain name.

	Returns:
		str: Domain name.
	"""
	# ext = tldextract.extract(subdomain)
	# return '.'.join(ext[1:3])

	if not validators.domain(subdomain):
		return None
	
	# Use tldextract to parse the subdomain
	extracted = tldextract.extract(subdomain)

	# if tldextract recognized the tld then its the final result
	if extracted.suffix:
		domain = f"{extracted.domain}.{extracted.suffix}"
	else:
		# Fallback method for unknown TLDs, like .clouds or .local etc
		parts = subdomain.split('.')
		if len(parts) >= 2:
			domain = '.'.join(parts[-2:])
		else:
			return None
		
	# Validate the domain before returning
	return domain if validators.domain(domain) else None


def sanitize_url(http_url):
	"""Removes HTTP ports 80 and 443 from HTTP URL because it's ugly.

	Args:
		http_url (str): Input HTTP URL.

	Returns:
		str: Stripped HTTP URL.
	"""
	# Check if the URL has a scheme. If not, add a temporary one to prevent empty netloc.
	if "://" not in http_url:
		http_url = "http://" + http_url
	try:
		url = urlparse(http_url)
	except ValueError:
		# Python 3.10+ raises ValueError for malformed bracket hosts (e.g. http://[]/path).
		return http_url.rstrip('/')

	if url.netloc.endswith(':80'):
		url = url._replace(netloc=url.netloc.replace(':80', ''))
	elif url.netloc.endswith(':443'):
		url = url._replace(scheme=url.scheme.replace('http', 'https'))
		url = url._replace(netloc=url.netloc.replace(':443', ''))
	return url.geturl().rstrip('/')


def parse_fetched_url_line(raw_line, starting_point_path=''):
	"""Normalize a single line from fetch_url tool output into a usable URL.

	Handles gospider-style lines like ``https://host/path] - /extra`` and
	``https://host - /path``. Invalid or filtered lines return None.
	"""
	url = (raw_line or '').strip()
	if not url:
		return None

	urlpath = None
	base_url = None
	if '] ' in url:
		split = tuple(url.split('] ', 1))
		if len(split) != 2:
			return None
		base_url, urlpath = split
		urlpath = urlpath.lstrip('- ')
	elif ' - ' in url:
		parts = url.split(' - ', 1)
		if len(parts) == 2:
			base_url, urlpath = parts

	if base_url and urlpath:
		if '://' not in base_url:
			base_url = f'http://{base_url}'
		parsed_base = urlparse(base_url)
		path = urlpath if urlpath.startswith('/') else f'/{urlpath}'
		url = f'{parsed_base.scheme}://{parsed_base.netloc}{path}'

	if starting_point_path and starting_point_path not in url:
		return None
	if not is_valid_url(url):
		return None
	return url


def url_param_signature(url):
	"""Return a dedup key based on scheme, netloc, path, and sorted param names (ignoring values).

	Two URLs sharing the same signature differ only in parameter values (e.g. ?id=1 vs ?id=2)
	and can be treated as the same functional endpoint for load-reduction purposes.
	"""
	try:
		parsed = urlparse(url)
		param_keys = ','.join(sorted(parse_qs(parsed.query).keys()))
		return f"{parsed.scheme}://{parsed.netloc}{parsed.path}?{param_keys}"
	except Exception:
		return url


def extract_path_from_url(url):
	parsed_url = urlparse(url)

	# Reconstruct the URL without scheme and netloc
	reconstructed_url = parsed_url.path

	if reconstructed_url.startswith('/'):
		reconstructed_url = reconstructed_url[1:]  # Remove the first slash

	if parsed_url.params:
		reconstructed_url += ';' + parsed_url.params
	if parsed_url.query:
		reconstructed_url += '?' + parsed_url.query
	if parsed_url.fragment:
		reconstructed_url += '#' + parsed_url.fragment

	return reconstructed_url


def exclude_urls_by_patterns(exclude_paths, urls):
	"""
		Filter out URLs based on a list of exclusion patterns provided from user
		
		Args:
			exclude_patterns (list of str): A list of patterns to exclude. 
			These can be plain path or regex.
			urls (list of str): A list of URLs to filter from.
			
		Returns:
			list of str: A new list containing URLs that don't match any exclusion pattern.
	"""
	logger.info('Filtering %d URLs by %d exclusion patterns', len(urls), len(exclude_paths))
	if not exclude_paths:
		# if no exclude paths are passed and is empty list return all urls as it is
		return urls
	
	compiled_patterns = []
	for path in exclude_paths:
		# treat each path as either regex or plain path
		try:
			raw_pattern = r"{}".format(path)
			compiled_patterns.append(re.compile(raw_pattern))
		except re.error:
			compiled_patterns.append(path)

	filtered_urls = []
	for url in urls:
		exclude = False
		for pattern in compiled_patterns:
			if isinstance(pattern, re.Pattern):
				if pattern.search(url):
					exclude = True
					break
			else:
				if pattern in url: #if the word matches anywhere in url exclude
					exclude = True
					break
		
		# if none conditions matches then add the url to filtered urls
		if not exclude:
			filtered_urls.append(url)

	return filtered_urls


def extract_params_from_url(url):
	"""
	Extracts query parameters from a URL and returns a list of dicts.
	"""
	params = []
	try:
		parsed = urlparse(url)
		query_dict = parse_qs(parsed.query)
		for key, values in query_dict.items():
			for value in values:
				params.append({
					'name': key,
					'value': value,
					'type': 'URL Query'
				})
	except Exception as e:
		logger.error("Error extracting parameters from URL %s: %s", url, e)
	return params


def get_ip_info(ip_address):
	is_ipv4 = bool(validators.ipv4(ip_address))
	is_ipv6 = bool(validators.ipv6(ip_address))
	ip_data = None
	if is_ipv4:
		ip_data = ipaddress.IPv4Address(ip_address)
	elif is_ipv6:
		ip_data = ipaddress.IPv6Address(ip_address)
	else:
		return None
	return ip_data


def get_ips_from_cidr_range(target):
	try:
		return [str(ip) for ip in ipaddress.IPv4Network(target, False)]
	except Exception as e:
		logger.error('%s is not a valid CIDR range. Skipping.', target)
