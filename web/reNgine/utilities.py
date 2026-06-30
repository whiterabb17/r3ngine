import re
import os
import logging
import validators


def is_safe_path(basedir, path, follow_symlinks=True):
	# Source: https://security.openstack.org/guidelines/dg_using-file-paths.html
	# resolves symbolic links
	if follow_symlinks:
		matchpath = os.path.realpath(path)
		basedir = os.path.realpath(basedir)
	else:
		matchpath = os.path.abspath(path)
		basedir = os.path.abspath(basedir)
	return os.path.normpath(basedir) == os.path.commonpath((basedir, matchpath))


# Source: https://stackoverflow.com/a/10408992
def remove_lead_and_trail_slash(s):
	if s.startswith('/'):
		s = s[1:]
	if s.endswith('/'):
		s = s[:-1]
	return s


def get_time_taken(latest, earlier):
	duration = latest - earlier
	days, seconds = duration.days, duration.seconds
	hours = days * 24 + seconds // 3600
	minutes = (seconds % 3600) // 60
	seconds = seconds % 60
	if not hours and not minutes:
		return f'{seconds} seconds'
	elif not hours:
		return f'{minutes} minutes'
	elif not minutes:
		return f'{hours} hours'
	return f'{hours} hours {minutes} minutes'

# Check if value is a simple string, a string with commas, a list [], a tuple (), a set {} and return an iterable
def return_iterable(string):
	if not isinstance(string, (list, tuple)):
		string = [string]

	return string


# Logging formatters

class RengineTaskFormatter(logging.Formatter):

	def format(self, record):
		record.__dict__.setdefault('task_name', f'{record.module}.{record.funcName}')
		record.__dict__.setdefault('task_id', '')
		return super().format(record)


def get_gpt_vuln_input_description(title, path):
	vulnerability_description = ''
	vulnerability_description += f'Vulnerability Title: {title}'
	# Note: path is removed from the prompt to ensure the generated report is target-agnostic
	return vulnerability_description


def replace_nulls(obj):
	if isinstance(obj, str):
		return obj.replace("\x00", "")
	elif isinstance(obj, list):
		return [replace_nulls(item) for item in obj]
	elif isinstance(obj, dict):
		return {key: replace_nulls(value) for key, value in obj.items()}
	else:
		return obj


def is_valid_url(url, validate_only_http_scheme=True):
	"""
		Validate a URL/endpoint

		Args:
		url (str): The URL to validate.
		validate_only_http_scheme (bool): If True, only validate HTTP/HTTPS URLs.

		Returns:
		bool: True if the URL is valid, False otherwise.
	"""
	# no urls returns false
	if not url:
		return False
	
	# urls with space are not valid urls
	if ' ' in url:
		return False

	if validators.url(url):
		# check for scheme, for example ftp:// can be a valid url but may not be required to crawl etc
		if validate_only_http_scheme:
			return url.startswith('http://') or url.startswith('https://')
		return True
	return False


class SubdomainScopeChecker:
	"""
		SubdomainScopeChecker is a utility class to check if a subdomain is in scope or not.
		it supports both regex and string matching.
	"""

	def __init__(self, patterns):
		self.regex_patterns = set()
		self.plain_patterns = set()
		self.load_patterns(patterns)

	def load_patterns(self, patterns):
		"""
			Load patterns into the checker.

			Args:
				patterns (list): List of patterns to load.
			Returns: 
				None
		"""
		for pattern in patterns:
			# skip empty patterns
			if not pattern:
				continue
			try:
				self.regex_patterns.add(re.compile(pattern, re.IGNORECASE))
			except re.error:
				self.plain_patterns.add(pattern.lower())

	def is_out_of_scope(self, subdomain):
		"""
			Check if a subdomain is out of scope.

			Args:
				subdomain (str): The subdomain to check.
			Returns:
				bool: True if the subdomain is out of scope, False otherwise.
		"""
		subdomain = subdomain.lower() # though we wont encounter this, but just in case
		if subdomain in self.plain_patterns:
			return True
		return any(pattern.search(subdomain) for pattern in self.regex_patterns)



def sorting_key(subdomain):
	# sort subdomains based on their http status code with priority 200 < 300 < 400 < rest
	status = subdomain['http_status']
	if 200 <= status <= 299:
		return 1
	elif 300 <= status <= 399:
		return 2
	elif 400 <= status <= 499:
		return 3
	else:
		return 4


def save_auth_candidate(scan_history, target, protocol, port, source_tool=None, metadata=None, subdomain=None, endpoint=None, tech_hint=None):
	"""
	Save or update an authentication candidate for brute-forcing.
	Handles deduplication and metadata merging.
	"""
	from startScan.models import AuthCandidate

	if metadata is None:
		metadata = {}

	if tech_hint:
		metadata['tech_hint'] = tech_hint

	# Clean protocol name to lowercase for consistency
	protocol = protocol.lower()

	# Try to find existing candidate to avoid duplicates
	candidate, created = AuthCandidate.objects.get_or_create(
		scan_history=scan_history,
		target=target,
		protocol=protocol,
		port=port,
		defaults={
			'subdomain': subdomain,
			'endpoint': endpoint,
			'source_tool': source_tool,
			'metadata': metadata,
			'status': 'pending'
		}
	)

	if not created:
		# If it exists, update metadata and source tool if new info is provided
		updated = False
		if source_tool and source_tool not in (candidate.source_tool or ''):
			candidate.source_tool = f"{candidate.source_tool}, {source_tool}" if candidate.source_tool else source_tool
			updated = True

		if metadata:
			# Merge metadata
			original_meta = candidate.metadata or {}
			original_meta.update(metadata)
			candidate.metadata = original_meta
			updated = True

		if updated:
			candidate.save()

	return candidate


def get_screenshot_path(subdomain):
	"""
	Returns a normalized relative path for a subdomain screenshot, 
	ensuring it includes the scan results directory prefix.
	Supports searching in subscan directories if the file is not found in the main directory.
	"""
	from django.conf import settings
	from django.apps import apps
	import os
	import glob
	
	path = subdomain.screenshot_path
	results_dir = subdomain.scan_history.results_dir if subdomain.scan_history else ""
	
	if not path:
		# Fallback to the first available screenshot object
		Screenshot = apps.get_model('startScan', 'Screenshot')
		first_screenshot = Screenshot.objects.filter(subdomain=subdomain).first()
		if first_screenshot:
			path = first_screenshot.screenshot_path
			if first_screenshot.scan_history:
				results_dir = first_screenshot.scan_history.results_dir
	
	if not path:
		return None
	
	# Strip media prefix if present
	if path.startswith('/media/'):
		path = path[len('/media/'):]
	elif path.startswith('media/'):
		path = path[len('media/'):]
		
	# If the path is already absolute (starts with /), try to make it relative to MEDIA_ROOT
	if os.path.isabs(path) and path.startswith(settings.MEDIA_ROOT):
		path = os.path.relpath(path, settings.MEDIA_ROOT)

	# Normalize results_dir relative to MEDIA_ROOT if it's absolute
	if results_dir and os.path.isabs(results_dir) and results_dir.startswith(settings.MEDIA_ROOT):
		results_dir = os.path.relpath(results_dir, settings.MEDIA_ROOT)

	# Construct full absolute path for existence check
	full_results_dir = os.path.join(settings.MEDIA_ROOT, results_dir)
	if results_dir and not os.path.isdir(full_results_dir):
		return None
	
	# If the path doesn't contain the results_dir prefix, try to find it
	final_path = path
	if results_dir and not path.startswith(results_dir):
		# Try main scan directory first
		test_path = os.path.join(results_dir, path)
		if os.path.exists(os.path.join(settings.MEDIA_ROOT, test_path)):
			final_path = test_path
		else:
			# Not in main directory, check subscans directory
			# Pattern: results_dir/subscans/*/path
			subscans_dir = os.path.join(full_results_dir, 'subscans')
			if os.path.isdir(subscans_dir):
				subscan_pattern = os.path.join(subscans_dir, '*', path)
				matches = glob.glob(subscan_pattern)
				if matches:
					# Use the first match and convert back to relative path
					final_path = os.path.relpath(matches[0], settings.MEDIA_ROOT)
				else:
					# Fallback to default prepending if nothing found
					final_path = test_path
			else:
				final_path = test_path
	
	if final_path:
		full_final_path = os.path.join(settings.MEDIA_ROOT, final_path)
		if not os.path.exists(full_final_path):
			return None
			
	return final_path.replace('\\', '/') if final_path else None


def secure_url_fetcher(url, *args, **kwargs):
	"""
	Secure URL fetcher for WeasyPrint to prevent SSRF and LFI.
	Restricts to:
	- Data URLs (base64)
	- Local files strictly inside Django BASE_DIR or MEDIA_ROOT
	- Google Fonts domains (fonts.googleapis.com, fonts.gstatic.com)
	"""
	from urllib.parse import urlparse
	from django.conf import settings
	from weasyprint import default_url_fetcher

	parsed = urlparse(url)

	# 1. Allow data URLs
	if parsed.scheme == 'data':
		return default_url_fetcher(url, *args, **kwargs)

	# 2. Allow local files within settings.BASE_DIR or settings.MEDIA_ROOT
	if parsed.scheme == 'file' or not parsed.scheme:
		file_path = os.path.abspath(parsed.path)
		in_base = is_safe_path(os.path.abspath(settings.BASE_DIR), file_path)
		in_media = False
		if hasattr(settings, 'MEDIA_ROOT') and settings.MEDIA_ROOT:
			in_media = is_safe_path(os.path.abspath(settings.MEDIA_ROOT), file_path)
		
		if not (in_base or in_media):
			raise PermissionError(f"Access to file is forbidden: {file_path}")
		return default_url_fetcher(url, *args, **kwargs)

	# 3. Allow Google Fonts HTTP/HTTPS requests
	if parsed.scheme in ('http', 'https'):
		hostname = parsed.hostname
		if hostname in ('fonts.googleapis.com', 'fonts.gstatic.com'):
			return default_url_fetcher(url, *args, **kwargs)
		raise PermissionError(f"External network requests to {hostname} are forbidden.")

	raise PermissionError(f"Unsupported URL scheme: {parsed.scheme}")