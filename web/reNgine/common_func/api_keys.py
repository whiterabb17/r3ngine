"""Readers for the third-party API key models stored in the dashboard app.

Split out of the former reNgine/common_func.py; re-exported by
reNgine.common_func for backward compatibility.
"""
import logging

from dashboard.models import (
	ChaosAPIKey,
	HackerOneAPIKey,
	LeakLookupAPIKey,
	NetlasAPIKey,
	OpenAiAPIKey,
	SecurityTrailsAPIKey,
	SpiderfootAPIKey,
)

logger = logging.getLogger(__name__)


def get_spiderfoot_keys():
	"""Get Spiderfoot API keys from DB.

	Returns:
		dict: Dictionary of module_name: key_value.
	"""
	keys = SpiderfootAPIKey.objects.all()
	return {k.module_name: k.key_value for k in keys}


def get_leaklookup_key():
	"""Get LeakLookup API key from DB.

	Returns:
		str: LeakLookup API key or ''.
	"""
	key_obj = LeakLookupAPIKey.objects.first()
	return key_obj.key if key_obj else ''


def get_chaos_api_key():
	"""Get Chaos API key from DB (used for ProjectDiscovery).

	Returns:
		str: Chaos API key or ''.
	"""
	key_obj = ChaosAPIKey.objects.first()
	return key_obj.key if key_obj else ''


def get_securitytrails_key() -> str:
	"""Return the SecurityTrails API key from the vault, or ''."""
	key_obj = SecurityTrailsAPIKey.objects.first()
	return key_obj.key if key_obj else ''


def get_open_ai_key():
	openai_key = OpenAiAPIKey.objects.all()
	return openai_key[0] if openai_key else None


def get_netlas_key():
	netlas_key = NetlasAPIKey.objects.all()
	return netlas_key[0] if netlas_key else None


def get_chaos_key():
	chaos_key = ChaosAPIKey.objects.all()
	return chaos_key[0] if chaos_key else None


def get_hackerone_key_username():
	"""
		Get the HackerOne API key username from the database.
		Returns: a tuple of the username and api key
	"""
	hackerone_key = HackerOneAPIKey.objects.all()
	return (hackerone_key[0].username, hackerone_key[0].key) if hackerone_key else None
