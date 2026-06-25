import logging
import json
import requests

from django.core.cache import cache

from reNgine.common_func import *
from reNgine.definitions import *
from reNgine.llm import *
from startScan.models import Vulnerability, GPTVulnerabilityReport, VulnerabilityReference

logger = logging.getLogger(__name__)


def llm_vulnerability_description(vulnerability_id):
	"""Generate and store Vulnerability Description using GPT.

	Args:
		vulnerability_id (Vulnerability Model ID): Vulnerability ID to fetch Description.
	"""
	logger.info('Getting GPT Vulnerability Description')
	try:
		lookup_vulnerability = Vulnerability.objects.get(id=vulnerability_id)
		return get_vulnerability_gpt_report((lookup_vulnerability.name, lookup_vulnerability.get_path()), vulnerability_id=vulnerability_id)
	except Exception as e:
		return {
			'status': False,
			'error': str(e)
		}


def get_vulnerability_gpt_report(vuln, vulnerability_id=None):
	title = vuln[0]
	path = vuln[1]
	if not path:
		path = '/'
	logger.info(f'Getting GPT Report for {title}, PATH: {path}')

	# 1. Check if the specific vulnerability already has GPT info
	if vulnerability_id:
		try:
			lookup_vulnerability = Vulnerability.objects.get(id=vulnerability_id)
			if lookup_vulnerability.is_gpt_used and lookup_vulnerability.description and lookup_vulnerability.impact and lookup_vulnerability.remediation:
				logger.info(f'Returning existing GPT report from Vulnerability ID {vulnerability_id}')
				return {
					'status': True,
					'description': lookup_vulnerability.description,
					'impact': lookup_vulnerability.impact,
					'remediation': lookup_vulnerability.remediation,
					'references': [url.url for url in lookup_vulnerability.references.all()]
				}
		except Vulnerability.DoesNotExist:
			pass

	# 2. Check if in global cache (GPTVulnerabilityReport) already exists
	stored = GPTVulnerabilityReport.objects.filter(
		title=title
	).first()

	if stored and stored.description and stored.impact and stored.remediation:
		logger.info(f'Found GPT Report in global cache for {title}')
		response = {
			'status': True,
			'description': stored.description,
			'impact': stored.impact,
			'remediation': stored.remediation,
			'references': [url.url for url in stored.references.all()]
		}
	else:
		# 3. Call LLM
		report = LLMVulnerabilityReportGenerator(logger=logger)
		vulnerability_description = get_gpt_vuln_input_description(
			title,
			path
		)
		response = report.get_vulnerability_description(vulnerability_description)
		if response.get('status'):
			add_gpt_description_db(
				title,
				path,
				response.get('description'),
				response.get('impact'),
				response.get('remediation'),
				response.get('references', [])
			)

	# 4. Update all matching vulnerabilities that don't have GPT info yet, or at least the specific one
	if response.get('status'):
		def _apply_gpt_fields(v):
			v.description = response.get('description', v.description)
			v.impact = response.get('impact', v.impact)
			v.remediation = response.get('remediation', v.remediation)
			v.is_gpt_used = True
			v.save()
			for url in response.get('references', []):
				ref, _ = VulnerabilityReference.objects.get_or_create(url=url)
				v.references.add(ref)
			v.save()

		# Always update the specific requested vulnerability first (handles NULL http_url)
		if vulnerability_id:
			try:
				_apply_gpt_fields(Vulnerability.objects.get(id=vulnerability_id))
			except Vulnerability.DoesNotExist:
				pass

		# Also bulk-update any other findings with the same name/path that lack GPT data
		qs = Vulnerability.objects.filter(name=title, http_url__icontains=path, is_gpt_used=False)
		if vulnerability_id:
			qs = qs.exclude(id=vulnerability_id)
		for v in qs:
			_apply_gpt_fields(v)

	return response


def add_gpt_description_db(title, path, description, impact, remediation, references):
	logger.info(f'Adding GPT Report to DB for {title}, PATH: {path}')
	if not path:
		path = '/'

	gpt_report, created = GPTVulnerabilityReport.objects.update_or_create(
		url_path=path,
		title=title,
		defaults={
			'description': description,
			'impact': impact,
			'remediation': remediation
		}
	)

	if references:
		for url in references:
			ref, created = VulnerabilityReference.objects.get_or_create(url=url)
			gpt_report.references.add(ref)
		gpt_report.save()


def pull_ollama_model(model_name):
    """
    Pulls a model from Ollama and stores progress in cache for live terminal.
    """
    cache_key = f"ollama_pull_log_{model_name}"
    cache.set(cache_key, f"[*] Starting download of {model_name}...\n", 3600)

    try:
        url = f"{OLLAMA_INSTANCE}/api/pull"
        payload = {"name": model_name, "stream": True}

        response = requests.post(url, json=payload, stream=True, timeout=None)

        for line in response.iter_lines():
            if line:
                data = json.loads(line)
                status = data.get('status', '')
                digest = data.get('digest', '')
                total = data.get('total', 0)
                completed = data.get('completed', 0)

                if total > 0:
                    percent = round((completed / total) * 100, 2)
                    progress_msg = f"[*] {status} {digest[:12]}... {percent}%\n"
                else:
                    progress_msg = f"[*] {status}\n"

                # Append to cache
                current_log = cache.get(cache_key, "")
                # Keep only last 50 lines to prevent cache bloat
                log_lines = current_log.split('\n')[-50:]
                log_lines.append(progress_msg.strip())
                cache.set(cache_key, '\n'.join(log_lines) + '\n', 3600)

                if status == 'success':
                    cache.set(f"ollama_pull_status_{model_name}", "success", 3600)
                    return True

    except Exception as e:
        error_msg = f"[!] Error pulling model: {str(e)}\n"
        current_log = cache.get(cache_key, "")
        cache.set(cache_key, current_log + error_msg, 3600)
        cache.set(f"ollama_pull_status_{model_name}", "failed", 3600)
        return False

    return True
