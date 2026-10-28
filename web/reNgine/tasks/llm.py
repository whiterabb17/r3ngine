import logging
import json
import requests

from django.core.cache import cache

from reNgine.common_func import *
from reNgine.definitions import *
from reNgine.llm import *
from startScan.models import Vulnerability, GPTVulnerabilityReport, VulnerabilityReference

logger = logging.getLogger(__name__)

# Mid-band CVSS v3.1 estimates when the LLM omits a score (severity int → float).
_SEVERITY_CVSS_FALLBACK = {
	0: 0.0,   # info
	1: 3.9,   # low
	2: 5.5,   # medium
	3: 7.5,   # high
	4: 9.5,   # critical
}


def _severity_band_cvss(severity):
	"""Return a mid-band CVSS estimate for a Nuclei-style severity int, or None."""
	try:
		return _SEVERITY_CVSS_FALLBACK.get(int(severity))
	except (TypeError, ValueError):
		return None


def _resolve_estimated_cvss(response, vulnerability):
	"""Pick an estimated CVSS from the LLM response or severity-band fallback.

	Only used when the vulnerability has no tool/NVD cvss_score yet.
	"""
	score = response.get('estimated_cvss_score')
	if score is not None:
		try:
			score = float(score)
			if 0.0 <= score <= 10.0:
				return score
		except (TypeError, ValueError):
			pass
	return _severity_band_cvss(getattr(vulnerability, 'severity', None))


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
	logger.info("Getting GPT Report for %s, PATH: %s", title, path)

	# 1. Check if the specific vulnerability already has GPT info
	if vulnerability_id:
		try:
			lookup_vulnerability = Vulnerability.objects.get(id=vulnerability_id)
			if lookup_vulnerability.is_gpt_used and lookup_vulnerability.description and lookup_vulnerability.impact and lookup_vulnerability.remediation:
				logger.info("Returning existing GPT report from Vulnerability ID %s", vulnerability_id)
				# Backfill estimated CVSS when the finding already has GPT text but no score.
				if lookup_vulnerability.cvss_score is None:
					fallback = _severity_band_cvss(lookup_vulnerability.severity)
					if fallback is not None:
						lookup_vulnerability.cvss_score = fallback
						lookup_vulnerability.cvss_estimated = True
						lookup_vulnerability.save(update_fields=['cvss_score', 'cvss_estimated'])
				return {
					'status': True,
					'description': lookup_vulnerability.description,
					'impact': lookup_vulnerability.impact,
					'remediation': lookup_vulnerability.remediation,
					'references': [url.url for url in lookup_vulnerability.references.all()],
					'estimated_cvss_score': lookup_vulnerability.cvss_score if lookup_vulnerability.cvss_estimated else None,
					'cvss_estimated': bool(lookup_vulnerability.cvss_estimated),
				}
		except Vulnerability.DoesNotExist:
			pass

	# 2. Check if in global cache (GPTVulnerabilityReport) already exists
	stored = GPTVulnerabilityReport.objects.filter(
		title=title
	).first()

	if stored and stored.description and stored.impact and stored.remediation:
		logger.info("Found GPT Report in global cache for %s", title)
		response = {
			'status': True,
			'description': stored.description,
			'impact': stored.impact,
			'remediation': stored.remediation,
			'references': [url.url for url in stored.references.all()],
		}
		if stored.estimated_cvss_score is not None:
			response['estimated_cvss_score'] = stored.estimated_cvss_score
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
				response.get('references', []),
				estimated_cvss_score=response.get('estimated_cvss_score'),
			)

	# 4. Update all matching vulnerabilities that don't have GPT info yet, or at least the specific one
	if response.get('status'):
		def _apply_gpt_fields(v):
			v.description = response.get('description', v.description)
			v.impact = response.get('impact', v.impact)
			v.remediation = response.get('remediation', v.remediation)
			v.is_gpt_used = True
			if v.cvss_score is None:
				estimated = _resolve_estimated_cvss(response, v)
				if estimated is not None:
					v.cvss_score = estimated
					v.cvss_estimated = True
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

		# Reflect only what was actually applied to the requested finding.
		# Never mark cvss_estimated from the LLM payload alone — tool/NVD scores
		# are left untouched by _apply_gpt_fields and must not show as estimated.
		if vulnerability_id:
			try:
				applied = Vulnerability.objects.get(id=vulnerability_id)
				if applied.cvss_estimated and applied.cvss_score is not None:
					response['estimated_cvss_score'] = applied.cvss_score
					response['cvss_estimated'] = True
				else:
					response.pop('estimated_cvss_score', None)
					response['cvss_estimated'] = False
			except Vulnerability.DoesNotExist:
				pass

	return response


def add_gpt_description_db(title, path, description, impact, remediation, references, estimated_cvss_score=None):
	logger.info("Adding GPT Report to DB for %s, PATH: %s", title, path)
	if not path:
		path = '/'

	defaults = {
		'description': description,
		'impact': impact,
		'remediation': remediation,
	}
	if estimated_cvss_score is not None:
		try:
			score = float(estimated_cvss_score)
			if 0.0 <= score <= 10.0:
				defaults['estimated_cvss_score'] = score
		except (TypeError, ValueError):
			pass

	gpt_report, created = GPTVulnerabilityReport.objects.update_or_create(
		url_path=path,
		title=title,
		defaults=defaults,
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
