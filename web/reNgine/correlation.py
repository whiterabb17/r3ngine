import logging
import hashlib
import yaml
from django.db import IntegrityError, transaction
from django.db.models import Q, Count
from django.utils import timezone
from startScan.models import Vulnerability, Subdomain, EndPoint, ImpactAssessment, VulnerabilityHistory


logger = logging.getLogger(__name__)

class VulnerabilityCorrelationEngine:
	"""
	Orchestrates vulnerability correlation across multiple tools (Nuclei, Semgrep, Retire.js).
	Tracks vulnerability persistence and handles deduplication within scans.
	"""
	
	def __init__(self, scan_history=None):
		"""
		Initialize the correlation engine with optional scan history context.

		Args:
			scan_history (ScanHistory, optional): The scan history object being analyzed.
		"""
		self.scan_history = scan_history
		self.tier7_config = {}
		if self.scan_history and hasattr(self.scan_history, 'scan_type') and self.scan_history.scan_type and self.scan_history.scan_type.yaml_configuration:
			try:
				config = yaml.safe_load(self.scan_history.scan_type.yaml_configuration)
				if isinstance(config, dict):
					self.tier7_config = config.get('tier_7', {})
			except Exception:
				pass
				
		self.weights = {
			'severity': 0.4,
			'multi_tool_match': 0.25,
			'exploitability': 0.2,
			'asset_criticality': 0.1,
			'temporal': 0.05
		}

	def correlate_findings(self, subdomain_id=None):
		"""
		Groups vulnerabilities by asset and CVE/type, calculates correlation scores,
		applies duplicate suppression, and updates the vulnerability history and attack paths.

		Args:
			subdomain_id (int, optional): The specific subdomain ID to filter correlation.
		"""
		query = Q()
		if subdomain_id:
			query &= Q(subdomain_id=subdomain_id)
		if self.scan_history:
			query &= Q(subdomain__scan_history=self.scan_history)
			
		vulns = Vulnerability.objects.filter(query).prefetch_related('cve_ids', 'cwe_ids')
		
		# Generate group keys for all findings
		for vuln in vulns:
			vuln.group_key = self._generate_group_key(vuln)
		
		# In-memory prefetch optimization for duplicate findings search
		subdomain_ids = {v.subdomain_id for v in vulns if v.subdomain_id}
		subdomain_cve_map = {}
		if subdomain_ids:
			all_subdomain_vulns = Vulnerability.objects.filter(
				subdomain_id__in=subdomain_ids
			).prefetch_related('cve_ids')
			for v in all_subdomain_vulns:
				if not v.subdomain_id:
					continue
				for cve in v.cve_ids.all():
					key = (v.subdomain_id, cve.name)
					if key not in subdomain_cve_map:
						subdomain_cve_map[key] = []
					subdomain_cve_map[key].append(v)

		# In-memory prefetch optimization for ImpactAssessment records
		vuln_ids = [v.id for v in vulns]
		existing_assessments = ImpactAssessment.objects.filter(vulnerability_id__in=vuln_ids)
		
		assessments_by_vuln = {}
		for assessment in existing_assessments:
			if assessment.vulnerability_id not in assessments_by_vuln:
				assessments_by_vuln[assessment.vulnerability_id] = []
			assessments_by_vuln[assessment.vulnerability_id].append(assessment)

		# Batch accumulators to minimize database hits
		vulns_to_update = []
		assessments_to_create = []
		assessments_to_update = []
		assessment_ids_to_delete = []
		
		# Process scoring and preliminary calculations
		for vuln in vulns:
			self._process_single_vuln(
				vuln,
				subdomain_cve_map=subdomain_cve_map,
				assessments_by_vuln=assessments_by_vuln,
				vulns_to_update=vulns_to_update,
				assessments_to_create=assessments_to_create,
				assessments_to_update=assessments_to_update,
				assessment_ids_to_delete=assessment_ids_to_delete
			)

		# In-scan duplicate detection using group_key (in-memory to avoid unsaved DB lookups)
		from collections import defaultdict
		vulns_by_key = defaultdict(list)
		for v in vulns:
			vulns_by_key[v.group_key].append(v)
		
		for key, group_vulns in vulns_by_key.items():
			if len(group_vulns) > 1:
				# Sort by verification status first (verified first), then by correlation score descending
				group_vulns.sort(key=lambda x: (x.validation_status == 'verified', x.correlation_score or 0.0), reverse=True)
				
				survivor = group_vulns[0]
				if not survivor.affected_urls:
					survivor.affected_urls = []
				if survivor.http_url and survivor.http_url not in survivor.affected_urls:
					survivor.affected_urls.append(survivor.http_url)
					
				# Ensure survivor is in vulns_to_update if modified
				if survivor not in vulns_to_update:
					vulns_to_update.append(survivor)

				# Suppress all except the highest-ranked one
				for dup_vuln in group_vulns[1:]:
					dup_vuln.is_suppressed = True
					
					if dup_vuln.http_url and dup_vuln.http_url not in survivor.affected_urls:
						survivor.affected_urls.append(dup_vuln.http_url)
						
					# If it's a by-module grouping (where values might differ but are merged), union the extracted_results
					HIGH_NOISE_MODULES = set(self.tier7_config.get('high_noise_modules', ['sourcemap-detect', 'cookie-security-detect']))
					if survivor.name.lower().strip() in HIGH_NOISE_MODULES:
						if dup_vuln.extracted_results:
							if not survivor.extracted_results:
								survivor.extracted_results = []
							for res in dup_vuln.extracted_results:
								if res not in survivor.extracted_results:
									survivor.extracted_results.append(res)
					
					# If a suppressed vulnerability has an existing assessment, queue it for cleanup
					existing_list = assessments_by_vuln.get(dup_vuln.id, [])
					for ass in existing_list:
						assessment_ids_to_delete.append(ass.id)

		# Filter assessments to create/update to ensure we only have one per vuln_id (and none for suppressed vulns)
		processed_assessment_vuln_ids = set()
		final_assessments_to_create = []
		for ass in assessments_to_create:
			if ass.vulnerability.is_suppressed:
				continue
			if ass.vulnerability_id not in processed_assessment_vuln_ids:
				final_assessments_to_create.append(ass)
				processed_assessment_vuln_ids.add(ass.vulnerability_id)

		final_assessments_to_update = []
		for ass in assessments_to_update:
			if ass.vulnerability.is_suppressed:
				continue
			if ass.vulnerability_id not in processed_assessment_vuln_ids:
				final_assessments_to_update.append(ass)
				processed_assessment_vuln_ids.add(ass.vulnerability_id)

		# Perform bulk database operations within atomic transaction to mitigate data races
		try:
			with transaction.atomic():
				if vulns_to_update:
					Vulnerability.objects.bulk_update(
						vulns_to_update, 
						['correlation_score', 'validation_status', 'group_key', 'is_suppressed', 'affected_urls', 'extracted_results']
					)
					
				if assessment_ids_to_delete:
					# Dedup ID list to delete
					ImpactAssessment.objects.filter(id__in=list(set(assessment_ids_to_delete))).delete()
					
				if final_assessments_to_create:
					ImpactAssessment.objects.bulk_create(final_assessments_to_create)
					
				if final_assessments_to_update:
					ImpactAssessment.objects.bulk_update(
						final_assessments_to_update, 
						['potential_attack_chain', 'scan_history', 'subdomain']
					)
		except Exception as e:
			logger.error(f"Failed to save correlated findings transaction: {e}")

		# Record vulnerability history tracking
		if self.scan_history:
			try:
				self._update_vulnerability_history(vulns)
			except Exception as e:
				logger.error(f"Failed to update vulnerability history: {e}")

	def _generate_group_key(self, vuln):
		"""
		Generates a unique deterministic SHA-256 key to group identical vulnerabilities.

		Args:
			vuln (Vulnerability): The vulnerability record.

		Returns:
			str: A 64-character hexadecimal SHA-256 hash.
		"""
		source = (vuln.source or 'unknown').lower().strip()
		name = vuln.name.lower().strip()
		severity = str(vuln.severity)
		subdomain = (vuln.subdomain.name or '').lower().strip() if vuln.subdomain else ''
		
		# Read high-noise modules from scan configuration (defaults if missing)
		HIGH_NOISE_MODULES = set(self.tier7_config.get('high_noise_modules', ['sourcemap-detect', 'cookie-security-detect']))
		
		if name in HIGH_NOISE_MODULES:
			# By-Module grouping: Ignore extracted_results and endpoint
			raw_key = f"{source}:{name}:{severity}:{subdomain}:bymodule"
		elif vuln.extracted_results and len(vuln.extracted_results) > 0:
			# Value-based grouping: Include the extracted value instead of the endpoint
			sorted_vals = ",".join(sorted(vuln.extracted_results)).lower().strip()
			raw_key = f"{source}:{name}:{severity}:{subdomain}:val:{sorted_vals}"
		else:
			# Fallback: strict endpoint grouping (current behavior) to prevent false merges
			endpoint = (vuln.endpoint.http_url or '').lower().strip() if vuln.endpoint else ''
			raw_key = f"{source}:{name}:{severity}:{subdomain}:ep:{endpoint}"
			
		return hashlib.sha256(raw_key.encode('utf-8')).hexdigest()

	def _process_single_vuln(self, vuln, subdomain_cve_map, assessments_by_vuln, vulns_to_update, assessments_to_create, assessments_to_update, assessment_ids_to_delete):
		"""
		Calculates the correlation score for a single vulnerability based on multi-tool evidence.

		Args:
			vuln (Vulnerability): The vulnerability object.
			subdomain_cve_map (dict): Cached mapping of CVEs on subdomains.
			assessments_by_vuln (dict): Cache of existing ImpactAssessment objects.
			vulns_to_update (list): Collector list for vulnerabilities to update.
			assessments_to_create (list): Collector list for assessments to create.
			assessments_to_update (list): Collector list for assessments to update.
			assessment_ids_to_delete (list): Collector list for assessments to delete.
		"""
		score = 0.0
		
		# 1. CVSS-based severity (40% weight)
		cvss_severity = 0.0
		if vuln.cve_ids.exists():
			cve = vuln.cve_ids.first()
			if cve.cvss_v31_base_score is not None:
				cvss_severity = cve.cvss_v31_base_score / 10.0
			else:
				cvss_severity = (vuln.severity or 1) / 4.0
		else:
			cvss_severity = (vuln.severity or 1) / 4.0
		score += cvss_severity * self.weights['severity']
		
		# 2. Multi-Tool Confirmation (25% weight)
		match_boost, tools = self._calculate_tool_match_boost(vuln, subdomain_cve_map)
		# Reward increasingly based on number of confirming tools:
		# 1 tool = 0.3 base score
		# 2 tools = 0.7 score
		# 3+ tools = 1.0 score
		if len(tools) == 1:
			tool_boost = 0.3
		elif len(tools) == 2:
			tool_boost = 0.7
		else:
			tool_boost = 1.0
		score += tool_boost * self.weights['multi_tool_match']
		
		# 3. Exploitability (20% weight)
		exploit_score = 0.3  # Default fallback
		if any(cve.is_cisa_kev for cve in vuln.cve_ids.all()):
			exploit_score = 0.9
		
		# Incorporate EPSS score/percentile if available
		cve_with_epss = vuln.cve_ids.filter(epss_percentile__isnull=False).first()
		if cve_with_epss and cve_with_epss.epss_percentile is not None:
			exploit_score = max(exploit_score, cve_with_epss.epss_percentile / 100.0)
			
		# Explicit proof of concept
		if vuln.exploit_url:
			exploit_score = 1.0
		score += exploit_score * self.weights['exploitability']
		
		# 4. Asset Context (10% weight)
		criticality = 1
		if vuln.subdomain and vuln.subdomain.criticality_level:
			criticality = vuln.subdomain.criticality_level
		crit_score = criticality / 5.0
		score += crit_score * self.weights['asset_criticality']
		
		# 5. Temporal Factor (5% weight)
		discovered_date = vuln.discovered_date or timezone.now()
		days_old = (timezone.now() - discovered_date).days
		if days_old < 7:
			temporal_score = 1.0
		elif days_old < 30:
			temporal_score = 0.8
		elif days_old < 90:
			temporal_score = 0.5
		else:
			temporal_score = 0.2
		score += temporal_score * self.weights['temporal']
		
		vuln.correlation_score = round(score * 100, 2)
		
		# Threshold-based verification
		cve_with_cisa = vuln.cve_ids.filter(is_cisa_kev=True).first()
		if vuln.correlation_score >= 90 and len(tools) >= 2:
			vuln.validation_status = 'verified'
		elif vuln.correlation_score >= 75 and cve_with_cisa:
			vuln.validation_status = 'verified'
		else:
			vuln.validation_status = 'unverified'
			
		vulns_to_update.append(vuln)
		
		# Generate Potential Attack Chain
		self._generate_attack_chain(
			vuln,
			tools,
			assessments_by_vuln=assessments_by_vuln,
			assessments_to_create=assessments_to_create,
			assessments_to_update=assessments_to_update,
			assessment_ids_to_delete=assessment_ids_to_delete
		)

	def _calculate_tool_match_boost(self, vuln, subdomain_cve_map):
		"""
		Checks if other tools confirmed this finding (Optimized using in-memory map instead of query loop).

		Args:
			vuln (Vulnerability): The vulnerability being evaluated.
			subdomain_cve_map (dict): Pre-fetched map of subdomain vulnerabilities by CVE.

		Returns:
			tuple: A tuple containing (boost_score, list_of_tools).
		"""
		tools = [self._infer_tool_name(vuln)]
		boost = 0.5
		cve_ids = list(vuln.cve_ids.values_list('name', flat=True))
		
		other_findings = []
		if vuln.subdomain_id:
			seen_ids = set()
			for name in cve_ids:
				key = (vuln.subdomain_id, name)
				for other in subdomain_cve_map.get(key, []):
					if other.id != vuln.id and other.id not in seen_ids:
						other_findings.append(other)
						seen_ids.add(other.id)
		
		for other in other_findings:
			tool_name = self._infer_tool_name(other)
			if tool_name not in tools:
				tools.append(tool_name)
		
		if len(tools) > 1:
			boost = 1.0 # High confidence
			
		return boost, tools

	def _infer_tool_name(self, vuln):
		"""
		Determines the scanner tool name from the vulnerability source or name.
		
		Args:
			vuln (Vulnerability): The vulnerability record.
			
		Returns:
			str: The inferred tool name.
		"""
		if vuln.source:
			source = vuln.source.strip()
			if source.lower() == 'retire':
				return 'Retire.js'
			return source.capitalize()

		name = vuln.name.lower()
		mappings = {
			'gitleaks': 'Gitleaks',
			'semgrep': 'Semgrep',
			'retire': 'Retire.js',
			'nuclei': 'Nuclei',
		}
		for key, tool in mappings.items():
			if key in name:
				return tool
		return 'Unknown'

	def _generate_attack_chain(self, vuln, tools, assessments_by_vuln, assessments_to_create, assessments_to_update, assessment_ids_to_delete):
		"""
		Populates the potential_attack_chain in ImpactAssessment (Optimized using in-memory batch maps).

		Args:
			vuln (Vulnerability): The vulnerability record.
			tools (list): List of confirming tool names.
			assessments_by_vuln (dict): Cache of existing ImpactAssessment records.
			assessments_to_create (list): Collector list for assessments to create.
			assessments_to_update (list): Collector list for assessments to update.
			assessment_ids_to_delete (list): Collector list for assessments to delete.
		"""
		chain = {
			'steps': [
				{'phase': 'Discovery', 'description': f"Identified via {', '.join(tools)}"},
			],
			'confidence': 'High' if len(tools) > 1 else 'Medium'
		}
		
		# Heuristic steps based on vuln type
		if vuln.type == 'SCA':
			chain['steps'].append({'phase': 'Exploitation', 'description': "Leverage known CVE in public-facing dependency"})
		elif vuln.type == 'SAST':
			chain['steps'].append({'phase': 'Exploitation', 'description': "Exploit insecure code pattern (e.g. Injection)"})
		elif 'leak' in vuln.name.lower() or 'secret' in vuln.name.lower():
			chain['steps'].append({'phase': 'Exploitation', 'description': "Use exposed credentials/keys to access unauthorized services"})
		
		chain['steps'].append({'phase': 'Post-Exploitation', 'description': "Pivot to internal network or access sensitive data"})
		
		existing_list = assessments_by_vuln.get(vuln.id, [])
		if existing_list:
			existing_list.sort(key=lambda x: x.updated_at or x.id, reverse=True)
		existing = existing_list[0] if existing_list else None
		
		if existing and existing.potential_attack_chain and 'apme_path_id' in existing.potential_attack_chain:
			logger.info(f"Correlation: Skipping heuristic chain for vuln {vuln.id}, APME path already exists.")
			return

		# Deduplicate
		if len(existing_list) > 1:
			logger.warning(
				f"Correlation: Found {len(existing_list)} ImpactAssessment rows for vuln {vuln.id}. "
				f"Deduplicating — keeping most recent record."
			)
			assessment_ids_to_delete.extend([x.id for x in existing_list[1:]])

		# Safely perform updates/creates via batch lists
		if existing:
			existing.potential_attack_chain = chain
			existing.scan_history = self.scan_history
			existing.subdomain = vuln.subdomain
			assessments_to_update.append(existing)
		else:
			assessment = ImpactAssessment(
				vulnerability=vuln,
				potential_attack_chain=chain,
				scan_history=self.scan_history,
				subdomain=vuln.subdomain
			)
			assessments_to_create.append(assessment)

	def _update_vulnerability_history(self, current_vulns):
		"""
		Tracks vulnerability history records and marks resolved items as remediated.

		Args:
			current_vulns (QuerySet): Vulnerabilities processed in this run.
		"""
		current_keys = set()
		for vuln in current_vulns:
			if vuln.is_suppressed:
				continue
			current_keys.add(vuln.group_key)
			cve = vuln.cve_ids.first() if vuln.cve_ids.exists() else None
			
			# Check for previous history record to find first_seen or accumulate occurrences
			prev_history = VulnerabilityHistory.objects.filter(
				group_key=vuln.group_key
			).order_by('-last_seen').first()
			
			first_seen_time = prev_history.first_seen if prev_history else timezone.now()
			total_count = (prev_history.total_occurrences + 1) if prev_history else 1
			
			VulnerabilityHistory.objects.update_or_create(
				group_key=vuln.group_key,
				scan_history=self.scan_history,
				defaults={
					'vulnerability': vuln,
					'cve': cve,
					'first_seen': first_seen_time,
					'total_occurrences': total_count,
					'is_remediated': False,
					'remediation_date': None
				}
			)

		# Mark remediated findings: present in previous scans for the same domain, but not in this one
		prev_scans = self.scan_history.domain.scanhistory_set.exclude(id=self.scan_history.id)
		if prev_scans.exists():
			active_prev_histories = VulnerabilityHistory.objects.filter(
				scan_history__in=prev_scans,
				is_remediated=False
			).exclude(group_key__in=current_keys)
			
			for old_hist in active_prev_histories:
				old_hist.is_remediated = True
				old_hist.remediation_date = timezone.now()
				old_hist.save()
