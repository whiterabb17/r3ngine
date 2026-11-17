"""Shared WordPress version guidance helpers for WPScan and WPTaint."""
from __future__ import annotations

import re
from typing import Any, Dict, Iterable, List, Optional, Tuple

from startScan.models import Vulnerability

_PATCH_MARKER = "**Version guidance:**"
_INSTALLED_RE = re.compile(
	r"(?:Plugin|Theme)\s+\*\*[^*]+\*\*\s+v(?P<installed>[0-9][0-9A-Za-z._-]*)",
	re.IGNORECASE,
)
_LATEST_RE = re.compile(r"latest:\s*(?P<latest>[0-9][0-9A-Za-z._-]*)", re.IGNORECASE)
_FIXED_IN_TITLE_RE = re.compile(r"<\s*(?P<fixed>[0-9][0-9A-Za-z._-]*)")
_WPTAINT_SLUG_RE = re.compile(r"^WP Taint \((?P<slug>[^)]+)\):")


def normalize_version(value: Any) -> Optional[str]:
	"""Return a usable version string or None."""
	if value is None:
		return None
	text = str(value).strip()
	if not text or text.lower() in {"unknown", "n/a", "none"}:
		return None
	return text


def build_version_guidance(
	*,
	component: str,
	slug: str,
	installed: Any = None,
	latest: Any = None,
	outdated: Any = None,
	fixed_in: Any = None,
	tainted_version: Any = None,
	tainted_source: Any = None,
	extra: Optional[Dict[str, Any]] = None,
) -> Dict[str, Any]:
	"""Build a compact version_guidance dict (omit empty keys)."""
	guidance: Dict[str, Any] = {
		"component": component,
		"slug": slug,
	}
	installed_n = normalize_version(installed)
	latest_n = normalize_version(latest)
	fixed_n = normalize_version(fixed_in)
	tainted_n = normalize_version(tainted_version)
	if installed_n:
		guidance["installed"] = installed_n
	if latest_n:
		guidance["latest"] = latest_n
	if outdated is not None:
		guidance["outdated"] = bool(outdated)
	if fixed_n:
		guidance["fixed_in"] = fixed_n
	if tainted_n:
		guidance["tainted_version"] = tainted_n
	if tainted_source:
		guidance["tainted_source"] = str(tainted_source)
	if extra:
		for key, val in extra.items():
			if val is not None and val != "":
				guidance[key] = val
	return guidance


def version_guidance_to_extracted_results(guidance: Dict[str, Any]) -> List[str]:
	"""Flatten version_guidance into extracted_results tokens."""
	if not guidance:
		return []
	component = guidance.get("component") or "plugin"
	slug = guidance.get("slug")
	tokens: List[str] = []
	if slug:
		tokens.append(f"{component}:{slug}")
	for key in ("installed", "latest", "fixed_in", "tainted_version", "tainted_source"):
		val = guidance.get(key)
		if val is not None and val != "":
			tokens.append(f"{key}:{val}")
	if "outdated" in guidance:
		tokens.append(f"outdated:{bool(guidance.get('outdated'))}")
	return tokens


def format_version_patch_line(guidance: Dict[str, Any]) -> str:
	"""Deterministic remediation sentence for UI/reports."""
	if not guidance:
		return ""
	slug = guidance.get("slug") or "component"
	installed = guidance.get("installed")
	latest = guidance.get("latest")
	fixed_in = guidance.get("fixed_in")
	tainted_version = guidance.get("tainted_version")
	tainted_source = guidance.get("tainted_source")

	parts: List[str] = [f"{_PATCH_MARKER} `{slug}`"]
	if installed:
		parts.append(f"installed `{installed}`")
	if latest:
		parts.append(f"latest `{latest}`")
	if fixed_in:
		parts.append(f"vulnerable below `{fixed_in}` — patch/upgrade to ≥ `{fixed_in}`")
	elif latest and installed and installed != latest:
		parts.append(f"upgrade toward latest `{latest}`")
	elif latest:
		parts.append(f"ensure version is current (latest `{latest}`)")
	else:
		parts.append("confirm installed version and apply vendor security updates")
	if tainted_version:
		src = tainted_source or "unknown"
		parts.append(f"WPTaint analyzed `{tainted_version}` ({src})")
	elif tainted_source:
		if tainted_source in {"latest", "latest_fallback"}:
			parts.append(
				f"WPTaint analyzed latest wordpress.org release (`{tainted_source}`); "
				"installed version unconfirmed for the taint tree"
			)
		else:
			parts.append(f"WPTaint analyzed plugin source (`{tainted_source}`)")
	return "; ".join(parts) + "."


def merge_extracted_results(existing: Optional[Iterable[str]], guidance: Dict[str, Any]) -> List[str]:
	"""Merge guidance tokens into existing extracted_results without dupes.

	Replaces prior tokens for the same key prefix (installed:/latest:/fixed_in:/…)
	so re-correlation does not leave stale version values.
	"""
	guided = version_guidance_to_extracted_results(guidance)
	guided_prefixes = set()
	for token in guided:
		if ":" in token:
			guided_prefixes.add(token.split(":", 1)[0] + ":")

	merged: List[str] = []
	seen = set()
	for item in list(existing or []):
		text = str(item).strip()
		if not text or text in seen:
			continue
		if ":" in text and (text.split(":", 1)[0] + ":") in guided_prefixes:
			continue
		seen.add(text)
		merged.append(text)
	for text in guided:
		if not text or text in seen:
			continue
		seen.add(text)
		merged.append(text)
	return merged


def apply_version_guidance_to_vuln(
	vuln: Vulnerability,
	guidance: Dict[str, Any],
	*,
	note: Optional[str] = None,
	update_validation_reason: bool = False,
) -> Vulnerability:
	"""Persist version_guidance onto a Vulnerability row."""
	if not guidance:
		return vuln

	enrichment = dict(vuln.agent_enrichment or {})
	existing_vg = dict(enrichment.get("version_guidance") or {})
	existing_vg.update({k: v for k, v in guidance.items() if v is not None and v != ""})
	enrichment["version_guidance"] = existing_vg
	if note:
		enrichment["version_guidance_note"] = note
	vuln.agent_enrichment = enrichment
	vuln.extracted_results = merge_extracted_results(vuln.extracted_results, existing_vg)

	update_fields = ["agent_enrichment", "extracted_results"]
	patch_line = format_version_patch_line(existing_vg)
	if patch_line:
		remediation = vuln.remediation or ""
		if _PATCH_MARKER in remediation:
			# Replace prior guidance block (single line) if present.
			lines = remediation.splitlines()
			rewritten = []
			for line in lines:
				if line.strip().startswith(_PATCH_MARKER):
					rewritten.append(patch_line)
				else:
					rewritten.append(line)
			remediation = "\n".join(rewritten)
			if _PATCH_MARKER not in remediation:
				remediation = (remediation.rstrip() + "\n\n" + patch_line).strip()
		else:
			remediation = (remediation.rstrip() + "\n\n" + patch_line).strip() if remediation else patch_line
		vuln.remediation = remediation
		update_fields.append("remediation")

		if update_validation_reason:
			reason = vuln.validation_reason or ""
			if _PATCH_MARKER in reason:
				lines = reason.splitlines()
				rewritten = []
				for line in lines:
					if line.strip().startswith(_PATCH_MARKER):
						rewritten.append(patch_line)
					else:
						rewritten.append(line)
				vuln.validation_reason = "\n".join(rewritten)
			else:
				vuln.validation_reason = (reason.rstrip() + "\n" + patch_line).strip() if reason else patch_line
			update_fields.append("validation_reason")

	vuln.save(update_fields=update_fields)
	return vuln


_PLUGIN_SLUG_RE = re.compile(r"^[a-z0-9-]+$")


def is_safe_wordpress_plugin_slug(slug: str) -> bool:
	"""True when slug matches wordpress.org plugin slug conventions."""
	return bool(slug and _PLUGIN_SLUG_RE.fullmatch(slug))


def wordpress_org_plugin_download_candidates(
	slug: str,
	installed_version: Optional[str] = None,
) -> List[Tuple[str, Optional[str], str]]:
	"""Return ordered (url, version_label, source) download candidates.

	Prefers the installed version zip when known, then latest zip.
	"""
	if not is_safe_wordpress_plugin_slug(slug):
		return []
	candidates: List[Tuple[str, Optional[str], str]] = []
	installed = normalize_version(installed_version)
	# Restrict installed version to wordpress.org-safe path characters.
	if installed and not re.fullmatch(r"[0-9A-Za-z._-]+", installed):
		installed = None
	if installed:
		candidates.append(
			(
				f"https://downloads.wordpress.org/plugin/{slug}.{installed}.zip",
				installed,
				"installed",
			)
		)
		candidates.append(
			(
				f"https://downloads.wordpress.org/plugin/{slug}.zip",
				"latest",
				"latest_fallback",
			)
		)
	else:
		candidates.append(
			(
				f"https://downloads.wordpress.org/plugin/{slug}.zip",
				"latest",
				"latest",
			)
		)
	return candidates


def parse_wptaint_plugin_slug(name: str) -> Optional[str]:
	"""Extract plugin slug from a WPTaint finding name."""
	match = _WPTAINT_SLUG_RE.match(name or "")
	return match.group("slug").strip() if match else None


def parse_guidance_from_wpscan_vuln(vuln: Vulnerability) -> Optional[Dict[str, Any]]:
	"""Best-effort version_guidance from an existing WPScan row."""
	enrichment = vuln.agent_enrichment or {}
	existing = enrichment.get("version_guidance")
	if isinstance(existing, dict) and existing.get("slug"):
		return dict(existing)

	name = vuln.name or ""
	slug = None
	component = "plugin"
	if name.startswith("WordPress Plugin Detected: "):
		slug = name[len("WordPress Plugin Detected: "):].strip()
		component = "plugin"
	elif name.startswith("WordPress Plugin: "):
		slug = name[len("WordPress Plugin: "):].split(" - ")[0].strip()
		component = "plugin"
	elif name.startswith("WordPress Theme Detected: "):
		slug = name[len("WordPress Theme Detected: "):].strip()
		component = "theme"
	elif name.startswith("WordPress Theme: "):
		slug = name[len("WordPress Theme: "):].split(" - ")[0].strip()
		component = "theme"
	elif name.startswith("WordPress Core Detected:"):
		slug = "wordpress-core"
		component = "core"
	elif name.startswith("WordPress Core"):
		slug = "wordpress-core"
		component = "core"
	else:
		return None

	installed = None
	latest = None
	fixed_in = None
	for token in vuln.extracted_results or []:
		text = str(token)
		if text.startswith("installed:"):
			installed = text.split(":", 1)[1]
		elif text.startswith("latest:"):
			latest = text.split(":", 1)[1]
		elif text.startswith("fixed_in:"):
			fixed_in = text.split(":", 1)[1]

	desc = vuln.description or ""
	if not installed:
		m = _INSTALLED_RE.search(desc)
		if m:
			installed = m.group("installed")
		elif component == "core":
			m_core = re.search(r"v(?P<v>[0-9][0-9A-Za-z._-]*)", name)
			if m_core:
				installed = m_core.group("v")
	if not latest:
		m = _LATEST_RE.search(desc)
		if m:
			latest = m.group("latest")
	if not fixed_in:
		m = _FIXED_IN_TITLE_RE.search(name)
		if m:
			fixed_in = m.group("fixed")

	outdated = None
	if "outdated" in desc.lower():
		outdated = True

	return build_version_guidance(
		component=component,
		slug=slug,
		installed=installed,
		latest=latest,
		outdated=outdated,
		fixed_in=fixed_in,
	)


def collect_wpscan_plugin_versions(scan) -> Dict[str, Dict[str, Any]]:
	"""Map plugin slug -> best version_guidance from WPScan rows on a scan.

	Prefers detection rows with installed version; merges fixed_in from advisories.
	"""
	by_slug: Dict[str, Dict[str, Any]] = {}
	qs = Vulnerability.objects.filter(
		scan_history=scan,
		source="WPScan",
		type="WordPress",
	).order_by("id")
	for vuln in qs:
		guidance = parse_guidance_from_wpscan_vuln(vuln)
		if not guidance:
			continue
		if guidance.get("component") not in {"plugin", "theme", "core"}:
			continue
		slug = guidance.get("slug")
		if not slug:
			continue
		current = by_slug.get(slug, {})
		merged = dict(current)
		# Prefer concrete installed/latest from detection-style rows.
		for key in ("component", "slug", "installed", "latest", "outdated", "fixed_in"):
			val = guidance.get(key)
			if val is None or val == "":
				continue
			if key in {"installed", "latest"} and merged.get(key) and not (
				vuln.name or ""
			).startswith(("WordPress Plugin Detected:", "WordPress Theme Detected:", "WordPress Core Detected:")):
				# Don't let advisory-only rows clobber detection installed/latest unless missing.
				continue
			if key == "fixed_in":
				existing_fixed = merged.get("fixed_in")
				if existing_fixed and existing_fixed != val:
					all_fixed = list(merged.get("fixed_in_all") or [])
					for item in (existing_fixed, val):
						if item not in all_fixed:
							all_fixed.append(item)
					merged["fixed_in_all"] = all_fixed

					def _ver_key(v):
						parts = []
						for p in re.split(r"[._-]", str(v)):
							if p.isdigit():
								parts.append((0, int(p)))
							else:
								parts.append((1, str(p)))
						return tuple(parts)

					try:
						merged["fixed_in"] = max([existing_fixed, val], key=_ver_key)
					except TypeError:
						# Keep the longer/more specific cutoff when mixed types collide.
						merged["fixed_in"] = max([existing_fixed, val], key=lambda x: (len(str(x)), str(x)))
				else:
					merged["fixed_in"] = val
			else:
				merged[key] = val
		by_slug[slug] = merged
	return by_slug
