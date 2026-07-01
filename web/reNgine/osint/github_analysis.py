"""GitHub org analysis: repo enumeration, secret scanning engines, CI/CD audit.

Orchestration entry point: run_github_analysis()
Private helpers:
  _derive_github_orgs()   — auto-derive org slugs from a domain name
  _get_proxy_env()        — build env dict with HTTP(S)_PROXY if configured
  _run_enumerepo()        — enumerate repos with enumerepo (Go)
  _run_trufflehog_github()— scan repos with trufflehog github source
  _run_gitleaks_github()  — scan repos with gitleaks (URL source)
  _run_noseyparker()      — scan repos with noseyparker, then parse report
  _run_titus()            — scan repos with titus
  _run_gato()             — audit GitHub Actions CI/CD workflows (requires token)
"""

import json
import logging
import os
import re as _re
import subprocess

import requests
import tldextract

from dashboard.models import GitHubAPIKey
from reNgine.common_func import get_random_proxy
from reNgine.definitions import (
    ENUMEREPO,
    GATO,
    GITLEAKS,
    NOSEYPARKER,
    TITUS,
    TRUFFLEHOG,
    USES_TOOLS,
)
from reNgine.tasks.persistence import save_secret_leak
from scanEngine.models import Proxy

logger = logging.getLogger(__name__)

_GITHUB_API = 'https://api.github.com/orgs/{}'

# gato is installed into its own uv venv
_GATO_BIN = '/usr/src/github/gato/.venv/bin/gato'


def _safe_slug(value: str) -> str:
    """Reduce an externally-sourced org/repo name to a safe filesystem slug.

    Strips any character that is not alphanumeric, a hyphen, a dot, or an
    underscore, then truncates to 64 characters.  This prevents path-traversal
    attacks when the value is used as a component inside os.path.join().
    """
    return _re.sub(r'[^a-zA-Z0-9._-]', '_', value)[:64]


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------

def _derive_github_orgs(host: str, token: str | None) -> list[str]:
    """Auto-derive probable GitHub org slugs from a domain name.

    Queries the GitHub API to confirm which candidate slugs resolve to real orgs.
    Returns a list of validated org slugs; empty list if none resolve.
    """
    extracted = tldextract.extract(host)
    domain_part = extracted.domain  # e.g. 'acme' from 'acme.com'

    candidates: set[str] = set()
    candidates.add(domain_part)
    # Add hyphen-collapsed and hyphen-expanded variants
    if '-' in domain_part:
        candidates.add(domain_part.replace('-', ''))
    candidates.add(domain_part.replace('_', '-'))

    headers = {'Authorization': f'token {token}'} if token else {}
    validated = []
    for slug in sorted(candidates):
        if not slug:
            continue
        try:
            resp = requests.get(
                _GITHUB_API.format(slug),
                headers=headers,
                timeout=10,
            )
            if resp.status_code == 200:
                validated.append(slug)
        except Exception as exc:
            logger.warning("GitHub API check failed for slug %s: %s", slug, exc)

    return validated


def _get_proxy_env() -> dict:
    """Return a copy of os.environ with HTTP(S)_PROXY set if a proxy is configured."""
    proxy_obj = Proxy.objects.first()
    proxy = get_random_proxy() if proxy_obj and proxy_obj.use_proxy else None
    env = os.environ.copy()
    if proxy:
        env['HTTPS_PROXY'] = proxy
        env['HTTP_PROXY'] = proxy
    return env


def _run_enumerepo(orgs: list[str], token: str | None, results_dir: str) -> list[str]:
    """Return list of 'org/repo' strings discovered by enumerepo."""
    env = _get_proxy_env()
    if token:
        env['GITHUB_TOKEN'] = token

    repos: list[str] = []
    for org in orgs:
        cmd = ['enumerepo', '-org', org]
        try:
            result = subprocess.run(cmd, capture_output=True, env=env, timeout=120)
            for line in result.stdout.decode('utf-8', errors='replace').splitlines():
                line = line.strip()
                if '/' in line:
                    repos.append(line)
        except Exception as exc:
            logger.warning("enumerepo failed for org %s: %s", org, exc)

    return repos


def _run_trufflehog_github(repos: list[str], scan_history, results_dir: str) -> None:
    """Scan each repo with trufflehog github source and persist findings."""
    env = _get_proxy_env()
    for repo in repos:
        cmd = [
            'trufflehog', 'github',
            '--repo', f'https://github.com/{repo}',
            '--json', '--no-update',
        ]
        try:
            result = subprocess.run(cmd, capture_output=True, env=env, timeout=300)
            for line in result.stdout.decode('utf-8', errors='replace').splitlines():
                if line.strip():
                    save_secret_leak(
                        scan_history=scan_history,
                        tool_name='trufflehog-github',
                        secret_type='git_secret',
                        source_url=f'https://github.com/{repo}',
                        match_content=line[:2000],
                    )
        except Exception as exc:
            logger.warning("trufflehog github failed for %s: %s", repo, exc)


def _run_gitleaks_github(repos: list[str], scan_history, results_dir: str) -> None:
    """Clone and scan each repo with gitleaks, persist JSON findings."""
    env = _get_proxy_env()
    for repo in repos:
        safe_repo = _safe_slug(repo.replace('/', '_'))
        clone_dir = os.path.join(results_dir, 'gitleaks_clone', safe_repo)
        os.makedirs(clone_dir, exist_ok=True)
        report_path = os.path.join(results_dir, f'gitleaks_{safe_repo}.json')
        clone_cmd = ['git', 'clone', '--depth', '1',
                     f'https://github.com/{repo}', clone_dir]
        try:
            subprocess.run(clone_cmd, capture_output=True, env=env, timeout=120)
            scan_cmd = [
                'gitleaks', 'detect',
                '--source', clone_dir,
                '--report-format', 'json',
                '--report-path', report_path,
                '--exit-code', '0',
            ]
            subprocess.run(scan_cmd, capture_output=True, env=env, timeout=300)
            if os.path.exists(report_path):
                with open(report_path, 'r') as fh:
                    findings = json.load(fh)
                for finding in findings or []:
                    save_secret_leak(
                        scan_history=scan_history,
                        tool_name='gitleaks-github',
                        secret_type=finding.get('Description', 'git_secret'),
                        source_url=finding.get('File', f'https://github.com/{repo}'),
                        match_content=finding.get('Secret', '')[:2000],
                    )
        except Exception as exc:
            logger.warning("gitleaks github failed for %s: %s", repo, exc)


def _run_noseyparker(repos: list[str], scan_history, results_dir: str) -> None:
    """Scan repos with noseyparker then parse the JSON report for findings."""
    env = _get_proxy_env()
    datastore = os.path.join(results_dir, 'noseyparker_ds')
    os.makedirs(datastore, exist_ok=True)

    for repo in repos:
        scan_cmd = [
            'noseyparker', 'scan',
            '--datastore', datastore,
            f'https://github.com/{repo}',
        ]
        try:
            subprocess.run(scan_cmd, capture_output=True, env=env, timeout=300)
        except Exception as exc:
            logger.warning("noseyparker scan failed for %s: %s", repo, exc)

    report_cmd = [
        'noseyparker', 'report',
        '--datastore', datastore,
        '--format', 'json',
    ]
    try:
        result = subprocess.run(report_cmd, capture_output=True, env=env, timeout=60)
        # noseyparker v0.24.0 JSON report is a list of finding objects.
        # Each finding: {'rule_name': str, 'matches': [{'snippet': {'before': str,
        #   'matching': str, 'after': str}, 'provenance': [{'kind': 'file'|'git_repo',
        #   'path'|'repo_path': str, ...}], ...}], ...}
        data = json.loads(result.stdout.decode('utf-8', errors='replace'))
        findings = data if isinstance(data, list) else []
        for finding in findings:
            rule_name = finding.get('rule_name', 'git_secret')
            for match in finding.get('matches', []):
                # Extract a source URL from the first provenance entry that has
                # a repo_path (git_repo kind) or a file path.
                source_url = 'github'
                for prov in match.get('provenance', []):
                    if prov.get('kind') == 'git_repo':
                        source_url = prov.get('repo_path', 'github')
                        break
                    if prov.get('kind') == 'file':
                        source_url = prov.get('path', 'github')
                        break
                snippet_obj = match.get('snippet') or {}
                snippet = str(snippet_obj.get('matching', ''))
                save_secret_leak(
                    scan_history=scan_history,
                    tool_name='noseyparker',
                    secret_type=rule_name,
                    source_url=source_url,
                    match_content=snippet[:2000],
                )
    except Exception as exc:
        logger.warning("noseyparker report failed: %s", exc)


def _run_titus(repos: list[str], scan_history, results_dir: str) -> None:
    """Scan repos for secrets with titus."""
    env = _get_proxy_env()
    for repo in repos:
        cmd = ['titus', '-repo', f'https://github.com/{repo}']
        try:
            result = subprocess.run(cmd, capture_output=True, env=env, timeout=300)
            for line in result.stdout.decode('utf-8', errors='replace').splitlines():
                if line.strip():
                    save_secret_leak(
                        scan_history=scan_history,
                        tool_name='titus',
                        secret_type='git_secret',
                        source_url=f'https://github.com/{repo}',
                        match_content=line[:2000],
                    )
        except Exception as exc:
            logger.warning("titus failed for %s: %s", repo, exc)


def _run_gato(orgs: list[str], token: str | None, results_dir: str) -> None:
    """Audit GitHub Actions CI/CD workflows with gato.

    Requires a GitHub API token; silently skips if no token is provided.
    """
    if not token:
        logger.warning("gato: no GitHub API key configured — skipping")
        return

    env = _get_proxy_env()
    env['GITHUB_TOKEN'] = token

    for org in orgs:
        output_json = os.path.join(results_dir, f'gato_{_safe_slug(org)}.json')
        cmd = [
            _GATO_BIN,
            'enumerate',
            '--target', org,
            '--skip_sh_runner_enum',
            '--output-json', output_json,
        ]
        try:
            subprocess.run(cmd, capture_output=True, env=env, timeout=600)
        except Exception as exc:
            logger.warning("gato failed for org %s: %s", org, exc)


# ---------------------------------------------------------------------------
# Public entry point
# ---------------------------------------------------------------------------

def run_github_analysis(self, host: str, scan_history, results_dir: str, config: dict) -> None:
    """Orchestrate GitHub org analysis: enumerate repos then scan secrets.

    Called from osint_discovery() when config contains a 'github_analysis' key.
    Org resolution priority:
      1. Explicit github_orgs list in config
      2. Auto-derived from domain name via GitHub API
    """
    github_config = config.get('github_analysis', {})
    if not github_config:
        return

    key_obj = GitHubAPIKey.objects.first()
    token: str | None = key_obj.key if key_obj else None

    if not token:
        logger.warning(
            "GitHub analysis: no API key configured — enumerepo will be heavily rate-limited"
        )

    # Org resolution
    orgs: list[str] = github_config.get('github_orgs') or []
    if not orgs:
        orgs = _derive_github_orgs(host, token)

    if not orgs:
        logger.warning(
            "GitHub analysis: could not determine GitHub org for %s — skipping", host
        )
        return

    uses_tools: list[str] = github_config.get(USES_TOOLS, [ENUMEREPO])

    # enumerepo always runs first to build the repo list
    repos: list[str] = []
    if ENUMEREPO in uses_tools:
        repos = _run_enumerepo(orgs, token, results_dir)
        logger.info("GitHub analysis: found %d repos for %s", len(repos), host)

    if repos:
        if TRUFFLEHOG in uses_tools:
            _run_trufflehog_github(repos, scan_history, results_dir)
        if GITLEAKS in uses_tools:
            _run_gitleaks_github(repos, scan_history, results_dir)
        if NOSEYPARKER in uses_tools:
            _run_noseyparker(repos, scan_history, results_dir)
        if TITUS in uses_tools:
            _run_titus(repos, scan_history, results_dir)

    if github_config.get(GATO):
        _run_gato(orgs, token, results_dir)

    logger.info("GitHub analysis finished for %s", host)
