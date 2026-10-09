# CVE Enrichment System

## Overview

The CVE enrichment system automatically fetches and updates vulnerability metadata from official sources:

- **NVD API v2.0**: CVSS v3.1 scores, attack vectors, impact metrics
- **FIRST EPSS API**: Exploit prediction scores
- **CISA KEV Catalog**: Known exploited vulnerabilities
- **SploitScan**: Public exploit evidence (ExploitDB, Metasploit, GitHub PoCs), HackerOne stats, and Patching Priority
- **Internal LLM Engine**: Automated, context-aware risk assessments and mitigation strategies

The enriched metadata is stored in the `CveId` model and is consumed by the
`VulnerabilityCorrelationEngine` to produce more accurate correlation and risk scores.

---

## Installation & Setup

### 1. Configure API Keys (Optional)

For faster NVD API access, obtain a free API key from:
https://nvd.nist.gov/developers/request-an-api-key

Add to `.env`:
```
NVD_API_KEY=your-api-key-here
```

### 2. Run Migrations

```bash
python manage.py migrate startScan
```

This creates / verifies the following database objects:
- Enhanced `CveId` model with CVSS v3.1, EPSS, and attack-vector fields (migration `0035`)
- `VulnerabilityHistory` model for cross-scan vulnerability tracking (migration `0036`)

### 3. Install Optional Dependencies

```bash
pip install requests  # Usually already installed
```

---

## Usage

### Programmatic Usage

```python
from reNgine.cve_enrichment import CVEEnrichmentService

service = CVEEnrichmentService()

# Enrich a single CVE
cve = service.enrich_cve('CVE-2024-1234')
print(f"CVSS: {cve.cvss_v31_base_score}")
print(f"EPSS: {cve.epss_percentile}%")
print(f"CISA KEV: {cve.is_cisa_kev}")

# Batch enrich
results = service.enrich_multiple_cves([
    'CVE-2024-1234',
    'CVE-2024-5678'
])

# Sync CISA KEV catalog
result = service.sync_cisa_kev_catalog()
print(f"Updated {result['updated']} KEV entries")
```

### Management Command Usage

```bash
# Enrich unenriched CVEs (default)
python manage.py sync_cve_data

# Sync CISA KEV catalog
python manage.py sync_cve_data --kev

# Refresh CVEs from last 30 days
python manage.py sync_cve_data --refresh 30

# Full synchronization
python manage.py sync_cve_data --all --limit 500

# Run once daily via cron
0 2 * * * cd /app && python manage.py sync_cve_data --all
```

### Background Sync

There is no Celery task any more. The Python orchestrator runs `sync_cve_data` as a one-shot
startup sync about five minutes after it starts (see `_STARTUP_SYNC_TASKS` in
`web/scanEngine/management/commands/run_temporal_orchestrator.py`), and scans enrich their own
CVEs through `enrich_scan_cves_activity`. For anything else, use the management command above.

---

## Correlation Integration

The `VulnerabilityCorrelationEngine` (`reNgine/correlation.py`) automatically uses enriched CVE
data when calculating risk scores:

```python
# Scoring weights CVE severity (40% of total score)
if cve.cvss_v31_base_score is not None:
    severity_score = cve.cvss_v31_base_score / 10.0   # 0-1 scale

# Incorporates EPSS for exploitability (20% of total score)
if cve.epss_percentile is not None:
    exploit_score = max(base_score, cve.epss_percentile / 100.0)

# Boosts CISA KEV vulnerabilities to 0.9 exploitability
if cve.is_cisa_kev:
    exploit_score = 0.9
```

Vulnerabilities are automatically marked `verified` when their correlation score exceeds the
threshold (≥ 90 with multi-tool confirmation, or ≥ 75 with CISA KEV status).

---

## Troubleshooting

### API Timeouts

If external API calls timeout:
- Check network connectivity inside the Docker container
- Verify API keys are valid
- Increase timeout in `cve_enrichment.py` (default: `REQUEST_TIMEOUT = 15` seconds)

### Rate Limiting

NVD API is rate-limited:
- **With API key**: 50 requests / 30 seconds
- **Without API key**: 5 requests / 30 seconds

The service gracefully handles this by:
- Caching responses for 7 days
- Skipping recently enriched CVEs (re-enrichment only after 7 days)
- Logging warnings instead of raising exceptions

### Missing CVSS Data

Some CVEs may not have CVSS v3.1 data in NVD yet.
The system falls back to the vulnerability's own `severity` field for scoring.

---

## Data Retention

Enriched CVE data is cached:
- **Individual CVEs**: 7 days (`CACHE_TTL_CVE = 86400 * 7`)
- **CISA KEV catalog**: 1 hour (`CACHE_TTL_KEV = 3600`)

Clear cache to force re-fetch:
```bash
python manage.py shell
>>> from django.core.cache import cache
>>> cache.clear()
```

---

## Performance Considerations

| Operation | Approximate Time |
|---|---|
| First enrichment per CVE | ~200 ms (API + DB write) |
| Cached lookup | ~1 ms |
| Batch enrichment throughput | ~100 CVEs / minute |

**Recommendations:**
- Run enrichment during off-peak hours via cron
- Use `--limit` flag to avoid overwhelming the system
- Schedule daily sync: `0 2 * * * python manage.py sync_cve_data --all`

---

## Monitoring

Check enrichment progress from the Django shell:

```bash
python manage.py shell
>>> from startScan.models import CveId
>>> total = CveId.objects.count()
>>> enriched = CveId.objects.filter(cvss_v31_base_score__isnull=False).count()
>>> print(f"{enriched}/{total} CVEs enriched ({100*enriched//total if total else 0}%)")

>>> kev = CveId.objects.filter(is_cisa_kev=True).count()
>>> print(f"{kev} CVEs in CISA KEV catalog")
```

---

## Model Reference

The `CveId` model (`startScan/models.py`) stores the following enrichment fields:

| Field | Source | Description |
|---|---|---|
| `cvss_v31_base_score` | NVD | CVSS v3.1 base score (0–10) |
| `attack_vector` | NVD | NETWORK / ADJACENT / LOCAL / PHYSICAL |
| `attack_complexity` | NVD | LOW / HIGH |
| `privileges_required` | NVD | NONE / LOW / HIGH |
| `user_interaction` | NVD | NONE / REQUIRED |
| `confidentiality_impact` | NVD | NONE / LOW / HIGH |
| `integrity_impact` | NVD | NONE / LOW / HIGH |
| `availability_impact` | NVD | NONE / LOW / HIGH |
| `epss_score` | FIRST | Exploitation probability (0–1) |
| `epss_percentile` | FIRST | Percentile rank (0–100) |
| `published_date` | NVD | CVE publication date |
| `last_modified_date` | NVD | Last NVD update date |
| `vulnerability_type` | Internal | SCA / DAST / SAST / Config |
| `is_cisa_kev` | CISA | True if in Known Exploited Vulnerabilities catalog |
| `public_exploits` | SploitScan | JSON array of ExploitDB, Metasploit, and GitHub PoCs |
| `hackerone_data` | SploitScan | JSON object containing Hacktivity stats and rank |
| `patching_priority` | SploitScan | String priority level |
| `ai_risk_assessment` | Internal LLM | Text containing LLM-generated risk assessment |
| `mitigation_ideas` | Internal LLM | Text containing LLM-generated mitigation strategy |
