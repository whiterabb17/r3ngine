import type { components, operations } from '@/types/api';

/**
 * `VulnerabilitySerializer.get_scan_history`: the scan's own columns (`model_to_dict`, so
 * relations are ids) with a few display fields added, or `{}` when the finding has no scan.
 */
export interface VulnerabilityScanHistory {
  id?: number;
  start_scan_date?: string;
  stop_scan_date?: string | null;
  scan_status?: number;
  scan_type?: number;
  results_dir?: string;
  error_message?: string | null;
  domain?: { name: string };
  initiated_by?: components["schemas"]["MinimalUser"] | null;
  aborted_by?: components["schemas"]["MinimalUser"] | null;
  completed_ago?: string | null;
}

/** drf-yasg types the `scan_history` `SerializerMethodField` as `string`; restated here. */
export type Vulnerability = Omit<components["schemas"]["Vulnerability"], "scan_history"> & {
  readonly scan_history?: VulnerabilityScanHistory;
};

export type VulnerabilityResponse = operations["api_listVulnerability_list"]["responses"]["200"]["content"]["application/json"];


/**
 * A nested `CveId` row. `VulnerabilitySerializer` uses depth=2 and so returns every
 * enrichment column, while the generated schema only lists `id`, `name` and `is_cisa_kev`.
 */
export type VulnerabilityCve = NonNullable<Vulnerability["cve_ids"]>[number] & {
  cvss_v31_base_score?: number | null;
  attack_vector?: string | null;
  attack_complexity?: string | null;
  privileges_required?: string | null;
  user_interaction?: string | null;
  confidentiality_impact?: string | null;
  integrity_impact?: string | null;
  availability_impact?: string | null;
  epss_score?: number | null;
  epss_percentile?: number | null;
  published_date?: string | null;
  last_modified_date?: string | null;
  vulnerability_type?: string | null;
};

/** Relations `VulnerabilityCompactSerializer` drops or reduces. */
type VulnerabilityRelationKey =
  | 'scan_history' | 'validation_results' | 'subdomain' | 'endpoint' | 'target_domain'
  | 'tags' | 'references' | 'cve_ids' | 'cwe_ids' | 'vuln_subscan_ids';

type Related<K extends keyof Vulnerability, F extends keyof NonNullable<Vulnerability[K]>> =
  Pick<NonNullable<Vulnerability[K]>, F> | null;

/**
 * A row of `GET /api/listVulnerability/?compact=1`: the vulnerability's own fields, with
 * each relation reduced to the keys list views read. Every key kept has the same name and
 * value as in the default row, so a compact row can stand in for a `Vulnerability` there.
 */
export type VulnerabilityCompact = Omit<Vulnerability, VulnerabilityRelationKey> & {
  /** `{}` when the finding has no scan. */
  readonly scan_history?: { id?: number };
  readonly subdomain?: Related<'subdomain', 'id' | 'name'>;
  readonly endpoint?: Related<'endpoint', 'id' | 'http_url'>;
  readonly target_domain?: Related<'target_domain', 'id' | 'name'>;
  readonly tags?: Vulnerability['tags'];
  readonly references?: Vulnerability['references'];
  readonly cve_ids?: VulnerabilityCve[];
};

export type VulnerabilityCompactResponse = Omit<VulnerabilityResponse, 'results'> & {
  results: VulnerabilityCompact[];
};

/** Response of `GET /api/tools/gpt_vulnerability_report/`. */
export interface GptVulnerabilityReport {
  status: boolean;
  description?: string;
  impact?: string;
  remediation?: string;
  references?: string[];
  error?: string;
}

/**
 * A vulnerability shown in a detail modal: after an AI analysis `references` holds the
 * report's newline-joined URLs instead of the serializer's `{ id, url }` rows.
 */
export type VulnerabilityWithReportReferences = Omit<Vulnerability, "references"> & {
  references?: Vulnerability["references"] | string;
};
