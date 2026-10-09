import type { components, operations } from '@/types/api';
import type { SummaryResponseBase } from '../../scans/types';

/**
 * `DomainSerializer` row. drf-yasg types every `SerializerMethodField` as `string`, so the
 * method fields whose getters return other types are restated from the serializer.
 */
export type Domain = Omit<
  components["schemas"]["Domain"],
  'vuln_count' | 'subdomain_count' | 'vulnerability_count' | 'organization' | 'most_recent_scan'
  | 'insert_date' | 'insert_date_humanized' | 'start_scan_date' | 'start_scan_date_humanized'
  | 'most_recent_scan_progress'
> & {
  readonly vuln_count?: number;
  readonly subdomain_count?: number;
  readonly vulnerability_count?: number;
  /** Names of the organizations the target belongs to. */
  readonly organization?: string[] | null;
  /** Id of the latest scan. */
  readonly most_recent_scan?: number | null;
  /** `naturalday` of the insert date, e.g. "Today". */
  readonly insert_date?: string | null;
  readonly insert_date_humanized?: string | null;
  readonly start_scan_date?: string | null;
  readonly start_scan_date_humanized?: string | null;
  /** Percentage, 0-100. */
  readonly most_recent_scan_progress?: number;
};

/** Paginated `GET /api/listTargets/` response. */
export type DomainListResponse = Omit<
  operations["api_listTargets_list"]["responses"]["200"]["content"]["application/json"],
  'results'
> & { results: Domain[] };

export interface Organization {
  id: number;
  name: string;
  description?: string;
}

export interface Engine {
  id: number;
  engine_name: string;
  yaml_configuration: string;
  default_engine: boolean;
}

/** Response of `GET /api/target-summary/<slug>/<id>/` (`TargetSummaryAPIView`). */
export interface TargetSummaryResponse extends SummaryResponseBase {
  important_subdomains: { name: string; http_status: number | null; page_title: string | null }[];
  target_info: {
    name: string;
    id: number;
    in_scope_ips: string[];
    secondary_domains: string[];
    manual_subdomains: string[];
  };
  vulnerability_highlights: {
    name: string;
    severity: number;
    http_url: string | null;
    discovered_date: string;
  }[];
  subdomains: { name: string; http_status: number | null; page_title: string | null }[];
  endpoints: { http_url: string; http_status: number | null; content_type: string | null }[];
  vulnerabilities: { name: string; severity: number; description: string | null }[];
}
