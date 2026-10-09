import type { components } from '@/types/api';

/**
 * `ScanHistorySerializer` row. drf-yasg types every `SerializerMethodField` as `string`, so the
 * method fields whose getters return other types are restated from the serializer.
 */
export type ScanHistory = Omit<
  components["schemas"]["ScanHistory"],
  | "id" | "scan_status" | "subdomain_count" | "endpoint_count" | "vulnerability_count" | "current_progress"
  | "completed_time" | "completed_ago" | "organizations" | "max_severity" | "is_spiderfoot_running"
  | "successful_task_count" | "failed_task_count" | "total_task_count" | "current_tier" | "total_tiers"
  | "current_tier_progress"
> & {
  readonly id: number;
  scan_status: number;
  readonly subdomain_count?: number;
  readonly endpoint_count?: number;
  readonly vulnerability_count?: number;
  /** Percentage of finished tasks, 0-100. */
  readonly current_progress?: number;
  /** Seconds between start and stop; `null` while running. */
  readonly completed_time?: number | null;
  /** `null` while running. */
  readonly completed_ago?: string | null;
  /** Names of the target's organizations. */
  readonly organizations?: string[];
  readonly max_severity?: 'critical' | 'high' | 'medium' | 'low' | 'info' | 'unknown' | 'none';
  readonly is_spiderfoot_running?: boolean;
  readonly successful_task_count?: number;
  readonly failed_task_count?: number;
  readonly total_task_count?: number;
  readonly current_tier?: number;
  readonly total_tiers?: number;
  readonly current_tier_progress?: number;
};
/** `/api/scheduledScans/` is backed by `TemporalScheduleSerializer`. */
export type ScheduledScan = components["schemas"]["TemporalSchedule"];
/** `SubScanSerializer` row; `engine` is the engine name. */
export type SubScan = Omit<components["schemas"]["SubScan"], "id"> & { readonly id: number };

/** `GET /api/scan_status/?project=`: the project's active and recent scans and subscans. */
export interface ScanStatusResponse {
  scans: { pending: ScanHistory[]; scanning: ScanHistory[]; completed: ScanHistory[] };
  tasks: { pending: SubScan[]; running: SubScan[]; completed: SubScan[] };
}
export type Command = components["schemas"]["Command"];
export type { Vulnerability } from '../../vulnerabilities/types';
export type Subdomain = components["schemas"]["Subdomain"];
export type { Domain } from '../../targets/types';

/** Row of `GET /api/listDirectories/` with `subdomain_id` (`EndPointDirectorySerializer`). */
export type { DirectoryFile } from '../../subdomains/types';

/** Row of `GET /api/listDirectories/` without `subdomain_id`: a subdomain that has endpoints. */
export interface DirectorySubdomainSummary {
  id: number;
  name: string;
  directory_count: number;
}

/** Row of `most_common_vulnerability`: `values('name', 'severity').annotate(count=...)`. */
export interface MostCommonVulnerabilityCount {
  name: string;
  severity: number;
  count: number;
}

/** Row of `most_common_tags` / `most_common_cve` / `most_common_cwe`: `values('name', 'nused')`. */
export interface NamedUsageCount {
  name: string;
  nused: number;
}

export interface AssetCountryCount {
  name: string;
  iso: string;
  count: number;
}

export interface HttpStatusCount {
  http_status: number;
  count: number;
}

export interface MatchedGfCount {
  matched_gf_patterns: string;
  count: number;
}

export interface DiscoveredPort {
  number: number;
  service_name: string | null;
  is_uncommon: boolean;
  count: number;
}

export interface DiscoveredTechnology {
  name: string;
  count: number;
}

/** `TacticalScanHistorySerializer` row plus the per-scan fields the summary views add. */
export interface RecentScan {
  id: number;
  start_scan_date: string;
  stop_scan_date: string | null;
  scan_status: number;
  highest_severity: 'critical' | 'high' | 'medium' | 'low' | 'info' | 'unknown' | 'none';
  completed_ago: string;
  subdomain_count: number;
  engine_name: string;
  subdomain_diff: number;
}

export interface DomainInfoDnsRecord {
  type: string;
  /** The record value (an A/MX/TXT record); `DNSRecord` has no separate value column. */
  name: string;
}

export interface DomainInfoHistoricalIp {
  ip: string;
  location: string;
  owner: string;
  last_seen: string;
}

/** A WHOIS contact (`DomainRegistration`); `null` when the lookup had none. */
export interface WhoisContact {
  name: string | null;
  organization: string | null;
  email: string | null;
  phone: string | null;
  fax: string | null;
  address: string | null;
  city: string | null;
  state: string | null;
  zip_code: string | null;
  country: string | null;
}

/** `domain_info.whois`, read by the WHOIS tab (`api/summary_domain_info.py`). */
export interface DomainWhoisSummary {
  statuses: string[];
  registrant: WhoisContact | null;
  admin: WhoisContact | null;
  tech: WhoisContact | null;
  /** `DomainInfo.whois_raw`: jswhois / whoisdomain JSON, shape depends on the tool. */
  raw: Record<string, unknown> | null;
}

/** `domain_info` block of the scan and target summary views (`api/summary_domain_info.py`). */
export interface DomainInfoSummary {
  dnssec: boolean;
  geolocation_iso: string | null;
  created: string | null;
  updated: string | null;
  expires: string | null;
  whois_server: string | null;
  registrar: { name: string | null; phone: string | null; email: string | null; url: string | null };
  dns_records: DomainInfoDnsRecord[];
  name_servers: { name: string }[];
  nameservers: string[];
  historical_ips: DomainInfoHistoricalIp[];
  whois: DomainWhoisSummary;
}

/** Known keys of `MonitoringDiscovery.content`, a JSONField written by `reNgine/tasks/monitor.py`. */
export interface MonitoringDiscoveryContent {
  name?: string;
  url?: string;
  source?: string;
  status?: number;
  title?: string;
}

export type MonitoringDiscoveryEntry = Omit<components["schemas"]["MonitoringDiscovery"], "content"> & {
  content: MonitoringDiscoveryContent;
};

/** `monitoring_discoveries`: `values('id', 'discovery_type', 'content')`. */
export type MonitoringDiscoverySummary = Pick<MonitoringDiscoveryEntry, "discovery_type" | "content"> & { id: number };

/** Fields both vulnerability rows of the scan summary carry; `severity` is the model's -1..4. */
export interface SummaryVulnerabilityBase {
  id: number;
  name: string;
  severity: number;
  http_url: string | null;
  description: string | null;
  impact: string | null;
  remediation: string | null;
  is_gpt_used: boolean;
}

/** `vulnerability_highlights`: the ten most severe, newest first. */
export interface SummaryVulnerabilityHighlight extends SummaryVulnerabilityBase {
  discovered_date: string | null;
}

/** `vulnerabilities`: up to 100 rows, most severe first. */
export interface SummaryVulnerability extends SummaryVulnerabilityBase {
  /** `discovered_date` under another name. */
  matched_at: string | null;
  /** The subdomain name, else the target name. */
  domain_name: string;
}

export interface SummaryEndpoint {
  id: number;
  http_url: string;
  http_status: number | null;
  content_type: string | null;
  techs__name: string | null;
}

export interface SummaryEmail {
  id: number;
  address: string | null;
  password: string | null;
  source: string;
  metadata: Record<string, unknown>;
  breach_count: number;
}

export interface SummaryEmployee {
  id: number;
  name: string | null;
  designation: string | null;
  metadata: Record<string, unknown>;
}

/** `EmailBreachSerializer` row; `compromised_data` is the JSON list of HIBP data classes. */
export type EmailBreach = Omit<components["schemas"]["EmailBreach"], "compromised_data"> & {
  compromised_data?: string[];
};

export interface Dork {
  id: number;
  type: string | null;
  url: string | null;
}

/** `MetafinderDocumentSerializer` (depth=1); the nested foreign keys are not read by the UI. */
export interface MetafinderDocument {
  id: number;
  doc_name: string | null;
  url: string | null;
  title: string | null;
  author: string | null;
  producer: string | null;
  creator: string | null;
  os: string | null;
  http_status: number | null;
  creation_date: string | null;
  modified_date: string | null;
  scan_history: Record<string, unknown> | null;
  target_domain: Record<string, unknown> | null;
  subdomain: Record<string, unknown> | null;
}

/** `S3BucketSerializer`; the `perm_*` fields are S3Scanner's 0/1 ACL flags. */
export interface S3Bucket {
  id: number;
  name: string | null;
  region: string | null;
  provider: string | null;
  owner_id: string | null;
  owner_display_name: string | null;
  perm_auth_users_read: number;
  perm_auth_users_write: number;
  perm_auth_users_read_acl: number;
  perm_auth_users_write_acl: number;
  perm_auth_users_full_control: number;
  perm_all_users_read: number;
  perm_all_users_write: number;
  perm_all_users_read_acl: number;
  perm_all_users_write_acl: number;
  perm_all_users_full_control: number;
  num_objects: number;
  size: number;
}

export interface TodoNote {
  id: number;
  title: string;
  description: string;
  is_done: boolean;
  is_important: boolean;
}

export interface ScanActivity {
  id: number | string;
  task_uid: string | null;
  title: string;
  name: string;
  status: 'SUCCESS' | 'RUNNING' | 'FAILED' | 'ABORTED' | 'PENDING' | 'UNKNOWN';
  time: string;
  time_started: string | null;
  time_ended: string | null;
  tier: number | null;
  has_commands: boolean;
  error_message?: string | null;
  target_host?: string;
  traceback?: string | null;
  execution_id?: string | null;
  /** Slug from `classify_failure()`; only set for FAILED/ABORTED rows. */
  failure_category?: string | null;
  /** Fixed, role-safe sentence that goes with `failure_category`. */
  failure_hint?: string | null;
}

/** One row the tier-retry endpoint could not queue, and why. */
export interface ScanTierRetrySkip {
  activity_id: number;
  name: string;
  title: string;
  reason: string;
  message: string;
}

export interface ScanTierRetryQueued {
  activity_id: number;
  name: string;
  title: string;
  workflow_id: string;
}

/** Response of `POST /api/action/retry/tier/<scan_id>/<tier>/`. */
export interface ScanTierRetryResponse {
  status: boolean;
  no_op: boolean;
  scan_id: number;
  tier: number;
  queued_count: number;
  skipped_count: number;
  queued: ScanTierRetryQueued[];
  skipped: ScanTierRetrySkip[];
  message: string;
}

/** Fields the scan summary and target summary endpoints both return with the same shape. */
export interface SummaryResponseBase {
  subdomain_count: number;
  alive_count: number;
  endpoint_count: number;
  endpoint_alive_count: number;
  critical_count: number;
  high_count: number;
  medium_count: number;
  low_count: number;
  info_count: number;
  unknown_count: number;
  total_vul_ignore_info_count: number;
  vulnerability_count: number;
  most_common_vulnerability: MostCommonVulnerabilityCount[];
  most_common_tags: NamedUsageCount[];
  most_common_cve: NamedUsageCount[];
  most_common_cwe: NamedUsageCount[];
  asset_countries: AssetCountryCount[];
  http_status_breakdown: HttpStatusCount[];
  exposed_count: number;
  email_count: number;
  employees_count: number;
  monitoring_discoveries_list: MonitoringDiscoveryEntry[];
  subscans: SubScan[];
  recent_scans: RecentScan[];
  discovered_ports: DiscoveredPort[];
  discovered_technologies: DiscoveredTechnology[];
  project_info: { name: string; slug: string };
  domain_info: DomainInfoSummary | null;
  related_domains: string[];
  related_tlds: string[];
  scan_count: number;
  this_week_scan_count: number;
  monitoring_discoveries: MonitoringDiscoverySummary[];
}

export interface ScanSummaryResponse extends SummaryResponseBase {
  secret_leaks_count: number;
  exploitable_count: number;
  matched_gf_count: MatchedGfCount[];
  buckets_count: number;
  emails: SummaryEmail[];
  employees: SummaryEmployee[];
  dorks: Dork[];
  documents: MetafinderDocument[];
  buckets: S3Bucket[];
  todo_notes: TodoNote[];
  important_subdomains: Subdomain[];
  target_info: { name: string; id: number };
  vulnerability_highlights: SummaryVulnerabilityHighlight[];
  subdomains: Subdomain[];
  endpoints: SummaryEndpoint[];
  vulnerabilities: SummaryVulnerability[];
  secret_leaks: SecretLeak[];
  scan_info: {
    id: number;
    scan_status: number;
    engine_name: string;
    hardware_profile_id: number | null;
    start_scan_date: string;
    stop_scan_date: string | null;
    duration: number;
    progress: number;
    cfg_starting_point_path: string | null;
    cfg_imported_subdomains: string[];
    cfg_out_of_scope_subdomains: string[];
    cfg_excluded_paths: string[];
    tasks: string[];
    used_gf_patterns: string[];
    is_spiderfoot_running: boolean;
  };
  timeline: ScanActivity[];
}


export interface SecretLeak {
  id: number;
  tool_name: string;
  secret_type: string;
  source_url: string;
  match_content: string;
  status: string;
  scan_history: number;
  subdomain: number | null;
  discovered_date: string;
}

export interface OsintStaging {
  id: number;
  osint_type: string;
  content: string;
  source: string;
  confidence: number;
  metadata: Record<string, unknown>;
  status?: string;
  agent_verified?: boolean | null;
  agent_verified_at?: string | null;
  discovered_date: string;
  discovered_date_humanized: string;
  target_domain_name: string;
  scan_history_id: number;
}

export interface Parameter {
  id: number;
  name: string;
  value: string | null;
  type: string | null;
  confidence: number;
  sources: string[];
  param_location: string | null;
  data_type: string | null;
  is_auth_related: boolean;
  observed_in_js: boolean;
  observed_in_openapi: boolean;
  observed_in_graphql: boolean;
  endpoint: { id: number; http_url: string } | null;
}

export interface ParameterResponse {
  count: number;
  next: string | null;
  previous: string | null;
  results: Parameter[];
}
