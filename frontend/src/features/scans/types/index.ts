import type { components } from '@/types/api';

export type ScanHistory = Omit<components["schemas"]["ScanHistory"], "scan_status"> & {
  scan_status?: number;
  is_spiderfoot_running?: boolean;
  successful_task_count?: number;
  failed_task_count?: number;
  total_task_count?: number;
  current_tier?: number;
  total_tiers?: number;
  current_tier_progress?: number;
};
export type ScheduledScan = components["schemas"]["PeriodicTask"];
export type SubScan = components["schemas"]["SubScan"];
export type Command = components["schemas"]["Command"];
export type Vulnerability = components["schemas"]["Vulnerability"];
export type Subdomain = components["schemas"]["Subdomain"];
export type Domain = components["schemas"]["Domain"];

export type DirectoryFile = components["schemas"]["DirectoryFile"];

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
}

export interface ScanSummaryResponse {
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
  most_common_vulnerability: any[];
  most_common_tags: any[];
  most_common_cve: any[];
  most_common_cwe: any[];
  asset_countries: any[];
  http_status_breakdown: any[];
  exposed_count: number;
  secret_leaks_count: number;
  exploitable_count: number;
  matched_gf_count: any[];
  buckets_count: number;
  email_count: number;
  employees_count: number;
  emails: any[];
  employees: any[];
  dorks: any[];
  documents: any[];
  buckets: any[];
  todo_notes: TodoNote[];
  monitoring_discoveries_list: any[];
  subscans: SubScan[];
  recent_scans: any[];
  important_subdomains: Subdomain[];
  discovered_ports: any[];
  discovered_technologies: any[];
  project_info: { name: string; slug: string };
  target_info: { name: string; id: number };
  domain_info: any;
  related_domains: string[];
  related_tlds: string[];
  scan_count: number;
  this_week_scan_count: number;
  vulnerability_highlights: Vulnerability[];
  subdomains: Subdomain[];
  endpoints: any[];
  vulnerabilities: Vulnerability[];
  monitoring_discoveries: any[];
  secret_leaks: SecretLeak[];
  scan_info: {
    id: number;
    scan_status: number;
    engine_name: string;
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
