import { useQuery } from '@tanstack/react-query';
import { getCsrfToken } from '../../api/axiosConfig';

export interface DashboardData {
  project_info: {
    name: string;
    slug: string;
  };
  rengine_version: string;
  kpis: {

    domain_count: number;
    subdomain_count: number;
    endpoint_count: number;
    vulnerability_count: number;
    critical_count: number;
    high_count: number;
    medium_count: number;
    low_count: number;
    info_count: number;
    unknown_count: number;
    secret_leak_count: number;
    alive_count: number;
    endpoint_alive_count: number;
    total_vul_count: number;
  };
  trends: {
    targets_in_last_week: number[];
    subdomains_in_last_week: number[];
    endpoints_in_last_week: number[];
    vulns_in_last_week: number[];
    leaks_in_last_week: number[];
    last_7_dates: string[];
  };
  most_used_port: Array<{ number: number; service_name: string; count: number }>;
  most_used_ip: Array<{ address: string; count: number }>;
  most_used_tech: Array<{ name: string; count: number }>;
  most_common_cve: Array<{ name: string; count: number }>;
  most_common_cwe: Array<{ name: string; count: number }>;
  most_common_tags: Array<{ name: string; count: number }>;
  asset_countries: { name: string; iso: string; count: number }[];
  most_vulnerable_targets: {
    name: string;
    vuln_count: number;
    critical_count: number;
    high_count: number;
    medium_count: number;
    low_count: number;
    info_count: number;
    unknown_count: number;
  }[];
  most_common_vulnerabilities: {
    name: string;
    severity: number;
    count: number;
  }[];
  activity_feed: Array<{
    id: number;
    domain: string;
    title: string;
    name: string;
    status: number;
    completed_ago: string;
    time: string;
  }>;
  vulnerability_feed: Array<{
    id: number;
    name: string;
    severity: number;
    http_url: string;
    discovered_date: string;
  }>;
}

export const useDashboardData = (projectSlug: string) => {
  return useQuery<DashboardData>({
    queryKey: ['dashboard', projectSlug],
    queryFn: async () => {
      const response = await fetch(`/api/dashboard/${projectSlug}/`, {
        credentials: 'include'
      });
      if (!response.ok) {
        throw new Error('Network response was not ok');
      }
      return response.json();
    },

    enabled: !!projectSlug,
  });
};

/** LLM-generated CWE summary returned by `GET /api/cwe-info/` (`CWEInfoAPIView`). */
export interface CWEInfo {
  name: string;
  description: string;
  impact: string;
  remediation: string;
  examples: string[];
  severity: string;
}

/** `result` of `GET /api/tools/cve_details/` (`CVEDetails` in `api/views/vulns.py`). */
export interface CveDetails {
  id: string;
  summary: string;
  assigner: string;
  ai_risk_assessment: string | null;
  /** CIRCL's `cvss` when present, otherwise the NVD base score. */
  cvss: number | string | null;
  cvss_v31_base_score: number | null;
  cvss_vector: string;
  attack_vector: string | null;
  attack_complexity: string | null;
  privileges_required: string | null;
  user_interaction: string | null;
  confidentiality_impact: string | null;
  integrity_impact: string | null;
  availability_impact: string | null;
  epss_score: number | null;
  epss_percentile: number | null;
  is_cisa_kev: boolean;
  is_poc: boolean;
  is_template: boolean;
  vulnerability_type: string | null;
  published_date: string | null;
  last_modified_date: string | null;
  references: string[];
}

export type CweInfoResponse =
  | (CWEInfo & { status: true; cwe: string })
  | { status?: false; error?: string };

export type CveDetailsResponse =
  | { status: true; result: CveDetails }
  | { status: false; message?: string };

/** Body of `POST /api/tools/cve_description_generate/` (`GenerateCveDescription`). */
export type CveDescriptionResponse =
  | {
      status: true;
      description: string;
      impact: string;
      remediation: string;
      ai_risk_assessment: string | null;
    }
  | { status: false; message?: string };

/** Resolves with the JSON body regardless of the HTTP status; callers branch on `status`. */
export const fetchCweInfo = async (cweName: string): Promise<CweInfoResponse> => {
  const response = await fetch(`/api/cwe-info/?name=${encodeURIComponent(cweName)}`, {
    credentials: 'include',
  });
  return response.json();
};

/** Resolves with the JSON body regardless of the HTTP status; callers branch on `status`. */
export const fetchCveDetails = async (cveId: string): Promise<CveDetailsResponse> => {
  const response = await fetch(`/api/tools/cve_details/?cve_id=${encodeURIComponent(cveId)}`, {
    credentials: 'include',
  });
  return response.json();
};

/** Asks the configured LLM to (re)write the CVE's description and risk assessment. */
export const generateCveDescription = async (cveId: string): Promise<CveDescriptionResponse> => {
  const response = await fetch('/api/tools/cve_description_generate/', {
    method: 'POST',
    credentials: 'include',
    headers: { 'Content-Type': 'application/json', 'X-CSRFToken': getCsrfToken() ?? '' },
    body: JSON.stringify({ cve_id: cveId }),
  });
  return response.json();
};
