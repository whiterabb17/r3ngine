import type { components } from '@/types/api';

export interface Technology {
  id: number;
  name: string;
}

export interface Parameter {
  name: string;
  value: string;
  type: string;
}

/**
 * `AuthCandidateSerializer` row. `metadata` is a JSON column (drf-yasg types it as an empty
 * object); `extract_auth` stores the login form it parsed there.
 */
export type AuthCandidate = Omit<components["schemas"]["AuthCandidate"], "metadata"> & {
  metadata?: {
    method?: string;
    user_field?: string;
    pass_field?: string;
    all_fields?: string[];
  } & Record<string, unknown>;
};

export interface Endpoint {
  id: number;
  http_url: string;
  http_status: number;
  page_title: string;
  matched_gf_patterns: string;
  content_type: string;
  content_length: number;
  response_time: number;
  webserver: string;
  techs: Technology[];
  parameters: Parameter[];
  discovered_date: string;
  auth_candidates?: AuthCandidate[];
}

export interface EndpointResponse {
  count: number;
  next: string | null;
  previous: string | null;
  results: Endpoint[];
}
