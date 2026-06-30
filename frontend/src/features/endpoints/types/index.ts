export interface Technology {
  id: number;
  name: string;
}

export interface Parameter {
  name: string;
  value: string;
  type: string;
}

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
  auth_candidates?: any[];
}

export interface EndpointResponse {
  count: number;
  next: string | null;
  previous: string | null;
  results: Endpoint[];
}
