export interface SearchResultSubdomain {
  name: string;
  http_url?: string;
  http_status: number;
  page_title?: string;
  cname?: string;
}

export interface SearchResultEndpoint {
  http_url: string;
  http_status: number;
  page_title?: string;
}

export interface SearchResultVulnerability {
  name: string;
  severity: number;
  http_url?: string;
  description?: string;
}

export interface SearchResponse {
  status: boolean;
  results: {
    subdomains: SearchResultSubdomain[];
    endpoints: SearchResultEndpoint[];
    vulnerabilities: SearchResultVulnerability[];
    /** Reserved by `SearchView`; always `{}` today. */
    others: Record<string, unknown>;
  };
}

export interface SearchHistoryItem {
  query: string;
  timestamp: string;
}
