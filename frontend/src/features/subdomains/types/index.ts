export interface IPAddress {
  id: number;
  address: string;
  is_cdn: boolean;
  ports: Port[];
}

export interface Port {
  id: number;
  number: number;
  service_name: string;
  description: string;
  is_uncommon: boolean;
}

export interface Waf {
  id: number;
  name: string;
  manufacturer: string | null;
}

export interface DirectoryFile {
  id: number;
  name: string; // base64 encoded
  url: string;
  http_status: number;
  length: number;
  lines: number | null;
  words: number | null;
  content_type: string;
}

export interface DirectoryScan {
  id: number;
  scanned_date: string;
  formatted_date_for_id: string;
  directory_files: DirectoryFile[];
}

export interface Subdomain {
  id: number;
  name: string;
  http_url: string | null;
  http_status: number;
  page_title: string | null;
  content_length: number;
  response_time: number | null;
  screenshot_path: string | null;
  screenshots: Array<{ id: number; screenshot_path: string; url: string; status_code: number | null }>;
  ip_addresses: IPAddress[];
  technologies: { id: number; name: string }[];
  waf: Waf[];
  is_interesting: boolean;
  is_important: boolean;
  cname: string | null;
  endpoint_count: number;
  info_count: number;
  low_count: number;
  medium_count: number;
  high_count: number;
  critical_count: number;
  todos_count: number;
  directories_count: number;
  subscan_count: number;
  vuln_count: number | null;
  discovered_date: string | null;
  directories?: DirectoryScan[];
}

export interface SubdomainResponse {
  count: number;
  next: string | null;
  previous: string | null;
  results: Subdomain[];
}
