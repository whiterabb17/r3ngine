export interface ProxySettings {
  use_proxy: boolean;
  proxies: string;
  use_proxychains: boolean;
  use_tor: boolean;
  valid_proxy_count?: number;
}

export interface ProxyTaskStatus {
  task_id: string;
  status: 'PENDING' | 'PROGRESS' | 'SUCCESS' | 'FAILURE';
  result: string | null;
  message?: string;
  progress?: number;
}
