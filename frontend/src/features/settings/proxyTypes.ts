export interface ProxySettings {
  use_proxy: boolean;
  proxies: string;
  use_proxychains: boolean;
  use_tor: boolean;
  /** Hand-entered proxies, tried before the scraped pool and never overwritten by the fetch. */
  priority_proxies?: string;
  use_priority_proxies?: boolean;
  /** Scan direct and engage the pool only once the target is found to block us. */
  proxy_only_after_ban?: boolean;
  valid_proxy_count?: number;
}

export interface ProxyTaskStatus {
  task_id: string;
  status: 'PENDING' | 'PROGRESS' | 'SUCCESS' | 'FAILURE';
  result: string | null;
  message?: string;
  progress?: number;
}
