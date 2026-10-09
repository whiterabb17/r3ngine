import type { LocustDashboardProps, StressorDashboardProps } from '../components/scan/StressTab/ToolComponents';

/** Per-tool settings persisted to localStorage and sent as `<tool>_config` on start. */
export type StressToolConfigs = {
  k6: {
    vus: number;
    duration: string;
    attack_type: string;
    rps: string;
    insecure_skip_tls: boolean;
    no_connection_reuse: boolean;
    http_debug: string;
  };
  wrk: {
    threads: string;
    connections: number;
    duration: string;
    latency: boolean;
    timeout: string;
    headers: string[];
  };
  hping3: {
    attack_mode: string;
    port: string;
    rate: string;
    data_size: string;
  };
  locust: {
    users: number;
    spawn_rate: number;
    run_time: string;
    loglevel: string;
  };
  stressor: {
    method: string;
    threads: number;
    duration: string;
    rpc: string;
    proxy_type: string;
    proxy_file: string;
    port: string;
  };
};

export type StressToolConfig = StressToolConfigs[keyof StressToolConfigs];

/** Global run settings persisted to localStorage. */
export interface StressRunConfig {
  concurrency: number;
  duration: string;
  uses_tools: string[];
}

/** Body of `POST /api/stress/<scan_id>/control/` with `action: 'start'`. */
export interface StressStartPayload {
  action: 'start';
  config: {
    concurrency: number;
    duration: string;
    uses_tools: string[];
    selected_endpoints: string[];
    [toolConfigKey: `${string}_config`]: StressToolConfig;
  };
}

/** Row of Locust's aggregated statistics table (`LocustParser` in `reNgine/parsers.py`). */
export interface LocustStatsRow {
  method: string;
  name: string;
  reqs: number;
  fails: number;
  error_rate: number;
  avg: number;
  min: number;
  max: number;
  med: number;
  req_s: number;
  fail_s: number;
}

/** Row of Locust's response-time percentile table. */
export interface LocustPercentileRow {
  method: string;
  name: string;
  p50: number;
  p66: number;
  p75: number;
  p80: number;
  p90: number;
  p95: number;
  p98: number;
  p99: number;
  p999: number;
  p9999: number;
  p100: number;
  reqs: number;
}

/** Latest value of each tool metric found in the active tool's telemetry, plus derived stats. */
export interface AggregatedStressMetrics {
  avg_latency: number;
  throughput_rps: number;
  error_rate: number;
  response_codes: Record<string, number>;
  error_breakdown: Record<string, number>;
  total_requests?: number;
  failed_requests?: number;
  throughput_bps?: number;
  min_latency?: number;
  max_latency?: number;
  latency_stdev?: number;
  p50_latency?: number;
  p90_latency?: number;
  p95_latency?: number;
  p99_latency?: number;
  packet_loss?: number;
  total_users?: number;
  endpoint_count?: number;
  socket_errors?: number;
  timeout_errors?: number;
  attack_mode?: StressorDashboardProps['attackMode'];
  pps_peak?: number;
  bps_peak?: number;
  rps_peak?: number;
  response_rate?: number;
  block_rate?: number;
  main_table?: LocustStatsRow[];
  percentile_table?: LocustPercentileRow[];
  percentiles?: LocustDashboardProps['percentiles'];
  packets_sent?: number;
  packets_received?: number;
  rtt_min?: number;
  rtt_avg?: number;
  rtt_max?: number;
}

/** Per-endpoint aggregate row plotted by the endpoint-level stress charts and table. */
export interface EndpointStressMetrics {
  endpoint: string;
  timestamp: number;
  concurrent_users: number;
  total_requests: number;
  avg_latency: number;
  p95_latency: number;
  p99_latency: number;
  /** Fraction of failed requests, 0-1. */
  error_rate: number;
  throughput_rps: number;
}
