import type { Vulnerability } from '@/features/vulnerabilities/types';

export interface ExposureEvidence {
  id: number;
  exposure: number;
  source_tool: string;
  evidence_data: Record<string, unknown>;
  timestamp: string;
}

export interface Exposure {
  id: number;
  scan_history: number;
  type: string[];
  risk_score: number;
  status: 'open' | 'verified' | 'false_positive' | 'remediated';
  evidence: ExposureEvidence[];
  vulnerabilities: Vulnerability[];
  created_at: string;
  updated_at: string;
}

export interface ExposuresResponse {
  count: number;
  next: string | null;
  previous: string | null;
  results: Exposure[];
}

export interface ExposureQueryParams {
  project?: string;
  target_id?: string;
  scan_history?: string;
  status?: string;
  type?: string;
  page?: number;
  length?: number;
}
