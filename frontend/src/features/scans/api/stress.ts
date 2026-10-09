import axios from '../../../api/axiosConfig';
import type { StressStartPayload } from '../../../types/stressTesting';

/** Body of `POST /api/stress/<scan_id>/report/` (`StressReportGenerationAPI`). */
export interface StressReportRequest {
  report_template: 'stress_modern' | 'stress_cyber_pro';
  include_endpoints: boolean;
  include_timeline: boolean;
}

export type StressReportCreateResponse =
  | { status: true; report_id: number; message: string }
  | { status: false; error?: string };

/** `ScanReport.status`: -1 initiated, 0 failed, 2 success (other values mean in progress). */
export interface StressReportStatus {
  status: number;
  error_message: string | null;
  report_url: string | null;
  completed_at: string | null;
}

export const startStressTest = async (
  scanId: number | string,
  payload: StressStartPayload,
): Promise<void> => {
  await axios.post(`/api/stress/${scanId}/control/`, payload);
};

export const stopStressTest = async (scanId: number | string): Promise<void> => {
  await axios.post(`/api/stress/${scanId}/control/`, { action: 'stop' });
};

export const createStressReport = async (
  scanId: number | string,
  body: StressReportRequest,
): Promise<StressReportCreateResponse> => {
  const response = await axios.post<StressReportCreateResponse>(`/api/stress/${scanId}/report/`, body);
  return response.data;
};

export const fetchStressReportStatus = async (
  scanId: number | string,
  reportId: number,
): Promise<StressReportStatus> => {
  const response = await axios.get<StressReportStatus>(`/api/stress/${scanId}/report/`, {
    params: { report_id: reportId },
  });
  return response.data;
};
