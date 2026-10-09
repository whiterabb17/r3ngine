/** Response of `/scan/create_report/<scan_id>`. */
export interface CreateScanReportResponse {
  status?: boolean;
  report_id?: number;
}

/** Response of `/scan/report/status/<report_id>`; `status` is 0 = failed, 2 = success, anything else = pending. */
export interface ScanReportStatusResponse {
  status: number;
  report_url: string | null;
  error_message: string | null;
}

/** Starts report generation; `params` is the report option query string built by the caller. */
export const createScanReport = async (
  scanId: number,
  params: URLSearchParams,
): Promise<CreateScanReportResponse> => {
  const response = await fetch(`/scan/create_report/${scanId}?${params.toString()}`, {
    credentials: 'include',
  });
  if (!response.ok) throw new Error('Failed to initiate report');
  return response.json();
};

export const fetchScanReportStatus = async (reportId: number): Promise<ScanReportStatusResponse> => {
  const response = await fetch(`/scan/report/status/${reportId}`, {
    credentials: 'include',
  });
  if (!response.ok) throw new Error('Failed to check status');
  return response.json();
};
