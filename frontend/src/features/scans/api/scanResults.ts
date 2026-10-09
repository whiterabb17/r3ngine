import { useQuery } from '@tanstack/react-query';
import axios from '../../../api/axiosConfig';

/** One node of the tree served by `/api/queryAllScanResultVisualise/` (VisualiseDataSerializer). */
export interface ScanVisualisationNode {
  description: string;
  title?: string | null;
  http_status?: number | null;
  children?: ScanVisualisationNode[];
}

export interface ScanVisualisationParams {
  scanId?: number;
  targetId?: number;
}

/** Returns one tree per matching scan; `scanId` wins over `targetId` (latest scan of the target). */
export const fetchScanVisualisation = async ({
  scanId,
  targetId,
}: ScanVisualisationParams): Promise<ScanVisualisationNode[]> => {
  let url = `/api/queryAllScanResultVisualise/?format=json`;
  if (scanId) {
    url += `&scan_id=${scanId}`;
  } else if (targetId) {
    url += `&target_id=${targetId}`;
  }
  const response = await axios.get<ScanVisualisationNode[]>(url);
  return response.data;
};

export const fetchDirectoryFileAuthLogs = async (workflowId: string): Promise<string[]> => {
  const { data } = await axios.get<{ logs?: string[] }>(
    `/api/action/directory-file/auth-logs/?workflow_id=${workflowId}`,
  );
  return data.logs ?? [];
};

export interface ScreenshotEntry {
  id: number | string;
  screenshot_path: string;
  url: string;
  title: string | null;
  status_code: number | null;
}

export interface ScreenshotSubdomain {
  id: number;
  name: string;
  http_url: string | null;
  screenshot_path: string;
  http_status: number | null;
  screenshots: ScreenshotEntry[];
}

export const fetchScanScreenshotSubdomains = async (scanId: number): Promise<ScreenshotSubdomain[]> => {
  const url = new URL(`${window.location.origin}/api/listSubdomains/`);
  url.searchParams.append('scan_id', scanId.toString());
  // Fetch ALL subdomains to ensure we don't miss any due to server-side filter bugs
  url.searchParams.append('no_page', '1');
  url.searchParams.append('format', 'json');

  const response = await fetch(url.toString(), {
    credentials: 'include',
  });

  if (!response.ok) {
    throw new Error('Failed to fetch screenshots');
  }

  const data: unknown = await response.json();
  // SubdomainsViewSet returns the list directly (array) when no_page is set,
  // or as { results: [...] }. Handle both.
  if (Array.isArray(data)) return data;
  const results = (data as { results?: unknown } | null)?.results;
  if (Array.isArray(results)) return results;
  return [];
};

export const useScanScreenshots = (scanId: number) => {
  return useQuery<ScreenshotSubdomain[]>({
    queryKey: ['screenshots', scanId],
    queryFn: () => fetchScanScreenshotSubdomains(scanId),
    enabled: !!scanId,
  });
};
