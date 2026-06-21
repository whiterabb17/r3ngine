import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query';
import type { operations, components } from '@/types/api';
import type { ScanHistory, ScheduledScan, SubScan, Command, ScanSummaryResponse, SecretLeak, DirectoryFile } from '../types';
import type { Domain } from '../../targets/types';

export const useDirectories = (params: { scan_id?: string | number, subdomain_id?: string | number, page?: number }) => {
  return useQuery<{ count: number, next: string | null, previous: string | null, results: DirectoryFile[] }>({
    queryKey: ['directories', params],
    queryFn: async () => {
      const searchParams = new URLSearchParams();
      if (params.scan_id) searchParams.append('scan_history', params.scan_id.toString());
      if (params.subdomain_id) searchParams.append('subdomain_id', params.subdomain_id.toString());
      if (params.page) searchParams.append('page', params.page.toString());
      
      const response = await fetch(`/api/listDirectories/?${searchParams.toString()}&format=json`, {
        credentials: 'include'
      });
      if (!response.ok) {
        throw new Error('Network response was not ok');
      }
      return await response.json();
    },
    enabled: !!(params.scan_id || params.subdomain_id),
  });
};

export const useDomains = (projectSlug: string) => {
  return useQuery<Domain[]>({
    queryKey: ['domains', projectSlug],
    queryFn: async () => {
      const response = await fetch(`/api/listTargets/?slug=${projectSlug}`, {
        credentials: 'include'
      });
      if (!response.ok) {
        throw new Error('Network response was not ok');
      }
      const data = await response.json() as operations["api_listTargets_list"]["responses"]["200"]["content"]["application/json"];
      return data.results || [];
    },
    enabled: !!projectSlug,
  });
};


export const useScans = (projectSlug: string) => {
  return useQuery<ScanHistory[]>({
    queryKey: ['scans', projectSlug],
    queryFn: async () => {
      const response = await fetch(`/api/listScanHistory/?project=${projectSlug}`, {
        credentials: 'include'
      });
      if (!response.ok) {
        throw new Error('Network response was not ok');
      }
      const data = await response.json() as { results?: ScanHistory[] };
      return (data.results || []) as ScanHistory[];
    },
    enabled: !!projectSlug,
    refetchInterval: 5000,
  });
};


export const useInitiateScan = (projectSlug: string) => {
  const queryClient = useQueryClient();

  return useMutation({
    mutationFn: async (params: {
      domain_id: number | number[];
      engine_id: number;
      hardware_profile_id?: number;
      importSubdomainTextArea?: string[];
      outOfScopeSubdomainTextarea?: string[];
      startingPointPath?: string;
      excludedPaths?: string | string[];
      customDorkSwitch?: boolean;
      customDorkTextarea?: string;
      api_discovery_tools?: string[];
      kr_wordlist?: string;
      spiderfoot_scan?: boolean;
      selected_plugins?: string[];
    }) => {
      const response = await fetch('/api/action/initiate/scan/', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'X-CSRFToken': document.cookie.split('; ').find(row => row.startsWith('csrftoken='))?.split('=')[1] || '',
        },
        credentials: 'include',
        body: JSON.stringify(params),
      });

      if (!response.ok) {
        const errorData = await response.json();
        throw new Error(errorData.message || 'Failed to initiate scan');
      }

      return response.json();
    },
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['scans', projectSlug] });
    },
  });
};

export const useScheduledScans = () => {
  return useQuery<ScheduledScan[]>({
    queryKey: ['scheduled-scans'],
    queryFn: async () => {
      const response = await fetch('/api/scheduledScans/', {
        credentials: 'include'
      });
      if (!response.ok) {
        throw new Error('Network response was not ok');
      }
      const data = await response.json();
      return Array.isArray(data) ? data : data.results || [];
    },
  });
};

export const useToggleScheduledScan = () => {
  const queryClient = useQueryClient();
  return useMutation({
    mutationFn: async (id: number) => {
      const response = await fetch(`/api/scheduledScans/${id}/toggle/`, {
        method: 'POST',
        headers: {
          'X-CSRFToken': document.cookie.split('; ').find(row => row.startsWith('csrftoken='))?.split('=')[1] || '',
        },
        credentials: 'include',
      });
      return response.json();
    },
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['scheduled-scans'] });
    },
  });
};

export const useBulkDeleteScheduledScans = () => {
  const queryClient = useQueryClient();
  return useMutation({
    mutationFn: async (ids: number[]) => {
      const response = await fetch('/api/scheduledScans/bulk_delete/', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'X-CSRFToken': document.cookie.split('; ').find(row => row.startsWith('csrftoken='))?.split('=')[1] || '',
        },
        credentials: 'include',
        body: JSON.stringify({ ids }),
      });
      return response.json();
    },
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['scheduled-scans'] });
    },
  });
};

export const useSubScans = (projectSlug: string) => {
  return useQuery<SubScan[]>({
    queryKey: ['subscans', projectSlug],
    queryFn: async () => {
      const response = await fetch(`/api/subscans/?project=${projectSlug}`, {
        credentials: 'include'
      });
      if (!response.ok) {
        throw new Error('Network response was not ok');
      }
      const data = await response.json();
      return Array.isArray(data) ? data : data.results || [];
    },
    enabled: !!projectSlug,
    refetchInterval: 5000,
  });
};

export const useBulkStopSubScans = (projectSlug: string) => {
  const queryClient = useQueryClient();
  return useMutation({
    mutationFn: async (ids: number[]) => {
      const response = await fetch('/api/action/stop/scan/', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'X-CSRFToken': document.cookie.split('; ').find(row => row.startsWith('csrftoken='))?.split('=')[1] || '',
        },
        credentials: 'include',
        body: JSON.stringify({ subscan_ids: ids }),
      });
      return response.json();
    },
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['subscans', projectSlug] });
    },
  });
};

export const useBulkDeleteSubScans = (projectSlug: string) => {
  const queryClient = useQueryClient();
  return useMutation({
    mutationFn: async (ids: number[]) => {
      const response = await fetch('/api/subscans/bulk_delete/', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'X-CSRFToken': document.cookie.split('; ').find(row => row.startsWith('csrftoken='))?.split('=')[1] || '',
        },
        credentials: 'include',
        body: JSON.stringify({ ids }),
      });
      return response.json();
    },
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['subscans', projectSlug] });
    },
  });
};

export const useScansHistory = (project: string) => {
  return useQuery<ScanHistory[]>({
    queryKey: ['scans-history', project],
    queryFn: async () => {
      const response = await fetch(`/api/listScans/?project=${project}`, {
        credentials: 'include'
      });
      if (!response.ok) {
        throw new Error('Network response was not ok');
      }
      const data = await response.json() as operations["api_listScans_list"]["responses"]["200"]["content"]["application/json"];
      return (data.results || []) as ScanHistory[];
    },
    enabled: !!project,
    refetchInterval: 5000,
  });
};


export const useStopScan = (projectSlug: string) => {
  const queryClient = useQueryClient();
  return useMutation({
    mutationFn: async (id: number) => {
      const response = await fetch('/api/action/stop/scan/', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'X-CSRFToken': document.cookie.split('; ').find(row => row.startsWith('csrftoken='))?.split('=')[1] || '',
        },
        credentials: 'include',
        body: JSON.stringify({ scan_ids: [id] }),
      });
      return response.json();
    },
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['scans-history', projectSlug] });
      queryClient.invalidateQueries({ queryKey: ['scan-summary'] });
      queryClient.invalidateQueries({ queryKey: ['scan-status', projectSlug] });
      queryClient.invalidateQueries({ queryKey: ['domains', projectSlug] });
    },
  });
};

export const useResumeScan = (projectSlug: string) => {
  const queryClient = useQueryClient();
  return useMutation({
    mutationFn: async (id: number) => {
      const response = await fetch('/api/action/resume/scan/', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'X-CSRFToken': document.cookie.split('; ').find(row => row.startsWith('csrftoken='))?.split('=')[1] || '',
        },
        credentials: 'include',
        body: JSON.stringify({ scan_id: id }),
      });
      return response.json();
    },
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['scans-history', projectSlug] });
      queryClient.invalidateQueries({ queryKey: ['scan-status', projectSlug] });
    },
  });
};

export const useDeleteScan = (projectSlug: string) => {
  const queryClient = useQueryClient();
  return useMutation({
    mutationFn: async (id: number) => {
      const response = await fetch(`/api/listScans/${id}/delete_scan/`, {
        method: 'POST',
        headers: {
          'X-CSRFToken': document.cookie.split('; ').find(row => row.startsWith('csrftoken='))?.split('=')[1] || '',
        },
        credentials: 'include',
      });
      return response.json();
    },
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['scans-history', projectSlug] });
    },
  });
};

export const useBulkScanAction = (projectSlug: string) => {
  const queryClient = useQueryClient();
  return useMutation({
    mutationFn: async ({ action, ids }: { action: 'bulk_stop' | 'bulk_delete', ids: number[] }) => {
      const url = action === 'bulk_stop' ? '/api/action/stop/scan/' : `/api/listScans/${action}/`;
      const body = action === 'bulk_stop' ? { scan_ids: ids } : { ids };

      const response = await fetch(url, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'X-CSRFToken': document.cookie.split('; ').find(row => row.startsWith('csrftoken='))?.split('=')[1] || '',
        },
        credentials: 'include',
        body: JSON.stringify(body),
      });
      return response.json();
    },
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['scans-history', projectSlug] });
    },
  });
};

export const useScanSummary = (projectSlug: string, scanId: number) => {
  return useQuery<ScanSummaryResponse>({
    queryKey: ['scan-summary', projectSlug, scanId],
    queryFn: async () => {
      const response = await fetch(`/api/scan-summary/${projectSlug}/${scanId}/`, {
        credentials: 'include'
      });
      if (!response.ok) {
        throw new Error('Network response was not ok');
      }
      return response.json();
    },
    enabled: !!projectSlug && !!scanId,
    refetchInterval: (query) => {
      const data = query.state.data;
      if (data && data.scan_info && data.scan_info.scan_status === 2 && !data.scan_info.is_spiderfoot_running) return false;
      return 5000;
    }
  });
};

export const useDownloadAiExport = (projectSlug: string, scanId: number) => {
  return useMutation({
    mutationFn: async (options: {
      preset: 'analyst_assist';
      include_raw_outputs: boolean;
      include_timeline: boolean;
      include_sidecars: boolean;
    }) => {
      const response = await fetch(`/api/scan-summary/${projectSlug}/${scanId}/export-ai/`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'X-CSRFToken': document.cookie.split('; ').find(row => row.startsWith('csrftoken='))?.split('=')[1] || '',
        },
        credentials: 'include',
        body: JSON.stringify(options),
      });

      if (!response.ok) {
        let message = 'Failed to export AI bundle';
        try {
          const errorData = await response.json();
          message = errorData.error || message;
        } catch {
          // ignore JSON parse failure
        }
        throw new Error(message);
      }

      const blob = await response.blob();
      const disposition = response.headers.get('Content-Disposition') || '';
      const match = disposition.match(/filename="?([^"]+)"?/);
      const filename = match?.[1] || `ai_bundle_scan_${scanId}.zip`;

      const url = window.URL.createObjectURL(blob);
      const anchor = document.createElement('a');
      anchor.href = url;
      anchor.download = filename;
      document.body.appendChild(anchor);
      anchor.click();
      anchor.remove();
      window.URL.revokeObjectURL(url);

      return { filename };
    },
  });
};

export const useSecretLeaks = (projectSlug: string, scanId: number) => {
  return useQuery<SecretLeak[]>({
    queryKey: ['secret-leaks', projectSlug, scanId],
    queryFn: async () => {
      const response = await fetch(`/api/scan-summary/${projectSlug}/${scanId}/`, {
        credentials: 'include'
      });
      if (!response.ok) {
        throw new Error('Network response was not ok');
      }
      const data = await response.json() as ScanSummaryResponse;
      return data.secret_leaks || [];
    },
    enabled: !!projectSlug && !!scanId,
  });
};

export const useScanStatus = (projectSlug: string) => {
  return useQuery({
    queryKey: ['scan-status', projectSlug],
    queryFn: async () => {
      const response = await fetch(`/api/scan_status/?project=${projectSlug}`, {
        credentials: 'include'
      });
      if (!response.ok) {
        throw new Error('Network response was not ok');
      }
      return response.json();
    },
    enabled: !!projectSlug,
    refetchInterval: 10000, // Poll every 10 seconds
  });
};

export const useStopScanAction = (projectSlug: string) => {
  const queryClient = useQueryClient();
  return useMutation({
    mutationFn: async (id: number) => {
      const response = await fetch(`/api/action/stop/scan/?scan_id=${id}`, {
        method: 'POST',
        headers: {
          'X-CSRFToken': document.cookie.split('; ').find(row => row.startsWith('csrftoken='))?.split('=')[1] || '',
        },
        credentials: 'include',
      });
      return response.json();
    },
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['scan-status', projectSlug] });
    }
  });
};

export const useResumeScanAction = (projectSlug: string) => {
  const queryClient = useQueryClient();
  return useMutation({
    mutationFn: async (id: number) => {
      const response = await fetch(`/api/action/resume/scan/`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'X-CSRFToken': document.cookie.split('; ').find(row => row.startsWith('csrftoken='))?.split('=')[1] || '',
        },
        credentials: 'include',
        body: JSON.stringify({ scan_id: id }),
      });
      return response.json();
    },
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['scan-status', projectSlug] });
    }
  });
};
export const useDeleteScanAction = (projectSlug: string) => {
  const queryClient = useQueryClient();
  return useMutation({
    mutationFn: async (id: number) => {
      const response = await fetch(`/api/action/rows/delete/`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'X-CSRFToken': document.cookie.split('; ').find(row => row.startsWith('csrftoken='))?.split('=')[1] || '',
        },
        credentials: 'include',
        body: JSON.stringify({
          rows: [id],
          model: 'ScanHistory'
        })
      });
      return response.json();
    },
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['scan-status', projectSlug] });
    }
  });
};

export const useActivityLogs = (activityId: number | null) => {
  return useQuery({
    queryKey: ['activity-logs', activityId],
    queryFn: async () => {
      const response = await fetch(`/api/listActivityLogs/?activity_id=${activityId}`, {
        credentials: 'include'
      });
      if (!response.ok) {
        throw new Error('Network response was not ok');
      }
      const data = await response.json();
      return Array.isArray(data) ? data : data.results || [];
    },
    enabled: !!activityId,
    refetchInterval: 5000, // Poll every 5 seconds for real-time logs
  });
};

export const useStressTelemetry = (scanId: number | string | undefined) => {
  return useQuery({
    queryKey: ['stress-telemetry', scanId],
    queryFn: async () => {
      if (!scanId) return [];
      const response = await fetch(`/api/stress-testing/${scanId}/`, {
        credentials: 'include'
      });
      if (!response.ok) {
        throw new Error('Network response was not ok');
      }
      const data = await response.json();
      return Array.isArray(data.results) ? data.results : [];
    },
    enabled: !!scanId,
    refetchInterval: 15000, // Refresh every 15s during test runs
  });
};
export const useFetchWhois = (projectSlug: string, scanId: number) => {
  const queryClient = useQueryClient();
  return useMutation({
    mutationFn: async (target: string) => {
      const response = await fetch(`/api/tools/whois/?target=${target}&is_reload=true`, {
        credentials: 'include',
      });
      if (!response.ok) {
        throw new Error('Failed to fetch WHOIS data');
      }
      return response.json();
    },
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['scan-summary', projectSlug, scanId] });
    },
  });
};

export const useScanLogs = (activityId: number | null, scanId: number | null) => {
  return useQuery<Command[]>({
    queryKey: ['scan-logs', activityId, scanId],
    queryFn: async () => {
      const endpoint = activityId
        ? `/api/listActivityLogs/?activity_id=${activityId}`
        : `/api/listScanLogs/?scan_id=${scanId}`;
      const response = await fetch(endpoint, {
        credentials: 'include'
      });
      if (!response.ok) {
        throw new Error('Network response was not ok');
      }
      const data = await response.json();
      return Array.isArray(data) ? data : (data.results || []) as Command[];
    },
    enabled: !!activityId || !!scanId,
  });
};

export const useOsintStaging = (params: { scan_id?: number | string, search?: string, osint_type?: string, page?: number }) => {
  return useQuery({
    queryKey: ['osint-staging', params],
    queryFn: async () => {
      const searchParams = new URLSearchParams();
      if (params.scan_id) searchParams.append('scan_id', params.scan_id.toString());
      if (params.search) searchParams.append('search', params.search);
      if (params.osint_type) searchParams.append('osint_type', params.osint_type);
      if (params.page) searchParams.append('page', params.page.toString());
      
      const response = await fetch(`/api/osintStaging/?${searchParams.toString()}`, {
        credentials: 'include'
      });
      if (!response.ok) {
        throw new Error('Network response was not ok');
      }
      const data = await response.json();
      return {
        results: data.results || [],
        count: data.count || 0
      };
    },
    enabled: !!params.scan_id,
  });
};


export const useBulkDiscardOsint = () => {
  const queryClient = useQueryClient();
  return useMutation({
    mutationFn: async (ids: number[]) => {
      const response = await fetch('/api/osintStaging/bulk_discard/', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'X-CSRFToken': document.cookie.split('; ').find(row => row.startsWith('csrftoken='))?.split('=')[1] || '',
        },
        credentials: 'include',
        body: JSON.stringify({ ids }),
      });
      return response.json();
    },
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['osint-staging'] });
    },
  });
};

export const useBulkPromoteOsint = () => {
  const queryClient = useQueryClient();
  return useMutation({
    mutationFn: async (ids: number[]) => {
      const response = await fetch('/api/osintStaging/bulk_promote/', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'X-CSRFToken': document.cookie.split('; ').find(row => row.startsWith('csrftoken='))?.split('=')[1] || '',
        },
        credentials: 'include',
        body: JSON.stringify({ ids }),
      });
      return response.json();
    },
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['osint-staging'] });
      queryClient.invalidateQueries({ queryKey: ['emails'] });
      queryClient.invalidateQueries({ queryKey: ['subdomains'] });
      queryClient.invalidateQueries({ queryKey: ['employees'] });
    },
  });
};

export const usePromoteOsint = (id: number) => {
  const queryClient = useQueryClient();
  return useMutation({
    mutationFn: async () => {
      const response = await fetch(`/api/osintStaging/${id}/promote/`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'X-CSRFToken': document.cookie.split('; ').find(row => row.startsWith('csrftoken='))?.split('=')[1] || '',
        },
        credentials: 'include',
      });
      return response.json();
    },
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['osint-staging'] });
      queryClient.invalidateQueries({ queryKey: ['emails'] });
      queryClient.invalidateQueries({ queryKey: ['subdomains'] });
      queryClient.invalidateQueries({ queryKey: ['employees'] });
    },
  });
};
export const useParameters = (params: {
  scan_id?: string | number;
  target_id?: string | number;
  page?: number;
  search?: string;
  param_location?: string;
  is_auth_related?: boolean;
  observed_in_js?: boolean;
  observed_in_openapi?: boolean;
  observed_in_graphql?: boolean;
  confidence_min?: number;
  data_type?: string;
}) => {
  return useQuery<import('../types').ParameterResponse>({
    queryKey: ['parameters', params],
    queryFn: async () => {
      const searchParams = new URLSearchParams();
      if (params.scan_id) searchParams.append('scan_history', params.scan_id.toString());
      if (params.target_id) searchParams.append('target_id', params.target_id.toString());
      if (params.page) searchParams.append('page', params.page.toString());
      if (params.search) searchParams.append('search', params.search);
      if (params.param_location) searchParams.append('param_location', params.param_location);
      if (params.is_auth_related !== undefined) searchParams.append('is_auth_related', String(params.is_auth_related));
      if (params.observed_in_js !== undefined) searchParams.append('observed_in_js', String(params.observed_in_js));
      if (params.observed_in_openapi !== undefined) searchParams.append('observed_in_openapi', String(params.observed_in_openapi));
      if (params.observed_in_graphql !== undefined) searchParams.append('observed_in_graphql', String(params.observed_in_graphql));
      if (params.confidence_min !== undefined) searchParams.append('confidence_min', String(params.confidence_min));
      if (params.data_type) searchParams.append('data_type', params.data_type);

      const response = await fetch('/api/listParameters/?' + searchParams.toString(), {
        credentials: 'include'
      });
      if (!response.ok) {
        throw new Error('Network response was not ok');
      }
      return response.json();
    },
  });
};

export const usePauseScan = (projectSlug: string) => {
  const queryClient = useQueryClient();
  return useMutation({
    mutationFn: async (params: { scan_ids?: number[]; target_id?: number }) => {
      const response = await fetch('/api/action/pause/scan/', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'X-CSRFToken': document.cookie.split('; ').find(row => row.startsWith('csrftoken='))?.split('=')[1] || '',
        },
        credentials: 'include',
        body: JSON.stringify(params),
      });
      if (!response.ok) {
        const errorData = await response.json();
        throw new Error(errorData.message || 'Failed to pause scan(s)');
      }
      return response.json();
    },
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['scans-history', projectSlug] });
      queryClient.invalidateQueries({ queryKey: ['scan-status', projectSlug] });
      queryClient.invalidateQueries({ queryKey: ['domains', projectSlug] });
    },
  });
};

export const useUnpauseScan = (projectSlug: string) => {
  const queryClient = useQueryClient();
  return useMutation({
    mutationFn: async (params: { scan_ids?: number[]; target_id?: number }) => {
      const response = await fetch('/api/action/unpause/scan/', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'X-CSRFToken': document.cookie.split('; ').find(row => row.startsWith('csrftoken='))?.split('=')[1] || '',
        },
        credentials: 'include',
        body: JSON.stringify(params),
      });
      if (!response.ok) {
        const errorData = await response.json();
        throw new Error(errorData.message || 'Failed to unpause scan(s)');
      }
      return response.json();
    },
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['scans-history', projectSlug] });
      queryClient.invalidateQueries({ queryKey: ['scan-status', projectSlug] });
      queryClient.invalidateQueries({ queryKey: ['domains', projectSlug] });
    },
  });
};

export const useDirectoryFileDispatch = () => {
  return useMutation({
    mutationFn: async (params: {
      url: string;
      action: string;
      scan_id: number;
    }): Promise<{ status: string; workflow_id: string }> => {
      const response = await fetch('/api/action/directory-file/dispatch/', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'X-CSRFToken': document.cookie.split('; ').find(row => row.startsWith('csrftoken='))?.split('=')[1] || '',
        },
        credentials: 'include',
        body: JSON.stringify(params),
      });
      if (!response.ok) {
        const errorData = await response.json();
        throw new Error(errorData.error || errorData.message || 'Failed to dispatch directory file action');
      }
      return response.json();
    },
  });
};

export const useDirectoryFileDelete = () => {
  const queryClient = useQueryClient();
  return useMutation({
    mutationFn: async (params: {
      directory_file_ids: number[];
    }): Promise<{ deleted: number }> => {
      const response = await fetch('/api/action/directory-file/delete/', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'X-CSRFToken': document.cookie.split('; ').find(row => row.startsWith('csrftoken='))?.split('=')[1] || '',
        },
        credentials: 'include',
        body: JSON.stringify(params),
      });
      if (!response.ok) {
        const errorData = await response.json();
        throw new Error(errorData.error || errorData.message || 'Failed to delete directory file(s)');
      }
      return response.json();
    },
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['directories'] });
    },
  });
};
