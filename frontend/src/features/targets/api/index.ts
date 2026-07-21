import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query';
import type { paths, operations, components } from '@/types/api';
import type { Domain, Organization, Engine } from '../types';

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


export const useAddTarget = (projectSlug: string) => {
  const queryClient = useQueryClient();
  
  return useMutation({
    mutationFn: async (params: {
      domain_name: string;
      slug: string;
      organization?: string;
      h1_team_handle?: string;
      description?: string;
      is_monitored?: boolean;
      monitor_frequency?: string;
      monitor_engine_id?: number;
      monitor_scan_scope?: string;
      starting_point_path?: string;
      excluded_paths?: string[];
      target_type?: string;
    }) => {
      const response = await fetch('/api/add/target/', {
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
        throw new Error(errorData.message || 'Failed to add target');
      }

      return response.json();
    },
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['domains', projectSlug] });
    },
  });
};


export const useOrganizations = () => {
  return useQuery<Organization[]>({
    queryKey: ['organizations'],
    queryFn: async () => {
      const response = await fetch('/api/listOrganizations/', {
        credentials: 'include'
      });
      if (!response.ok) {
        throw new Error('Network response was not ok');
      }
      const data = await response.json();
      if (Array.isArray(data)) return data;
      if (data.organizations && Array.isArray(data.organizations)) return data.organizations;
      if (data.results && Array.isArray(data.results)) return data.results;
      return [];
    },
  });
};

export const useDeleteTargets = (projectSlug: string) => {
  const queryClient = useQueryClient();
  
  return useMutation({
    mutationFn: async (targetIds: number[]) => {
      const response = await fetch('/api/action/rows/delete/', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'X-CSRFToken': document.cookie.split('; ').find(row => row.startsWith('csrftoken='))?.split('=')[1] || '',
        },
        credentials: 'include',
        body: JSON.stringify({
          type: 'target',
          rows: targetIds,
        }),
      });

      if (!response.ok) {
        throw new Error('Failed to delete targets');
      }

      return response.json();
    },
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['domains', projectSlug] });
    },
  });
};

export const useTargetSummary = (projectSlug: string, targetId: number) => {
  return useQuery({
    queryKey: ['target-summary', projectSlug, targetId],
    queryFn: async () => {
      const response = await fetch(`/api/target-summary/${projectSlug}/${targetId}/`, {
        credentials: 'include'
      });
      if (!response.ok) {
        throw new Error('Network response was not ok');
      }
      return response.json();
    },
    enabled: !!projectSlug && !!targetId,
  });
};

export const useEngines = () => {
  return useQuery<Engine[]>({
    queryKey: ['engines'],
    queryFn: async () => {
      const response = await fetch('/api/listEngines/', {
        credentials: 'include'
      });
      if (!response.ok) {
        throw new Error('Network response was not ok');
      }
      const data = await response.json() as any;
      // listEngines returns a list directly in some cases, or wrapped in an object
      if (Array.isArray(data)) return data as Engine[];
      if ('engines' in data && Array.isArray(data.engines)) return data.engines as Engine[];
      return [] as Engine[];
    },
  });
};


export const useUpdateTarget = (projectSlug: string) => {
  const queryClient = useQueryClient();

  return useMutation({
    mutationFn: async (params: {
      id: number;
      description?: string;
      h1_team_handle?: string;
      target_type?: string;
      organization?: string;
      is_monitored?: boolean;
      monitor_frequency?: string;
      monitor_engine_id?: number | null;
      monitor_scan_scope?: string;
      starting_point_path?: string;
      excluded_paths?: string;
      in_scope_ips?: string;
      secondary_domains?: string;
    }) => {
      const response = await fetch('/api/update/target/', {
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
        throw new Error(errorData.message || 'Failed to update target');
      }

      return response.json();
    },
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['domains', projectSlug] });
    },
  });
};


export const useResolveIP = () => {
  return useMutation({
    mutationFn: async (ipAddress: string) => {
      const response = await fetch(`/api/tools/ip_to_domain/?ip_address=${ipAddress}`, {
        credentials: 'include'
      });
      if (!response.ok) {
        throw new Error('Failed to resolve IP');
      }
      return response.json();
    }
  });
};

export const useTargetScans = (targetId: number) => {
  return useQuery<{ id: number; start_scan_date: string; scan_status: number }[]>({
    queryKey: ['target-scans', targetId],
    queryFn: async () => {
      const response = await fetch(`/api/listScans/?target_id=${targetId}`, {
        credentials: 'include',
      });
      if (!response.ok) throw new Error('Failed to fetch scans');
      const data = await response.json();
      return Array.isArray(data) ? data : data.results ?? [];
    },
    enabled: !!targetId,
  });
};

export const useCreateTargetReport = () => {
  return useMutation({
    mutationFn: async (params: {
      domainId: number;
      scanIds: number[];
      includedSections: string[];
    }) => {
      const qs = new URLSearchParams({
        scan_ids: params.scanIds.join(','),
        included_sections: params.includedSections.join(','),
      });
      const response = await fetch(`/scan/target/create_report/${params.domainId}/?${qs}`, {
        credentials: 'include',
      });
      if (!response.ok) throw new Error('Failed to create target report');
      return response.json() as Promise<{ status: boolean; report_id: number }>;
    },
  });
};

export const fetchTargetReportStatus = async (reportId: number) => {
  const response = await fetch(`/scan/target/report/status/${reportId}/`, {
    credentials: 'include',
  });
  if (!response.ok) throw new Error('Failed to fetch report status');
  return response.json() as Promise<{
    status: number;
    error_message: string | null;
    report_url: string | null;
    completed_at: string | null;
  }>;
};
