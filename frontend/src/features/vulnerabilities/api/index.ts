import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query';
import type { operations } from '@/types/api';
import type { VulnerabilityResponse } from '../types';


export interface VulnerabilityFilters {
  severity?: string;
  exclude_severity?: string;
  validation_status?: string;
  open_status?: string;
  source?: string;
  exclude_source?: string;
}

export const useVulnerabilities = (projectSlug: string, page = 1, searchQuery = '', scanId?: number, targetId?: number, filters?: VulnerabilityFilters, pageSize = 10) => {
  return useQuery<VulnerabilityResponse>({
    queryKey: ['vulnerabilities', projectSlug, page, searchQuery, scanId, targetId, filters, pageSize],
    queryFn: async () => {
      const url = new URL(`${window.location.origin}/api/listVulnerability/`);
      url.searchParams.append('project', projectSlug);
      url.searchParams.append('page', page.toString());
      url.searchParams.append('length', pageSize.toString());
      
      if (searchQuery) {
        url.searchParams.append('search[value]', searchQuery);
      }
      
      if (scanId) {
        url.searchParams.append('scan_history', scanId.toString());
      }

      if (targetId) {
        url.searchParams.append('target_id', targetId.toString());
      }
      
      if (filters) {
        if (filters.severity) url.searchParams.append('severity', filters.severity);
        if (filters.exclude_severity) url.searchParams.append('exclude_severity', filters.exclude_severity);
        if (filters.validation_status) url.searchParams.append('validation_status', filters.validation_status);
        if (filters.open_status) url.searchParams.append('open_status', filters.open_status);
        if (filters.source) url.searchParams.append('source', filters.source);
        if (filters.exclude_source) url.searchParams.append('exclude_source', filters.exclude_source);
      }
      
      url.searchParams.append('format', 'json');

      const response = await fetch(url.toString(), {
        credentials: 'include'
      });
      
      if (!response.ok) {
        throw new Error('Network response was not ok');
      }
      return await response.json() as operations["api_listVulnerability_list"]["responses"]["200"]["content"]["application/json"];
    },

    enabled: !!projectSlug,
  });
};

export const useDeleteVulnerability = () => {
  const queryClient = useQueryClient();
  return useMutation({
    mutationFn: async (ids: number[]) => {
      const response = await fetch('/api/action/vulnerability/delete/', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'X-CSRFToken': document.cookie.split('; ').find(row => row.startsWith('csrftoken='))?.split('=')[1] || ''
        },
        body: JSON.stringify({ vulnerability_ids: ids }),
        credentials: 'include'
      });
      if (!response.ok) {
        throw new Error('Failed to delete vulnerability');
      }
      return response.json();
    },
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['vulnerabilities'] });
    }
  });
};

export const useGptVulnerabilityDetails = () => {
  return useMutation({
    mutationFn: async ({ id, name }: { id: number; name: string }) => {
      const response = await fetch(`/api/tools/gpt_vulnerability_report/?id=${id}`, {
        credentials: 'include'
      });
      if (!response.ok) {
        throw new Error('Failed to fetch GPT details');
      }
      return response.json();
    }
  });
};

export const useReportToHackerone = () => {
  return useMutation({
    mutationFn: async (vulnerabilityId: number) => {
      const response = await fetch(`/api/vulnerability/report/?vulnerability_id=${vulnerabilityId}`, {
        credentials: 'include'
      });
      if (!response.ok) {
        throw new Error('Failed to report to Hackerone');
      }
      return response.json();
    }
  });
};

export const useToggleVulnerabilityStatus = () => {
  const queryClient = useQueryClient();
  return useMutation({
    mutationFn: async (id: number) => {
      const response = await fetch(`/scan/toggle/vuln_status/${id}/`, {
        method: 'POST',
        headers: {
          'X-CSRFToken': document.cookie.split('; ').find(row => row.startsWith('csrftoken='))?.split('=')[1] || ''
        },
        credentials: 'include'
      });
      if (!response.ok) {
        throw new Error('Failed to toggle vulnerability status');
      }
      return response.json();
    },
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['vulnerabilities'] });
    }
  });
};

export const useUpdateVulnerabilityValidationStatus = () => {
  const queryClient = useQueryClient();
  return useMutation({
    mutationFn: async ({ id, status }: { id: number; status: string }) => {
      const formData = new FormData();
      formData.append('status', status);
      const response = await fetch(`/scan/update/vuln_validation_status/${id}/`, {
        method: 'POST',
        headers: {
          'X-CSRFToken': document.cookie.split('; ').find(row => row.startsWith('csrftoken='))?.split('=')[1] || ''
        },
        body: formData,
        credentials: 'include'
      });
      if (!response.ok) {
        throw new Error('Failed to update vulnerability validation status');
      }
      return response.json();
    },
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['vulnerabilities'] });
    }
  });
};

export const useGenerateImpact = (projectSlug: string) => {
  return useMutation({
    mutationFn: async (vulnId: number) => {
      const response = await fetch(`/${projectSlug}/api/impact/vulnerability/${vulnId}/generate/`, {
        method: 'POST',
        headers: {
          'X-CSRFToken': document.cookie.split('; ').find(row => row.startsWith('csrftoken='))?.split('=')[1] || ''
        },
        credentials: 'include'
      });
      if (!response.ok) {
        throw new Error('Failed to trigger impact generation');
      }
      return response.json();
    }
  });
};

export const useImpactGraphData = (projectSlug: string, vulnId: number | null) => {
  return useQuery({
    queryKey: ['impact-graph', projectSlug, vulnId],
    queryFn: async () => {
      const response = await fetch(`/${projectSlug}/api/impact/vulnerability/${vulnId}/data/`, {
        credentials: 'include'
      });
      if (!response.ok) {
        throw new Error('Failed to fetch impact graph data');
      }
      return response.json();
    },
    enabled: !!projectSlug && !!vulnId,
  });
};
export interface AttackChainStep {
  phase: string;
  description: string;
}

export interface ImpactAssessmentResponse {
  status: boolean;
  potential_impact?: string;
  remediation_priority?: number;
  potential_attack_chain?: {
    steps: AttackChainStep[];
    confidence?: string;
  };
  created_at?: string;
  is_ai_generated?: boolean;
}

export const useImpactAssessment = (projectSlug: string, vulnId: number | null) => {
  return useQuery<ImpactAssessmentResponse>({
    queryKey: ['impact-assessment', projectSlug, vulnId],
    queryFn: async () => {
      const response = await fetch(`/${projectSlug}/api/impact/vulnerability/${vulnId}/details/`, {
        credentials: 'include'
      });
      if (!response.ok) {
        throw new Error('Failed to fetch impact assessment');
      }
      return response.json() as Promise<ImpactAssessmentResponse>;
    },
    enabled: !!projectSlug && !!vulnId,
    refetchInterval: (query) => {
      if (!query.state.data || query.state.data.status === false) return 5000;
      return false;
    }
  });
};
