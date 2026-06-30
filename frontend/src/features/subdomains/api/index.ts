import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query';
import axios from '../../../api/axiosConfig';
import { getCsrfToken } from '../../../api/axiosConfig';
import type { SubdomainResponse } from '../types';

export interface SubdomainFilters {
  http_status?: string;
  is_important?: string;
  has_vulnerabilities?: string;
  ports?: string;
  has_ip?: string;
}

export const useSubdomains = (
  projectSlug: string,
  page = 1,
  searchQuery = '',
  scanId?: number,
  onlyDirectory = false,
  targetId?: number,
  filters?: SubdomainFilters,
  pageSize = 10,
  sortCol?: string,
  sortDir?: 'asc' | 'desc'
) => {
  return useQuery<SubdomainResponse>({
    queryKey: ['subdomains', projectSlug, page, searchQuery, scanId, onlyDirectory, targetId, filters, pageSize, sortCol, sortDir],
    queryFn: async () => {
      const response = await axios.get('/api/listDatatableSubdomain/', {
        params: {
          project: projectSlug,
          page: page.toString(),
          length: pageSize.toString(),
          'search[value]': searchQuery,
          scan_id: scanId?.toString(),
          target_id: targetId?.toString(),
          only_directory: onlyDirectory ? 'true' : undefined,
          format: 'json',
          http_status: filters?.http_status,
          is_important: filters?.is_important,
          has_vulnerabilities: filters?.has_vulnerabilities,
          ports: filters?.ports,
          has_ip: filters?.has_ip,
          'order[0][column]': sortCol,
          'order[0][dir]': sortDir
        }
      });
      return response.data;
    },
    enabled: !!projectSlug,
  });
};

export const useInitiateSubscan = () => {
  return useMutation({
    mutationFn: async (params: { engine_id: number | null; tasks: string[]; subdomain_ids: number[]; selected_plugins?: string[] }) => {
      const response = await axios.post('/api/action/initiate/subtask/', params, {
        headers: {
          'X-CSRFToken': getCsrfToken()
        }
      });
      return response.data;
    },
  });
};

export const useGPTAttackSurface = () => {
  return useMutation({
    mutationFn: async (subdomainId: number) => {
      const response = await axios.get('/api/tools/gpt_get_possible_attacks/', {
        params: {
          format: 'json',
          subdomain_id: subdomainId
        },
        headers: {
          'X-CSRFToken': getCsrfToken()
        }
      });
      return response.data;
    },
  });
};

export const use_show_attack_surface_modal = async (subdomainId: number) => {
  try {
    const response = await axios.get('/api/tools/gpt_get_possible_attacks/', {
      params: {
        format: 'json',
        subdomain_id: subdomainId
      },
      headers: {
        'X-CSRFToken': getCsrfToken()
      }
    });
    const data = response.data;
    if (data.status) {
      console.log("data");
      console.log(data);
      // Should be displayed in the modal dialog.
      // $('#modal_title').html(`Attack Surface Suggestion for ${data.subdomain_name} (BETA)`);
      // $('#modal-content').empty();
      // $('#modal-content').append(data.description.replace(new RegExp('\r?\n', 'g'), '<br />'));
      // $('#modal_dialog').modal('show');
    }
    else {
      console.log("no data");
    }
  } catch (error) {
    console.error(error);
  }
}

export const useDeleteSubdomain = (projectSlug: string) => {
  const queryClient = useQueryClient();
  return useMutation({
    mutationFn: async (subdomain_ids: number[]) => {
      const response = await axios.post('/api/action/subdomain/delete/', { subdomain_ids }, {
        headers: {
          'X-CSRFToken': getCsrfToken()
        }
      });
      return response.data;
    },
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['subdomains', projectSlug] });
    },
  });
};

export const useToggleSubdomainImportant = (projectSlug: string) => {
  const queryClient = useQueryClient();
  return useMutation({
    mutationFn: async (id: number) => {
      const response = await axios.post('/api/toggle/subdomain/important/', { subdomain_id: id }, {
        headers: {
          'X-CSRFToken': getCsrfToken()
        }
      });
      return response.data;
    },
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['subdomains', projectSlug] });
    },
  });
};

export const useAddManualSubdomain = (projectSlug: string) => {
  const queryClient = useQueryClient();
  return useMutation({
    mutationFn: async (params: { target_id?: number; scan_id?: number; subdomain_name: string }) => {
      const response = await axios.post('/api/action/subdomain/add/', params, {
        headers: {
          'X-CSRFToken': getCsrfToken()
        }
      });
      return response.data;
    },
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['subdomains', projectSlug] });
    },
  });
};


