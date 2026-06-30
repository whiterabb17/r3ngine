import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query';
import axios from '../../../api/axiosConfig';
import { getCsrfToken } from '../../../api/axiosConfig';
import type { EndpointResponse } from '../types';

export const useDeleteEndpoints = (projectSlug: string) => {
  const queryClient = useQueryClient();
  return useMutation({
    mutationFn: async (endpoint_ids: number[]) => {
      await Promise.all(
        endpoint_ids.map((id) =>
          axios.delete(`/api/listEndpoints/${id}/`, {
            headers: {
              'X-CSRFToken': getCsrfToken()
            }
          })
        )
      );
    },
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['endpoints', projectSlug] });
    },
  });
};

export const useEndpoints = (projectSlug: string, page = 1, searchQuery = '', scanId?: number, gfTag?: string, targetId?: number, httpStatus?: string, pageSize = 25) => {
  return useQuery<EndpointResponse>({
    queryKey: ['endpoints', projectSlug, page, searchQuery, scanId, gfTag, targetId, httpStatus, pageSize],
    queryFn: async () => {
      const url = new URL(`${window.location.origin}/api/listEndpoints/`);
      url.searchParams.append('project', projectSlug);
      url.searchParams.append('page', page.toString());
      url.searchParams.append('length', pageSize.toString());
      
      if (searchQuery) {
        url.searchParams.append('query_param', searchQuery);
      }
      
      if (scanId) {
        url.searchParams.append('scan_history', scanId.toString());
      }

      if (targetId) {
        url.searchParams.append('target_id', targetId.toString());
      }
      
      if (gfTag) {
        url.searchParams.append('gf_tag', gfTag);
      }

      if (httpStatus) {
        url.searchParams.append('http_status', httpStatus);
      }
      
      url.searchParams.append('format', 'json');

      const response = await fetch(url.toString(), {
        credentials: 'include'
      });
      
      if (!response.ok) {
        throw new Error('Network response was not ok');
      }
      return response.json();
    },
    enabled: !!projectSlug,
  });
};
