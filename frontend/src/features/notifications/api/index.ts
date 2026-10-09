import axios from 'axios';
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query';
import type { components } from '@/types/api';
import type { WithRequired } from '@/types/apiRows';

/** `InAppNotificationSerializer` row; the list is unpaginated. */
export type InAppNotification = WithRequired<
  components["schemas"]["InAppNotification"],
  'id' | 'created_at' | 'is_read' | 'notification_type' | 'status'
>;

export const useNotifications = (projectSlug?: string) => {
  return useQuery<InAppNotification[]>({
    queryKey: ['notifications', projectSlug],
    queryFn: async () => {
      const response = await axios.get('/api/notifications/', {
        params: { project_slug: projectSlug }
      });
      return response.data;
    }
  });
};

export const useUnreadCount = (projectSlug?: string) => {
  return useQuery({
    queryKey: ['notifications-unread-count', projectSlug],
    queryFn: async () => {
      const response = await axios.get('/api/notifications/unread_count/', {
        params: { project_slug: projectSlug }
      });
      return response.data;
    },
    refetchInterval: 30000, // Refetch every 30 seconds
  });
};

export const useMarkAllRead = () => {
  const queryClient = useQueryClient();
  return useMutation({
    mutationFn: async (projectSlug?: string) => {
      await axios.post(`/api/notifications/mark_all_read/`, null, {
        params: { project_slug: projectSlug }
      });
    },
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['notifications'] });
      queryClient.invalidateQueries({ queryKey: ['notifications-unread-count'] });
    }
  });
};

export const useMarkRead = () => {
  const queryClient = useQueryClient();
  return useMutation({
    mutationFn: async (id: number) => {
      await axios.post(`/api/notifications/${id}/mark_read/`);
    },
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['notifications'] });
      queryClient.invalidateQueries({ queryKey: ['notifications-unread-count'] });
    }
  });
};

export const useClearAll = () => {
  const queryClient = useQueryClient();
  return useMutation({
    mutationFn: async (projectSlug?: string) => {
      await axios.post(`/api/notifications/clear_all/`, null, {
        params: { project_slug: projectSlug }
      });
    },
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['notifications'] });
      queryClient.invalidateQueries({ queryKey: ['notifications-unread-count'] });
    }
  });
};
