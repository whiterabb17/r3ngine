import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query';
import type { Assessment, Client, Engagement } from '../types';

export const useAssessments = () => {
  return useQuery<Assessment[]>({
    queryKey: ['assessments'],
    queryFn: async () => {
      const response = await fetch('/api/engagements/assessments/', {
        credentials: 'include'
      });
      if (!response.ok) {
        throw new Error('Network response was not ok');
      }
      return response.json();
    },
  });
};

export const useClients = () => {
  return useQuery<Client[]>({
    queryKey: ['clients'],
    queryFn: async () => {
      const response = await fetch('/api/engagements/clients/', {
        credentials: 'include'
      });
      if (!response.ok) {
        throw new Error('Network response was not ok');
      }
      return response.json();
    },
  });
};

export const useEngagements = () => {
  return useQuery<Engagement[]>({
    queryKey: ['engagements'],
    queryFn: async () => {
      const response = await fetch('/api/engagements/engagements/', {
        credentials: 'include'
      });
      if (!response.ok) {
        throw new Error('Network response was not ok');
      }
      return response.json();
    },
  });
};
