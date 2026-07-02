import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query';
import axios from '@/api/axiosConfig';
import type { Assessment, Client, Engagement } from '../types';

export const useAssessments = () => {
  return useQuery<Assessment[]>({
    queryKey: ['assessments'],
    queryFn: async () => {
      const response = await axios.get('/api/engagements/assessments/');
      return response.data;
    },
  });
};

export const useClients = () => {
  return useQuery<Client[]>({
    queryKey: ['clients'],
    queryFn: async () => {
      const response = await axios.get('/api/engagements/clients/');
      return response.data;
    },
  });
};

export const useEngagements = () => {
  return useQuery<Engagement[]>({
    queryKey: ['engagements'],
    queryFn: async () => {
      const response = await axios.get('/api/engagements/engagements/');
      return response.data;
    },
  });
};

// Mutations
export const useStartAssessment = () => {
  const queryClient = useQueryClient();
  return useMutation({
    mutationFn: async (assessmentId: string) => {
      const response = await axios.post(`/api/engagements/assessments/${assessmentId}/start/`);
      return response.data;
    },
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['assessments'] });
    },
  });
};

export const usePauseAssessment = () => {
  const queryClient = useQueryClient();
  return useMutation({
    mutationFn: async (assessmentId: string) => {
      const response = await axios.post(`/api/engagements/assessments/${assessmentId}/pause/`);
      return response.data;
    },
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['assessments'] });
    },
  });
};

export const useResumeAssessment = () => {
  const queryClient = useQueryClient();
  return useMutation({
    mutationFn: async (assessmentId: string) => {
      const response = await axios.post(`/api/engagements/assessments/${assessmentId}/resume/`);
      return response.data;
    },
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['assessments'] });
    },
  });
};

export const useCancelAssessment = () => {
  const queryClient = useQueryClient();
  return useMutation({
    mutationFn: async (assessmentId: string) => {
      const response = await axios.post(`/api/engagements/assessments/${assessmentId}/cancel/`);
      return response.data;
    },
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['assessments'] });
    },
  });
};
