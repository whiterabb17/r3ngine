import axios from 'axios';
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query';
import type { Organization, CreateOrganizationDTO, UpdateOrganizationDTO } from '../orgTypes';

const API_BASE = '/api';

export const useOrganizations = () => {
  return useQuery({
    queryKey: ['organizations'],
    queryFn: async () => {
      const response = await axios.get<{ organizations: Organization[] }>(`${API_BASE}/listOrganizations/`);
      return response.data.organizations;
    },
  });
};

export const useTargetsWithoutOrganization = () => {
  return useQuery({
    queryKey: ['targets', 'without-organization'],
    queryFn: async () => {
      const response = await axios.get<{ domains: { name: string; id: number }[] }>(`${API_BASE}/queryTargetsWithoutOrganization/`);
      return response.data.domains;
    },
  });
};

export const useCreateOrganization = () => {
  const queryClient = useQueryClient();
  return useMutation({
    mutationFn: async (data: CreateOrganizationDTO) => {
      const response = await axios.post(`${API_BASE}/createOrganization/`, data);
      return response.data;
    },
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['organizations'] });
      queryClient.invalidateQueries({ queryKey: ['targets', 'without-organization'] });
    },
  });
};

export const useUpdateOrganization = () => {
  const queryClient = useQueryClient();
  return useMutation({
    mutationFn: async (data: UpdateOrganizationDTO) => {
      const response = await axios.post(`${API_BASE}/updateOrganization/`, data);
      return response.data;
    },
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['organizations'] });
      queryClient.invalidateQueries({ queryKey: ['targets', 'without-organization'] });
    },
  });
};

export const useDeleteOrganizations = () => {
  const queryClient = useQueryClient();
  return useMutation({
    mutationFn: async (ids: number[]) => {
      const response = await axios.post(`${API_BASE}/action/rows/delete/`, {
        type: 'organization',
        rows: ids,
      });
      return response.data;
    },
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['organizations'] });
      queryClient.invalidateQueries({ queryKey: ['targets', 'without-organization'] });
    },
  });
};
