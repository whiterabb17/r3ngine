import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query';
import axios from '@/api/axiosConfig';
import type { Evidence, EvidenceCollection, EvidenceAnnotation } from '../types';

// -------------------------------------------------------------------------
// Query Keys
// -------------------------------------------------------------------------
export const evidenceKeys = {
  all:         ['evidence'] as const,
  collections: ['evidence', 'collections'] as const,
  collection:  (uuid: string) => ['evidence', 'collections', uuid] as const,
  items:       (collectionUuid: string) => ['evidence', 'items', collectionUuid] as const,
  item:        (uuid: string) => ['evidence', 'item', uuid] as const,
};

// -------------------------------------------------------------------------
// Collections
// -------------------------------------------------------------------------
export const useEvidenceCollections = (assessmentUuid?: string) => {
  return useQuery<EvidenceCollection[]>({
    queryKey: assessmentUuid
      ? [...evidenceKeys.collections, assessmentUuid]
      : evidenceKeys.collections,
    queryFn: async () => {
      const params = assessmentUuid ? { assessment: assessmentUuid } : {};
      const response = await axios.get('/api/evidence/collections/', { params });
      return response.data.results ?? response.data;
    },
  });
};

export const useEvidenceCollection = (uuid: string) => {
  return useQuery<EvidenceCollection>({
    queryKey: evidenceKeys.collection(uuid),
    queryFn: async () => {
      const response = await axios.get(`/api/evidence/collections/${uuid}/`);
      return response.data;
    },
    enabled: Boolean(uuid),
  });
};

export const useCollectionItems = (
  collectionUuid: string,
  filters?: { status?: string; type?: string }
) => {
  return useQuery<Evidence[]>({
    queryKey: [...evidenceKeys.items(collectionUuid), filters],
    queryFn: async () => {
      const params: Record<string, string> = {};
      if (filters?.status) params.status = filters.status;
      if (filters?.type) params.type = filters.type;
      const response = await axios.get(
        `/api/evidence/collections/${collectionUuid}/items/`,
        { params }
      );
      return response.data.results ?? response.data;
    },
    enabled: Boolean(collectionUuid),
  });
};

export const useArchiveCollection = () => {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: async (uuid: string) => {
      const res = await axios.post(`/api/evidence/collections/${uuid}/archive/`);
      return res.data;
    },
    onSuccess: () => qc.invalidateQueries({ queryKey: evidenceKeys.collections }),
  });
};

// -------------------------------------------------------------------------
// Evidence items
// -------------------------------------------------------------------------
export const useEvidenceItem = (uuid: string) => {
  return useQuery<Evidence>({
    queryKey: evidenceKeys.item(uuid),
    queryFn: async () => {
      const response = await axios.get(`/api/evidence/${uuid}/`);
      return response.data;
    },
    enabled: Boolean(uuid),
  });
};

export const useVerifyEvidence = () => {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: async (uuid: string) => {
      const res = await axios.post(`/api/evidence/${uuid}/verify/`);
      return res.data as { passed: boolean; sha256_hash: string };
    },
    onSuccess: (_, uuid) => qc.invalidateQueries({ queryKey: evidenceKeys.item(uuid) }),
  });
};

export const useArchiveEvidence = () => {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: async ({ uuid, note }: { uuid: string; note?: string }) => {
      const res = await axios.post(`/api/evidence/${uuid}/archive/`, { note });
      return res.data;
    },
    onSuccess: () => qc.invalidateQueries({ queryKey: evidenceKeys.all }),
  });
};

export const usePurgeEvidence = () => {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: async ({ uuid, deleteFile }: { uuid: string; deleteFile?: boolean }) => {
      const res = await axios.delete(`/api/evidence/${uuid}/purge/`, {
        data: { delete_file: deleteFile ?? false },
      });
      return res.data;
    },
    onSuccess: () => qc.invalidateQueries({ queryKey: evidenceKeys.all }),
  });
};

export const useAddAnnotation = (evidenceUuid: string) => {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: async (data: { annotation_type: string; content: string; region?: object }) => {
      const res = await axios.post(`/api/evidence/${evidenceUuid}/annotations/`, data);
      return res.data as EvidenceAnnotation;
    },
    onSuccess: () => qc.invalidateQueries({ queryKey: evidenceKeys.item(evidenceUuid) }),
  });
};

// -------------------------------------------------------------------------
// Upload
// -------------------------------------------------------------------------
export const useUploadEvidence = (collectionUuid: string) => {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: async (formData: FormData) => {
      const res = await axios.post('/api/evidence/upload/', formData, {
        headers: { 'Content-Type': 'multipart/form-data' },
      });
      return res.data as Evidence;
    },
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: evidenceKeys.items(collectionUuid) });
      qc.invalidateQueries({ queryKey: evidenceKeys.collection(collectionUuid) });
    },
  });
};
