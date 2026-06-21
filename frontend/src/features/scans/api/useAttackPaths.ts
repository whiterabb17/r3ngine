import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query';
import axios from 'axios';

// ... (interfaces stay same)

export const useTriggerAttackPathModeling = () => {
  const queryClient = useQueryClient();
  return useMutation({
    mutationFn: async (scanId: number) => {
      const { data } = await axios.post(`/api/apme/trigger/`, { scan_id: scanId });
      return data;
    },
    onSuccess: (_, scanId) => {
      // Invalidate paths to refresh when done (though it's async in backend)
      queryClient.invalidateQueries({ queryKey: ['attack-paths', scanId] });
    },
  });
};

export const useRecalculateAttackPaths = () => {
  const queryClient = useQueryClient();
  return useMutation({
    mutationFn: async (scanId: number) => {
      const { data } = await axios.post(`/api/apme/recalculate/`, { scan_id: scanId });
      return data;
    },
    onSuccess: (_, scanId) => {
      queryClient.invalidateQueries({ queryKey: ['attack-paths', scanId] });
    },
  });
};

export interface EnrichedNode {
  id: string;
  type: string;
  subtype: string;
  name?: string;
  severity?: number;
  cvss_score?: number;
  vuln_id?: number | null;
  cwe?: string;
  technique?: string;
}

export interface AttackStep {
  from: string;
  to: string;
  action: string;
  edge_type: string;
  confidence: number;
  validated: boolean;
  status: 'validated' | 'inferred';
  from_node?: EnrichedNode;
  to_node?: EnrichedNode;
  mitre_technique?: string;
  mitre_technique_name?: string;
  mitre_tactic?: string;
  mitre_tactic_display?: string;
  mitre_tactic_color?: string;
}

export interface AttackPath {
  path_id: string;
  risk: string;
  score: number;
  step_count: number;
  steps: AttackStep[];
  potential_impact: string;
  remediation_priority: number;
  vulnerability_id: number | null;
  explanation?: string;
  mitre_techniques?: string[];
  mitre_tactics?: string[];
}

export interface AttackPathsResponse {
  total_paths: number;
  paths: AttackPath[];
  speculative_paths?: AttackPath[];
}

const fetchAttackPaths = async (scanId: number): Promise<AttackPathsResponse> => {
  const { data } = await axios.get(`/api/apme/paths/`, {
    params: { scan_id: scanId },
  });
  return data;
};

export const useAttackPaths = (scanId: number) =>
  useQuery<AttackPathsResponse>({
    queryKey: ['attack-paths', scanId],
    queryFn: () => fetchAttackPaths(scanId),
    staleTime: 5 * 60 * 1000, // 5 min — paths don't change post-scan
    enabled: !!scanId,
  });

export const useExplainAttackPath = () => {
  const queryClient = useQueryClient();
  return useMutation({
    mutationFn: async ({ pathId, scanId }: { pathId: string; scanId: number }) => {
      const { data } = await axios.post(`/api/apme/explain/`, { path_id: pathId });
      return data;
    },
    onSuccess: (data, variables) => {
      // Invalidate queries so the updated path (with explanation) is fetched from backend
      queryClient.invalidateQueries({ queryKey: ['attack-paths', variables.scanId] });
    },
  });
};

