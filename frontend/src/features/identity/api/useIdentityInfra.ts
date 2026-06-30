import { useQuery } from '@tanstack/react-query';
import axios from '../../../api/axiosConfig';

export interface IdentityRecord {
  id: number;
  host: string;
  url: string | null;
  infra_type: string;
  detection_method: string;
  confidence_score: number;
  is_externally_accessible: boolean;
  additional_signals: Record<string, unknown>;
}

export interface IdentityInfraResponse {
  count: number;
  summary: Record<string, number>;
  results: IdentityRecord[];
}

export const useIdentityInfra = (
  scanId: number | undefined,
  projectSlug?: string,
) =>
  useQuery<IdentityInfraResponse>({
    queryKey: ['identity-infra', scanId, projectSlug],
    queryFn: async () => {
      const params = new URLSearchParams();
      params.set('scan_id', String(scanId));
      if (projectSlug) {
        params.set('project', projectSlug);
      }
      const { data } = await axios.get<IdentityInfraResponse>(
        `/api/identity/?${params.toString()}`
      );
      return data;
    },
    enabled: scanId !== undefined,
  });
