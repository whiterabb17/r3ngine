import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query';
import { getExposures, updateExposureStatus } from './exposures';
import type { ExposureQueryParams } from '../types';

export const useExposures = (params: ExposureQueryParams) => {
  return useQuery({
    queryKey: ['exposures', params],
    queryFn: () => getExposures(params),
    staleTime: 30000,
  });
};

export const useMutateExposureStatus = (
  onSuccessCallback?: () => void,
  onErrorCallback?: (message: string) => void,
) => {
  const queryClient = useQueryClient();

  return useMutation({
    mutationFn: ({ id, status }: { id: number; status: 'open' | 'verified' | 'false_positive' | 'remediated' }) =>
      updateExposureStatus(id, status),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['exposures'] });
      onSuccessCallback?.();
    },
    onError: () => {
      onErrorCallback?.('Failed to update exposure status. Please try again.');
    },
  });
};
