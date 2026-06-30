import axiosInstance from '@/api/axiosConfig';
import type { ExposuresResponse, ExposureQueryParams, Exposure } from '../types';

export const getExposures = async (params: ExposureQueryParams): Promise<ExposuresResponse> => {
  const response = await axiosInstance.get('/api/listExposures/', { params });
  return response.data;
};

export const updateExposureStatus = async (
  id: number,
  status: 'open' | 'verified' | 'false_positive' | 'remediated'
): Promise<Exposure> => {
  const response = await axiosInstance.patch(`/api/listExposures/${id}/`, { status });
  return response.data;
};
