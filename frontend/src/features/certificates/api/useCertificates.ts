import { useQuery } from '@tanstack/react-query';
import axios from '../../../api/axiosConfig';

export interface CertificateRecord {
  id: number;
  host: string;
  port: number;
  subject_cn: string | null;
  subject_an: string[];
  issuer_cn: string | null;
  issuer_org: string | null;
  not_before: string | null;
  not_after: string | null;
  tls_version: string | null;
  cipher: string | null;
  fingerprint_sha256: string | null;
  self_signed: boolean;
  mismatched: boolean;
  is_expired: boolean;
  has_weak_cipher: boolean;
}

export interface CertificateResponse {
  count: number;
  page: number;
  page_size: number;
  results: CertificateRecord[];
}

export const useCertificates = (
  scanId: number | undefined,
  page = 1,
  pageSize = 100,
  projectSlug?: string,
) =>
  useQuery<CertificateResponse>({
    queryKey: ['certificates', scanId, page, pageSize, projectSlug],
    queryFn: async () => {
      const params = new URLSearchParams();
      params.set('scan_id', String(scanId));
      params.set('page', String(page));
      params.set('page_size', String(pageSize));
      if (projectSlug) {
        params.set('project', projectSlug);
      }
      const { data } = await axios.get<CertificateResponse>(
        `/api/certs/?${params.toString()}`
      );
      return data;
    },
    enabled: scanId !== undefined,
  });
