import React from 'react';
import { Grid } from '@mui/material';
import { EmailSection } from './EmailSection';
import { EmployeeSection } from './EmployeeSection';
import { DorkSection } from './DorkSection';
import { DocumentSection } from './DocumentSection';
import { OsintStagingSection } from './OsintStagingSection';
import { useEmails } from '../../api';
import type { ScanSummaryResponse } from '../../types';

interface OsintTabProps {
  /** The scan summary; only its OSINT collections are read here. */
  data: Pick<ScanSummaryResponse, 'dorks' | 'documents'>;
  scanId: number;
}

export const OsintTab: React.FC<OsintTabProps> = ({ data, scanId }) => {
  const { data: emails = [], refetch: refetchEmails } = useEmails(scanId);

  return (
    <Grid container spacing={2}>
      <Grid size={12}>
        <OsintStagingSection scanId={scanId} />
      </Grid>

      <Grid size={12}>
        <EmailSection emails={emails} scanId={scanId} refetchEmails={refetchEmails} />
      </Grid>

      <Grid size={12}>
        <EmployeeSection scanId={scanId} />
      </Grid>

      {data.dorks && data.dorks.length > 0 && (
        <Grid size={12}>
          <DorkSection dorks={data.dorks} />
        </Grid>
      )}

      {data.documents && data.documents.length > 0 && (
        <Grid size={12}>
          <DocumentSection documents={data.documents} />
        </Grid>
      )}
    </Grid>
  );
};
