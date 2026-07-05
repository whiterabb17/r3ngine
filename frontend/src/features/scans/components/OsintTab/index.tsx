import React from 'react';
import { Grid } from '@mui/material';
import { EmailSection } from './EmailSection';
import { EmployeeSection } from './EmployeeSection';
import { DorkSection } from './DorkSection';
import { DocumentSection } from './DocumentSection';
import { OsintStagingSection } from './OsintStagingSection';
import { useEmails } from '../../api';

interface OsintTabProps {
  data: any; // eslint-disable-line @typescript-eslint/no-explicit-any -- full scan data from parent
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
