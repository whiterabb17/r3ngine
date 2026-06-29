import React from 'react';
import { Box, Container } from '@mui/material';
import { AssessmentList } from '../components/AssessmentList';

export const AssessmentsPage: React.FC = () => {
  return (
    <Container maxWidth="xl">
      <Box sx={{ py: 4 }}>
        <AssessmentList />
      </Box>
    </Container>
  );
};
