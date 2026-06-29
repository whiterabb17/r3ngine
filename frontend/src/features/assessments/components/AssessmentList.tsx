import React from 'react';
import {
  Box,
  Typography,
  Table,
  TableBody,
  TableCell,
  TableContainer,
  TableHead,
  TableRow,
  Paper,
  CircularProgress
} from '@mui/material';
import { useAssessments } from '../api';

export const AssessmentList: React.FC = () => {
  const { data: assessments, isLoading, error } = useAssessments();

  if (isLoading) {
    return (
      <Box sx={{ display: 'flex', justifyContent: 'center', p: 4 }}>
        <CircularProgress />
      </Box>
    );
  }

  if (error) {
    return (
      <Box sx={{ p: 4 }}>
        <Typography color="error">Error loading assessments.</Typography>
      </Box>
    );
  }

  return (
    <Box>
      <Box sx={{ display: 'flex', justifyContent: 'space-between', mb: 2 }}>
        <Typography variant="h5" component="h2">
          Assessments
        </Typography>
      </Box>

      <TableContainer component={Paper}>
        <Table>
          <TableHead>
            <TableRow>
              <TableCell>Name</TableCell>
              <TableCell>Type</TableCell>
              <TableCell>Status</TableCell>
              <TableCell>Start Date</TableCell>
              <TableCell>End Date</TableCell>
            </TableRow>
          </TableHead>
          <TableBody>
            {assessments?.length === 0 ? (
              <TableRow>
                <TableCell colSpan={5} align="center">
                  No assessments found.
                </TableCell>
              </TableRow>
            ) : (
              assessments?.map((assessment) => (
                <TableRow key={assessment.id}>
                  <TableCell>{assessment.name}</TableCell>
                  <TableCell>{assessment.assessment_type}</TableCell>
                  <TableCell>{assessment.status}</TableCell>
                  <TableCell>{assessment.start_date}</TableCell>
                  <TableCell>{assessment.end_date}</TableCell>
                </TableRow>
              ))
            )}
          </TableBody>
        </Table>
      </TableContainer>
    </Box>
  );
};
