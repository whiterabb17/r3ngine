import React from 'react';
import { useParams } from 'react-router-dom';
import { Box, Typography, Grid, Paper } from '@mui/material';
import { useAssessments } from '../api';
import { useAssessmentStream } from '../hooks/useAssessmentStream';
import { AssessmentControlPanel } from '../components/AssessmentControlPanel';
import { AssessmentStatusTimeline } from '../components/AssessmentStatusTimeline';

export const AssessmentExecutionDashboard: React.FC = () => {
  const { id } = useParams<{ id: string }>();
  
  // Use existing query to get initial status, fallback to finding by ID
  const { data: assessments, isLoading } = useAssessments();
  const assessment = assessments?.find(a => a.uuid === id);
  
  // Connect WebSocket
  const { events, isConnected } = useAssessmentStream(id || '');

  // The latest state from WebSockets takes precedence, otherwise fallback to DB state
  const latestEvent = events.length > 0 ? events[events.length - 1] : null;
  const currentStatus = latestEvent?.data?.status || assessment?.status || 'Draft';
  const progress = latestEvent?.data?.progress || 0; // Or whatever path progress is emitted on

  if (isLoading) return <Typography>Loading...</Typography>;
  if (!assessment) return <Typography>Assessment not found</Typography>;

  return (
    <Box sx={{ p: 3 }}>
      <Typography variant="h4" gutterBottom>
        Execution Dashboard: {assessment.name}
      </Typography>
      
      <Typography variant="subtitle1" color={isConnected ? 'success.main' : 'error.main'} sx={{ mb: 3 }}>
        Live Connection: {isConnected ? 'Active' : 'Disconnected'}
      </Typography>

      <Grid container spacing={3}>
        <Grid size={{ xs: 12, md: 4 }}>
          <Paper sx={{ p: 0, height: '100%' }} elevation={2}>
            <AssessmentControlPanel assessmentId={assessment.uuid} status={currentStatus} />
          </Paper>
        </Grid>
        
        <Grid size={{ xs: 12, md: 8 }}>
          <Paper sx={{ p: 0, height: '100%' }} elevation={2}>
            <AssessmentStatusTimeline 
              currentStage={currentStatus} 
              progress={progress} 
              events={events} 
            />
          </Paper>
        </Grid>

        {/* ECharts could be added here in the future to show findings distributions */}
        <Grid size={{ xs: 12 }}>
          <Paper sx={{ p: 2, mt: 2 }} elevation={2}>
            <Typography variant="h6">Metrics (Placeholder for ECharts)</Typography>
            <Typography variant="body2" color="text.secondary">
              Findings and vulnerability trends will appear here as the assessment progresses.
            </Typography>
          </Paper>
        </Grid>
      </Grid>
    </Box>
  );
};
