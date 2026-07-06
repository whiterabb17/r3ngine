import React from 'react';
import { Box, Typography, Stepper, Step, StepLabel, LinearProgress } from '@mui/material';
import type { AssessmentStreamEvent } from '../hooks/useAssessmentStream';

interface Props {
  currentStage: string;
  progress: number;
  events: AssessmentStreamEvent[];
}

const STAGES = [
  'Draft',
  'Ready',
  'Discovery',
  'Enumeration',
  'Analysis',
  'Validation',
  'Reporting',
  'Complete'
];

export const AssessmentStatusTimeline: React.FC<Props> = ({ currentStage, progress, events }) => {
  const activeStep = STAGES.indexOf(currentStage);

  return (
    <Box sx={{ p: 2, border: '1px solid', borderColor: 'divider', borderRadius: 1 }}>
      <Typography variant="h6" gutterBottom>
        Execution Status
      </Typography>
      
      <Box sx={{ mt: 3, mb: 4 }}>
        <Stepper activeStep={activeStep} alternativeLabel>
          {STAGES.map((label) => (
            <Step key={label}>
              <StepLabel>{label}</StepLabel>
            </Step>
          ))}
        </Stepper>
      </Box>

      <Box sx={{ mt: 2 }}>
        <Typography variant="body2" color="text.secondary" gutterBottom>
          Overall Progress: {progress}%
        </Typography>
        <LinearProgress variant="determinate" value={progress} sx={{ height: 10, borderRadius: 5 }} />
      </Box>

      {events.length > 0 && (
        <Box sx={{ mt: 4 }}>
          <Typography variant="subtitle2" gutterBottom>
            Recent Activity
          </Typography>
          <Box sx={{ maxHeight: 200, overflow: 'auto', bgcolor: 'background.default', p: 1, borderRadius: 1 }}>
            {events.slice().reverse().map((event, idx) => (
              <Typography key={idx} variant="caption" sx={{ display: 'block', mb: 0.5 }}>
                [{new Date(event.timestamp).toLocaleTimeString()}] {event.event_type} - {JSON.stringify(event.data)}
              </Typography>
            ))}
          </Box>
        </Box>
      )}
    </Box>
  );
};
