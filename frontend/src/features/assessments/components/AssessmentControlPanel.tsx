import React from 'react';
import { Button, Stack, Box, Typography } from '@mui/material';
import PlayArrowIcon from '@mui/icons-material/PlayArrow';
import PauseIcon from '@mui/icons-material/Pause';
import StopIcon from '@mui/icons-material/Stop';
import RestartAltIcon from '@mui/icons-material/RestartAlt';

import {
  useStartAssessment,
  usePauseAssessment,
  useResumeAssessment,
  useCancelAssessment,
} from '../api';

interface Props {
  assessmentId: string;
  status: string;
}

export const AssessmentControlPanel: React.FC<Props> = ({ assessmentId, status }) => {
  const startMutation = useStartAssessment();
  const pauseMutation = usePauseAssessment();
  const resumeMutation = useResumeAssessment();
  const cancelMutation = useCancelAssessment();

  const handleStart = () => startMutation.mutate(assessmentId);
  const handlePause = () => pauseMutation.mutate(assessmentId);
  const handleResume = () => resumeMutation.mutate(assessmentId);
  const handleCancel = () => cancelMutation.mutate(assessmentId);

  const canStart = status === 'Draft' || status === 'Pending';
  const canPause = status === 'Ready' || status === 'Running' || status === 'Discovery' || status === 'Enumeration' || status === 'Analysis' || status === 'Validation' || status === 'Reporting';
  const canResume = status === 'Paused';
  const canCancel = canPause || canResume || canStart;

  return (
    <Box sx={{ p: 2, border: '1px solid', borderColor: 'divider', borderRadius: 1 }}>
      <Typography variant="h6" gutterBottom>
        Execution Controls
      </Typography>
      <Stack direction="row" spacing={2} sx={{ mt: 2 }}>
        <Button
          variant="contained"
          color="primary"
          startIcon={<PlayArrowIcon />}
          onClick={handleStart}
          disabled={!canStart || startMutation.isPending}
        >
          Start Assessment
        </Button>
        <Button
          variant="outlined"
          color="warning"
          startIcon={<PauseIcon />}
          onClick={handlePause}
          disabled={!canPause || pauseMutation.isPending}
        >
          Pause
        </Button>
        <Button
          variant="outlined"
          color="info"
          startIcon={<RestartAltIcon />}
          onClick={handleResume}
          disabled={!canResume || resumeMutation.isPending}
        >
          Resume
        </Button>
        <Button
          variant="outlined"
          color="error"
          startIcon={<StopIcon />}
          onClick={handleCancel}
          disabled={!canCancel || cancelMutation.isPending}
        >
          Cancel
        </Button>
      </Stack>
    </Box>
  );
};
