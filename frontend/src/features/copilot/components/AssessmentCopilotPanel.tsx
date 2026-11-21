import React from 'react';
import { Box, Paper, Typography } from '@mui/material';
import { useTheme } from '@mui/material/styles';
import { useThemeTokens } from '../../../theme/useThemeTokens';
import { getSurfaceSx } from '../../../theme/semanticColors';
import { CopilotSupportBox } from './CopilotSupportBox';

type Props = {
  projectSlug: string;
  assessmentId?: number | null;
  scanId?: number | null;
};

/** In-context co-pilot panel for assessment dashboard pages. */
export const AssessmentCopilotPanel: React.FC<Props> = ({
  projectSlug,
  assessmentId = null,
  scanId = null,
}) => {
  const theme = useTheme();
  const { tokens, isLight } = useThemeTokens();

  return (
    <Paper
      elevation={0}
      sx={{
        ...getSurfaceSx(isLight, tokens, theme),
        height: '100%',
        minHeight: 420,
        overflow: 'hidden',
      }}
    >
      <Box sx={{ px: 2, pt: 1.5 }}>
        <Typography variant="caption" color="text.secondary">
          In-assessment co-pilot — chat and approve validations / SAFE PoCs / remediations.
        </Typography>
      </Box>
      <Box sx={{ height: 'calc(100% - 28px)' }}>
        <CopilotSupportBox
          projectSlug={projectSlug}
          assessmentId={assessmentId}
          scanId={scanId}
        />
      </Box>
    </Paper>
  );
};
