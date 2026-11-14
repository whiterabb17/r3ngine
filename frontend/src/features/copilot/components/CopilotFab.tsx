import React, { useState } from 'react';
import { Badge, Box, Fab, Paper, Zoom, alpha } from '@mui/material';
import { Bot, MessageCircle } from 'lucide-react';
import { useTheme } from '@mui/material/styles';
import { useParams } from '@tanstack/react-router';
import { useThemeTokens } from '../../../theme/useThemeTokens';
import { useCopilotStatus } from '../api';
import { CopilotSupportBox } from './CopilotSupportBox';

/**
 * Global floating support-style entry for Assessment Copilot.
 * Shown when co-pilot is enabled; used especially when the assessment panel is inaccessible.
 */
export const CopilotFab: React.FC = () => {
  const theme = useTheme();
  const { tokens } = useThemeTokens();
  const params = useParams({ strict: false }) as { projectSlug?: string };
  const projectSlug = params.projectSlug || '';
  const [open, setOpen] = useState(false);
  const { data: status } = useCopilotStatus(projectSlug);

  if (!projectSlug) return null;
  if (status?.settings && status.settings.enabled === false) return null;

  const pending = status?.pending_proposals || 0;

  return (
    <Box
      sx={{
        position: 'fixed',
        right: 24,
        bottom: 24,
        zIndex: theme.zIndex.modal + 2,
        display: 'flex',
        flexDirection: 'column',
        alignItems: 'flex-end',
        gap: 1.5,
      }}
    >
      <Zoom in={open}>
        <Paper
          elevation={8}
          sx={{
            width: { xs: 'calc(100vw - 32px)', sm: 380 },
            maxWidth: '100vw',
            overflow: 'hidden',
            borderRadius: 2,
            border: `1px solid ${alpha(tokens.accent.primary, 0.25)}`,
          }}
        >
          <CopilotSupportBox
            projectSlug={projectSlug}
            compact
            onClose={() => setOpen(false)}
          />
        </Paper>
      </Zoom>

      <Badge badgeContent={pending || undefined} color="error" overlap="circular">
        <Fab
          color="primary"
          aria-label="Open Assessment Copilot"
          onClick={() => setOpen((v) => !v)}
          sx={{
            bgcolor: tokens.accent.primary,
            color: theme.palette.getContrastText(tokens.accent.primary),
            '&:hover': { bgcolor: alpha(tokens.accent.primary, 0.85) },
          }}
        >
          {open ? <MessageCircle size={22} /> : <Bot size={22} />}
        </Fab>
      </Badge>
    </Box>
  );
};
