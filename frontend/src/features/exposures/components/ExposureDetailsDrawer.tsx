import React, { useState } from 'react';
import {
  Drawer, Box, Typography, IconButton, Divider,
  List, ListItem, ListItemText, Chip, Stack, Button, Snackbar, Alert,
} from '@mui/material';
import CloseIcon from '@mui/icons-material/Close';
import { useParams, Link } from '@tanstack/react-router';
import type { Exposure } from '../types';
import { useThemeTokens } from '@/theme/useThemeTokens';
import { useMutateExposureStatus } from '../api/useExposures';

function EvidenceValue({ data }: { data: Record<string, unknown> }) {
  const primary = (data?.url ?? data?.name ?? data?.value) as string | undefined;
  if (primary) {
    return <span>{primary}</span>;
  }
  const entries = Object.entries(data).filter(([, v]) => v !== null && v !== undefined);
  if (entries.length === 0) return <span style={{ fontStyle: 'italic' }}>No details</span>;
  return (
    <Box component="ul" sx={{ m: 0, pl: 2, listStyle: 'none' }}>
      {entries.map(([k, v]) => (
        <Box component="li" key={k} sx={{ fontSize: '0.72rem', color: 'text.secondary' }}>
          <Box component="span" sx={{ fontWeight: 600, color: 'text.primary', mr: 0.5 }}>
            {k}:
          </Box>
          {String(v)}
        </Box>
      ))}
    </Box>
  );
}

interface ExposureDetailsDrawerProps {
  exposure: Exposure;
  onClose: () => void;
}

export const ExposureDetailsDrawer: React.FC<ExposureDetailsDrawerProps> = ({ exposure, onClose }) => {
  const { tokens } = useThemeTokens();
  const { projectSlug } = useParams({ strict: false });
  const [snackbar, setSnackbar] = useState<{
    open: boolean;
    message: string;
    severity: 'success' | 'error';
  }>({ open: false, message: '', severity: 'success' });

  const mutateStatus = useMutateExposureStatus(
    () => {
      setSnackbar({ open: true, message: 'Exposure status updated', severity: 'success' });
      // Brief delay so the user sees the success message before the drawer closes
      setTimeout(onClose, 900);
    },
    (msg) => setSnackbar({ open: true, message: msg, severity: 'error' }),
  );

  return (
    <>
      <Drawer
        anchor="right"
        open={Boolean(exposure)}
        onClose={onClose}
        sx={{
          '& .MuiDrawer-paper': {
            width: { xs: '100%', sm: 450 },
            backgroundColor: 'background.paper',
            backgroundImage: 'none',
            display: 'flex',
            flexDirection: 'column',
          },
        }}
      >
        {/* Header */}
        <Box sx={{ p: 3, display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
          <Typography variant="h5" sx={{ color: 'text.primary', fontWeight: 700 }}>
            Exposure Details
          </Typography>
          <IconButton onClick={onClose} sx={{ color: 'text.secondary' }}>
            <CloseIcon />
          </IconButton>
        </Box>
        <Divider sx={{ borderColor: tokens.border.subtle }} />

        {/* Scrollable body */}
        <Box sx={{ p: 3, flex: 1, overflowY: 'auto' }}>
          <Stack direction="row" spacing={1} sx={{ flexWrap: 'wrap', mb: 2 }}>
            {exposure.type && exposure.type.length > 0 ? (
              exposure.type.map((t) => (
                <Chip
                  key={t}
                  label={t}
                  size="small"
                  sx={{
                    backgroundColor: tokens.surface.secondary,
                    color: tokens.text.primary,
                    fontWeight: 600,
                    borderRadius: 1,
                  }}
                />
              ))
            ) : (
              <Typography variant="body2" color="text.secondary">
                Unclassified Asset
              </Typography>
            )}
          </Stack>

          <Stack direction="row" spacing={1} sx={{ mb: 3 }}>
            <Chip label={`Status: ${exposure.status}`} size="small" variant="outlined" />
            <Chip
              label={`Risk Score: ${exposure.risk_score.toFixed(1)}`}
              size="small"
              sx={{
                backgroundColor:
                  exposure.risk_score >= 7 ? `${tokens.accent.error}15` :
                  exposure.risk_score >= 4 ? `${tokens.accent.warning}15` :
                  `${tokens.accent.info}15`,
                color:
                  exposure.risk_score >= 7 ? tokens.accent.error :
                  exposure.risk_score >= 4 ? tokens.accent.warning :
                  tokens.accent.info,
              }}
            />
          </Stack>

          <Typography variant="subtitle1" sx={{ color: 'text.primary', fontWeight: 600, mb: 1 }}>
            Evidence ({exposure.evidence?.length || 0})
          </Typography>
          <List sx={{ mb: 2 }}>
            {exposure.evidence?.map((ev) => (
              <ListItem key={ev.id} sx={{ px: 0, py: 0.5 }}>
                <ListItemText
                  primary={
                    <Typography variant="body2" sx={{ color: 'text.primary' }}>
                      <Box
                        component="span"
                        sx={{
                          fontWeight: 600,
                          mr: 1,
                          textTransform: 'uppercase',
                          fontSize: '0.75rem',
                          color: 'text.secondary',
                        }}
                      >
                        {ev.source_tool}
                      </Box>
                      <EvidenceValue data={ev.evidence_data} />
                    </Typography>
                  }
                  secondary={
                    ev.timestamp && (
                      <Typography variant="caption" sx={{ color: 'text.disabled', fontSize: '0.68rem' }}>
                        {new Date(ev.timestamp).toLocaleString()}
                      </Typography>
                    )
                  }
                />
              </ListItem>
            ))}
            {(!exposure.evidence || exposure.evidence.length === 0) && (
              <Typography variant="body2" sx={{ color: 'text.secondary' }}>
                No evidence recorded.
              </Typography>
            )}
          </List>

          <Divider sx={{ borderColor: tokens.border.subtle, my: 2 }} />

          <Typography variant="subtitle1" sx={{ color: 'text.primary', fontWeight: 600, mb: 1 }}>
            Correlated Vulnerabilities ({exposure.vulnerabilities?.length || 0})
          </Typography>
          <List>
            {exposure.vulnerabilities?.map((vuln) => (
              <ListItem
                key={vuln.id}
                sx={{ px: 0, py: 1, borderBottom: `1px solid ${tokens.border.subtle}` }}
              >
                <ListItemText
                  primary={
                    projectSlug ? (
                      <Link
                        to={`/$projectSlug/vulns`}
                        params={{ projectSlug }}
                        style={{ textDecoration: 'none' }}
                      >
                        <Typography
                          variant="body2"
                          sx={{
                            color: tokens.accent.primary,
                            fontWeight: 500,
                            '&:hover': { textDecoration: 'underline' },
                          }}
                        >
                          {vuln.name}
                        </Typography>
                      </Link>
                    ) : (
                      <Typography variant="body2" sx={{ color: 'text.primary', fontWeight: 500 }}>
                        {vuln.name}
                      </Typography>
                    )
                  }
                  secondary={
                    <Typography variant="caption" sx={{ color: 'text.secondary' }}>
                      Severity: {vuln.severity}
                    </Typography>
                  }
                />
              </ListItem>
            ))}
            {(!exposure.vulnerabilities || exposure.vulnerabilities.length === 0) && (
              <Typography variant="body2" sx={{ color: 'text.secondary' }}>
                No correlated vulnerabilities.
              </Typography>
            )}
          </List>
        </Box>

        {/* Sticky action footer — only shown for open exposures */}
        {exposure.status === 'open' && (
          <Box sx={{ p: 3, borderTop: `1px solid ${tokens.border.subtle}` }}>
            <Typography variant="caption" sx={{ color: 'text.secondary', display: 'block', mb: 1.5 }}>
              Review the evidence above before acting.
            </Typography>
            <Stack direction="row" spacing={1}>
              <Button
                variant="contained"
                disabled={mutateStatus.isPending}
                sx={{
                  backgroundColor: `${tokens.accent.success}1A`,
                  color: tokens.accent.success,
                  '&:hover': { backgroundColor: `${tokens.accent.success}30` },
                }}
                onClick={() => mutateStatus.mutate({ id: exposure.id, status: 'remediated' })}
              >
                {mutateStatus.isPending ? 'Saving…' : 'Mark Resolved'}
              </Button>
              <Button
                variant="outlined"
                color="inherit"
                disabled={mutateStatus.isPending}
                onClick={() => mutateStatus.mutate({ id: exposure.id, status: 'false_positive' })}
              >
                False Positive
              </Button>
            </Stack>
          </Box>
        )}
      </Drawer>

      <Snackbar
        open={snackbar.open}
        autoHideDuration={3000}
        onClose={() => setSnackbar((s) => ({ ...s, open: false }))}
        anchorOrigin={{ vertical: 'bottom', horizontal: 'center' }}
      >
        <Alert
          severity={snackbar.severity}
          onClose={() => setSnackbar((s) => ({ ...s, open: false }))}
        >
          {snackbar.message}
        </Alert>
      </Snackbar>
    </>
  );
};
