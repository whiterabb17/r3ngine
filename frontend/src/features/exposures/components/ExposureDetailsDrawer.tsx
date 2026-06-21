import React from 'react';
import { Drawer, Box, Typography, IconButton, Divider, List, ListItem, ListItemText, Chip, Stack } from '@mui/material';
import CloseIcon from '@mui/icons-material/Close';
import type { Exposure } from '../types';
import { useThemeTokens } from '@/theme/useThemeTokens';

interface ExposureDetailsDrawerProps {
  exposure: Exposure;
  onClose: () => void;
}

export const ExposureDetailsDrawer: React.FC<ExposureDetailsDrawerProps> = ({ exposure, onClose }) => {
  const { tokens } = useThemeTokens();

  return (
    <Drawer
      anchor="right"
      open={Boolean(exposure)}
      onClose={onClose}
      sx={{
        '& .MuiDrawer-paper': {
          width: { xs: '100%', sm: 450 },
          backgroundColor: 'background.paper',
          backgroundImage: 'none',
        }
      }}
    >
      <Box sx={{ p: 3, display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
        <Typography variant="h5" sx={{ color: 'text.primary', fontWeight: 700 }}>
          Exposure Details
        </Typography>
        <IconButton onClick={onClose} sx={{ color: 'text.secondary' }}>
          <CloseIcon />
        </IconButton>
      </Box>
      <Divider sx={{ borderColor: tokens.border.subtle }} />

      <Box sx={{ p: 3 }}>
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
                  borderRadius: 1
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
              backgroundColor: exposure.risk_score >= 7 ? `${tokens.accent.error}15` :
                exposure.risk_score >= 4 ? `${tokens.accent.warning}15` :
                  `${tokens.accent.info}15`,
              color: exposure.risk_score >= 7 ? tokens.accent.error :
                exposure.risk_score >= 4 ? tokens.accent.warning :
                  tokens.accent.info,
            }}
          />
        </Stack>

        <Typography variant="subtitle1" sx={{ color: 'text.primary', fontWeight: 600, mb: 1 }}>
          Evidence ({exposure.evidence?.length || 0})
        </Typography>
        <List sx={{ mb: 2 }}>
          {exposure.evidence?.map(ev => (
            <ListItem key={ev.id} sx={{ px: 0, py: 0.5 }}>
              <ListItemText
                primary={
                  <Typography variant="body2" sx={{ color: 'text.primary' }}>
                    <Box component="span" sx={{ fontWeight: 600, mr: 1, textTransform: 'uppercase', fontSize: '0.75rem', color: 'text.secondary' }}>
                      {ev.source_tool}
                    </Box>
                    {ev.evidence_data?.url as string || ev.evidence_data?.name as string || JSON.stringify(ev.evidence_data)}
                  </Typography>
                }
              />
            </ListItem>
          ))}
          {(!exposure.evidence || exposure.evidence.length === 0) && (
            <Typography variant="body2" sx={{ color: 'text.secondary' }}>No evidence recorded.</Typography>
          )}
        </List>

        <Divider sx={{ borderColor: tokens.border.subtle, my: 2 }} />

        <Typography variant="subtitle1" sx={{ color: 'text.primary', fontWeight: 600, mb: 1 }}>
          Correlated Vulnerabilities ({exposure.vulnerabilities?.length || 0})
        </Typography>
        <List>
          {exposure.vulnerabilities?.map(vuln => (
            <ListItem key={vuln.id} sx={{ px: 0, py: 1, borderBottom: `1px solid ${tokens.border.subtle}` }}>
              <ListItemText
                primary={
                  <Typography variant="body2" sx={{ color: 'text.primary', fontWeight: 500 }}>
                    {vuln.name}
                  </Typography>
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
            <Typography variant="body2" sx={{ color: 'text.secondary' }}>No correlated vulnerabilities.</Typography>
          )}
        </List>
      </Box>
    </Drawer>
  );
};
