import React from 'react';
import { Box, Typography, Stack, CircularProgress, Chip, Button } from '@mui/material';
import { useGraphStore } from '../../../store/useGraphStore';
import { ShieldAlert, Activity } from 'lucide-react';
import { useGraphNodeDetails, useCreateTicket } from '../api/graphApi';
import { useThemeTokens } from '../../../theme/useThemeTokens';

interface Props {
  projectSlug: string;
}

export const GraphNodeDetailPanel: React.FC<Props> = ({ projectSlug }) => {
  const { tokens, theme } = useThemeTokens();
  const { selectedNodeId, selectedNodeData, activePanel, setActivePanel } = useGraphStore();
  
  const { data: details, isLoading } = useGraphNodeDetails(
    projectSlug, 
    activePanel === 'details' ? selectedNodeId : null
  );
  
  const { mutate: createTicket } = useCreateTicket(projectSlug);

  const handleCreateTicket = () => {
    if (!selectedNodeId) return;
    createTicket(selectedNodeId, {
      onSuccess: (res) => alert(res.message || 'Ticket created'),
      onError: (e) => console.error(e)
    });
  };

  if (!selectedNodeId || activePanel !== 'details') return null;

  return (
    <Box sx={{
      width: 350,
      bgcolor: tokens.surface.glass,
      backdropFilter: tokens.effects.blur,
      borderLeft: `1px solid ${tokens.border.subtle}`,
      p: 2,
      display: 'flex',
      flexDirection: 'column',
      gap: 2,
      height: '100%',
      overflowY: 'auto'
    }}>
      <Box sx={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
        <Typography sx={{ color: tokens.accent.primary, fontWeight: 800, fontSize: '14px', fontFamily: tokens.headingFont === 'orbitron' ? 'Orbitron' : 'Inter' }}>
          NODE DETAILS
        </Typography>
        <Chip label={selectedNodeData?.type} size="small" sx={{ bgcolor: `${tokens.accent.primary}15`, color: tokens.accent.primary, fontSize: '10px' }} />
      </Box>

      {isLoading ? (
        <Box sx={{ display: 'flex', justifyContent: 'center', p: 4 }}>
          <CircularProgress size={24} sx={{ color: tokens.accent.primary }} />
        </Box>
      ) : details ? (
        <Stack spacing={2}>
          <Typography sx={{ color: 'text.primary', fontSize: '16px', fontWeight: 600, wordBreak: 'break-all' }}>
            {selectedNodeData?.label}
          </Typography>

          <Box sx={{ bgcolor: 'action.hover', p: 1.5, borderRadius: 1, border: 1, borderColor: 'divider' }}>
            <Typography sx={{ fontSize: '10px', color: 'text.secondary', mb: 1, fontWeight: 700 }}>PROPERTIES</Typography>
            <Stack spacing={1}>
              {Object.entries(details.properties || {}).map(([k, v]) => (
                <Box key={k} sx={{ display: 'flex', justifyContent: 'space-between' }}>
                  <Typography sx={{ fontSize: '11px', color: 'text.secondary' }}>{k}</Typography>
                  <Typography sx={{ fontSize: '11px', color: 'text.primary', fontWeight: 500, maxWidth: '60%', textAlign: 'right', wordBreak: 'break-all' }}>
                    {String(v)}
                  </Typography>
                </Box>
              ))}
            </Stack>
          </Box>

          <Box sx={{ display: 'flex', gap: 1 }}>
            <Box sx={{ flex: 1, bgcolor: `${tokens.severity.critical}1A`, p: 1, borderRadius: 1, border: `1px solid ${tokens.severity.critical}33`, textAlign: 'center' }}>
              <Typography sx={{ fontSize: '18px', color: tokens.severity.critical, fontWeight: 800 }}>{selectedNodeData?.criticalVulnCount || 0}</Typography>
              <Typography sx={{ fontSize: '9px', color: tokens.severity.critical, fontWeight: 700 }}>CRITICAL</Typography>
            </Box>
            <Box sx={{ flex: 1, bgcolor: `${tokens.severity.high}1A`, p: 1, borderRadius: 1, border: `1px solid ${tokens.severity.high}33`, textAlign: 'center' }}>
              <Typography sx={{ fontSize: '18px', color: tokens.severity.high, fontWeight: 800 }}>{selectedNodeData?.highVulnCount || 0}</Typography>
              <Typography sx={{ fontSize: '9px', color: tokens.severity.high, fontWeight: 700 }}>HIGH</Typography>
            </Box>
            <Box sx={{ flex: 1, bgcolor: `${tokens.accent.primary}15`, p: 1, borderRadius: 1, border: `1px solid ${tokens.accent.primary}33`, textAlign: 'center' }}>
              <Typography sx={{ fontSize: '18px', color: tokens.accent.primary, fontWeight: 800 }}>{selectedNodeData?.degree_centrality || 0}</Typography>
              <Typography sx={{ fontSize: '9px', color: `${tokens.accent.primary}CC`, fontWeight: 700 }}>EDGES</Typography>
            </Box>
          </Box>

          <Stack spacing={1}>
            <Button 
              fullWidth 
              variant="outlined" 
              startIcon={<Activity size={14} />}
              onClick={() => setActivePanel('blastRadius')}
              sx={{ borderColor: `${tokens.accent.primary}4D`, color: tokens.accent.primary, fontSize: '11px', fontWeight: 700 }}
            >
              COMPUTE BLAST RADIUS
            </Button>
            <Button 
              fullWidth 
              variant="contained" 
              startIcon={<ShieldAlert size={14} />}
              onClick={handleCreateTicket}
              sx={{ 
                bgcolor: tokens.severity.critical, 
                color: theme.palette.common.white,
                fontSize: '11px', 
                fontWeight: 700, 
                '&:hover': { bgcolor: theme.palette.error.dark } 
              }}
            >
              CREATE TICKET
            </Button>
          </Stack>
        </Stack>
      ) : (
        <Typography sx={{ color: 'text.secondary', fontSize: '12px' }}>Failed to load details.</Typography>
      )}
    </Box>
  );
};
