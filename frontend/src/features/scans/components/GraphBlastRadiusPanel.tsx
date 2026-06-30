import React from 'react';
import { Box, Typography, Stack, CircularProgress, Button } from '@mui/material';
import { useGraphStore } from '../../../store/useGraphStore';
import { ArrowLeft, Crosshair } from 'lucide-react';
import { useGraphBlastRadius } from '../api/graphApi';
import { useThemeTokens } from '../../../theme/useThemeTokens';

interface Props {
  projectSlug: string;
}

export const GraphBlastRadiusPanel: React.FC<Props> = ({ projectSlug }) => {
  const { tokens, isLight } = useThemeTokens();
  const { selectedNodeId, selectedNodeData, activePanel, setActivePanel } = useGraphStore();
  
  const { data, isLoading } = useGraphBlastRadius(
    projectSlug, 
    activePanel === 'blastRadius' ? selectedNodeId : null
  );

  if (!selectedNodeId || activePanel !== 'blastRadius') return null;

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
      <Box sx={{ display: 'flex', alignItems: 'center', gap: 1 }}>
        <Button 
            size="small" 
            onClick={() => setActivePanel('details')}
            sx={{ minWidth: 0, p: 0.5, color: 'text.secondary' }}
        >
            <ArrowLeft size={16} />
        </Button>
        <Typography sx={{ color: tokens.accent.primary, fontWeight: 800, fontSize: '14px', fontFamily: tokens.headingFont === 'orbitron' ? 'Orbitron' : 'Inter' }}>
          BLAST RADIUS
        </Typography>
      </Box>

      {isLoading ? (
        <Box sx={{ display: 'flex', justifyContent: 'center', p: 4 }}>
          <CircularProgress size={24} sx={{ color: tokens.accent.primary }} />
        </Box>
      ) : data ? (
        <Stack spacing={2}>
            <Box sx={{ bgcolor: `${tokens.severity.critical}1A`, p: 2, borderRadius: 1, border: `1px solid ${tokens.severity.critical}33` }}>
                <Typography sx={{ fontSize: '12px', color: tokens.severity.critical, fontWeight: 700, mb: 1, display: 'flex', alignItems: 'center', gap: 1 }}>
                    <Crosshair size={14} /> COMPROMISED ASSETS
                </Typography>
                <Typography sx={{ fontSize: '24px', color: tokens.severity.critical, fontWeight: 900 }}>
                    {data.nodes?.length || 0}
                </Typography>
                <Typography sx={{ fontSize: '11px', color: 'text.secondary', mt: 1 }}>
                    Downstream assets exposed if {selectedNodeData?.label} is breached.
                </Typography>
            </Box>

            <Box sx={{ bgcolor: 'action.hover', p: 1.5, borderRadius: 1, border: 1, borderColor: 'divider' }}>
                <Typography sx={{ fontSize: '10px', color: 'text.secondary', mb: 1, fontWeight: 700 }}>AFFECTED NODES</Typography>
                <Stack spacing={1}>
                {data.nodes?.map((n: any) => (
                    <Box key={n.data.id} sx={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', p: 1, bgcolor: tokens.surface.primary, border: 1, borderColor: 'divider', borderRadius: 1 }}>
                        <Typography sx={{ fontSize: '11px', color: 'text.primary', fontWeight: 500, wordBreak: 'break-all' }}>
                            {n.data.label}
                        </Typography>
                        <Typography sx={{ fontSize: '9px', color: n.data.color, fontWeight: 700, ml: 1 }}>
                            {n.data.type}
                        </Typography>
                    </Box>
                ))}
                </Stack>
            </Box>
        </Stack>
      ) : (
        <Typography sx={{ color: 'text.secondary', fontSize: '12px' }}>Failed to compute blast radius.</Typography>
      )}
    </Box>
  );
};
