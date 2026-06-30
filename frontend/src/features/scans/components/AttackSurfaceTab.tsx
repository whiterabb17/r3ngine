import React, { useState, Suspense, useRef, useCallback } from 'react';
import { Box, Typography, CircularProgress, Stack, Button } from '@mui/material';
import { Map as MapIcon } from 'lucide-react';
import { TacticalPanel } from '../../../components/TacticalPanel';
import { GraphNodeDetailPanel } from './GraphNodeDetailPanel';
import { GraphBlastRadiusPanel } from './GraphBlastRadiusPanel';
import { GraphControlPanel } from './GraphControlPanel';
import { GraphCanvas } from './GraphCanvas';
import { useGraphData } from '../api/graphApi';
import { useThemeTokens } from '../../../theme/useThemeTokens';

interface AttackSurfaceTabProps {
  projectSlug: string;
  scanId?: number;
  targetId?: number;
}

const AttackSurfaceContent: React.FC<AttackSurfaceTabProps> = ({ projectSlug, scanId, targetId }) => {
  const { tokens, isLight } = useThemeTokens();
  const [searchQuery, setSearchQuery] = useState('');
  const [layoutName, setLayoutName] = useState<'fcose' | 'klay' | 'cose'>('fcose');
  const cyRef = useRef<cytoscape.Core | null>(null);

  const { data } = useGraphData(projectSlug, scanId, targetId);

  const handleInit = useCallback((cy: cytoscape.Core) => {
    cyRef.current = cy;
  }, []);

  const resetZoom = useCallback(() => {
    cyRef.current?.fit(undefined, 50);
  }, []);

  const refreshLayout = useCallback(() => {
    if (!cyRef.current) return;
    cyRef.current.layout({ 
      name: layoutName,
      animate: true,
      ...(layoutName === 'fcose' ? {
        nodeRepulsion: 4500,
        idealEdgeLength: 100,
      } : layoutName === 'klay' ? {
        klay: { direction: 'DOWN', spacing: 50 }
      } : {})
    } as any).run();
  }, [layoutName]);

  const exportPNG = useCallback(() => {
    if (!cyRef.current) return;
    const pngContent = cyRef.current.png({ full: true, bg: tokens.surface.primary });
    const link = document.createElement('a');
    link.href = pngContent;
    link.download = `attack-surface-${targetId ? 'target-' + targetId : 'scan-' + scanId}.png`;
    link.click();
  }, [scanId, targetId, tokens.surface.primary]);

  return (
    <TacticalPanel title="GRAPH CONTROLS" icon={<MapIcon size={14} />}>
      <GraphControlPanel 
          searchQuery={searchQuery}
          onSearch={setSearchQuery}
          onResetZoom={resetZoom}
          onRefreshLayout={refreshLayout}
          onExport={exportPNG}
          layoutName={layoutName}
          onChangeLayout={setLayoutName}
      />

      <Box sx={{ position: 'relative', bgcolor: tokens.surface.primary, height: '600px', overflow: 'hidden' }}>
        <GraphCanvas 
          data={data} 
          layoutName={layoutName} 
          searchQuery={searchQuery}
          onInit={handleInit}
        />
        
        <Box sx={{ 
          position: 'absolute', 
          bottom: 20, 
          left: 20, 
          bgcolor: tokens.surface.glass, 
          backdropFilter: tokens.effects.blur,
          p: 1.5,
          borderRadius: 1,
          border: `1px solid ${tokens.border.subtle}`,
          zIndex: 2,
          pointerEvents: 'none'
        }}>
            <Typography sx={{ fontSize: '0.6rem', color: 'text.secondary', fontWeight: 900, mb: 1, textTransform: 'uppercase' }}>Legend</Typography>
            <Stack spacing={1}>
              <Stack spacing={0.5}>
                  <Typography sx={{ fontSize: '0.55rem', color: `${tokens.accent.primary}99`, fontWeight: 800 }}>NODE TYPES</Typography>
                  {[
                    { label: 'Domain', color: tokens.accent.info, shape: 'hexagon' },
                    { label: 'Subdomain', color: tokens.accent.success, shape: 'circle' },
                    { label: 'IP Address', color: tokens.accent.warning, shape: 'circle' },
                    { label: 'Vulnerability', color: tokens.accent.error, shape: 'diamond' }
                  ].map(item => (
                    <Stack key={item.label} direction="row" spacing={1} sx={{ alignItems: 'center' }}>
                      <Box sx={{ 
                        width: 8, height: 8, 
                        bgcolor: item.color, 
                        borderRadius: item.shape === 'circle' ? '50%' : 0,
                        transform: item.shape === 'diamond' ? 'rotate(45deg)' : 'none'
                      }} />
                      <Typography sx={{ fontSize: '0.7rem', color: 'text.primary', fontWeight: 600 }}>{item.label}</Typography>
                    </Stack>
                  ))}
              </Stack>
            </Stack>
        </Box>
        
        <Box sx={{ position: 'absolute', top: 0, right: 0, bottom: 0, zIndex: 3, display: 'flex', pointerEvents: 'none' }}>
          <Box sx={{ pointerEvents: 'auto' }}>
            <GraphNodeDetailPanel projectSlug={projectSlug} />
          </Box>
          <Box sx={{ pointerEvents: 'auto' }}>
            <GraphBlastRadiusPanel projectSlug={projectSlug} />
          </Box>
        </Box>
      </Box>
    </TacticalPanel>
  );
};

export const AttackSurfaceTab: React.FC<AttackSurfaceTabProps> = (props) => {
  const { tokens } = useThemeTokens();
  return (
    <Box sx={{ width: '100%', mt: 2 }}>
      <Box sx={{ mb: 4, px: { xs: 2, sm: 0 } }}>
        <Typography variant="h5" sx={{ 
          fontWeight: 900, 
          fontFamily: tokens.headingFont === 'orbitron' ? 'Orbitron' : 'Inter', 
          letterSpacing: { xs: 1, sm: 3 }, 
          color: 'text.primary',
          textTransform: 'uppercase',
          fontSize: { xs: '1.1rem', sm: '1.5rem' }
        }}>
          Attack Surface Map {props.targetId ? `(Target Coverage)` : `(Scan #${props.scanId})`}
        </Typography>
        <Typography sx={{ fontSize: '12px', color: 'text.secondary', mt: 0.5, letterSpacing: 1 }}>
          V3.0 INFRASTRUCTURE GRAPH VISUALIZATION
        </Typography>
      </Box>

      <Suspense fallback={
        <Box sx={{ height: 600, display: 'flex', alignItems: 'center', justifyContent: 'center', bgcolor: tokens.surface.primary, borderRadius: 1, border: 1, borderColor: 'divider' }}>
          <CircularProgress sx={{ color: tokens.accent.primary }} />
        </Box>
      }>
        <AttackSurfaceContent {...props} />
      </Suspense>
    </Box>
  );
};
