import React from 'react';
import { 
  Box, 
  Card, 
  CardContent, 
  Typography, 
  List, 
  Chip
} from '@mui/material';
import { Activity } from 'lucide-react';
import type { DashboardData } from '../api';
import { useThemeTokens } from '../../../theme/useThemeTokens';
import { getSeverityColor, getSurfaceSx } from '../../../theme/semanticColors';

const SeverityChip: React.FC<{ severity: number }> = ({ severity }) => {
  const { isLight, tokens } = useThemeTokens();
  const configs: Record<number, { label: string; color: string }> = {
    4: { label: 'CRITICAL', color: getSeverityColor('critical', tokens) },
    3: { label: 'HIGH', color: getSeverityColor('high', tokens) },
    2: { label: 'MEDIUM', color: getSeverityColor('medium', tokens) },
    1: { label: 'LOW', color: getSeverityColor('low', tokens) },
    0: { label: 'INFO', color: getSeverityColor('info', tokens) },
    [-1]: { label: 'UNKNOWN', color: getSeverityColor('unknown', tokens) }
  };
  const config = configs[severity] || configs[-1];
  return (
    <Chip 
      label={config.label} 
      size="small" 
      sx={{ 
        fontSize: '0.6rem', 
        fontWeight: 800, 
        borderRadius: 1,
        bgcolor: 'transparent',
        border: `1px solid ${config.color}`,
        color: config.color,
        boxShadow: isLight ? 'none' : `0 0 8px ${config.color}80`
      }} 
    />
  );
};

const FeedCard: React.FC<{ title: string; icon: React.ReactNode; iconColor: string; children: React.ReactNode }> = ({ title, icon, iconColor, children }) => {
  const { tokens, isLight } = useThemeTokens();
  return (
    <Card sx={{ 
      height: 500, 
      ...getSurfaceSx(isLight, tokens),
      position: 'relative',
      '&::after': {
        content: '""',
        position: 'absolute',
        top: 0,
        left: 0,
        width: '100%',
        height: '2px',
        background: `linear-gradient(90deg, ${iconColor}, transparent)`
      }
    }}>
      <CardContent sx={{ height: '100%', display: 'flex', flexDirection: 'column' }}>
        <Box sx={{ display: 'flex', alignItems: 'center', mb: 2 }}>
          <Box sx={{ color: iconColor, mr: 1.5, display: 'flex' }}>{icon}</Box>
          <Typography variant="h6" sx={{ 
            fontSize: '0.85rem', 
            fontWeight: 800, 
            textTransform: 'uppercase', 
            letterSpacing: 1.5,
            fontFamily: 'Orbitron',
            color: 'text.primary'
          }}>
            {title}
          </Typography>
        </Box>
        <Box sx={{ mt: 1, flexGrow: 1, overflow: 'auto', pr: 1, '&::-webkit-scrollbar': { width: 4 }, '&::-webkit-scrollbar-thumb': { bgcolor: isLight ? 'rgba(0,0,0,0.1)' : tokens.border.subtle, borderRadius: 2 } }}>
          {children}
        </Box>
      </CardContent>
    </Card>
  );
};

export const ActivityFeed: React.FC<{ data: DashboardData }> = ({ data }) => {
  const { tokens, isLight } = useThemeTokens();
  return (
    <FeedCard 
      title="OPERATIONAL SCAN ACTIVITY" 
      icon={<Activity size={20} />} 
      iconColor={tokens.accent.primary}
    >
      <List sx={{ p: 0 }}>
        {data.activity_feed.length === 0 ? (
          <Typography variant="body2" color="text.secondary">No recent scans.</Typography>
        ) : (
          data.activity_feed.map((scan, i) => (
            <Box 
              key={scan.id} 
              sx={{ 
                mb: 1, 
                p: 1.2, 
                borderRadius: 2, 
                bgcolor: 'action.hover',
                border: `1px solid ${tokens.border.subtle}`,
                position: 'relative',
                overflow: 'hidden',
                transition: 'all 0.2s',
                '&:hover': {
                  bgcolor: 'action.selected',
                  borderColor: tokens.accent.primary,
                  boxShadow: isLight ? 'none' : `0 0 10px ${tokens.accent.primary}33`
                }
              }}
            >
              <Box sx={{ display: 'flex', alignItems: 'center', mb: 1 }}>
                <Box 
                  sx={{ 
                    width: 6, 
                    height: 6, 
                    borderRadius: '50%', 
                    bgcolor: scan.status === 2 ? tokens.accent.success : tokens.accent.warning, 
                    mr: 1.2, 
                    boxShadow: isLight ? 'none' : (scan.status === 2 ? `0 0 8px ${tokens.accent.success}` : `0 0 8px ${tokens.accent.warning}`)
                  }} 
                />
                <Typography variant="body2" sx={{ fontWeight: 800, color: 'text.primary', fontSize: '0.8rem', flex: 1 }}>
                  {scan.title}
                </Typography>
              </Box>

              <Box sx={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between' }}>
                <Box sx={{ 
                  display: 'inline-flex', 
                  alignItems: 'center',
                  px: 1, 
                  py: 0.2, 
                  borderRadius: 0.5, 
                  bgcolor: `${tokens.accent.primary}1A`, 
                  border: `1px solid ${tokens.accent.primary}33`,
                }}>
                  <Typography variant="body2" sx={{ color: tokens.accent.primary, fontWeight: 700, fontSize: '0.65rem' }}>
                    {scan.domain}
                  </Typography>
                </Box>

                <Typography variant="caption" sx={{ color: 'text.secondary', fontSize: '0.65rem' }}>
                  {scan.completed_ago}
                </Typography>
              </Box>
            </Box>
          ))
        )}
      </List>
    </FeedCard>
  );
};
