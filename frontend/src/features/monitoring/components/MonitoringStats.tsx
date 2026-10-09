import React from 'react';
import { Grid, Card, CardContent, Typography, Box } from '@mui/material';
import { Monitor, Globe, Link, Lock, type LucideProps } from 'lucide-react';
import type { MonitoringStats as StatsType } from '../types';
import { useThemeTokens } from '../../../theme/useThemeTokens';
import { getSurfaceSx } from '../../../theme/semanticColors';

const StatCard: React.FC<{
  title: string;
  value: number;
  /** A lucide icon element; it is cloned at two sizes. */
  icon: React.ReactElement<LucideProps>;
  color: string;
}> = ({ title, value, icon, color }) => {
  const { tokens, isLight } = useThemeTokens();
  return (
  <Card sx={{ 
    ...getSurfaceSx(isLight, tokens),
    position: 'relative',
    overflow: 'hidden'
  }}>
    <Box sx={{ 
      position: 'absolute', 
      top: -10, 
      right: -10, 
      opacity: 0.1, 
      transform: 'rotate(-15deg)' 
    }}>
      {React.cloneElement(icon, { size: 80, color })}
    </Box>
    <CardContent>
      <Box sx={{ display: 'flex', alignItems: 'center', gap: 2, mb: 1 }}>
        <Box sx={{ 
          p: 1, 
          borderRadius: 1, 
          bgcolor: `${color}15`, 
          color,
          display: 'flex',
          alignItems: 'center',
          justifyContent: 'center',
          boxShadow: `0 0 15px ${color}33`
        }}>
          {React.cloneElement(icon, { size: 20 })}
        </Box>
        <Typography variant="body2" sx={{ color: 'text.secondary', fontWeight: 600, letterSpacing: 1 }}>
          {title.toUpperCase()}
        </Typography>
      </Box>
      <Typography variant="h4" sx={{ 
        fontWeight: 900, 
        fontFamily: 'Orbitron',
        color: 'text.primary',
        textShadow: isLight ? 'none' : `0 0 10px ${color}66`
      }}>
        {value.toLocaleString()}
      </Typography>
    </CardContent>
  </Card>
  );
};

export const MonitoringStats: React.FC<{ stats: StatsType }> = ({ stats }) => {
  const { tokens } = useThemeTokens();
  return (
    <Grid container spacing={3}>
      <Grid size={{ xs: 12, sm: 6, md: 3 }}>
        <StatCard 
          title="Total Discoveries" 
          value={stats.total_discoveries} 
          icon={<Monitor />} 
          color={tokens.accent.primary} 
        />
      </Grid>
      <Grid size={{ xs: 12, sm: 6, md: 3 }}>
        <StatCard 
          title="New Subdomains" 
          value={stats.subdomain_discoveries} 
          icon={<Globe />} 
          color={tokens.accent.success} 
        />
      </Grid>
      <Grid size={{ xs: 12, sm: 6, md: 3 }}>
        <StatCard 
          title="New Directories" 
          value={stats.endpoint_discoveries} 
          icon={<Link />} 
          color="#7000ff" 
        />
      </Grid>
      <Grid size={{ xs: 12, sm: 6, md: 3 }}>
        <StatCard 
          title="Login Pages" 
          value={stats.login_discoveries} 
          icon={<Lock />} 
          color={tokens.accent.warning} 
        />
      </Grid>
    </Grid>
  );
};
