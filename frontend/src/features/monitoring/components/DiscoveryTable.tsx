import React from 'react';
import { 
  Box, 
  Card, 
  CardContent, 
  Typography, 
  Table, 
  TableBody, 
  TableCell, 
  TableContainer, 
  TableHead, 
  TableRow,
  Chip,
  IconButton,
  Tooltip
} from '@mui/material';
import { Eye, ExternalLink, ShieldAlert } from 'lucide-react';
import { Link } from '@tanstack/react-router';
import type { MonitoringDiscovery } from '../types';
import { useThemeTokens } from '../../../theme/useThemeTokens';
import { getSurfaceSx } from '../../../theme/semanticColors';

export const DiscoveryTable: React.FC<{ discoveries: MonitoringDiscovery[], projectSlug: string }> = ({ discoveries, projectSlug }) => {
  const { tokens, isLight } = useThemeTokens();
  const getTypeColor = (type: string) => {
    switch (type.toLowerCase()) {
      case 'subdomain': return tokens.accent.success;
      case 'ip': return tokens.accent.primary;
      case 'vhost': return '#7000ff';
      case 'directory': return '#ff00ff';
      case 'login': return tokens.accent.warning;
      case 'status_change': return tokens.accent.error;
      default: return tokens.text.primary;
    }
  };

  return (
    <Card sx={{ 
      ...getSurfaceSx(isLight, tokens),
      mt: 3
    }}>
      <CardContent sx={{ p: 0 }}>
        <Box sx={{ p: 2, borderBottom: `1px solid ${tokens.border.subtle}`, display: 'flex', alignItems: 'center', gap: 2 }}>
          <ShieldAlert size={20} color={tokens.accent.primary} />
          <Typography variant="h6" sx={{ fontSize: '0.9rem', fontWeight: 900, fontFamily: 'Orbitron', letterSpacing: 1 }}>
            RECENT DISCOVERIES LOG
          </Typography>
        </Box>
        <TableContainer>
          <Table sx={{ minWidth: 650 }}>
            <TableHead sx={{ bgcolor: 'action.hover' }}>
              <TableRow>
                <TableCell sx={{ color: 'text.secondary', fontWeight: 700, fontSize: '0.7rem', textTransform: 'uppercase' }}>Type</TableCell>
                <TableCell sx={{ color: 'text.secondary', fontWeight: 700, fontSize: '0.7rem', textTransform: 'uppercase' }}>Target</TableCell>
                <TableCell sx={{ color: 'text.secondary', fontWeight: 700, fontSize: '0.7rem', textTransform: 'uppercase' }}>Discovery</TableCell>
                <TableCell sx={{ color: 'text.secondary', fontWeight: 700, fontSize: '0.7rem', textTransform: 'uppercase' }}>Details</TableCell>
                <TableCell sx={{ color: 'text.secondary', fontWeight: 700, fontSize: '0.7rem', textTransform: 'uppercase' }}>Date</TableCell>
                <TableCell sx={{ color: 'text.secondary', fontWeight: 700, fontSize: '0.7rem', textTransform: 'uppercase', textAlign: 'right' }}>Actions</TableCell>
              </TableRow>
            </TableHead>
            <TableBody>
              {discoveries.map((discovery) => {
                const color = getTypeColor(discovery.discovery_type);
                const content = typeof discovery.content === 'string' ? JSON.parse(discovery.content) : discovery.content;
                return (
                  <TableRow key={discovery.id} sx={{ '&:hover': { bgcolor: 'action.hover' }, borderBottom: `1px solid ${tokens.border.subtle}` }}>
                    <TableCell>
                      <Chip 
                        label={discovery.discovery_type.toUpperCase()} 
                        size="small" 
                        sx={{ 
                          height: 20, 
                          fontSize: '0.6rem', 
                          fontWeight: 900, 
                          bgcolor: `${color}15`, 
                          color: color,
                          border: `1px solid ${color}33`,
                          borderRadius: 0.5
                        }} 
                      />
                    </TableCell>
                    <TableCell>
                      <Typography variant="body2" sx={{ fontWeight: 600, color: 'text.primary' }}>
                        {discovery.domain_name}
                      </Typography>
                    </TableCell>
                    <TableCell>
                      <Typography variant="body2" sx={{ color: 'text.secondary', fontSize: '0.8rem' }}>
                        {content.name || content.url || 'N/A'}
                      </Typography>
                    </TableCell>
                    <TableCell>
                      <Box sx={{ display: 'flex', gap: 1 }}>
                        {content.status && (
                          <Chip 
                            label={content.status} 
                            size="small" 
                            variant="outlined" 
                            sx={{ height: 18, fontSize: '0.6rem', color: 'text.secondary' }} 
                          />
                        )}
                        {content.title && (
                          <Typography variant="caption" sx={{ opacity: 0.4 }}>
                            {content.title.substring(0, 30)}...
                          </Typography>
                        )}
                      </Box>
                    </TableCell>
                    <TableCell sx={{ color: 'text.secondary', fontSize: '0.75rem' }}>
                      {new Date(discovery.discovered_at).toLocaleString()}
                    </TableCell>
                    <TableCell align="right">
                      {discovery.scan_history_id && (
                        <Tooltip title="View Scan History">
                          <IconButton 
                            component={Link} 
                            to={`/projects/${projectSlug}/scans/${discovery.scan_history_id}`}
                            size="small" 
                            sx={{ color: 'primary.main', '&:hover': { bgcolor: 'primary.main', color: '#000' } }}
                          >
                            <Eye size={16} />
                          </IconButton>
                        </Tooltip>
                      )}
                    </TableCell>
                  </TableRow>
                );
              })}
            </TableBody>
          </Table>
        </TableContainer>
      </CardContent>
    </Card>
  );
};
