import React from 'react';
import {
  Table,
  TableBody,
  TableCell,
  TableContainer,
  TableHead,
  TableRow,
  Paper,
  Checkbox,
  IconButton,
  Tooltip,
  Box,
  Typography,
  Badge,
} from '@mui/material';
import { Edit2, Trash2, Zap, Clock } from 'lucide-react';
import type { Organization } from '../orgTypes';

const formatRelativeTime = (dateString: string) => {
  const date = new Date(dateString);
  const now = new Date();
  const diffInSeconds = Math.floor((now.getTime() - date.getTime()) / 1000);
  
  if (diffInSeconds < 60) return 'just now';
  if (diffInSeconds < 3600) return `${Math.floor(diffInSeconds / 60)}m ago`;
  if (diffInSeconds < 86400) return `${Math.floor(diffInSeconds / 3600)}h ago`;
  return `${Math.floor(diffInSeconds / 86400)}d ago`;
};

interface OrganizationTableProps {
  organizations: Organization[];
  selectedIds: number[];
  onToggleSelect: (id: number) => void;
  onSelectAll: (checked: boolean) => void;
  onEdit: (org: Organization) => void;
  onDelete: (id: number) => void;
  projectSlug: string;
}

export const OrganizationTable: React.FC<OrganizationTableProps> = ({
  organizations,
  selectedIds,
  onToggleSelect,
  onSelectAll,
  onEdit,
  onDelete,
  projectSlug,
}) => {
  const isAllSelected = organizations.length > 0 && selectedIds.length === organizations.length;

  return (
    <TableContainer component={Paper} sx={{ 
      backgroundColor: 'transparent', 
      backgroundImage: 'none',
      boxShadow: 'none',
      overflowX: 'auto'
    }}>
      <Table sx={{ minWidth: 650 }} aria-label="organization table">
        <TableHead>
          <TableRow sx={{ borderBottom: '2px solid #1a1a2e' }}>
            <TableCell padding="checkbox">
              <Checkbox
                checked={isAllSelected}
                onChange={(e) => onSelectAll(e.target.checked)}
                sx={{ color: '#1a1a2e', '&.Mui-checked': { color: '#00f3ff' } }}
              />
            </TableCell>
            <TableCell sx={{ color: '#00f3ff', fontWeight: 'bold', textTransform: 'uppercase', fontFamily: 'Orbitron', fontSize: '0.75rem', letterSpacing: '1px' }}>Organization</TableCell>
            <TableCell sx={{ color: '#00f3ff', fontWeight: 'bold', textTransform: 'uppercase', fontFamily: 'Orbitron', fontSize: '0.75rem', letterSpacing: '1px' }}>Description</TableCell>
            <TableCell align="center" sx={{ color: '#00f3ff', fontWeight: 'bold', textTransform: 'uppercase', fontFamily: 'Orbitron', fontSize: '0.75rem', letterSpacing: '1px' }}>Total Targets</TableCell>
            <TableCell align="center" sx={{ color: '#00f3ff', fontWeight: 'bold', textTransform: 'uppercase', fontFamily: 'Orbitron', fontSize: '0.75rem', letterSpacing: '1px' }}>Added</TableCell>
            <TableCell align="right" sx={{ color: '#00f3ff', fontWeight: 'bold', textTransform: 'uppercase', fontFamily: 'Orbitron', fontSize: '0.75rem', letterSpacing: '1px' }}>Actions</TableCell>
          </TableRow>
        </TableHead>
        <TableBody>
          {organizations.map((org) => (
            <TableRow
              key={org.id}
              sx={{ 
                '&:hover': { backgroundColor: 'rgba(0, 243, 255, 0.03)' },
                borderBottom: '1px solid #1a1a2e'
              }}
            >
              <TableCell padding="checkbox">
                <Checkbox
                  checked={selectedIds.includes(org.id)}
                  onChange={() => onToggleSelect(org.id)}
                  sx={{ color: '#1a1a2e', '&.Mui-checked': { color: '#00f3ff' } }}
                />
              </TableCell>
              <TableCell sx={{ color: 'text.primary' }}>
                <Typography variant="body1" sx={{ fontWeight: 500 }}>
                  {org.name}
                </Typography>
              </TableCell>
              <TableCell sx={{ color: 'text.secondary' }}>
                {org.description || '—'}
              </TableCell>
              <TableCell align="center">
                <Badge 
                  badgeContent={org.domains?.length || 0} 
                  color="primary"
                  sx={{ 
                    '& .MuiBadge-badge': { 
                      background: 'rgba(0, 243, 255, 0.2)', 
                      color: '#00f3ff',
                      border: '1px solid rgba(0, 243, 255, 0.3)'
                    } 
                  }}
                />
              </TableCell>
              <TableCell align="center" sx={{ color: 'text.secondary', fontSize: '0.875rem' }}>
                <Tooltip title={new Date(org.insert_date).toLocaleString()}>
                  <span>{formatRelativeTime(org.insert_date)}</span>
                </Tooltip>
              </TableCell>
              <TableCell align="right">
                <Box sx={{ display: 'flex', justifyContent: 'flex-end', gap: 1 }}>
                  <Tooltip title="Initiate Scan">
                    <IconButton size="small" sx={{ color: '#00f3ff', '&:hover': { backgroundColor: 'rgba(0, 243, 255, 0.1)' } }}>
                      <Zap size={18} />
                    </IconButton>
                  </Tooltip>
                  <Tooltip title="Schedule Scan">
                    <IconButton size="small" sx={{ color: 'text.secondary', '&:hover': { color: 'text.primary', backgroundColor: 'rgba(255, 255, 255, 0.05)' } }}>
                      <Clock size={18} />
                    </IconButton>
                  </Tooltip>
                  <Tooltip title="Edit">
                    <IconButton 
                      size="small" 
                      onClick={() => onEdit(org)}
                      sx={{ color: '#00f3ff', '&:hover': { backgroundColor: 'rgba(0, 243, 255, 0.1)' } }}
                    >
                      <Edit2 size={18} />
                    </IconButton>
                  </Tooltip>
                  <Tooltip title="Delete">
                    <IconButton 
                      size="small" 
                      onClick={() => onDelete(org.id)}
                      sx={{ color: '#ff003c', '&:hover': { backgroundColor: 'rgba(255, 0, 60, 0.1)' } }}
                    >
                      <Trash2 size={18} />
                    </IconButton>
                  </Tooltip>
                </Box>
              </TableCell>
            </TableRow>
          ))}
        </TableBody>
      </Table>
    </TableContainer>
  );
};
