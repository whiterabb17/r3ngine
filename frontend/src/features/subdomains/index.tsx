import React, { useState } from 'react';
import { useParams } from '@tanstack/react-router';
import {
  Box,
  Container,
  Typography,
  Grid,
  InputBase,
  Button,
  IconButton,
  Tooltip,
  CircularProgress,
  Pagination,
  Stack,
  Avatar,
  Menu,
  MenuItem,
  ListItemIcon,
  ListItemText,
  Chip,
  Backdrop,
  Select,
  FormControl
} from '@mui/material';
import {
  Search,
  Zap,
  Eye,
  FilePlus,
  MoreHorizontal,
  Download,
  Filter,
  LayoutGrid,
  ChevronRight,
  ExternalLink,
  Shield,
  ShieldOff,
  AlertTriangle,
  Trash2,
  Copy,
  FileText
} from 'lucide-react';

import { useThemeTokens } from '../../theme/useThemeTokens';
import { getHttpStatusColor } from '../../theme/semanticColors';
import { useSubdomains } from './api';
import { TacticalPanel } from '../../components/TacticalPanel';

export const SubdomainsPage: React.FC = () => {
  const { tokens } = useThemeTokens();

  const getStatusColor = (status: number) => getHttpStatusColor(status, tokens);
  const { projectSlug } = useParams({ from: '/$projectSlug/subdomains' });
  const [page, setPage] = useState(1);
  const [pageSize, setPageSize] = useState(10);
  const [searchQuery, setSearchQuery] = useState('');
  const [activeSearch, setActiveSearch] = useState('');
  const [anchorEl, setAnchorEl] = useState<null | HTMLElement>(null);
  const [selectedAssets, setSelectedAssets] = useState<number[]>([]);

  const { data, isLoading } = useSubdomains(projectSlug, page, activeSearch, undefined, false, undefined, undefined, pageSize);
  const [isReady, setIsReady] = useState(false);

  // Tactical Render Delay to ensure huge data-tables don't "white-screen" during paint
  React.useEffect(() => {
    if (!isLoading && data) {
      const timer = setTimeout(() => setIsReady(true), 100);
      return () => clearTimeout(timer);
    } else {
      setIsReady(false);
    }
  }, [isLoading, data]);

  const toggleSelectAll = () => {
    if (selectedAssets.length === data?.results.length) {
      setSelectedAssets([]);
    } else {
      setSelectedAssets(data?.results.map(s => s.id) || []);
    }
  };

  const toggleSelectAsset = (id: number) => {
    setSelectedAssets(prev =>
      prev.includes(id) ? prev.filter(i => i !== id) : [...prev, id]
    );
  };

  const handleSearch = () => {
    setPage(1);
    setActiveSearch(searchQuery);
  };

  const handleActionClick = (event: React.MouseEvent<HTMLButtonElement>) => {
    setAnchorEl(event.currentTarget);
  };

  const handleActionClose = () => {
    setAnchorEl(null);
  };

  return (
    <Container maxWidth="xl" sx={{ py: 4 }}>
      {/* Tactical Header */}
      <Box sx={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', mb: 4 }}>
        <Box>
          <Typography variant="h5" sx={{
            fontWeight: 900,
            fontFamily: 'Orbitron',
            letterSpacing: 3,
            color: 'text.primary',
            textTransform: 'uppercase'
          }}>
            Subdomain Inventory
          </Typography>
          <Typography sx={{ fontSize: '12px', color: 'text.secondary', mt: 0.5, letterSpacing: 1 }}>
            V3.0 PROJECT ASSET RECON ACTIVE
          </Typography>
        </Box>
        <Box sx={{ display: 'flex', alignItems: 'center', gap: 1 }}>
          <Typography sx={{ fontSize: '10px', fontWeight: 800, color: 'text.secondary', letterSpacing: 2 }}>DASHBOARD</Typography>
          <ChevronRight size={12} style={{ color: tokens.accent.secondary }} />
          <Typography sx={{ fontSize: '10px', fontWeight: 800, color: 'text.primary', letterSpacing: 2 }}>SUBDOMAINS</Typography>
        </Box>
      </Box>

      {/* Enterprise-Grade Search Bar */}
      <Box sx={{
        display: 'flex',
        bgcolor: 'action.hover',
        borderRadius: '4px',
        overflow: 'hidden',
        mb: 3,
        border: 1,
        borderColor: 'divider',
        '&:focus-within': {
          borderColor: 'rgba(0, 243, 255, 0.4)',
          boxShadow: '0 0 15px rgba(0, 243, 255, 0.1)'
        },
        transition: 'all 0.2s'
      }}>
        <Box sx={{ display: 'flex', alignItems: 'center', pl: 2, color: 'text.disabled' }}>
          <Search size={18} />
        </Box>
        <InputBase
          placeholder="Filter Subdomains (e.g. name=google.com, http_status=200)"
          value={searchQuery}
          onChange={(e) => setSearchQuery(e.target.value)}
          onKeyPress={(e) => e.key === 'Enter' && handleSearch()}
          sx={{
            flex: 1,
            px: 2,
            py: 1,
            fontSize: '0.9rem',
            color: 'text.primary',
            '&::placeholder': { color: 'text.disabled', opacity: 1 }
          }}
        />
        <Button
          onClick={handleSearch}
          sx={{
            bgcolor: `${tokens.accent.primary}15`,
            color: tokens.accent.primary,
            px: 4,
            borderRadius: 0,
            fontWeight: 700,
            fontSize: '11px',
            letterSpacing: 1,
            borderLeft: '1px solid rgba(0, 243, 255, 0.1)',
            '&:hover': { bgcolor: 'rgba(0, 243, 255, 0.2)' }
          }}
        >
          SEARCH
        </Button>
      </Box>

      {/* Tactical Panel */}
      <TacticalPanel>
        {/* Tactical Table Header (Legacy Parity) */}
        <Box sx={{
          p: 2,
          display: 'flex',
          alignItems: 'center',
          justifyContent: 'space-between',
          borderBottom: '1px solid rgba(255,255,255,0.05)',
          bgcolor: 'rgba(255,255,255,0.01)'
        }}>
          <Box sx={{ display: 'flex', alignItems: 'center', gap: 2 }}>
            <Box sx={{ display: 'flex', alignItems: 'center', gap: 1 }}>
              <Typography sx={{ fontSize: '11px', fontWeight: 600, color: 'text.secondary' }}>Results :</Typography>
              <Box sx={{ px: 1, py: 0.5, bgcolor: 'rgba(255,255,255,0.05)', border: '1px solid rgba(255,255,255,0.1)', borderRadius: 1 }}>
                <Typography sx={{ fontSize: '11px', color: 'text.primary', fontWeight: 700 }}>50</Typography>
              </Box>
            </Box>
            <Box sx={{ px: 3, py: 0.8, bgcolor: 'rgba(255,255,255,0.03)', borderRadius: 1, border: '1px solid rgba(255,255,255,0.1)' }}>
              <Typography sx={{ fontSize: '11px', fontWeight: 700, color: 'text.secondary', letterSpacing: 0.5 }}>
                Showing page {page} of {Math.ceil((data?.count || 0) / 50) || 1}
              </Typography>
            </Box>
          </Box>
          <Box sx={{ display: 'flex', gap: 1 }}>
            {selectedAssets.length > 0 && (
              <Button size="small" variant="contained" sx={{ bgcolor: '#ff003c', color: '#fff', fontSize: '10px', fontWeight: 800, '&:hover': { bgcolor: '#cc0030' } }}>
                DELETE SELECTED ({selectedAssets.length})
              </Button>
            )}
            <IconButton size="small" sx={{ color: '#00f3ff', bgcolor: 'rgba(0, 243, 255, 0.05)', border: '1px solid rgba(0, 243, 255, 0.1)', borderRadius: 1 }}>
              <Download size={14} />
            </IconButton>
          </Box>
        </Box>

        {/* Responsive Subdomains Table */}
        <Box sx={{
          overflowX: 'auto',
          width: '100%',
          '&::-webkit-scrollbar': { height: '6px' },
          '&::-webkit-scrollbar-thumb': { bgcolor: 'rgba(0, 243, 255, 0.2)', borderRadius: '3px' }
        }}>
          <table style={{ width: '100%', borderCollapse: 'collapse', minWidth: '1200px', tableLayout: 'fixed' }}>
            <thead>
              <tr style={{
                textAlign: 'left',
                borderBottom: '1px solid rgba(255,255,255,0.1)',
                backgroundColor: 'rgba(255,255,255,0.02)'
              }}>
                <th style={{ width: '40px', padding: '12px 16px', textAlign: 'center' }}>
                  <input
                    type="checkbox"
                    checked={selectedAssets.length === data?.results.length && data?.results.length > 0}
                    onChange={toggleSelectAll}
                    style={{ width: '14px', height: '14px', accentColor: '#00f3ff', cursor: 'pointer', opacity: 0.6 }}
                  />
                </th>
                <th style={{ width: '220px', padding: '12px 16px', color: '#00f3ff', fontSize: '10px', fontWeight: 900, letterSpacing: 1.5, fontFamily: 'Orbitron' }}>SUBDOMAIN</th>
                <th style={{ width: '100px', padding: '12px 16px', color: '#00f3ff', fontSize: '10px', fontWeight: 900, letterSpacing: 1.5, fontFamily: 'Orbitron' }}>STATUS</th>
                <th style={{ width: '150px', padding: '12px 16px', color: '#00f3ff', fontSize: '10px', fontWeight: 900, letterSpacing: 1.5, fontFamily: 'Orbitron' }}>IP</th>
                <th style={{ width: '200px', padding: '12px 16px', color: '#00f3ff', fontSize: '10px', fontWeight: 900, letterSpacing: 1.5, fontFamily: 'Orbitron' }}>PORTS</th>
                <th style={{ width: '100px', padding: '12px 16px', color: '#00f3ff', fontSize: '10px', fontWeight: 900, letterSpacing: 1.5, fontFamily: 'Orbitron' }}>CONTENT</th>
                <th style={{ width: '100px', padding: '12px 16px', color: '#00f3ff', fontSize: '10px', fontWeight: 900, letterSpacing: 1.5, fontFamily: 'Orbitron' }}>TIME</th>
                <th style={{ width: '100px', padding: '12px 16px', color: '#00f3ff', fontSize: '10px', fontWeight: 900, letterSpacing: 1.5, fontFamily: 'Orbitron' }}>SCREENSHOT</th>
                <th style={{ width: '120px', padding: '12px 16px', color: '#00f3ff', fontSize: '10px', fontWeight: 900, letterSpacing: 1.5, fontFamily: 'Orbitron' }}>ACTION</th>
              </tr>
            </thead>
            <tbody>
              {isLoading ? (
                <tr>
                  <td colSpan={9} style={{ padding: '80px', textAlign: 'center' }}>
                    <Box sx={{ display: 'flex', flexDirection: 'column', alignItems: 'center', gap: 2 }}>
                      <CircularProgress size={32} sx={{ color: '#00f3ff', filter: 'drop-shadow(0 0 8px #00f3ff)' }} />
                      <Typography sx={{
                        fontSize: '10px',
                        fontWeight: 900,
                        color: 'rgba(0, 243, 255, 0.5)',
                        fontFamily: 'Orbitron',
                        letterSpacing: 2,
                        textTransform: 'uppercase'
                      }}>
                        System Fetching Subdomains...
                      </Typography>
                    </Box>
                  </td>
                </tr>
              ) : data?.results.map((sub) => (
                <tr key={sub.id} style={{
                  borderBottom: '1px solid rgba(255,255,255,0.05)',
                  backgroundColor: selectedAssets.includes(sub.id) ? 'rgba(0, 243, 255, 0.02)' : (sub.is_important ? 'rgba(255, 0, 60, 0.03)' : 'transparent'),
                  transition: 'background 0.2s'
                }}>
                  <td style={{ padding: '12px 16px', verticalAlign: 'middle', textAlign: 'center' }}>
                    <input
                      type="checkbox"
                      checked={selectedAssets.includes(sub.id)}
                      onChange={() => toggleSelectAsset(sub.id)}
                      style={{
                        width: '14px',
                        height: '14px',
                        accentColor: '#00f3ff',
                        cursor: 'pointer',
                        opacity: 0.6
                      }}
                    />
                  </td>
                  <td style={{ padding: '12px 16px' }}>
                    <Box sx={{ display: 'flex', flexDirection: 'column', gap: 0.5 }}>
                      <Box sx={{ display: 'flex', alignItems: 'center', gap: 1 }}>
                        <Typography sx={{ fontSize: '13px', fontWeight: 700, color: 'text.primary', letterSpacing: 0.2 }}>{sub.name}</Typography>
                        <IconButton size="small" sx={{ p: 0.2, color: 'text.secondary', '&:hover': { color: '#00f3ff' } }}>
                          <Copy size={12} />
                        </IconButton>
                      </Box>

                      {/* Asset Intelligence Badges (Legacy Feature) */}
                      <Box sx={{ display: 'flex', gap: 1.5, mt: 0.5 }}>
                        <Box sx={{ display: 'flex', alignItems: 'center', gap: 0.5 }}>
                          <Typography sx={{ fontSize: '9px', fontWeight: 800, color: 'text.secondary', display: 'flex', alignItems: 'center', gap: 0.5 }}>
                            <Zap size={10} style={{ color: '#00f3ff' }} /> {sub.subscan_count || 0}
                          </Typography>
                        </Box>
                        <Box sx={{ display: 'flex', alignItems: 'center', gap: 0.5 }}>
                          <Typography sx={{ fontSize: '9px', fontWeight: 800, color: 'text.secondary', display: 'flex', alignItems: 'center', gap: 0.5 }}>
                            <ExternalLink size={10} style={{ color: '#7000ff' }} /> {sub.endpoint_count || 0}
                          </Typography>
                        </Box>
                        <Box sx={{ display: 'flex', alignItems: 'center', gap: 0.5 }}>
                          <Typography sx={{ fontSize: '9px', fontWeight: 800, color: 'text.secondary', display: 'flex', alignItems: 'center', gap: 0.5 }}>
                            <AlertTriangle size={10} style={{ color: '#ff003c' }} /> {sub.critical_count || 0}
                          </Typography>
                        </Box>
                        {sub.info_count > 0 && (
                          <Chip label={`${sub.info_count} Info`} size="small" sx={{ height: 14, fontSize: '7px', fontWeight: 900, bgcolor: 'rgba(0, 243, 255, 0.1)', color: '#00f3ff', borderRadius: 0.5 }} />
                        )}
                      </Box>
                    </Box>
                  </td>
                  <td style={{ padding: '12px 16px' }}>
                    <Box sx={{
                      display: 'inline-flex',
                      px: 1.2,
                      py: 0.4,
                      borderRadius: 0.5,
                      bgcolor: `${getStatusColor(sub.http_status)}20`,
                      border: `1px solid ${getStatusColor(sub.http_status)}40`,
                    }}>
                      <Typography sx={{ fontSize: '11px', fontWeight: 900, color: getStatusColor(sub.http_status) }}>
                        {sub.http_status || '404'}
                      </Typography>
                    </Box>
                  </td>
                  <td style={{ padding: '12px 16px' }}>
                    <Box sx={{ display: 'flex', flexWrap: 'wrap', gap: 0.5 }}>
                      {sub.ip_addresses?.map(ip => (
                        <Typography
                          key={`ip-${sub.id}-${ip.id}`}
                          sx={{
                            fontSize: '11px',
                            color: ip.is_cdn ? '#ffae00' : 'text.secondary',
                            fontFamily: 'monospace',
                            fontWeight: 600
                          }}
                        >
                          {ip.address}
                        </Typography>
                      ))}
                    </Box>
                  </td>
                  <td style={{ padding: '12px 16px' }}>
                    <Box sx={{ display: 'flex', flexWrap: 'wrap', gap: 0.5 }}>
                      {sub.ip_addresses?.flatMap(ip => ip.ports.map(port => ({ ...port, ipId: ip.id }))).map(port => (
                        <Box
                          key={`port-${sub.id}-${port.ipId}-${port.id}`}
                          sx={{
                            px: 1,
                            py: 0.2,
                            borderRadius: 0.5,
                            bgcolor: port.is_uncommon ? 'rgba(255, 0, 60, 0.1)' : 'rgba(255,255,255,0.05)',
                            border: '1px solid rgba(255,255,255,0.1)'
                          }}
                        >
                          <Typography sx={{ fontSize: '9px', fontWeight: 800, color: port.is_uncommon ? '#ff003c' : 'text.secondary' }}>
                            {port.number}/{port.service_name}
                          </Typography>
                        </Box>
                      ))}
                    </Box>
                  </td>
                  <td style={{ padding: '12px 16px' }}>
                    <Typography sx={{ fontSize: '11px', color: 'text.secondary', fontFamily: 'monospace', fontWeight: 600 }}>
                      {sub.content_length?.toLocaleString() || '0'}
                    </Typography>
                  </td>
                  <td style={{ padding: '12px 16px' }}>
                    <Typography sx={{ fontSize: '11px', color: '#ff003c', fontFamily: 'monospace', fontWeight: 700 }}>
                      {sub.response_time ? `${sub.response_time.toFixed(4)}s` : '-'}
                    </Typography>
                  </td>
                  <td style={{ padding: '12px 16px' }}>
                    {(() => {
                      const ssPath = sub.screenshot_path || sub.screenshots?.[0]?.screenshot_path || null;
                      return ssPath ? (
                        <Box sx={{
                          width: 50,
                          height: 30,
                          borderRadius: 0.5,
                          overflow: 'hidden',
                          border: '1px solid rgba(255,255,255,0.1)',
                          cursor: 'pointer',
                          '&:hover': { borderColor: '#00f3ff', transform: 'scale(1.5)', zIndex: 10 },
                          transition: 'all 0.2s'
                        }}>
                          <img
                            src={`/media/${ssPath}`}
                            alt="Visual"
                            style={{ width: '100%', height: '100%', objectFit: 'cover' }}
                          />
                        </Box>
                      ) : (
                        <Box sx={{ width: 50, height: 30, borderRadius: 0.5, bgcolor: 'rgba(255,255,255,0.02)', border: '1px dashed rgba(255,255,255,0.05)', display: 'flex', alignItems: 'center', justifyContent: 'center' }}>
                          <Typography sx={{ fontSize: '6px', color: 'text.disabled' }}>NULL</Typography>
                        </Box>
                      );
                    })()}
                  </td>
                  <td style={{ padding: '12px 16px' }}>
                    <Box sx={{ display: 'flex', gap: 0.5 }}>
                      <Tooltip title="Show Attack Surface">
                        <IconButton size="small" sx={{ color: '#00f3ff', bgcolor: 'rgba(0, 243, 255, 0.05)', p: 0.5 }}>
                          <Eye size={14} />
                        </IconButton>
                      </Tooltip>
                      <Tooltip title="Further Scan Subdomain">
                        <IconButton size="small" sx={{ color: '#00ffaa', bgcolor: 'rgba(0, 255, 170, 0.05)', p: 0.5 }}>
                          <Zap size={14} />
                        </IconButton>
                      </Tooltip>
                      <Tooltip title="Add Recon TODO/Note">
                        <IconButton size="small" sx={{ color: '#ffae00', bgcolor: 'rgba(255, 174, 0, 0.05)', p: 0.5 }}>
                          <FileText size={14} />
                        </IconButton>
                      </Tooltip>
                      <IconButton size="small" onClick={handleActionClick} sx={{ color: 'text.secondary', p: 0.5 }}>
                        <MoreHorizontal size={14} />
                      </IconButton>
                    </Box>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </Box>

        {/* Tactical Pagination */}
        <Box sx={{ p: 2, display: 'flex', justifyContent: 'center', borderTop: '1px solid rgba(255,255,255,0.05)' }}>
          <Box sx={{ display: 'flex', justifyContent: 'center', alignItems: 'center', mt: 4, mb: 4, gap: 2 }}>
            <Pagination
              count={Math.ceil((data?.count || 0) / pageSize)}
              page={page}
              onChange={(_, v) => setPage(v)}
              size="small"
              sx={{
                '& .MuiPaginationItem-root': {
                  color: 'text.secondary',
                  borderColor: 'rgba(255,255,255,0.1)',
                  fontFamily: 'Orbitron',
                  fontSize: '10px',
                  '&.Mui-selected': {
                    bgcolor: 'rgba(0, 243, 255, 0.1)',
                    color: '#00f3ff',
                    borderColor: 'rgba(0, 243, 255, 0.3)',
                  },
                  '&:hover': {
                    bgcolor: 'rgba(255,255,255,0.05)',
                  }
                }
              }}
            />
            <FormControl size="small" variant="outlined" sx={{ minWidth: 100 }}>
              <Select
                value={pageSize}
                onChange={(e) => {
                  setPageSize(Number(e.target.value));
                  setPage(1);
                }}
                sx={{
                  color: '#00f3ff',
                  bgcolor: 'rgba(0, 243, 255, 0.05)',
                  '& .MuiOutlinedInput-notchedOutline': { borderColor: 'rgba(0, 243, 255, 0.2)' },
                  '&:hover .MuiOutlinedInput-notchedOutline': { borderColor: 'rgba(0, 243, 255, 0.4)' },
                  '&.Mui-focused .MuiOutlinedInput-notchedOutline': { borderColor: '#00f3ff' },
                  '& .MuiSvgIcon-root': { color: '#00f3ff' },
                  fontSize: '0.75rem',
                  height: '28px',
                }}
              >
                <MenuItem value={10}>10 items</MenuItem>
                <MenuItem value={20}>20 items</MenuItem>
                <MenuItem value={50}>50 items</MenuItem>
              </Select>
            </FormControl>
          </Box>
        </Box>
      </TacticalPanel>

      {/* Action Menu */}
      <Menu
        anchorEl={anchorEl}
        open={Boolean(anchorEl)}
        onClose={handleActionClose}
        slotProps={{
          paper: {
            sx: {
              bgcolor: '#001a24',
              border: '1px solid rgba(0, 243, 255, 0.2)',
              color: '#fff',
              '& .MuiMenuItem-root': {
                fontSize: '12px',
                fontWeight: 600,
                fontFamily: 'Inter',
                '&:hover': { bgcolor: 'rgba(0, 243, 255, 0.1)' }
              }
            }
          }
        }}
      >
        <MenuItem onClick={handleActionClose}>
          <ListItemIcon><Eye size={16} color="#00f3ff" /></ListItemIcon>
          <ListItemText primary="ATTACK SURFACE" />
        </MenuItem>
        <MenuItem onClick={handleActionClose}>
          <ListItemIcon><Zap size={16} color="#00f3ff" /></ListItemIcon>
          <ListItemText primary="INITIATE SCAN" />
        </MenuItem>
        <MenuItem onClick={handleActionClose}>
          <ListItemIcon><FilePlus size={16} color="#00f3ff" /></ListItemIcon>
          <ListItemText primary="ADD NOTE" />
        </MenuItem>
        <MenuItem onClick={handleActionClose} sx={{ color: '#ffae00' }}>
          <ListItemIcon><Shield size={16} color="#ffae00" /></ListItemIcon>
          <ListItemText primary="MARK IMPORTANT" />
        </MenuItem>
        <MenuItem onClick={handleActionClose} sx={{ color: '#ff003c' }}>
          <ListItemIcon><Trash2 size={16} color="#ff003c" /></ListItemIcon>
          <ListItemText primary="DELETE ASSET" />
        </MenuItem>
      </Menu>

      {/* <style>{`
        @keyframes pulse {
          0% { transform: scale(1); opacity: 1; }
          50% { transform: scale(1.2); opacity: 0.7; }
          100% { transform: scale(1); opacity: 1; }
        }
      `}</style> */}
    </Container>
  );
};
