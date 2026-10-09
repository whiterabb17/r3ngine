import React, { useState, useEffect } from 'react';
import {
  Box,
  Typography,
  Grid,
  Button,
  Card,
  CardContent,
  CardActions,
  Chip,
  IconButton,
  Tooltip,
  CircularProgress,
  Avatar,
  ButtonGroup,
  Menu,
  MenuItem,
  Divider,
  Alert,
  Snackbar,
  LinearProgress
} from '@mui/material';
import {
  MoreVertical,
  RefreshCw,
  Download,
  Trash2,
  ExternalLink,
  Hammer,
  Wrench,
  Shield,
  Zap,
  Cpu,
  Plus,
  Edit3,
  RefreshCcw
} from 'lucide-react';
import { TacticalPanel } from '../../../components/TacticalPanel';
import {
  useToolArsenal,
  useToolVersion,
  useUpdateTool,
  useUninstallTool,
  useAddTool,
  useModifyTool
} from '../api';
import type { InstalledTool } from '../api';
import { useParams } from '@tanstack/react-router';
import { ToolFormModal } from './ToolFormModal';
import { useThemeTokens } from '../../../theme/useThemeTokens';
import { getSafeUrl } from '../../../utils/securityUtils';
import type { ApiErrorLike } from '../../../types/errors';

export const ToolArsenalPage: React.FC = () => {
  const { tokens } = useThemeTokens();
  const { projectSlug } = useParams({ from: '/$projectSlug/settings/tools-arsenal' });
  const [filter, setFilter] = useState<'all' | 'default' | 'custom'>('all');
  const [currentVersions, setCurrentVersions] = useState<Record<number, string>>({});
  const [latestVersions, setLatestVersions] = useState<Record<number, string>>({});
  const [loadingTools, setLoadingTools] = useState<Record<number, boolean>>({});
  const [versionError, setVersionError] = useState<Record<number, string>>({});
  const [anchorEl, setAnchorEl] = useState<{ [key: number]: HTMLElement | null }>({});
  const [snackbar, setSnackbar] = useState<{ open: boolean; message: string; severity: 'success' | 'error' | 'info' }>({
    open: false,
    message: '',
    severity: 'info'
  });

  const [modal, setModal] = useState<{ open: boolean; tool?: InstalledTool }>({
    open: false
  });

  const { data: arsenal, isLoading } = useToolArsenal(projectSlug);
  const fetchVersion = useToolVersion();
  const updateTool = useUpdateTool();
  const uninstallTool = useUninstallTool(projectSlug);
  const addTool = useAddTool(projectSlug);
  const modifyTool = useModifyTool(projectSlug);

  const filteredTools = arsenal?.tools.filter(tool => {
    if (filter === 'default') return tool.is_default;
    if (filter === 'custom') return !tool.is_default;
    return true;
  }) || [];

  // Fetch current versions on mount
  useEffect(() => {
    if (arsenal?.tools) {
      arsenal.tools.forEach(tool => {
        handleFetchVersion(tool.id, 'current');
      });
    }
  }, [arsenal?.tools]);

  const handleFetchVersion = (toolId: number, type: 'current' | 'latest' = 'latest') => {
    setLoadingTools(prev => ({ ...prev, [toolId]: true }));
    setVersionError(prev => ({ ...prev, [toolId]: '' }));

    // Safety timeout to prevent infinite spinning
    const timeoutId = setTimeout(() => {
      setLoadingTools(prev => {
        if (prev[toolId]) {
          setVersionError(err => ({ ...err, [toolId]: 'TIMEOUT' }));
          return { ...prev, [toolId]: false };
        }
        return prev;
      });
    }, 15000);

    fetchVersion.mutate({ toolId, type }, {
      onSuccess: (data) => {
        clearTimeout(timeoutId);
        setLoadingTools(prev => ({ ...prev, [toolId]: false }));
        if (data.status) {
          const version = data.version_number || data.name || 'Unknown';
          if (type === 'current') {
            setCurrentVersions(prev => ({ ...prev, [toolId]: version }));
          } else {
            setLatestVersions(prev => ({ ...prev, [toolId]: version }));
            setSnackbar({ open: true, message: `LATEST VERSION FOR TOOL IS ${version.toUpperCase()}`, severity: 'info' });
          }
        } else {
          setVersionError(prev => ({ ...prev, [toolId]: data.message || 'ERROR' }));
        }
      },
      onError: (caught) => {
        const error = caught as ApiErrorLike;
        clearTimeout(timeoutId);
        setLoadingTools(prev => ({ ...prev, [toolId]: false }));
        setVersionError(prev => ({ ...prev, [toolId]: error?.response?.data?.message || 'UNABLE TO CHECK VERSION' }));
      }
    });
  };

  const handleAction = (action: string, toolId: number, toolName: string) => {
    setSnackbar({ open: true, message: `UPDATING ${toolName.toUpperCase()}...`, severity: 'info' });
    updateTool.mutate(toolId, {
      onSuccess: (data) => {
        setSnackbar({ open: true, message: data.message?.toUpperCase() || `${toolName.toUpperCase()} UPDATED SUCCESSFULLY`, severity: 'success' });
        handleFetchVersion(toolId, 'current');
        setLatestVersions(prev => {
          const newState = { ...prev };
          delete newState[toolId];
          return newState;
        });
      },
      onError: () => {
        setSnackbar({ open: true, message: `FAILED TO UPDATE ${toolName.toUpperCase()}`, severity: 'error' });
      }
    });
  };

  const handleUninstall = (toolId: number, toolName: string) => {
    if (window.confirm(`Are you sure you want to uninstall ${toolName}?`)) {
      uninstallTool.mutate(toolId, {
        onSuccess: () => {
          setSnackbar({ open: true, message: `${toolName} uninstalled`, severity: 'success' });
        }
      });
    }
  };

  const handleFormSubmit = (formData: FormData) => {
    if (modal.tool) {
      modifyTool.mutate({ toolId: modal.tool.id, formData }, {
        onSuccess: (data) => {
          setSnackbar({ open: true, message: data.message || 'Tool updated successfully', severity: 'success' });
          setModal({ open: false });
        },
        onError: (caught) => {
          const error = caught as ApiErrorLike;
          setSnackbar({ open: true, message: error?.response?.data?.message || 'Failed to update tool', severity: 'error' });
        }
      });
    } else {
      addTool.mutate(formData, {
        onSuccess: (data) => {
          setSnackbar({ open: true, message: data.message || 'Tool added successfully', severity: 'success' });
          setModal({ open: false });
        },
        onError: (caught) => {
          const error = caught as ApiErrorLike;
          setSnackbar({ open: true, message: error?.response?.data?.message || 'Failed to add tool', severity: 'error' });
        }
      });
    }
  };

  const handleMenuOpen = (id: number, event: React.MouseEvent<HTMLElement>) => {
    setAnchorEl({ ...anchorEl, [id]: event.currentTarget });
  };

  const handleMenuClose = (id: number) => {
    setAnchorEl({ ...anchorEl, [id]: null });
  };

  if (isLoading) {
    return (
      <Box sx={{ display: 'flex', justifyContent: 'center', p: 10 }}>
        <CircularProgress sx={{ color: tokens.accent.primary }} />
      </Box>
    );
  }

  return (
    <Box sx={{ p: 3 }}>
      <Box sx={{ mb: 4, display: 'flex', justifyContent: 'space-between', alignItems: 'flex-end' }}>
        <Box>
          <Typography variant="h4" sx={{ fontFamily: 'Orbitron', fontWeight: 900, color: 'text.primary', mb: 1, letterSpacing: '2px' }}>
            TOOL ARSENAL
          </Typography>
          <Typography variant="body2" sx={{ color: `${tokens.accent.primary}99`, fontFamily: 'monospace' }}>
            {`// Manage external security components and update routines`}
          </Typography>
        </Box>
        <Box sx={{ display: 'flex', gap: 2 }}>
          <ButtonGroup variant="outlined" size="small">
            {(['all', 'default', 'custom'] as const).map((f) => (
              <Button
                key={f}
                onClick={() => setFilter(f)}
                sx={{
                  bgcolor: filter === f ? `${tokens.accent.primary}1A` : 'transparent',
                  color: filter === f ? tokens.accent.primary : 'text.secondary',
                  borderColor: filter === f ? tokens.accent.primary : `${tokens.accent.primary}4D`,
                  fontFamily: 'Orbitron',
                  fontSize: '10px',
                  px: 2,
                  '&:hover': {
                    borderColor: tokens.accent.primary,
                    bgcolor: `${tokens.accent.primary}0D`
                  }
                }}
              >
                {f.toUpperCase()}
              </Button>
            ))}
          </ButtonGroup>
          <Button
            variant="contained"
            startIcon={<Plus size={18} />}
            onClick={() => setModal({ open: true })}
            sx={{
              bgcolor: tokens.accent.primary,
              color: '#000',
              fontWeight: 'bold',
              fontFamily: 'Orbitron',
              fontSize: '11px',
              '&:hover': { bgcolor: tokens.accent.primary, filter: 'brightness(1.1)' },
              boxShadow: `0 0 15px ${tokens.accent.primary}4D`
            }}
          >
            ADD TOOL
          </Button>
        </Box>
      </Box>

      <Box sx={{
        display: 'grid',
        gridTemplateColumns: {
          xs: '1fr',
          sm: 'repeat(2, 1fr)',
          md: 'repeat(3, 1fr)',
          lg: 'repeat(4, 1fr)',
          xl: 'repeat(5, 1fr)'
        },
        gap: 3,
        width: '100%'
      }}>
        {filteredTools.map((tool) => (
          <Box key={tool.id} sx={{ height: '100%' }}>
            <Card sx={{
              bgcolor: 'background.paper',
              border: 1,
              borderColor: tool.is_default ? `${tokens.accent.primary}26` : `${tokens.accent.secondary}26`,
              height: '580px',
              width: '100%',
              display: 'flex',
              flexDirection: 'column',
              position: 'relative',
              overflow: 'hidden',
              backdropFilter: 'blur(10px)',
              '&:hover': {
                borderColor: tool.is_default ? tokens.accent.primary : tokens.accent.secondary,
                boxShadow: `0 0 20px ${tool.is_default ? `${tokens.accent.primary}1A` : `${tokens.accent.secondary}1A`}`,
                transform: 'translateY(-2px)',
                transition: 'all 0.3s ease'
              }
            }}>
              {/* Top Badge */}
              <Box sx={{
                position: 'absolute',
                top: 0,
                left: 0,
                bgcolor: tool.is_default ? `${tokens.accent.primary}33` : `${tokens.accent.secondary}33`,
                color: tool.is_default ? tokens.accent.primary : tokens.accent.secondary,
                px: 1,
                py: 0.5,
                fontSize: '9px',
                fontWeight: 'bold',
                fontFamily: 'Orbitron',
                display: 'flex',
                alignItems: 'center',
                gap: 0.5,
                zIndex: 1,
                borderBottomRightRadius: '4px',
                border: '1px solid',
                borderColor: 'divider'
              }}>
                <Shield size={10} />
                {tool.is_default ? 'DEFAULT' : 'CUSTOM'}
              </Box>

              {/* Action Menu */}
              <Box sx={{ position: 'absolute', top: 5, right: 5, zIndex: 2 }}>
                <IconButton
                  size="small"
                  onClick={(e) => handleMenuOpen(tool.id, e)}
                  sx={{ color: 'text.disabled', '&:hover': { color: tokens.accent.primary } }}
                >
                  <MoreVertical size={16} />
                </IconButton>
                <Menu
                  anchorEl={anchorEl[tool.id]}
                  open={Boolean(anchorEl[tool.id])}
                  onClose={() => handleMenuClose(tool.id)}
                  slotProps={{
                    paper: {
                      sx: {
                        bgcolor: 'background.paper',
                        color: 'text.primary',
                        border: `1px solid ${tokens.accent.primary}33`,
                        '& .MuiMenuItem-root': { fontSize: '11px', fontFamily: 'Orbitron' },
                        '& .MuiMenuItem-root:hover': { bgcolor: `${tokens.accent.primary}1A` }
                      }
                    }
                  }}
                >
                  <MenuItem onClick={() => { handleMenuClose(tool.id); setModal({ open: true, tool }); }}>
                    <Edit3 size={14} style={{ marginRight: 8, color: tokens.accent.primary }} /> MODIFY
                  </MenuItem>
                  {!tool.is_default && (
                    <MenuItem onClick={() => { handleMenuClose(tool.id); handleUninstall(tool.id, tool.name); }} sx={{ color: 'error.main' }}>
                      <Trash2 size={14} style={{ marginRight: 8 }} /> UNINSTALL
                    </MenuItem>
                  )}
                  <MenuItem onClick={() => { handleMenuClose(tool.id); handleAction('force_pull_latest', tool.id, tool.name); }}>
                    <RefreshCcw size={14} style={{ marginRight: 8, color: '#00e676' }} /> FORCE PULL
                  </MenuItem>
                </Menu>
              </Box>

              <CardContent sx={{ p: 3, pt: 6, display: 'flex', flexDirection: 'column', alignItems: 'center', flexGrow: 1, overflow: 'hidden' }}>
                {/* Logo/Icon */}
                <Avatar
                  src={getSafeUrl(tool.logo_url)}
                  sx={{
                    width: 60,
                    height: 60,
                    mb: 2,
                    bgcolor: 'action.hover',
                    border: '1px solid',
                    borderColor: 'divider'
                  }}
                >
                  {!tool.logo_url && <Hammer size={30} color={`${tokens.accent.primary}66`} />}
                </Avatar>

                <Box sx={{ height: '45px', display: 'flex', alignItems: 'center', justifyContent: 'center', mb: 1 }}>
                  <Typography variant="h6" sx={{
                    fontFamily: 'Orbitron',
                    fontWeight: 'bold',
                    color: 'text.primary',
                    textAlign: 'center',
                    fontSize: '18px',
                    letterSpacing: '1px',
                    display: '-webkit-box',
                    WebkitLineClamp: 2,
                    WebkitBoxOrient: 'vertical',
                    overflow: 'hidden'
                  }}>
                    {tool.name.toUpperCase()}
                  </Typography>
                </Box>

                <Box sx={{ display: 'flex', gap: 2, mb: 2 }}>
                  <Typography component="a" href={getSafeUrl(tool.github_url) ?? '#'} target="_blank" sx={{ color: 'text.disabled', fontSize: '10px', display: 'flex', alignItems: 'center', gap: 0.5, textDecoration: 'none', '&:hover': { color: tokens.accent.primary } }}>
                    GITHUB <ExternalLink size={10} />
                  </Typography>
                  {tool.license_url && (
                    <Typography component="a" href={getSafeUrl(tool.license_url) ?? '#'} target="_blank" sx={{ color: 'text.disabled', fontSize: '10px', display: 'flex', alignItems: 'center', gap: 0.5, textDecoration: 'none', '&:hover': { color: tokens.accent.primary } }}>
                      LICENSE <ExternalLink size={10} />
                    </Typography>
                  )}
                </Box>

                {/* Divider */}
                <Box sx={{ width: '40px', height: '2px', bgcolor: tool.is_default ? tokens.accent.primary : tokens.accent.secondary, mb: 3, opacity: 0.5 }} />

                {/* Version Section */}
                <Box sx={{ textAlign: 'center', mb: 3 }}>
                  <Typography sx={{ color: tokens.accent.secondary, fontSize: '9px', fontFamily: 'Orbitron', fontWeight: 'bold', letterSpacing: '1px', mb: 1 }}>
                    INSTALLED VERSION
                  </Typography>
                  <Box sx={{
                    bgcolor: 'action.hover',
                    px: 2,
                    py: 0.5,
                    borderRadius: '4px',
                    border: 1,
                    borderColor: versionError[tool.id] ? 'error.main' : 'divider',
                    display: 'inline-block',
                    minWidth: '80px'
                  }}>
                    <Typography sx={{
                      color: versionError[tool.id] ? 'error.main' : (currentVersions[tool.id] ? tokens.accent.primary : 'text.disabled'),
                      fontSize: versionError[tool.id] ? '9px' : '13px',
                      fontFamily: 'monospace',
                      fontWeight: 'bold'
                    }}>
                      {versionError[tool.id]
                        ? versionError[tool.id].toUpperCase()
                        : (currentVersions[tool.id] || 'NOT DETECTED')}
                    </Typography>
                  </Box>

                  {latestVersions[tool.id] && latestVersions[tool.id] !== currentVersions[tool.id] && (
                    <Box sx={{ mt: 1 }}>
                      <Typography sx={{ color: '#00e676', fontSize: '9px', fontFamily: 'Orbitron', fontWeight: 'bold' }}>
                        NEW VERSION AVAILABLE: {latestVersions[tool.id]}
                      </Typography>
                    </Box>
                  )}
                </Box>

                {/* Description Area - Grows but fits in fixed height card */}
                <Box sx={{
                  flexGrow: 1,
                  width: '100%',
                  overflowY: 'auto',
                  mb: 2,
                  px: 1,
                  display: 'flex',
                  flexDirection: 'column',
                  '&::-webkit-scrollbar': { width: '4px' },
                  '&::-webkit-scrollbar-thumb': { bgcolor: `${tokens.accent.primary}1A`, borderRadius: '10px' }
                }}>
                  <Typography variant="body2" sx={{
                    color: 'text.secondary',
                    textAlign: 'center',
                    fontSize: '11px',
                    lineHeight: 1.6,
                  }}>
                    {tool.description}
                  </Typography>
                </Box>

                <Box sx={{ mt: 'auto', width: '100%', pt: 2 }}>
                  <Button
                    fullWidth
                    variant={latestVersions[tool.id] && latestVersions[tool.id] !== currentVersions[tool.id] ? "contained" : "outlined"}
                    startIcon={loadingTools[tool.id] ? <CircularProgress size={14} color="inherit" /> : (latestVersions[tool.id] && latestVersions[tool.id] !== currentVersions[tool.id] ? <Download size={14} /> : <RefreshCcw size={14} />)}
                    onClick={() => {
                      if (latestVersions[tool.id] && latestVersions[tool.id] !== currentVersions[tool.id]) {
                        handleAction('update', tool.id, tool.name);
                      } else {
                        handleFetchVersion(tool.id, 'latest');
                      }
                    }}
                    disabled={loadingTools[tool.id]}
                    sx={{
                      borderColor: latestVersions[tool.id] && latestVersions[tool.id] !== currentVersions[tool.id] ? '#00e676' : `${tokens.accent.primary}33`,
                      bgcolor: latestVersions[tool.id] && latestVersions[tool.id] !== currentVersions[tool.id] ? '#00e676' : 'transparent',
                      color: latestVersions[tool.id] && latestVersions[tool.id] !== currentVersions[tool.id] ? '#000' : tokens.accent.primary,
                      fontSize: '10px',
                      fontWeight: 'bold',
                      fontFamily: 'Orbitron',
                      py: 1,
                      '&:hover': {
                        bgcolor: latestVersions[tool.id] && latestVersions[tool.id] !== currentVersions[tool.id] ? '#00c853' : `${tokens.accent.primary}1A`,
                        borderColor: tokens.accent.primary
                      }
                    }}
                  >
                    {loadingTools[tool.id]
                      ? 'PROCESSING...'
                      : (latestVersions[tool.id] && latestVersions[tool.id] !== currentVersions[tool.id] ? 'INSTALL UPDATE' : 'CHECK UPDATE')}
                  </Button>
                </Box>
              </CardContent>
              {loadingTools[tool.id] && <LinearProgress sx={{ position: 'absolute', bottom: 0, left: 0, right: 0, height: 2, bgcolor: 'transparent', '& .MuiLinearProgress-bar': { bgcolor: tokens.accent.primary } }} />}
            </Card>
          </Box>
        ))}
      </Box>

      <ToolFormModal
        open={modal.open}
        tool={modal.tool}
        onClose={() => setModal({ open: false })}
        onSubmit={handleFormSubmit}
      />

      <Snackbar
        open={snackbar.open}
        autoHideDuration={6000}
        onClose={() => setSnackbar({ ...snackbar, open: false })}
      >
        <Alert
          onClose={() => setSnackbar({ ...snackbar, open: false })}
          severity={snackbar.severity}
          sx={{
            width: '100%',
            bgcolor: snackbar.severity === 'success' ? '#00c853' : snackbar.severity === 'error' ? '#ff1744' : '#2979ff',
            color: '#000',
            fontWeight: 'bold',
            fontFamily: 'Orbitron',
            fontSize: '12px'
          }}
        >
          {snackbar.message.toUpperCase()}
        </Alert>
      </Snackbar>

      <style>
        {`
          @keyframes spin {
            from { transform: rotate(0deg); }
            to { transform: rotate(360deg); }
          }
          .animate-spin {
            animation: spin 2s linear infinite;
          }
        `}
      </style>
    </Box>
  );
};

