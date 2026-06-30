import React, { useState } from 'react';
import {
  Dialog,
  DialogTitle,
  DialogContent,
  DialogActions,
  Button,
  TextField,
  Box,
  Typography,
  IconButton,
  MenuItem,
  CircularProgress,
  Alert,
  Switch,
  FormControlLabel,
  Collapse,
  Divider,
  alpha
} from '@mui/material';
import { X, Target, Globe, Building2, Terminal, Activity, Clock, Settings2, Search, Zap, ListX, Map } from 'lucide-react';
import { useAddTarget, useOrganizations, useEngines, useResolveIP } from '../api';
import { Checkbox, List, ListItem, ListItemButton, ListItemIcon, ListItemText } from '@mui/material';
import { useThemeTokens } from '../../../theme/useThemeTokens';
import { getDialogPaperSx, getFieldSx } from '../../../theme/semanticColors';

const TARGET_TYPES = [
  { value: 'domain',         label: 'Domain',            placeholder: 'example.com',                     description: 'Full domain scan (7-tier pipeline)' },
  { value: 'host',           label: 'Host',               placeholder: 'target.example.com',              description: 'Host/hostname reconnaissance' },
  { value: 'ip',             label: 'IP Address',         placeholder: '192.0.2.1',                       description: 'Single IP reconnaissance' },
  { value: 'url',            label: 'URL',                placeholder: 'https://example.com',             description: 'URL crawl and vulnerability scan' },
  { value: 'cidr',           label: 'CIDR / Network',     placeholder: '192.168.0.0/24',                  description: 'Network range discovery' },
  { value: 'email',          label: 'Email',              placeholder: 'user@example.com',                description: 'Email breach hunt (h8mail + maigret)' },
  { value: 'username',       label: 'Username',           placeholder: 'johndoe',                         description: 'Account search across platforms' },
  { value: 'phone',          label: 'Phone',              placeholder: '+1 555 123 4567',                 description: 'Phone number OSINT' },
  { value: 'crypto_address', label: 'Crypto Address',     placeholder: '0x742d35Cc...',                   description: 'Crypto wallet OSINT' },
  { value: 'code_path',      label: 'Code / Repository',  placeholder: 'https://github.com/user/repo',    description: 'Source code secrets and CVE scan' },
] as const;
type TargetTypeValue = typeof TARGET_TYPES[number]['value'];

interface AddTargetModalProps {
  open: boolean;
  onClose: () => void;
  projectSlug: string;
}

export const AddTargetModal: React.FC<AddTargetModalProps> = ({ open, onClose, projectSlug }) => {
  const { tokens, isLight, isCyber, theme } = useThemeTokens();
  const [formData, setFormData] = useState({
    domain_name: '',
    description: '',
    organization: '',
    h1_team_handle: '',
    is_monitored: false,
    monitor_frequency: 'daily',
    monitor_engine_id: '',
    monitor_scan_scope: 'none',
    starting_point_path: '',
    excluded_paths: '',
    target_type: 'domain' as TargetTypeValue,
  });

  const [showAdvanced, setShowAdvanced] = useState(false);
  const [resolverInput, setResolverInput] = useState('');
  const [resolvedDomains, setResolvedDomains] = useState<string[]>([]);
  const [selectedDomains, setSelectedDomains] = useState<string[]>([]);
  const [isResolverOpen, setIsResolverOpen] = useState(false);

  const { data: organizations, isLoading: loadingOrgs } = useOrganizations();
  const { data: engines, isLoading: loadingEngines } = useEngines();
  const { mutate: addTarget, isPending, error, reset } = useAddTarget(projectSlug);
  const { mutate: resolveIP, isPending: isResolving } = useResolveIP();

  const selectedTypeMeta = TARGET_TYPES.find(t => t.value === formData.target_type);

  const handleSubmit = (e: React.FormEvent) => {
    e.preventDefault();

    addTarget({
      domain_name: formData.domain_name,
      slug: projectSlug,
      organization: formData.organization,
      h1_team_handle: formData.h1_team_handle,
      description: formData.description,
      is_monitored: formData.is_monitored,
      monitor_frequency: formData.monitor_frequency,
      monitor_engine_id: formData.monitor_engine_id ? Number(formData.monitor_engine_id) : undefined,
      monitor_scan_scope: formData.monitor_scan_scope,
      starting_point_path: formData.starting_point_path || undefined,
      excluded_paths: formData.excluded_paths ? formData.excluded_paths.split('\n').filter(p => p.trim()) : [],
      target_type: formData.target_type,
    }, {
      onSuccess: () => {
        onClose();
        setFormData({
          domain_name: '',
          description: '',
          organization: '',
          h1_team_handle: '',
          is_monitored: false,
          monitor_frequency: 'daily',
          monitor_engine_id: '',
          monitor_scan_scope: 'none',
          starting_point_path: '',
          excluded_paths: '',
          target_type: 'domain',
        });
        reset();
      },
    });
  };

  const handleResolve = () => {
    if (!resolverInput) return;
    resolveIP(resolverInput, {
      onSuccess: (data) => {
        setResolvedDomains(data.domains || []);
        setSelectedDomains(data.domains || []);
      }
    });
  };

  const toggleDomain = (domain: string) => {
    setSelectedDomains(prev => 
      prev.includes(domain) ? prev.filter(d => d !== domain) : [...prev, domain]
    );
  };

  const addSelectedToTargets = () => {
    const currentTargets = formData.domain_name.split('\n').filter(t => t.trim());
    const newTargets = [...new Set([...currentTargets, ...selectedDomains])];
    setFormData({ ...formData, domain_name: newTargets.join('\n') });
    setIsResolverOpen(false);
    setResolverInput('');
    setResolvedDomains([]);
    setSelectedDomains([]);
  };

  const handleClose = () => {
    onClose();
    reset();
  };

  const fieldStyles = {
    ...getFieldSx(isLight, tokens, tokens.accent.primary),
    '& .MuiOutlinedInput-root': {
      color: 'text.primary',
      '& fieldset': { borderColor: isLight ? 'rgba(0, 0, 0, 0.12)' : 'rgba(255, 255, 255, 0.1)' },
      '&:hover fieldset': { borderColor: alpha(tokens.accent.primary, 0.4) },
      '&.Mui-focused fieldset': { borderColor: tokens.accent.primary },
      bgcolor: isLight ? 'rgba(0,0,0,0.01)' : 'rgba(255,255,255,0.03)',
    },
    '& .MuiInputLabel-root': { 
      color: 'text.secondary',
      '&.Mui-focused': { color: tokens.accent.primary }
    },
    '& .MuiSelect-icon': { color: 'text.secondary' },
  };

  return (
    <Dialog 
      open={open} 
      onClose={handleClose}
      slotProps={{
        paper: {
          sx: {
            ...getDialogPaperSx(isLight, theme, tokens),
            borderRadius: 4,
            maxWidth: 600,
            width: '100%',
            backgroundImage: isLight ? 'none' : 'radial-gradient(circle at top right, rgba(0, 243, 255, 0.05), transparent)',
            border: `1px solid ${isLight ? 'rgba(0,0,0,0.08)' : `${tokens.accent.primary}33`}`,
          }
        }
      }}
    >
      <DialogTitle sx={{ 
        display: 'flex', 
        justifyContent: 'space-between', 
        alignItems: 'center',
        borderBottom: `1px solid ${isLight ? 'rgba(0,0,0,0.06)' : 'rgba(255,255,255,0.05)'}`,
        pb: 2
      }}>
        <Box sx={{ display: 'flex', alignItems: 'center', gap: 1.5 }}>
          <Box sx={{ 
            p: 1, 
            borderRadius: 2, 
            bgcolor: alpha(tokens.accent.primary, 0.1), 
            color: tokens.accent.primary,
            display: 'flex'
          }}>
            <Target size={20} />
          </Box>
          <Typography variant="h6" sx={{ 
            fontFamily: 'Orbitron', 
            fontWeight: 800, 
            letterSpacing: 1,
            color: tokens.text.primary
          }}>
            INITIATE NEW TARGETS
          </Typography>
        </Box>
        <IconButton onClick={handleClose} sx={{ color: 'text.disabled', '&:hover': { color: tokens.accent.error } }}>
          <X size={20} />
        </IconButton>
      </DialogTitle>

      <form onSubmit={handleSubmit}>
        <DialogContent sx={{ mt: 2 }}>
          {error && (
            <Alert severity="error" sx={{ 
              mb: 3, 
              bgcolor: alpha(tokens.accent.error, 0.1), 
              color: tokens.accent.error,
              border: `1px solid ${alpha(tokens.accent.error, 0.2)}`,
              '& .MuiAlert-icon': { color: tokens.accent.error }
            }}>
              {error.message}
            </Alert>
          )}

          <Box sx={{ display: 'flex', flexDirection: 'column', gap: 3 }}>
            <TextField
              label="Target Type"
              select
              fullWidth
              value={formData.target_type}
              onChange={(e) => setFormData({ ...formData, target_type: e.target.value as TargetTypeValue })}
              sx={fieldStyles}
              slotProps={{
                input: {
                  startAdornment: <Target size={18} style={{ marginRight: 12, color: tokens.accent.primary }} />
                }
              }}
            >
              {TARGET_TYPES.map((type) => (
                <MenuItem key={type.value} value={type.value}>
                  <Box>
                    <Typography sx={{ fontSize: '0.85rem', color: 'text.primary', lineHeight: 1.2 }}>
                      {type.label}
                    </Typography>
                    <Typography sx={{ fontSize: '0.7rem', color: 'text.secondary', lineHeight: 1.2 }}>
                      {type.description}
                    </Typography>
                  </Box>
                </MenuItem>
              ))}
            </TextField>

            <TextField
              label="Targets"
              fullWidth
              required
              multiline
              rows={4}
              value={formData.domain_name}
              onChange={(e) => setFormData({ ...formData, domain_name: e.target.value })}
              placeholder={selectedTypeMeta?.placeholder ?? 'example.com'}
              sx={fieldStyles}
              helperText="Enter multiple targets separated by newlines"
              slotProps={{
                formHelperText: { sx: { color: 'text.disabled' } },
                input: {
                  startAdornment: <Globe size={18} style={{ marginRight: 12, marginTop: -60, color: tokens.accent.primary }} />,
                  endAdornment: (
                    <Box sx={{ display: 'flex', flexDirection: 'column', gap: 1, position: 'absolute', right: 8, top: 8 }}>
                      <Button
                        size="small"
                        onClick={() => setIsResolverOpen(!isResolverOpen)}
                        startIcon={<Zap size={14} />}
                        sx={{
                          fontSize: '0.65rem',
                          bgcolor: isResolverOpen ? alpha(tokens.accent.primary, 0.2) : 'action.hover',
                          color: tokens.accent.primary,
                          borderColor: alpha(tokens.accent.primary, 0.3),
                          '&:hover': { bgcolor: alpha(tokens.accent.primary, 0.3) }
                        }}
                        variant="outlined"
                      >
                        IP RESOLVER
                      </Button>
                    </Box>
                  )
                }
              }}
            />

            <Collapse in={isResolverOpen}>
              <Box sx={{ 
                p: 2, 
                borderRadius: 2, 
                bgcolor: alpha(tokens.accent.primary, 0.05),
                border: `1px solid ${alpha(tokens.accent.primary, 0.15)}`,
                mb: 2
              }}>
                <Typography variant="caption" sx={{ color: tokens.accent.primary, mb: 1, display: 'block', fontWeight: 600 }}>
                  IP / CIDR RESOLVER TOOL
                </Typography>
                <Box sx={{ display: 'flex', gap: 1, mb: 2 }}>
                  <TextField
                    size="small"
                    placeholder="Enter IP or CIDR (e.g. 1.1.1.1/24)"
                    fullWidth
                    value={resolverInput}
                    onChange={(e) => setResolverInput(e.target.value)}
                    sx={fieldStyles}
                  />
                  <Button 
                    variant="contained" 
                    size="small"
                    disabled={isResolving}
                    onClick={handleResolve}
                    sx={{ 
                      bgcolor: tokens.accent.primary, 
                      color: isLight ? '#fff' : '#000', 
                      fontWeight: 900,
                      '&:hover': { bgcolor: alpha(tokens.accent.primary, 0.8) }
                    }}
                  >
                    {isResolving ? <CircularProgress size={16} sx={{ color: isLight ? '#fff' : '#000' }} /> : 'RESOLVE'}
                  </Button>
                </Box>
                
                {resolvedDomains.length > 0 && (
                  <Box>
                    <Box sx={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', mb: 1 }}>
                      <Typography variant="caption" sx={{ color: 'text.secondary' }}>
                        Resolved {resolvedDomains.length} domains
                      </Typography>
                      <Box>
                        <Button size="small" sx={{ fontSize: '0.6rem', color: tokens.accent.primary }} onClick={() => setSelectedDomains(resolvedDomains)}>All</Button>
                        <Button size="small" sx={{ fontSize: '0.6rem', color: 'text.disabled' }} onClick={() => setSelectedDomains([])}>None</Button>
                      </Box>
                    </Box>
                    <Box sx={{ maxHeight: 200, overflowY: 'auto', bgcolor: isLight ? 'rgba(0,0,0,0.03)' : 'rgba(0,0,0,0.2)', borderRadius: 1 }}>
                      <List dense>
                        {resolvedDomains.map((domain) => (
                          <ListItem key={domain} disablePadding>
                            <ListItemButton onClick={() => toggleDomain(domain)} dense>
                              <ListItemIcon sx={{ minWidth: 32 }}>
                                <Checkbox
                                  edge="start"
                                  checked={selectedDomains.includes(domain)}
                                  tabIndex={-1}
                                  disableRipple
                                  size="small"
                                  sx={{ color: alpha(tokens.accent.primary, 0.3), '&.Mui-checked': { color: tokens.accent.primary } }}
                                />
                              </ListItemIcon>
                              <ListItemText 
                                primary={
                                  <Typography sx={{ fontSize: '0.75rem', color: 'text.primary' }}>
                                    {domain}
                                  </Typography>
                                } 
                              />
                            </ListItemButton>
                          </ListItem>
                        ))}
                      </List>
                    </Box>
                    <Button 
                      fullWidth 
                      variant="outlined" 
                      size="small" 
                      onClick={addSelectedToTargets}
                      sx={{ 
                        mt: 2, 
                        color: tokens.accent.primary, 
                        borderColor: alpha(tokens.accent.primary, 0.4),
                        '&:hover': { borderColor: tokens.accent.primary, bgcolor: alpha(tokens.accent.primary, 0.05) }
                      }}
                    >
                      ADD {selectedDomains.length} SELECTED TO TARGETS
                    </Button>
                  </Box>
                )}
              </Box>
            </Collapse>

            <Box sx={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 2 }}>
              <TextField
                label="Organization (Optional)"
                select
                fullWidth
                value={formData.organization}
                onChange={(e) => setFormData({ ...formData, organization: e.target.value })}
                sx={fieldStyles}
                slotProps={{
                  input: {
                    startAdornment: <Building2 size={18} style={{ marginRight: 12, color: tokens.text.secondary }} />
                  }
                }}
              >
                <MenuItem value="">
                  <em>None</em>
                </MenuItem>
                {organizations?.map((org: any) => (
                  <MenuItem key={org.id} value={org.name}>
                    {org.name}
                  </MenuItem>
                ))}
              </TextField>

              <TextField
                label="HackerOne Team Handle"
                fullWidth
                value={formData.h1_team_handle}
                onChange={(e) => setFormData({ ...formData, h1_team_handle: e.target.value })}
                placeholder="Optional team handle"
                sx={fieldStyles}
                slotProps={{
                  input: {
                    startAdornment: <Terminal size={18} style={{ marginRight: 12, color: tokens.text.secondary }} />
                  }
                }}
              />
            </Box>

            <TextField
              label="Description"
              fullWidth
              multiline
              rows={2}
              value={formData.description}
              onChange={(e) => setFormData({ ...formData, description: e.target.value })}
              placeholder="Target reconnaissance notes..."
              sx={fieldStyles}
            />

            <Divider sx={{ borderColor: 'divider' }} />

            <Box>
              <Button
                fullWidth
                variant="text"
                onClick={() => setShowAdvanced(!showAdvanced)}
                startIcon={<Settings2 size={16} />}
                sx={{ 
                  justifyContent: 'flex-start',
                  color: 'text.secondary',
                  fontSize: '0.75rem',
                  fontFamily: 'Orbitron',
                  '&:hover': { color: tokens.accent.primary, bgcolor: 'transparent' }
                }}
              >
                {showAdvanced ? 'HIDE' : 'SHOW'} ADVANCED SCAN CONFIGURATION
              </Button>
              
              <Collapse in={showAdvanced}>
                <Box sx={{ mt: 2, display: 'flex', flexDirection: 'column', gap: 2 }}>
                  <TextField
                    label="Starting Point Path"
                    fullWidth
                    size="small"
                    value={formData.starting_point_path}
                    onChange={(e) => setFormData({ ...formData, starting_point_path: e.target.value })}
                    placeholder="/api/v1 (Optional)"
                    sx={fieldStyles}
                    slotProps={{
                      input: {
                        startAdornment: <Map size={16} style={{ marginRight: 12, color: 'text.secondary' }} />
                      }
                    }}
                    helperText="Initial path to start scanning from"
                  />
                  <TextField
                    label="Excluded Paths"
                    fullWidth
                    multiline
                    rows={2}
                    size="small"
                    value={formData.excluded_paths}
                    onChange={(e) => setFormData({ ...formData, excluded_paths: e.target.value })}
                    placeholder="/logout&#10;/admin/delete"
                    sx={fieldStyles}
                    slotProps={{
                      input: {
                        startAdornment: <ListX size={16} style={{ marginRight: 12, marginTop: -20, color: 'text.secondary' }} />
                      }
                    }}
                    helperText="Paths to ignore during scanning (newline separated)"
                  />
                </Box>
              </Collapse>
            </Box>

            <Divider sx={{ borderColor: 'divider' }} />

            <Box>
              <FormControlLabel
                control={
                  <Switch 
                    checked={formData.is_monitored}
                    onChange={(e) => setFormData({ ...formData, is_monitored: e.target.checked })}
                    sx={{
                      '& .MuiSwitch-switchBase.Mui-checked': { color: tokens.accent.primary },
                      '& .MuiSwitch-switchBase.Mui-checked + .MuiSwitch-track': { bgcolor: tokens.accent.primary },
                    }}
                  />
                }
                label={
                  <Box sx={{ display: 'flex', alignItems: 'center', gap: 1 }}>
                    <Activity size={16} color={formData.is_monitored ? tokens.accent.primary : tokens.text.disabled} />
                    <Typography sx={{ 
                      fontFamily: 'Orbitron', 
                      fontSize: '0.75rem', 
                      fontWeight: 600,
                      color: formData.is_monitored ? 'text.primary' : 'text.disabled'
                    }}>
                      CONTINUOUS MONITORING
                    </Typography>
                  </Box>
                }
              />

              <Collapse in={formData.is_monitored}>
                <Box sx={{ 
                  mt: 2, 
                  p: 2, 
                  borderRadius: 2, 
                  bgcolor: isLight ? 'rgba(0,0,0,0.01)' : 'rgba(255,255,255,0.02)',
                  border: '1px solid',
                  borderColor: 'divider',
                  display: 'flex',
                  flexDirection: 'column',
                  gap: 2
                }}>
                  <Box sx={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 2 }}>
                    <TextField
                      label="Frequency"
                      select
                      fullWidth
                      size="small"
                      value={formData.monitor_frequency}
                      onChange={(e) => setFormData({ ...formData, monitor_frequency: e.target.value })}
                      sx={fieldStyles}
                      slotProps={{
                        input: {
                          startAdornment: <Clock size={16} style={{ marginRight: 8, color: 'text.secondary' }} />
                        }
                      }}
                    >
                      <MenuItem value="hourly">Hourly</MenuItem>
                      <MenuItem value="daily">Daily</MenuItem>
                      <MenuItem value="weekly">Weekly</MenuItem>
                      <MenuItem value="monthly">Monthly</MenuItem>
                    </TextField>

                    <TextField
                      label="Auto Scan Scope"
                      select
                      fullWidth
                      size="small"
                      value={formData.monitor_scan_scope}
                      onChange={(e) => setFormData({ ...formData, monitor_scan_scope: e.target.value })}
                      sx={fieldStyles}
                      slotProps={{
                        input: {
                          startAdornment: <Search size={16} style={{ marginRight: 8, color: 'text.secondary' }} />
                        }
                      }}
                    >
                      <MenuItem value="none">None (Discovery Only)</MenuItem>
                      <MenuItem value="targeted">Targeted Scan</MenuItem>
                      <MenuItem value="full">Full Scan</MenuItem>
                    </TextField>
                  </Box>

                  <TextField
                    label="Monitoring Engine"
                    select
                    fullWidth
                    size="small"
                    required={formData.is_monitored}
                    value={formData.monitor_engine_id}
                    onChange={(e) => setFormData({ ...formData, monitor_engine_id: e.target.value })}
                    sx={fieldStyles}
                    slotProps={{
                      input: {
                        startAdornment: <Settings2 size={16} style={{ marginRight: 8, color: 'text.secondary' }} />
                      }
                    }}
                  >
                    {engines?.map((engine: any) => (
                      <MenuItem key={engine.id} value={engine.id}>
                        {engine.engine_name}
                      </MenuItem>
                    ))}
                  </TextField>
                </Box>
              </Collapse>
            </Box>
          </Box>
        </DialogContent>

        <DialogActions sx={{ p: 3, borderTop: '1px solid', borderColor: 'divider' }}>
          <Button 
            onClick={handleClose} 
            sx={{ 
              color: 'text.secondary',
              fontFamily: 'Orbitron',
              fontSize: '0.7rem',
              fontWeight: 800,
              '&:hover': { color: tokens.accent.error }
            }}
          >
            ABORT
          </Button>
          <Button
            type="submit"
            variant="contained"
            disabled={isPending || (formData.is_monitored && !formData.monitor_engine_id)}
            sx={{
              bgcolor: tokens.accent.primary,
              color: isLight ? '#fff' : '#000',
              fontWeight: 900,
              fontFamily: 'Orbitron',
              letterSpacing: 1,
              px: 4,
              '&:hover': {
                bgcolor: alpha(tokens.accent.primary, 0.8),
                boxShadow: isCyber ? `0 0 20px ${alpha(tokens.accent.primary, 0.4)}` : 'none'
              },
              '&.Mui-disabled': {
                bgcolor: alpha(tokens.accent.primary, 0.2),
                color: isLight ? 'rgba(0,0,0,0.26)' : 'rgba(255,255,255,0.3)'
              }
            }}
          >
            {isPending ? <CircularProgress size={20} sx={{ color: isLight ? '#fff' : '#000' }} /> : 'DEPLOY TARGETS'}
          </Button>
        </DialogActions>
      </form>
    </Dialog>
  );
};
