import React, { useState, useEffect } from 'react';
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
  Chip,
  useTheme,
  alpha,
} from '@mui/material';
import {
  X,
  Target,
  Globe,
  Building2,
  Terminal,
  Activity,
  Clock,
  Settings2,
  Search,
  ListX,
  Map,
  Network,
  GitBranch,
  Lock,
} from 'lucide-react';
import { useUpdateTarget, useOrganizations, useEngines } from '../api';
import type { Domain } from '../types';
import { useThemeTokens } from '../../../theme/useThemeTokens';
import { getDialogPaperSx, getFieldSx } from '../../../theme/semanticColors';

// The generated OpenAPI schema omits several fields that the backend serializes.
// Extend locally so we can read them without casting everywhere.
export type ExtendedDomain = Domain & {
  target_type?: string | null;
  in_scope_ips?: string | null;
  secondary_domains?: string | null;
};

const TARGET_TYPES = [
  { value: 'domain',         label: 'Domain',            description: 'Full domain scan (7-tier pipeline)' },
  { value: 'host',           label: 'Host',               description: 'Host/hostname reconnaissance' },
  { value: 'ip',             label: 'IP Address',         description: 'Single IP reconnaissance' },
  { value: 'url',            label: 'URL',                description: 'URL crawl and vulnerability scan' },
  { value: 'cidr',           label: 'CIDR / Network',     description: 'Network range discovery' },
  { value: 'email',          label: 'Email',              description: 'Email breach hunt (h8mail + maigret)' },
  { value: 'username',       label: 'Username',           description: 'Account search across platforms' },
  { value: 'phone',          label: 'Phone',              description: 'Phone number OSINT' },
  { value: 'crypto_address', label: 'Crypto Address',     description: 'Crypto wallet OSINT' },
  { value: 'code_path',      label: 'Code / Repository',  description: 'Source code secrets and CVE scan' },
] as const;

interface EditTargetModalProps {
  open: boolean;
  onClose: () => void;
  domain: ExtendedDomain;
  projectSlug: string;
}

export const EditTargetModal: React.FC<EditTargetModalProps> = ({
  open,
  onClose,
  domain,
  projectSlug,
}) => {
  const { tokens } = useThemeTokens();
  const theme = useTheme();
  const isLight = tokens.mode === 'light';

  const [formData, setFormData] = useState({
    description: '',
    organization: '',
    h1_team_handle: '',
    target_type: 'domain',
    is_monitored: false,
    monitor_frequency: 'daily',
    monitor_engine_id: '' as string | number,
    monitor_scan_scope: 'targeted',
    starting_point_path: '',
    excluded_paths: '',
    in_scope_ips: '',
    secondary_domains: '',
  });

  const [showAdvanced, setShowAdvanced] = useState(false);
  const [showScopeConfig, setShowScopeConfig] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const { data: organizations } = useOrganizations();
  const { data: engines } = useEngines();
  const { mutate: updateTarget, isPending } = useUpdateTarget(projectSlug);

  // Pre-populate form when modal opens or domain changes
  useEffect(() => {
    if (!open) return;

    // organization is returned as a string (org name) by DomainSerializer
    const orgName = typeof domain.organization === 'string' ? domain.organization : '';

    // excluded_paths is a JSONField — the schema types it as Record<string,never> but
    // at runtime it is string[] (or null). Cast through unknown to avoid TS errors.
    const rawExcluded = domain.excluded_paths as unknown;
    const excludedPathsValue = Array.isArray(rawExcluded)
      ? (rawExcluded as string[]).join('\n')
      : typeof rawExcluded === 'string' ? rawExcluded : '';

    // monitor_engine is a nested object with depth=2; extract its id
    const monitorEngineId = domain.monitor_engine?.id ?? '';

    setFormData({
      description: domain.description ?? '',
      organization: orgName,
      h1_team_handle: domain.h1_team_handle ?? '',
      target_type: domain.target_type ?? 'domain',
      is_monitored: domain.is_monitored ?? false,
      monitor_frequency: domain.monitor_frequency ?? 'daily',
      monitor_engine_id: monitorEngineId,
      monitor_scan_scope: domain.monitor_scan_scope ?? 'targeted',
      starting_point_path: domain.starting_point_path ?? '',
      excluded_paths: excludedPathsValue,
      in_scope_ips: domain.in_scope_ips ?? '',
      secondary_domains: domain.secondary_domains ?? '',
    });
    setError(null);
    setShowAdvanced(false);
    setShowScopeConfig(false);
  }, [domain, open]);

  const handleSubmit = (e: React.FormEvent<HTMLFormElement>) => {
    e.preventDefault();
    setError(null);

    updateTarget(
      {
        id: domain.id!,
        description: formData.description,
        h1_team_handle: formData.h1_team_handle,
        target_type: formData.target_type,
        organization: formData.organization,
        is_monitored: formData.is_monitored,
        monitor_frequency: formData.monitor_frequency,
        monitor_engine_id: formData.monitor_engine_id
          ? Number(formData.monitor_engine_id)
          : null,
        monitor_scan_scope: formData.monitor_scan_scope,
        starting_point_path: formData.starting_point_path,
        excluded_paths: formData.excluded_paths,
        in_scope_ips: formData.in_scope_ips,
        secondary_domains: formData.secondary_domains,
      },
      {
        onSuccess: () => onClose(),
        onError: (err: Error) => setError(err.message),
      }
    );
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
      onClose={onClose}
      maxWidth="md"
      fullWidth
      slotProps={{
        paper: {
          sx: {
            ...getDialogPaperSx(isLight, theme, tokens),
            borderRadius: 4,
            backgroundImage: isLight ? 'none' : `radial-gradient(circle at top right, ${alpha(tokens.accent.primary, 0.05)}, transparent)`,
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
        pb: 2,
      }}>
        <Box sx={{ display: 'flex', alignItems: 'center', gap: 1.5 }}>
          <Box sx={{
            p: 1,
            borderRadius: 2,
            bgcolor: alpha(tokens.accent.primary, 0.1),
            color: tokens.accent.primary,
            display: 'flex',
          }}>
            <Target size={20} />
          </Box>
          <Box>
            <Typography variant="h6" sx={{
              fontFamily: 'Orbitron',
              fontWeight: 800,
              letterSpacing: 1,
              color: tokens.text.primary,
              lineHeight: 1.1,
            }}>
              EDIT TARGET
            </Typography>
            <Box sx={{ display: 'flex', alignItems: 'center', gap: 0.5, mt: 0.5 }}>
              <Lock size={12} color={tokens.text.muted} />
              <Typography sx={{ fontSize: '0.7rem', color: tokens.text.secondary, fontFamily: 'monospace' }}>
                {domain.name}
              </Typography>
            </Box>
          </Box>
        </Box>
        <IconButton onClick={onClose} sx={{ color: tokens.text.muted, '&:hover': { color: tokens.accent.error } }}>
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
              '& .MuiAlert-icon': { color: tokens.accent.error },
            }}>
              {error}
            </Alert>
          )}

          <Box sx={{ display: 'flex', flexDirection: 'column', gap: 3 }}>
            {/* Identity */}
            <Box>
              <Typography sx={{ fontSize: '0.65rem', fontFamily: 'Orbitron', color: tokens.accent.primary, fontWeight: 700, letterSpacing: 1, mb: 1.5 }}>
                IDENTITY
              </Typography>
              <Box sx={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 2 }}>
                <TextField
                  label="Target Name"
                  fullWidth
                  value={domain.name}
                  disabled
                  sx={{
                    ...fieldStyles,
                    '& .MuiOutlinedInput-root.Mui-disabled': {
                      bgcolor: isLight ? 'rgba(0,0,0,0.02)' : 'rgba(255,255,255,0.01)',
                      '& fieldset': { borderColor: tokens.border.subtle },
                    },
                    '& .MuiInputBase-input.Mui-disabled': { color: tokens.text.disabled, WebkitTextFillColor: tokens.text.disabled },
                  }}
                  slotProps={{
                    input: {
                      startAdornment: (
                        <Box sx={{ display: 'flex', alignItems: 'center', gap: 0.5, mr: 1 }}>
                          <Globe size={16} color={tokens.text.disabled} />
                          <Chip label="READ-ONLY" size="small" sx={{ height: 16, fontSize: '0.55rem', bgcolor: alpha(tokens.text.primary, 0.05), color: tokens.text.secondary, fontFamily: 'Orbitron' }} />
                        </Box>
                      ),
                    }
                  }}
                />
                <TextField
                  label="Target Type"
                  select
                  fullWidth
                  value={formData.target_type}
                  onChange={(e) => setFormData({ ...formData, target_type: e.target.value })}
                  sx={fieldStyles}
                  slotProps={{
                    input: {
                      startAdornment: <Target size={16} style={{ marginRight: 12, color: tokens.accent.primary }} />,
                    }
                  }}
                >
                  {TARGET_TYPES.map((type) => (
                    <MenuItem key={type.value} value={type.value}>
                      <Box>
                        <Typography sx={{ fontSize: '0.85rem', color: tokens.text.primary, lineHeight: 1.2 }}>
                          {type.label}
                        </Typography>
                        <Typography sx={{ fontSize: '0.7rem', color: tokens.text.secondary, lineHeight: 1.2 }}>
                          {type.description}
                        </Typography>
                      </Box>
                    </MenuItem>
                  ))}
                </TextField>
              </Box>
            </Box>

            {/* Metadata */}
            <Box>
              <Typography sx={{ fontSize: '0.65rem', fontFamily: 'Orbitron', color: tokens.accent.primary, fontWeight: 700, letterSpacing: 1, mb: 1.5 }}>
                METADATA
              </Typography>
              <Box sx={{ display: 'flex', flexDirection: 'column', gap: 2 }}>
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
                        startAdornment: <Building2 size={16} style={{ marginRight: 12, color: tokens.text.secondary }} />,
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
                        startAdornment: <Terminal size={16} style={{ marginRight: 12, color: tokens.text.secondary }} />,
                      }
                    }}
                  />
                </Box>
              </Box>
            </Box>

            <Divider sx={{ borderColor: tokens.border.subtle }} />

            {/* Scope Configuration */}
            <Box>
              <Button
                fullWidth
                variant="text"
                onClick={() => setShowScopeConfig(!showScopeConfig)}
                startIcon={<Network size={16} />}
                sx={{
                  justifyContent: 'flex-start',
                  color: showScopeConfig ? tokens.accent.primary : tokens.text.secondary,
                  fontSize: '0.75rem',
                  fontFamily: 'Orbitron',
                  '&:hover': { color: tokens.accent.primary, bgcolor: 'transparent' },
                }}
              >
                {showScopeConfig ? 'HIDE' : 'SHOW'} SCOPE CONFIGURATION
              </Button>
              <Collapse in={showScopeConfig}>
                <Box sx={{ mt: 2, display: 'flex', flexDirection: 'column', gap: 2 }}>
                  <TextField
                    label="In-Scope IPs / CIDRs"
                    fullWidth
                    multiline
                    rows={3}
                    size="small"
                    value={formData.in_scope_ips}
                    onChange={(e) => setFormData({ ...formData, in_scope_ips: e.target.value })}
                    placeholder="192.168.1.0/24&#10;10.0.0.1"
                    sx={fieldStyles}
                    helperText="One IP or CIDR per line — included in scanning scope"
                    slotProps={{
                      formHelperText: { sx: { color: tokens.text.muted } },
                      input: {
                        startAdornment: <Network size={16} style={{ marginRight: 12, marginTop: -40, color: tokens.text.secondary }} />,
                      }
                    }}
                  />
                  <TextField
                    label="Secondary Domains"
                    fullWidth
                    multiline
                    rows={3}
                    size="small"
                    value={formData.secondary_domains}
                    onChange={(e) => setFormData({ ...formData, secondary_domains: e.target.value })}
                    placeholder="sub.example.com&#10;other.example.com"
                    sx={fieldStyles}
                    helperText="Related domains included in the scan scope (one per line)"
                    slotProps={{
                      formHelperText: { sx: { color: tokens.text.muted } },
                      input: {
                        startAdornment: <GitBranch size={16} style={{ marginRight: 12, marginTop: -40, color: tokens.text.secondary }} />,
                      }
                    }}
                  />
                </Box>
              </Collapse>
            </Box>

            {/* Advanced Scan Configuration */}
            <Box>
              <Button
                fullWidth
                variant="text"
                onClick={() => setShowAdvanced(!showAdvanced)}
                startIcon={<Settings2 size={16} />}
                sx={{
                  justifyContent: 'flex-start',
                  color: showAdvanced ? tokens.accent.primary : tokens.text.secondary,
                  fontSize: '0.75rem',
                  fontFamily: 'Orbitron',
                  '&:hover': { color: tokens.accent.primary, bgcolor: 'transparent' },
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
                    helperText="Initial path to start scanning from"
                    slotProps={{
                      formHelperText: { sx: { color: tokens.text.muted } },
                      input: {
                        startAdornment: <Map size={16} style={{ marginRight: 12, color: tokens.text.secondary }} />,
                      }
                    }}
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
                    helperText="Paths to ignore during scanning (newline separated)"
                    slotProps={{
                      formHelperText: { sx: { color: tokens.text.muted } },
                      input: {
                        startAdornment: <ListX size={16} style={{ marginRight: 12, marginTop: -20, color: tokens.text.secondary }} />,
                      }
                    }}
                  />
                </Box>
              </Collapse>
            </Box>

            <Divider sx={{ borderColor: tokens.border.subtle }} />

            {/* Monitoring */}
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
                    <Activity size={16} color={formData.is_monitored ? tokens.accent.primary : tokens.text.secondary} />
                    <Typography sx={{
                      fontFamily: 'Orbitron',
                      fontSize: '0.75rem',
                      fontWeight: 600,
                      color: formData.is_monitored ? tokens.text.primary : tokens.text.secondary,
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
                  bgcolor: alpha(tokens.accent.primary, 0.03),
                  border: `1px solid ${alpha(tokens.accent.primary, 0.1)}`,
                  display: 'flex',
                  flexDirection: 'column',
                  gap: 2,
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
                          startAdornment: <Clock size={16} style={{ marginRight: 8, color: tokens.text.secondary }} />,
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
                          startAdornment: <Search size={16} style={{ marginRight: 8, color: tokens.text.secondary }} />,
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
                        startAdornment: <Settings2 size={16} style={{ marginRight: 8, color: tokens.text.secondary }} />,
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

        <DialogActions sx={{ p: 3, borderTop: `1px solid ${tokens.border.subtle}` }}>
          <Button
            onClick={onClose}
            sx={{
              color: tokens.text.secondary,
              fontFamily: 'Orbitron',
              fontSize: '0.7rem',
              fontWeight: 800,
              '&:hover': { color: tokens.text.primary }
            }}
          >
            CANCEL
          </Button>
          <Button
            type="submit"
            variant="contained"
            disabled={isPending || (formData.is_monitored && !formData.monitor_engine_id)}
            sx={{
              bgcolor: tokens.accent.primary,
              color: theme.palette.getContrastText(tokens.accent.primary),
              fontWeight: 900,
              fontFamily: 'Orbitron',
              letterSpacing: 1,
              px: 4,
              '&:hover': {
                bgcolor: alpha(tokens.accent.primary, 0.85),
                boxShadow: `0 0 20px ${alpha(tokens.accent.primary, 0.4)}`,
              },
              '&.Mui-disabled': {
                bgcolor: alpha(tokens.accent.primary, 0.2),
                color: alpha(theme.palette.getContrastText(tokens.accent.primary), 0.5),
              },
            }}
          >
            {isPending ? <CircularProgress size={20} sx={{ color: theme.palette.getContrastText(tokens.accent.primary) }} /> : 'SAVE CHANGES'}
          </Button>
        </DialogActions>
      </form>
    </Dialog>
  );
};
