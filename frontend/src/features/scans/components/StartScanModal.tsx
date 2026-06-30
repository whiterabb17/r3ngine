import React, { useState, useEffect } from 'react';
import {
  Dialog,
  DialogTitle,
  DialogContent,
  DialogActions,
  Button,
  Box,
  Typography,
  IconButton,
  MenuItem,
  CircularProgress,
  Alert,
  TextField,
  FormControlLabel,
  Switch,
  Checkbox,
  FormGroup,
  Collapse,
  Divider,
  Grid,
  useTheme,
  alpha
} from '@mui/material';
import { X, Zap, Shield, Cpu, Terminal, ChevronDown, ChevronUp, Puzzle, Server } from 'lucide-react';
import { useEngines, useHardwareProfiles } from '../../engines/api';
import { usePlugins } from '../../plugins/api/pluginsApi';
import { useInitiateScan } from '../api';
import { useRemoteWorkers } from '../../settings/api';
import { useNavigate } from '@tanstack/react-router';
import { generateDorks } from '../utils/dorkUtils';
import { useThemeTokens } from '../../../theme/useThemeTokens';
import { getDialogPaperSx, getFieldSx } from '../../../theme/semanticColors';
import { WorkflowLauncher } from '../../workflows/components/WorkflowLauncher';

interface StartScanModalProps {
  open: boolean;
  onClose: () => void;
  domainIds: number[];
  domainNames: string[];
  projectSlug: string;
}

export const StartScanModal: React.FC<StartScanModalProps> = ({
  open,
  onClose,
  domainIds,
  domainNames,
  projectSlug
}) => {
  const { tokens } = useThemeTokens();
  const theme = useTheme();
  const isLight = tokens.mode === 'light';

  const [formData, setFormData] = useState({
    engine_id: '' as number | '',
    hardware_profile_id: '' as number | '',
    customDorkSwitch: false,
    customDorkTextarea: '',
    spiderfoot_scan: false,
    importSubdomainTextArea: '',
    outOfScopeSubdomainTextarea: '',
    profile_name: '',
    worker_name: '',
  });
  const [selectedPlugins, setSelectedPlugins] = useState<string[]>([]);
  const [pluginSectionOpen, setPluginSectionOpen] = useState(false);
  const [showWorkflows, setShowWorkflows] = useState(false);

  const { data: engines, isLoading: loadingEngines } = useEngines();
  const { data: hardwareProfiles } = useHardwareProfiles();
  const { data: allPlugins } = usePlugins();
  const enabledPlugins = (allPlugins ?? []).filter(p => p.is_enabled);
  const { data: remoteWorkers } = useRemoteWorkers();
  const { mutate: initiateScan, isPending, error, reset } = useInitiateScan(projectSlug);
  const navigate = useNavigate();

  useEffect(() => {
    if (hardwareProfiles && !formData.hardware_profile_id) {
      const defaultProfile = hardwareProfiles.find(p => p.is_default && p.is_active);
      if (defaultProfile) {
        setFormData(prev => ({ ...prev, hardware_profile_id: defaultProfile.id }));
      } else {
        const firstActive = hardwareProfiles.find(p => p.is_active);
        if (firstActive) {
          setFormData(prev => ({ ...prev, hardware_profile_id: firstActive.id }));
        }
      }
    }
  }, [hardwareProfiles]);

  const handleSubmit = (e: React.FormEvent) => {
    e.preventDefault();
    if (!formData.engine_id || !formData.hardware_profile_id || domainIds.length === 0) return;

    initiateScan({
      domain_id: domainIds.length === 1 ? domainIds[0] : domainIds as any,
      engine_id: formData.engine_id as number,
      hardware_profile_id: formData.hardware_profile_id as number,
      customDorkSwitch: formData.customDorkSwitch,
      customDorkTextarea: formData.customDorkTextarea,
      spiderfoot_scan: formData.spiderfoot_scan,
      importSubdomainTextArea: formData.importSubdomainTextArea.split('\n').filter(s => s.trim()),
      outOfScopeSubdomainTextarea: formData.outOfScopeSubdomainTextarea.split('\n').filter(s => s.trim()),
      selected_plugins: selectedPlugins,
      ...(formData.profile_name ? { profile_name: formData.profile_name } : {}),
      ...(formData.worker_name ? { worker_name: formData.worker_name } : {}),
    }, {
      onSuccess: () => {
        onClose();
        reset();
        setFormData(prev => ({ ...prev, profile_name: '' }));
        navigate({ to: `/${projectSlug}/scans` });
      },
    });
  };

  const handleClose = () => {
    onClose();
    reset();
    setSelectedPlugins([]);
    setPluginSectionOpen(false);
    setShowWorkflows(false);
    setFormData(prev => ({ ...prev, profile_name: '' }));
  };

  const targetLabel = domainNames.length > 1
    ? `${domainNames.length} SELECTED TARGETS`
    : domainNames[0]?.toUpperCase() || 'N/A';

  const fieldStyles = {
    ...getFieldSx(isLight, tokens),
    '& .MuiOutlinedInput-root': {
      ...getFieldSx(isLight, tokens)['& .MuiOutlinedInput-root'],
      bgcolor: isLight ? 'transparent' : alpha(tokens.text.primary, 0.03),
    },
    '& .MuiFormHelperText-root': { color: tokens.text.muted }
  };

  const switchStyles = {
    '& .MuiSwitch-switchBase.Mui-checked': {
      color: tokens.accent.primary,
      '& + .MuiSwitch-track': {
        backgroundColor: tokens.accent.primary,
      },
    },
  };

  return (
    <Dialog
      open={open}
      onClose={handleClose}
      maxWidth="md"
      fullWidth
      slotProps={{
        paper: {
          sx: {
            ...getDialogPaperSx(isLight, theme, tokens),
            backgroundImage: isLight
              ? 'none'
              : `radial-gradient(circle at top right, ${alpha(tokens.accent.primary, 0.05)}, transparent)`,
            border: `1px solid ${alpha(tokens.accent.primary, 0.2)}`,
          }
        }
      }}
    >
      <DialogTitle sx={{
        display: 'flex',
        justifyContent: 'space-between',
        alignItems: 'center',
        borderBottom: `1px solid ${tokens.border.subtle}`,
        pb: 2,
        color: tokens.text.primary
      }}>
        <Box sx={{ display: 'flex', alignItems: 'center', gap: 1.5 }}>
          <Box sx={{
            p: 1,
            borderRadius: 2,
            bgcolor: alpha(tokens.accent.primary, 0.1),
            color: tokens.accent.primary,
            display: 'flex'
          }}>
            <Zap size={20} />
          </Box>
          <Box>
            <Typography variant="h6" sx={{
              fontFamily: 'Orbitron',
              fontWeight: 800,
              letterSpacing: 1,
              color: tokens.text.primary,
              lineHeight: 1.2
            }}>
              LAUNCH RECONNAISSANCE
            </Typography>
            <Typography variant="caption" sx={{ color: tokens.accent.primary, fontWeight: 700, letterSpacing: 1 }}>
              TARGET: {targetLabel}
            </Typography>
          </Box>
        </Box>
        <IconButton onClick={handleClose} sx={{ color: tokens.text.muted, '&:hover': { color: tokens.accent.error } }}>
          <X size={20} />
        </IconButton>
      </DialogTitle>

      <form onSubmit={handleSubmit}>
        <DialogContent sx={{ mt: 2, color: tokens.text.primary }}>
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

          <Grid container spacing={3}>
            <Grid size={{ xs: 12, md: 6 }} >
              <Typography variant="overline" sx={{ color: tokens.text.secondary, fontWeight: 800, mb: 1, display: 'block' }}>
                PRIMARY CONFIGURATION
              </Typography>
              <Box sx={{ display: 'flex', flexDirection: 'column', gap: 3 }}>
                <TextField
                  label="Scan Engine"
                  select
                  fullWidth
                  required
                  value={formData.engine_id}
                  onChange={(e) => setFormData({ ...formData, engine_id: Number(e.target.value) })}
                  sx={fieldStyles}
                  slotProps={{
                    input: {
                      startAdornment: <Shield size={18} style={{ marginRight: 12, color: tokens.accent.primary }} />
                    }
                  }}
                >
                  {engines?.map((engine) => (
                    <MenuItem key={engine.id} value={engine.id}>
                      {engine.engine_name}
                    </MenuItem>
                  ))}
                </TextField>

                <TextField
                  label="Hardware Profile / Speed"
                  select
                  fullWidth
                  required
                  value={formData.hardware_profile_id}
                  onChange={(e) => setFormData({ ...formData, hardware_profile_id: Number(e.target.value) })}
                  sx={fieldStyles}
                  slotProps={{
                    input: {
                      startAdornment: <Cpu size={18} style={{ marginRight: 12, color: tokens.accent.primary }} />
                    }
                  }}
                  helperText={
                    formData.hardware_profile_id && hardwareProfiles
                      ? hardwareProfiles.find(p => p.id === formData.hardware_profile_id)?.description || ''
                      : 'Select concurrency / speed profile'
                  }
                >
                  {hardwareProfiles?.filter(p => p.is_active).map((profile) => (
                    <MenuItem key={profile.id} value={profile.id}>
                      {profile.name.toUpperCase()} {profile.is_default ? '(DEFAULT)' : ''} (Threads: {profile.threads}, Rate: {profile.rate_limit}/s)
                    </MenuItem>
                  ))}
                </TextField>

                <TextField
                  label="Scan Worker (Optional)"
                  select
                  fullWidth
                  value={formData.worker_name}
                  onChange={(e) => setFormData({ ...formData, worker_name: e.target.value })}
                  sx={fieldStyles}
                  slotProps={{
                    input: {
                      startAdornment: <Server size={18} style={{ marginRight: 12, color: tokens.accent.primary }} />
                    }
                  }}
                  helperText="Leave empty to use the default worker pool"
                >
                  <MenuItem value="">
                    <em>Default Worker Pool</em>
                  </MenuItem>
                  {remoteWorkers?.map((worker) => (
                    <MenuItem key={worker.id} value={worker.name}>
                      {worker.name} {worker.ip_address ? `(${worker.ip_address})` : ''}
                    </MenuItem>
                  ))}
                </TextField>

                <FormControlLabel
                  control={
                    <Switch
                      checked={formData.spiderfoot_scan}
                      onChange={(e) => setFormData({ ...formData, spiderfoot_scan: e.target.checked })}
                      sx={switchStyles}
                    />
                  }
                  label={
                    <Typography sx={{ color: tokens.text.primary, fontSize: '0.85rem', fontWeight: 600 }}>
                      Enable SpiderFoot OSINT
                    </Typography>
                  }
                />

                <Divider sx={{ borderColor: tokens.border.subtle }} />

                <FormControlLabel
                  control={
                    <Switch
                      checked={formData.customDorkSwitch}
                      onChange={(e) => setFormData({ ...formData, customDorkSwitch: e.target.checked })}
                      sx={switchStyles}
                    />
                  }
                  label={
                    <Typography sx={{ color: tokens.text.primary, fontSize: '0.85rem', fontWeight: 600 }}>
                      Custom Github Dorks
                    </Typography>
                  }
                />

                {formData.customDorkSwitch && (
                  <>
                    <Box sx={{ display: 'flex', justifyContent: 'flex-end', mb: 1 }}>
                      <Button
                        size="small"
                        onClick={() => setFormData({ 
                          ...formData, 
                          customDorkTextarea: generateDorks(domainNames) 
                        })}
                        startIcon={<Terminal size={14} />}
                        sx={{
                          color: tokens.accent.primary,
                          fontFamily: 'Orbitron',
                          fontSize: '0.65rem',
                          fontWeight: 800,
                          border: `1px solid ${alpha(tokens.accent.primary, 0.2)}`,
                          '&:hover': {
                            bgcolor: alpha(tokens.accent.primary, 0.05),
                            border: `1px solid ${tokens.accent.primary}`,
                          }
                        }}
                      >
                        AUTOGENERATE DORKS
                      </Button>
                    </Box>
                    <TextField
                      label="Github Dorks"
                      fullWidth
                      multiline
                      rows={4}
                      value={formData.customDorkTextarea}
                      onChange={(e) => setFormData({ ...formData, customDorkTextarea: e.target.value })}
                      placeholder="Enter custom dorks, one per line..."
                      sx={fieldStyles}
                    />
                  </>
                )}

              </Box>
            </Grid>

            <Grid size={{ xs: 12, md: 6 }} >
              <Typography variant="overline" sx={{ color: tokens.text.secondary, fontWeight: 800, mb: 1, display: 'block' }}>
                ADVANCED SCOPE
              </Typography>
              <Box sx={{ display: 'flex', flexDirection: 'column', gap: 3 }}>
                <TextField
                  label="Import Subdomains"
                  fullWidth
                  multiline
                  rows={3}
                  value={formData.importSubdomainTextArea}
                  onChange={(e) => setFormData({ ...formData, importSubdomainTextArea: e.target.value })}
                  placeholder="Paste subdomains to include..."
                  sx={fieldStyles}
                  helperText="One subdomain per line"
                />

                <TextField
                  label="Out of Scope Subdomains"
                  fullWidth
                  multiline
                  rows={3}
                  value={formData.outOfScopeSubdomainTextarea}
                  onChange={(e) => setFormData({ ...formData, outOfScopeSubdomainTextarea: e.target.value })}
                  placeholder="Paste subdomains to exclude..."
                  sx={fieldStyles}
                  helperText="One subdomain per line"
                />
              </Box>
            </Grid>
          </Grid>

          {enabledPlugins.length > 0 && (
            <Box sx={{ mt: 3 }}>
              <Divider sx={{ borderColor: tokens.border.subtle, mb: 2 }} />
              <Button
                fullWidth
                onClick={() => setPluginSectionOpen(prev => !prev)}
                endIcon={pluginSectionOpen ? <ChevronUp size={16} /> : <ChevronDown size={16} />}
                sx={{
                  justifyContent: 'space-between',
                  color: tokens.text.secondary,
                  fontFamily: 'Orbitron',
                  fontSize: '0.7rem',
                  fontWeight: 800,
                  letterSpacing: 1,
                  px: 0,
                  '&:hover': { color: tokens.accent.primary, bgcolor: 'transparent' },
                }}
                startIcon={<Puzzle size={16} />}
              >
                PLUGINS
                {selectedPlugins.length > 0 && (
                  <Box component="span" sx={{
                    ml: 1,
                    px: 1,
                    py: 0.25,
                    bgcolor: alpha(tokens.accent.primary, 0.15),
                    color: tokens.accent.primary,
                    borderRadius: 1,
                    fontSize: '0.65rem',
                    fontWeight: 900,
                  }}>
                    {selectedPlugins.length} SELECTED
                  </Box>
                )}
              </Button>
              <Collapse in={pluginSectionOpen}>
                <Box sx={{ mt: 1.5 }}>
                  <Typography sx={{ color: tokens.text.muted, fontSize: '0.68rem', mb: 1.5, fontFamily: 'monospace' }}>
                    Select which enabled plugins to include in this scan. Leave all unchecked to run all enabled plugins.
                  </Typography>
                  <FormGroup row sx={{ gap: 1 }}>
                    {enabledPlugins.map(plugin => (
                      <FormControlLabel
                        key={plugin.slug}
                        control={
                          <Checkbox
                            size="small"
                            checked={selectedPlugins.includes(plugin.slug)}
                            onChange={(e) => {
                              setSelectedPlugins(prev =>
                                e.target.checked
                                  ? [...prev, plugin.slug]
                                  : prev.filter(s => s !== plugin.slug)
                                );
                            }}
                            sx={{ color: alpha(tokens.accent.primary, 0.2), '&.Mui-checked': { color: tokens.accent.primary } }}
                          />
                        }
                        label={
                          <Box>
                            <Typography sx={{ fontSize: '0.8rem', color: tokens.text.primary, fontWeight: 700 }}>
                              {plugin.name}
                            </Typography>
                            {plugin.description && (
                              <Typography sx={{ fontSize: '0.65rem', color: tokens.text.secondary }}>
                                {plugin.description}
                              </Typography>
                            )}
                          </Box>
                        }
                        sx={{
                          mx: 0,
                          px: 1.5,
                          py: 0.75,
                          border: '1px solid',
                          borderColor: selectedPlugins.includes(plugin.slug)
                            ? alpha(tokens.accent.primary, 0.3)
                            : tokens.border.subtle,
                          borderRadius: 2,
                          bgcolor: selectedPlugins.includes(plugin.slug)
                            ? alpha(tokens.accent.primary, 0.05)
                            : alpha(tokens.text.primary, 0.02),
                          transition: 'all 0.15s',
                          alignItems: 'flex-start',
                        }}
                      />
                    ))}
                  </FormGroup>
                </Box>
              </Collapse>
            </Box>
          )}
        </DialogContent>

        <Box sx={{ px: 3, pb: 2 }}>
          <Button
            variant="text"
            size="small"
            onClick={() => setShowWorkflows(v => !v)}
            sx={{ color: tokens.text.secondary, textTransform: 'none' }}
          >
            {showWorkflows ? '▲ Hide Quick Workflows' : '▼ Quick Workflow Launch'}
          </Button>
          <Collapse in={showWorkflows}>
            <Box sx={{ mt: 1, p: 2, border: 1, borderColor: 'divider', borderRadius: 1 }}>
              <WorkflowLauncher
                onSuccess={(_id, _slug) => { onClose(); }}
                onError={(err) => console.error('Workflow error:', err)}
              />
            </Box>
          </Collapse>
        </Box>

        <DialogActions sx={{ p: 3, borderTop: `1px solid ${tokens.border.subtle}` }}>
          <Button
            onClick={handleClose}
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
            disabled={isPending || !formData.engine_id || domainIds.length === 0}
            sx={{
              bgcolor: tokens.accent.primary,
              color: theme.palette.getContrastText(tokens.accent.primary),
              fontWeight: 900,
              fontFamily: 'Orbitron',
              letterSpacing: 1,
              px: 4,
              '&:hover': {
                bgcolor: alpha(tokens.accent.primary, 0.85),
                boxShadow: `0 0 20px ${alpha(tokens.accent.primary, 0.4)}`
              },
              '&.Mui-disabled': {
                bgcolor: alpha(tokens.accent.primary, 0.2),
                color: alpha(theme.palette.getContrastText(tokens.accent.primary), 0.5)
              }
            }}
          >
            {isPending ? <CircularProgress size={20} sx={{ color: theme.palette.getContrastText(tokens.accent.primary) }} /> : 'START MISSION'}
          </Button>
        </DialogActions>
      </form>
    </Dialog>
  );
};
