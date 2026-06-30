import React, { useState, useEffect } from 'react';
import {
  Box,
  Typography,
  Card,
  CardContent,
  Switch,
  FormControlLabel,
  TextField,
  Button,
  LinearProgress,
  Alert,
  Stack,
  Snackbar,
  CircularProgress,
  Checkbox
} from '@mui/material';
import {
  Settings,
  Shield,
  Save,
  RefreshCw,
  AlertCircle,
  CheckCircle2
} from 'lucide-react';
import { useParams } from '@tanstack/react-router';
import { useQueryClient } from '@tanstack/react-query';
import { ConfirmDialog } from '../../../components/ConfirmDialog';
import { useProxySettings, useUpdateProxySettings, useFetchProxies, useProxyTaskStatus, useTorStatus } from '../api';
import { TacticalPanel } from '../../../components/TacticalPanel';
import { ProxyValidationModal } from './ProxyValidationModal';
import { useThemeTokens } from '../../../theme/useThemeTokens';

const KNOWN_SCHEMES = /^(https?|socks[45]):\/\//i;
const HOST_PORT_RE = /^[\w.\-]+:\d{1,5}$/;

/**
 * Validates a single line from a fetched proxy list.
 * Returns the bare "host:port" string, or null if the line is malformed.
 * Exported for unit testing.
 */
export function parseProxyLine(line: string): string | null {
  const trimmed = line.trim();
  if (!trimmed || trimmed.startsWith('#') || trimmed.startsWith('//')) return null;

  const bare = trimmed.replace(KNOWN_SCHEMES, '');

  // Credentials (user:pass@) or a path after the port are both invalid.
  if (bare.includes('@') || bare.includes('/')) return null;

  if (!HOST_PORT_RE.test(bare)) return null;

  const port = parseInt(bare.slice(bare.lastIndexOf(':') + 1), 10);
  if (port < 1 || port > 65535) return null;

  return bare;
}

export const ProxySettingsPage: React.FC = () => {
  const { tokens } = useThemeTokens();
  const { projectSlug = 'default' } = useParams({ strict: false }) as any;
  const queryClient = useQueryClient();
  const { data: settings, isLoading: isSettingsLoading } = useProxySettings(projectSlug);
  const updateSettings = useUpdateProxySettings(projectSlug);
  const fetchProxies = useFetchProxies(projectSlug);

  const [useProxy, setUseProxy] = useState(false);
  const [useProxychains, setUseProxychains] = useState(false);
  const [proxyList, setProxyList] = useState('');
  const [currentTaskId, setCurrentTaskId] = useState<string | null>(null);
  const [isConfirmOpen, setIsConfirmOpen] = useState(false);
  const [fetchLimit, setFetchLimit] = useState<number | 'custom'>(1000);
  const [customLimit, setCustomLimit] = useState<string>('2000');
  const [validateOnSave, setValidateOnSave] = useState(false);
  const [useTor, setUseTor] = useState(false);
  const [isValidationModalOpen, setIsValidationModalOpen] = useState(false);
  const [isFetchingQuick, setIsFetchingQuick] = useState<string | null>(null);

  const { data: torStatus } = useTorStatus();
  const [snackbar, setSnackbar] = useState<{
    open: boolean;
    message: string;
    severity: 'success' | 'error' | 'info' | 'warning';
  }>({
    open: false,
    message: '',
    severity: 'success',
  });

  const { data: taskStatus } = useProxyTaskStatus(projectSlug, currentTaskId);

  useEffect(() => {
    if (settings) {
      setUseProxy(settings.use_proxy);
      setUseProxychains(settings.use_proxychains);
      setProxyList(settings.proxies);
      setUseTor(settings.use_tor ?? false);
    }
  }, [settings]);

  useEffect(() => {
    if (taskStatus?.status === 'SUCCESS' && taskStatus.result) {
      const resultData = taskStatus.result as any;
      const proxyStr = typeof resultData === 'string' ? resultData : (resultData?.proxies || '');
      setProxyList(proxyStr);
      setUseProxy(true);
      queryClient.invalidateQueries({ queryKey: ['proxy-settings', projectSlug] });
      setSnackbar({
        open: true,
        message: 'Proxies automatically fetched and saved to database.',
        severity: 'success',
      });
      setCurrentTaskId(null);
    } else if (taskStatus?.status === 'FAILURE') {
      setSnackbar({
        open: true,
        message: 'Failed to fetch proxies automatically.',
        severity: 'error',
      });
      setCurrentTaskId(null);
    }
  }, [projectSlug, queryClient, taskStatus]);

  const handleCloseSnackbar = () => {
    setSnackbar({ ...snackbar, open: false });
  };

  const doSave = (proxies: string, skipValidation: boolean) => {
    updateSettings.mutate({
      use_proxy: useProxy,
      use_proxychains: useProxychains,
      proxies,
      skip_validation: skipValidation,
      use_tor: useTor,
    }, {
      onSuccess: () => {
        setSnackbar({ open: true, message: 'Proxy settings saved successfully.', severity: 'success' });
      },
      onError: (error: any) => {
        setSnackbar({
          open: true,
          message: `Failed to save proxy settings: ${error?.response?.data?.message || error.message || 'Unknown error'}`,
          severity: 'error',
        });
      },
    });
  };

  const handleSave = () => {
    if (validateOnSave && useProxy && proxyList.trim()) {
      setIsValidationModalOpen(true);
    } else {
      doSave(proxyList, true);
    }
  };

  const handleValidationSave = (validProxies: string[]) => {
    setIsValidationModalOpen(false);
    const validList = validProxies.join('\n');
    setProxyList(validList);
    doSave(validList, true);
  };

  const handleLimitChange = (option: number | 'custom') => {
    setFetchLimit(option);
  };

  const handleFetchClick = () => {
    setIsConfirmOpen(true);
  };

  const handleConfirmFetch = () => {
    setIsConfirmOpen(false);
    setSnackbar({
      open: true,
      message: 'Initiating proxy fetch task...',
      severity: 'success'
    });

    const finalLimit = fetchLimit === 'custom' ? parseInt(customLimit, 10) || 1000 : fetchLimit;

    fetchProxies.mutate(finalLimit, {
      onSuccess: (data) => {
        setCurrentTaskId(data.task_id);
        setSnackbar({
          open: true,
          message: 'Proxy fetch task started. Monitoring progress...',
          severity: 'success'
        });
      },
      onError: (error: any) => {
        setSnackbar({
          open: true,
          message: `Failed to start proxy fetch: ${error?.response?.data?.error || error?.response?.data?.message || error.message || 'Unknown error'}`,
          severity: 'error'
        });
      }
    });
  };

  const handleFetchQuick = async (url: string, protocol: 'socks5' | 'socks4' | 'https', label: string) => {
    setIsFetchingQuick(label);
    try {
      const response = await fetch(url);
      if (!response.ok) {
        throw new Error(`HTTP error! status: ${response.status}`);
      }
      const text = await response.text();
      const parsedLines = text
        .split('\n')
        .map(line => parseProxyLine(line))
        .filter((p): p is string => p !== null);

      if (parsedLines.length === 0) {
        setSnackbar({
          open: true,
          message: `No valid proxies found in ${label}.`,
          severity: 'warning'
        });
        return;
      }

      const prefix = `${protocol}://`;
      const formatted = parsedLines.map(p => `${prefix}${p}`);

      let addedCount = 0;
      setProxyList(prev => {
        const existingSet = new Set(prev.split('\n').map(l => l.trim()).filter(Boolean));
        const newEntries = formatted.filter(p => !existingSet.has(p));
        addedCount = newEntries.length;
        if (newEntries.length === 0) return prev;
        return [...existingSet, ...newEntries].join('\n');
      });

      setSnackbar({
        open: true,
        message: addedCount > 0
          ? `Added ${addedCount} new proxies from ${label}.`
          : `No new proxies from ${label} — all already present.`,
        severity: addedCount > 0 ? 'success' : 'info'
      });
      setUseProxy(true);
    } catch (error: any) {
      setSnackbar({
        open: true,
        message: `Failed to fetch from ${label}: ${error.message}`,
        severity: 'error'
      });
    } finally {
      setIsFetchingQuick(null);
    }
  };


  const parsedProxies = proxyList.split('\n').map(p => p.trim()).filter(p => p.length > 0);

  if (isSettingsLoading) return <LinearProgress sx={{ bgcolor: `${tokens.accent.primary}1A`, '& .MuiLinearProgress-bar': { bgcolor: tokens.accent.primary } }} />;

  return (
    <Box sx={{ p: 3 }}>
      <Box sx={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', mb: 4 }}>
        <Box>
          <Typography variant="h4" sx={{
            fontFamily: 'Orbitron',
            fontWeight: 900,
            letterSpacing: 2,
            color: 'text.primary',
            textShadow: `0 0 20px ${tokens.accent.primary}80`,
            mb: 1
          }}>
            PROXY SETTINGS
          </Typography>
          <Typography variant="body2" sx={{ color: 'text.secondary', letterSpacing: 1 }}>
            TRAFFIC ANONYMIZATION & RATE LIMIT BYPASS
          </Typography>
        </Box>
        <Box sx={{ textAlign: 'right' }}>
          <Typography variant="caption" sx={{ color: 'text.disabled', fontFamily: 'Orbitron', display: 'block', mb: 1 }}>
            SETTINGS {'>'} <span style={{ color: tokens.accent.primary }}>PROXY</span>
          </Typography>
          <Box sx={{
            display: 'inline-flex',
            alignItems: 'center',
            bgcolor: `${tokens.accent.primary}1A`,
            px: 1.5,
            py: 0.5,
            borderRadius: 1,
            border: `1px solid ${tokens.accent.primary}4D`
          }}>
            <Typography variant="caption" sx={{ color: tokens.accent.primary, fontFamily: 'Orbitron', fontWeight: 700, letterSpacing: 1 }}>
              TOTAL PROXIES: {proxyList.split('\n').filter(p => p.trim() !== '').length}
            </Typography>
          </Box>
        </Box>
      </Box>

      <Stack spacing={3}>
        <Alert
          severity="info"
          icon={<Shield size={20} />}
          sx={{
            bgcolor: `${tokens.accent.primary}0D`,
            color: tokens.accent.primary,
            border: `1px solid ${tokens.accent.primary}33`,
            '& .MuiAlert-icon': { color: tokens.accent.primary }
          }}
        >
          Every website has a limit to requests. Exceeding it results in blocks.
          Using proxies is highly recommended for reliable recon and OSINT.
        </Alert>

        <TacticalPanel title="CONFIGURATION" icon={<Settings size={20} />}>
          <Box sx={{ p: 1 }}>
            <Box sx={{ display: 'flex', flexDirection: 'column', gap: 1 }}>
              <FormControlLabel
                control={
                  <Switch
                    checked={useProxy}
                    onChange={(e) => setUseProxy(e.target.checked)}
                    sx={{
                      '& .MuiSwitch-switchBase.Mui-checked': { color: tokens.accent.primary },
                      '& .MuiSwitch-switchBase.Mui-checked + .MuiSwitch-track': { bgcolor: tokens.accent.primary }
                    }}
                  />
                }
                label={
                  <Typography sx={{ color: 'text.primary', fontFamily: 'Orbitron', fontSize: '0.9rem', fontWeight: 700 }}>
                    ENABLE PROXY ROTATION
                  </Typography>
                }
              />

              <FormControlLabel
                control={
                  <Switch
                    checked={useProxychains}
                    onChange={(e) => setUseProxychains(e.target.checked)}
                    disabled={!useProxy}
                    sx={{
                      '& .MuiSwitch-switchBase.Mui-checked': { color: tokens.accent.secondary },
                      '& .MuiSwitch-switchBase.Mui-checked + .MuiSwitch-track': { bgcolor: tokens.accent.secondary }
                    }}
                  />
                }
                label={
                  <Box>
                    <Typography sx={{ color: 'text.primary', fontFamily: 'Orbitron', fontSize: '0.9rem', fontWeight: 700 }}>
                      USE PROXYCHAINS WRAPPER
                    </Typography>
                    <Typography variant="caption" sx={{ color: 'text.secondary', display: 'block' }}>
                      Force proxy usage for tools without native proxy support
                    </Typography>
                  </Box>
                }
              />
            </Box>

            <Box sx={{
              mt: 3, p: 2,
              bgcolor: 'action.hover',
              borderRadius: 1,
              border: 1,
              borderColor: 'divider',
              display: 'flex',
              alignItems: 'center',
              gap: 2,
              flexWrap: { xs: 'wrap', md: 'nowrap' },
            }}>
              <Box sx={{ flex: 1, minWidth: 0 }}>
                <Typography variant="subtitle2" sx={{ color: 'text.primary', fontFamily: 'Orbitron', mb: 0.5, fontWeight: 700 }}>
                  AUTOMATED PROXY FETCH LIMIT
                </Typography>
                <Typography variant="caption" sx={{ color: 'text.secondary', display: 'block' }}>
                  Select the maximum number of raw proxies to scrape and check for liveness.
                  (Note: It may take a while to complete [~75000/10m:00s]. Validation rate: ~1/3%)
                </Typography>
              </Box>

              <Box sx={{ display: 'flex', alignItems: 'center', gap: 0.5, flexShrink: 0, flexWrap: 'nowrap' }}>
                {([5000, 10000, 25000] as const).map((n) => (
                  <FormControlLabel
                    key={n}
                    control={
                      <Checkbox
                        checked={fetchLimit === n}
                        onChange={() => handleLimitChange(n)}
                        size="small"
                        sx={{ color: `${tokens.accent.primary}4D`, '&.Mui-checked': { color: tokens.accent.primary } }}
                      />
                    }
                    label={<Typography sx={{ color: 'text.primary', fontFamily: 'Orbitron', fontSize: '0.78rem', whiteSpace: 'nowrap' }}>{n.toLocaleString()} Proxies</Typography>}
                    sx={{ mr: 0 }}
                  />
                ))}
                <FormControlLabel
                  control={
                    <Checkbox
                      checked={fetchLimit === 'custom'}
                      onChange={() => handleLimitChange('custom')}
                      size="small"
                      sx={{ color: `${tokens.accent.primary}4D`, '&.Mui-checked': { color: tokens.accent.primary } }}
                    />
                  }
                  label={<Typography sx={{ color: 'text.primary', fontFamily: 'Orbitron', fontSize: '0.78rem' }}>Custom</Typography>}
                  sx={{ mr: 0 }}
                />
                {fetchLimit === 'custom' && (
                  <TextField
                    type="number"
                    label="Enter Proxy Count"
                    value={customLimit}
                    onChange={(e) => setCustomLimit(e.target.value)}
                    size="small"
                    sx={{
                      ml: 1,
                      width: 160,
                      '& .MuiInputLabel-root': { color: 'text.secondary', fontFamily: 'Orbitron', fontSize: '0.75rem' },
                      '& .MuiOutlinedInput-root': {
                        color: 'text.primary',
                        bgcolor: 'action.hover',
                        '& fieldset': { borderColor: 'divider' },
                        '&:hover fieldset': { borderColor: `${tokens.accent.primary}4D` },
                        '&.Mui-focused fieldset': { borderColor: tokens.accent.primary },
                      },
                    }}
                  />
                )}
              </Box>
            </Box>

            <Box sx={{ mt: 3, mb: 1.5, display: 'flex', alignItems: 'center', gap: 1.5, flexWrap: 'wrap' }}>
              <Typography variant="body2" sx={{ color: 'text.secondary', fontWeight: 600, fontFamily: 'Orbitron', fontSize: '0.75rem', letterSpacing: 0.5 }}>
                FETCH PROXY FROM:
              </Typography>
              
              <Button
                variant="outlined"
                size="small"
                disabled={isFetchingQuick !== null}
                onClick={() => handleFetchQuick(
                  'https://raw.githubusercontent.com/proxifly/free-proxy-list/refs/heads/main/proxies/protocols/socks5/data.txt',
                  'socks5',
                  'proxifly(s5)'
                )}
                sx={{
                  borderColor: 'divider',
                  color: tokens.accent.primary,
                  fontFamily: 'Orbitron',
                  fontSize: '0.65rem',
                  fontWeight: 900,
                  py: 0.2,
                  px: 1.2,
                  minWidth: 0,
                  '&:hover': { borderColor: tokens.accent.primary, bgcolor: `${tokens.accent.primary}0D` }
                }}
              >
                {isFetchingQuick === 'proxifly(s5)' ? 'LOADING...' : 'PROXIFLY (S5)'}
              </Button>

              <Button
                variant="outlined"
                size="small"
                disabled={isFetchingQuick !== null}
                onClick={() => handleFetchQuick(
                  'https://raw.githubusercontent.com/proxifly/free-proxy-list/refs/heads/main/proxies/protocols/socks4/data.txt',
                  'socks4',
                  'proxifly(s4)'
                )}
                sx={{
                  borderColor: 'divider',
                  color: tokens.accent.secondary,
                  fontFamily: 'Orbitron',
                  fontSize: '0.65rem',
                  fontWeight: 900,
                  py: 0.2,
                  px: 1.2,
                  minWidth: 0,
                  '&:hover': { borderColor: tokens.accent.secondary, bgcolor: `${tokens.accent.secondary}0D` }
                }}
              >
                {isFetchingQuick === 'proxifly(s4)' ? 'LOADING...' : 'PROXIFLY (S4)'}
              </Button>

              <Button
                variant="outlined"
                size="small"
                disabled={isFetchingQuick !== null}
                onClick={() => handleFetchQuick(
                  'https://raw.githubusercontent.com/proxifly/free-proxy-list/refs/heads/main/proxies/protocols/https/data.txt',
                  'https',
                  'proxifly(https)'
                )}
                sx={{
                  borderColor: 'divider',
                  color: tokens.accent.primary,
                  fontFamily: 'Orbitron',
                  fontSize: '0.65rem',
                  fontWeight: 900,
                  py: 0.2,
                  px: 1.2,
                  minWidth: 0,
                  '&:hover': { borderColor: tokens.accent.primary, bgcolor: `${tokens.accent.primary}0D` }
                }}
              >
                {isFetchingQuick === 'proxifly(https)' ? 'LOADING...' : 'PROXIFLY (HTTPS)'}
              </Button>

              <Button
                variant="outlined"
                size="small"
                disabled={isFetchingQuick !== null}
                onClick={() => handleFetchQuick(
                  'https://raw.githubusercontent.com/VPSLabCloud/VPSLab-Free-Proxy-List/refs/heads/main/socks5_all.txt',
                  'socks5',
                  'vpslab(s5)'
                )}
                sx={{
                  borderColor: 'divider',
                  color: tokens.accent.secondary,
                  fontFamily: 'Orbitron',
                  fontSize: '0.65rem',
                  fontWeight: 900,
                  py: 0.2,
                  px: 1.2,
                  minWidth: 0,
                  '&:hover': { borderColor: tokens.accent.secondary, bgcolor: `${tokens.accent.secondary}0D` }
                }}
              >
                {isFetchingQuick === 'vpslab(s5)' ? 'LOADING...' : 'VPSLAB (S5)'}
              </Button>

              <Typography
                variant="caption"
                sx={{ color: 'text.disabled', fontSize: '0.6rem', width: '100%', mt: 0.5 }}
              >
                Unvetted public lists — review all entries before saving.
              </Typography>
            </Box>

            <Typography variant="body2" sx={{ color: 'text.secondary', mt: 2, mb: 1, fontWeight: 600 }}>
              PROXY LIST (ONE PER LINE)
            </Typography>

            <TextField
              multiline
              rows={12}
              fullWidth
              variant="outlined"
              value={proxyList}
              onChange={(e) => setProxyList(e.target.value)}
              disabled={!useProxy}
              placeholder="http://ip:port\nhttp://user:pass@ip:port"
              sx={{
                '& .MuiOutlinedInput-root': {
                  color: 'text.primary',
                  bgcolor: 'action.hover',
                  fontFamily: 'monospace',
                  fontSize: '0.85rem',
                  '& fieldset': { borderColor: 'divider' },
                  '&:hover fieldset': { borderColor: `${tokens.accent.primary}4D` },
                  '&.Mui-focused fieldset': { borderColor: tokens.accent.primary },
                },
                '& .Mui-disabled': {
                  opacity: 0.5,
                  bgcolor: 'rgba(0,0,0,0.2)'
                }
              }}
            />

            {currentTaskId && (
              <Box sx={{ mb: 4, p: 2, bgcolor: 'action.hover', borderRadius: 1, border: 1, borderColor: 'divider' }}>
                <Stack direction="row" spacing={2} sx={{ alignItems: 'center', mb: 2 }}>
                  {(!taskStatus || taskStatus.status === 'PROGRESS' || taskStatus.status === 'PENDING') ? (
                    <CircularProgress size={20} sx={{ color: tokens.accent.primary }} />
                  ) : taskStatus.status === 'SUCCESS' ? (
                    <CheckCircle2 size={20} color="#00ff00" />
                  ) : (
                    <AlertCircle size={20} color="#ff0055" />
                  )}
                  <Box sx={{ flexGrow: 1 }}>
                    <Typography variant="subtitle2" sx={{ color: 'text.primary', fontFamily: 'Orbitron', mb: 0.5 }}>
                      {taskStatus?.message || 'Initializing task...'}
                    </Typography>
                    <LinearProgress
                      variant="determinate"
                      value={taskStatus?.progress || 0}
                      sx={{
                        height: 6,
                        borderRadius: 3,
                        bgcolor: 'rgba(255, 255, 255, 0.05)',
                        '& .MuiLinearProgress-bar': { bgcolor: tokens.accent.primary }
                      }}
                    />
                  </Box>
                  <Typography variant="caption" sx={{ color: 'text.secondary', fontFamily: 'Orbitron' }}>
                    {taskStatus?.progress || 0}%
                  </Typography>
                </Stack>
                {taskStatus?.status === 'SUCCESS' && (
                  <Alert severity="success" sx={{ bgcolor: 'rgba(0, 255, 0, 0.05)', color: '#00ff00', border: '1px solid rgba(0, 255, 0, 0.2)' }}>
                    Proxies fetched, verified, and automatically saved to the database.
                  </Alert>
                )}
                {taskStatus?.status === 'FAILURE' && (
                  <Alert severity="error" sx={{ bgcolor: 'rgba(255, 0, 0, 0.05)', color: '#ff0055', border: '1px solid rgba(255, 0, 0, 0.2)' }}>
                    Task failed: {taskStatus.result || 'Unknown error during verification'}
                  </Alert>
                )}
              </Box>
            )}

            <Box sx={{ display: 'flex', justifyContent: 'space-between', mt: 4 }}>
              <Button
                variant="outlined"
                startIcon={<RefreshCw size={18} className={fetchProxies.isPending ? 'spin' : ''} />}
                onClick={handleFetchClick}
                disabled={fetchProxies.isPending || (taskStatus && taskStatus.status === 'PROGRESS')}
                sx={{
                  borderColor: tokens.accent.primary,
                  color: tokens.accent.primary,
                  fontFamily: 'Orbitron',
                  fontWeight: 800,
                  '&:hover': { borderColor: tokens.accent.primary, bgcolor: `${tokens.accent.primary}1A` }
                }}
              >
                FETCH & UPDATE
              </Button>

              <Box sx={{ display: 'flex', alignItems: 'center', gap: 2 }}>
                <FormControlLabel
                  control={
                    <Switch
                      checked={validateOnSave}
                      onChange={(e) => setValidateOnSave(e.target.checked)}
                      size="small"
                      sx={{
                        '& .MuiSwitch-switchBase.Mui-checked': { color: tokens.accent.primary },
                        '& .MuiSwitch-switchBase.Mui-checked + .MuiSwitch-track': { bgcolor: tokens.accent.primary }
                      }}
                    />
                  }
                  label={
                    <Typography sx={{ color: 'text.primary', fontFamily: 'Orbitron', fontSize: '0.8rem' }}>
                      VALIDATE ON SAVE
                    </Typography>
                  }
                />
                <Button
                  variant="contained"
                  startIcon={<Save size={18} />}
                  onClick={handleSave}
                  disabled={updateSettings.isPending}
                  sx={{
                    bgcolor: `${tokens.accent.primary}1A`,
                    color: tokens.accent.primary,
                    border: `1px solid ${tokens.accent.primary}4D`,
                    fontFamily: 'Orbitron',
                    fontWeight: 800,
                    '&:hover': { bgcolor: `${tokens.accent.primary}33`, boxShadow: `0 0 20px ${tokens.accent.primary}66` }
                  }}
                >
                  {updateSettings.isPending ? 'SAVING...' : 'SAVE PROXIES'}
                </Button>
              </Box>
            </Box>
          </Box>
        </TacticalPanel>

        {/* TOR Mode */}
        <Card variant="outlined" sx={{ mt: 2 }}>
          <CardContent>
            <Stack direction="row" sx={{ alignItems: 'center', mb: 1 }} spacing={1}>
              <Shield size={18} />
              <Typography variant="subtitle1" sx={{ fontWeight: 'bold' }}>
                TOR Mode
              </Typography>
              <Box
                sx={{
                  ml: 1,
                  px: 1,
                  py: 0.25,
                  borderRadius: 1,
                  bgcolor: torStatus?.running ? 'success.main' : 'grey.600',
                  color: 'white',
                  fontSize: '0.7rem',
                  fontWeight: 'bold',
                }}
              >
                {torStatus?.running ? 'RUNNING' : 'STOPPED'}
              </Box>
            </Stack>

            <Alert severity="warning" sx={{ mb: 2 }}>
              TOR Mode routes all scanning traffic through the TOR network.
              Tools using raw sockets (naabu) will log a warning but run
              without TOR routing. Scanning will be significantly slower than normal.
            </Alert>

            <FormControlLabel
              control={
                <Switch
                  checked={useTor}
                  onChange={(e) => {
                    const checked = e.target.checked;
                    setUseTor(checked);
                    if (checked) {
                      setUseProxy(false);
                      setUseProxychains(false);
                    }
                  }}
                  color="warning"
                />
              }
              label="Enable TOR Mode"
            />
          </CardContent>
        </Card>
      </Stack>

      <ConfirmDialog
        open={isConfirmOpen}
        title="FETCH PROXIES"
        message={`This will initiate an automated task to fetch up to ${fetchLimit === 'custom' ? customLimit : fetchLimit} raw proxies and verify them. The existing list will be updated with the results. You will need to SAVE the settings once the task completes. Proceed?`}
        onConfirm={handleConfirmFetch}
        onClose={() => setIsConfirmOpen(false)}
        type="info"
        isDestructive={false}
        confirmText="INITIATE FETCH"
      />

      <Snackbar
        open={snackbar.open}
        autoHideDuration={6000}
        onClose={handleCloseSnackbar}
        anchorOrigin={{ vertical: 'bottom', horizontal: 'right' }}
      >
        <Alert
          onClose={handleCloseSnackbar}
          severity={snackbar.severity}
          variant="filled"
          sx={{
            fontFamily: 'Orbitron',
            fontSize: '0.8rem',
            fontWeight: 700,
            bgcolor: snackbar.severity === 'success' ? `${tokens.accent.primary}E6` : 'rgba(255, 0, 85, 0.9)',
            color: '#000',
            '& .MuiAlert-icon': { color: '#000' }
          }}
        >
          {snackbar.message}
        </Alert>
      </Snackbar>

      <ProxyValidationModal
        open={isValidationModalOpen}
        onClose={() => setIsValidationModalOpen(false)}
        onSave={handleValidationSave}
        proxyList={parsedProxies}
        projectSlug={projectSlug}
      />
    </Box>
  );
};
