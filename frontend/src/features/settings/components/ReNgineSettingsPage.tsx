import React, { useState } from 'react';
import {
  Box,
  Typography,
  Stack,
  Button,
  Paper,
  Divider,
  Alert,
  CircularProgress,
  Grid,
  Snackbar,
  Switch,
  FormControlLabel
} from '@mui/material';
import {
  Trash2,
  Database,
  Image as ImageIcon,
  AlertTriangle,
  HardDrive,
  Download,
  Upload
} from 'lucide-react';
import Chart from 'react-apexcharts';
import type { ApexOptions } from 'apexcharts';
import {
  useRengineSystemSettings,
  useDeleteAllScanResults,
  useDeleteAllScreenshots,
  useToggleScanQueueing,
  exportConfigBackup,
  exportScanResultsBackup,
  importConfigBackup
} from '../api';
import { TacticalPanel } from '../../../components/TacticalPanel';
import { useThemeTokens } from '../../../theme/useThemeTokens';

export const ReNgineSettingsPage: React.FC = () => {
  const { tokens } = useThemeTokens();
  const { data: systemInfo, isLoading } = useRengineSystemSettings();
  const deleteScanResults = useDeleteAllScanResults();
  const deleteScreenshots = useDeleteAllScreenshots();
  const toggleScanQueueing = useToggleScanQueueing();
  const [snackbar, setSnackbar] = useState<{
    open: boolean;
    message: string;
    severity: 'success' | 'error' | 'info' | 'warning';
  }>({
    open: false,
    message: '',
    severity: 'success',
  });

  const [importFile, setImportFile] = useState<File | null>(null);
  const [overwriteConfigs, setOverwriteConfigs] = useState(false);
  const [isExporting, setIsExporting] = useState(false);
  const [isExportingScanResults, setIsExportingScanResults] = useState(false);
  const [isImporting, setIsImporting] = useState(false);

  const handleCloseSnackbar = () => {
    setSnackbar({ ...snackbar, open: false });
  };

  const handleDeleteScanResults = async () => {
    if (window.confirm('CRITICAL: This will permanently delete all scan history and results. This action cannot be undone. Proceed?')) {
      try {
        await deleteScanResults.mutateAsync();
        setSnackbar({
          open: true,
          message: 'All scan results have been deleted.',
          severity: 'success',
        });
      } catch (err) {
        setSnackbar({
          open: true,
          message: 'Failed to initiate deletion of scan results.',
          severity: 'error',
        });
      }
    }
  };

  const handleDeleteScreenshots = async () => {
    if (window.confirm('WARNING: This will permanently delete all screenshots. Proceed?')) {
      try {
        await deleteScreenshots.mutateAsync();
        setSnackbar({
          open: true,
          message: 'All screenshots have been deleted.',
          severity: 'success',
        });
      } catch (err) {
        setSnackbar({
          open: true,
          message: 'Failed to initiate deletion of screenshots.',
          severity: 'error',
        });
      }
    }
  };

  const handleToggleQueueing = async () => {
    try {
      await toggleScanQueueing.mutateAsync();
      setSnackbar({
        open: true,
        message: 'Scan queueing setting updated.',
        severity: 'success',
      });
    } catch (err) {
      setSnackbar({
        open: true,
        message: 'Failed to update scan queueing setting.',
        severity: 'error',
      });
    }
  };

  const handleExportConfig = async () => {
    try {
      setIsExporting(true);
      const archive = await exportConfigBackup();
      const url = window.URL.createObjectURL(new Blob([archive]));
      const link = document.createElement('a');
      link.href = url;
      link.setAttribute('download', 'r3ngine_config_backup.zip');
      document.body.appendChild(link);
      link.click();
      link.remove();
      setSnackbar({ open: true, message: 'Configuration exported successfully', severity: 'success' });
    } catch (err) {
      setSnackbar({ open: true, message: 'Failed to export configuration', severity: 'error' });
    } finally {
      setIsExporting(false);
    }
  };

  const handleExportScanResults = async () => {
    try {
      setIsExportingScanResults(true);
      const archive = await exportScanResultsBackup();
      const url = window.URL.createObjectURL(new Blob([archive]));
      const link = document.createElement('a');
      link.href = url;
      link.setAttribute('download', 'scan_results_backup.zip');
      document.body.appendChild(link);
      link.click();
      link.remove();
      setSnackbar({ open: true, message: 'Scan results exported successfully', severity: 'success' });
    } catch (err) {
      setSnackbar({ open: true, message: 'Failed to export scan results', severity: 'error' });
    } finally {
      setIsExportingScanResults(false);
    }
  };

  const handleImportConfig = async () => {
    if (!importFile) return;
    try {
      setIsImporting(true);
      const result = await importConfigBackup(importFile, overwriteConfigs);
      if (result.status) {
        setSnackbar({ open: true, message: 'Configuration imported successfully', severity: 'success' });
        setImportFile(null);
      } else {
        setSnackbar({ open: true, message: result.message || 'Import failed', severity: 'error' });
      }
    } catch (err) {
      setSnackbar({ open: true, message: 'Failed to import configuration', severity: 'error' });
    } finally {
      setIsImporting(false);
    }
  };

  if (isLoading) {
    return (
      <Box sx={{ display: 'flex', justifyContent: 'center', p: 10 }}>
        <CircularProgress sx={{ color: tokens.accent.primary }} />
      </Box>
    );
  }

  const percent = systemInfo?.consumed_percent || 0;
  const isDanger = percent >= 90;
  const isWarning = percent >= 70;

  const gaugeColor = isDanger ? '#ff1100' : (isWarning ? '#ffcc00' : tokens.accent.primary);
  const gradientColor = isDanger ? '#cc0000' : (isWarning ? '#997700' : tokens.accent.primary);

  const chartOptions: ApexOptions = {
    chart: {
      type: "radialBar",
      offsetY: -30,
      sparkline: {
        enabled: true
      }
    },
    plotOptions: {
      radialBar: {
        startAngle: -90,
        endAngle: 90,
        track: {
          background: "rgba(255, 255, 255, 0.05)",
          strokeWidth: '97%',
          margin: 5,
          dropShadow: {
            enabled: true,
            top: 2,
            left: 0,
            color: '#000',
            opacity: 0.3,
            blur: 4
          }
        },
        dataLabels: {
          name: {
            show: false
          },
          value: {
            offsetY: -2,
            fontSize: '22px',
            color: 'text.primary',
            fontWeight: 900,
            fontFamily: 'Orbitron'
          }
        }
      }
    },
    fill: {
      type: 'gradient',
      gradient: {
        shade: 'dark',
        type: 'horizontal',
        shadeIntensity: 0.5,
        gradientToColors: [gradientColor],
        inverseColors: true,
        opacityFrom: 1,
        opacityTo: 1,
        stops: [0, 100]
      }
    },
    stroke: {
      lineCap: 'round'
    },
    labels: ['Storage Used'],
    colors: [gaugeColor],
  };

  const series = [percent];

  return (
    <Box sx={{ p: 3, maxWidth: 1200, mx: 'auto' }}>
      <Stack spacing={3}>
        <Box>
          <Typography variant="h4" sx={{ color: 'text.primary', fontFamily: 'Orbitron', fontWeight: 900, mb: 1 }}>
            RENGINE SYSTEM CONFIG
          </Typography>
          <Typography variant="body2" sx={{ color: 'text.secondary' }}>
            Monitor system resources and perform global maintenance actions.
          </Typography>
        </Box>

        <TacticalPanel title="SCAN CONFIGURATION">
          <Box sx={{ p: 2 }}>
            <FormControlLabel
              control={
                <Switch
                  checked={systemInfo?.enable_scan_queueing || false}
                  onChange={handleToggleQueueing}
                  disabled={toggleScanQueueing.isPending}
                  color="info"
                />
              }
              label={
                <Box>
                  <Typography sx={{ color: 'text.primary', fontFamily: 'Orbitron', fontWeight: 600 }}>
                    Enable Scan Queueing
                  </Typography>
                  <Typography variant="caption" sx={{ color: 'text.secondary' }}>
                    When enabled, running main scans and subscans will queue rather than running concurrently, allowing max 1 main scan and 1 specific subscan at a time.
                  </Typography>
                </Box>
              }
            />
          </Box>
        </TacticalPanel>

        <TacticalPanel title="CONFIGURATION EXPORT / IMPORT">
          <Box sx={{ display: 'flex', flexDirection: 'column', gap: 3, p: 2 }}>
            <Box sx={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
              <Box>
                <Typography sx={{ color: tokens.accent.primary, fontWeight: 900, mb: 0.5, textTransform: 'uppercase' }}>
                  Export Configuration
                </Typography>
                <Typography variant="body2" sx={{ color: 'text.secondary' }}>
                  Download a ZIP containing all configured API keys, tool configs, custom scan engines, and custom wordlists.
                </Typography>
              </Box>
              <Button
                variant="outlined"
                color="info"
                onClick={handleExportConfig}
                disabled={isExporting}
                startIcon={isExporting ? <CircularProgress size={18} /> : <Download size={18} />}
                sx={{
                  borderColor: tokens.accent.primary,
                  color: tokens.accent.primary,
                  fontFamily: 'Orbitron',
                  fontWeight: 900,
                  px: 3,
                  '&:hover': {
                    bgcolor: `${tokens.accent.primary}1A`,
                    borderColor: tokens.accent.primary
                  }
                }}
              >
                {isExporting ? 'EXPORTING...' : 'DOWNLOAD BACKUP'}
              </Button>
            </Box>

            <Divider sx={{ borderColor: 'divider' }} />

            <Box sx={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
              <Box>
                <Typography sx={{ color: tokens.accent.primary, fontWeight: 900, mb: 0.5, textTransform: 'uppercase' }}>
                  Export Scan Results
                </Typography>
                <Typography variant="body2" sx={{ color: 'text.secondary' }}>
                  Download a ZIP containing all scan results and reports from the container. This may take some time depending on size.
                </Typography>
              </Box>
              <Button
                variant="outlined"
                color="info"
                onClick={handleExportScanResults}
                disabled={isExportingScanResults}
                startIcon={isExportingScanResults ? <CircularProgress size={18} /> : <Download size={18} />}
                sx={{
                  borderColor: tokens.accent.primary,
                  color: tokens.accent.primary,
                  fontFamily: 'Orbitron',
                  fontWeight: 900,
                  px: 3,
                  '&:hover': {
                    bgcolor: `${tokens.accent.primary}1A`,
                    borderColor: tokens.accent.primary
                  }
                }}
              >
                {isExportingScanResults ? 'EXPORTING...' : 'DOWNLOAD SCANS'}
              </Button>
            </Box>

            <Divider sx={{ borderColor: 'divider' }} />

            <Box sx={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
              <Box sx={{ flex: 1 }}>
                <Typography sx={{ color: '#00ff9d', fontWeight: 900, mb: 0.5, textTransform: 'uppercase' }}>
                  Import Configuration
                </Typography>
                <Typography variant="body2" sx={{ color: 'text.secondary', mb: 1 }}>
                  Upload a previously exported ZIP backup to restore API keys, engines, tools, and wordlists.
                </Typography>
                <Stack direction="row" sx={{ spacing: 2, alignItems: 'center' }}>
                  <Button
                    variant="contained"
                    component="label"
                    sx={{
                      bgcolor: '#00ff9d',
                      color: '#000',
                      fontFamily: 'Orbitron',
                      fontWeight: 900,
                      '&:hover': { bgcolor: '#00cc7d' }
                    }}
                  >
                    SELECT ZIP
                    <input
                      type="file"
                      accept=".zip"
                      hidden
                      onChange={(e) => {
                        if (e.target.files && e.target.files[0]) {
                          setImportFile(e.target.files[0]);
                        }
                      }}
                    />
                  </Button>
                  {importFile && (
                    <Typography variant="body2" sx={{ color: 'text.primary' }}>
                      {importFile.name}
                    </Typography>
                  )}
                </Stack>
                <Box sx={{ mt: 1 }}>
                  <FormControlLabel
                    control={
                      <Switch
                        checked={overwriteConfigs}
                        onChange={(e) => setOverwriteConfigs(e.target.checked)}
                        color="success"
                      />
                    }
                    label={<Typography variant="body2" sx={{ color: 'text.secondary' }}>Overwrite existing configurations</Typography>}
                  />
                </Box>
              </Box>

              <Button
                variant="outlined"
                color="success"
                onClick={handleImportConfig}
                disabled={!importFile || isImporting}
                startIcon={isImporting ? <CircularProgress size={18} /> : <Upload size={18} />}
                sx={{
                  borderColor: '#00ff9d',
                  color: '#00ff9d',
                  fontFamily: 'Orbitron',
                  fontWeight: 900,
                  px: 3,
                  '&:hover': {
                    bgcolor: 'rgba(0, 255, 157, 0.1)',
                    borderColor: '#00ff9d'
                  }
                }}
              >
                {isImporting ? 'IMPORTING...' : 'UPLOAD BACKUP'}
              </Button>
            </Box>
          </Box>
        </TacticalPanel>

        <TacticalPanel title="STORAGE METRICS">
          <Box sx={{
            display: 'flex',
            flexDirection: { xs: 'column', md: 'row' },
            alignItems: 'center',
            justifyContent: 'center',
            gap: { xs: 4, md: 8 }
          }}>
            <Box sx={{ width: 300, display: 'flex', justifyContent: 'center', alignItems: 'center', position: 'relative' }}>
              <Chart
                options={chartOptions}
                series={series}
                type="radialBar"
                height={320}
              />
              <Box sx={{ position: 'absolute', bottom: 10, textAlign: 'center' }}>
                <Typography sx={{
                  fontFamily: 'Orbitron',
                  fontSize: '0.6rem',
                  fontWeight: 900,
                  color: gaugeColor,
                  letterSpacing: 2,
                  textTransform: 'uppercase'
                }}>
                  {isDanger ? 'CRITICAL LEVEL' : (isWarning ? 'WARNING LEVEL' : 'STABLE LEVEL')}
                </Typography>
              </Box>
            </Box>

            <Box sx={{ flex: '0 1 auto' }}>
              <Grid container spacing={3}>
                <Grid size={{ xs: 12, sm: 4 }} >
                  <MetricCard
                    label="TOTAL STORAGE"
                    value={`${systemInfo?.total || 0} GB`}
                    icon={<Database size={20} color="#ffd600" />}
                  />
                </Grid>
                <Grid size={{ xs: 12, sm: 4 }} >
                  <MetricCard
                    label="USED SPACE"
                    value={`${systemInfo?.used || 0} GB`}
                    icon={<HardDrive size={20} color={gaugeColor} />}
                    statusColor={gaugeColor}
                  />
                </Grid>
                <Grid size={{ xs: 12, sm: 4 }} >
                  <MetricCard
                    label="FREE SPACE"
                    value={`${systemInfo?.free || 0} GB`}
                    icon={<Database size={20} color="#00ff9d" />}
                    statusColor="#00ff9d"
                  />
                </Grid>
              </Grid>
            </Box>
          </Box>
        </TacticalPanel>

        <TacticalPanel title="DANGER ZONE" borderColor="rgba(255, 0, 85, 0.3)">
          <Stack spacing={0} divider={<Divider sx={{ borderColor: 'rgba(255,0,85,0.1)' }} />}>
            <MaintenanceRow
              title="Delete all scan results"
              description="Permanently remove all scan history, findings, and logs across all projects. This action is irreversible."
              onAction={handleDeleteScanResults}
              isLoading={deleteScanResults.isPending}
              buttonLabel="PURGE ALL SCANS"
            />
            <MaintenanceRow
              title="Delete all screenshots"
              description="Remove all captured website screenshots to free up disk space. Scan reports will no longer show visual evidence."
              onAction={handleDeleteScreenshots}
              isLoading={deleteScreenshots.isPending}
              buttonLabel="PURGE SCREENSHOTS"
            />
          </Stack>
        </TacticalPanel>

        <Alert
          severity="info"
          icon={<AlertTriangle size={20} />}
          sx={{
            bgcolor: `${tokens.accent.primary}0D`,
            color: tokens.accent.primary,
            border: `1px solid ${tokens.accent.primary}33`,
            '& .MuiAlert-icon': { color: tokens.accent.primary }
          }}
        >
          System maintenance actions affect all projects globally. Ensure you have backups before performing purge operations.
        </Alert>
      </Stack>

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
    </Box>
  );
};

const MetricCard: React.FC<{ label: string; value: string; icon: React.ReactNode; statusColor?: string }> = ({ label, value, icon, statusColor }) => (
  <Paper sx={{
    p: 2,
    bgcolor: 'action.hover',
    border: '1px solid',
    borderColor: statusColor ? `${statusColor}33` : 'divider',
    display: 'flex',
    flexDirection: 'column',
    gap: 1,
    transition: 'all 0.3s ease',
    '&:hover': {
      bgcolor: 'action.selected',
      borderColor: statusColor ? statusColor : 'text.disabled',
    }
  }}>
    <Box sx={{ display: 'flex', alignItems: 'center', gap: 1 }}>
      {icon}
      <Typography sx={{ color: 'text.secondary', fontSize: '0.7rem', fontWeight: 900, fontFamily: 'Orbitron' }}>
        {label}
      </Typography>
    </Box>
    <Typography sx={{ color: 'text.primary', fontSize: '1.2rem', fontWeight: 900, fontFamily: 'Orbitron' }}>
      {value}
    </Typography>
  </Paper>
);

const MaintenanceRow: React.FC<{
  title: string;
  description: string;
  onAction: () => void;
  isLoading: boolean;
  buttonLabel: string;
}> = ({ title, description, onAction, isLoading, buttonLabel }) => (
  <Box sx={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', py: 3, px: 2 }}>
    <Box sx={{ flex: 1, pr: 4 }}>
      <Typography sx={{ color: '#ff0055', fontWeight: 900, mb: 0.5, textTransform: 'uppercase' }}>
        {title}
      </Typography>
      <Typography variant="body2" sx={{ color: 'text.secondary' }}>
        {description}
      </Typography>
    </Box>
    <Button
      variant="outlined"
      color="error"
      onClick={onAction}
      disabled={isLoading}
      startIcon={<Trash2 size={18} />}
      sx={{
        borderColor: '#ff0055',
        color: '#ff0055',
        fontFamily: 'Orbitron',
        fontWeight: 900,
        px: 3,
        '&:hover': {
          bgcolor: 'rgba(255, 0, 85, 0.1)',
          borderColor: '#ff0055'
        }
      }}
    >
      {isLoading ? 'PROCESSING...' : buttonLabel}
    </Button>
  </Box>
);
