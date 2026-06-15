import React, { useState } from 'react';
import {
  Box,
  Typography,
  Button,
  Paper,
  Tabs,
  Tab,
  CircularProgress,
  Snackbar,
  Alert,
  Stack
} from '@mui/material';
import { alpha } from '@mui/material/styles';
import {
  Upload as UploadIcon,
  Extension as ExtensionIcon,
  AccountTree as PipelineIcon
} from '@mui/icons-material';
import {
  Shield
} from 'lucide-react';
import { useQueryClient } from '@tanstack/react-query';
import {
  usePlugins,
  useUploadPlugin,
  useMarketplacePlugins,
  useRefreshMarketplace
} from '../api/pluginsApi';
import PluginInventory from '../components/PluginInventory';
import PipelineBuilder from '../components/PipelineBuilder';
import InstallProgressOverlay from '../components/InstallProgressOverlay';
import { useThemeTokens } from '../../../theme/useThemeTokens';

const PluginManagementPage: React.FC = () => {
  const { tokens } = useThemeTokens();
  const [activeTab, setActiveTab] = useState(0);
  const [installId, setInstallId] = useState<string | null>(null);
  const [snackbar, setSnackbar] = useState<{ open: boolean; message: string; severity: 'success' | 'error' }>({
    open: false,
    message: '',
    severity: 'success'
  });

  const queryClient = useQueryClient();
  const { data: plugins, isLoading: isPluginsLoading, error: pluginsError } = usePlugins();
  const { data: marketplaceData, isLoading: isMarketplaceLoading } = useMarketplacePlugins();
  const uploadMutation = useUploadPlugin();
  const refreshMarketplaceMutation = useRefreshMarketplace();

  const handleFileUpload = (event: React.ChangeEvent<HTMLInputElement>) => {
    const file = event.target.files?.[0];
    if (file) {
      uploadMutation.mutate(file, {
        onSuccess: (result) => {
          setInstallId(result.install_id);
        },
        onError: (err: any) => {
          setSnackbar({
            open: true,
            message: `Upload failed: ${err.response?.data?.error || err.message}`,
            severity: 'error'
          });
        }
      });
    }
  };

  const handleInstallComplete = (pluginName: string) => {
    queryClient.invalidateQueries({ queryKey: ['plugins'] });
    queryClient.invalidateQueries({ queryKey: ['pluginsRegistry'] });
    setSnackbar({ open: true, message: `${pluginName} installed successfully!`, severity: 'success' });
    setInstallId(null);
  };

  const handleInstallError = (message: string) => {
    setSnackbar({ open: true, message, severity: 'error' });
    setInstallId(null);
  };

  const handleRefreshMarketplace = () => {
    refreshMarketplaceMutation.mutate(undefined, {
      onSuccess: () => {
        setSnackbar({ open: true, message: 'Marketplace index refreshed.', severity: 'success' });
      },
      onError: (err: any) => {
        setSnackbar({ 
          open: true, 
          message: `Refresh failed: ${err.message}`, 
          severity: 'error' 
        });
      }
    });
  };

  const isLoading = isPluginsLoading || (isMarketplaceLoading && !marketplaceData);

  if (isLoading) {
    return (
      <Box sx={{ display: "flex", flexDirection: 'column', alignItems: "center", justifyContent: 'center', height: '60vh', gap: 2 }}>
        <CircularProgress sx={{ color: tokens.accent.primary }} />
        <Typography sx={{ fontFamily: 'var(--r3-heading-font)', color: 'text.secondary', fontSize: '0.8rem', letterSpacing: 2 }}>
          BROWSING THE MARKETPLACE...
        </Typography>
      </Box>
    );
  }

  return (
    <Box sx={{ p: 4 }}>
      <InstallProgressOverlay
        installId={installId}
        onComplete={handleInstallComplete}
        onError={handleInstallError}
      />

      <Box sx={{ display: "flex", justifyContent: "space-between", alignItems: "flex-end", mb: 6 }}>
        <Box>
          <Stack direction="row" spacing={2} sx={{ alignItems: 'center', mb: 1 }}>
            <Shield size={32} color={tokens.accent.primary} />
            <Typography variant="h3" sx={{ fontFamily: 'var(--r3-heading-font)', fontWeight: 900, letterSpacing: -1, color: 'text.primary' }}>
              PLUGIN ORCHESTRATION
            </Typography>
          </Stack>
          <Typography variant="body1" sx={{ color: 'text.secondary', maxWidth: 600 }}>
            Extend system capabilities with modular reconnaissance engines and intelligence layers. 
            Maintain total control over the execution pipeline.
          </Typography>
        </Box>
        <Button
          variant="contained"
          component="label"
          startIcon={<UploadIcon />}
          sx={{
            bgcolor: tokens.accent.primary,
            color: tokens.mode === 'light' ? '#fff' : '#000',
            fontFamily: 'var(--r3-heading-font)',
            fontWeight: 900,
            borderRadius: 0,
            px: 4,
            py: 1.5,
            clipPath: 'polygon(10% 0, 100% 0, 90% 100%, 0% 100%)',
            '&:hover': { bgcolor: tokens.accent.primary }
          }}
        >
          UPLOAD PLUGIN
          <input type="file" hidden accept=".r3n,.zip" onChange={handleFileUpload} />
        </Button>
      </Box>

      {pluginsError && (
        <Alert 
          severity="error" 
          variant="outlined"
          sx={{ mb: 4, borderColor: alpha(tokens.accent.error, 0.3), color: tokens.accent.error, bgcolor: alpha(tokens.accent.error, 0.05) }}
        >
          CRITICAL ERROR: Failed to synchronize with orchestration backend.
        </Alert>
      )}

      <Paper sx={{ 
        borderRadius: 0, 
        overflow: 'hidden', 
        bgcolor: 'transparent',
        border: 1,
        borderColor: 'divider'
      }}>
        <Tabs
          value={activeTab}
          onChange={(_, val) => setActiveTab(val)}
          sx={{ 
            borderBottom: 1,
            borderColor: 'divider',
            bgcolor: 'action.hover',
            '& .MuiTab-root': {
              minHeight: 70,
              fontFamily: 'var(--r3-heading-font)',
              fontWeight: 800,
              fontSize: '0.8rem',
              letterSpacing: 1,
              color: 'text.disabled',
              '&.Mui-selected': { color: tokens.accent.primary }
            },
            '& .MuiTabs-indicator': { bgcolor: tokens.accent.primary, height: 3 }
          }}
        >
          <Tab icon={<ExtensionIcon sx={{ fontSize: 20 }} />} iconPosition="start" label="INVENTORY" />
          <Tab icon={<PipelineIcon sx={{ fontSize: 20 }} />} iconPosition="start" label="PIPELINE BUILDER" />
        </Tabs>

        <Box sx={{ p: 4, minHeight: '400px' }}>
          {activeTab === 0 ? (
            <PluginInventory 
              plugins={plugins || []} 
              marketplacePlugins={marketplaceData}
              onRefreshMarketplace={handleRefreshMarketplace}
              isRefreshingMarketplace={refreshMarketplaceMutation.isPending}
              onInstallStarted={setInstallId}
            />
          ) : (
            <PipelineBuilder plugins={plugins || []} />
          )}
        </Box>
      </Paper>

      <Snackbar
        open={snackbar.open}
        autoHideDuration={6000}
        onClose={() => setSnackbar({ ...snackbar, open: false })}
        anchorOrigin={{ vertical: 'bottom', horizontal: 'right' }}
      >
        <Alert 
          onClose={() => setSnackbar({ ...snackbar, open: false })} 
          severity={snackbar.severity} 
          variant="filled"
          sx={{ 
            fontFamily: 'var(--r3-heading-font)', 
            fontWeight: 800,
            bgcolor: snackbar.severity === 'success' ? tokens.accent.success : tokens.accent.error,
            color: tokens.mode === 'light' ? '#fff' : '#000',
            borderRadius: 0
          }}
        >
          {snackbar.message}
        </Alert>
      </Snackbar>
    </Box>
  );
};

export default PluginManagementPage;
