import React from 'react';
import { Box, Typography, Divider, IconButton, Tooltip, Stack, Grid } from '@mui/material';
import { Refresh as RefreshIcon, Store as StoreIcon, Inventory as InventoryIcon } from '@mui/icons-material';
import { alpha } from '@mui/material/styles';
import type { Plugin, MarketplacePlugin } from '../api/pluginsApi';
import PluginCard from './PluginCard';
import { useThemeTokens } from '../../../theme/useThemeTokens';

interface Props {
  plugins: Plugin[];
  marketplacePlugins?: MarketplacePlugin[];
  onRefreshMarketplace?: () => void;
  isRefreshingMarketplace?: boolean;
  /** Forwarded to marketplace PluginCards so the install_id reaches the parent page. */
  onInstallStarted?: (installId: string) => void;
}

const PluginInventory: React.FC<Props> = ({
  plugins,
  marketplacePlugins = [],
  onRefreshMarketplace,
  isRefreshingMarketplace,
  onInstallStarted,
}) => {
  const { tokens } = useThemeTokens();

  return (
    <Box>
      {/* INSTALLED PLUGINS */}
      <Stack direction="row" spacing={1} sx={{ alignItems: 'center', mb: 3 }}>
        <InventoryIcon sx={{ color: tokens.text.muted, fontSize: 20 }} />
        <Typography sx={{ fontFamily: 'var(--r3-heading-font)', fontWeight: 900, letterSpacing: 2, fontSize: '0.7rem', color: tokens.text.secondary }}>
          INSTALLED ASSETS
        </Typography>
      </Stack>

      {(!Array.isArray(plugins) || plugins.length === 0) ? (
        <Box sx={{ textAlign: "center", py: 4, mb: 6, border: `1px dashed ${tokens.border.subtle}` }}>
          <Typography variant="body2" color="text.secondary" sx={{ fontFamily: 'var(--r3-heading-font)' }}>
            NO PLUGINS INSTALLED
          </Typography>
        </Box>
      ) : (
        <Grid container spacing={3} sx={{ mb: 8 }}>
          {plugins.map((plugin) => (
            <Grid size={{ xs: 12, md: 6, lg: 4 }} key={plugin.slug}>
              <PluginCard plugin={plugin} />
            </Grid>
          ))}
        </Grid>
      )}

      <Divider sx={{ mb: 6, borderColor: tokens.border.subtle }} />

      {/* MARKETPLACE PLUGINS */}
      <Box sx={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', mb: 3 }}>
        <Stack direction="row" spacing={1} sx={{ alignItems: 'center' }}>
          <StoreIcon sx={{ color: tokens.accent.primary, fontSize: 20 }} />
          <Typography sx={{ fontFamily: 'var(--r3-heading-font)', fontWeight: 900, letterSpacing: 2, fontSize: '0.7rem', color: tokens.accent.primary }}>
            PLUGIN MARKETPLACE
          </Typography>
        </Stack>
        <Tooltip title="Refresh Marketplace">
          <IconButton
            onClick={onRefreshMarketplace}
            disabled={isRefreshingMarketplace}
            sx={{ color: tokens.text.muted, '&:hover': { color: tokens.accent.primary } }}
          >
            <RefreshIcon sx={{ fontSize: 18 }} />
          </IconButton>
        </Tooltip>
      </Box>

      {(!Array.isArray(marketplacePlugins) || marketplacePlugins.length === 0) ? (
        <Box sx={{ textAlign: "center", py: 10, border: `1px dashed ${tokens.border.subtle}` }}>
          <Typography variant="h6" sx={{ fontFamily: 'var(--r3-heading-font)', fontWeight: 800, color: tokens.text.muted }}>
            MARKETPLACE COMING SOON
          </Typography>
          <Typography variant="body2" color="text.secondary" sx={{ mt: 1 }}>
            The official r3ngine plugin repository is currently
            being alpha tested, and will be released soon.
          </Typography>
        </Box>
      ) : (
        <Grid container spacing={3}>
          {marketplacePlugins.map((plugin) => (
            <Grid size={{ xs: 12, md: 6, lg: 4 }} key={plugin.slug}>
              <PluginCard marketplacePlugin={plugin} onInstallStarted={onInstallStarted} />
            </Grid>
          ))}
        </Grid>
      )}
    </Box>
  );
};

export default PluginInventory;
