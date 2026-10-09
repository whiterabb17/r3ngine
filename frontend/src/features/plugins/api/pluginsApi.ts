import axios from 'axios';
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query';

const API_URL = '/api/plugins/';

/** Entry of a manifest's `ui.components` or `ui.overrides` list. */
export interface PluginManifestComponent {
  /** Core component (override) or slot entry name matched by `PluginComponent`. */
  name?: string;
  /** Module under `/media/plugins/<slug>/ui/`. */
  file: string;
  /** Slot name matched by `PluginSlot`. */
  type?: string;
  [key: string]: unknown;
}

/** Entry of a manifest's `ui.tabs` list, rendered as an extra scan-detail tab. */
export interface PluginManifestTab {
  label: string;
  file: string;
}

/** `ui` section of a manifest; also served as-is by `/api/plugins/registry/`. */
export interface PluginManifestUi {
  menu_item?: string;
  menu_path?: string;
  entry_export?: string;
  components?: PluginManifestComponent[];
  overrides?: PluginManifestComponent[];
  tabs?: PluginManifestTab[];
  [key: string]: unknown;
}

/**
 * Parsed `manifest.yaml` (`PluginManager.validate_manifest` in `web/plugins/utils.py`).
 * `name`, `version` and `runtime` are required on upload, but the model defaults to `{}`.
 */
export interface PluginManifest {
  name?: string;
  version?: string;
  description?: string;
  author?: string;
  icon?: string;
  /** Holds `run after` or `run before`: the anchor scan task, or `standalone`. */
  runtime?: Record<string, unknown>;
  /** Dotted paths registered on the orchestrator (`web/plugins/temporal_registry.py`). */
  temporal?: {
    workflows?: string[];
    activities?: string[];
  };
  ui?: PluginManifestUi;
  [key: string]: unknown;
}

/** One entry of `tools.yaml`'s `tools` list. */
export interface PluginToolEntry {
  name?: string;
  version?: string;
  source?: string;
  description?: string;
  [key: string]: unknown;
}

/** Parsed `tools.yaml`; free-form apart from the `tools` list. */
export interface PluginToolsConfig {
  tools?: PluginToolEntry[];
  [key: string]: unknown;
}

export interface Plugin {
  name: string;
  slug: string;
  version: string;
  description: string;
  is_enabled: boolean;
  anchor_step: string;
  runtime_position: 'BEFORE' | 'AFTER';
  order_weight: number;
  manifest: PluginManifest;
  tools_config: PluginToolsConfig;
  installed_at: string;
  needs_restart: boolean;
  author: string;
  trust_level: 'official' | 'signed_unknown' | 'unsigned' | 'legacy';
  icon_path?: string;
}

export interface MarketplacePlugin {
  name: string;
  slug: string;
  version: string;
  description: string;
  category?: string;
  author?: string;
  signed?: boolean;
  is_installed: boolean;
  update_available?: boolean;
  installed_version?: string;
  icon_url?: string | null;
}

const MARKETPLACE_ICON_HOST = 'raw.githubusercontent.com';
const MARKETPLACE_ICON_PATH_PREFIX = '/whiterabb17/r3ngine-plugins/refs/heads/master/';
const MARKETPLACE_ICON_EXT_RE = /\.(png|svg|jpe?g|webp|gif)$/i;

function isSafeMarketplaceIconUrl(url: string): boolean {
  try {
    const parsed = new URL(url);
    return (
      parsed.protocol === 'https:' &&
      parsed.hostname === MARKETPLACE_ICON_HOST &&
      parsed.pathname.startsWith(MARKETPLACE_ICON_PATH_PREFIX)
    );
  } catch {
    return false;
  }
}

function withIconExtension(url: string, ext: '.png' | '.svg'): string | undefined {
  try {
    const parsed = new URL(url);
    if (!MARKETPLACE_ICON_EXT_RE.test(parsed.pathname)) return undefined;
    parsed.pathname = parsed.pathname.replace(MARKETPLACE_ICON_EXT_RE, ext);
    return parsed.toString();
  } catch {
    return undefined;
  }
}

/** Local installed icon first; otherwise same-repo GitHub raw PNG and SVG URLs. */
export function resolvePluginIconSrcs(
  plugin?: Plugin,
  marketplacePlugin?: MarketplacePlugin,
): string[] {
  if (plugin?.icon_path && plugin.slug) {
    return [`/api/plugins/${encodeURIComponent(plugin.slug)}/icon/`];
  }
  const primary = marketplacePlugin?.icon_url;
  if (!primary || !isSafeMarketplaceIconUrl(primary)) return [];

  const urls = [primary];
  for (const ext of ['.svg', '.png'] as const) {
    const alternate = withIconExtension(primary, ext);
    if (alternate && alternate !== primary && isSafeMarketplaceIconUrl(alternate)) {
      urls.push(alternate);
    }
  }
  return urls;
}

export function resolvePluginIconSrc(
  plugin?: Plugin,
  marketplacePlugin?: MarketplacePlugin,
): string | undefined {
  return resolvePluginIconSrcs(plugin, marketplacePlugin)[0];
}

// --- CORE FETCHERS ---
export const fetchPlugins = async (): Promise<Plugin[]> => {
  const { data } = await axios.get(API_URL);
  return Array.isArray(data) ? data : data.results || [];
};

/** UI section of an enabled plugin's manifest, as served by `/api/plugins/registry/`. */
export type PluginRegistryComponents = PluginManifestUi;

export interface PluginRegistryEntry {
  slug: string;
  name: string;
  components: PluginRegistryComponents;
}

export const fetchPluginRegistry = async (): Promise<PluginRegistryEntry[]> => {
  const res = await axios.get<PluginRegistryEntry[]>(`${API_URL}registry/`);
  return res.data;
};

export const uploadPlugin = async (file: File): Promise<{ install_id: string }> => {
  const formData = new FormData();
  formData.append('file', file);
  const { data } = await axios.post(`${API_URL}upload/`, formData, {
    headers: { 'Content-Type': 'multipart/form-data' },
  });
  return data;
};

export interface InstallStep {
  key: string;
  label: string;
  status: 'pending' | 'in_progress' | 'completed' | 'failed' | 'skipped';
  message: string;
}

export interface InstallStatus {
  steps: InstallStep[];
  status: 'running' | 'success' | 'failed';
  plugin_name: string | null;
  error?: string;
  warning?: string;
}

export const fetchInstallStatus = async (installId: string): Promise<InstallStatus> => {
  const { data } = await axios.get(`${API_URL}install-status/`, { params: { id: installId } });
  return data;
};

export const togglePlugin = async ({ slug, is_enabled }: { slug: string; is_enabled: boolean }) => {
  const { data } = await axios.patch(`${API_URL}${slug}/`, { is_enabled });
  return data;
};

export const updatePluginWeight = async ({ slug, order_weight }: { slug: string; order_weight: number }) => {
  const { data } = await axios.patch(`${API_URL}${slug}/`, { order_weight });
  return data;
};

export const deletePlugin = async (slug: string) => {
  const { data } = await axios.delete(`${API_URL}${slug}/`);
  return data;
};

// --- CORE HOOKS ---
export const usePlugins = () => {
  return useQuery({ queryKey: ['plugins'], queryFn: fetchPlugins });
};

export const usePluginRegistry = () => {
  return useQuery({ queryKey: ['pluginsRegistry'], queryFn: fetchPluginRegistry });
};

export const useUploadPlugin = () => {
  return useMutation({
    mutationFn: uploadPlugin,
    // Query invalidation is deferred — InstallProgressOverlay calls onComplete when install finishes
  });
};

export const useInstallStatus = (installId: string | null) => {
  return useQuery({
    queryKey: ['plugin-install-status', installId],
    queryFn: () => fetchInstallStatus(installId!),
    enabled: !!installId,
    refetchInterval: (query) =>
      query.state.data?.status === 'running' ? 2000 : false,
  });
};

export const useTogglePlugin = () => {
  const queryClient = useQueryClient();
  return useMutation({
    mutationFn: togglePlugin,
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['plugins'] });
      queryClient.invalidateQueries({ queryKey: ['pluginsRegistry'] });
    },
  });
};

export const useDeletePlugin = () => {
  const queryClient = useQueryClient();
  return useMutation({
    mutationFn: deletePlugin,
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['plugins'] });
      queryClient.invalidateQueries({ queryKey: ['pluginsRegistry'] });
    },
  });
};

export const updatePluginPosition = async ({
  slug,
  anchor_step,
  runtime_position,
}: {
  slug: string;
  anchor_step: string;
  runtime_position: 'BEFORE' | 'AFTER';
}) => {
  const res = await axios.patch(`${API_URL}${slug}/`, { anchor_step, runtime_position });
  return res.data;
};

export const useUpdatePluginPosition = () => {
  const queryClient = useQueryClient();
  return useMutation({
    mutationFn: updatePluginPosition,
    onSuccess: () => queryClient.invalidateQueries({ queryKey: ['plugins'] }),
  });
};

export const useUpdatePluginWeight = () => {
  const queryClient = useQueryClient();
  return useMutation({
    mutationFn: updatePluginWeight,
    onSuccess: () => queryClient.invalidateQueries({ queryKey: ['plugins'] }),
  });
};

// --- MARKETPLACE FETCHERS ---
export const fetchMarketplacePlugins = async (refresh = false): Promise<MarketplacePlugin[]> => {
  const { data } = await axios.get(`${API_URL}marketplace/`, { params: { refresh } });
  return data;
};

export const installMarketplacePlugin = async (slug: string): Promise<{ install_id: string }> => {
  const { data } = await axios.post(`${API_URL}marketplace/install/`, { slug });
  return data;
};

// --- MARKETPLACE HOOKS ---
export const useMarketplacePlugins = () => {
  return useQuery({ 
    queryKey: ['marketplace-plugins'], 
    queryFn: () => fetchMarketplacePlugins() 
  });
};

export const useInstallMarketplacePlugin = () => {
  const queryClient = useQueryClient();
  return useMutation({
    mutationFn: installMarketplacePlugin,
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['plugins'] });
      queryClient.invalidateQueries({ queryKey: ['marketplace-plugins'] });
      queryClient.invalidateQueries({ queryKey: ['pluginsRegistry'] });
    },
  });
};

export const useRefreshMarketplace = () => {
  const queryClient = useQueryClient();
  return useMutation({
    mutationFn: () => fetchMarketplacePlugins(true),
    onSuccess: (data) => {
      queryClient.setQueryData(['marketplace-plugins'], data);
    },
  });
};

export const restartOrchestrator = async () => {
  const { data } = await axios.post(`${API_URL}restart-orchestrator/`);
  return data;
};

export const useRestartOrchestrator = () => {
  const queryClient = useQueryClient();
  return useMutation({
    mutationFn: restartOrchestrator,
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['plugins'] });
    },
  });
};

export const restartServer = async () => {
  const { data } = await axios.post(`${API_URL}restart-server/`);
  return data;
};

export const useRestartServer = () => {
  return useMutation({ mutationFn: restartServer });
};

export const fetchPluginDocs = async (slug: string): Promise<Record<string, string>> => {
  const { data } = await axios.get(`${API_URL}${slug}/docs/`);
  return data;
};

export const usePluginDocs = (slug: string, enabled = false) => {
  return useQuery({
    queryKey: ['plugin-docs', slug],
    queryFn: () => fetchPluginDocs(slug),
    enabled: enabled && !!slug,
    retry: false,
  });
};

export interface BurpConfig {
  api_url: string;
  api_key: string;
  auto_import_enabled: boolean;
  auto_push_enabled: boolean;
  severity_filter: string;
}

export const fetchBurpConfig = async (): Promise<BurpConfig> => {
  const { data } = await axios.get('/api/plugins/burpsuite_integration/config/');
  return data;
};

export const updateBurpConfig = async (config: Partial<BurpConfig>): Promise<BurpConfig> => {
  const { data } = await axios.put('/api/plugins/burpsuite_integration/config/', config);
  return data;
};

/**
 * `GET /api/plugins/burpsuite_integration/health/`, served by the external plugin; only
 * `status` (`'ok'` when Burp is reachable) and `message` are read.
 */
export interface BurpHealth {
  status: string;
  message?: string;
  [key: string]: unknown;
}

export const fetchBurpHealth = async (): Promise<BurpHealth> => {
  const { data } = await axios.get('/api/plugins/burpsuite_integration/health/');
  return data;
};

export const useBurpConfig = (enabled: boolean) => {
  return useQuery({
    queryKey: ['burp_config_status'],
    queryFn: fetchBurpConfig,
    enabled: enabled,
  });
};

export const useUpdateBurpConfig = () => {
  const queryClient = useQueryClient();
  return useMutation({
    mutationFn: updateBurpConfig,
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['burp_config_status'] });
      queryClient.invalidateQueries({ queryKey: ['burp_health_status'] });
    },
  });
};

export const useBurpHealth = (enabled: boolean) => {
  return useQuery({
    queryKey: ['burp_health_status'],
    queryFn: fetchBurpHealth,
    enabled: enabled,
    refetchInterval: 15000, // Poll every 15s
    retry: false,
  });
};


