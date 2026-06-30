import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query';
import type { UseQueryOptions } from '@tanstack/react-query';
import axios from 'axios';
import { getCsrfToken } from '../../../api/axiosConfig';

export interface NotificationSettings {
  send_to_slack: boolean;
  send_to_lark: boolean;
  send_to_discord: boolean;
  send_to_telegram: boolean;
  slack_hook_url: string | null;
  lark_hook_url: string | null;
  discord_hook_url: string | null;
  telegram_bot_token: string | null;
  telegram_bot_chat_id: string | null;
  send_scan_status_notif: boolean;
  send_interesting_notif: boolean;
  send_vuln_notif: boolean;
  send_subdomain_changes_notif: boolean;
  send_scan_output_file: boolean;
  send_scan_tracebacks: boolean;
}

export interface LLMConfig {
  provider: string;
  api_key: string;
  selected_model: string;
  is_active: boolean;
}

export interface LLMModel {
  name: string;
  expertise?: string;
  size?: string;
  suggested_ram?: string;
  description?: string;
  is_local?: boolean;
}

export interface OllamaPullStatus {
  status: 'running' | 'success' | 'failed';
  log: string;
}

export interface TestLlmConnectionResult {
  status: 'success' | 'error';
  message: string;
  response: string;
}



export interface ProxySettings {
  use_proxy: boolean;
  proxies: string;
  use_proxychains: boolean;
  use_tor: boolean;
  valid_proxy_count?: number;
  skip_validation?: boolean;
}

export interface ProxyTaskStatus {
  task_id: string;
  status: 'PENDING' | 'PROGRESS' | 'SUCCESS' | 'FAILURE';
  result: string | null;
  message?: string;
  progress?: number;
}

export interface OpSecSettings {
  enable_opsec: boolean;
  enable_random_ua: boolean;
  enable_waf_bypass: boolean;
  enable_ja3_randomization: boolean;
  enable_rate_limit: boolean;
  max_rps: number;
  enable_delay: boolean;
  delay_ms: number;
  enable_jitter: boolean;
  jitter_percent: number;
  http_protocol: string;
  custom_dns_servers: string;
  enable_metadata_stripping: boolean;
}

export interface ToolSettings {
  gf_patterns: string[];
  nuclei_templates: string[];
}

export interface ApiVaultSettings {
  netlas_key: string;
  chaos_key: string;
  shodan_key: string;
  censys_key: string;
  leaklookup_key: string;
  hackerone_username: string;
  hackerone_key: string;
  acunetix_url: string;
  acunetix_key: string;
  linkedin_username?: string;
  linkedin_password?: string;
  hunterio_key?: string;
  wpscan_key?: string;
  projectdiscovery_key?: string;
}

export interface ReportSettings {
  primary_color: string;
  secondary_color: string;
  company_name: string;
  company_address: string;
  company_email: string;
  company_website: string;
  show_rengine_banner: boolean;
  show_executive_summary: boolean;
  executive_summary_description: string;
  enable_llm_report_generation: boolean;
  show_footer: boolean;
  footer_text: string;
}

export interface RengineSystemSettings {
  total: number;
  used: number;
  free: number;
  consumed_percent: number;
  enable_scan_queueing: boolean;
}

export interface RengineUpdateResponse {
  status: boolean;
  update_available: boolean;
  latest_version: string | null;
  current_version: string;
  redirect_link: string;
  changelog?: string;
  message?: string;
}

export interface InstalledTool {
  id: number;
  name: string;
  description: string;
  logo_url: string | null;
  github_url: string;
  license_url: string | null;
  is_default: boolean;
  is_subdomain_gathering: boolean;
  is_github_cloned: boolean;
  github_clone_path: string | null;
  install_command: string;
  update_command: string | null;
  version_lookup_command: string | null;
  version_match_regex?: string;
  subdomain_gathering_command?: string;
}

export interface FileContentResponse {
  status: boolean;
  content: string;
  message?: string;
}



export const useProxySettings = (
  slug: string,
  options?: Omit<UseQueryOptions<ProxySettings>, 'queryKey' | 'queryFn'>
) => {
  return useQuery<ProxySettings>({
    queryKey: ['proxy-settings', slug],
    queryFn: async () => {
      const response = await axios.get(`/scanEngine/${slug}/proxy_settings`, {
        headers: { 'Accept': 'application/json' }
      });
      return response.data;
    },
    ...options,
  });
};

export const useUpdateProxySettings = (slug: string) => {
  const queryClient = useQueryClient();
  return useMutation({
    mutationFn: async (data: ProxySettings) => {
      const formData = new FormData();
      if (data.use_proxy) {
        formData.append('use_proxy', 'on');
      }
      if (data.use_proxychains) {
        formData.append('use_proxychains', 'on');
      }
      if (data.use_tor) {
        formData.append('use_tor', 'on');
      }
      formData.append('proxies', data.proxies);
      if (data.skip_validation) {
        formData.append('skip_validation', 'true');
      }

      const response = await axios.post(`/scanEngine/${slug}/proxy_settings`, formData, {
        headers: {
          'X-CSRFToken': getCsrfToken(),
          'Accept': 'application/json'
        }
      });
      return response.data;
    },
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['proxy-settings', slug] });
    },
  });
};

export const useFetchProxies = (slug: string) => {
  return useMutation({
    mutationFn: async (limit?: number) => {
      const response = await axios.post(`/scanEngine/${slug}/fetch_proxies`, { limit }, {
        headers: {
          'X-CSRFToken': getCsrfToken()
        }
      });
      return response.data as { task_id: string };
    },
  });
};

export const checkProxy = async (
  slug: string,
  proxy: string,
  signal?: AbortSignal
): Promise<{ proxy: string; valid: boolean }> => {
  const response = await axios.post(
    `/scanEngine/${slug}/check_proxy/`,
    { proxy },
    { headers: { 'X-CSRFToken': getCsrfToken() }, signal }
  );
  return response.data;
};

export const checkProxyBulk = async (
  slug: string,
  proxies: string[],
  signal?: AbortSignal
): Promise<{ results: Record<string, boolean> }> => {
  const response = await axios.post(
    `/scanEngine/${slug}/check_proxy_bulk/`,
    { proxies },
    { headers: { 'X-CSRFToken': getCsrfToken() }, signal }
  );
  return response.data;
};

export const useProxyTaskStatus = (slug: string, taskId: string | null) => {
  return useQuery<ProxyTaskStatus>({
    queryKey: ['proxy-task-status', slug, taskId],
    queryFn: async () => {
      const response = await axios.get(`/scanEngine/${slug}/task_status/${taskId}`);
      return response.data;
    },
    enabled: !!taskId,
    refetchInterval: (query) => {
      const data = query.state.data as ProxyTaskStatus | undefined;
      if (data && (data.status === 'SUCCESS' || data.status === 'FAILURE')) {
        return false;
      }
      return 2000;
    },
  });
};

export const useTorStatus = () => {
  return useQuery<{ running: boolean }>({
    queryKey: ['tor-status'],
    queryFn: async () => {
      const response = await axios.get('/api/rengine/tor-status/', {
        headers: { 'Accept': 'application/json' }
      });
      return response.data;
    },
    refetchInterval: 10000,
  });
};

export const useTorExitIP = (enabled: boolean) => {
  return useQuery<{ ip: string | null }>({
    queryKey: ['tor-exit-ip'],
    queryFn: async () => {
      const response = await axios.get('/api/rengine/tor-exit-ip/', {
        headers: { 'Accept': 'application/json' }
      });
      return response.data;
    },
    enabled,
    refetchInterval: enabled ? 30000 : false,
  });
};

export const useOpSecSettings = (slug: string) => {
  return useQuery<OpSecSettings>({
    queryKey: ['opsec-settings', slug],
    queryFn: async () => {
      const response = await axios.get(`/scanEngine/${slug}/opsec_settings`, {
        headers: { 'Accept': 'application/json' }
      });
      return response.data;
    },
  });
};

export const useUpdateOpSecSettings = (slug: string) => {
  const queryClient = useQueryClient();
  return useMutation({
    mutationFn: async (data: OpSecSettings) => {
      const formData = new FormData();
      if (data.enable_opsec) formData.append('enable_opsec', 'on');
      if (data.enable_random_ua) formData.append('enable_random_ua', 'on');
      if (data.enable_waf_bypass) formData.append('enable_waf_bypass', 'on');
      if (data.enable_ja3_randomization) formData.append('enable_ja3_randomization', 'on');
      if (data.enable_rate_limit) formData.append('enable_rate_limit', 'on');
      formData.append('max_rps', data.max_rps.toString());
      if (data.enable_delay) formData.append('enable_delay', 'on');
      formData.append('delay_ms', data.delay_ms.toString());
      if (data.enable_jitter) formData.append('enable_jitter', 'on');
      formData.append('jitter_percent', data.jitter_percent.toString());
      formData.append('http_protocol', data.http_protocol);
      formData.append('custom_dns_servers', data.custom_dns_servers);
      if (data.enable_metadata_stripping) formData.append('enable_metadata_stripping', 'on');

      const response = await axios.post(`/scanEngine/${slug}/opsec_settings`, formData, {
        headers: {
          'X-CSRFToken': getCsrfToken(),
          'Accept': 'application/json'
        }
      });
      return response.data;
    },
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['opsec-settings', slug] });
    },
  });
};

export const useToolSettings = (slug: string) => {
  return useQuery<ToolSettings>({
    queryKey: ['toolSettings', slug],
    queryFn: async () => {
      const { data } = await axios.get(`/scanEngine/${slug}/tool_settings`, {
        headers: { Accept: 'application/json' },
      });
      return data;
    },
  });
};

export const useUpdateToolConfig = (slug: string) => {
  const queryClient = useQueryClient();
  return useMutation({
    mutationFn: async ({ key, content }: { key: string; content: string }) => {
      const formData = new FormData();
      formData.append(key, content);
      const { data } = await axios.post(`/scanEngine/${slug}/tool_settings`, formData, {
        headers: {
          'X-CSRFToken': getCsrfToken(),
          Accept: 'application/json',
        },
      });
      return data;
    },
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['toolSettings', slug] });
    },
  });
};

export const useUploadToolFiles = (slug: string) => {
  const queryClient = useQueryClient();
  return useMutation({
    mutationFn: async ({ key, files }: { key: string; files: File[] }) => {
      const formData = new FormData();
      files.forEach((file) => {
        formData.append(`${key}[]`, file);
      });
      const { data } = await axios.post(`/scanEngine/${slug}/tool_settings`, formData, {
        headers: {
          'X-CSRFToken': getCsrfToken(),
          Accept: 'application/json',
          'Content-Type': 'multipart/form-data',
        },
      });
      return data;
    },
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['toolSettings', slug] });
    },
  });
};

export const useFileContent = (params: Record<string, string>) => {
  return useQuery<FileContentResponse>({
    queryKey: ['fileContent', params],
    queryFn: async () => {
      const { data } = await axios.get(`/api/getFileContents/`, {
        params,
      });
      return data;
    },
    enabled: Object.keys(params).length > 0,
  });
};

export const useToolArsenal = (slug: string) => {
  return useQuery<{ tools: InstalledTool[] }>({
    queryKey: ['toolArsenal', slug],
    queryFn: async () => {
      const { data } = await axios.get(`/scanEngine/${slug}/tool_arsenal`, {
        headers: { Accept: 'application/json' },
      });
      return data;
    },
  });
};

export const useToolVersion = () => {
  return useMutation({
    mutationFn: async ({ toolId, type }: { toolId: number; type: 'current' | 'latest' }) => {
      const endpoint = type === 'current'
        ? `/api/external/tool/get_current_release/`
        : `/api/github/tool/get_latest_releases/`;
      const { data } = await axios.get(endpoint, {
        params: { tool_id: toolId },
      });
      return data;
    },
  });
};

export const useUpdateTool = () => {
  return useMutation({
    mutationFn: async (toolId: number) => {
      const { data } = await axios.get(`/api/tool/update/`, {
        params: { tool_id: toolId },
      });
      return data;
    },
  });
};

export const useUninstallTool = (slug: string) => {
  const queryClient = useQueryClient();
  return useMutation({
    mutationFn: async (toolId: number) => {
      const { data } = await axios.get(`/api/tool/uninstall/`, {
        params: { tool_id: toolId },
      });
      return data;
    },
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['toolArsenal', slug] });
    },
  });
};

export const useAddTool = (slug: string) => {
  const queryClient = useQueryClient();
  return useMutation({
    mutationFn: async (formData: FormData) => {
      const { data } = await axios.post(`/scanEngine/${slug}/tool_arsenal/add/`, formData, {
        headers: {
          'X-CSRFToken': getCsrfToken(),
          Accept: 'application/json',
        },
      });
      return data;
    },
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['toolArsenal', slug] });
    },
  });
};

export const useModifyTool = (slug: string) => {
  const queryClient = useQueryClient();
  return useMutation({
    mutationFn: async ({ toolId, formData }: { toolId: number; formData: FormData }) => {
      const { data } = await axios.post(`/scanEngine/${slug}/tool_arsenal/update/${toolId}`, formData, {
        headers: {
          'X-CSRFToken': getCsrfToken(),
          Accept: 'application/json',
        },
      });
      return data;
    },
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['toolArsenal', slug] });
    },
  });
};

export const useApiVault = (slug: string) => {
  return useQuery<ApiVaultSettings>({
    queryKey: ['api-vault', slug],
    queryFn: async () => {
      const response = await axios.get(`/scanEngine/${slug}/api_vault`, {
        headers: { 'Accept': 'application/json' }
      });
      return response.data;
    },
  });
};

export const useUpdateApiVault = (slug: string) => {
  const queryClient = useQueryClient();
  return useMutation({
    mutationFn: async (data: ApiVaultSettings) => {

      const formData = new FormData();
      formData.append('key_netlas', data.netlas_key);
      formData.append('key_chaos', data.chaos_key);
      formData.append('key_shodan', data.shodan_key);
      formData.append('key_censys', data.censys_key);
      formData.append('key_leaklookup', data.leaklookup_key);
      formData.append('username_hackerone', data.hackerone_username);
      formData.append('key_hackerone', data.hackerone_key);
      formData.append('key_acunetix_url', data.acunetix_url);
      formData.append('key_acunetix_key', data.acunetix_key);
      formData.append('linkedin_username', data.linkedin_username || '');
      formData.append('linkedin_password', data.linkedin_password || '');
      formData.append('hunterio_key', data.hunterio_key || '');
      formData.append('wpscan_key', data.wpscan_key || '');
      formData.append('key_projectdiscovery', data.projectdiscovery_key || '');

      const response = await axios.post(`/scanEngine/${slug}/api_vault`, formData, {
        headers: {
          'X-CSRFToken': getCsrfToken(),
          'Accept': 'application/json'
        }
      });
      return response.data;
    },
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['api-vault', slug] });
    },
  });
};

export const useLlmToolkit = (slug: string) => {
  return useQuery<{ llm_configs: LLMConfig[]; active_provider: string }>({
    queryKey: ['llm-toolkit', slug],
    queryFn: async () => {
      const response = await axios.get(`/scanEngine/${slug}/llm_toolkit`, {
        headers: { 'Accept': 'application/json' }
      });
      return response.data;
    },
  });
};

export const useLlmModels = (slug: string, provider: string, apiKey: string) => {
  return useQuery<LLMModel[]>({
    queryKey: ['llm-models', slug, provider, apiKey],
    queryFn: async () => {
      const response = await axios.get(`/scanEngine/${slug}/fetch_llm_models`, {
        params: { provider, api_key: apiKey }
      });
      return response.data.models;
    },
    enabled: !!provider && (provider === 'ollama' || !!apiKey),
  });
};

export const useUpdateLlmSettings = (slug: string) => {
  const queryClient = useQueryClient();
  return useMutation({
    mutationFn: async (data: { provider: string; api_key: string; selected_model: string; is_active: boolean; action: 'save' | 'pull' }) => {
      const formData = new FormData();
      formData.append('provider', data.provider);
      formData.append('api_key', data.api_key);
      formData.append('selected_model', data.selected_model);
      formData.append('is_active', data.is_active ? 'true' : 'false');
      formData.append('action', data.action);

      const response = await axios.post(`/scanEngine/${slug}/update_llm_settings`, formData, {
        headers: {
          'X-CSRFToken': getCsrfToken(),
          'Accept': 'application/json'
        }
      });
      return response.data;
    },
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['llm-toolkit', slug] });
    },
  });
};

export const useOllamaPullStatus = (slug: string, model: string | null) => {
  return useQuery<OllamaPullStatus>({
    queryKey: ['ollama-pull-status', slug, model],
    queryFn: async () => {
      const response = await axios.get(`/scanEngine/${slug}/get_ollama_pull_status`, {
        params: { model }
      });
      return response.data;
    },
    enabled: !!model,
    refetchInterval: (query) => {
      const data = query.state.data as OllamaPullStatus | undefined;
      if (data && (data.status === 'success' || data.status === 'failed')) {
        return false;
      }
      return 2000;
    },
  });
};

export const useOllamaServiceStatus = (slug: string) => {
  return useQuery<{ status: string; running: boolean }>({
    queryKey: ['ollama-service-status', slug],
    queryFn: async () => {
      const response = await axios.get(`/scanEngine/${slug}/ollama/service_status`, {
        headers: { 'Accept': 'application/json' }
      });
      return response.data;
    },
    refetchInterval: 5000,
  });
};

export const useStartOllamaService = (slug: string) => {
  const queryClient = useQueryClient();
  return useMutation({
    mutationFn: async () => {
      const response = await axios.post(`/scanEngine/${slug}/ollama/service_start`, {}, {
        headers: {
          'X-CSRFToken': getCsrfToken(),
          'Accept': 'application/json'
        }
      });
      return response.data;
    },
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['ollama-service-status', slug] });
    },
  });
};

export const useStopOllamaService = (slug: string) => {
  const queryClient = useQueryClient();
  return useMutation({
    mutationFn: async () => {
      const response = await axios.post(`/scanEngine/${slug}/ollama/service_stop`, {}, {
        headers: {
          'X-CSRFToken': getCsrfToken(),
          'Accept': 'application/json'
        }
      });
      return response.data;
    },
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['ollama-service-status', slug] });
    },
  });
};

export const useTestLlmConnection = (slug: string) => {
  return useMutation<TestLlmConnectionResult, Error, { provider: string; api_key: string; model: string }>({
    mutationFn: async (data) => {
      const formData = new FormData();
      formData.append('provider', data.provider);
      formData.append('api_key', data.api_key);
      formData.append('model', data.model);

      const response = await axios.post(`/scanEngine/${slug}/test_llm_connection`, formData, {
        headers: {
          'X-CSRFToken': getCsrfToken(),
          'Accept': 'application/json',
        },
        validateStatus: () => true,
      });
      return response.data as TestLlmConnectionResult;
    },
  });
};

export const useReportSettings = () => {
  return useQuery<ReportSettings>({
    queryKey: ['report-settings'],
    queryFn: async () => {
      const response = await axios.get('/api/report-settings/', {
        headers: { 'Accept': 'application/json' }
      });
      return response.data;
    },
  });
};

export const useUpdateReportSettings = () => {
  const queryClient = useQueryClient();
  return useMutation({
    mutationFn: async (data: Partial<ReportSettings>) => {
      const response = await axios.post('/api/report-settings/', data, {
        headers: {
          'X-CSRFToken': getCsrfToken(),
          'Accept': 'application/json'
        }
      });
      return response.data;
    },
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['report-settings'] });
    },
  });
};

export const useRengineSystemSettings = () => {
  return useQuery<RengineSystemSettings>({
    queryKey: ['rengine-system-settings'],
    queryFn: async () => {
      const response = await axios.get('/api/rengine/system-settings/', {
        headers: { 'Accept': 'application/json' }
      });
      return response.data;
    },
  });
};

export const useRengineUpdateCheck = () => {
  return useMutation({
    mutationFn: async () => {
      const response = await axios.get('/api/rengine/update/', {
        headers: { 'Accept': 'application/json' }
      });
      return response.data as RengineUpdateResponse;
    },
  });
};

export const useDeleteAllScanResults = () => {
  return useMutation({
    mutationFn: async () => {
      const response = await axios.post('/scan/delete/scan_results/', {}, {
        headers: {
          'X-CSRFToken': getCsrfToken(),
          'Accept': 'application/json'
        }
      });
      return response.data;
    },
  });
};

export const useToggleScanQueueing = () => {
  const queryClient = useQueryClient();
  return useMutation({
    mutationFn: async () => {
      const response = await axios.post('/api/toggle-scan-queueing-mode/', {}, {
        headers: {
          'X-CSRFToken': getCsrfToken(),
          'Accept': 'application/json'
        }
      });
      return response.data;
    },
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['rengine-system-settings'] });
    },
  });
};

export const useDeleteAllScreenshots = () => {
  return useMutation({
    mutationFn: async () => {
      const response = await axios.post('/scan/delete/screenshots/', {}, {
        headers: {
          'X-CSRFToken': getCsrfToken(),
          'Accept': 'application/json'
        }
      });
      return response.data;
    },
  });
};

export const useNotificationSettings = () => {
  return useQuery<NotificationSettings>({
    queryKey: ['notification-settings'],
    queryFn: async () => {
      const response = await axios.get('/api/notification-settings/', {
        headers: { 'Accept': 'application/json' }
      });
      return response.data;
    },
  });
};

export const useUpdateNotificationSettings = () => {
  const queryClient = useQueryClient();
  return useMutation({
    mutationFn: async (data: Partial<NotificationSettings> & { send_test?: boolean }) => {
      const response = await axios.post('/api/notification-settings/', data, {
        headers: {
          'X-CSRFToken': getCsrfToken(),
          'Accept': 'application/json'
        }
      });
      return response.data;
    },
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['notification-settings'] });
    },
  });
};

export interface User {
  id: number;
  username: string;
  full_name: string;
  email: string;
  role: string;
  is_active: boolean;
  is_staff: boolean;
  date_joined_humanized: string;
  last_login_humanized: string;
}

export const useUsers = () => {
  return useQuery<User[]>({
    queryKey: ['users'],
    queryFn: async () => {
      const response = await axios.get('/api/users/');
      return Array.isArray(response.data) ? response.data : response.data.results;
    },
  });
};

export const useCreateUser = () => {
  const queryClient = useQueryClient();
  return useMutation({
    mutationFn: async (data: any) => {
      const response = await axios.post('/api/users/', data, {
        headers: {
          'X-CSRFToken': getCsrfToken(),
          'Accept': 'application/json'
        }
      });
      return response.data;
    },
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['users'] });
    },
  });
};

export const useToggleUserStatus = () => {
  const queryClient = useQueryClient();
  return useMutation({
    mutationFn: async (userId: number) => {
      const response = await axios.post(`/api/users/${userId}/toggle_status/`, {}, {
        headers: {
          'X-CSRFToken': getCsrfToken(),
          'Accept': 'application/json'
        }
      });
      return response.data;
    },
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['users'] });
    },
  });
};

export const useUpdateUser = () => {
  const queryClient = useQueryClient();
  return useMutation({
    mutationFn: async ({ userId, data }: { userId: number; data: any }) => {
      const response = await axios.post(`/api/users/${userId}/update_user/`, data, {
        headers: {
          'X-CSRFToken': getCsrfToken(),
          'Accept': 'application/json'
        }
      });
      return response.data;
    },
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['users'] });
    },
  });
};

export const useDeleteUser = () => {
  const queryClient = useQueryClient();
  return useMutation({
    mutationFn: async (userId: number) => {
      const response = await axios.delete(`/api/users/${userId}/`, {
        headers: {
          'X-CSRFToken': getCsrfToken(),
          'Accept': 'application/json'
        }
      });
      return response.data;
    },
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['users'] });
    },
  });
};

export interface RemoteWorker {
  id: number;
  name: string;
  auth_token: string;
  ip_address: string | null;
  last_heartbeat: string | null;
  created_at: string;
}

export const useRemoteWorkers = () => {
  return useQuery<RemoteWorker[]>({
    queryKey: ['remote-workers'],
    queryFn: async () => {
      const response = await axios.get('/api/settings/workers/');
      return Array.isArray(response.data) ? response.data : response.data.results;
    },
    refetchInterval: 30000,
  });
};

export const useCreateRemoteWorker = () => {
  const queryClient = useQueryClient();
  return useMutation({
    mutationFn: async (data: { name: string, auth_token: string }) => {
      const response = await axios.post('/api/settings/workers/', data, {
        headers: {
          'X-CSRFToken': getCsrfToken(),
          'Accept': 'application/json'
        }
      });
      return response.data;
    },
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['remote-workers'] });
    },
  });
};

export const useDeleteRemoteWorker = () => {
  const queryClient = useQueryClient();
  return useMutation({
    mutationFn: async (workerId: number) => {
      const response = await axios.delete(`/api/settings/workers/${workerId}/`, {
        headers: {
          'X-CSRFToken': getCsrfToken(),
          'Accept': 'application/json'
        }
      });
      return response.data;
    },
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['remote-workers'] });
    },
  });
};
