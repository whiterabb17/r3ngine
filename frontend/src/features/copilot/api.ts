import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query';
import axios from 'axios';
import { getCsrfToken } from '../../api/axiosConfig';

export interface CopilotSession {
  id: number;
  project_slug: string;
  scan_id?: number | null;
  assessment_id?: number | null;
  title: string;
  created_at?: string;
  updated_at?: string;
  message_count?: number;
  messages?: CopilotMessage[];
}

export interface CopilotMessage {
  id?: number;
  role: 'user' | 'assistant' | 'system';
  content: string;
  created_at?: string;
}

export interface CopilotProposal {
  id: number;
  project_slug: string;
  scan_id?: number | null;
  assessment_id?: number | null;
  vulnerability_id?: number | null;
  session_id?: number | null;
  action_type: 'validate' | 'safe_poc' | 'followup' | 'remediation' | 'msf_module';
  status: 'pending' | 'approved' | 'rejected' | 'failed';
  summary: string;
  rationale: string;
  payload: Record<string, unknown>;
  safe_poc_attempt_id?: number | null;
  followup_plan_id?: number | null;
  msf_aux_attempt_id?: number | null;
  result?: Record<string, unknown>;
  created_at?: string;
  decided_at?: string | null;
}

export interface CopilotTraceEvent {
  id: number;
  project_slug: string;
  session_id?: number | null;
  turn_id: string;
  event_type: 'retrieve' | 'decision' | 'proposal' | 'msf_aux' | 'thought' | 'error' | string;
  summary: string;
  payload: Record<string, unknown>;
  proposal_id?: number | null;
  msf_aux_attempt_id?: number | null;
  created_at?: string | null;
}

export interface CopilotSettings {
  project_slug: string;
  enabled: boolean;
  memory_scope: 'project' | 'org' | 'global' | 'tiered';
  model_id: string;
  org_id: string;
  updated_at?: string | null;
}

export interface CopilotStatus {
  health: {
    reachable?: boolean;
    status?: string;
    hint?: string;
    model_default?: string;
    ollama?: { reachable?: boolean; version?: string };
  };
  settings?: CopilotSettings | null;
  pending_proposals: number;
}

const csrf = () => ({ headers: { 'X-CSRFToken': getCsrfToken() || '' } });

export function msfPluginHandoffUrl(
  projectSlug: string,
  payload: Record<string, unknown>,
): string {
  const module = String(payload.module || '');
  const options = (payload.options && typeof payload.options === 'object'
    ? (payload.options as Record<string, unknown>)
    : {}) as Record<string, unknown>;
  const params = new URLSearchParams();
  if (module) params.set('module', module);
  const rhosts = options.RHOSTS ?? options.RHOST;
  if (rhosts != null) params.set('rhosts', String(rhosts));
  if (options.RPORT != null) params.set('rport', String(options.RPORT));
  return `/${projectSlug}/p/metasploit_integration?${params.toString()}`;
}

export function useCopilotStatus(projectSlug: string) {
  return useQuery({
    queryKey: ['copilot', 'status', projectSlug],
    queryFn: async () => {
      const { data } = await axios.get<CopilotStatus>('/api/copilot/status/', {
        params: { project_slug: projectSlug },
      });
      return data;
    },
    enabled: Boolean(projectSlug),
    refetchInterval: 30_000,
  });
}

export function useCopilotSettings(projectSlug: string) {
  return useQuery({
    queryKey: ['copilot', 'settings', projectSlug],
    queryFn: async () => {
      const { data } = await axios.get<CopilotSettings>('/api/copilot/settings/', {
        params: { project_slug: projectSlug },
      });
      return data;
    },
    enabled: Boolean(projectSlug),
  });
}

export function useUpdateCopilotSettings(projectSlug: string) {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: async (body: Partial<CopilotSettings> & { project_slug: string }) => {
      const { data } = await axios.patch<CopilotSettings>('/api/copilot/settings/', body, csrf());
      return data;
    },
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ['copilot', 'settings', projectSlug] });
      qc.invalidateQueries({ queryKey: ['copilot', 'status', projectSlug] });
    },
  });
}

export function useCopilotSessions(projectSlug: string) {
  return useQuery({
    queryKey: ['copilot', 'sessions', projectSlug],
    queryFn: async () => {
      const { data } = await axios.get<{ sessions: CopilotSession[] }>('/api/copilot/sessions/', {
        params: { project_slug: projectSlug },
      });
      return data.sessions;
    },
    enabled: Boolean(projectSlug),
  });
}

export function useCopilotSession(projectSlug: string, sessionId: number | null) {
  return useQuery({
    queryKey: ['copilot', 'session', projectSlug, sessionId],
    queryFn: async () => {
      const { data } = await axios.get<CopilotSession>(`/api/copilot/sessions/${sessionId}/`, {
        params: { project_slug: projectSlug },
      });
      return data;
    },
    enabled: Boolean(projectSlug && sessionId),
  });
}

export function useCreateCopilotSession(projectSlug: string) {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: async (body: { title?: string; scan_id?: number; assessment_id?: number }) => {
      const { data } = await axios.post<CopilotSession>(
        '/api/copilot/sessions/',
        { project_slug: projectSlug, ...body },
        csrf(),
      );
      return data;
    },
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ['copilot', 'sessions', projectSlug] });
    },
  });
}

export function useCopilotChat(projectSlug: string) {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: async (body: { session_id: number; content: string }) => {
      const { data } = await axios.post(
        '/api/copilot/chat/',
        { ...body, project_slug: projectSlug },
        csrf(),
      );
      return data;
    },
    onSuccess: (_data, vars) => {
      qc.invalidateQueries({ queryKey: ['copilot', 'session', projectSlug, vars.session_id] });
      qc.invalidateQueries({ queryKey: ['copilot', 'sessions', projectSlug] });
      qc.invalidateQueries({ queryKey: ['copilot', 'proposals', projectSlug] });
      qc.invalidateQueries({ queryKey: ['copilot', 'status', projectSlug] });
      qc.invalidateQueries({ queryKey: ['copilot', 'trace', projectSlug] });
    },
  });
}

export function useCopilotProposals(projectSlug: string, status: string = 'pending') {
  return useQuery({
    queryKey: ['copilot', 'proposals', projectSlug, status],
    queryFn: async () => {
      const { data } = await axios.get<{ proposals: CopilotProposal[] }>('/api/copilot/proposals/', {
        params: { project_slug: projectSlug, status },
      });
      return data.proposals;
    },
    enabled: Boolean(projectSlug),
    refetchInterval: 15_000,
  });
}

export function useApproveCopilotProposal(projectSlug: string) {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: async (id: number) => {
      const { data } = await axios.post(`/api/copilot/proposals/${id}/approve/`, {}, csrf());
      return data;
    },
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ['copilot', 'proposals', projectSlug] });
      qc.invalidateQueries({ queryKey: ['copilot', 'status', projectSlug] });
      qc.invalidateQueries({ queryKey: ['copilot', 'trace', projectSlug] });
    },
  });
}

export function useRejectCopilotProposal(projectSlug: string) {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: async (id: number) => {
      const { data } = await axios.post(`/api/copilot/proposals/${id}/reject/`, {}, csrf());
      return data;
    },
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ['copilot', 'proposals', projectSlug] });
      qc.invalidateQueries({ queryKey: ['copilot', 'status', projectSlug] });
    },
  });
}

export function useCopilotTrace(
  projectSlug: string,
  opts?: { sessionId?: number | null; enabled?: boolean },
) {
  const sessionId = opts?.sessionId ?? null;
  return useQuery({
    queryKey: ['copilot', 'trace', projectSlug, sessionId],
    queryFn: async () => {
      const { data } = await axios.get<{ events: CopilotTraceEvent[] }>('/api/copilot/trace/', {
        params: {
          project_slug: projectSlug,
          ...(sessionId != null ? { session_id: sessionId } : {}),
          limit: 100,
        },
      });
      return data.events;
    },
    enabled: Boolean(projectSlug) && (opts?.enabled ?? true),
    refetchInterval: 15_000,
  });
}

export function useCopilotTraceDetail(projectSlug: string, eventId: number | null) {
  return useQuery({
    queryKey: ['copilot', 'trace', 'detail', projectSlug, eventId],
    queryFn: async () => {
      const { data } = await axios.get<CopilotTraceEvent>(`/api/copilot/trace/${eventId}/`, {
        params: { project_slug: projectSlug },
      });
      return data;
    },
    enabled: Boolean(projectSlug && eventId),
  });
}
