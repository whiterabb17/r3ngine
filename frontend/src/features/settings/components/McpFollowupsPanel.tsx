import React, { useMemo, useState } from 'react';
import {
  Box,
  Button,
  Checkbox,
  Chip,
  FormControlLabel,
  Stack,
  TextField,
  Typography,
} from '@mui/material';
import { ListChecks } from 'lucide-react';
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query';
import axios from 'axios';
import { useParams } from '@tanstack/react-router';
import { useThemeTokens } from '../../../theme/useThemeTokens';
import { getFieldSx } from '../../../theme/semanticColors';
import { TacticalPanel } from '../../../components/TacticalPanel';

type FollowupStep = {
  id: string;
  kind: string;
  status?: string;
  tool?: string;
  rationale?: string;
  error?: string;
};

type FollowupPlan = {
  id: number;
  project_slug: string;
  scan_id?: number | null;
  status: string;
  rationale: string;
  steps: FollowupStep[];
  retry_count: number;
};

async function fetchPlans(projectSlug: string, status?: string) {
  const { data } = await axios.get('/api/action/followups/', {
    params: { project_slug: projectSlug, status: status || undefined, limit: 30 },
  });
  return (data.results || []) as FollowupPlan[];
}

export const McpFollowupsPanel: React.FC = () => {
  const { projectSlug = 'default' } = useParams({ strict: false }) as { projectSlug?: string };
  const { tokens, isLight, theme } = useThemeTokens();
  const fieldSx = getFieldSx(isLight, tokens);
  const qc = useQueryClient();
  const [statusFilter, setStatusFilter] = useState('proposed');
  const [selected, setSelected] = useState<FollowupPlan | null>(null);
  const [editJson, setEditJson] = useState('');
  const [retryIds, setRetryIds] = useState<string[]>([]);

  const { data: plans = [], isLoading } = useQuery({
    queryKey: ['followup-plans', projectSlug, statusFilter],
    queryFn: () => fetchPlans(projectSlug, statusFilter),
    enabled: Boolean(projectSlug),
  });

  const approve = useMutation({
    mutationFn: async (plan: FollowupPlan) => {
      let steps;
      if (editJson.trim() && selected?.id === plan.id) {
        steps = JSON.parse(editJson);
      }
      const { data } = await axios.post(`/api/action/followups/${plan.id}/approve/`, {
        steps,
      });
      return data;
    },
    onSuccess: () => qc.invalidateQueries({ queryKey: ['followup-plans'] }),
  });

  const abort = useMutation({
    mutationFn: async (id: number) => {
      const { data } = await axios.post(`/api/action/followups/${id}/abort/`, {});
      return data;
    },
    onSuccess: () => qc.invalidateQueries({ queryKey: ['followup-plans'] }),
  });

  const retry = useMutation({
    mutationFn: async (plan: FollowupPlan) => {
      const { data } = await axios.post(`/api/action/followups/${plan.id}/retry/`, {
        step_ids: retryIds.length ? retryIds : undefined,
      });
      return data;
    },
    onSuccess: () => {
      setRetryIds([]);
      qc.invalidateQueries({ queryKey: ['followup-plans'] });
    },
  });

  const update = useMutation({
    mutationFn: async (plan: FollowupPlan) => {
      const steps = JSON.parse(editJson);
      const { data } = await axios.post(`/api/action/followups/${plan.id}/update/`, { steps });
      return data;
    },
    onSuccess: () => qc.invalidateQueries({ queryKey: ['followup-plans'] }),
  });

  const statusColor = useMemo(
    () => ({
      proposed: 'default',
      running: 'warning',
      done: 'success',
      failed: 'error',
      aborted: 'default',
    }) as Record<string, 'default' | 'warning' | 'success' | 'error'>,
    [],
  );

  if (!projectSlug) {
    return null;
  }

  return (
    <TacticalPanel title="Follow-up plans" icon={<ListChecks size={20} />}>
      <Typography variant="body2" sx={{ mb: 2, color: theme.palette.text.secondary }}>
        Agent-proposed batches (max 5 steps). Edit while proposed, then Approve. Abort running plans; Retry failed/aborted.
      </Typography>
      <Stack direction="row" spacing={1} sx={{ mb: 2, flexWrap: 'wrap' }}>
        {['proposed', 'running', 'failed', 'aborted', 'done', ''].map((s) => (
          <Chip
            key={s || 'all'}
            label={s || 'all'}
            size="small"
            color={statusFilter === s ? 'primary' : 'default'}
            onClick={() => setStatusFilter(s)}
          />
        ))}
      </Stack>
      {isLoading && (
        <Typography variant="body2" color="text.secondary">
          Loading…
        </Typography>
      )}
      <Stack spacing={1.5}>
        {plans.map((plan) => (
          <Box
            key={plan.id}
            sx={{
              border: `1px solid ${tokens.border.subtle}`,
              borderRadius: 1,
              p: 1.5,
            }}
          >
            <Stack
              direction="row"
              sx={{ justifyContent: 'space-between', alignItems: 'center', gap: 1 }}
            >
              <Typography variant="subtitle2">
                Plan #{plan.id}
                {plan.scan_id ? ` · scan ${plan.scan_id}` : ''}
              </Typography>
              <Chip size="small" label={plan.status} color={statusColor[plan.status] || 'default'} />
            </Stack>
            {plan.rationale && (
              <Typography variant="body2" sx={{ mt: 0.5, color: theme.palette.text.secondary }}>
                {plan.rationale}
              </Typography>
            )}
            <Box component="ul" sx={{ m: 0, pl: 2, mt: 1 }}>
              {(plan.steps || []).map((step) => (
                <li key={step.id}>
                  <Typography variant="caption" component="span">
                    [{step.status || 'pending'}] {step.kind}
                    {step.tool ? ` · ${step.tool}` : ''}
                    {step.error ? ` — ${step.error}` : ''}
                  </Typography>
                  {(plan.status === 'failed' || plan.status === 'aborted') && (
                    <FormControlLabel
                      sx={{ ml: 1 }}
                      control={
                        <Checkbox
                          size="small"
                          checked={retryIds.includes(step.id)}
                          onChange={(_, checked) => {
                            setRetryIds((prev) =>
                              checked ? [...prev, step.id] : prev.filter((x) => x !== step.id),
                            );
                            setSelected(plan);
                          }}
                        />
                      }
                      label="retry"
                    />
                  )}
                </li>
              ))}
            </Box>
            <Stack direction="row" spacing={1} sx={{ mt: 1, flexWrap: 'wrap' }}>
              {plan.status === 'proposed' && (
                <>
                  <Button
                    size="small"
                    variant="outlined"
                    onClick={() => {
                      setSelected(plan);
                      setEditJson(JSON.stringify(plan.steps, null, 2));
                    }}
                  >
                    Edit steps
                  </Button>
                  <Button
                    size="small"
                    variant="contained"
                    disabled={approve.isPending}
                    onClick={() => {
                      setSelected(plan);
                      approve.mutate(plan);
                    }}
                  >
                    Approve
                  </Button>
                </>
              )}
              {(plan.status === 'approved' || plan.status === 'running') && (
                <Button
                  size="small"
                  color="warning"
                  variant="outlined"
                  disabled={abort.isPending}
                  onClick={() => abort.mutate(plan.id)}
                >
                  Abort
                </Button>
              )}
              {(plan.status === 'failed' || plan.status === 'aborted') && (
                <Button
                  size="small"
                  variant="contained"
                  disabled={retry.isPending}
                  onClick={() => {
                    setSelected(plan);
                    retry.mutate(plan);
                  }}
                >
                  Retry
                </Button>
              )}
            </Stack>
          </Box>
        ))}
      </Stack>
      {selected && selected.status === 'proposed' && (
        <Box sx={{ mt: 2 }}>
          <Typography variant="subtitle2" sx={{ mb: 1 }}>
            Edit steps (JSON) — plan #{selected.id}
          </Typography>
          <TextField
            fullWidth
            multiline
            minRows={6}
            value={editJson}
            onChange={(e) => setEditJson(e.target.value)}
            sx={fieldSx}
          />
          <Stack direction="row" spacing={1} sx={{ mt: 1 }}>
            <Button
              size="small"
              variant="outlined"
              disabled={update.isPending}
              onClick={() => update.mutate(selected)}
            >
              Save edit
            </Button>
            <Button
              size="small"
              variant="contained"
              disabled={approve.isPending}
              onClick={() => approve.mutate(selected)}
            >
              Save & approve
            </Button>
          </Stack>
        </Box>
      )}
    </TacticalPanel>
  );
};
