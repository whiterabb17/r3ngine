import React, { useState } from 'react';
import {
  Box,
  Button,
  Chip,
  Typography,
  TextField,
  Alert,
  CircularProgress,
  Divider,
} from '@mui/material';
import { Zap } from 'lucide-react';
import { WORKFLOW_REGISTRY } from '../types';
import type { WorkflowSlug, WorkflowMeta, StartWorkflowPayload } from '../types';
import { useStartWorkflow } from '../api';
import { ProfileSelector } from '../../profiles/components/ProfileSelector';
import { useThemeTokens } from '../../../theme/useThemeTokens';
import type { ResolvedThemeTokens } from '../../../theme/tokens';

interface WorkflowLauncherProps {
  onSuccess?: (workflowId: string, slug: WorkflowSlug) => void;
  onError?: (error: string) => void;
}

// Colors will be generated dynamically using theme tokens

const CATEGORY_LABELS: Record<WorkflowMeta['category'], string> = {
  recon: 'Recon',
  vuln: 'Vulnerability',
  crawl: 'Crawl',
  osint: 'OSINT',
  code: 'Code',
  network: 'Network',
};

const CATEGORY_ORDER: WorkflowMeta['category'][] = [
  'recon',
  'network',
  'crawl',
  'vuln',
  'osint',
  'code',
];

/**
 * Map inputType to the correct StartWorkflowPayload key.
 * cidr → cidr, domain → domain, url/path/ip/email/username → target
 */
function buildPayload(
  meta: WorkflowMeta,
  targetValue: string,
  profileName: string | null
): StartWorkflowPayload {
  const payload: StartWorkflowPayload = {};

  if (profileName) {
    payload.profile_name = profileName;
  }

  switch (meta.inputType) {
    case 'cidr':
      payload.cidr = targetValue;
      break;
    case 'domain':
      payload.domain = targetValue;
      break;
    case 'url':
    case 'ip':
    case 'email':
    case 'username':
    case 'path':
    default:
      payload.target = targetValue;
      break;
  }

  return payload;
}

const getFieldStyles = (tokens: ResolvedThemeTokens) => ({
  '& .MuiOutlinedInput-root': {
    color: 'text.primary',
    '& fieldset': { borderColor: 'divider' },
    '&:hover fieldset': { borderColor: `${tokens.accent.primary}4D` },
    '&.Mui-focused fieldset': { borderColor: tokens.accent.primary },
    bgcolor: 'action.hover',
  },
  '& .MuiInputLabel-root': {
    color: 'text.disabled',
    '&.Mui-focused': { color: tokens.accent.primary },
  },
  '& .MuiFormHelperText-root': { color: 'text.disabled' },
});

export const WorkflowLauncher: React.FC<WorkflowLauncherProps> = ({
  onSuccess,
  onError,
}) => {
  const { tokens } = useThemeTokens();
  const [selectedSlug, setSelectedSlug] = useState<WorkflowSlug | null>(null);
  const [target, setTarget] = useState('');
  const [profileName, setProfileName] = useState<string | null>(null);
  const [errorMessage, setErrorMessage] = useState<string | null>(null);

  const categoryColors: Record<WorkflowMeta['category'], string> = {
    recon: tokens.accent.primary,
    vuln: tokens.accent.error,
    crawl: tokens.accent.secondary,
    osint: tokens.accent.warning,
    code: tokens.accent.success,
    network: tokens.accent.info,
  };

  const { mutate: startWorkflow, isPending } = useStartWorkflow();

  const selectedMeta = selectedSlug
    ? WORKFLOW_REGISTRY.find((w) => w.slug === selectedSlug) ?? null
    : null;

  const handleSelectWorkflow = (slug: WorkflowSlug) => {
    setSelectedSlug(slug);
    setTarget('');
    setErrorMessage(null);
  };

  const handleLaunch = () => {
    if (!selectedMeta || !target.trim()) return;
    setErrorMessage(null);

    const payload = buildPayload(selectedMeta, target.trim(), profileName);

    startWorkflow(
      { slug: selectedMeta.slug, payload },
      {
        onSuccess: (data) => {
          setTarget('');
          setProfileName(null);
          setSelectedSlug(null);
          onSuccess?.(data.workflow_id, selectedMeta.slug);
        },
        onError: (err) => {
          const msg = err instanceof Error ? err.message : 'Failed to start workflow';
          setErrorMessage(msg);
          onError?.(msg);
        },
      }
    );
  };

  // Group workflows by category
  const grouped = React.useMemo(() => {
    const map = new Map<WorkflowMeta['category'], WorkflowMeta[]>();
    for (const wf of WORKFLOW_REGISTRY) {
      const group = map.get(wf.category) ?? [];
      group.push(wf);
      map.set(wf.category, group);
    }
    return map;
  }, []);

  return (
    <Box>
      {/* Workflow grid grouped by category */}
      {CATEGORY_ORDER.map((category) => {
        const group = grouped.get(category);
        if (!group || group.length === 0) return null;
        const color = categoryColors[category];
        return (
          <Box key={category} sx={{ mb: 2 }}>
            <Typography
              variant="overline"
              sx={{
                color: `${color}80`,
                fontWeight: 800,
                fontSize: '0.6rem',
                letterSpacing: 1.5,
                display: 'block',
                mb: 0.75,
              }}
            >
              {CATEGORY_LABELS[category]}
            </Typography>
            <Box sx={{ display: 'flex', flexWrap: 'wrap', gap: 0.75 }}>
              {group.map((wf) => {
                const isSelected = selectedSlug === wf.slug;
                return (
                  <Chip
                    key={wf.slug}
                    label={wf.label}
                    onClick={() => handleSelectWorkflow(wf.slug)}
                    title={wf.description}
                    sx={{
                      cursor: 'pointer',
                      fontWeight: isSelected ? 900 : 600,
                      fontSize: '0.72rem',
                      letterSpacing: 0.5,
                      bgcolor: isSelected ? `${color}22` : 'background.paper',
                      color: isSelected ? color : 'text.secondary',
                      border: '1px solid',
                      borderColor: isSelected ? color : 'divider',
                      transition: 'all 0.15s',
                      '&:hover': {
                        bgcolor: `${color}18`,
                        color: color,
                        borderColor: color,
                      },
                      '& .MuiChip-label': { px: 1.5 },
                    }}
                  />
                );
              })}
            </Box>
          </Box>
        );
      })}

      {/* Launch form — only visible when a workflow is selected */}
      {selectedMeta && (
        <>
          <Divider sx={{ borderColor: 'divider', my: 2 }} />

          <Box sx={{ display: 'flex', alignItems: 'center', gap: 1, mb: 2 }}>
            <Box
              sx={{
                p: 0.75,
                borderRadius: 1.5,
                bgcolor: `${categoryColors[selectedMeta.category]}18`,
                color: categoryColors[selectedMeta.category],
                display: 'flex',
              }}
            >
              <Zap size={16} />
            </Box>
            <Box>
              <Typography
                sx={{
                  fontFamily: 'Orbitron',
                  fontWeight: 800,
                  fontSize: '0.8rem',
                  color: 'text.primary',
                  lineHeight: 1.2,
                }}
              >
                {selectedMeta.label.toUpperCase()}
              </Typography>
              <Typography sx={{ color: 'text.disabled', fontSize: '0.7rem' }}>
                {selectedMeta.description}
              </Typography>
            </Box>
          </Box>

          {errorMessage && (
            <Alert
              severity="error"
              sx={{
                mb: 2,
                bgcolor: `${tokens.accent.error}1A`,
                color: tokens.accent.error,
                border: 1, borderColor: `${tokens.accent.error}33`,
                '& .MuiAlert-icon': { color: tokens.accent.error },
              }}
              onClose={() => setErrorMessage(null)}
            >
              {errorMessage}
            </Alert>
          )}

          <Box sx={{ display: 'flex', flexDirection: 'column', gap: 2 }}>
            <TextField
              label={selectedMeta.inputLabel}
              placeholder={selectedMeta.inputPlaceholder}
              fullWidth
              value={target}
              onChange={(e) => setTarget(e.target.value)}
              disabled={isPending}
              sx={getFieldStyles(tokens)}
            />

            {/*
            <ProfileSelector
              value={profileName}
              onChange={setProfileName}
              disabled={isPending}
            />
            */}

            <Box sx={{ display: 'flex', justifyContent: 'flex-end' }}>
              <Button
                variant="contained"
                onClick={handleLaunch}
                disabled={isPending || !target.trim()}
                startIcon={
                  isPending ? (
                    <CircularProgress size={16} sx={{ color: '#000' }} />
                  ) : (
                    <Zap size={16} />
                  )
                }
                sx={{
                  bgcolor: categoryColors[selectedMeta.category],
                  color: '#000',
                  fontWeight: 900,
                  fontFamily: 'Orbitron',
                  fontSize: '0.72rem',
                  letterSpacing: 1,
                  px: 3,
                  '&:hover': {
                    bgcolor: categoryColors[selectedMeta.category],
                    filter: 'brightness(1.15)',
                    boxShadow: `0 0 16px ${categoryColors[selectedMeta.category]}55`,
                  },
                  '&.Mui-disabled': {
                    bgcolor: `${categoryColors[selectedMeta.category]}30`,
                    color: 'text.disabled',
                  },
                }}
              >
                {isPending ? 'LAUNCHING…' : 'LAUNCH'}
              </Button>
            </Box>
          </Box>
        </>
      )}
    </Box>
  );
};
