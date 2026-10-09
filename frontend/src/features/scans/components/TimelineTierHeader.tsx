import React from 'react';
import { Box, Button, CircularProgress, Stack, Tooltip as MuiTooltip, Typography } from '@mui/material';
import { RefreshCw } from 'lucide-react';
import { useThemeTokens } from '../../../theme/useThemeTokens';
import { getFailureCategoryLabel } from '../utils/failureCategories';
import type { TierStatus, TierSummary } from '../utils/failureCategories';

const useTierStatusStyle = (status: TierStatus): { label: string; color: string } => {
  const { tokens, theme } = useThemeTokens();
  const styles: Record<TierStatus, { label: string; color: string }> = {
    FAILED: { label: 'FAILED', color: tokens.accent.error },
    NOT_RUN: { label: 'DID NOT RUN', color: theme.palette.text.disabled },
    RUNNING: { label: 'RUNNING', color: tokens.accent.primary },
    PENDING: { label: 'PENDING', color: tokens.accent.warning },
    COMPLETE: { label: 'COMPLETE', color: tokens.accent.success },
    EMPTY: { label: 'NO TASKS', color: theme.palette.text.disabled },
  };
  return styles[status];
};

const TierStatusChip: React.FC<{ status: TierStatus }> = ({ status }) => {
  const { label, color } = useTierStatusStyle(status);
  return (
    <Box
      component="span"
      sx={{
        px: 0.8,
        py: 0.1,
        borderRadius: 0.5,
        bgcolor: `${color}20`,
        border: `1px solid ${color}40`,
        color,
        fontSize: '0.55rem',
        fontWeight: 900,
        letterSpacing: '0.08em',
        whiteSpace: 'nowrap',
      }}
    >
      {label}
    </Box>
  );
};

export interface TimelineTierHeaderProps {
  label: string;
  summary: TierSummary;
  /** Accent the label like a plugin group instead of a tier group. */
  isPlugin?: boolean;
  /** Absent when the group is not a retryable tier (plugin groups, unknown tier). */
  onRetryTier?: () => void;
  /** Why the retry button is unavailable, shown as a tooltip when set. */
  retryBlockedReason?: string;
  isRetrying?: boolean;
}

/**
 * Group header for the scan timeline: says at a glance whether the tier failed,
 * what kind of failure it was, and offers a re-run when the tier has failed rows.
 */
export const TimelineTierHeader: React.FC<TimelineTierHeaderProps> = ({
  label,
  summary,
  isPlugin = false,
  onRetryTier,
  retryBlockedReason,
  isRetrying = false,
}) => {
  const { tokens } = useThemeTokens();
  const categoryLabels = summary.failureCategories
    .map((category) => getFailureCategoryLabel(category))
    .filter((text): text is string => !!text);
  const showRetry = summary.failedCount > 0 && (!!onRetryTier || !!retryBlockedReason);

  const retryButton = (
    <Button
      size="small"
      disabled={!onRetryTier || isRetrying}
      onClick={onRetryTier}
      startIcon={isRetrying ? <CircularProgress size={10} color="inherit" /> : <RefreshCw size={11} />}
      sx={{
        minWidth: 0,
        py: 0.1,
        px: 0.8,
        fontSize: '0.55rem',
        fontWeight: 900,
        letterSpacing: '0.06em',
        color: tokens.accent.primary,
        border: `1px solid ${tokens.accent.primary}40`,
        '&:hover': { bgcolor: `${tokens.accent.primary}15`, border: `1px solid ${tokens.accent.primary}` },
        '&.Mui-disabled': { color: 'text.disabled', border: 1, borderColor: 'divider' },
      }}
    >
      {isRetrying ? 'RETRYING' : 'RETRY TIER'}
    </Button>
  );

  return (
    <Box sx={{ mt: 1.5, mb: 0.5, px: 1 }}>
      <Stack
        direction="row"
        spacing={1}
        sx={{ alignItems: 'center', justifyContent: 'space-between', flexWrap: 'wrap', rowGap: 0.5 }}
      >
        <Stack direction="row" spacing={1} sx={{ alignItems: 'center', flexWrap: 'wrap', rowGap: 0.5, minWidth: 0 }}>
          <Typography
            component="span"
            sx={{
              fontSize: '0.55rem',
              fontWeight: 800,
              letterSpacing: '0.1em',
              textTransform: 'uppercase',
              color: isPlugin ? tokens.accent.primary : 'text.secondary',
            }}
          >
            {label}
          </Typography>
          <TierStatusChip status={summary.status} />
          {summary.failedCount > 0 && (
            <Typography component="span" sx={{ fontSize: '0.55rem', fontWeight: 700, color: tokens.accent.error }}>
              {summary.failedCount}/{summary.total} failed
            </Typography>
          )}
        </Stack>
        {showRetry && (
          retryBlockedReason
            ? <MuiTooltip title={retryBlockedReason} placement="top"><span>{retryButton}</span></MuiTooltip>
            : retryButton
        )}
      </Stack>
      {categoryLabels.length > 0 && (
        <Typography sx={{ mt: 0.3, fontSize: '0.55rem', fontWeight: 700, color: 'text.secondary', wordBreak: 'break-word' }}>
          Cause: {categoryLabels.join(', ')}
          {summary.allFailuresTransient ? ' — looks transient, a retry may clear it' : ''}
        </Typography>
      )}
      {summary.status === 'NOT_RUN' && (
        <Typography sx={{ mt: 0.3, fontSize: '0.55rem', fontWeight: 700, color: 'text.disabled', wordBreak: 'break-word' }}>
          {summary.notRunCount} task{summary.notRunCount === 1 ? '' : 's'} did not finish — the scan stopped before this work completed
        </Typography>
      )}
    </Box>
  );
};
