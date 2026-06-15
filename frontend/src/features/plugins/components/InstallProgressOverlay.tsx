import React from 'react';
import {
  Backdrop,
  Box,
  Button,
  Typography,
  LinearProgress,
  Stack,
  Chip,
} from '@mui/material';
import { alpha } from '@mui/material/styles';
import {
  CheckCircle,
  XCircle,
  Circle,
  Loader,
  PackageOpen,
  ShieldCheck,
  RefreshCw,
  AlertTriangle,
} from 'lucide-react';
import { useInstallStatus, type InstallStep } from '../api/pluginsApi';
import { useThemeTokens } from '../../../theme/useThemeTokens';

// All steps in the expected order — used to fill in pending steps before backend emits them
const ALL_STEPS: { key: string; label: string }[] = [
  { key: 'upload',     label: 'Saving plugin archive' },
  { key: 'extract',    label: 'Extracting archive' },
  { key: 'verify',     label: 'Verifying integrity' },
  { key: 'validate',   label: 'Validating manifest' },
  { key: 'backup',     label: 'Creating database backup' },
  { key: 'register',   label: 'Registering plugin' },
  { key: 'migrations', label: 'Running database migrations' },
  { key: 'assets',     label: 'Installing UI assets & fixtures' },
  { key: 'complete',   label: 'Installation complete' },
];

interface Props {
  installId: string | null;
  onComplete: (pluginName: string) => void;
  onError: (message: string) => void;
}

const InstallProgressOverlay: React.FC<Props> = ({ installId, onComplete, onError }) => {
  const { tokens } = useThemeTokens();
  const { data } = useInstallStatus(installId);

  // Merge backend steps with the full ordered step list so pending steps are always visible
  const mergedSteps: InstallStep[] = ALL_STEPS.map(({ key, label }) => {
    const live = data?.steps.find(s => s.key === key);
    return live ?? { key, label, status: 'pending', message: '' };
  });

  const completedCount = mergedSteps.filter(s => s.status === 'completed' || s.status === 'skipped').length;
  const progress = Math.round((completedCount / ALL_STEPS.length) * 100);
  const isSuccess = data?.status === 'success';
  const isFailed = data?.status === 'failed';

  return (
    <Backdrop
      open={!!installId}
      sx={{
        zIndex: (theme) => theme.zIndex.drawer + 100,
        backdropFilter: 'blur(6px)',
        bgcolor: alpha('#000000', 0.75),
      }}
    >
      <Box
        sx={{
          width: 480,
          bgcolor: tokens.surface.elevated,
          border: `1px solid ${isSuccess ? tokens.accent.success : isFailed ? tokens.accent.error : tokens.border.subtle}`,
          borderRadius: '20px',
          p: 4,
          boxShadow: `0 0 60px ${isSuccess ? alpha(tokens.accent.success, 0.1) : isFailed ? alpha(tokens.accent.error, 0.1) : alpha(tokens.accent.primary, 0.08)}`,
        }}
      >
        {/* Header */}
        <Stack direction="row" spacing={2} sx={{ mb: 3, alignItems: 'center' }}>
          <Box sx={{ color: isSuccess ? tokens.accent.success : isFailed ? tokens.accent.error : tokens.accent.primary, filter: `drop-shadow(0 0 8px currentColor)` }}>
            {isSuccess ? <ShieldCheck size={28} /> : isFailed ? <XCircle size={28} /> : <PackageOpen size={28} />}
          </Box>
          <Box sx={{ flex: 1 }}>
            <Typography
              sx={{
                fontFamily: 'var(--r3-heading-font)',
                fontWeight: 900,
                fontSize: '1rem',
                letterSpacing: 2,
                color: isSuccess ? tokens.accent.success : isFailed ? tokens.accent.error : tokens.text.primary,
              }}
            >
              {isSuccess ? 'INSTALL SUCCESSFUL' : isFailed ? 'INSTALLATION FAILED' : 'INSTALLING PLUGIN'}
            </Typography>
            {data?.plugin_name && (
              <Typography variant="caption" sx={{ color: tokens.text.muted, fontFamily: 'monospace', fontSize: '0.7rem' }}>
                {data.plugin_name}
              </Typography>
            )}
          </Box>
          <Chip
            label={`${progress}%`}
            size="small"
            sx={{
              fontFamily: 'var(--r3-heading-font)',
              fontWeight: 900,
              fontSize: '0.65rem',
              bgcolor: alpha(tokens.text.primary, 0.05),
              color: tokens.text.secondary,
              border: `1px solid ${tokens.border.subtle}`,
            }}
          />
        </Stack>

        {/* Progress bar */}
        <LinearProgress
          variant="determinate"
          value={progress}
          sx={{
            mb: 3,
            height: 3,
            borderRadius: 2,
            bgcolor: alpha(tokens.text.primary, 0.06),
            '& .MuiLinearProgress-bar': {
              borderRadius: 2,
              bgcolor: isSuccess ? tokens.accent.success : isFailed ? tokens.accent.error : tokens.accent.primary,
              boxShadow: `0 0 8px ${isSuccess ? tokens.accent.success : isFailed ? tokens.accent.error : tokens.accent.primary}`,
            },
          }}
        />

        {/* Step list */}
        <Stack spacing={0.5}>
          {mergedSteps.map((step) => (
            <StepRow key={step.key} step={step} />
          ))}
        </Stack>

        {/* Unsigned / legacy warning */}
        {isSuccess && data?.warning && (
          <Box sx={{ mt: 2.5, p: 1.5, bgcolor: alpha(tokens.accent.warning, 0.07), border: `1px solid ${alpha(tokens.accent.warning, 0.25)}`, borderRadius: 1, display: 'flex', gap: 1.25, alignItems: 'flex-start' }}>
            <Box sx={{ color: tokens.accent.warning, flexShrink: 0, mt: '1px' }}>
              <AlertTriangle size={14} />
            </Box>
            <Typography variant="caption" sx={{ color: tokens.accent.warning, fontFamily: 'monospace', fontSize: '0.68rem', lineHeight: 1.5 }}>
              {data.warning}
            </Typography>
          </Box>
        )}

        {/* Error message */}
        {isFailed && data?.error && (
          <Box sx={{ mt: 2.5, p: 1.5, bgcolor: alpha(tokens.accent.error, 0.07), border: `1px solid ${alpha(tokens.accent.error, 0.2)}`, borderRadius: 1 }}>
            <Typography variant="caption" sx={{ color: tokens.accent.error, fontFamily: 'monospace', fontSize: '0.7rem', wordBreak: 'break-all' }}>
              {data.error}
            </Typography>
          </Box>
        )}

        {/* Close / reload button — shown after terminal states */}
        {(isSuccess || isFailed) && (
          <Button
            fullWidth
            onClick={() => window.location.reload()}
            startIcon={<RefreshCw size={14} />}
            sx={{
              mt: 3,
              fontFamily: 'var(--r3-heading-font)',
              fontWeight: 900,
              fontSize: '0.7rem',
              letterSpacing: 1.5,
              borderRadius: '8px',
              py: 1,
              color: isSuccess ? tokens.accent.success : tokens.accent.error,
              border: `1px solid ${isSuccess ? alpha(tokens.accent.success, 0.3) : alpha(tokens.accent.error, 0.3)}`,
              bgcolor: isSuccess ? alpha(tokens.accent.success, 0.05) : alpha(tokens.accent.error, 0.05),
              '&:hover': {
                bgcolor: isSuccess ? alpha(tokens.accent.success, 0.12) : alpha(tokens.accent.error, 0.12),
              },
            }}
          >
            {isSuccess ? 'CLOSE & RELOAD' : 'DISMISS & RELOAD'}
          </Button>
        )}
      </Box>
    </Backdrop>
  );
};

// ── Step row ──────────────────────────────────────────────────────────────────

const StepRow: React.FC<{ step: InstallStep }> = ({ step }) => {
  const { tokens } = useThemeTokens();
  const { status, label, message } = step;

  const iconEl = (() => {
    switch (status) {
      case 'completed':
        return <CheckCircle size={14} color={tokens.accent.success} />;
      case 'failed':
        return <XCircle size={14} color={tokens.accent.error} />;
      case 'skipped':
        return <Circle size={14} color={tokens.accent.info} />;
      case 'in_progress':
        return (
          <Box
            sx={{
              display: 'flex',
              animation: 'spin 1s linear infinite',
              '@keyframes spin': { from: { transform: 'rotate(0deg)' }, to: { transform: 'rotate(360deg)' } },
            }}
          >
            <Loader size={14} color={tokens.accent.primary} />
          </Box>
        );
      default:
        return <Circle size={14} color={alpha(tokens.text.primary, 0.2)} />;
    }
  })();

  const labelColor = (() => {
    if (status === 'completed') return tokens.text.secondary;
    if (status === 'in_progress') return tokens.text.primary;
    if (status === 'failed') return tokens.accent.error;
    if (status === 'skipped') return alpha(tokens.accent.info, 0.6);
    return tokens.text.disabled;
  })();

  return (
    <Box>
      <Box sx={{ display: 'flex', alignItems: 'center', gap: 1.5, py: 0.6 }}>
        <Box sx={{ flexShrink: 0, width: 16, display: 'flex', justifyContent: 'center' }}>{iconEl}</Box>
        <Typography
          sx={{
            fontFamily: 'var(--r3-heading-font)',
            fontSize: '0.65rem',
            fontWeight: status === 'in_progress' ? 900 : 600,
            letterSpacing: 0.8,
            color: labelColor,
            flex: 1,
          }}
        >
          {label.toUpperCase()}
        </Typography>
        {status === 'in_progress' && (
          <Box sx={{ display: 'flex', gap: '3px', alignItems: 'center' }}>
            {[0, 1, 2].map(i => (
              <Box
                key={i}
                sx={{
                  width: 3,
                  height: 3,
                  borderRadius: '50%',
                  bgcolor: tokens.accent.primary,
                  animation: 'dotPulse 1.2s ease-in-out infinite',
                  animationDelay: `${i * 0.2}s`,
                  '@keyframes dotPulse': { '0%,80%,100%': { opacity: 0.2 }, '40%': { opacity: 1 } },
                }}
              />
            ))}
          </Box>
        )}
        {status === 'skipped' && (
          <Typography
            sx={{
              fontFamily: 'var(--r3-heading-font)',
              fontSize: '0.5rem',
              fontWeight: 700,
              letterSpacing: 0.5,
              color: alpha(tokens.accent.info, 0.5),
              border: `1px solid ${alpha(tokens.accent.info, 0.2)}`,
              borderRadius: '3px',
              px: 0.6,
              py: 0.1,
              lineHeight: 1.6,
            }}
          >
            NOT REQUIRED
          </Typography>
        )}
      </Box>
      {status === 'failed' && message && (
        <Typography variant="caption" sx={{ color: alpha(tokens.accent.error, 0.6), fontFamily: 'monospace', fontSize: '0.6rem', pl: 4, display: 'block' }}>
          {message}
        </Typography>
      )}
    </Box>
  );
};

export default InstallProgressOverlay;
