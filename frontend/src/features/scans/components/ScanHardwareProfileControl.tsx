import { useState } from 'react';
import { MenuItem, TextField } from '@mui/material';
import { Cpu } from 'lucide-react';
import { useThemeTokens } from '../../../theme/useThemeTokens';
import { getFieldSx, getMenuPaperSx } from '../../../theme/semanticColors';
import { useHardwareProfiles } from '../../engines/api';
import { useSetScanHardwareProfile } from '../api';

/** Pending, running and paused scans still have steps left to start. */
const SWITCHABLE_STATUSES = [-1, 1, 5];

const APPLIES_HINT = 'Applies to steps that start after the change; tools already running keep their settings.';

interface ScanHardwareProfileControlProps {
  scanId: number;
  scanStatus: number;
  currentProfileId: number | null;
}

type Feedback = { kind: 'success' | 'error'; text: string } | null;

/** Compact selector that switches the hardware profile of a live scan. */
export function ScanHardwareProfileControl({ scanId, scanStatus, currentProfileId }: ScanHardwareProfileControlProps) {
  const { tokens, isLight, theme } = useThemeTokens();
  const { data: profiles } = useHardwareProfiles();
  const mutation = useSetScanHardwareProfile();
  const [feedback, setFeedback] = useState<Feedback>(null);

  if (!SWITCHABLE_STATUSES.includes(scanStatus)) return null;

  const activeProfiles = (profiles ?? []).filter((p) => p.is_active);
  // A scan without a profile of its own runs on the active default (hardware_profile_context).
  const effectiveId = currentProfileId
    ?? (activeProfiles.find((p) => p.is_default) ?? activeProfiles[0])?.id
    ?? null;
  const value = activeProfiles.some((p) => p.id === effectiveId) ? effectiveId : '';

  const handleChange = (profileId: number) => {
    if (profileId === currentProfileId) return;
    setFeedback(null);
    mutation.mutate(
      { scanId, hardwareProfileId: profileId },
      {
        onSuccess: (res) => setFeedback({
          kind: 'success',
          text: `Switched to ${res.hardware_profile?.name ?? 'the new profile'}. ${APPLIES_HINT}`,
        }),
        onError: (err) => setFeedback({ kind: 'error', text: err.message }),
      },
    );
  };

  return (
    <TextField
      select
      size="small"
      label="Hardware profile"
      value={value ?? ''}
      disabled={mutation.isPending || activeProfiles.length === 0}
      onChange={(e) => handleChange(Number(e.target.value))}
      error={feedback?.kind === 'error'}
      helperText={feedback?.text ?? APPLIES_HINT}
      sx={{
        ...getFieldSx(isLight, tokens),
        width: { xs: '100%', md: 240 },
        '& .MuiFormHelperText-root': { mx: 0, fontSize: '0.65rem', lineHeight: 1.3 },
      }}
      slotProps={{
        input: {
          startAdornment: <Cpu size={14} style={{ marginRight: 8, flexShrink: 0, color: tokens.accent.primary }} />,
        },
        select: {
          MenuProps: { slotProps: { paper: { sx: getMenuPaperSx(isLight, theme, tokens) } } },
        },
        formHelperText: { role: feedback?.kind === 'error' ? 'alert' : 'status' },
      }}
    >
      {activeProfiles.map((profile) => (
        <MenuItem key={profile.id} value={profile.id}>
          {profile.name.toUpperCase()}{profile.is_default ? ' (DEFAULT)' : ''} · {profile.threads} thr · {profile.rate_limit}/s
        </MenuItem>
      ))}
    </TextField>
  );
}
