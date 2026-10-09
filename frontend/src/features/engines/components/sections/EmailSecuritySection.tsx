import React from 'react';
import { Grid, TextField, FormControlLabel, Checkbox, Typography, Collapse, Box } from '@mui/material';
import { alpha } from '@mui/material/styles';
import type { EmailSecurityConfig } from '../../types/engineConfig';
import { SectionCard } from '../shared/SectionCard';
import { getFieldSx } from '../../../../theme/semanticColors';
import { useThemeTokens } from '../../../../theme/useThemeTokens';

interface Props {
  config: EmailSecurityConfig;
  enabled: boolean;
  onToggle: (v: boolean) => void;
  onChange: (patch: Partial<EmailSecurityConfig>) => void;
}

/** Same bounds parse_mailbox_config clamps to, so the form never shows a value the scan won't use. */
const clamp = (value: string, lo: number, hi: number): number =>
  Math.max(lo, Math.min(hi, Math.trunc(Number(value)) || lo));

export const EmailSecuritySection: React.FC<Props> = ({ config, enabled, onToggle, onChange }) => {
  const { tokens, isLight } = useThemeTokens();
  const fieldSx = getFieldSx(isLight, tokens);
  const chkSx = { color: tokens.accent.primary, '&.Mui-checked': { color: tokens.accent.primary } };

  return (
    <SectionCard
      title="Email Security"
      description="SPF, DMARC, DKIM, open relay, STARTTLS and certificate checks for the target's mail. Runs after Tier 2, only when Port Scan is enabled."
      enabled={enabled}
      onToggle={onToggle}
    >
      <FormControlLabel
        control={
          <Checkbox
            checked={config.mailbox_verification}
            size="small"
            onChange={(e) => onChange({ mailbox_verification: e.target.checked })}
            sx={chkSx}
          />
        }
        label={<Typography variant="body2">Mailbox verification (Reacher)</Typography>}
      />
      <Typography variant="caption" component="p" sx={{ color: 'text.secondary', mb: 1 }}>
        Probes candidate addresses against the target's MX over SMTP. Noticeable to the mail server's operator.
      </Typography>

      <Collapse in={config.mailbox_verification}>
        <Box sx={{ mt: 1, pl: 2, borderLeft: `2px solid ${alpha(tokens.accent.primary, 0.25)}` }}>
          <Grid container spacing={2}>
            <Grid size={{ xs: 12, sm: 4 }}>
              <TextField
                label="Max Candidates"
                type="number"
                size="small"
                fullWidth
                value={config.max_candidates}
                onChange={(e) => onChange({ max_candidates: clamp(e.target.value, 1, 1000) })}
                slotProps={{ htmlInput: { min: 1, max: 1000 } }}
                sx={fieldSx}
              />
            </Grid>
            <Grid size={{ xs: 6, sm: 4 }}>
              <TextField
                label="Timeout per Check (s)"
                type="number"
                size="small"
                fullWidth
                value={config.timeout}
                onChange={(e) => onChange({ timeout: clamp(e.target.value, 1, 120) })}
                slotProps={{ htmlInput: { min: 1, max: 120 } }}
                sx={fieldSx}
              />
            </Grid>
            <Grid size={{ xs: 6, sm: 4 }}>
              <TextField
                label="Delay Between Checks (ms)"
                type="number"
                size="small"
                fullWidth
                value={config.delay_ms}
                onChange={(e) => onChange({ delay_ms: clamp(e.target.value, 0, 10000) })}
                slotProps={{ htmlInput: { min: 0, max: 10000 } }}
                sx={fieldSx}
              />
            </Grid>
            <Grid size={{ xs: 12 }}>
              <TextField
                label="Reacher HTTP URL (optional)"
                size="small"
                fullWidth
                value={config.http_url}
                onChange={(e) => onChange({ http_url: e.target.value.trim() })}
                placeholder="https://reacher.internal:8080"
                helperText="Self-hosted Reacher origin. Leave empty to use the bundled CLI."
                sx={fieldSx}
              />
            </Grid>
          </Grid>
        </Box>
      </Collapse>
    </SectionCard>
  );
};
