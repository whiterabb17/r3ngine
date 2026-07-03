import type { FC } from 'react';
import {
  Box,
  Grid,
  Card,
  CardActionArea,
  CardContent,
  Typography,
  Skeleton,
  Alert,
} from '@mui/material';
import { Cpu } from 'lucide-react';
import { useEngines } from '../api';
import { useThemeTokens } from '../../../theme/useThemeTokens';

// ─── Props ────────────────────────────────────────────────────────────────────

interface TemplatePickerProps {
  /** Called with the engine's raw yaml_configuration string when a card is clicked. */
  onSelect: (yaml: string) => void;
}

// ─── Built-in label fallbacks ─────────────────────────────────────────────────

const BUILT_IN_LABELS: Record<string, string> = {
  'Full Scan': 'Runs all tiers — comprehensive recon and vulnerability assessment',
  'Subdomain Recon': 'Tier 1 only — fast subdomain and DNS discovery',
  'Vulnerability Scan': 'Tier 6 focused — assumes subdomains already known',
  'Passive Only': 'Passive reconnaissance — no active probing',
  'Quick Recon': 'Fast surface mapping — ports, HTTP crawl, and screenshot',
  'Vuln Focus': 'Nuclei + DAST focused — skips recon, hits known targets',
};

// ─── Component ────────────────────────────────────────────────────────────────

export const TemplatePicker: FC<TemplatePickerProps> = ({ onSelect }) => {
  const { tokens, isLight } = useThemeTokens();
  const { data: engines, isLoading, isError } = useEngines();

  if (isLoading) {
    return (
      <Grid container spacing={2}>
        {[1, 2, 3].map((i) => (
          <Grid size={{ xs: 12, sm: 6, md: 4 }} key={i}>
            <Skeleton
              variant="rectangular"
              height={88}
              sx={{
                borderRadius: 1,
                bgcolor: tokens.surface.secondary,
              }}
            />
          </Grid>
        ))}
      </Grid>
    );
  }

  if (isError) {
    return (
      <Alert severity="error" sx={{ borderRadius: 1 }}>
        Failed to load engine templates.
      </Alert>
    );
  }

  if (!engines || engines.length === 0) {
    return (
      <Typography variant="body2" sx={{ color: tokens.text.muted }}>
        No saved engines found. Create one first to use it as a template.
      </Typography>
    );
  }

  return (
    <Box>
      <Typography variant="body2" sx={{ color: tokens.text.secondary, mb: 2 }}>
        Choose a saved engine to pre-fill the configuration, or start from scratch below.
      </Typography>

      <Grid container spacing={2}>
        {engines.map((engine) => (
          <Grid size={{ xs: 12, sm: 6, md: 4 }} key={engine.id}>
            <Card
              variant="outlined"
              sx={{
                height: '100%',
                bgcolor: tokens.surface.primary,
                borderColor: tokens.border.subtle,
                transition: 'border-color 0.15s ease, box-shadow 0.15s ease',
                '&:hover': {
                  borderColor: tokens.accent.primary,
                  boxShadow: `0 0 0 1px ${tokens.accent.primary}`,
                },
              }}
            >
              <CardActionArea
                onClick={() => onSelect(engine.yaml_configuration)}
                sx={{ height: '100%', p: 0 }}
              >
                <CardContent
                  sx={{
                    display: 'flex',
                    alignItems: 'flex-start',
                    gap: 1.5,
                    py: 1.5,
                    '&:last-child': { pb: 1.5 },
                  }}
                >
                  <Cpu
                    size={18}
                    style={{
                      color: engine.default_engine
                        ? tokens.accent.secondary
                        : tokens.accent.primary,
                      flexShrink: 0,
                      marginTop: 2,
                    }}
                  />
                  <Box>
                    <Typography
                      variant="subtitle2"
                      sx={{
                        fontWeight: 700,
                        color: tokens.text.primary,
                        lineHeight: 1.3,
                        mb: 0.25,
                      }}
                    >
                      {engine.engine_name}
                      {engine.default_engine && (
                        <Box
                          component="span"
                          sx={{
                            ml: 0.75,
                            fontSize: '0.65rem',
                            color: tokens.accent.secondary,
                            fontWeight: 500,
                            letterSpacing: '0.04em',
                          }}
                        >
                          DEFAULT
                        </Box>
                      )}
                    </Typography>
                    <Typography
                      variant="caption"
                      sx={{ color: tokens.text.secondary, lineHeight: 1.4 }}
                    >
                      {BUILT_IN_LABELS[engine.engine_name] ?? 'Custom scan engine configuration'}
                    </Typography>
                  </Box>
                </CardContent>
              </CardActionArea>
            </Card>
          </Grid>
        ))}
      </Grid>
    </Box>
  );
};
