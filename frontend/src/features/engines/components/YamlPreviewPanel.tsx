import React from 'react';
import { Box, Typography, Alert, IconButton, Tooltip } from '@mui/material';
import { Copy, Check } from 'lucide-react';
import { useThemeTokens } from '../../../theme/useThemeTokens';

interface YamlPreviewPanelProps {
  yaml: string;
  yamlError: string | null;
  onChange: (raw: string) => void;
}

export const YamlPreviewPanel: React.FC<YamlPreviewPanelProps> = ({ yaml, yamlError, onChange }) => {
  const { tokens, isLight } = useThemeTokens();
  const [copied, setCopied] = React.useState(false);

  const handleCopy = async () => {
    await navigator.clipboard.writeText(yaml);
    setCopied(true);
    setTimeout(() => setCopied(false), 2000);
  };

  return (
    <Box sx={{ display: 'flex', flexDirection: 'column', gap: 1, height: '100%' }}>
      <Box sx={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between' }}>
        <Typography variant="subtitle2" sx={{ color: 'text.secondary' }}>
          Live YAML — edits here sync back to the form
        </Typography>
        <Tooltip title={copied ? 'Copied!' : 'Copy to clipboard'}>
          <IconButton size="small" onClick={handleCopy}>
            {copied ? <Check size={14} color={tokens.accent.primary} /> : <Copy size={14} color={tokens.text.muted} />}
          </IconButton>
        </Tooltip>
      </Box>

      {yamlError && (
        <Alert severity="error" sx={{ py: 0.5, fontSize: '0.75rem' }}>
          Invalid YAML: {yamlError}
        </Alert>
      )}

      <Box
        component="textarea"
        value={yaml}
        onChange={(e: React.ChangeEvent<HTMLTextAreaElement>) => onChange(e.target.value)}
        spellCheck={false}
        sx={{
          flex: 1,
          minHeight: 480,
          width: '100%',
          fontFamily: 'monospace',
          fontSize: '0.8rem',
          lineHeight: 1.6,
          p: 1.5,
          border: yamlError
            ? `1px solid ${tokens.accent.error}`
            : `1px solid ${tokens.border.subtle}`,
          borderRadius: 1,
          bgcolor: tokens.surface.secondary,
          color: 'text.primary',
          resize: 'vertical',
          outline: 'none',
          '&:focus': {
            border: `1px solid ${tokens.accent.primary}`,
          },
        }}
      />
    </Box>
  );
};
