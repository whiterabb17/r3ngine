import React from 'react';
import { Autocomplete, Box, CircularProgress, TextField, Typography } from '@mui/material';
import { Link2 } from 'lucide-react';

import type { LLMModel } from '../api';
import { useThemeTokens } from '../../../theme/useThemeTokens';

interface OpenAiCompatibleFieldsProps {
  baseUrl: string;
  model: string;
  models: LLMModel[] | undefined;
  isModelsLoading: boolean;
  onBaseUrlChange: (value: string) => void;
  onModelChange: (value: string) => void;
}

/**
 * Base URL and model for a server that speaks the OpenAI chat completions API
 * (a gateway such as OpenRouter, or a local vLLM / LM Studio). The model is free
 * text: not every gateway lists all of its models under /models.
 */
export const OpenAiCompatibleFields: React.FC<OpenAiCompatibleFieldsProps> = ({
  baseUrl, model, models, isModelsLoading, onBaseUrlChange, onModelChange,
}) => {
  const { tokens } = useThemeTokens();
  const fieldSx = {
    '& .MuiOutlinedInput-root': {
      color: 'text.primary',
      bgcolor: 'action.hover',
      fontFamily: 'monospace',
      '& fieldset': { borderColor: 'divider' },
      '&:hover fieldset': { borderColor: `${tokens.accent.primary}4D` },
      '&.Mui-focused fieldset': { borderColor: tokens.accent.primary },
    },
  };
  const labelSx = { color: 'text.secondary', fontSize: '0.75rem', mb: 1, fontFamily: 'Orbitron' };

  return (
    <>
      <Box>
        <Typography sx={labelSx}>BASE_URL</Typography>
        <TextField
          fullWidth
          value={baseUrl}
          onChange={(e) => onBaseUrlChange(e.target.value)}
          placeholder="https://gateway.example.com/v1"
          slotProps={{
            input: {
              startAdornment: (
                <Box sx={{ color: `${tokens.accent.primary}80`, display: 'flex', mr: 1 }}>
                  <Link2 size={18} />
                </Box>
              ),
            },
            htmlInput: { 'aria-label': 'Base URL' },
          }}
          sx={fieldSx}
        />
        <Typography variant="caption" sx={{ color: 'text.disabled', mt: 1, display: 'block' }}>
          The API root that serves /chat/completions and /models, usually ending in /v1.
        </Typography>
      </Box>

      <Box>
        <Typography sx={labelSx}>MODEL</Typography>
        <Autocomplete
          freeSolo
          options={(models ?? []).map((m) => m.name)}
          value={model}
          inputValue={model}
          onInputChange={(_e, value) => onModelChange(value)}
          loading={isModelsLoading}
          renderInput={(params) => (
            <TextField
              {...params}
              placeholder="e.g. gpt-oss-120b"
              slotProps={{
                ...params.slotProps,
                input: {
                  ...params.slotProps.input,
                  endAdornment: (
                    <>
                      {isModelsLoading && <CircularProgress size={18} />}
                      {params.slotProps.input.endAdornment}
                    </>
                  ),
                },
                htmlInput: { ...params.slotProps.htmlInput, 'aria-label': 'Model' },
              }}
              sx={fieldSx}
            />
          )}
        />
        <Typography variant="caption" sx={{ color: 'text.disabled', mt: 1, display: 'block' }}>
          Pick from the gateway's /models list or type the model id it expects.
        </Typography>
      </Box>
    </>
  );
};
