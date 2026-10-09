import React, { useState } from 'react';
import {
  Box, Button, Chip, CircularProgress, Collapse, Divider,
  FormControl, FormControlLabel, Checkbox, Grid, IconButton,
  InputLabel, MenuItem, Select, TextField, Tooltip, Typography,
} from '@mui/material';
import DeleteIcon from '@mui/icons-material/Delete';
import AddIcon from '@mui/icons-material/Add';
import { useScanProfiles, useCreateScanProfile, useDeleteScanProfile } from '../api';
import type { CreateProfilePayload, ScanProfile } from '../types';

const CATEGORIES = ['hardware', 'speed', 'evasion', 'content', 'network', 'general'] as const;
const CATEGORY_LABELS: Record<string, string> = {
  hardware: 'Hardware',
  speed: 'Speed / Throttle',
  evasion: 'Evasion',
  content: 'Content',
  network: 'Network',
  general: 'General',
};

const EMPTY_FORM: CreateProfilePayload = { name: '', description: '', category: 'speed' };

import { useThemeTokens } from '../../../theme/useThemeTokens';

export const ProfileManager: React.FC = () => {
  const { tokens } = useThemeTokens();
  const { data: profiles = [], isLoading, refetch } = useScanProfiles();
  const createMutation = useCreateScanProfile();
  const deleteMutation = useDeleteScanProfile();

  const [showCreate, setShowCreate] = useState(false);
  const [form, setForm] = useState<CreateProfilePayload>(EMPTY_FORM);
  const [formError, setFormError] = useState<string | null>(null);

  const grouped = CATEGORIES.reduce<Record<string, ScanProfile[]>>((acc, cat) => {
    acc[cat] = profiles.filter(p => p.category === cat);
    return acc;
  }, {} as Record<string, ScanProfile[]>);

  const handleCreate = () => {
    if (!form.name.trim()) { setFormError('Name is required.'); return; }
    setFormError(null);
    createMutation.mutate(form, {
      onSuccess: () => { setShowCreate(false); setForm(EMPTY_FORM); refetch(); },
      onError: () => setFormError('Failed to create profile. Name may already exist.'),
    });
  };

  const handleDelete = (name: string) => {
    if (!confirm(`Delete profile "${name}"?`)) return;
    deleteMutation.mutate(name, { onSuccess: () => refetch() });
  };

  if (isLoading) return (
    <Box sx={{ display: 'flex', justifyContent: 'center', p: 4 }}>
      <CircularProgress size={24} sx={{ color: '#00ff62' }} />
    </Box>
  );

  return (
    <Box>
      <Box sx={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', mb: 2 }}>
        <Typography
          variant="h6"
          sx={{ fontFamily: 'Orbitron', fontWeight: 700, color: tokens.accent.primary, fontSize: '0.9rem', letterSpacing: 1 }}
        >
          SCAN PROFILES
        </Typography>
        <Button
          startIcon={<AddIcon />}
          variant="outlined"
          size="small"
          onClick={() => setShowCreate(v => !v)}
          sx={{
            borderColor: `${tokens.accent.primary}80`,
            color: tokens.accent.primary,
            fontFamily: 'Orbitron',
            fontWeight: 700,
            fontSize: '0.7rem',
            '&:hover': {
              borderColor: tokens.accent.primary,
              bgcolor: `${tokens.accent.primary}15`,
            },
          }}
        >
          {showCreate ? 'CANCEL' : 'NEW PROFILE'}
        </Button>
      </Box>

      <Collapse in={showCreate}>
        <Box sx={{
          p: 2, mb: 3,
          border: 1, borderColor: 'divider',
          borderRadius: 1,
          bgcolor: 'action.hover',
        }}>
          <Typography
            variant="subtitle2"
            sx={{ mb: 2, fontFamily: 'Orbitron', fontWeight: 700, color: 'text.secondary', fontSize: '0.75rem' }}
          >
            Create Custom Profile
          </Typography>
          {formError && (
            <Typography color="error" variant="caption" sx={{ display: 'block', mb: 1 }}>
              {formError}
            </Typography>
          )}
          <Grid container spacing={2}>
            <Grid size={{ xs: 12, sm: 6 }}>
              <TextField
                fullWidth size="small" label="Name *" value={form.name}
                onChange={e => setForm(f => ({ ...f, name: e.target.value }))}
                sx={{
                  '& .MuiOutlinedInput-root': {
                    color: 'text.primary',
                    '& fieldset': { borderColor: 'rgba(255,255,255,0.1)' },
                    '&:hover fieldset': { borderColor: `${tokens.accent.primary}4D` },
                    '&.Mui-focused fieldset': { borderColor: tokens.accent.primary },
                    bgcolor: 'action.hover',
                  },
                  '& .MuiInputLabel-root': {
                    color: 'text.secondary',
                    '&.Mui-focused': { color: tokens.accent.primary },
                  },
                }}
              />
            </Grid>
            <Grid size={{ xs: 12, sm: 6 }}>
              <FormControl fullWidth size="small" sx={{
                '& .MuiOutlinedInput-root': {
                  color: 'text.primary',
                  '& fieldset': { borderColor: 'rgba(255,255,255,0.1)' },
                  '&:hover fieldset': { borderColor: `${tokens.accent.primary}4D` },
                  '&.Mui-focused fieldset': { borderColor: tokens.accent.primary },
                  bgcolor: 'action.hover',
                },
                '& .MuiInputLabel-root': {
                  color: 'text.secondary',
                  '&.Mui-focused': { color: tokens.accent.primary },
                },
                '& .MuiSelect-icon': { color: 'text.secondary' },
              }}>
                <InputLabel>Category</InputLabel>
                <Select
                  value={form.category ?? 'speed'}
                  label="Category"
                  onChange={e => setForm(f => ({ ...f, category: e.target.value as ScanProfile['category'] }))}
                  MenuProps={{
                    slotProps: {
                      paper: {
                        sx: {
                          bgcolor: '#0a0a14',
                          border: '1px solid rgba(0, 255, 98, 0.15)',
                          '& .MuiMenuItem-root': {
                            color: '#fff',
                            '&:hover': { bgcolor: 'rgba(0, 255, 98, 0.08)' },
                            '&.Mui-selected': { bgcolor: 'rgba(0, 255, 98, 0.12)' },
                          },
                        },
                      },
                    },
                  }}
                >
                  {CATEGORIES.map(c => (
                    <MenuItem key={c} value={c}>{CATEGORY_LABELS[c]}</MenuItem>
                  ))}
                </Select>
              </FormControl>
            </Grid>
            <Grid size={{ xs: 12, sm: 6 }}>
              <TextField
                fullWidth size="small" label="Description" value={form.description ?? ''}
                onChange={e => setForm(f => ({ ...f, description: e.target.value }))}
                sx={{
                  '& .MuiOutlinedInput-root': {
                    color: 'text.primary',
                    '& fieldset': { borderColor: 'rgba(255,255,255,0.1)' },
                    '&:hover fieldset': { borderColor: 'rgba(0, 255, 98, 0.3)' },
                    '&.Mui-focused fieldset': { borderColor: '#00ff62' },
                    bgcolor: 'rgba(255,255,255,0.03)',
                  },
                  '& .MuiInputLabel-root': {
                    color: 'text.secondary',
                    '&.Mui-focused': { color: '#00ff62' },
                  },
                }}
              />
            </Grid>
            <Grid size={{ xs: 6, sm: 3 }}>
              <TextField
                fullWidth size="small" type="number" label="Rate Limit (r/s)"
                value={form.rate_limit ?? ''}
                onChange={e => setForm(f => ({ ...f, rate_limit: e.target.value ? +e.target.value : undefined }))}
                sx={{
                  '& .MuiOutlinedInput-root': {
                    color: 'text.primary',
                    '& fieldset': { borderColor: 'rgba(255,255,255,0.1)' },
                    '&:hover fieldset': { borderColor: 'rgba(0, 255, 98, 0.3)' },
                    '&.Mui-focused fieldset': { borderColor: '#00ff62' },
                    bgcolor: 'rgba(255,255,255,0.03)',
                  },
                  '& .MuiInputLabel-root': {
                    color: 'text.secondary',
                    '&.Mui-focused': { color: '#00ff62' },
                  },
                }}
              />
            </Grid>
            <Grid size={{ xs: 6, sm: 3 }}>
              <TextField
                fullWidth size="small" type="number" label="Threads"
                value={form.threads ?? ''}
                onChange={e => setForm(f => ({ ...f, threads: e.target.value ? +e.target.value : undefined }))}
                sx={{
                  '& .MuiOutlinedInput-root': {
                    color: 'text.primary',
                    '& fieldset': { borderColor: 'rgba(255,255,255,0.1)' },
                    '&:hover fieldset': { borderColor: 'rgba(0, 255, 98, 0.3)' },
                    '&.Mui-focused fieldset': { borderColor: '#00ff62' },
                    bgcolor: 'rgba(255,255,255,0.03)',
                  },
                  '& .MuiInputLabel-root': {
                    color: 'text.secondary',
                    '&.Mui-focused': { color: '#00ff62' },
                  },
                }}
              />
            </Grid>
            <Grid size={{ xs: 12 }}>
              {(['passive', 'active', 'stealth', 'hunt_secrets', 'tor'] as const).map(flag => (
                <FormControlLabel
                  key={flag}
                  control={
                    <Checkbox
                      size="small"
                      checked={!!form[flag]}
                      onChange={e => setForm(f => ({ ...f, [flag]: e.target.checked }))}
                      sx={{
                        color: 'text.secondary',
                        '&.Mui-checked': { color: '#00ff62' },
                      }}
                    />
                  }
                  label={
                    <Typography variant="caption" sx={{ color: 'text.secondary' }}>
                      {flag.replace(/_/g, ' ')}
                    </Typography>
                  }
                />
              ))}
            </Grid>
            <Grid size={{ xs: 12 }}>
              <Button
                variant="contained"
                size="small"
                onClick={handleCreate}
                disabled={createMutation.isPending}
                sx={{
                  bgcolor: '#00ff62',
                  color: '#000',
                  fontFamily: 'Orbitron',
                  fontWeight: 900,
                  fontSize: '0.7rem',
                  '&:hover': { bgcolor: '#00cc4f' },
                  '&.Mui-disabled': { bgcolor: 'rgba(0, 255, 98, 0.2)', color: 'rgba(0,0,0,0.5)' },
                }}
              >
                {createMutation.isPending ? 'SAVING...' : 'CREATE PROFILE'}
              </Button>
            </Grid>
          </Grid>
        </Box>
      </Collapse>

      {CATEGORIES.map(cat => {
        const items = grouped[cat];
        if (!items.length) return null;
        return (
          <Box key={cat} sx={{ mb: 3 }}>
            <Typography
              variant="overline"
              sx={{
                color: 'rgba(0, 255, 98, 0.6)',
                fontFamily: 'Orbitron',
                fontSize: '0.65rem',
                fontWeight: 800,
                letterSpacing: 2,
              }}
            >
              {CATEGORY_LABELS[cat]}
            </Typography>
            <Divider sx={{ mb: 1, borderColor: 'rgba(255,255,255,0.06)' }} />
            {items.map(p => (
              <Box
                key={p.name}
                sx={{
                  display: 'flex',
                  alignItems: 'center',
                  py: 0.75,
                  px: 1,
                  gap: 1,
                  borderRadius: 1,
                  '&:hover': { bgcolor: 'rgba(255,255,255,0.03)' },
                }}
              >
                <Box sx={{ flex: 1, minWidth: 0 }}>
                  <Typography
                    variant="body2"
                    sx={{ fontWeight: 600, color: 'text.primary', fontFamily: 'monospace', fontSize: '0.82rem' }}
                  >
                    {p.name}
                  </Typography>
                  {p.description && (
                    <Typography variant="caption" sx={{ color: 'text.secondary' }}>
                      {p.description}
                    </Typography>
                  )}
                </Box>
                <Box sx={{ display: 'flex', gap: 0.5, flexWrap: 'wrap', justifyContent: 'flex-end' }}>
                  {p.rate_limit != null && (
                    <Chip
                      label={`${p.rate_limit} r/s`}
                      size="small"
                      variant="outlined"
                      sx={{ borderColor: 'rgba(255,255,255,0.15)', color: 'text.secondary', fontSize: '0.65rem' }}
                    />
                  )}
                  {p.threads != null && (
                    <Chip
                      label={`${p.threads}t`}
                      size="small"
                      variant="outlined"
                      sx={{ borderColor: 'rgba(255,255,255,0.15)', color: 'text.secondary', fontSize: '0.65rem' }}
                    />
                  )}
                  {p.passive && (
                    <Chip
                      label="passive"
                      size="small"
                      sx={{ bgcolor: 'rgba(0, 180, 255, 0.15)', color: '#00b4ff', fontSize: '0.65rem', border: '1px solid rgba(0,180,255,0.3)' }}
                    />
                  )}
                  {p.stealth && (
                    <Chip
                      label="stealth"
                      size="small"
                      sx={{ bgcolor: 'rgba(255, 160, 0, 0.15)', color: '#ffa000', fontSize: '0.65rem', border: '1px solid rgba(255,160,0,0.3)' }}
                    />
                  )}
                  {p.tor && (
                    <Chip
                      label="tor"
                      size="small"
                      sx={{ bgcolor: 'rgba(0, 255, 98, 0.12)', color: '#00ff62', fontSize: '0.65rem', border: '1px solid rgba(0,255,98,0.25)' }}
                    />
                  )}
                  {p.is_builtin && (
                    <Chip
                      label="built-in"
                      size="small"
                      sx={{ bgcolor: 'rgba(255,255,255,0.06)', color: 'text.secondary', fontSize: '0.65rem' }}
                    />
                  )}
                </Box>
                <Tooltip title={p.is_builtin ? 'Cannot delete built-in profiles' : 'Delete profile'}>
                  <span>
                    <IconButton
                      size="small"
                      disabled={p.is_builtin}
                      onClick={() => handleDelete(p.name)}
                      sx={{
                        color: 'rgba(255, 0, 85, 0.5)',
                        '&:hover': { color: '#ff0055', bgcolor: 'rgba(255, 0, 85, 0.1)' },
                        '&.Mui-disabled': { color: 'text.disabled' },
                      }}
                    >
                      <DeleteIcon fontSize="small" />
                    </IconButton>
                  </span>
                </Tooltip>
              </Box>
            ))}
          </Box>
        );
      })}

      {profiles.length === 0 && (
        <Box sx={{ textAlign: 'center', py: 6 }}>
          <Typography variant="body2" sx={{ color: 'text.disabled', fontFamily: 'Orbitron', fontSize: '0.75rem' }}>
            NO PROFILES CONFIGURED
          </Typography>
        </Box>
      )}
    </Box>
  );
};

export default ProfileManager;
