import React, { useState, useEffect } from 'react';
import {
  Dialog,
  DialogTitle,
  DialogContent,
  DialogActions,
  Button,
  TextField,
  Box,
  Typography,
  FormControl,
  InputLabel,
  Select,
  MenuItem,
  OutlinedInput,
  Chip,
  CircularProgress,
  useTheme,
  alpha,
} from '@mui/material';
import { useTargetsWithoutOrganization, useCreateOrganization, useUpdateOrganization } from '../api';
import type { Organization } from '../orgTypes';
import { useThemeTokens } from '../../../theme/useThemeTokens';
import { getDialogPaperSx, getMenuPaperSx, getFieldSx } from '../../../theme/semanticColors';

interface CreateOrganizationModalProps {
  open: boolean;
  onClose: () => void;
  organization?: Organization; // If provided, we are in Edit mode
  projectSlug: string;
}

const ITEM_HEIGHT = 48;
const ITEM_PADDING_TOP = 8;

export const CreateOrganizationModal: React.FC<CreateOrganizationModalProps> = ({
  open,
  onClose,
  organization,
  projectSlug,
}) => {
  const theme = useTheme();
  const { tokens } = useThemeTokens();
  const isLight = tokens.mode === 'light';

  const [name, setName] = useState('');
  const [description, setDescription] = useState('');
  const [selectedDomains, setSelectedDomains] = useState<number[]>([]);

  const { data: availableTargets, isLoading: isLoadingTargets } = useTargetsWithoutOrganization();
  const createMutation = useCreateOrganization();
  const updateMutation = useUpdateOrganization();

  useEffect(() => {
    if (organization) {
      setName(organization.name);
      setDescription(organization.description || '');
      setSelectedDomains(organization.domains || []);
    } else {
      setName('');
      setDescription('');
      setSelectedDomains([]);
    }
  }, [organization, open]);

  const handleSubmit = async () => {
    if (!name) return;

    try {
      if (organization) {
        await updateMutation.mutateAsync({
          id: organization.id,
          name,
          description,
          domains: selectedDomains,
        });
      } else {
        await createMutation.mutateAsync({
          name,
          description,
          domains: selectedDomains,
          project: projectSlug as any, // Project ID or Slug depending on API
          slug: projectSlug
        });
      }
      onClose();
    } catch (error) {
      console.error('Failed to save organization:', error);
    }
  };

  const isSaving = createMutation.isPending || updateMutation.isPending;

  const selectMenuProps = {
    slotProps: {
      paper: {
        sx: {
          maxHeight: ITEM_HEIGHT * 4.5 + ITEM_PADDING_TOP,
          width: 250,
          ...getMenuPaperSx(isLight, theme, tokens),
        },
      }
    },
  };

  return (
    <Dialog
      open={open}
      onClose={onClose}
      maxWidth="md"
      fullWidth
      slotProps={{
        paper: {
          sx: {
            ...getDialogPaperSx(isLight, theme, tokens),
            backgroundImage: isLight
              ? 'none'
              : `linear-gradient(to bottom right, ${alpha(tokens.accent.primary, 0.05)}, ${alpha(tokens.accent.error, 0.05)})`,
            border: `1px solid ${tokens.border.subtle}`,
          }
        }
      }}
    >
      <DialogTitle sx={{ borderBottom: `1px solid ${tokens.border.subtle}`, py: 2 }}>
        <Typography variant="h6" sx={{ color: tokens.accent.primary, fontWeight: 'bold', textTransform: 'uppercase', letterSpacing: '1px' }}>
          {organization ? 'Edit Organization' : 'Create New Organization'}
        </Typography>
      </DialogTitle>
      <DialogContent sx={{ py: 3 }}>
        <Box sx={{ display: 'flex', flexDirection: 'column', gap: 3, mt: 1 }}>
          <TextField
            label="Organization Name"
            fullWidth
            value={name}
            onChange={(e) => setName(e.target.value)}
            variant="outlined"
            required
            sx={getFieldSx(isLight, tokens)}
          />
          <TextField
            label="Description (Optional)"
            fullWidth
            multiline
            rows={3}
            value={description}
            onChange={(e) => setDescription(e.target.value)}
            variant="outlined"
            sx={getFieldSx(isLight, tokens)}
          />

          <FormControl fullWidth sx={getFieldSx(isLight, tokens)}>
            <InputLabel id="domains-label">Select Targets</InputLabel>
            <Select
              labelId="domains-label"
              id="domains-select"
              multiple
              value={selectedDomains}
              onChange={(e) => setSelectedDomains(typeof e.target.value === 'string' ? e.target.value.split(',').map(Number) : e.target.value)}
              input={<OutlinedInput label="Select Targets" />}
              renderValue={(selected) => (
                <Box sx={{ display: 'flex', flexWrap: 'wrap', gap: 0.5 }}>
                  {selected.map((value) => {
                    const target = availableTargets?.find(t => t.id === value);
                    return (
                      <Chip
                        key={value}
                        label={target?.name || value}
                        sx={{
                          backgroundColor: alpha(tokens.accent.primary, 0.1),
                          color: tokens.accent.primary,
                          border: `1px solid ${alpha(tokens.accent.primary, 0.3)}`,
                          '& .MuiChip-deleteIcon': { color: tokens.accent.primary }
                        }}
                      />
                    );
                  })}
                </Box>
              )}
              MenuProps={selectMenuProps}
            >
              {isLoadingTargets ? (
                <MenuItem disabled>
                  <CircularProgress size={24} sx={{ color: tokens.accent.primary }} />
                </MenuItem>
              ) : availableTargets?.length === 0 ? (
                <MenuItem disabled>No available targets</MenuItem>
              ) : (
                availableTargets?.map((target) => (
                  <MenuItem key={target.id} value={target.id} sx={{
                    '&.Mui-selected': { backgroundColor: alpha(tokens.accent.primary, 0.2) },
                    '&:hover': { backgroundColor: alpha(tokens.accent.primary, 0.1) }
                  }}>
                    {target.name}
                  </MenuItem>
                ))
              )}
            </Select>
          </FormControl>
        </Box>
      </DialogContent>
      <DialogActions sx={{ px: 3, pb: 3 }}>
        <Button onClick={onClose} sx={{ color: tokens.text.secondary, '&:hover': { color: tokens.text.primary } }}>
          Cancel
        </Button>
        <Button
          onClick={handleSubmit}
          variant="contained"
          disabled={!name || isSaving}
          sx={{
            background: isLight 
              ? tokens.accent.primary 
              : `linear-gradient(45deg, ${tokens.accent.primary}, ${tokens.accent.secondary})`,
            color: theme.palette.getContrastText(tokens.accent.primary),
            fontWeight: 'bold',
            '&:hover': {
              bgcolor: alpha(tokens.accent.primary, 0.85),
              boxShadow: `0 0 15px ${alpha(tokens.accent.primary, 0.5)}`,
            },
            '&.Mui-disabled': {
              bgcolor: alpha(tokens.text.primary, 0.1),
              color: tokens.text.disabled,
            }
          }}
        >
          {isSaving ? <CircularProgress size={24} sx={{ color: theme.palette.getContrastText(tokens.accent.primary) }} /> : organization ? 'Update' : 'Create'}
        </Button>
      </DialogActions>
    </Dialog>
  );
};
