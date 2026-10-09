import React, { useState } from 'react';
import { Box, Typography, Button, TextField, InputAdornment, Stack, CircularProgress } from '@mui/material';
import { Plus, Search, Trash2 } from 'lucide-react';
import { useParams } from '@tanstack/react-router';
import { useOrganizations, useDeleteOrganizations } from '../api';
import { OrganizationTable } from './OrganizationTable';
import { CreateOrganizationModal } from './CreateOrganizationModal';
import type { Organization } from '../orgTypes';
import { TacticalPanel } from '../../../components/TacticalPanel';
import { ConfirmDialog } from '../../../components/ConfirmDialog';

export const OrganizationPage: React.FC = () => {
  const { projectSlug } = useParams({ from: '/$projectSlug/org' });
  const { data: organizations, isLoading } = useOrganizations();
  const deleteMutation = useDeleteOrganizations();

  const [searchQuery, setSearchQuery] = useState('');
  const [selectedIds, setSelectedIds] = useState<number[]>([]);
  const [isModalOpen, setIsModalOpen] = useState(false);
  const [editingOrg, setEditingOrg] = useState<Organization | undefined>(undefined);

  // Confirmation state
  const [confirmOpen, setConfirmOpen] = useState(false);
  const [confirmConfig, setConfirmConfig] = useState<{
    title: string;
    message: string;
    onConfirm: () => void;
    type?: 'danger' | 'info' | 'warning';
  }>({
    title: '',
    message: '',
    onConfirm: () => {},
  });

  const filteredOrgs = organizations?.filter(org => 
    org.name.toLowerCase().includes(searchQuery.toLowerCase()) ||
    org.description?.toLowerCase().includes(searchQuery.toLowerCase())
  ) || [];

  const handleToggleSelect = (id: number) => {
    setSelectedIds(prev => 
      prev.includes(id) ? prev.filter(i => i !== id) : [...prev, id]
    );
  };

  const handleSelectAll = (checked: boolean) => {
    if (checked) {
      setSelectedIds(filteredOrgs.map(org => org.id));
    } else {
      setSelectedIds([]);
    }
  };

  const handleAdd = () => {
    setEditingOrg(undefined);
    setIsModalOpen(true);
  };

  const handleEdit = (org: Organization) => {
    setEditingOrg(org);
    setIsModalOpen(true);
  };

  const handleDelete = async (id: number) => {
    setConfirmConfig({
      title: 'DELETE ORGANIZATION',
      message: 'Are you sure you want to delete this organization? All associated data will be archived or removed.',
      type: 'danger',
      onConfirm: async () => {
        await deleteMutation.mutateAsync([id]);
      }
    });
    setConfirmOpen(true);
  };

  const handleDeleteMultiple = async () => {
    if (selectedIds.length === 0) return;
    setConfirmConfig({
      title: 'BULK DELETE ORGANIZATIONS',
      message: `Are you sure you want to delete ${selectedIds.length} organizations?`,
      type: 'danger',
      onConfirm: async () => {
        await deleteMutation.mutateAsync(selectedIds);
        setSelectedIds([]);
      }
    });
    setConfirmOpen(true);
  };

  return (
    <Box sx={{ p: 4, maxWidth: '1600px', margin: '0 auto' }}>
      <TacticalPanel title="Organizations Management">
        <Box sx={{ mb: 4, display: 'flex', justifyContent: 'space-between', alignItems: 'center', flexWrap: 'wrap', gap: 2 }}>
          <Stack direction="row" spacing={2} sx={{ flexGrow: 1, maxWidth: '600px' }}>
            <TextField
              placeholder="Search organizations..."
              value={searchQuery}
              onChange={(e) => setSearchQuery(e.target.value)}
              fullWidth
              slotProps={{
                input: {
                  startAdornment: (
                    <InputAdornment position="start">
                      <Search size={18} color="rgba(255, 255, 255, 0.5)" />
                    </InputAdornment>
                  ),
                  sx: { 
                    backgroundColor: 'rgba(255, 255, 255, 0.03)',
                    color: 'text.primary',
                    '& .MuiOutlinedInput-notchedOutline': { borderColor: '#1a1a2e' },
                    '&:hover .MuiOutlinedInput-notchedOutline': { borderColor: '#00f3ff' },
                    '&.Mui-focused .MuiOutlinedInput-notchedOutline': { borderColor: '#00f3ff' }
                  }
                }
              }}
            />
          </Stack>
          
          <Stack direction="row" spacing={2}>
            {selectedIds.length > 0 && (
              <Button
                variant="outlined"
                color="error"
                startIcon={<Trash2 size={18} />}
                onClick={handleDeleteMultiple}
                sx={{ 
                  borderColor: '#ff003c', 
                  color: '#ff003c',
                  fontFamily: 'Orbitron',
                  fontSize: '0.8125rem',
                  letterSpacing: '1px',
                  borderRadius: '8px',
                  px: 2,
                  '&:hover': { backgroundColor: 'rgba(255, 0, 60, 0.1)', borderColor: '#ff003c' }
                }}
              >
                Delete Selected ({selectedIds.length})
              </Button>
            )}
            <Button
              variant="contained"
              startIcon={<Plus size={18} />}
              onClick={handleAdd}
              sx={{
                bgcolor: 'rgba(0, 243, 255, 0.05)',
                color: '#00f3ff',
                border: '1px solid rgba(0, 243, 255, 0.2)',
                fontWeight: 800,
                fontFamily: 'Orbitron',
                fontSize: '0.75rem',
                letterSpacing: '1px',
                borderRadius: '6px',
                px: 3,
                py: 1,
                boxShadow: '0 0 10px rgba(0, 243, 255, 0.1)',
                '&:hover': {
                  bgcolor: 'rgba(0, 243, 255, 0.15)',
                  borderColor: '#00f3ff',
                  boxShadow: '0 0 20px rgba(0, 243, 255, 0.4)',
                },
                transition: 'all 0.2s ease-in-out'
              }}
            >
              Add New Organization
            </Button>
          </Stack>
        </Box>

        {isLoading ? (
          <Box sx={{ display: 'flex', justifyContent: 'center', py: 10 }}>
            <CircularProgress sx={{ color: '#00f3ff' }} />
          </Box>
        ) : (
          <OrganizationTable
            organizations={filteredOrgs}
            selectedIds={selectedIds}
            onToggleSelect={handleToggleSelect}
            onSelectAll={handleSelectAll}
            onEdit={handleEdit}
            onDelete={handleDelete}
            projectSlug={projectSlug}
          />
        )}
      </TacticalPanel>

      <CreateOrganizationModal
        open={isModalOpen}
        onClose={() => setIsModalOpen(false)}
        organization={editingOrg}
        projectSlug={projectSlug}
      />

      {/* Confirmation Dialog */}
      <ConfirmDialog
        open={confirmOpen}
        onClose={() => setConfirmOpen(false)}
        onConfirm={() => {
          confirmConfig.onConfirm();
          setConfirmOpen(false);
        }}
        title={confirmConfig.title}
        message={confirmConfig.message}
        type={confirmConfig.type}
      />
    </Box>
  );
};
