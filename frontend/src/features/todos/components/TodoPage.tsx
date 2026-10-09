import React, { useState, useMemo } from 'react';
import { Box, Typography, TextField, InputAdornment, Dialog, DialogTitle, DialogContent, DialogActions, Button, Stack, FormControl, InputLabel, Select, MenuItem, CircularProgress } from '@mui/material';
import { Search, Plus, Filter, LayoutGrid, List, CheckSquare } from 'lucide-react';
import { useParams } from '@tanstack/react-router';
import { TodoSidebar } from './TodoSidebar';
import { TodoItem } from './TodoItem';
import { useTodoNotes, useCreateTodo, useToggleTodoStatus, useToggleImportantStatus, useDeleteTodo } from '../api';
import type { TodoNote } from '../types';
import { TacticalPanel } from '../../../components/TacticalPanel';

import { useScans } from '../../scans/api';
import { useSubdomains } from '../../subdomains/api';
import { ConfirmDialog } from '../../../components/ConfirmDialog';

export const TodoPage: React.FC = () => {
  const { projectSlug } = useParams({ from: '/$projectSlug/todo' });
  const { data: todos, isLoading } = useTodoNotes(projectSlug);
  
  // Fetch Scans and Subdomains for the dropdowns
  const { data: scans } = useScans(projectSlug);
  const { data: subdomainsData } = useSubdomains(projectSlug);
  const subdomains = subdomainsData?.results || [];

  const [activeFilter, setActiveFilter] = useState<'all' | 'done' | 'important'>('all');
  const [searchQuery, setSearchQuery] = useState('');
  const [selectedNote, setSelectedNote] = useState<TodoNote | null>(null);
  const [isAddModalOpen, setIsAddModalOpen] = useState(false);
  
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
  
  // Create/Update/Delete Mutations
  const createMutation = useCreateTodo();
  const toggleStatusMutation = useToggleTodoStatus();
  const toggleImportantMutation = useToggleImportantStatus();
  const deleteMutation = useDeleteTodo();

  // Form State for new TODO
  const [newTodo, setNewTodo] = useState({ 
    title: '', 
    description: '',
    scan_history_id: 0,
    subdomain_id: 0
  });

  const filteredTodos = useMemo(() => {
    if (!todos) return [];
    
    return todos.filter(todo => {
      const matchesFilter = 
        activeFilter === 'all' || 
        (activeFilter === 'done' && todo.is_done) || 
        (activeFilter === 'important' && todo.is_important);
      
      const matchesSearch = 
        todo.title.toLowerCase().includes(searchQuery.toLowerCase()) ||
        todo.description.toLowerCase().includes(searchQuery.toLowerCase()) ||
        (todo.domain_name?.toLowerCase().includes(searchQuery.toLowerCase()));
        
      return matchesFilter && matchesSearch;
    });
  }, [todos, activeFilter, searchQuery]);

  const counts = useMemo(() => {
    if (!todos) return { all: 0, done: 0, important: 0 };
    return {
      all: todos.length,
      done: todos.filter(t => t.is_done).length,
      important: todos.filter(t => t.is_important).length
    };
  }, [todos]);

  const handleCreateTodo = async () => {
    if (!newTodo.title) return;
    await createMutation.mutateAsync({
      title: newTodo.title,
      description: newTodo.description,
      project: projectSlug,
      scan_history_id: newTodo.scan_history_id || undefined,
      subdomain_id: newTodo.subdomain_id || undefined
    });
    setNewTodo({ title: '', description: '', scan_history_id: 0, subdomain_id: 0 });
    setIsAddModalOpen(false);
  };

  const handleToggleStatus = (id: number) => {
    toggleStatusMutation.mutate({ id, projectSlug });
  };

  const handleToggleImportant = (id: number) => {
    toggleImportantMutation.mutate({ id, projectSlug });
  };

  const handleDeleteTodo = (id: number) => {
    setConfirmConfig({
      title: 'DELETE TACTICAL NOTE',
      message: 'Are you sure you want to delete this tactical note? This action is permanent.',
      type: 'danger',
      onConfirm: () => {
        deleteMutation.mutate({ id, projectSlug });
      }
    });
    setConfirmOpen(true);
  };

  if (isLoading) {
    return (
      <Box sx={{ display: 'flex', justifyContent: 'center', alignItems: 'center', height: '60vh' }}>
        <CircularProgress sx={{ color: '#00f3ff' }} />
      </Box>
    );
  }

  return (
    <Box sx={{ display: 'flex', gap: 4, height: 'calc(100vh - 160px)' }}>
      {/* Sidebar */}
      <TodoSidebar 
        activeFilter={activeFilter} 
        setActiveFilter={setActiveFilter} 
        counts={counts}
        onNewTodo={() => setIsAddModalOpen(true)}
      />

      {/* Main Content */}
      <Box sx={{ flexGrow: 1, display: 'flex', flexDirection: 'column', gap: 3 }}>
        {/* Header / Search */}
        <Box sx={{ display: 'flex', gap: 2, alignItems: 'center' }}>
          <TextField
            fullWidth
            placeholder="Search tactical notes..."
            value={searchQuery}
            onChange={(e) => setSearchQuery(e.target.value)}
            slotProps={{
              input: {
                startAdornment: (
                  <InputAdornment position="start">
                    <Search size={18} color="rgba(255,255,255,0.3)" />
                  </InputAdornment>
                ),
              }
            }}
            sx={{
              '& .MuiOutlinedInput-root': {
                bgcolor: 'rgba(255,255,255,0.02)',
                borderRadius: '12px',
                '& fieldset': { borderColor: 'rgba(255,255,255,0.1)' },
                '&:hover fieldset': { borderColor: 'rgba(0, 243, 255, 0.3)' },
                '&.Mui-focused fieldset': { borderColor: '#00f3ff' }
              },
              '& .MuiInputBase-input': { color: 'text.primary', fontSize: '0.9rem' }
            }}
          />
          <Stack direction="row" spacing={1}>
            <Button sx={{ minWidth: 40, p: 1, color: 'text.secondary', bgcolor: 'rgba(255,255,255,0.02)' }}><Filter size={18} /></Button>
            <Button sx={{ minWidth: 40, p: 1, color: '#00f3ff', bgcolor: 'rgba(0, 243, 255, 0.1)' }}><List size={18} /></Button>
            <Button sx={{ minWidth: 40, p: 1, color: 'text.secondary', bgcolor: 'rgba(255,255,255,0.02)' }}><LayoutGrid size={18} /></Button>
          </Stack>
        </Box>

        {/* Todo List */}
        <Box sx={{ flexGrow: 1, overflow: 'auto', pr: 1 }}>
          {filteredTodos.length === 0 ? (
            <Box sx={{ textAlign: 'center', mt: 8, opacity: 0.5 }}>
              <CheckSquare size={48} style={{ marginBottom: 16 }} />
              <Typography sx={{ fontFamily: 'Orbitron', fontSize: '0.8rem', letterSpacing: 1 }}>NO TACTICAL NOTES FOUND</Typography>
            </Box>
          ) : (
            filteredTodos.map(note => (
              <TodoItem 
                key={note.id} 
                note={note}
                onToggleStatus={handleToggleStatus}
                onToggleImportant={handleToggleImportant}
                onDelete={handleDeleteTodo}
                onClick={setSelectedNote}
              />
            ))
          )}
        </Box>
      </Box>

      {/* Add Todo Modal */}
      <Dialog 
        open={isAddModalOpen} 
        onClose={() => setIsAddModalOpen(false)}
        fullWidth
        maxWidth="md"
        sx={{
          '& .MuiDialog-paper': {
            bgcolor: '#0a0a0f',
            border: '1px solid rgba(0, 243, 255, 0.2)',
            boxShadow: '0 0 30px rgba(0, 243, 255, 0.1)',
            borderRadius: '16px',
          }
        }}
      >
        <DialogTitle sx={{ 
          color: '#fff', 
          fontFamily: 'Orbitron', 
          fontSize: '1rem', 
          fontWeight: 900,
          borderBottom: '1px solid rgba(255,255,255,0.05)',
          mb: 2
        }}>
          NEW TACTICAL NOTE
        </DialogTitle>
        <DialogContent>
          <Stack spacing={3} sx={{ mt: 2 }}>
            <Box>
              <Typography sx={{ color: 'rgba(255,255,255,0.7)', fontSize: '0.75rem', fontWeight: 600, mb: 1 }}>TODO TITLE</Typography>
              <TextField 
                fullWidth 
                placeholder="Todo Title"
                value={newTodo.title}
                onChange={(e) => setNewTodo({ ...newTodo, title: e.target.value })}
                sx={{ 
                  '& .MuiOutlinedInput-root': { 
                    color: '#fff',
                    bgcolor: 'rgba(255,255,255,0.03)',
                    '& fieldset': { borderColor: 'rgba(255,255,255,0.1)' }
                  } 
                }}
              />
            </Box>

            <Box sx={{ display: 'flex', flexDirection: 'column', alignItems: 'center' }}>
              <Box sx={{ width: '500px' }}>
                <Typography sx={{ color: 'rgba(255,255,255,0.7)', fontSize: '0.75rem', fontWeight: 600, mb: 1 }}>SELECT SCAN HISTORY (OPTIONAL)</Typography>
                <FormControl sx={{ width: '500px' }}>
                  <Select
                    value={newTodo.scan_history_id}
                    onChange={(e) => setNewTodo({ ...newTodo, scan_history_id: Number(e.target.value) })}
                    displayEmpty
                    sx={{ 
                      color: '#fff',
                      bgcolor: 'rgba(255,255,255,0.03)',
                      '& .MuiOutlinedInput-notchedOutline': { borderColor: 'rgba(255,255,255,0.1)' },
                      '&:hover .MuiOutlinedInput-notchedOutline': { borderColor: 'rgba(0, 243, 255, 0.3)' }
                    }}
                    MenuProps={{
                      slotProps: {
                        paper: {
                          sx: { 
                            bgcolor: '#0a0a0f', 
                            border: '1px solid rgba(0, 243, 255, 0.2)', 
                            color: '#fff',
                            width: 500,
                            maxWidth: 500
                          }
                        }
                      }
                    }}
                  >
                    <MenuItem value={0} sx={{ color: 'rgba(255,255,255,0.4)' }}>Choose Scan History...</MenuItem>
                    {scans?.map(scan => (
                      <MenuItem key={scan.id!} value={scan.id!}>
                        {scan.domain?.name || 'Unknown'} - {new Date(scan.start_scan_date).toLocaleString()}
                      </MenuItem>
                    ))}
                  </Select>
                </FormControl>
              </Box>
            </Box>

            <Box sx={{ display: 'flex', flexDirection: 'column', alignItems: 'center' }}>
              <Box sx={{ width: '500px' }}>
                <Typography sx={{ color: 'rgba(255,255,255,0.7)', fontSize: '0.75rem', fontWeight: 600, mb: 1 }}>SELECT SUBDOMAIN (OPTIONAL)</Typography>
                <FormControl sx={{ width: '500px' }}>
                  <Select
                    value={newTodo.subdomain_id}
                    onChange={(e) => setNewTodo({ ...newTodo, subdomain_id: Number(e.target.value) })}
                    displayEmpty
                    sx={{ 
                      color: '#fff',
                      bgcolor: 'rgba(255,255,255,0.03)',
                      '& .MuiOutlinedInput-notchedOutline': { borderColor: 'rgba(255,255,255,0.1)' },
                      '&:hover .MuiOutlinedInput-notchedOutline': { borderColor: 'rgba(0, 243, 255, 0.3)' }
                    }}
                    MenuProps={{
                      slotProps: {
                        paper: {
                          sx: { 
                            bgcolor: '#0a0a0f', 
                            border: '1px solid rgba(0, 243, 255, 0.2)', 
                            color: '#fff',
                            width: 500,
                            maxWidth: 500
                          }
                        }
                      }
                    }}
                  >
                    <MenuItem value={0} sx={{ color: 'rgba(255,255,255,0.4)' }}>Choose Subdomain...</MenuItem>
                    {subdomains?.map(sub => (
                      <MenuItem key={sub.id!} value={sub.id!}>{sub.name}</MenuItem>
                    ))}
                  </Select>
                </FormControl>
              </Box>
            </Box>

            <Box>
              <Typography sx={{ color: 'rgba(255,255,255,0.7)', fontSize: '0.75rem', fontWeight: 600, mb: 1 }}>RECON TODO/NOTE</Typography>
              <TextField 
                fullWidth 
                multiline 
                rows={4}
                placeholder="Recon Todo/Note"
                value={newTodo.description}
                onChange={(e) => setNewTodo({ ...newTodo, description: e.target.value })}
                sx={{ 
                  '& .MuiOutlinedInput-root': { 
                    color: '#fff',
                    bgcolor: 'rgba(255,255,255,0.03)',
                    '& fieldset': { borderColor: 'rgba(255,255,255,0.1)' }
                  } 
                }}
              />
            </Box>
          </Stack>
        </DialogContent>
        <DialogActions sx={{ p: 3 }}>
          <Button onClick={() => setIsAddModalOpen(false)} sx={{ color: 'rgba(255,255,255,0.5)', fontFamily: 'Orbitron', fontSize: '0.7rem' }}>CANCEL</Button>
          <Button 
            onClick={handleCreateTodo}
            variant="contained" 
            sx={{ 
              bgcolor: '#00f3ff', 
              color: '#000', 
              fontFamily: 'Orbitron', 
              fontWeight: 900,
              fontSize: '0.7rem',
              '&:hover': { bgcolor: '#00cce6' }
            }}
          >
            CREATE NOTE
          </Button>
        </DialogActions>
      </Dialog>

      {/* Note Detail Modal */}
      <Dialog 
        open={!!selectedNote} 
        onClose={() => setSelectedNote(null)}
        slotProps={{
          paper: {
            sx: {
              bgcolor: '#0a0a0f',
              border: '1px solid rgba(0, 243, 255, 0.2)',
              boxShadow: '0 0 30px rgba(0, 243, 255, 0.1)',
              borderRadius: '16px',
              minWidth: '500px'
            }
          }
        }}
      >
        <DialogTitle sx={{ 
          color: '#00f3ff', 
          fontFamily: 'Orbitron', 
          fontSize: '1.1rem', 
          fontWeight: 900,
          borderBottom: '1px solid rgba(255,255,255,0.05)',
          mb: 2
        }}>
          {selectedNote?.title}
        </DialogTitle>
        <DialogContent>
          {selectedNote?.domain_name && (
            <Typography sx={{ color: '#ff00ff', fontFamily: 'Orbitron', fontSize: '0.65rem', fontWeight: 900, mb: 2 }}>
              TARGET: {selectedNote.domain_name.toUpperCase()}
            </Typography>
          )}
          <Typography sx={{ color: 'rgba(255,255,255,0.8)', lineHeight: 1.8, fontSize: '0.9rem' }}>
            {selectedNote?.description}
          </Typography>
        </DialogContent>
        <DialogActions sx={{ p: 3 }}>
          <Button onClick={() => setSelectedNote(null)} sx={{ color: '#00f3ff', fontFamily: 'Orbitron', fontSize: '0.7rem', fontWeight: 900 }}>CLOSE</Button>
        </DialogActions>
      </Dialog>

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


