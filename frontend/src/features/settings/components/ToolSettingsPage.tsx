import React, { useState } from 'react';
import {
  Box,
  Typography,
  Grid,
  Button,
  Tabs,
  Tab,
  Paper,
  IconButton,
  Tooltip,
  CircularProgress,
  List,
  ListItem,
  ListItemButton,
  ListItemText,
  ListItemSecondaryAction,
  Divider,
  TextField,
  Alert,
  Snackbar,
  Accordion,
  AccordionSummary,
  AccordionDetails,
  Chip
} from '@mui/material';
import {
  Settings,
  Upload,
  Save,
  FileText,
  Zap,
  Shield,
  Code,
  CheckCircle,
  AlertTriangle,
  Search,
  Trash2,
  Edit3,
  ExternalLink,
  ChevronRight,
  ChevronDown,
  FolderOpen,
  Folder
} from 'lucide-react';
import { TacticalPanel } from '../../../components/TacticalPanel';
import {
  useToolSettings,
  useFileContent,
  useUpdateToolConfig,
  useUploadToolFiles,
  fetchToolFileContent
} from '../api';
import { useParams } from '@tanstack/react-router';

interface TabPanelProps {
  children?: React.ReactNode;
  index: number;
  value: number;
}

function TabPanel(props: TabPanelProps) {
  const { children, value, index, ...other } = props;
  return (
    <div
      role="tabpanel"
      hidden={value !== index}
      id={`tool-tabpanel-${index}`}
      aria-labelledby={`tool-tab-${index}`}
      {...other}
    >
      {value === index && (
        <Box sx={{ py: 2 }}>
          {children}
        </Box>
      )}
    </div>
  );
}

const groupByDirectory = (templates: string[]): Record<string, string[]> =>
  templates.reduce((acc, t) => {
    const sep = t.lastIndexOf('/');
    const key = sep > -1 ? t.slice(0, sep) : 'custom';
    (acc[key] ??= []).push(t);
    return acc;
  }, {} as Record<string, string[]>);

import { useThemeTokens } from '../../../theme/useThemeTokens';
import type { ApiErrorLike } from '../../../types/errors';

export const ToolSettingsPage: React.FC = () => {
  const { tokens } = useThemeTokens();
  const { projectSlug } = useParams({ from: '/$projectSlug/settings/tool-settings' });
  const [tabValue, setTabValue] = useState(0);
  const [editingFile, setEditingFile] = useState<{ key: string; name: string } | null>(null);
  const [expandedGroup, setExpandedGroup] = useState<string | false>(false);
  const [fileContent, setFileContent] = useState('');
  const [snackbar, setSnackbar] = useState<{ open: boolean; message: string; severity: 'success' | 'error' }>({
    open: false,
    message: '',
    severity: 'success'
  });

  const { data: toolSettings, isLoading } = useToolSettings(projectSlug);
  const updateConfig = useUpdateToolConfig(projectSlug);
  const uploadFiles = useUploadToolFiles(projectSlug);

  const handleTabChange = (event: React.SyntheticEvent, newValue: number) => {
    setTabValue(newValue);
    setEditingFile(null);
  };

  const handleEditConfig = (key: string, name: string) => {
    setEditingFile({ key, name });
    setFileContent('Loading...');
    fetchToolFileContent(key)
      .then(res => {
        if (res.status) setFileContent(res.content);
        else setFileContent('Error loading file content');
      })
      .catch(() => setFileContent('Failed to fetch file content'));
  };

  const handleEditGF = (patternName: string) => {
    setEditingFile({ key: 'gf_pattern', name: patternName });
    setFileContent('Loading...');
    fetchToolFileContent('gf_pattern', patternName)
      .then(res => {
        if (res.status) setFileContent(res.content);
        else setFileContent('Error loading GF pattern');
      })
      .catch(() => setFileContent('Failed to fetch GF pattern'));
  };

  const handleViewNucleiTemplate = (templateName: string) => {
    setEditingFile({ key: 'nuclei_template', name: templateName });
    setFileContent('Loading...');
    fetchToolFileContent('nuclei_template', templateName)
      .then(res => {
        if (res.status) setFileContent(res.content);
        else setFileContent('Error loading template');
      })
      .catch(() => setFileContent('Failed to fetch template'));
  };

  const handleSaveConfig = () => {
    if (!editingFile) return;

    // Map the key back to the form field name expected by the backend
    let postKey = '';
    if (editingFile.key === 'nuclei_config') postKey = 'nuclei_config_text_area';
    else if (editingFile.key === 'subfinder_config') postKey = 'subfinder_config_text_area';
    else if (editingFile.key === 'naabu_config') postKey = 'naabu_config_text_area';
    else if (editingFile.key === 'amass_config') postKey = 'amass_config_text_area';
    else if (editingFile.key === 'theharvester_config') postKey = 'theharvester_config_text_area';
    else if (editingFile.key === 'spiderfoot_config') postKey = 'spiderfoot_config_text_area';

    if (postKey) {
      updateConfig.mutate({ key: postKey, content: fileContent }, {
        onSuccess: (data) => {
          setSnackbar({ open: true, message: data.message || 'Config updated successfully', severity: 'success' });
          setEditingFile(null);
        },
        onError: () => {
          setSnackbar({ open: true, message: 'Failed to update config', severity: 'error' });
        }
      });
    }
  };

  const handleFileUpload = (key: string, e: React.ChangeEvent<HTMLInputElement>) => {
    if (e.target.files && e.target.files.length > 0) {
      const files = Array.from(e.target.files);
      uploadFiles.mutate({ key, files }, {
        onSuccess: (data) => {
          setSnackbar({ open: true, message: data.message, severity: 'success' });
        },
        onError: (caught) => {
          const error = caught as ApiErrorLike;
          setSnackbar({ open: true, message: error?.response?.data?.message || 'Upload failed', severity: 'error' });
        }
      });
    }
  };

  if (isLoading) {
    return (
      <Box sx={{ display: 'flex', justifyContent: 'center', p: 10 }}>
        <CircularProgress sx={{ color: tokens.accent.primary }} />
      </Box>
    );
  }

  const configFiles = [
    { key: 'nuclei_config', name: 'Nuclei Config', icon: <Shield size={20} /> },
    { key: 'subfinder_config', name: 'Subfinder Config', icon: <Search size={20} /> },
    { key: 'naabu_config', name: 'Naabu Config', icon: <Zap size={20} /> },
    { key: 'amass_config', name: 'Amass Config', icon: <FileText size={20} /> },
    { key: 'theharvester_config', name: 'theHarvester Config', icon: <Search size={20} /> },
    { key: 'spiderfoot_config', name: 'SpiderFoot Config', icon: <Settings size={20} /> },
  ];

  return (
    <Box sx={{ p: 3 }}>
      <Box sx={{ mb: 4 }}>
        <Typography variant="h4" sx={{ fontFamily: 'Orbitron', fontWeight: 900, color: 'text.primary', mb: 1 }}>
          TOOL SETTINGS
        </Typography>
        <Typography variant="body2" sx={{ color: 'text.secondary' }}>
          Manage configuration files, GF patterns, and Nuclei templates.
        </Typography>
      </Box>

      <TacticalPanel title="CONFIGURATION PANEL" sx={{ width: '100%' }}>
        <Box sx={{ borderBottom: 1, borderColor: 'divider' }}>
          <Tabs
            value={tabValue}
            onChange={handleTabChange}
            sx={{
              '& .MuiTabs-indicator': { bgcolor: tokens.accent.primary },
              '& .MuiTab-root': {
                color: 'text.secondary',
                fontFamily: 'Orbitron',
                fontSize: '12px',
                '&.Mui-selected': { color: tokens.accent.primary }
              }
            }}
          >
            <Tab label="GF PATTERNS" />
            <Tab label="NUCLEI TEMPLATES" />
            <Tab label="CONFIG FILES" />
          </Tabs>
        </Box>

        <TabPanel value={tabValue} index={0}>
          <Grid container spacing={2}>
            <Grid size={{ xs: 12, md: 3 }} >
              <Paper sx={{ bgcolor: 'background.paper', p: 2, border: 1, borderColor: 'divider', width: '100%' }}>
                <Typography variant="h6" sx={{ color: tokens.accent.primary, fontFamily: 'Orbitron', fontSize: '14px', mb: 2 }}>
                  UPLOAD GF PATTERNS
                </Typography>
                <input
                  accept=".json"
                  style={{ display: 'none' }}
                  id="gf-upload"
                  multiple
                  type="file"
                  onChange={(e) => handleFileUpload('gfFileUpload', e)}
                />
                <label htmlFor="gf-upload">
                  <Button
                    variant="outlined"
                    component="span"
                    fullWidth
                    startIcon={<Upload size={18} />}
                    sx={{
                      borderColor: tokens.accent.primary,
                      color: tokens.accent.primary,
                      '&:hover': { bgcolor: `${tokens.accent.primary}1A`, borderColor: tokens.accent.primary }
                    }}
                  >
                    SELECT JSON FILES
                  </Button>
                </label>
                <Typography variant="caption" sx={{ color: 'text.disabled', mt: 1, display: 'block' }}>
                  Upload multiple .json patterns for GF
                </Typography>
              </Paper>

              <Box sx={{ mt: 3 }}>
                <Typography variant="subtitle2" sx={{ color: 'text.secondary', mb: 1 }}>
                  INSTALLED PATTERNS ({toolSettings?.gf_patterns.length})
                </Typography>
                <Paper sx={{
                  bgcolor: 'action.hover',
                  maxHeight: '400px',
                  overflow: 'auto',
                  border: 1, borderColor: 'divider',
                  width: '100%'
                }}>
                  <List dense>
                    {toolSettings?.gf_patterns.map((pattern) => (
                      <ListItem
                        key={pattern}
                        disablePadding
                        sx={{
                          borderBottom: 1, borderColor: 'divider'
                        }}
                      >
                        <ListItemButton
                          onClick={() => handleEditGF(pattern)}
                          sx={{
                            '&:hover': { bgcolor: 'action.selected' },
                          }}
                        >
                          <ListItemText
                            primary={pattern}
                            slotProps={{
                              primary: { sx: { color: 'text.primary', fontSize: '13px' } }
                            }}
                          />
                          <ChevronRight size={14} color="rgba(255,255,255,0.3)" />
                        </ListItemButton>
                      </ListItem>
                    ))}
                  </List>
                </Paper>
              </Box>
            </Grid>

            <Grid size={{ xs: 12, md: 9 }} >
              {editingFile && editingFile.key === 'gf_pattern' ? (
                <Paper sx={{ bgcolor: 'background.paper', p: 2, border: 1, borderColor: 'divider', width: '100%' }}>
                  <Box sx={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', mb: 2 }}>
                    <Typography sx={{ color: tokens.accent.primary, fontFamily: 'Orbitron', fontSize: '14px' }}>
                      EDITING: {editingFile.name}
                    </Typography>
                    <Box>
                      <Button
                        size="small"
                        variant="contained"
                        startIcon={<Save size={16} />}
                        onClick={handleSaveConfig}
                        disabled={updateConfig.isPending}
                        sx={{ bgcolor: tokens.accent.primary, color: '#000', fontWeight: 'bold', '&:hover': { bgcolor: tokens.accent.primary, filter: 'brightness(1.1)' } }}
                      >
                        SAVE
                      </Button>
                      <Button
                        size="small"
                        sx={{ color: 'text.secondary', ml: 1 }}
                        onClick={() => setEditingFile(null)}
                      >
                        CANCEL
                      </Button>
                    </Box>
                  </Box>
                  <TextField
                    multiline
                    fullWidth
                    rows={20}
                    value={fileContent}
                    onChange={(e) => setFileContent(e.target.value)}
                    variant="standard"
                    slotProps={{
                      input: {
                        disableUnderline: true,
                        sx: {
                          fontFamily: 'monospace',
                          color: '#a9b7c6',
                          bgcolor: '#1e1e1e',
                          p: 2,
                          fontSize: '13px',
                          border: 1, borderColor: 'divider'
                        }
                      }
                    }}
                  />
                  <Alert severity="warning" sx={{ mt: 2, bgcolor: 'rgba(255,152,0,0.1)', color: '#ff9800' }}>
                    Manually editing GF patterns is experimental. Ensure the JSON structure is valid.
                  </Alert>
                </Paper>
              ) : (
                <Box sx={{
                  height: '100%',
                  display: 'flex',
                  flexDirection: 'column',
                  alignItems: 'center',
                  justifyContent: 'center',
                  bgcolor: 'action.hover',
                  borderRadius: 1,
                  p: 5,
                  border: 1, borderStyle: 'dashed', borderColor: 'divider'
                }}>
                  <Code size={48} color={`${tokens.accent.primary}33`} />
                  <Typography sx={{ color: 'text.disabled', mt: 2, fontFamily: 'Orbitron', fontSize: '12px' }}>
                    SELECT A PATTERN TO VIEW OR EDIT
                  </Typography>
                </Box>
              )}
            </Grid>
          </Grid>
        </TabPanel>

        <TabPanel value={tabValue} index={1}>
          <Box sx={{ display: 'flex', gap: 2, width: '100%', alignItems: 'flex-start' }}>
            <Box sx={{ width: '300px', flexShrink: 0 }}>
              <Paper sx={{ bgcolor: 'background.paper', p: 2, border: 1, borderColor: 'divider', mb: 2 }}>
                <Typography variant="h6" sx={{ color: tokens.accent.primary, fontFamily: 'Orbitron', fontSize: '14px', mb: 2 }}>
                  UPLOAD NUCLEI TEMPLATES
                </Typography>
                <input
                  accept=".yaml,.yml"
                  style={{ display: 'none' }}
                  id="nuclei-upload"
                  multiple
                  type="file"
                  onChange={(e) => handleFileUpload('nucleiFileUpload', e)}
                />
                <label htmlFor="nuclei-upload">
                  <Button
                    variant="outlined"
                    component="span"
                    fullWidth
                    startIcon={<Upload size={18} />}
                    sx={{
                      borderColor: tokens.accent.primary,
                      color: tokens.accent.primary,
                      '&:hover': { bgcolor: `${tokens.accent.primary}1A`, borderColor: tokens.accent.primary }
                    }}
                  >
                    SELECT YAML FILES
                  </Button>
                </label>
              </Paper>

              <Typography variant="subtitle2" sx={{ color: 'text.secondary', mb: 1, fontFamily: 'Orbitron', fontSize: '11px' }}>
                CUSTOM TEMPLATES ({toolSettings?.nuclei_templates?.length || 0})
              </Typography>
              <Box sx={{ maxHeight: '500px', overflow: 'auto', border: 1, borderColor: 'divider', borderRadius: 1 }}>
                {Object.entries(groupByDirectory(toolSettings?.nuclei_templates ?? [])).map(([group, templates]) => (
                  <Accordion
                    key={group}
                    expanded={expandedGroup === group}
                    onChange={(_, isOpen) => setExpandedGroup(isOpen ? group : false)}
                    disableGutters
                    sx={{
                      bgcolor: 'action.hover',
                      backgroundImage: 'none',
                      boxShadow: 'none',
                      borderBottom: 1, borderColor: 'divider',
                      '&:before': { display: 'none' },
                    }}
                  >
                    <AccordionSummary
                      expandIcon={<ChevronDown size={14} color={tokens.accent.primary} />}
                      sx={{
                        minHeight: 36,
                        px: 1.5,
                        bgcolor: expandedGroup === group ? 'action.selected' : 'transparent',
                        '& .MuiAccordionSummary-content': { alignItems: 'center', gap: 1, my: 0.5 },
                      }}
                    >
                      {expandedGroup === group
                        ? <FolderOpen size={14} color={tokens.accent.primary} />
                        : <Folder size={14} color="rgba(255,255,255,0.4)" />
                      }
                      <Typography sx={{
                        color: expandedGroup === group ? tokens.accent.primary : 'text.secondary',
                        fontSize: '11px',
                        fontFamily: 'Orbitron',
                        fontWeight: 700,
                        textTransform: 'uppercase',
                        flex: 1,
                      }}>
                        {group}
                      </Typography>
                      <Chip
                        label={templates.length}
                        size="small"
                        sx={{
                          height: 16,
                          fontSize: '10px',
                          bgcolor: `${tokens.accent.primary}1A`,
                          color: tokens.accent.primary,
                          border: 1, borderColor: `${tokens.accent.primary}33`,
                          borderRadius: 1,
                          '& .MuiChip-label': { px: 0.75 }
                        }}
                      />
                    </AccordionSummary>
                    <AccordionDetails sx={{ p: 0 }}>
                      <List dense disablePadding>
                        {templates.map((template) => {
                          const filename = template.split('/').pop()!;
                          const isSelected = editingFile?.key === 'nuclei_template' && editingFile?.name === template;
                          return (
                            <ListItem key={template} disablePadding sx={{ borderBottom: 1, borderColor: 'divider' }}>
                              <ListItemButton
                                selected={isSelected}
                                onClick={() => handleViewNucleiTemplate(template)}
                                sx={{
                                  pl: 3.5,
                                  '&.Mui-selected': { bgcolor: `${tokens.accent.primary}1A`, borderLeft: `3px solid ${tokens.accent.primary}` },
                                  '&:hover': { bgcolor: 'action.hover' },
                                }}
                              >
                                <ListItemText
                                  primary={filename}
                                  slotProps={{
                                    primary: { sx: { color: isSelected ? tokens.accent.primary : 'text.primary', fontSize: '12px' } }
                                  }}
                                />
                              </ListItemButton>
                            </ListItem>
                          );
                        })}
                      </List>
                    </AccordionDetails>
                  </Accordion>
                ))}
              </Box>
            </Box>

            <Box sx={{ flexGrow: 1, minWidth: 0 }}>
              {editingFile && editingFile.key === 'nuclei_template' ? (
                <Paper sx={{ bgcolor: 'background.paper', p: 2, border: 1, borderColor: 'divider', width: '100%' }}>
                  <Box sx={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', mb: 2 }}>
                    <Typography sx={{ color: tokens.accent.primary, fontFamily: 'Orbitron', fontSize: '14px' }}>
                      {editingFile.name.split('/').pop()} (READ-ONLY)
                    </Typography>
                    <Box sx={{ display: 'flex', alignItems: 'center', gap: 1 }}>
                      <Shield size={16} color={tokens.accent.primary} />
                      <Typography sx={{ color: 'text.secondary', fontSize: '11px', fontFamily: 'Orbitron' }}>
                        TEMPLATES ARE VIEW-ONLY
                      </Typography>
                    </Box>
                  </Box>
                  <TextField
                    multiline
                    fullWidth
                    rows={28}
                    value={fileContent}
                    variant="standard"
                    slotProps={{
                      input: {
                        readOnly: true,
                        disableUnderline: true,
                        sx: {
                          fontFamily: 'monospace',
                          color: '#a9b7c6',
                          bgcolor: '#1e1e1e',
                          p: 2,
                          fontSize: '13px',
                          border: 1, borderColor: 'divider'
                        }
                      }
                    }}
                  />
                </Paper>
              ) : (
                <Box sx={{
                  height: '600px',
                  display: 'flex',
                  flexDirection: 'column',
                  alignItems: 'center',
                  justifyContent: 'center',
                  bgcolor: 'action.hover',
                  borderRadius: 1,
                  p: 5,
                  border: 1, borderStyle: 'dashed', borderColor: 'divider'
                }}>
                  <Shield size={48} color={`${tokens.accent.primary}33`} />
                  <Typography sx={{ color: 'text.disabled', mt: 2, fontFamily: 'Orbitron', fontSize: '12px', textAlign: 'center' }}>
                    SELECT A NUCLEI TEMPLATE TO VIEW CONTENT<br />
                    UPLOAD NEW ONES USING THE PANEL ON THE LEFT
                  </Typography>
                </Box>
              )}
            </Box>
          </Box>
        </TabPanel>

        <TabPanel value={tabValue} index={2}>
          <Box sx={{ display: 'flex', gap: 2, width: '100%', alignItems: 'flex-start' }}>
            <Box sx={{ width: '250px', flexShrink: 0 }}>
              <List sx={{ bgcolor: 'action.hover', borderRadius: 1 }}>
                {configFiles.map((file) => (
                  <ListItem
                    key={file.key}
                    disablePadding
                  >
                    <ListItemButton
                      selected={editingFile?.key === file.key}
                      onClick={() => handleEditConfig(file.key, file.name)}
                      sx={{
                        '&.Mui-selected': {
                          bgcolor: `${tokens.accent.primary}1A`,
                          borderLeft: `3px solid ${tokens.accent.primary}`
                        },
                        '&:hover': { bgcolor: 'action.selected' }
                      }}
                    >
                      <Box sx={{ mr: 2, color: editingFile?.key === file.key ? tokens.accent.primary : 'text.disabled' }}>
                        {file.icon}
                      </Box>
                      <ListItemText
                        primary={file.name}
                        slotProps={{
                          primary: {
                            sx: {
                              color: editingFile?.key === file.key ? tokens.accent.primary : 'text.secondary',
                              fontSize: '13px',
                              fontFamily: 'Orbitron'
                            }
                          }
                        }}
                      />
                    </ListItemButton>
                  </ListItem>
                ))}
              </List>
            </Box>

            <Box sx={{ flexGrow: 1, minWidth: 0 }}>
              {editingFile && editingFile.key !== 'gf_pattern' ? (
                <Paper sx={{ bgcolor: 'background.paper', p: 2, border: 1, borderColor: 'divider', width: '100%' }}>
                  <Box sx={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', mb: 2 }}>
                    <Typography sx={{ color: tokens.accent.primary, fontFamily: 'Orbitron', fontSize: '14px' }}>
                      {editingFile.name}
                    </Typography>
                    <Button
                      size="small"
                      variant="contained"
                      startIcon={<Save size={16} />}
                      onClick={handleSaveConfig}
                      disabled={updateConfig.isPending}
                      sx={{ bgcolor: tokens.accent.primary, color: '#000', fontWeight: 'bold', '&:hover': { bgcolor: tokens.accent.primary, filter: 'brightness(1.1)' } }}
                    >
                      UPDATE CONFIG
                    </Button>
                  </Box>
                  <TextField
                    multiline
                    fullWidth
                    rows={28}
                    value={fileContent}
                    onChange={(e) => setFileContent(e.target.value)}
                    variant="standard"
                    slotProps={{
                      input: {
                        disableUnderline: true,
                        sx: {
                          fontFamily: 'monospace',
                          color: '#a9b7c6',
                          bgcolor: '#1e1e1e',
                          p: 2,
                          fontSize: '13px',
                          border: 1, borderColor: 'divider'
                        }
                      }
                    }}
                  />
                </Paper>
              ) : (
                <Box sx={{
                  height: '400px',
                  display: 'flex',
                  flexDirection: 'column',
                  alignItems: 'center',
                  justifyContent: 'center',
                  bgcolor: 'action.hover',
                  borderRadius: 1,
                  p: 5,
                  border: 1, borderStyle: 'dashed', borderColor: 'divider'
                }}>
                  <Settings size={48} color={`${tokens.accent.primary}33`} />
                  <Typography sx={{ color: 'text.disabled', mt: 2, fontFamily: 'Orbitron', fontSize: '12px' }}>
                    SELECT A TOOL CONFIGURATION TO EDIT
                  </Typography>
                </Box>
              )}
            </Box>
          </Box>
        </TabPanel>
      </TacticalPanel>

      <Snackbar
        open={snackbar.open}
        autoHideDuration={6000}
        onClose={() => setSnackbar({ ...snackbar, open: false })}
      >
        <Alert
          onClose={() => setSnackbar({ ...snackbar, open: false })}
          severity={snackbar.severity}
          sx={{ width: '100%', bgcolor: snackbar.severity === 'success' ? '#1b5e20' : '#d32f2f', color: '#fff' }}
        >
          {snackbar.message}
        </Alert>
      </Snackbar>
    </Box>
  );
};
