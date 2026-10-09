import React, { useState, useMemo } from 'react';
import {
  Box,
  Typography,
  Grid,
  Card,
  CardContent,
  Avatar,
  Chip,
  Stack,
  TextField,
  InputAdornment,
  IconButton,
  Button,
  FormControl,
  Select,
  MenuItem,
  Checkbox,
  FormControlLabel,
  Dialog,
  DialogTitle,
  DialogContent,
  DialogActions,
  Accordion,
  AccordionSummary,
  AccordionDetails,
  CircularProgress,
  Tooltip,
  Snackbar,
  Divider,
  Alert
} from '@mui/material';
import { PageHeader } from '../../../components/PageHeader';
import {
  Search,
  Filter,
  ArrowUpDown,
  ExternalLink,
  Info,
  Bookmark,
  CheckCircle2,
  XCircle,
  DownloadCloud,
  Globe,
  PlusCircle,
  Folder,
  Zap,
  ChevronDown,
  ChevronRight,
  TrendingUp,
  DollarSign,
  Flag
} from 'lucide-react';
import { useParams } from '@tanstack/react-router';
import { useBountyPrograms, useProgramDetails, useImportPrograms } from '../api';
import { useAddTarget } from '../../targets/api';
import { formatDistanceToNow, subMonths } from 'date-fns';
import type { StructuredScope } from '../types';
import { useThemeTokens } from '../../../theme/useThemeTokens';
import { getSafeUrl } from '../../../utils/securityUtils';
import type { ApiErrorLike } from '../../../types/errors';
import type { ResolvedThemeTokens } from '../../../theme/tokens';

const getProgramCardStyle = (tokens: ResolvedThemeTokens) => ({
  bgcolor: 'action.hover',
  border: 1, borderColor: 'divider',
  transition: 'all 0.3s cubic-bezier(0.4, 0, 0.2, 1)',
  cursor: 'pointer',
  position: 'relative',
  overflow: 'hidden',
  height: '100%',
  '&:hover': {
    border: `1px solid ${tokens.accent.primary}4D`,
    boxShadow: `0 0 20px ${tokens.accent.primary}1A`,
    transform: 'translateY(-4px)'
  },
  '&.selected': {
    border: `1px solid ${tokens.accent.primary}`,
    bgcolor: `${tokens.accent.primary}0D`,
    boxShadow: `0 0 25px ${tokens.accent.primary}33`,
  }
});

export const BountyHubPage: React.FC = () => {
  const { tokens, theme, isLight } = useThemeTokens();
  const { projectSlug } = useParams({ strict: false });
  const [searchTerm, setSearchTerm] = useState('');
  const [filterType, setFilterType] = useState('All');
  const [showClosed, setShowClosed] = useState(false);
  const [showBookmarked, setShowBookmarked] = useState(false);
  const [sortBy, setSortBy] = useState('age-desc');
  const [selectedHandles, setSelectedHandles] = useState<string[]>([]);
  const [detailHandle, setDetailHandle] = useState<string | null>(null);
  const [snackbar, setSnackbar] = useState<{ open: boolean; message: string; severity: 'success' | 'error' | 'info' }>({
    open: false,
    message: '',
    severity: 'success'
  });

  const handleCloseSnackbar = () => setSnackbar(prev => ({ ...prev, open: false }));

  const [sortKey, sortOrder] = sortBy.split('-');
  const { data: programs, isLoading, error } = useBountyPrograms({
    sort_by: sortKey,
    sort_order: sortOrder,
    bookmarked: showBookmarked
  });

  const { data: details, isLoading: isLoadingDetails } = useProgramDetails(detailHandle);
  const importMutation = useImportPrograms();
  const addTargetMutation = useAddTarget(projectSlug || 'default');

  const groupedAssets = useMemo(() => {
    if (!details) return {};
    const grouped: Record<string, StructuredScope[]> = {};
    details.relationships.structured_scopes.data.forEach(scope => {
      if (scope.attributes.eligible_for_submission) {
        const type = scope.attributes.asset_type;
        if (!grouped[type]) grouped[type] = [];
        grouped[type].push(scope);
      }
    });
    return grouped;
  }, [details]);

  const filteredPrograms = useMemo(() => {
    if (!programs) return [];
    return programs.filter(p => {
      const matchesSearch = p.attributes.name.toLowerCase().includes(searchTerm.toLowerCase()) ||
        p.attributes.handle.toLowerCase().includes(searchTerm.toLowerCase());

      const matchesFilter = filterType === 'All' ||
        (filterType === 'Bounty Eligible' && p.attributes.offers_bounties) ||
        (filterType === 'VDP' && !p.attributes.offers_bounties) ||
        (filterType === 'Private Programs' && p.attributes.state === 'private_mode');

      const matchesClosed = showClosed || p.attributes.submission_state === 'open';

      return matchesSearch && matchesFilter && matchesClosed;
    });
  }, [programs, searchTerm, filterType, showClosed]);

  const toggleSelection = (handle: string) => {
    setSelectedHandles(prev =>
      prev.includes(handle) ? prev.filter(h => h !== handle) : [...prev, handle]
    );
  };

  const handleImport = async () => {
    if (selectedHandles.length === 0 || !projectSlug) return;
    try {
      await importMutation.mutateAsync({ handles: selectedHandles, projectSlug });
      setSelectedHandles([]);
      setSnackbar({
        open: true,
        message: `Import process started for ${selectedHandles.length} programs.`,
        severity: 'success'
      });
    } catch (caught) {
      const err = caught as ApiErrorLike;
      setSnackbar({
        open: true,
        message: err?.message || 'Import initiation failed.',
        severity: 'error'
      });
    }
  };

  const handleAddTarget = async (asset: string, programName: string) => {
    if (!projectSlug) return;
    try {
      await addTargetMutation.mutateAsync({
        domain_name: asset,
        slug: projectSlug,
      });
      setSnackbar({
        open: true,
        message: `Added target: ${asset}`,
        severity: 'success'
      });
    } catch (caught) {
      const err = caught as ApiErrorLike;
      setSnackbar({
        open: true,
        message: err?.message || 'Failed to add target.',
        severity: 'error'
      });
    }
  };

  return (
    <Box sx={{ p: 4, bgcolor: 'background.default', minHeight: '100vh' }}>
      {/* Header */}
      <Stack direction="row" sx={{ justifyContent: "space-between", alignItems: "flex-start", mb: 0 }}>
        <PageHeader
          title="BOUNTY HUB"
          subtitle="INTEGRATED VULNERABILITY RESOURCES V3"
        />
        <Stack direction="row" spacing={2} sx={{ pt: 0.5 }}>
          {/* Action buttons removed from header to match legacy floating container if selected */}
          <Typography variant="caption" sx={{ color: isLight ? theme.palette.text.secondary : 'rgba(255,255,255,0.3)', alignSelf: 'center', fontFamily: 'Orbitron' }}>
            {programs?.length || 0} PROGRAMS SYNCED
          </Typography>
        </Stack>
      </Stack>

      {/* Filters Bar */}
      <Box sx={{
        p: 2,
        bgcolor: isLight ? theme.palette.background.paper : 'rgba(255,255,255,0.02)',
        border: `1px solid ${isLight ? theme.palette.divider : 'rgba(255,255,255,0.05)'}`,
        boxShadow: isLight ? '0 1px 3px rgba(0,0,0,0.08)' : 'none',
        borderRadius: 2,
        mb: 4
      }}>
        <Grid container spacing={2} sx={{ alignItems: 'center' }}>
          <Grid size={{ xs: 12, md: 4 }}>
            <TextField
              fullWidth
              placeholder="Search programs..."
              value={searchTerm}
              onChange={(e) => setSearchTerm(e.target.value)}
              slotProps={{
                input: {
                  startAdornment: <Search size={18} style={{ color: isLight ? theme.palette.text.secondary : 'rgba(255,255,255,0.3)', marginRight: 8 }} />
                }
              }}
              sx={{ '& .MuiOutlinedInput-root': { bgcolor: isLight ? 'transparent' : 'rgba(255,255,255,0.01)' } }}
            />
          </Grid>
          <Grid size={{ xs: 12, md: 2 }}>
            <FormControl fullWidth size="small">
              <Select
                value={filterType}
                onChange={(e) => setFilterType(e.target.value)}
                sx={{ color: isLight ? theme.palette.text.primary : '#fff', bgcolor: isLight ? 'transparent' : 'rgba(255,255,255,0.01)' }}
              >
                <MenuItem value="All">All Types</MenuItem>
                <MenuItem value="Bounty Eligible">Bounty Eligible</MenuItem>
                <MenuItem value="VDP">VDP Only</MenuItem>
                <MenuItem value="Private Programs">Private Only</MenuItem>
              </Select>
            </FormControl>
          </Grid>
          <Grid size={{ xs: 12, md: 2 }}>
            <FormControl fullWidth size="small">
              <Select
                value={sortBy}
                onChange={(e) => setSortBy(e.target.value)}
                sx={{ color: isLight ? theme.palette.text.primary : '#fff', bgcolor: isLight ? 'transparent' : 'rgba(255,255,255,0.01)' }}
              >
                <MenuItem value="age-desc">Most Recent</MenuItem>
                <MenuItem value="age-asc">Least Recent</MenuItem>
                <MenuItem value="name-asc">Name (A-Z)</MenuItem>
                <MenuItem value="name-desc">Name (Z-A)</MenuItem>
                <MenuItem value="reports-desc">Most Reports</MenuItem>
                <MenuItem value="reports-asc">Least Reports</MenuItem>
              </Select>
            </FormControl>
          </Grid>
          <Grid size={{ xs: 12, md: 4 }}>
            <Stack direction="row" spacing={2} sx={{ justifyContent: "flex-end" }}>
              <FormControlLabel
                control={<Checkbox checked={showClosed} onChange={(e) => setShowClosed(e.target.checked)} />}
                label={<Typography variant="body2" sx={{ color: 'text.secondary' }}>Show Closed</Typography>}
              />
              <FormControlLabel
                control={<Checkbox checked={showBookmarked} onChange={(e) => setShowBookmarked(e.target.checked)} />}
                label={<Typography variant="body2" sx={{ color: 'text.secondary' }}>Bookmarked</Typography>}
              />
            </Stack>
          </Grid>
        </Grid>
      </Box>

      {/* Grid */}
      {isLoading ? (
        <Box sx={{ display: 'flex', justifyContent: 'center', py: 10 }}>
          <CircularProgress sx={{ color: tokens.accent.primary }} />
        </Box>
      ) : error ? (
        <Alert severity="error" sx={{ bgcolor: 'rgba(211, 47, 47, 0.1)', color: '#ff5252' }}>
          Failed to load programs. Ensure HackerOne API keys are configured.
        </Alert>
      ) : (
        <Grid container spacing={3}>
          {filteredPrograms.map((p) => (
            <Grid size={{ xs: 12, sm: 6, md: 4, lg: 3 }} key={p.id}>
              <Card
                className={selectedHandles.includes(p.attributes.handle) ? 'selected' : ''}
                sx={getProgramCardStyle(tokens)}
                onClick={() => toggleSelection(p.attributes.handle)}
              >
                <CardContent sx={{ p: 2, '&:last-child': { pb: 2 } }}>
                  <Stack direction="row" spacing={2} sx={{ mb: 2 }}>
                    <Avatar
                      src={getSafeUrl(p.attributes.profile_picture)}
                      variant="rounded"
                      sx={{ width: 48, height: 48, border: '1px solid rgba(255,255,255,0.1)' }}
                    />
                    <Box sx={{ minWidth: 0 }}>
                      <Typography variant="subtitle1" noWrap sx={{ color: 'text.primary', fontWeight: 600 }}>
                        {p.attributes.name}
                        {p.attributes.bookmarked && <Bookmark size={14} fill={tokens.accent.primary} color={tokens.accent.primary} style={{ marginLeft: 6 }} />}
                      </Typography>
                      <Typography variant="caption" sx={{ color: tokens.accent.primary, display: 'flex', alignItems: 'center', gap: 0.5, opacity: 0.7 }}>
                        @{p.attributes.handle}
                        <ExternalLink size={10} />
                      </Typography>
                    </Box>
                  </Stack>

                  <Stack direction="row" spacing={1} sx={{ mb: 2, flexWrap: 'wrap', gap: 0.5 }}>
                    <Chip
                      label={p.attributes.submission_state === 'open' ? 'OPEN' : 'CLOSED'}
                      size="small"
                      sx={{
                        height: 18, fontSize: '0.65rem', fontWeight: 900,
                        bgcolor: p.attributes.submission_state === 'open' ? 'rgba(0, 255, 0, 0.1)' : 'rgba(255, 0, 0, 0.1)',
                        color: p.attributes.submission_state === 'open' ? '#00ff00' : '#ff5252',
                        border: `1px solid ${p.attributes.submission_state === 'open' ? 'rgba(0, 255, 0, 0.2)' : 'rgba(255, 0, 0, 0.2)'}`
                      }}
                    />
                    <Chip
                      label={p.attributes.state === 'public_mode' ? 'PUBLIC' : 'PRIVATE'}
                      size="small"
                      sx={{ height: 18, fontSize: '0.65rem', fontWeight: 900, bgcolor: 'action.hover', color: 'text.secondary' }}
                    />
                    {p.attributes.offers_bounties ? (
                      <Chip label="BOUNTY" size="small" sx={{ height: 18, fontSize: '0.65rem', fontWeight: 900, bgcolor: `${tokens.accent.primary}1A`, color: tokens.accent.primary }} />
                    ) : (
                      <Chip label="VDP" size="small" sx={{ height: 18, fontSize: '0.65rem', fontWeight: 900, bgcolor: 'rgba(255, 152, 0, 0.1)', color: '#ff9800' }} />
                    )}
                    {p.attributes.open_scope && (
                      <Chip label="OPEN SCOPE" size="small" sx={{ height: 18, fontSize: '0.65rem', fontWeight: 900, bgcolor: 'rgba(76, 175, 80, 0.1)', color: '#4caf50' }} />
                    )}
                    {new Date(p.attributes.started_accepting_at) > subMonths(new Date(), 3) && (
                      <Chip icon={<Zap size={10} />} label="NEW" size="small" sx={{ height: 18, fontSize: '0.65rem', fontWeight: 900, bgcolor: `${tokens.accent.primary}1A`, color: tokens.accent.primary, '& .MuiChip-icon': { color: tokens.accent.primary } }} />
                    )}
                  </Stack>

                  <Grid container spacing={1} sx={{ mb: 2 }}>
                    <Grid size={{ xs: 6 }}>
                      <Stack direction="row" spacing={1} sx={{ alignItems: "center" }}>
                        <Flag size={12} color="rgba(255,255,255,0.4)" />
                        <Typography variant="caption" sx={{ color: 'text.secondary' }}>
                          Reports: {p.attributes.number_of_reports_for_user}
                        </Typography>
                      </Stack>
                    </Grid>
                    <Grid size={{ xs: 6 }}>
                      <Stack direction="row" spacing={1} sx={{ alignItems: "center" }}>
                        <DollarSign size={12} color="rgba(255,255,255,0.4)" />
                        <Typography variant="caption" sx={{ color: 'text.secondary' }}>
                          Earnings: ${p.attributes.bounty_earned_for_user.toFixed(0)}
                        </Typography>
                      </Stack>
                    </Grid>
                  </Grid>

                  <Divider sx={{ mb: 1.5, borderColor: 'divider' }} />

                  <Stack direction="row" sx={{ justifyContent: "space-between", color: 'text.disabled', mb: 1.5 }}>
                    <Typography variant="caption" sx={{ display: 'flex', alignItems: 'center', gap: 0.5 }}>
                      Since {new Date(p.attributes.started_accepting_at).toLocaleDateString('en-US', { month: 'short', year: 'numeric' })}
                    </Typography>
                    <Typography variant="caption" sx={{ fontWeight: 900 }}>
                      {p.attributes.currency.toUpperCase()}
                    </Typography>
                  </Stack>

                  <Button
                    fullWidth
                    size="small"
                    startIcon={<Info size={14} />}
                    onClick={(e) => {
                      e.stopPropagation();
                      setDetailHandle(p.attributes.handle);
                    }}
                    sx={{ color: 'text.secondary', '&:hover': { bgcolor: 'action.hover' } }}
                  >
                    SEE DETAILS
                  </Button>
                </CardContent>
              </Card>
            </Grid>
          ))}
        </Grid>
      )}

      {/* Floating Action Container */}
      {selectedHandles.length > 0 && (
        <Box sx={{
          position: 'fixed',
          bottom: 32,
          left: '50%',
          transform: 'translateX(-50%)',
          zIndex: 1000,
          bgcolor: 'background.paper',
          border: 1, borderColor: tokens.accent.primary,
          p: 1.5,
          borderRadius: 2,
          display: 'flex',
          alignItems: 'center',
          gap: 3,
          boxShadow: `0 0 30px ${tokens.accent.primary}33`,
          backdropFilter: 'blur(10px)'
        }}>
          <Button
            variant="contained"
            onClick={handleImport}
            disabled={importMutation.isPending}
            startIcon={importMutation.isPending ? <CircularProgress size={16} color="inherit" /> : <DownloadCloud size={18} />}
            sx={{
              bgcolor: tokens.accent.primary,
              color: '#000',
              fontFamily: 'Orbitron',
              fontWeight: 900,
              '&:hover': { bgcolor: tokens.accent.primary, filter: 'brightness(1.1)' }
            }}
          >
            {importMutation.isPending ? 'IMPORTING...' : `IMPORT ${selectedHandles.length} PROGRAM${selectedHandles.length !== 1 ? 'S' : ''}`}
          </Button>
          <Button
            variant="text"
            onClick={() => setSelectedHandles([])}
            sx={{ color: 'text.secondary', fontFamily: 'Orbitron', fontSize: '0.7rem', fontWeight: 800 }}
          >
            CLEAR ALL <XCircle size={14} style={{ marginLeft: 8 }} />
          </Button>
        </Box>
      )}

      {/* Details Dialog */}
      <Dialog
        open={!!detailHandle}
        onClose={() => setDetailHandle(null)}
        maxWidth="md"
        fullWidth
        slotProps={{
          paper: {
            sx: { bgcolor: 'background.default', border: '1px solid rgba(255,255,255,0.1)', backgroundImage: 'none' }
          }
        }}
      >
        {isLoadingDetails ? (
          <Box sx={{ p: 4, textAlign: 'center' }}><CircularProgress /></Box>
        ) : details && (
          <>
            <DialogTitle sx={{ p: 3, borderBottom: 1, borderColor: 'divider' }}>
              <Stack direction="row" spacing={2} sx={{ alignItems: "center" }}>
                <Avatar src={getSafeUrl(details.attributes.profile_picture)} sx={{ width: 40, height: 40 }} />
                <Box>
                  <Typography variant="h6" sx={{ color: 'text.primary', fontFamily: 'Orbitron' }}>{details.attributes.name}</Typography>
                  <Typography variant="caption" sx={{ color: tokens.accent.primary }}>@{details.attributes.handle}</Typography>
                </Box>
              </Stack>
            </DialogTitle>
            <DialogContent sx={{ p: 3 }}>
              <Grid container spacing={4}>
                <Grid size={{ xs: 12, md: 7 }}>
                  <Typography variant="subtitle2" sx={{ color: tokens.accent.primary, mb: 2, letterSpacing: 1, opacity: 0.7 }}>ASSETS ON SCOPE</Typography>
                  <Box sx={{ maxHeight: 400, overflowY: 'auto', pr: 1 }}>
                    {Object.keys(groupedAssets).length > 0 ? (
                      Object.entries(groupedAssets).map(([type, assets]) => (
                        <Accordion key={type} sx={{
                          bgcolor: 'transparent',
                          backgroundImage: 'none',
                          border: 1, borderColor: 'divider',
                          mb: 1,
                          '&:before': { display: 'none' }
                        }}>
                          <AccordionSummary expandIcon={<ChevronDown color="rgba(255,255,255,0.3)" size={18} />}>
                            <Stack direction="row" spacing={1.5} sx={{ alignItems: "center" }}>
                              <Folder size={16} color={tokens.accent.primary} />
                              <Typography variant="body2" sx={{ fontWeight: 800, color: 'text.primary', fontFamily: 'Orbitron' }}>
                                {type}S <Typography component="span" variant="caption" sx={{ color: tokens.accent.primary, ml: 1, opacity: 0.5 }}>({assets.length})</Typography>
                              </Typography>
                            </Stack>
                          </AccordionSummary>
                          <AccordionDetails sx={{ pt: 0 }}>
                            <Stack spacing={1}>
                              {assets.map((scope) => (
                                <Box key={scope.id} sx={{
                                  p: 1.5,
                                  bgcolor: 'action.hover',
                                  border: 1, borderColor: 'divider',
                                  borderRadius: 1,
                                  display: 'flex',
                                  justifyContent: 'space-between',
                                  alignItems: 'center',
                                  '&:hover': { bgcolor: 'action.hover' }
                                }}>
                                  <Box sx={{ minWidth: 0, flexGrow: 1, mr: 2 }}>
                                    <Typography variant="body2" noWrap sx={{ color: 'text.primary', fontWeight: 600 }}>{scope.attributes.asset_identifier}</Typography>
                                    <Typography variant="caption" sx={{ color: 'text.disabled' }}>{scope.attributes.asset_type}</Typography>
                                  </Box>
                                  <Button
                                    size="small"
                                    variant="text"
                                    startIcon={<PlusCircle size={14} />}
                                    onClick={() => handleAddTarget(scope.attributes.asset_identifier, details.attributes.name)}
                                    disabled={addTargetMutation.isPending}
                                    sx={{ color: tokens.accent.primary, minWidth: 'auto', '&:hover': { bgcolor: `${tokens.accent.primary}1A` } }}
                                  >
                                    ADD
                                  </Button>
                                </Box>
                              ))}
                            </Stack>
                          </AccordionDetails>
                        </Accordion>
                      ))
                    ) : (
                      <Typography variant="body2" sx={{ color: 'text.disabled' }}>No structured scope found.</Typography>
                    )}
                  </Box>
                </Grid>
                <Grid size={{ xs: 12, md: 5 }}>
                  <Stack spacing={3}>
                    <Box>
                      <Typography variant="subtitle2" sx={{ color: tokens.accent.primary, mb: 1.5, letterSpacing: 1, opacity: 0.7 }}>STATS</Typography>
                      <Grid container spacing={2}>
                        <Grid size={{ xs: 6 }}>
                          <Box sx={{ p: 2, bgcolor: 'action.hover', borderRadius: 1, textAlign: 'center' }}>
                            <Typography variant="h5" sx={{ color: 'text.primary', fontWeight: 900 }}>{details.attributes.number_of_reports_for_user || 0}</Typography>
                            <Typography variant="caption" sx={{ color: 'text.disabled' }}>REPORTS</Typography>
                          </Box>
                        </Grid>
                        <Grid size={{ xs: 6 }}>
                          <Box sx={{ p: 2, bgcolor: 'action.hover', borderRadius: 1, textAlign: 'center' }}>
                            <Typography variant="h5" sx={{ color: 'text.primary', fontWeight: 900 }}>${(details.attributes.bounty_earned_for_user || 0).toFixed(0)}</Typography>
                            <Typography variant="caption" sx={{ color: 'text.disabled' }}>EARNED</Typography>
                          </Box>
                        </Grid>
                      </Grid>
                    </Box>
                    <Box>
                      <Typography variant="subtitle2" sx={{ color: tokens.accent.primary, mb: 1.5, letterSpacing: 1, opacity: 0.7 }}>PROGRAM INFO</Typography>
                      <Stack spacing={1}>
                        <Typography variant="body2" sx={{ color: 'text.secondary', display: 'flex', alignItems: 'center', gap: 1 }}>
                          <CheckCircle2 size={14} color="#00ff00" /> Active since {new Date(details.attributes.started_accepting_at).toLocaleDateString()}
                        </Typography>
                        <Typography variant="body2" sx={{ color: 'text.secondary', display: 'flex', alignItems: 'center', gap: 1 }}>
                          <Zap size={14} color={tokens.accent.primary} /> {details.attributes.currency.toUpperCase()} Currency
                        </Typography>
                      </Stack>
                    </Box>
                  </Stack>
                </Grid>
              </Grid>
            </DialogContent>
            <DialogActions sx={{ p: 3, borderTop: 1, borderColor: 'divider' }}>
              <Button onClick={() => setDetailHandle(null)} sx={{ color: 'text.secondary' }}>CLOSE</Button>
              <Button
                variant="contained"
                startIcon={<DownloadCloud size={16} />}
                onClick={() => {
                  toggleSelection(details.attributes.handle);
                  setDetailHandle(null);
                }}
                sx={{ bgcolor: tokens.accent.primary, color: '#000', fontWeight: 900, fontFamily: 'Orbitron' }}
              >
                SELECT FOR IMPORT
              </Button>
            </DialogActions>
          </>
        )}
      </Dialog>

      <Snackbar
        open={snackbar.open}
        autoHideDuration={5000}
        onClose={handleCloseSnackbar}
        anchorOrigin={{ vertical: 'bottom', horizontal: 'right' }}
      >
        <Alert
          onClose={handleCloseSnackbar}
          severity={snackbar.severity}
          variant="filled"
          sx={{
            fontFamily: 'Orbitron',
            fontSize: '0.8rem',
            fontWeight: 700,
            bgcolor: snackbar.severity === 'success' ? `${tokens.accent.primary}E6` :
              snackbar.severity === 'error' ? 'rgba(255, 0, 85, 0.9)' : `${tokens.accent.primary}80`,
            color: '#000',
            border: 1, borderColor: 'divider',
            '& .MuiAlert-icon': { color: '#000' }
          }}
        >
          {snackbar.message}
        </Alert>
      </Snackbar>
    </Box>
  );
};
