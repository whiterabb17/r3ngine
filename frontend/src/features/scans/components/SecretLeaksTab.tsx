import React from 'react';
import {
  Box,
  Typography,
  Table,
  TableBody,
  TableCell,
  TableContainer,
  TableHead,
  TableRow,
  TablePagination,
  Chip,
  CircularProgress,
  Stack,
  Tooltip,
  IconButton,
  TextField,
  Button,
  Grid,
  Card,
  CardContent,
  Collapse,
} from '@mui/material';
import { Shield, ExternalLink, Copy, AlertTriangle, Fingerprint, Mail, ShieldAlert, ChevronDown, ChevronUp } from 'lucide-react';
import { useSecretLeaks, useScanSummary, useEmailBreaches, useCheckEmailBreach } from '../api';
import { TacticalPanel } from '../../../components/TacticalPanel';
import { useThemeTokens } from '../../../theme/useThemeTokens';
import { formatSecretType, getSecretCategory } from '../utils/secretTypeUtils';
import type { SecretLeak } from '../types';

interface SecretLeaksTabProps {
  projectSlug: string;
  scanId: number;
}

interface LeakGroup {
  key: string;
  secret_type: string;
  source_url: string;
  tool_name: string;
  status: string;
  matches: Array<{ id: number; match_content: string }>;
}

const CATEGORY_COLORS: Record<string, string> = {
  error: '#ff003c',
  warning: '#ff9f00',
  info: '#00d4ff',
  default: '#6b7280',
};

function groupLeaks(leaks: SecretLeak[]): LeakGroup[] {
  const map = new Map<string, LeakGroup>();
  for (const leak of leaks) {
    const key = `${leak.secret_type}||${leak.source_url}`;
    if (!map.has(key)) {
      map.set(key, {
        key,
        secret_type: leak.secret_type,
        source_url: leak.source_url,
        tool_name: leak.tool_name,
        status: leak.status,
        matches: [],
      });
    }
    map.get(key)!.matches.push({ id: leak.id, match_content: leak.match_content });
  }
  return Array.from(map.values()).sort((a, b) => b.matches.length - a.matches.length);
}

export const SecretLeaksTab: React.FC<SecretLeaksTabProps> = ({ projectSlug, scanId }) => {
  const { tokens } = useThemeTokens();
  const { data: leaks, isLoading } = useSecretLeaks(projectSlug, scanId);
  const { data: summary, refetch: refetchSummary } = useScanSummary(projectSlug, scanId);
  const { data: emailBreaches, refetch: refetchBreaches } = useEmailBreaches(scanId);
  const checkEmailMutation = useCheckEmailBreach();

  const [manualEmail, setManualEmail] = React.useState('');
  const [checkingEmails, setCheckingEmails] = React.useState<Record<string, boolean>>({});
  const [leaksPage, setLeaksPage] = React.useState(0);
  const [leaksRowsPerPage, setLeaksRowsPerPage] = React.useState(10);
  const [expandedKeys, setExpandedKeys] = React.useState<Set<string>>(new Set());

  const emails = summary?.emails || [];

  const groups = React.useMemo(() => groupLeaks(leaks || []), [leaks]);
  const pagedGroups = groups.slice(leaksPage * leaksRowsPerPage, leaksPage * leaksRowsPerPage + leaksRowsPerPage);

  const toggleExpand = (key: string) => {
    setExpandedKeys(prev => {
      const next = new Set(prev);
      next.has(key) ? next.delete(key) : next.add(key);
      return next;
    });
  };

  const handleManualCheck = async (emailAddress: string) => {
    if (!emailAddress) return;
    setCheckingEmails(prev => ({ ...prev, [emailAddress]: true }));
    try {
      await checkEmailMutation.mutateAsync({ emailAddress, scanId });
      refetchSummary();
      refetchBreaches();
    } catch (err) {
      console.error('Failed to check breach:', err);
    } finally {
      setCheckingEmails(prev => ({ ...prev, [emailAddress]: false }));
    }
  };

  const handleAddAndScan = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!manualEmail.trim()) return;
    const targetEmail = manualEmail.trim();
    setManualEmail('');
    await handleManualCheck(targetEmail);
  };

  const getStatusColor = (status: string) => {
    switch (status) {
      case 'verified': return '#00ff62';
      case 'unverified': return '#ff9f00';
      case 'false_positive': return '#ff003c';
      default: return '#fff';
    }
  };

  if (isLoading) {
    return (
      <Box sx={{ display: 'flex', justifyContent: 'center', p: 8 }}>
        <CircularProgress sx={{ color: tokens.accent.primary }} />
      </Box>
    );
  }

  return (
    <Box sx={{ width: '100%' }}>
      <Box sx={{ mb: 4, mt: 2 }}>
        <Typography variant="h5" sx={{ fontWeight: 900, fontFamily: 'Orbitron', letterSpacing: 3, color: 'text.primary', textTransform: 'uppercase' }}>
          Leaks & Secrets
        </Typography>
        <Typography sx={{ fontSize: '12px', color: 'text.secondary', mt: 0.5, letterSpacing: 1 }}>
          V3.0 CREDENTIAL INTELLIGENCE REPORT
        </Typography>
      </Box>

      <TacticalPanel title="SENSITIVE FINDINGS" icon={<Shield size={14} />}>
        <TableContainer>
          <Table size="small">
            <TableHead>
              <TableRow sx={{ '& th': { borderBottom: '2px solid #7000ff', bgcolor: 'action.hover', color: tokens.accent.primary, fontSize: '0.7rem', fontWeight: 900, py: 2 } }}>
                <TableCell sx={{ color: tokens.accent.primary, fontSize: '10px', fontWeight: 900, fontFamily: 'Orbitron', width: 32 }} />
                <TableCell sx={{ color: tokens.accent.primary, fontSize: '10px', fontWeight: 900, fontFamily: 'Orbitron' }}>TOOL</TableCell>
                <TableCell sx={{ color: tokens.accent.primary, fontSize: '10px', fontWeight: 900, fontFamily: 'Orbitron' }}>TYPE</TableCell>
                <TableCell sx={{ color: tokens.accent.primary, fontSize: '10px', fontWeight: 900, fontFamily: 'Orbitron' }}>COUNT</TableCell>
                <TableCell sx={{ display: { xs: 'none', md: 'table-cell' }, color: tokens.accent.primary, fontSize: '10px', fontWeight: 900, fontFamily: 'Orbitron' }}>SOURCE</TableCell>
                <TableCell sx={{ display: { xs: 'none', sm: 'table-cell' }, color: tokens.accent.primary, fontSize: '10px', fontWeight: 900, fontFamily: 'Orbitron' }}>STATUS</TableCell>
              </TableRow>
            </TableHead>
            <TableBody>
              {pagedGroups.map((group) => {
                const label = formatSecretType(group.secret_type);
                const category = getSecretCategory(label);
                const isExpanded = expandedKeys.has(group.key);
                const catColor = CATEGORY_COLORS[category.colorKey] || CATEGORY_COLORS.default;

                return (
                  <React.Fragment key={group.key}>
                    <TableRow
                      onClick={() => toggleExpand(group.key)}
                      sx={{ cursor: 'pointer', '& td': { borderBottom: 1, borderColor: 'divider', py: 1.5 }, '&:hover': { bgcolor: 'action.hover' } }}
                    >
                      <TableCell sx={{ pl: 1, pr: 0 }}>
                        {isExpanded ? <ChevronUp size={14} color={tokens.accent.primary} /> : <ChevronDown size={14} color={tokens.text.muted} />}
                      </TableCell>
                      <TableCell>
                        <Chip label={group.tool_name} size="small" sx={{ bgcolor: 'rgba(112,0,255,0.1)', color: '#7000ff', fontWeight: 800, fontSize: '0.65rem', border: '1px solid rgba(112,0,255,0.2)' }} />
                      </TableCell>
                      <TableCell>
                        <Stack direction="row" spacing={1} sx={{ alignItems: 'center', flexWrap: 'wrap', gap: 0.5 }}>
                          <Typography sx={{ fontSize: '0.75rem', fontWeight: 700, color: 'text.primary' }}>
                            {label}
                          </Typography>
                          <Chip
                            label={category.label}
                            size="small"
                            sx={{
                              bgcolor: `${catColor}18`,
                              color: catColor,
                              fontWeight: 800,
                              fontSize: '0.6rem',
                              border: `1px solid ${catColor}30`,
                              height: 18,
                              borderRadius: 0.5,
                            }}
                          />
                        </Stack>
                      </TableCell>
                      <TableCell>
                        <Chip
                          label={`${group.matches.length}×`}
                          size="small"
                          sx={{ bgcolor: 'rgba(0,0,0,0.2)', color: 'text.secondary', fontWeight: 700, fontSize: '0.65rem', height: 18 }}
                        />
                      </TableCell>
                      <TableCell sx={{ display: { xs: 'none', md: 'table-cell' } }}>
                        <Stack direction="row" sx={{ alignItems: 'center' }} spacing={1}>
                          <Typography sx={{ fontSize: '0.7rem', color: 'text.secondary', maxWidth: '200px', overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>
                            {group.source_url}
                          </Typography>
                          <IconButton size="small" component="a" href={/^https?:\/\//i.test(group.source_url) ? group.source_url : '#'} target="_blank" sx={{ color: tokens.accent.primary, p: 0.5 }} onClick={e => e.stopPropagation()}>
                            <ExternalLink size={12} />
                          </IconButton>
                        </Stack>
                      </TableCell>
                      <TableCell sx={{ display: { xs: 'none', sm: 'table-cell' } }}>
                        <Box sx={{ display: 'inline-flex', px: 1, py: 0.2, borderRadius: 0.5, bgcolor: `${getStatusColor(group.status)}10`, border: `1px solid ${getStatusColor(group.status)}30`, color: getStatusColor(group.status), fontSize: '0.65rem', fontWeight: 900, textTransform: 'uppercase' }}>
                          {group.status}
                        </Box>
                      </TableCell>
                    </TableRow>

                    <TableRow>
                      <TableCell colSpan={6} sx={{ p: 0, border: 0 }}>
                        <Collapse in={isExpanded} unmountOnExit>
                          <Box sx={{ p: 2, bgcolor: 'rgba(0,0,0,0.15)', borderBottom: '1px solid', borderColor: 'divider' }}>
                            <Typography sx={{ fontSize: '0.65rem', fontWeight: 800, color: tokens.accent.primary, mb: 1, fontFamily: 'Orbitron' }}>
                              MATCHED CONTENT ({group.matches.length})
                            </Typography>
                            <Stack spacing={0.75}>
                              {group.matches.map((m) => (
                                <Box key={m.id} sx={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', p: 1, bgcolor: 'rgba(0,0,0,0.3)', border: 1, borderColor: 'divider', borderRadius: 0.5 }}>
                                  <Typography sx={{ fontSize: '0.7rem', fontFamily: 'monospace', color: '#00ff62', overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap', flex: 1 }}>
                                    {m.match_content}
                                  </Typography>
                                  <IconButton
                                    size="small"
                                    sx={{ color: 'text.disabled', p: 0.2, ml: 1, flexShrink: 0 }}
                                    onClick={(e) => { e.stopPropagation(); navigator.clipboard.writeText(m.match_content); }}
                                  >
                                    <Copy size={12} />
                                  </IconButton>
                                </Box>
                              ))}
                            </Stack>
                          </Box>
                        </Collapse>
                      </TableCell>
                    </TableRow>
                  </React.Fragment>
                );
              })}

              {groups.length === 0 && (
                <TableRow>
                  <TableCell colSpan={6} align="center" sx={{ py: 8 }}>
                    <Box sx={{ opacity: 0.3 }}>
                      <AlertTriangle size={32} style={{ marginBottom: '8px' }} />
                      <Typography sx={{ fontSize: '0.8rem', fontWeight: 700 }}>NO SECRETS OR LEAKS DETECTED</Typography>
                    </Box>
                  </TableCell>
                </TableRow>
              )}
            </TableBody>
          </Table>
        </TableContainer>

        {groups.length > 0 && (
          <TablePagination
            component="div"
            count={groups.length}
            page={leaksPage}
            rowsPerPage={leaksRowsPerPage}
            rowsPerPageOptions={[10, 25, 50]}
            onPageChange={(_e, newPage) => setLeaksPage(newPage)}
            onRowsPerPageChange={(e) => { setLeaksRowsPerPage(parseInt(e.target.value, 10)); setLeaksPage(0); }}
            sx={{ borderTop: '1px solid', borderColor: 'divider', color: 'text.secondary', fontSize: '0.7rem', '& .MuiTablePagination-selectLabel, & .MuiTablePagination-displayedRows': { fontSize: '0.7rem' }, '& .MuiTablePagination-select': { fontSize: '0.7rem' } }}
          />
        )}
      </TacticalPanel>

      {/* --- Email sections below unchanged --- */}
      <Box sx={{ mt: 4 }}>
        <Grid container spacing={3}>
          <Grid size={{ xs: 12, md: 4 }}>
            <TacticalPanel title="MANUAL EMAIL AUDIT" icon={<Mail size={14} />}>
              <Box component="form" onSubmit={handleAddAndScan} sx={{ p: 2, display: 'flex', flexDirection: 'column', gap: 2 }}>
                <Typography variant="caption" sx={{ color: 'text.secondary' }}>
                  Audit individual email addresses for third-party security breaches.
                </Typography>
                <TextField
                  fullWidth size="small" label="Email Address" placeholder="e.g. user@target.com"
                  value={manualEmail} onChange={(e) => setManualEmail(e.target.value)}
                  sx={{ '& .MuiInputBase-input': { fontSize: '0.8rem', fontFamily: 'monospace' }, '& .MuiInputLabel-root': { fontSize: '0.8rem' } }}
                />
                <Button fullWidth type="submit" variant="contained" disabled={checkEmailMutation.isPending}
                  sx={{ bgcolor: tokens.accent.primary, color: '#fff', fontWeight: 800, fontFamily: 'Orbitron', fontSize: '0.75rem', '&:hover': { bgcolor: 'rgba(112,0,255,0.8)' } }}>
                  {checkEmailMutation.isPending ? 'CHECKING...' : 'ADD & CHECK'}
                </Button>
              </Box>
            </TacticalPanel>
          </Grid>

          <Grid size={{ xs: 12, md: 8 }}>
            <TacticalPanel title="EMAIL BREACH COVERAGE" icon={<ShieldAlert size={14} />}>
              <TableContainer sx={{ maxHeight: '280px' }}>
                <Table size="small" stickyHeader>
                  <TableHead>
                    <TableRow sx={{ '& th': { borderBottom: '2px solid #7000ff', bgcolor: 'action.hover', color: tokens.accent.primary, fontSize: '0.7rem', fontWeight: 900, py: 1 } }}>
                      <TableCell sx={{ color: tokens.accent.primary, fontSize: '10px', fontWeight: 900, fontFamily: 'Orbitron' }}>EMAIL ADDRESS</TableCell>
                      <TableCell sx={{ color: tokens.accent.primary, fontSize: '10px', fontWeight: 900, fontFamily: 'Orbitron' }}>STATUS</TableCell>
                      <TableCell align="right" sx={{ color: tokens.accent.primary, fontSize: '10px', fontWeight: 900, fontFamily: 'Orbitron' }}>ACTIONS</TableCell>
                    </TableRow>
                  </TableHead>
                  <TableBody>
                    {emails?.map((email: any) => {
                      const matchedBreaches = emailBreaches?.filter((b: any) => b.email_address === email.address) || [];
                      const isChecking = checkingEmails[email.address];
                      return (
                        <TableRow key={email.id} sx={{ '& td': { py: 1 } }}>
                          <TableCell sx={{ fontFamily: 'monospace', fontSize: '0.75rem', fontWeight: 700 }}>{email.address}</TableCell>
                          <TableCell>
                            {isChecking ? (
                              <Stack direction="row" spacing={1} sx={{ alignItems: 'center' }}>
                                <CircularProgress size={10} sx={{ color: tokens.accent.primary }} />
                                <Typography sx={{ fontSize: '0.65rem', color: 'text.secondary' }}>CHECKING HIBP...</Typography>
                              </Stack>
                            ) : matchedBreaches.length > 0 ? (
                              <Chip label={`${matchedBreaches.length} BREACHES`} size="small" sx={{ bgcolor: 'rgba(255,0,60,0.1)', color: '#ff003c', fontWeight: 900, fontSize: '0.6rem', border: '1px solid rgba(255,0,60,0.2)' }} />
                            ) : (
                              <Chip label="CLEAN" size="small" sx={{ bgcolor: 'rgba(0,255,98,0.1)', color: '#00ff62', fontWeight: 900, fontSize: '0.6rem', border: '1px solid rgba(0,255,98,0.2)' }} />
                            )}
                          </TableCell>
                          <TableCell align="right">
                            <Tooltip title="Run HIBP Audit">
                              <IconButton size="small" disabled={isChecking} onClick={() => handleManualCheck(email.address)} sx={{ color: tokens.accent.primary }}>
                                <Fingerprint size={12} />
                              </IconButton>
                            </Tooltip>
                          </TableCell>
                        </TableRow>
                      );
                    })}
                    {(!emails || emails.length === 0) && (
                      <TableRow>
                        <TableCell colSpan={3} align="center" sx={{ py: 4 }}>
                          <Typography sx={{ fontSize: '0.7rem', color: 'text.secondary' }}>NO EMAIL ADDRESSES ASSOCIATED WITH THIS SCAN</Typography>
                        </TableCell>
                      </TableRow>
                    )}
                  </TableBody>
                </Table>
              </TableContainer>
            </TacticalPanel>
          </Grid>
        </Grid>
      </Box>

      {emailBreaches && emailBreaches.length > 0 && (
        <Box sx={{ mt: 4 }}>
          <Box sx={{ mb: 2 }}>
            <Typography variant="h6" sx={{ fontWeight: 800, fontFamily: 'Orbitron', letterSpacing: 2, color: 'text.primary', fontSize: '1rem' }}>
              IDENTIFIED THIRD-PARTY BREACHES
            </Typography>
            <Typography sx={{ fontSize: '10px', color: 'text.secondary' }}>SOURCE: HAVEIBEENPWNED DATABASE AUDIT</Typography>
          </Box>
          <Grid container spacing={2}>
            {emailBreaches.map((breach: any) => (
              <Grid size={{ xs: 12, sm: 6 }} key={breach.id}>
                <Card sx={{ bgcolor: 'background.paper', border: `1px solid ${tokens.border.subtle}`, borderRadius: 1, '&:hover': { borderColor: tokens.border.strong, boxShadow: 2 } }}>
                  <CardContent sx={{ p: 2.5, '&:last-child': { pb: 2.5 } }}>
                    <Stack direction="row" sx={{ justifyContent: 'space-between', alignItems: 'flex-start', mb: 1.5 }}>
                      <Box>
                        <Typography variant="subtitle2" sx={{ fontWeight: 800, color: tokens.accent.primary }}>{breach.breach_name}</Typography>
                        <Typography sx={{ fontSize: '0.65rem', fontFamily: 'monospace', color: 'text.secondary' }}>Target: {breach.email_address}</Typography>
                      </Box>
                      <Chip label={breach.breach_date || 'Unknown Date'} size="small" sx={{ bgcolor: 'action.hover', color: 'text.primary', fontSize: '0.65rem', fontWeight: 700 }} />
                    </Stack>
                    <Typography sx={{ fontSize: '0.75rem', color: 'text.secondary', mb: 2, lineHeight: 1.4 }}>{breach.description}</Typography>
                    <Box sx={{ mb: 2 }}>
                      <Typography sx={{ fontSize: '10px', fontWeight: 800, color: 'text.primary', mb: 0.5, letterSpacing: 0.5 }}>COMPROMISED DATA:</Typography>
                      <Stack direction="row" sx={{ flexWrap: 'wrap', gap: 0.5 }}>
                        {breach.compromised_data?.map((dataClass: string) => (
                          <Chip key={dataClass} label={dataClass} size="small" sx={{ bgcolor: 'rgba(112,0,255,0.05)', color: 'text.primary', fontSize: '0.6rem', fontWeight: 600, height: '18px', borderRadius: 0.5 }} />
                        ))}
                      </Stack>
                    </Box>
                    <Button size="small" variant="outlined" component="a"
                      href={`https://haveibeenpwned.com/Breach/${encodeURIComponent(breach.breach_name)}`}
                      target="_blank" endIcon={<ExternalLink size={10} />}
                      sx={{ fontSize: '0.65rem', fontWeight: 900, fontFamily: 'Orbitron', color: tokens.accent.primary, borderColor: 'rgba(112,0,255,0.3)', '&:hover': { borderColor: tokens.accent.primary, bgcolor: 'rgba(112,0,255,0.05)' } }}>
                      View Details
                    </Button>
                  </CardContent>
                </Card>
              </Grid>
            ))}
          </Grid>
        </Box>
      )}
    </Box>
  );
};
