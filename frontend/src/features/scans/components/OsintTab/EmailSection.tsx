import React, { useState } from 'react';
import Box from '@mui/material/Box';
import Button from '@mui/material/Button';
import Chip from '@mui/material/Chip';
import IconButton from '@mui/material/IconButton';
import Menu from '@mui/material/Menu';
import MenuItem from '@mui/material/MenuItem';
import ListItemIcon from '@mui/material/ListItemIcon';
import Table from '@mui/material/Table';
import TableBody from '@mui/material/TableBody';
import TableCell from '@mui/material/TableCell';
import TableContainer from '@mui/material/TableContainer';
import TableHead from '@mui/material/TableHead';
import TableRow from '@mui/material/TableRow';
import Tooltip from '@mui/material/Tooltip';
import Typography from '@mui/material/Typography';
import { Copy, Check, Key, Plus, Search, ChevronDown } from 'lucide-react';
import { useThemeTokens } from '../../../../theme/useThemeTokens';
import type { EmailRecord } from '../../api';
import { useEmailDiscoveryStore } from '../../../../store/emailDiscoveryStore';
import { EmailImportModal } from './EmailImportModal';
import { EmailDiscoveryModal } from './EmailDiscoveryModal';
import { TacticalPanel } from '../../../../components/TacticalPanel';

interface EmailSectionProps {
  emails: EmailRecord[];
  scanId: number;
  refetchEmails: () => void;
}

const SOURCE_LABELS: Record<string, { label: string; color: 'warning' | 'default' }> = {
  manual:    { label: 'MANUAL',    color: 'warning' },
  hunter:    { label: 'HUNTER',    color: 'default' },
  harvester: { label: 'HARVESTER', color: 'default' },
  phonebook: { label: 'PHONEBOOK', color: 'default' },
  pattern:   { label: 'PATTERN',   color: 'default' },
  crawled:   { label: 'CRAWLED',   color: 'default' },
};

export const EmailSection: React.FC<EmailSectionProps> = ({ emails, scanId, refetchEmails }) => {
  const { tokens } = useThemeTokens();
  const [actionsAnchor, setActionsAnchor] = useState<HTMLElement | null>(null);
  const [importOpen, setImportOpen] = useState(false);
  const [discoveryOpen, setDiscoveryOpen] = useState(false);
  const [copiedId, setCopiedId] = useState<string | null>(null);
  const running = useEmailDiscoveryStore((s) => s.running);

  const handleCopy = (text: string, id: string) => {
    navigator.clipboard.writeText(text);
    setCopiedId(id);
    setTimeout(() => setCopiedId(null), 2000);
  };

  const actionsMenu = (
    <Box sx={{ display: 'flex', alignItems: 'center', gap: 1 }}>
      <Button
        size="small"
        variant="outlined"
        endIcon={<ChevronDown size={14} />}
        onClick={(e) => setActionsAnchor(e.currentTarget)}
        sx={{ fontSize: '0.7rem', letterSpacing: '0.08em' }}
      >
        {running ? 'DISCOVERY RUNNING...' : 'ACTIONS'}
      </Button>
      <Menu
        anchorEl={actionsAnchor}
        open={Boolean(actionsAnchor)}
        onClose={() => setActionsAnchor(null)}
      >
        <MenuItem onClick={() => { setActionsAnchor(null); setImportOpen(true); }}>
          <ListItemIcon><Plus size={16} /></ListItemIcon>
          Add / Import Emails
        </MenuItem>
        <MenuItem
          onClick={() => { setActionsAnchor(null); setDiscoveryOpen(true); }}
          disabled={running}
        >
          <ListItemIcon><Search size={16} /></ListItemIcon>
          Discover Emails
        </MenuItem>
      </Menu>
    </Box>
  );

  return (
    <>
      <TacticalPanel
        title="Email Addresses"
        headerAction={actionsMenu}
      >
        {emails.length === 0 ? (
          <Typography variant="body2" sx={{ color: tokens.text.secondary, p: 2 }}>
            No email addresses discovered yet.
          </Typography>
        ) : (
          <TableContainer>
            <Table size="small">
              <TableHead>
                <TableRow>
                  <TableCell sx={{ color: 'text.secondary', fontWeight: 'bold' }}>ADDRESS</TableCell>
                  <TableCell sx={{ color: 'text.secondary', fontWeight: 'bold' }}>CREDENTIALS</TableCell>
                  <TableCell sx={{ display: { xs: 'none', md: 'table-cell' }, color: 'text.secondary', fontWeight: 'bold' }}>SOCIAL FOOTPRINT</TableCell>
                  <TableCell align="right" sx={{ color: 'text.secondary', fontWeight: 'bold' }}>ACTIONS</TableCell>
                </TableRow>
              </TableHead>
              <TableBody>
                {emails.map((email) => {
                  const srcInfo = SOURCE_LABELS[email.source] ?? null;
                  const holehe = (email.metadata?.holehe as string[] | undefined) ?? [];
                  return (
                    <TableRow key={email.id} hover>
                      <TableCell>
                        <Box sx={{ display: 'flex', alignItems: 'center', gap: 1 }}>
                          <Typography variant="body2" sx={{ fontFamily: 'monospace' }}>
                            {email.address}
                          </Typography>
                          {srcInfo && (
                            <Chip
                              label={srcInfo.label}
                              color={srcInfo.color}
                              size="small"
                              sx={{ fontSize: '0.6rem', height: 16 }}
                            />
                          )}
                        </Box>
                      </TableCell>
                      <TableCell>
                        {email.password ? (
                          <Box sx={{ display: 'flex', alignItems: 'center', gap: 1, color: 'error.main' }}>
                            <Key size={14} />
                            <Typography variant="body2" sx={{ fontFamily: 'monospace' }}>
                              {email.password}
                            </Typography>
                          </Box>
                        ) : (
                          <Typography variant="caption" sx={{ color: 'text.disabled', fontStyle: 'italic' }}>
                            No password found
                          </Typography>
                        )}
                      </TableCell>
                      <TableCell sx={{ display: { xs: 'none', md: 'table-cell' } }}>
                        <Box sx={{ display: 'flex', flexWrap: 'wrap', gap: 0.5 }}>
                          {holehe.map((site) => (
                            <Chip key={site} label={site} size="small" variant="outlined" />
                          ))}
                          {holehe.length === 0 && (
                            <Typography variant="caption" sx={{ color: 'text.disabled' }}>—</Typography>
                          )}
                        </Box>
                      </TableCell>
                      <TableCell align="right">
                        <Box sx={{ display: 'flex', justifyContent: 'flex-end', gap: 1 }}>
                          <Tooltip title={copiedId === `addr-${email.id}` ? 'Copied!' : 'Copy Address'}>
                            <IconButton
                              size="small"
                              onClick={() => handleCopy(email.address, `addr-${email.id}`)}
                              sx={{ color: copiedId === `addr-${email.id}` ? 'success.main' : 'inherit' }}
                            >
                              {copiedId === `addr-${email.id}` ? <Check size={14} /> : <Copy size={14} />}
                            </IconButton>
                          </Tooltip>
                          {email.password && (
                            <Tooltip title={copiedId === `pass-${email.id}` ? 'Copied!' : 'Copy Password'}>
                              <IconButton
                                size="small"
                                onClick={() => handleCopy(email.password!, `pass-${email.id}`)}
                                sx={{ color: copiedId === `pass-${email.id}` ? 'success.main' : 'inherit' }}
                              >
                                {copiedId === `pass-${email.id}` ? <Check size={14} /> : <Copy size={14} />}
                              </IconButton>
                            </Tooltip>
                          )}
                        </Box>
                      </TableCell>
                    </TableRow>
                  );
                })}
              </TableBody>
            </Table>
          </TableContainer>
        )}
      </TacticalPanel>

      <EmailImportModal
        open={importOpen}
        onClose={() => setImportOpen(false)}
        scanId={scanId}
        onSuccess={refetchEmails}
      />
      <EmailDiscoveryModal
        open={discoveryOpen}
        onClose={() => setDiscoveryOpen(false)}
        scanId={scanId}
        onComplete={refetchEmails}
      />
    </>
  );
};
