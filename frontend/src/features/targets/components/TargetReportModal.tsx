import React, { useState } from 'react';
import {
  Dialog,
  DialogTitle,
  DialogContent,
  DialogActions,
  Button,
  Box,
  Typography,
  Checkbox,
  IconButton,
  Stack,
  Divider,
  CircularProgress,
  FormControlLabel,
  useTheme,
  alpha,
  Chip,
} from '@mui/material';
import { X, FileText, Download, Shield, Clock } from 'lucide-react';
import { useThemeTokens } from '../../../theme/useThemeTokens';
import { getDialogPaperSx } from '../../../theme/semanticColors';
import { useTargetScans, useCreateTargetReport, fetchTargetReportStatus } from '../api';

const OPTIONAL_SECTIONS: { key: string; label: string }[] = [
  { key: 'subdomain_changes', label: 'Subdomain Changes' },
  { key: 'attack_surface_trend', label: 'Attack Surface Trend' },
  { key: 'exposures', label: 'Exposure Intelligence' },
  { key: 'certificates', label: 'Certificates' },
  { key: 'waf_info', label: 'WAF Detection' },
  { key: 'endpoints', label: 'Endpoints' },
  { key: 'directories', label: 'Directories' },
  { key: 's3_buckets', label: 'S3 Buckets' },
  { key: 'employees', label: 'Employees' },
  { key: 'email_breaches', label: 'Email Breaches' },
  { key: 'secret_findings', label: 'Secret Leaks' },
];

interface TargetReportModalProps {
  open: boolean;
  onClose: () => void;
  domainId: number;
  domainName: string;
}

export const TargetReportModal: React.FC<TargetReportModalProps> = ({
  open,
  onClose,
  domainId,
  domainName,
}) => {
  const { tokens } = useThemeTokens();
  const theme = useTheme();
  const isLight = tokens.mode === 'light';

  const { data: scans = [], isLoading: scansLoading } = useTargetScans(domainId);
  const createReport = useCreateTargetReport();

  const [selectedScanIds, setSelectedScanIds] = useState<Set<number>>(new Set());
  const [selectedSections, setSelectedSections] = useState<Set<string>>(new Set());
  const [isGenerating, setIsGenerating] = useState(false);
  const [statusMessage, setStatusMessage] = useState<string | null>(null);
  const [reportUrl, setReportUrl] = useState<string | null>(null);
  const [hasError, setHasError] = useState(false);

  const completedScans = scans.filter((s) => s.scan_status === 2);

  const toggleScan = (id: number) => {
    setSelectedScanIds((prev) => {
      const next = new Set(prev);
      next.has(id) ? next.delete(id) : next.add(id);
      return next;
    });
  };

  const toggleSection = (key: string) => {
    setSelectedSections((prev) => {
      const next = new Set(prev);
      next.has(key) ? next.delete(key) : next.add(key);
      return next;
    });
  };

  const pollStatus = (reportId: number) => {
    const check = async () => {
      try {
        const data = await fetchTargetReportStatus(reportId);
        if (data.status === 2) {
          setIsGenerating(false);
          setStatusMessage('Report generated successfully!');
          setReportUrl(data.report_url);
          if (data.report_url) {
            const win = window.open(data.report_url, '_blank');
            if (!win) setStatusMessage('Report ready — click Download below (popup was blocked).');
          }
        } else if (data.status === 0) {
          setIsGenerating(false);
          setHasError(true);
          setStatusMessage(`Error: ${data.error_message ?? 'Unknown error'}`);
        } else {
          setTimeout(check, 3000);
        }
      } catch {
        setIsGenerating(false);
        setHasError(true);
        setStatusMessage('Failed to check report status.');
      }
    };
    check();
  };

  const handleGenerate = async () => {
    setIsGenerating(true);
    setHasError(false);
    setStatusMessage('Initiating report generation…');
    setReportUrl(null);
    try {
      const data = await createReport.mutateAsync({
        domainId,
        scanIds: Array.from(selectedScanIds),
        includedSections: Array.from(selectedSections),
      });
      if (data.status && data.report_id) {
        setStatusMessage('Generating report — this may take a minute…');
        pollStatus(data.report_id);
      } else {
        throw new Error('Invalid server response');
      }
    } catch (err: any) {
      setIsGenerating(false);
      setHasError(true);
      setStatusMessage(err?.message ?? 'Failed to start report generation.');
    }
  };

  const handleClose = () => {
    if (isGenerating) return;
    setSelectedScanIds(new Set());
    setSelectedSections(new Set());
    setStatusMessage(null);
    setReportUrl(null);
    setHasError(false);
    onClose();
  };

  const canGenerate = selectedScanIds.size >= 2 && !isGenerating;

  const accentPrimary = tokens.accent.primary;
  const accentSuccess = tokens.accent.success;
  const accentError = tokens.accent.error;

  return (
    <Dialog
      open={open}
      onClose={isGenerating ? undefined : handleClose}
      maxWidth="sm"
      fullWidth
      slotProps={{
        paper: {
          sx: {
            ...getDialogPaperSx(isLight, theme, tokens),
            backgroundImage: isLight
              ? 'none'
              : `linear-gradient(${alpha(accentPrimary, 0.02)} 1px, transparent 1px), linear-gradient(90deg, ${alpha(accentPrimary, 0.02)} 1px, transparent 1px)`,
            backgroundSize: '20px 20px',
            border: `1px solid ${alpha(accentPrimary, 0.2)}`,
          },
        },
      }}
    >
      <DialogTitle
        sx={{
          m: 0, p: 2,
          bgcolor: alpha(accentPrimary, 0.05),
          borderBottom: `1px solid ${tokens.border.subtle}`,
          display: 'flex',
          alignItems: 'center',
          justifyContent: 'space-between',
        }}
      >
        <Stack direction="row" spacing={1.5} sx={{ alignItems: 'center' }}>
          <FileText size={20} color={accentPrimary} />
          <Box>
            <Typography sx={{ fontFamily: 'Orbitron', fontWeight: 900, fontSize: '0.95rem', letterSpacing: '0.08rem' }}>
              TARGET REPORT
            </Typography>
            <Typography sx={{ fontSize: '0.68rem', color: tokens.text.muted, mt: 0.2 }}>
              {domainName}
            </Typography>
          </Box>
        </Stack>
        {!isGenerating && (
          <IconButton onClick={handleClose} sx={{ color: tokens.text.muted, '&:hover': { color: accentError } }}>
            <X size={18} />
          </IconButton>
        )}
      </DialogTitle>

      <DialogContent sx={{ p: 3, mt: 1 }}>
        <Stack spacing={3}>
          {/* Status banner */}
          {statusMessage && (
            <Box sx={{
              p: 2,
              bgcolor: hasError
                ? alpha(accentError, 0.05)
                : reportUrl
                  ? alpha(accentSuccess, 0.05)
                  : alpha(accentPrimary, 0.05),
              border: `1px solid ${hasError ? alpha(accentError, 0.25) : reportUrl ? alpha(accentSuccess, 0.25) : alpha(accentPrimary, 0.2)}`,
              borderRadius: 1,
              display: 'flex',
              alignItems: 'center',
              gap: 1.5,
            }}>
              {isGenerating && <CircularProgress size={18} sx={{ color: accentPrimary, flexShrink: 0 }} />}
              {!isGenerating && reportUrl && <Shield size={18} color={accentSuccess} style={{ flexShrink: 0 }} />}
              <Typography sx={{
                fontSize: '0.78rem',
                fontWeight: 700,
                fontFamily: 'Orbitron',
                color: hasError ? accentError : reportUrl ? accentSuccess : accentPrimary,
              }}>
                {statusMessage}
              </Typography>
            </Box>
          )}

          {/* Scan selector */}
          <Box sx={{ opacity: isGenerating ? 0.5 : 1, pointerEvents: isGenerating ? 'none' : 'auto' }}>
            <Typography sx={{
              color: accentPrimary,
              fontFamily: 'Orbitron',
              fontSize: '0.72rem',
              fontWeight: 800,
              mb: 1.5,
              display: 'flex',
              alignItems: 'center',
              gap: 1,
            }}>
              <Clock size={13} /> SELECT SCANS (minimum 2)
            </Typography>

            {scansLoading ? (
              <Box sx={{ display: 'flex', justifyContent: 'center', py: 2 }}>
                <CircularProgress size={22} sx={{ color: accentPrimary }} />
              </Box>
            ) : completedScans.length === 0 ? (
              <Typography sx={{ fontSize: '0.8rem', color: tokens.text.muted }}>
                No completed scans found for this target.
              </Typography>
            ) : (
              <Box sx={{
                border: `1px solid ${alpha(accentPrimary, 0.15)}`,
                borderRadius: 1,
                maxHeight: 220,
                overflowY: 'auto',
              }}>
                {completedScans.map((scan, idx) => (
                  <Box
                    key={scan.id}
                    onClick={() => toggleScan(scan.id)}
                    sx={{
                      display: 'flex',
                      alignItems: 'center',
                      gap: 1,
                      px: 2,
                      py: 1,
                      cursor: 'pointer',
                      borderBottom: idx < completedScans.length - 1 ? `1px solid ${alpha(accentPrimary, 0.08)}` : 'none',
                      bgcolor: selectedScanIds.has(scan.id) ? alpha(accentPrimary, 0.06) : 'transparent',
                      '&:hover': { bgcolor: alpha(accentPrimary, 0.04) },
                    }}
                  >
                    <Checkbox
                      checked={selectedScanIds.has(scan.id)}
                      size="small"
                      sx={{ p: 0.5, color: alpha(accentPrimary, 0.3), '&.Mui-checked': { color: accentPrimary } }}
                      onClick={(e) => e.stopPropagation()}
                      onChange={() => toggleScan(scan.id)}
                    />
                    <Box sx={{ flex: 1 }}>
                      <Typography sx={{ fontSize: '0.8rem', fontWeight: 600, color: tokens.text.primary }}>
                        {new Date(scan.start_scan_date).toLocaleDateString('en-GB', {
                          day: '2-digit', month: 'short', year: 'numeric', hour: '2-digit', minute: '2-digit',
                        })}
                      </Typography>
                    </Box>
                    {selectedScanIds.has(scan.id) && (
                      <Chip
                        label={`#${Array.from(selectedScanIds).indexOf(scan.id) + 1}`}
                        size="small"
                        sx={{
                          height: 18,
                          fontSize: '0.62rem',
                          fontWeight: 700,
                          bgcolor: alpha(accentPrimary, 0.15),
                          color: accentPrimary,
                          border: `1px solid ${alpha(accentPrimary, 0.3)}`,
                        }}
                      />
                    )}
                  </Box>
                ))}
              </Box>
            )}
            {selectedScanIds.size === 1 && (
              <Typography sx={{ fontSize: '0.7rem', color: tokens.text.muted, mt: 0.75 }}>
                Select at least one more scan to enable report generation.
              </Typography>
            )}
          </Box>

          <Divider sx={{ borderColor: tokens.border.subtle }} />

          {/* Optional sections */}
          <Box sx={{ opacity: isGenerating ? 0.5 : 1, pointerEvents: isGenerating ? 'none' : 'auto' }}>
            <Box sx={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', mb: 1.5 }}>
              <Typography sx={{
                color: accentPrimary,
                fontFamily: 'Orbitron',
                fontSize: '0.72rem',
                fontWeight: 800,
                display: 'flex',
                alignItems: 'center',
                gap: 1,
              }}>
                <Shield size={13} /> OPTIONAL SECTIONS
              </Typography>
              <Button
                size="small"
                onClick={() =>
                  setSelectedSections(
                    selectedSections.size === OPTIONAL_SECTIONS.length
                      ? new Set()
                      : new Set(OPTIONAL_SECTIONS.map((s) => s.key))
                  )
                }
                sx={{
                  fontSize: '0.62rem',
                  fontFamily: 'Orbitron',
                  fontWeight: 700,
                  color: accentPrimary,
                  minWidth: 0,
                  px: 1,
                  py: 0.25,
                  border: `1px solid ${alpha(accentPrimary, 0.25)}`,
                  '&:hover': { bgcolor: alpha(accentPrimary, 0.06) },
                }}
              >
                {selectedSections.size === OPTIONAL_SECTIONS.length ? 'CLEAR ALL' : 'SELECT ALL'}
              </Button>
            </Box>
            <Box sx={{ display: 'grid', gridTemplateColumns: '1fr 1fr', columnGap: 2, rowGap: 0.5 }}>
              {OPTIONAL_SECTIONS.map((sec) => (
                <FormControlLabel
                  key={sec.key}
                  control={
                    <Checkbox
                      checked={selectedSections.has(sec.key)}
                      onChange={() => toggleSection(sec.key)}
                      size="small"
                      sx={{ color: alpha(accentPrimary, 0.25), '&.Mui-checked': { color: accentPrimary }, py: 0.5 }}
                    />
                  }
                  label={
                    <Typography sx={{ fontSize: '0.75rem', color: tokens.text.secondary }}>
                      {sec.label}
                    </Typography>
                  }
                />
              ))}
            </Box>
          </Box>
        </Stack>
      </DialogContent>

      <DialogActions sx={{ p: 2.5, bgcolor: alpha(accentPrimary, 0.01), borderTop: `1px solid ${tokens.border.subtle}` }}>
        <Button
          onClick={handleClose}
          disabled={isGenerating}
          sx={{
            color: tokens.text.secondary,
            fontFamily: 'Orbitron',
            fontWeight: 800,
            fontSize: '0.68rem',
            mr: 'auto',
            '&:hover': { color: tokens.text.primary },
          }}
        >
          CANCEL
        </Button>

        {reportUrl ? (
          <Button
            href={reportUrl}
            target="_blank"
            variant="contained"
            startIcon={<Download size={15} />}
            sx={{
              bgcolor: accentSuccess,
              color: theme.palette.getContrastText(accentSuccess),
              fontFamily: 'Orbitron',
              fontWeight: 900,
              fontSize: '0.72rem',
              px: 3,
              '&:hover': { bgcolor: alpha(accentSuccess, 0.85) },
            }}
          >
            DOWNLOAD REPORT
          </Button>
        ) : (
          <Button
            onClick={handleGenerate}
            disabled={!canGenerate}
            variant="contained"
            startIcon={
              isGenerating
                ? <CircularProgress size={15} sx={{ color: 'inherit' }} />
                : <Download size={15} />
            }
            sx={{
              bgcolor: accentPrimary,
              color: theme.palette.getContrastText(accentPrimary),
              fontFamily: 'Orbitron',
              fontWeight: 900,
              fontSize: '0.72rem',
              px: 3,
              '&:hover': { bgcolor: alpha(accentPrimary, 0.85) },
              '&.Mui-disabled': {
                bgcolor: alpha(accentPrimary, 0.12),
                color: alpha(accentPrimary, 0.4),
              },
            }}
          >
            {isGenerating ? 'GENERATING…' : 'GENERATE REPORT'}
          </Button>
        )}
      </DialogActions>
    </Dialog>
  );
};
