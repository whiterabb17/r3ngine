import React, { useState, useEffect } from 'react';
import {
  Box,
  Typography,
  Grid,
  Button,
  Stack,
  TextField,
  Switch,
  FormControlLabel,
  CircularProgress,
  Divider,
  Paper,
  InputAdornment,
  Snackbar,
  Alert
} from '@mui/material';
import {
  FileText,
  Settings,
  Save,
  Palette,
  Building2,
  Mail,
  Globe,
  MapPin,
  CheckCircle2,
  Info,
  Sparkles,
  Layout,
  Eye,
  Bold,
  Italic,
  Heading1,
  Heading2,
  List,
  Link,
  Code,
  Quote,
  HelpCircle
} from 'lucide-react';
import { useParams } from '@tanstack/react-router';
import {
  useReportSettings,
  useUpdateReportSettings
} from '../api';
import type { ReportSettings } from '../api';
import { TacticalPanel } from '../../../components/TacticalPanel';
import { useThemeTokens } from '../../../theme/useThemeTokens';
import type { ApiErrorLike } from '../../../types/errors';

export const ReportSettingsPage: React.FC = () => {
  const { tokens } = useThemeTokens();
  const { projectSlug = 'default' } = useParams({ strict: false });
  const { data: settings, isLoading } = useReportSettings();
  const updateSettings = useUpdateReportSettings();
  const textareaRef = React.useRef<HTMLTextAreaElement>(null);

  const [form, setForm] = useState<ReportSettings>({
    primary_color: '#FFB74D',
    secondary_color: '#212121',
    company_name: '',
    company_address: '',
    company_email: '',
    company_website: '',
    show_rengine_banner: true,
    show_executive_summary: true,
    executive_summary_description: '',
    enable_llm_report_generation: false,
    show_footer: false,
    footer_text: ''
  });

  const [snackbar, setSnackbar] = useState<{
    open: boolean;
    message: string;
    severity: 'success' | 'error' | 'info' | 'warning';
  }>({
    open: false,
    message: '',
    severity: 'success',
  });

  useEffect(() => {
    if (settings) {
      setForm(settings);
    }
  }, [settings]);

  const handleCloseSnackbar = () => {
    setSnackbar({ ...snackbar, open: false });
  };

  const handleSave = () => {
    updateSettings.mutate(form, {
      onSuccess: () => {
        setSnackbar({
          open: true,
          message: 'Report settings updated successfully.',
          severity: 'success',
        });
      },
      onError: (caught) => {
        const error = caught as ApiErrorLike;
        setSnackbar({
          open: true,
          message: `Failed to update report settings: ${error?.response?.data?.message || error?.message || 'Unknown error'}`,
          severity: 'error',
        });
      },
    });
  };

  const handleFormat = (prefix: string, suffix: string = '') => {
    if (!textareaRef.current) return;
    const textarea = textareaRef.current;
    const start = textarea.selectionStart;
    const end = textarea.selectionEnd;
    const text = form.executive_summary_description;
    const selectedText = text.substring(start, end);
    const before = text.substring(0, start);
    const after = text.substring(end);

    const newText = before + prefix + selectedText + suffix + after;
    setForm(prev => ({ ...prev, executive_summary_description: newText }));

    // Re-focus and set selection
    setTimeout(() => {
      textarea.focus();
      textarea.setSelectionRange(start + prefix.length, end + prefix.length);
    }, 0);
  };

  if (isLoading) {
    return (
      <Box sx={{ display: 'flex', justifyContent: 'center', p: 10 }}>
        <CircularProgress sx={{ color: tokens.accent.primary }} />
      </Box>
    );
  }

  return (
    <Box sx={{ width: '100%', display: 'flex', flexDirection: 'column' }}>
      <Box sx={{ mb: 4, width: '100%' }}>
        <Typography variant="h4" sx={{
          fontFamily: 'Orbitron',
          fontWeight: 900,
          color: 'text.primary',
          textShadow: `0 0 20px ${tokens.accent.primary}80`,
          mb: 1
        }}>
          REPORT CALIBRATION
        </Typography>
        <Typography variant="body2" sx={{ color: 'text.secondary', letterSpacing: 1 }}>
          CUSTOMIZE VULNERABILITY REPORT AESTHETICS & BRANDING
        </Typography>
      </Box>

      <Stack spacing={3} sx={{ width: '100%' }}>
        {/* Branding & Aesthetics */}
        <TacticalPanel title="BRANDING & VISUALS" icon={<Palette size={18} />} sx={{ width: '100%' }}>
          <Stack spacing={4}>
            <Box>
              <Typography sx={{ color: 'text.secondary', fontSize: '0.75rem', mb: 2, fontFamily: 'Orbitron' }}>
                THEME COLORS
              </Typography>
              <Grid container spacing={3}>
                <Grid size={{ xs: 12, sm: 6 }} >
                  <Typography variant="caption" sx={{ color: tokens.accent.primary, mb: 1, display: 'block', fontWeight: 600 }}>PRIMARY COLOR</Typography>
                  <Typography variant="caption" sx={{ color: 'text.disabled', mb: 1.5, display: 'block', lineHeight: 1.4 }}>
                    Used for Main Title, Footer Background, and Page Counters.
                  </Typography>
                  <Box sx={{ display: 'flex', gap: 1, alignItems: 'center' }}>
                    <input
                      type="color"
                      value={form.primary_color}
                      onChange={(e) => setForm({ ...form, primary_color: e.target.value })}
                      style={{ width: 42, height: 42, border: '2px solid rgba(255,255,255,0.1)', borderRadius: '4px', background: 'none', cursor: 'pointer' }}
                    />
                    <TextField
                      size="small"
                      value={form.primary_color}
                      onChange={(e) => setForm({ ...form, primary_color: e.target.value })}
                      sx={{
                        '& .MuiOutlinedInput-root': {
                          color: 'text.primary',
                          fontFamily: 'monospace',
                          bgcolor: 'action.hover',
                          fontSize: '0.8rem'
                        }
                      }}
                    />
                  </Box>
                </Grid>
                <Grid size={{ xs: 12, sm: 6 }} >
                  <Typography variant="caption" sx={{ color: '#ffd600', mb: 1, display: 'block', fontWeight: 600 }}>SECONDARY COLOR</Typography>
                  <Typography variant="caption" sx={{ color: 'text.disabled', mb: 1.5, display: 'block', lineHeight: 1.4 }}>
                    Used for the report cover background.
                  </Typography>
                  <Box sx={{ display: 'flex', gap: 1, alignItems: 'center' }}>
                    <input
                      type="color"
                      value={form.secondary_color}
                      onChange={(e) => setForm({ ...form, secondary_color: e.target.value })}
                      style={{ width: 42, height: 42, border: '2px solid rgba(255,255,255,0.1)', borderRadius: '4px', background: 'none', cursor: 'pointer' }}
                    />
                    <TextField
                      size="small"
                      value={form.secondary_color}
                      onChange={(e) => setForm({ ...form, secondary_color: e.target.value })}
                      sx={{
                        '& .MuiOutlinedInput-root': {
                          color: 'text.primary',
                          fontFamily: 'monospace',
                          bgcolor: 'action.hover',
                          fontSize: '0.8rem'
                        }
                      }}
                    />
                  </Box>
                </Grid>
              </Grid>
            </Box>

            <Divider sx={{ borderColor: 'divider' }} />

            <Box sx={{ width: '100%' }}>
              <Typography sx={{ color: 'text.secondary', fontSize: '0.75rem', mb: 2, fontFamily: 'Orbitron' }}>
                COMPANY IDENTITY
              </Typography>
              <Stack spacing={3} sx={{ width: '100%' }}>
                <Stack direction="row" spacing={2} sx={{ width: '100%' }}>
                  <Box sx={{ flex: 1 }}>
                    <TextField
                      fullWidth
                      label="Company Name"
                      value={form.company_name}
                      onChange={(e) => setForm({ ...form, company_name: e.target.value })}
                      slotProps={{
                        input: {
                          startAdornment: (
                            <InputAdornment position="start">
                              <Building2 size={18} color={tokens.accent.primary} style={{ opacity: 0.5 }} />
                            </InputAdornment>
                          ),
                        }
                      }}
                      variant="outlined"
                      sx={{ '& .MuiOutlinedInput-root': { color: 'text.primary' } }}
                    />
                  </Box>
                  <Box sx={{ flex: 1 }}>
                    <TextField
                      fullWidth
                      label="Company Address"
                      value={form.company_address}
                      onChange={(e) => setForm({ ...form, company_address: e.target.value })}
                      slotProps={{
                        input: {
                          startAdornment: (
                            <InputAdornment position="start">
                              <MapPin size={18} color={tokens.accent.primary} style={{ opacity: 0.5 }} />
                            </InputAdornment>
                          ),
                        }
                      }}
                      variant="outlined"
                      sx={{ '& .MuiOutlinedInput-root': { color: 'text.primary' } }}
                    />
                  </Box>
                </Stack>

                <Stack direction="row" spacing={2} sx={{ width: '100%' }}>
                  <Box sx={{ flex: 1 }}>
                    <TextField
                      fullWidth
                      label="Company Website"
                      placeholder="https://company.com"
                      value={form.company_website}
                      onChange={(e) => setForm({ ...form, company_website: e.target.value })}
                      slotProps={{
                        input: {
                          startAdornment: (
                            <InputAdornment position="start">
                              <Globe size={18} color={tokens.accent.primary} style={{ opacity: 0.5 }} />
                            </InputAdornment>
                          ),
                        }
                      }}
                      variant="outlined"
                      sx={{ '& .MuiOutlinedInput-root': { color: 'text.primary' } }}
                    />
                  </Box>
                  <Box sx={{ flex: 1 }}>
                    <TextField
                      fullWidth
                      label="Company Email"
                      placeholder="email@yourcompany.com"
                      value={form.company_email}
                      onChange={(e) => setForm({ ...form, company_email: e.target.value })}
                      slotProps={{
                        input: {
                          startAdornment: (
                            <InputAdornment position="start">
                              <Mail size={18} color={tokens.accent.primary} style={{ opacity: 0.5 }} />
                            </InputAdornment>
                          ),
                        }
                      }}
                      variant="outlined"
                      sx={{ '& .MuiOutlinedInput-root': { color: 'text.primary' } }}
                    />
                  </Box>
                </Stack>
              </Stack>
            </Box>
          </Stack>
        </TacticalPanel>

        {/* Report Content */}
        <TacticalPanel title="REPORT COMPONENTS" icon={<Layout size={18} />} sx={{ width: '100%' }}>
          <Stack spacing={4}>
            <Box>
              <Typography sx={{ color: 'text.secondary', fontSize: '0.75rem', mb: 2, fontFamily: 'Orbitron' }}>
                LAYOUT TOGGLES
              </Typography>
              <Stack
                direction="row"
                spacing={4}
                sx={{
                  width: '100%',
                  justifyContent: 'center',
                  flexWrap: 'wrap',
                  '& > *': { minWidth: '250px' }
                }}
              >
                <FormControlLabel
                  control={
                    <Switch
                      checked={form.show_rengine_banner}
                      onChange={(e) => setForm({ ...form, show_rengine_banner: e.target.checked })}
                      sx={{ '& .MuiSwitch-switchBase.Mui-checked': { color: tokens.accent.primary } }}
                    />
                  }
                  label={
                    <Box>
                      <Typography sx={{ color: 'text.primary', fontSize: '0.85rem' }}>Show reNgine Banner</Typography>
                      <Typography variant="caption" sx={{ color: 'text.disabled', display: 'block' }}>
                        Includes 'Generated by reNgine' in the footer.
                      </Typography>
                    </Box>
                  }
                />
                <FormControlLabel
                  control={
                    <Switch
                      checked={form.show_executive_summary}
                      onChange={(e) => setForm({ ...form, show_executive_summary: e.target.checked })}
                      sx={{ '& .MuiSwitch-switchBase.Mui-checked': { color: tokens.accent.primary } }}
                    />
                  }
                  label={
                    <Box>
                      <Typography sx={{ color: 'text.primary', fontSize: '0.85rem' }}>Show Executive Summary</Typography>
                      <Typography variant="caption" sx={{ color: 'text.disabled', display: 'block' }}>
                        Appears before the quick summary section.
                      </Typography>
                    </Box>
                  }
                />
                <FormControlLabel
                  control={
                    <Switch
                      checked={form.enable_llm_report_generation}
                      onChange={(e) => setForm({ ...form, enable_llm_report_generation: e.target.checked })}
                      sx={{ '& .MuiSwitch-switchBase.Mui-checked': { color: tokens.accent.primary } }}
                    />
                  }
                  label={
                    <Box>
                      <Box sx={{ display: 'flex', alignItems: 'center', gap: 1 }}>
                        <Typography sx={{ color: 'text.primary', fontSize: '0.85rem' }}>AI Powered Report Generation</Typography>
                        <Sparkles size={14} color="#ffd600" />
                      </Box>
                      <Typography variant="caption" sx={{ color: 'text.disabled', display: 'block' }}>
                        Automatically generates Overview, Brief, and Conclusion via LLM.
                      </Typography>
                    </Box>
                  }
                />
              </Stack>
            </Box>

            <Divider sx={{ borderColor: 'divider' }} />

            <Box>
              <Typography sx={{ color: 'text.secondary', fontSize: '0.75rem', mb: 2, fontFamily: 'Orbitron' }}>
                EXECUTIVE SUMMARY TEMPLATE
              </Typography>

              <Box sx={{ mb: 2, p: 2, bgcolor: 'background.default', borderRadius: '8px', border: 1, borderColor: 'divider' }}>
                <Typography variant="caption" sx={{ color: tokens.accent.primary, fontWeight: 600, display: 'block', mb: 2, fontFamily: 'Orbitron' }}>
                  AVAILABLE SYNTAX (Curly braces are mandatory)
                </Typography>
                <Stack spacing={1}>
                  {[
                    { tag: '{scan_date}', desc: 'Scan Date (e.g. 25 June, 2020)' },
                    { tag: '{company_name}', desc: 'Auditing Company Name' },
                    { tag: '{target_name}', desc: 'Target Domain' },
                    { tag: '{target_description}', desc: 'Target Description' },
                    { tag: '{subdomain_count}', desc: 'Total Subdomains' },
                    { tag: '{vulnerability_count}', desc: 'Total Vulnerabilities' },
                    { tag: '{critical_count}', desc: 'Critical Vulnerabilities' },
                    { tag: '{high_count}', desc: 'High Vulnerabilities' },
                    { tag: '{medium_count}', desc: 'Medium Vulnerabilities' },
                    { tag: '{low_count}', desc: 'Low Vulnerabilities' },
                    { tag: '{info_count}', desc: 'Info Vulnerabilities' },
                    { tag: '{unknown_count}', desc: 'Unknown Severity' },
                    { tag: '{comments}', desc: 'Assessment comments provided during report generation' },
                  ].map((item) => (
                    <Box key={item.tag} sx={{ display: 'flex', gap: 2, alignItems: 'center' }}>
                      <Typography sx={{
                        color: '#ffd600',
                        fontSize: '11px',
                        fontFamily: 'monospace',
                        bgcolor: 'rgba(255, 214, 0, 0.1)',
                        px: 1,
                        py: 0.2,
                        borderRadius: '4px',
                        minWidth: '120px',
                        textAlign: 'center',
                        border: '1px solid rgba(255, 214, 0, 0.2)'
                      }}>
                        {item.tag}
                      </Typography>
                      <Typography sx={{ color: 'text.secondary', fontSize: '11px' }}>{item.desc}</Typography>
                    </Box>
                  ))}
                </Stack>
              </Box>

              <Box sx={{
                display: 'flex',
                alignItems: 'center',
                gap: 0.5,
                px: 1,
                py: 0.5,
                bgcolor: 'action.hover',
                border: 1,
                borderColor: 'divider',
                borderBottom: 'none',
                borderTopLeftRadius: '8px',
                borderTopRightRadius: '8px'
              }}>
                {[
                  { icon: <Eye size={16} />, label: 'Preview', action: () => { } },
                  { icon: <Bold size={16} />, label: 'Bold', action: () => handleFormat('**', '**') },
                  { icon: <Italic size={16} />, label: 'Italic', action: () => handleFormat('*', '*') },
                  { icon: <Heading1 size={16} />, label: 'Heading 1', action: () => handleFormat('# ') },
                  { icon: <Heading2 size={16} />, label: 'Heading 2', action: () => handleFormat('## ') },
                  { icon: <List size={16} />, label: 'List', action: () => handleFormat('- ') },
                  { icon: <Link size={16} />, label: 'Link', action: () => handleFormat('[', '](url)') },
                  { separator: true },
                  { icon: <Code size={16} />, label: 'Code', action: () => handleFormat('`', '`') },
                  { separator: true },
                  { icon: <Quote size={16} />, label: 'Quote', action: () => handleFormat('> ') },
                  { separator: true },
                  { icon: <HelpCircle size={16} />, label: 'Help', action: () => { } },
                ].map((item, idx) => (
                  item.separator ? (
                    <Box key={idx} sx={{ width: '1px', height: '16px', bgcolor: 'divider', mx: 0.5 }} />
                  ) : (
                    <Button
                      key={idx}
                      size="small"
                      onClick={item.action}
                      sx={{
                        minWidth: '32px',
                        height: '32px',
                        p: 0,
                        color: `${tokens.accent.primary}B3`,
                        '&:hover': { color: tokens.accent.primary, bgcolor: `${tokens.accent.primary}1A` }
                      }}
                      title={item.label}
                    >
                      {item.icon}
                    </Button>
                  )
                ))}
              </Box>

              <TextField
                fullWidth
                multiline
                rows={7}
                inputRef={textareaRef}
                placeholder="Enter markdown summary template..."
                value={form.executive_summary_description}
                onChange={(e) => setForm({ ...form, executive_summary_description: e.target.value })}
                sx={{
                  '& .MuiOutlinedInput-root': {
                    color: '#000000ff',
                    bgcolor: '#fff',
                    fontFamily: 'monospace',
                    fontSize: '0.85rem',
                    lineHeight: 1.6,
                    padding: 0,
                    borderTopLeftRadius: 0,
                    borderTopRightRadius: 0,
                    '& fieldset': {
                      borderTop: 'none'
                    },
                    '& textarea': {
                      padding: '16.5px 14px',
                      resize: 'vertical',
                      minHeight: '80px'
                    }
                  }
                }}
              />
            </Box>

            <Box>
              <FormControlLabel
                control={
                  <Switch
                    checked={form.show_footer}
                    onChange={(e) => setForm({ ...form, show_footer: e.target.checked })}
                    sx={{ '& .MuiSwitch-switchBase.Mui-checked': { color: tokens.accent.primary } }}
                  />
                }
                label={
                  <Box>
                    <Typography sx={{ color: 'text.primary', fontSize: '0.85rem' }}>Show Footer Text</Typography>
                    <Typography variant="caption" sx={{ color: 'text.disabled', display: 'block' }}>
                      Copyright or generation info, placed bottom-left.
                    </Typography>
                  </Box>
                }
              />
              {form.show_footer && (
                <TextField
                  fullWidth
                  size="small"
                  placeholder="Footer text..."
                  value={form.footer_text}
                  onChange={(e) => setForm({ ...form, footer_text: e.target.value })}
                  sx={{ mt: 1, '& .MuiOutlinedInput-root': { color: 'text.primary' } }}
                />
              )}
            </Box>
          </Stack>
        </TacticalPanel>

        {/* Global Action */}
        <Paper sx={{
          p: 2,
          width: '100%',
          bgcolor: `${tokens.accent.primary}0D`,
          border: `1px solid ${tokens.accent.primary}33`,
          display: 'flex',
          justifyContent: 'space-between',
          alignItems: 'center'
        }}>
          <Box sx={{ display: 'flex', alignItems: 'center', gap: 2 }}>
            <Info size={20} color={tokens.accent.primary} />
            <Typography sx={{ color: 'text.secondary', fontSize: '0.8rem' }}>
              These settings will be applied to all PDF reports generated across all projects.
            </Typography>
          </Box>
          <Button
            variant="contained"
            startIcon={<Save size={20} />}
            onClick={handleSave}
            disabled={updateSettings.isPending}
            sx={{
              bgcolor: tokens.accent.primary,
              color: '#000',
              fontFamily: 'Orbitron',
              fontWeight: 900,
              px: 6,
              '&:hover': { bgcolor: tokens.accent.primary, filter: 'brightness(1.1)' }
            }}
          >
            {updateSettings.isPending ? 'SYNCHRONIZING...' : 'UPDATE CONFIG'}
          </Button>
        </Paper>
      </Stack>

      <Snackbar
        open={snackbar.open}
        autoHideDuration={6000}
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
            bgcolor: snackbar.severity === 'success' ? `${tokens.accent.primary}E6` : 'rgba(255, 0, 85, 0.9)',
            color: '#000',
            '& .MuiAlert-icon': { color: '#000' }
          }}
        >
          {snackbar.message}
        </Alert>
      </Snackbar>
    </Box>
  );
};
