import React, { useState } from 'react';
import {
  Dialog,
  DialogTitle,
  DialogContent,
  DialogActions,
  Button,
  Box,
  Typography,
  FormControl,
  FormLabel,
  RadioGroup,
  FormControlLabel,
  Radio,
  Checkbox,
  IconButton,
  Stack,
  Divider,
  CircularProgress,
  TextField,
  Collapse,
  useTheme,
  alpha
} from '@mui/material';
import { X, FileText, Shield, FileSearch, Download, MessageSquare, ChevronDown, ChevronUp, Sliders, Briefcase, Terminal } from 'lucide-react';
import { useThemeTokens } from '../../../theme/useThemeTokens';
import { getDialogPaperSx, getFieldSx } from '../../../theme/semanticColors';

const SectionTitle = ({ title, icon }: { title: string, icon?: React.ReactNode }) => {
  const { tokens } = useThemeTokens();
  return (
    <Typography sx={{
      color: tokens.accent.primary,
      fontFamily: 'Orbitron',
      fontSize: '0.75rem',
      fontWeight: 800,
      mb: 2,
      display: 'flex',
      alignItems: 'center',
      gap: 1
    }}>
      {icon} {title}
    </Typography>
  );
};

interface ScanReportModalProps {
  open: boolean;
  onClose: () => void;
  scanId: number;
}

export const ScanReportModal: React.FC<ScanReportModalProps> = ({ open, onClose, scanId }) => {
  const { tokens } = useThemeTokens();
  const theme = useTheme();
  const isLight = tokens.mode === 'light';

  const [reportType, setReportType] = useState('full');
  const [reportTemplate, setReportTemplate] = useState('modern');
  const [isGenerating, setIsGenerating] = useState(false);
  const [generationStatus, setGenerationStatus] = useState<string | null>(null);
  const [reportUrl, setReportUrl] = useState<string | null>(null);
  const [comments, setComments] = useState('');
  const [commentsExpanded, setCommentsExpanded] = useState(false);

  // Executive Settings
  const [execSettings, setExecSettings] = useState({
    attackSurface: false,
    attackPaths: false,
  });

  // Technical Settings
  const [techSettings, setTechSettings] = useState({
    ignoreInfoVuln: false,
    secretFindings: true,
    parameters: false,
    endpoints: false,
    directories: false,
    s3Buckets: false,
    wafInfo: false,
    technologies: false,
    apiIntelligence: false,
    identityIntelligence: false,
    exposures: false,
    metadataDorks: false,
    certificates: false,
    employees: false,
  });

  const handleTechSettingChange = (field: keyof typeof techSettings) => (e: React.ChangeEvent<HTMLInputElement>) => {
    setTechSettings(prev => ({ ...prev, [field]: e.target.checked }));
  };

  const handleExecSettingChange = (field: keyof typeof execSettings) => (e: React.ChangeEvent<HTMLInputElement>) => {
    setExecSettings(prev => ({ ...prev, [field]: e.target.checked }));
  };

  const handleMasterTechToggle = (checked: boolean) => {
    setTechSettings({
      ignoreInfoVuln: checked,
      secretFindings: checked,
      parameters: checked,
      endpoints: checked,
      directories: checked,
      s3Buckets: checked,
      wafInfo: checked,
      technologies: checked,
      apiIntelligence: checked,
      identityIntelligence: checked,
      exposures: checked,
      metadataDorks: checked,
      certificates: checked,
      employees: checked,
    });
  };

  const handleMasterExecToggle = (checked: boolean) => {
    setExecSettings({
      attackSurface: checked,
      attackPaths: checked,
    });
  };

  const pollReportStatus = async (reportId: number) => {
    setIsGenerating(true);
    setGenerationStatus('Generating report...');
    
    const checkStatus = async () => {
      try {
        const response = await fetch(`/scan/report/status/${reportId}`, {
          credentials: 'include'
        });
        if (!response.ok) throw new Error('Failed to check status');
        
        const data = await response.json();
        
        if (data.status === 2) { // Success
          setIsGenerating(false);
          setGenerationStatus('Report successfully generated!');
          setReportUrl(data.report_url);
          
          // Try to auto-open only if it's the first time reaching success
          if (data.report_url) {
            const win = window.open(data.report_url, '_blank');
            if (!win) {
              setGenerationStatus('Report ready! Please click the download button below (Popup was blocked).');
            }
          }
        } else if (data.status === 0) { // Failed
          setIsGenerating(false);
          setGenerationStatus(`Error: ${data.error_message || 'Unknown error'}`);
        } else {
          // Continue polling
          setTimeout(checkStatus, 3000);
        }
      } catch (error) {
        setIsGenerating(false);
        setGenerationStatus('Failed to check report status');
      }
    };
    
    checkStatus();
  };

  const initiateReport = async (download: boolean) => {
    setGenerationStatus('Initiating report generation...');
    setIsGenerating(true);
    
    try {
      const params = new URLSearchParams({
        report_type: reportType,
        report_template: reportTemplate,
        ignore_info_vuln: techSettings.ignoreInfoVuln ? 'True' : 'False',
        include_attack_surface_map: execSettings.attackSurface ? 'True' : 'False',
        include_attack_paths: execSettings.attackPaths ? 'True' : 'False',
        include_found_parameters: techSettings.parameters ? 'True' : 'False',
        include_secret_findings: techSettings.secretFindings ? 'True' : 'False',
        include_endpoints: techSettings.endpoints ? 'True' : 'False',
        include_directories: techSettings.directories ? 'True' : 'False',
        include_s3_buckets: techSettings.s3Buckets ? 'True' : 'False',
        include_waf: techSettings.wafInfo ? 'True' : 'False',
        include_technologies: techSettings.technologies ? 'True' : 'False',
        include_api_intelligence: techSettings.apiIntelligence ? 'True' : 'False',
        include_identity: techSettings.identityIntelligence ? 'True' : 'False',
        include_exposures: techSettings.exposures ? 'True' : 'False',
        include_dorks_metadata: techSettings.metadataDorks ? 'True' : 'False',
        include_certificates: techSettings.certificates ? 'True' : 'False',
        include_employees: techSettings.employees ? 'True' : 'False',
        download: download ? 'True' : 'False',
        comments: comments
      });
      
      const response = await fetch(`/scan/create_report/${scanId}?${params.toString()}`, {
        credentials: 'include'
      });
      
      if (!response.ok) throw new Error('Failed to initiate report');
      
      const data = await response.json();
      if (data.status && data.report_id) {
        pollReportStatus(data.report_id);
      } else {
        throw new Error('Invalid response from server');
      }
    } catch (error) {
      setIsGenerating(false);
      setGenerationStatus('Failed to initiate report generation');
    }
  };

  const handleDownload = () => initiateReport(true);
  const handlePreview = () => initiateReport(false);

  const getFieldStyles = (isLight: boolean, tokens: any) => ({
    ...getFieldSx(isLight, tokens),
    '& .MuiOutlinedInput-root': {
      ...getFieldSx(isLight, tokens)['& .MuiOutlinedInput-root'],
      bgcolor: isLight ? 'transparent' : alpha(tokens.text.primary, 0.03),
    }
  });

  return (
    <Dialog
      open={open}
      onClose={isGenerating ? undefined : onClose}
      maxWidth="sm"
      fullWidth
      slotProps={{
        paper: {
          sx: {
            ...getDialogPaperSx(isLight, theme, tokens),
            backgroundImage: isLight
              ? 'none'
              : `linear-gradient(${alpha(tokens.accent.primary, 0.02)} 1px, transparent 1px), linear-gradient(90deg, ${alpha(tokens.accent.primary, 0.02)} 1px, transparent 1px)`,
            backgroundSize: '20px 20px',
            border: `1px solid ${alpha(tokens.accent.primary, 0.2)}`,
            boxShadow: isLight
              ? `0 4px 20px ${alpha(tokens.accent.primary, 0.15)}`
              : `0 0 30px rgba(0, 0, 0, 0.5), 0 0 10px ${alpha(tokens.accent.primary, 0.1)}`,
          }
        }
      }}
    >
      <DialogTitle sx={{
        m: 0,
        p: 2,
        bgcolor: alpha(tokens.accent.primary, 0.05),
        borderBottom: `1px solid ${tokens.border.subtle}`,
        display: 'flex',
        alignItems: 'center',
        justifyContent: 'space-between'
      }}>
        <Stack direction="row" spacing={1.5} sx={{ alignItems: 'center' }}>
          <FileText size={20} color={tokens.accent.primary} />
          <Typography sx={{
            fontFamily: 'Orbitron',
            fontWeight: 900,
            color: 'text.primary',
            letterSpacing: '0.1rem',
            fontSize: '1rem'
          }}>
            GENERATE SCAN REPORT
          </Typography>
        </Stack>
        {!isGenerating && (
          <IconButton onClick={onClose} sx={{ color: tokens.text.muted, '&:hover': { color: tokens.accent.error } }}>
            <X size={20} />
          </IconButton>
        )}
      </DialogTitle>

      <DialogContent sx={{ p: 3, mt: 2 }}>
        <Stack spacing={4}>
          {generationStatus && (
            <Box sx={{ 
              p: 2, 
              bgcolor: reportUrl ? alpha(tokens.accent.success, 0.05) : alpha(tokens.accent.primary, 0.05), 
              border: `1px solid ${reportUrl ? alpha(tokens.accent.success, 0.2) : alpha(tokens.accent.primary, 0.2)}`,
              borderRadius: 1,
              display: 'flex',
              alignItems: 'center',
              gap: 2
            }}>
              {isGenerating && <CircularProgress size={20} sx={{ color: tokens.accent.primary }} />}
              {!isGenerating && reportUrl && <Shield size={20} color={tokens.accent.success} />}
              <Typography sx={{ color: reportUrl ? tokens.accent.success : tokens.accent.primary, fontSize: '0.8rem', fontWeight: 700, fontFamily: 'Orbitron' }}>
                {generationStatus}
              </Typography>
            </Box>
          )}

          <Box sx={{ opacity: isGenerating ? 0.5 : 1, pointerEvents: isGenerating ? 'none' : 'auto' }}>
            <Typography sx={{
              color: tokens.accent.primary,
              fontFamily: 'Orbitron',
              fontSize: '0.75rem',
              fontWeight: 800,
              mt: 1,
              mb: 2,
              display: 'flex',
              alignItems: 'center',
              gap: 1
            }}>
              <FileSearch size={14} /> SELECT REPORT TYPE
            </Typography>
            <FormControl component="fieldset">
              <RadioGroup value={reportType} onChange={(e) => setReportType(e.target.value)}>
                <Stack spacing={1}>
                  <FormControlLabel
                    value="full"
                    control={<Radio sx={{ color: alpha(tokens.accent.primary, 0.2), '&.Mui-checked': { color: tokens.accent.primary } }} />}
                    label={
                      <Box>
                        <Typography sx={{ color: 'text.primary', fontSize: '0.85rem', fontWeight: 700, fontFamily: 'Orbitron' }}>Full Scan Report</Typography>
                        <Typography sx={{ color: 'text.secondary', fontSize: '0.7rem' }}>Includes all findings: subdomains, endpoints, and vulnerabilities.</Typography>
                      </Box>
                    }
                  />
                  <FormControlLabel
                    value="vulnerability"
                    control={<Radio sx={{ color: alpha(tokens.accent.primary, 0.2), '&.Mui-checked': { color: tokens.accent.primary } }} />}
                    label={
                      <Box>
                        <Typography sx={{ color: 'text.primary', fontSize: '0.85rem', fontWeight: 700, fontFamily: 'Orbitron' }}>Vulnerability Report</Typography>
                        <Typography sx={{ color: 'text.secondary', fontSize: '0.7rem' }}>Focuses specifically on detected security vulnerabilities.</Typography>
                      </Box>
                    }
                  />
                </Stack>
              </RadioGroup>
            </FormControl>
          </Box>

          <Divider sx={{ borderColor: tokens.border.subtle }} />

          <Box sx={{ opacity: isGenerating ? 0.5 : 1, pointerEvents: isGenerating ? 'none' : 'auto' }}>
            <Typography sx={{
              color: tokens.accent.primary,
              fontFamily: 'Orbitron',
              fontSize: '0.75rem',
              fontWeight: 800,
              mb: 2,
              display: 'flex',
              alignItems: 'center',
              gap: 1
            }}>
              <Shield size={14} /> REPORT SETTINGS
            </Typography>
            <Stack spacing={2}>
              <Box>
                <Typography sx={{ color: tokens.text.secondary, fontSize: '0.7rem', fontWeight: 800, mb: 1, fontFamily: 'Orbitron' }}>TEMPLATE</Typography>
                <RadioGroup row value={reportTemplate} onChange={(e) => {
                  const val = e.target.value;
                  setReportTemplate(val);
                  if (val !== 'enterprise' && val !== 'cyber_pro') {
                    setExecSettings(prev => ({ ...prev, attackSurface: false, attackPaths: false }));
                  }
                }}>
                  <FormControlLabel
                    value="default"
                    control={<Radio size="small" sx={{ color: alpha(tokens.accent.primary, 0.2), '&.Mui-checked': { color: tokens.accent.primary } }} />}
                    label={<Typography sx={{ color: 'text.primary', fontSize: '0.8rem', fontWeight: 600 }}>Default</Typography>}
                  />
                  <FormControlLabel
                    value="modern"
                    control={<Radio size="small" sx={{ color: alpha(tokens.accent.primary, 0.2), '&.Mui-checked': { color: tokens.accent.primary } }} />}
                    label={<Typography sx={{ color: 'text.primary', fontSize: '0.8rem', fontWeight: 600 }}>Modern (V2)</Typography>}
                  />
                  <FormControlLabel
                    value="enterprise"
                    control={<Radio size="small" sx={{ color: alpha(tokens.accent.primary, 0.2), '&.Mui-checked': { color: tokens.accent.primary } }} />}
                    label={<Typography sx={{ color: 'text.primary', fontSize: '0.8rem', fontWeight: 600 }}>Enterprise</Typography>}
                  />
                  <FormControlLabel
                    value="cyber_pro"
                    control={<Radio size="small" sx={{ color: alpha(tokens.accent.primary, 0.2), '&.Mui-checked': { color: tokens.accent.primary } }} />}
                    label={<Typography sx={{ color: 'text.primary', fontSize: '0.8rem', fontWeight: 600 }}>Cyber Pro</Typography>}
                  />
                </RadioGroup>
              </Box>

              {/* Executive & Technical Configuration Modes */}
              <Box sx={{ mt: 3, display: 'flex', flexDirection: 'column', gap: 3 }}>
                
                {/* Executive Settings Group */}
                <Box sx={{
                  border: `1px solid ${alpha(tokens.accent.primary, 0.2)}`,
                  borderRadius: 2,
                  bgcolor: alpha(tokens.accent.primary, 0.02),
                  overflow: 'hidden'
                }}>
                  <Box sx={{
                    p: 2,
                    borderBottom: `1px solid ${alpha(tokens.accent.primary, 0.1)}`,
                    display: 'flex',
                    alignItems: 'center',
                    justifyContent: 'space-between',
                    bgcolor: alpha(tokens.accent.primary, 0.04)
                  }}>
                    <Stack direction="row" spacing={1.5} sx={{ alignItems: 'center' }}>
                      <Briefcase size={18} color={tokens.accent.primary} />
                      <Box>
                        <Typography sx={{ color: tokens.text.primary, fontSize: '0.85rem', fontWeight: 800, fontFamily: 'Orbitron' }}>
                          EXECUTIVE MODE
                        </Typography>
                        <Typography sx={{ color: tokens.text.secondary, fontSize: '0.65rem' }}>
                          High-level summaries, visualizations, and impact paths
                        </Typography>
                      </Box>
                    </Stack>
                    <FormControlLabel
                      control={<Checkbox 
                        checked={Object.values(execSettings).some(v => v)} 
                        onChange={(e) => handleMasterExecToggle(e.target.checked)} 
                        sx={{ color: alpha(tokens.accent.primary, 0.3), '&.Mui-checked': { color: tokens.accent.primary } }} 
                      />}
                      label=""
                      sx={{ m: 0 }}
                    />
                  </Box>
                  <Box sx={{ p: 2, display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 2 }}>
                    <FormControlLabel
                      control={<Checkbox
                        checked={execSettings.attackSurface}
                        disabled={reportTemplate !== 'enterprise' && reportTemplate !== 'cyber_pro'}
                        onChange={handleExecSettingChange('attackSurface')}
                        sx={{ color: alpha(tokens.accent.primary, 0.2), '&.Mui-checked': { color: tokens.accent.primary } }}
                      />}
                      label={
                        <Box>
                          <Typography sx={{ color: (reportTemplate === 'enterprise' || reportTemplate === 'cyber_pro') ? tokens.text.secondary : tokens.text.disabled, fontSize: '0.75rem', fontWeight: 600 }}>Attack Surface Map</Typography>
                          {reportTemplate !== 'enterprise' && reportTemplate !== 'cyber_pro' && <Typography sx={{ color: alpha(tokens.accent.primary, 0.3), fontSize: '0.6rem' }}>Enterprise/Pro only</Typography>}
                        </Box>
                      }
                    />
                    <FormControlLabel
                      control={<Checkbox
                        checked={execSettings.attackPaths}
                        disabled={reportTemplate !== 'enterprise' && reportTemplate !== 'cyber_pro'}
                        onChange={handleExecSettingChange('attackPaths')}
                        sx={{ color: alpha(tokens.accent.primary, 0.2), '&.Mui-checked': { color: tokens.accent.primary } }}
                      />}
                      label={
                        <Box>
                          <Typography sx={{ color: (reportTemplate === 'enterprise' || reportTemplate === 'cyber_pro') ? tokens.text.secondary : tokens.text.disabled, fontSize: '0.75rem', fontWeight: 600 }}>Attack Paths</Typography>
                          {reportTemplate !== 'enterprise' && reportTemplate !== 'cyber_pro' && <Typography sx={{ color: alpha(tokens.accent.primary, 0.3), fontSize: '0.6rem' }}>Enterprise/Pro only</Typography>}
                        </Box>
                      }
                    />
                  </Box>
                </Box>

                {/* Technical Settings Group */}
                <Box sx={{
                  border: `1px solid ${alpha(tokens.accent.primary, 0.2)}`,
                  borderRadius: 2,
                  bgcolor: alpha(tokens.accent.primary, 0.02),
                  overflow: 'hidden'
                }}>
                  <Box sx={{
                    p: 2,
                    borderBottom: `1px solid ${alpha(tokens.accent.primary, 0.1)}`,
                    display: 'flex',
                    alignItems: 'center',
                    justifyContent: 'space-between',
                    bgcolor: alpha(tokens.accent.primary, 0.04)
                  }}>
                    <Stack direction="row" spacing={1.5} sx={{ alignItems: 'center' }}>
                      <Terminal size={18} color={tokens.accent.primary} />
                      <Box>
                        <Typography sx={{ color: tokens.text.primary, fontSize: '0.85rem', fontWeight: 800, fontFamily: 'Orbitron' }}>
                          TECHNICAL MODE
                        </Typography>
                        <Typography sx={{ color: tokens.text.secondary, fontSize: '0.65rem' }}>
                          Raw data, parameters, deep-dive intelligence, and full findings
                        </Typography>
                      </Box>
                    </Stack>
                    <FormControlLabel
                      control={<Checkbox 
                        checked={Object.values(techSettings).some(v => v)} 
                        onChange={(e) => handleMasterTechToggle(e.target.checked)} 
                        sx={{ color: alpha(tokens.accent.primary, 0.3), '&.Mui-checked': { color: tokens.accent.primary } }} 
                      />}
                      label=""
                      sx={{ m: 0 }}
                    />
                  </Box>
                  <Box sx={{ p: 2, display: 'grid', gridTemplateColumns: '1fr 1fr', gap: y => 1.5, columnGap: 3 }}>
                    <FormControlLabel control={<Checkbox checked={techSettings.ignoreInfoVuln} onChange={handleTechSettingChange('ignoreInfoVuln')} size="small" sx={{ color: alpha(tokens.accent.primary, 0.2), '&.Mui-checked': { color: tokens.accent.primary } }}/>} label={<Typography sx={{ fontSize: '0.75rem', color: tokens.text.secondary }}>Ignore Info Vulns</Typography>} />
                    <FormControlLabel control={<Checkbox checked={techSettings.secretFindings} onChange={handleTechSettingChange('secretFindings')} size="small" sx={{ color: alpha(tokens.accent.primary, 0.2), '&.Mui-checked': { color: tokens.accent.primary } }}/>} label={<Typography sx={{ fontSize: '0.75rem', color: tokens.text.secondary }}>Secret & Credential Findings</Typography>} />
                    <FormControlLabel control={<Checkbox checked={techSettings.parameters} onChange={handleTechSettingChange('parameters')} size="small" sx={{ color: alpha(tokens.accent.primary, 0.2), '&.Mui-checked': { color: tokens.accent.primary } }}/>} label={<Typography sx={{ fontSize: '0.75rem', color: tokens.text.secondary }}>Found Parameters</Typography>} />
                    <FormControlLabel control={<Checkbox checked={techSettings.endpoints} onChange={handleTechSettingChange('endpoints')} size="small" sx={{ color: alpha(tokens.accent.primary, 0.2), '&.Mui-checked': { color: tokens.accent.primary } }}/>} label={<Typography sx={{ fontSize: '0.75rem', color: tokens.text.secondary }}>Endpoints</Typography>} />
                    <FormControlLabel control={<Checkbox checked={techSettings.directories} onChange={handleTechSettingChange('directories')} size="small" sx={{ color: alpha(tokens.accent.primary, 0.2), '&.Mui-checked': { color: tokens.accent.primary } }}/>} label={<Typography sx={{ fontSize: '0.75rem', color: tokens.text.secondary }}>Directories</Typography>} />
                    <FormControlLabel control={<Checkbox checked={techSettings.s3Buckets} onChange={handleTechSettingChange('s3Buckets')} size="small" sx={{ color: alpha(tokens.accent.primary, 0.2), '&.Mui-checked': { color: tokens.accent.primary } }}/>} label={<Typography sx={{ fontSize: '0.75rem', color: tokens.text.secondary }}>S3 Buckets</Typography>} />
                    <FormControlLabel control={<Checkbox checked={techSettings.wafInfo} onChange={handleTechSettingChange('wafInfo')} size="small" sx={{ color: alpha(tokens.accent.primary, 0.2), '&.Mui-checked': { color: tokens.accent.primary } }}/>} label={<Typography sx={{ fontSize: '0.75rem', color: tokens.text.secondary }}>WAF Info</Typography>} />
                    <FormControlLabel control={<Checkbox checked={techSettings.technologies} onChange={handleTechSettingChange('technologies')} size="small" sx={{ color: alpha(tokens.accent.primary, 0.2), '&.Mui-checked': { color: tokens.accent.primary } }}/>} label={<Typography sx={{ fontSize: '0.75rem', color: tokens.text.secondary }}>Technologies</Typography>} />
                    <FormControlLabel control={<Checkbox checked={techSettings.apiIntelligence} onChange={handleTechSettingChange('apiIntelligence')} size="small" sx={{ color: alpha(tokens.accent.primary, 0.2), '&.Mui-checked': { color: tokens.accent.primary } }}/>} label={<Typography sx={{ fontSize: '0.75rem', color: tokens.text.secondary }}>API Intelligence</Typography>} />
                    <FormControlLabel control={<Checkbox checked={techSettings.identityIntelligence} onChange={handleTechSettingChange('identityIntelligence')} size="small" sx={{ color: alpha(tokens.accent.primary, 0.2), '&.Mui-checked': { color: tokens.accent.primary } }}/>} label={<Typography sx={{ fontSize: '0.75rem', color: tokens.text.secondary }}>Identity Intelligence</Typography>} />
                    <FormControlLabel control={<Checkbox checked={techSettings.exposures} onChange={handleTechSettingChange('exposures')} size="small" sx={{ color: alpha(tokens.accent.primary, 0.2), '&.Mui-checked': { color: tokens.accent.primary } }}/>} label={<Typography sx={{ fontSize: '0.75rem', color: tokens.text.secondary }}>Exposures</Typography>} />
                    <FormControlLabel control={<Checkbox checked={techSettings.metadataDorks} onChange={handleTechSettingChange('metadataDorks')} size="small" sx={{ color: alpha(tokens.accent.primary, 0.2), '&.Mui-checked': { color: tokens.accent.primary } }}/>} label={<Typography sx={{ fontSize: '0.75rem', color: tokens.text.secondary }}>Metadata & Dorks</Typography>} />
                    <FormControlLabel control={<Checkbox checked={techSettings.certificates} onChange={handleTechSettingChange('certificates')} size="small" sx={{ color: alpha(tokens.accent.primary, 0.2), '&.Mui-checked': { color: tokens.accent.primary } }}/>} label={<Typography sx={{ fontSize: '0.75rem', color: tokens.text.secondary }}>Certificates</Typography>} />
                    <FormControlLabel control={<Checkbox checked={techSettings.employees} onChange={handleTechSettingChange('employees')} size="small" sx={{ color: alpha(tokens.accent.primary, 0.2), '&.Mui-checked': { color: tokens.accent.primary } }}/>} label={<Typography sx={{ fontSize: '0.75rem', color: tokens.text.secondary }}>Employees</Typography>} />
                  </Box>
                </Box>
              </Box>
            </Stack>
          </Box>

          <Divider sx={{ borderColor: tokens.border.subtle }} />

          <Box sx={{ opacity: isGenerating ? 0.5 : 1, pointerEvents: isGenerating ? 'none' : 'auto' }}>
            <Box
              onClick={() => setCommentsExpanded(!commentsExpanded)}
              sx={{
                display: 'flex',
                alignItems: 'center',
                justifyContent: 'space-between',
                cursor: 'pointer',
                userSelect: 'none',
                mb: commentsExpanded ? 2 : 0,
                '&:hover': {
                  opacity: 0.8
                }
              }}
            >
              <Typography sx={{
                color: tokens.accent.primary,
                fontFamily: 'Orbitron',
                fontSize: '0.75rem',
                fontWeight: 800,
                display: 'flex',
                alignItems: 'center',
                gap: 1
              }}>
                <MessageSquare size={14} /> ASSESSMENT COMMENTS (OPTIONAL)
              </Typography>
              {commentsExpanded ? <ChevronUp size={16} color={tokens.accent.primary} /> : <ChevronDown size={16} color={tokens.accent.primary} />}
            </Box>
            
            <Collapse in={commentsExpanded}>
              <TextField
                fullWidth
                multiline
                rows={4}
                placeholder="Enter any comments or notes about the assessment to insert into the {comments} placeholder..."
                value={comments}
                onChange={(e) => setComments(e.target.value)}
                sx={getFieldStyles(isLight, tokens)}
              />
            </Collapse>
          </Box>
        </Stack>
      </DialogContent>

      <DialogActions sx={{ p: 3, bgcolor: alpha(tokens.accent.primary, 0.01), borderTop: `1px solid ${tokens.border.subtle}` }}>
        <Button
          onClick={onClose}
          disabled={isGenerating}
          sx={{
            color: tokens.text.secondary,
            fontFamily: 'Orbitron',
            fontWeight: 800,
            fontSize: '0.7rem',
            mr: 'auto',
            '&:hover': { color: tokens.text.primary }
          }}
        >
          CANCEL
        </Button>
        {reportUrl ? (
          <Button
            href={reportUrl}
            target="_blank"
            variant="contained"
            startIcon={<Download size={16} />}
            sx={{
              bgcolor: tokens.accent.success,
              color: theme.palette.getContrastText(tokens.accent.success),
              fontFamily: 'Orbitron',
              fontWeight: 900,
              fontSize: '0.75rem',
              px: 4,
              '&:hover': { bgcolor: alpha(tokens.accent.success, 0.85) }
            }}
          >
            DOWNLOAD NOW
          </Button>
        ) : (
          <>
            <Button
              onClick={handlePreview}
              disabled={isGenerating}
              sx={{
                color: tokens.accent.primary,
                fontFamily: 'Orbitron',
                fontWeight: 800,
                fontSize: '0.7rem',
                border: `1px solid ${alpha(tokens.accent.primary, 0.3)}`,
                px: 2,
                '&:hover': { bgcolor: alpha(tokens.accent.primary, 0.05), borderColor: tokens.accent.primary }
              }}
            >
              PREVIEW
            </Button>
            <Button
              onClick={handleDownload}
              variant="contained"
              disabled={isGenerating}
              startIcon={isGenerating ? <CircularProgress size={16} sx={{ color: theme.palette.getContrastText(tokens.accent.primary) }} /> : <Download size={16} />}
              sx={{
                bgcolor: tokens.accent.primary,
                color: theme.palette.getContrastText(tokens.accent.primary),
                fontFamily: 'Orbitron',
                fontWeight: 900,
                fontSize: '0.7rem',
                px: 3,
                '&:hover': { bgcolor: alpha(tokens.accent.primary, 0.85) }
              }}
            >
              {isGenerating ? 'GENERATING...' : 'GENERATE & DOWNLOAD'}
            </Button>
          </>
        )}
      </DialogActions>
    </Dialog>
  );
};

