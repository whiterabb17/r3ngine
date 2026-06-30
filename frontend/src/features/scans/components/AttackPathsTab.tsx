import React, { useState } from 'react';
import {
  Box,
  Stack,
  Typography,
  CircularProgress,
  Chip,
  Collapse,
  IconButton,
  Divider,
  Tooltip,
  Button,
  Snackbar,
  Alert,
  useTheme,
} from '@mui/material';
import {
  ChevronDown,
  ChevronRight,
  ShieldAlert,
  CheckCircle2,
  HelpCircle,
  GitBranch,
  Zap,
  AlertTriangle,
  ArrowRight,
  Server,
  Key,
  Lock,
} from 'lucide-react';
import { useParams, Link } from '@tanstack/react-router';
import { 
  useAttackPaths, 
  useTriggerAttackPathModeling,
  useRecalculateAttackPaths,
  useExplainAttackPath,
  type AttackPath, 
  type AttackStep,
  type EnrichedNode
} from '../api/useAttackPaths';
import { TacticalPanel } from '../../../components/TacticalPanel';
import { Bot, Brain } from 'lucide-react';
import { useThemeTokens } from '../../../theme/useThemeTokens';
import { getSeverityColor } from '../../../theme/semanticColors';
import { AttackTreeViewer } from './AttackTreeViewer';

const RISK_LABEL: Record<string, string> = {
  critical: 'CRITICAL',
  high: 'HIGH',
  medium: 'MEDIUM',
  low: 'LOW',
  unknown: 'UNKNOWN',
};

// ─── Risk badge ───────────────────────────────────────────────────────────────
const RiskBadge: React.FC<{ risk: string }> = ({ risk }) => {
  const { tokens } = useThemeTokens();
  const color = getSeverityColor(risk, tokens);
  const label = RISK_LABEL[risk] ?? risk?.toUpperCase() ?? 'UNKNOWN';
  return (
    <Box
      sx={{
        display: 'inline-flex',
        px: 1,
        py: 0.2,
        borderRadius: 0.5,
        bgcolor: `${color}20`,
        border: `1px solid ${color}50`,
        color,
        fontSize: '0.6rem',
        fontWeight: 900,
        letterSpacing: 1,
        fontFamily: 'Orbitron',
      }}
    >
      {label}
    </Box>
  );
};

// ─── MITRE Tactic color palette ──────────────────────────────────────────────
const TACTIC_COLORS: Record<string, string> = {
  'initial-access':       '#ff4444',
  'execution':            '#ff8800',
  'persistence':          '#ffcc00',
  'privilege-escalation': '#aa00ff',
  'defense-evasion':      '#0088ff',
  'credential-access':    '#00aaff',
  'discovery':            '#00ff88',
  'lateral-movement':     '#ff00aa',
  'collection':           '#ff6600',
  'command-and-control':  '#9944ff',
  'exfiltration':         '#ff0066',
  'impact':               '#ff0000',
  'resource-development': '#888888',
  'reconnaissance':       '#44aaff',
};

// ─── MITRE ATT&CK badge ───────────────────────────────────────────────────────
interface MitreBadgeProps {
  technique?: string;
  techniqueName?: string;
  tactic?: string;
  tacticDisplay?: string;
  tacticColor?: string;
}

const MitreBadge: React.FC<MitreBadgeProps> = ({
  technique,
  techniqueName,
  tactic,
  tacticDisplay,
  tacticColor,
}) => {
  if (!technique) return null;
  const color = tacticColor ?? TACTIC_COLORS[tactic ?? ''] ?? '#888888';
  const tooltip = `${techniqueName ?? technique}${tacticDisplay ? ` · ${tacticDisplay}` : ''}`;
  return (
    <Tooltip title={tooltip} arrow placement="top">
      <Box
        sx={{
          display: 'inline-flex',
          alignItems: 'center',
          px: 0.75,
          py: 0.15,
          borderRadius: 0.5,
          borderLeft: `3px solid ${color}`,
          bgcolor: `${color}12`,
          color,
          fontSize: '0.48rem',
          fontWeight: 900,
          fontFamily: 'monospace',
          letterSpacing: 0.5,
          cursor: 'default',
          userSelect: 'none',
          whiteSpace: 'nowrap',
          flexShrink: 0,
        }}
      >
        ATT&amp;CK&nbsp;·&nbsp;{technique}
      </Box>
    </Tooltip>
  );
};

// ─── Enriched Node Rendering ──────────────────────────────────────────────────
const RenderNode: React.FC<{ node: EnrichedNode | undefined; rawId: string; projectSlug?: string }> = ({ node, rawId, projectSlug }) => {
  const { tokens, isLight } = useThemeTokens();
  const theme = useTheme();
  const type = node?.type ?? (rawId.startsWith('vuln::') ? 'Vulnerability' : rawId.startsWith('goal::capability::') ? 'Capability' : rawId.startsWith('goal::privilege::') ? 'Privilege' : 'Asset');
  const subtype = node?.subtype ?? rawId.split('::').pop() ?? '';
  const name = node?.name ?? (type === 'Vulnerability' ? `Vulnerability #${subtype}` : subtype);
  
  let color = tokens.accent.primary;
  let icon = <Server size={14} />;
  let bgColor = isLight ? 'rgba(0, 0, 0, 0.02)' : 'rgba(0, 243, 255, 0.03)';
  let borderColor = isLight ? 'rgba(0, 0, 0, 0.1)' : `${tokens.accent.primary}15`;
  
  if (type === 'Vulnerability') {
    const severity = node?.severity ?? 2;
    const sevColors = [tokens.accent.success, tokens.accent.success, tokens.accent.warning, tokens.accent.warning, tokens.accent.error];
    color = sevColors[severity] ?? tokens.accent.warning;
    icon = <ShieldAlert size={14} />;
    bgColor = `${color}08`;
    borderColor = `${color}20`;
  } else if (type === 'Capability') {
    color = isLight ? '#9c27b0' : '#d500f9';
    icon = <Zap size={14} />;
    bgColor = isLight ? 'rgba(156, 39, 176, 0.03)' : 'rgba(213, 0, 249, 0.03)';
    borderColor = isLight ? 'rgba(156, 39, 176, 0.1)' : 'rgba(213, 0, 249, 0.1)';
  } else if (type === 'Privilege') {
    color = tokens.accent.warning;
    icon = <Key size={14} />;
    bgColor = isLight ? 'rgba(245, 158, 11, 0.03)' : 'rgba(255, 171, 0, 0.03)';
    borderColor = isLight ? 'rgba(245, 158, 11, 0.1)' : 'rgba(255, 171, 0, 0.1)';
  } else if (type === 'Credential') {
    color = tokens.accent.warning;
    icon = <Lock size={14} />;
    bgColor = isLight ? 'rgba(245, 158, 11, 0.03)' : 'rgba(255, 171, 0, 0.03)';
    borderColor = isLight ? 'rgba(245, 158, 11, 0.1)' : 'rgba(255, 171, 0, 0.1)';
  }

  return (
    <Box
      sx={{
        display: 'flex',
        alignItems: 'center',
        gap: 2,
        p: 1.5,
        borderRadius: 1,
        bgcolor: bgColor,
        border: `1px solid ${borderColor}`,
        width: '100%',
        boxShadow: isLight ? '0 4px 12px rgba(0,0,0,0.05)' : `0 4px 12px rgba(0,0,0,0.15)`,
      }}
    >
      <Box
        sx={{
          width: 28,
          height: 28,
          borderRadius: '50%',
          bgcolor: `${color}15`,
          border: `1px solid ${color}33`,
          display: 'flex',
          alignItems: 'center',
          justifyContent: 'center',
          color: color,
          flexShrink: 0,
        }}
      >
        {icon}
      </Box>
      <Box sx={{ flex: 1, minWidth: 0 }}>
        <Stack direction="row" spacing={1} sx={{ alignItems: 'center', mb: 0.3 }}>
          <Typography
            sx={{
              fontSize: '0.55rem',
              fontWeight: 900,
              fontFamily: 'Orbitron',
              color: 'text.secondary',
              letterSpacing: 0.5,
            }}
          >
            {type.toUpperCase()} ({subtype.toUpperCase()})
          </Typography>
          {type === 'Vulnerability' && node?.cvss_score !== undefined && (
            <Chip
              label={`CVSS ${node.cvss_score}`}
              size="small"
              sx={{
                height: 14,
                fontSize: '0.5rem',
                fontFamily: 'monospace',
                bgcolor: 'action.hover',
                color: 'text.primary',
                border: '1px solid',
                borderColor: 'divider',
                '& .MuiChip-label': { px: 0.5 }
              }}
            />
          )}
          {type === 'Vulnerability' && node?.cwe && (
            <Chip
              label={node.cwe}
              size="small"
              sx={{
                height: 14,
                fontSize: '0.5rem',
                fontFamily: 'monospace',
                bgcolor: isLight ? 'rgba(245,158,11,0.08)' : 'rgba(255,159,0,0.08)',
                color: tokens.accent.warning,
                border: '1px solid',
                borderColor: 'divider',
                '& .MuiChip-label': { px: 0.5 }
              }}
            />
          )}
          {type === 'Vulnerability' && node?.technique && (
            <MitreBadge technique={node.technique} />
          )}
        </Stack>
        <Typography
          noWrap
          sx={{
            fontSize: '0.74rem',
            color: 'text.primary',
            fontWeight: 700,
          }}
        >
          {name}
        </Typography>
      </Box>
      {type === 'Vulnerability' && node?.vuln_id && projectSlug && (
        <Button
          size="small"
          component={Link}
          to={`/${projectSlug}/vulns`}
          sx={{
            fontSize: '0.55rem',
            color: color,
            borderColor: `${color}44`,
            border: '1px solid',
            px: 1,
            py: 0,
            height: 20,
            fontFamily: 'Orbitron',
            minWidth: 'auto',
            '&:hover': {
              bgcolor: `${color}11`,
              borderColor: color,
            }
          }}
        >
          VIEW
        </Button>
      )}
    </Box>
  );
};

// ─── Timeline Connector Edge ──────────────────────────────────────────────────
const TimelineConnector: React.FC<{ step: AttackStep }> = ({ step }) => {
  const { tokens, isLight } = useThemeTokens();
  const isValidated = step.validated;
  const edgeColor = isValidated ? tokens.accent.success : tokens.accent.warning;
  const Icon = isValidated ? CheckCircle2 : HelpCircle;

  return (
    <Box sx={{ display: 'flex', flexDirection: 'column', alignItems: 'stretch', my: 0.5, pl: 1.5, position: 'relative', width: '100%' }}>
      <Box
        sx={{
          position: 'absolute',
          left: 14, // align with RenderNode circle center
          top: -10,
          bottom: -10,
          width: 2,
          borderLeft: `2px dashed ${edgeColor}44`,
          zIndex: 0,
        }}
      />

      <Box
        sx={{
          ml: 4,
          p: 1.5,
          borderRadius: 1,
          bgcolor: 'action.hover',
          border: '1px solid',
          borderColor: 'divider',
          zIndex: 1,
        }}
      >
        <Stack direction="row" spacing={1} sx={{ alignItems: 'center', mb: 0.8, flexWrap: 'wrap', gap: 0.5 }}>
          <Chip
            label={step.edge_type}
            size="small"
            sx={{
              height: 16,
              fontSize: '0.55rem',
              fontWeight: 900,
              bgcolor: isLight ? 'rgba(112,0,255,0.08)' : 'rgba(112,0,255,0.1)',
              border: `1px solid ${isLight ? 'rgba(112,0,255,0.2)' : 'rgba(112,0,255,0.2)'}`,
              color: isLight ? '#7c3aed' : '#aa00ff',
              fontFamily: 'Orbitron',
            }}
          />
          <Typography sx={{ fontSize: '0.6rem', color: 'text.disabled', fontWeight: 700 }}>
            CONF: <Box component="span" sx={{ color: tokens.accent.primary }}>{(step.confidence * 100).toFixed(0)}%</Box>
          </Typography>
          <MitreBadge
            technique={step.mitre_technique}
            techniqueName={step.mitre_technique_name}
            tactic={step.mitre_tactic}
            tacticDisplay={step.mitre_tactic_display}
            tacticColor={step.mitre_tactic_color}
          />
          <Stack direction="row" spacing={0.5} sx={{ alignItems: 'center', ml: 'auto' }}>
            <Icon size={10} color={edgeColor} />
            <Typography sx={{ fontSize: '0.55rem', color: edgeColor, fontWeight: 900, fontFamily: 'Orbitron', letterSpacing: 0.5 }}>
              {step.status.toUpperCase()}
            </Typography>
          </Stack>
        </Stack>

        <Typography sx={{ fontSize: '0.7rem', color: 'text.secondary', lineHeight: 1.4 }}>
          {step.action}
        </Typography>
      </Box>
    </Box>
  );
};

// ─── Timeline Assembler ───────────────────────────────────────────────────────
const AttackPathTimeline: React.FC<{ steps: AttackStep[]; projectSlug?: string }> = ({ steps, projectSlug }) => {
  const { tokens } = useThemeTokens();
  if (!steps || steps.length === 0) return null;

  return (
    <Stack spacing={0} sx={{ mt: 1, position: 'relative' }}>
      {steps.map((step, i) => {
        const isLast = i === steps.length - 1;
        return (
          <React.Fragment key={i}>
            <RenderNode node={step.from_node} rawId={step.from} projectSlug={projectSlug} />
            <TimelineConnector step={step} />
            {isLast && (
              <RenderNode node={step.to_node} rawId={step.to} projectSlug={projectSlug} />
            )}
          </React.Fragment>
        );
      })}
    </Stack>
  );
};

// ─── Single attack path card ──────────────────────────────────────────────────
interface AttackPathCardProps {
  path: AttackPath;
  rank: number;
  projectSlug?: string;
}

const AttackPathCard: React.FC<AttackPathCardProps> = ({ path, rank, projectSlug }) => {
  const { tokens, isLight } = useThemeTokens();
  const [expanded, setExpanded] = useState(rank === 0);
  const riskColor = getSeverityColor(path.risk, tokens);
  const validatedCount = path.steps.filter((s) => s.validated).length;
  const inferredCount = path.steps.length - validatedCount;
  const { scanId: scanIdStr } = useParams({ strict: false });
  const scanId = Number(scanIdStr);
  const explainMutation = useExplainAttackPath();

  const handleExplain = async () => {
    if (!scanId || !path.path_id) return;
    try {
      await explainMutation.mutateAsync({ pathId: path.path_id, scanId });
    } catch (err) {
      console.error('Failed to generate path explanation', err);
    }
  };


  return (
    <Box
      sx={{
        borderRadius: 1.5,
        border: `1px solid ${riskColor}30`,
        bgcolor: `${riskColor}08`,
        overflow: 'hidden',
        transition: 'border-color 0.2s',
        '&:hover': { borderColor: `${riskColor}60` },
      }}
    >
      {/* Header */}
      <Stack
        direction="row"
        spacing={1.5}
        sx={{
          alignItems: 'center',
          px: 2,
          py: 1.5,
          cursor: 'pointer',
          '&:hover': { bgcolor: 'action.hover' },
        }}
        onClick={() => setExpanded((p) => !p)}
      >
        {/* Rank */}
        <Box
          sx={{
            width: 28,
            height: 28,
            borderRadius: '50%',
            bgcolor: `${riskColor}20`,
            border: `1px solid ${riskColor}50`,
            display: 'flex',
            alignItems: 'center',
            justifyContent: 'center',
            color: riskColor,
            fontSize: '0.7rem',
            fontWeight: 900,
            fontFamily: 'Orbitron',
            flexShrink: 0,
          }}
        >
          #{rank + 1}
        </Box>

        <Box sx={{ flex: 1, minWidth: 0 }}>
          <Stack direction="row" spacing={1} sx={{ alignItems: 'center', mb: 0.3, flexWrap: 'wrap', gap: 0.5 }}>
            <RiskBadge risk={path.risk} />
            {path.remediation_priority !== undefined && path.remediation_priority !== null && (
              <PriorityBadge priority={path.remediation_priority} />
            )}
            <Typography
              noWrap
              sx={{ fontSize: '0.7rem', color: 'text.secondary', fontFamily: 'monospace', fontStyle: 'italic' }}
            >
              {path.path_id}
            </Typography>
          </Stack>
          <Typography
            sx={{
              fontSize: '0.72rem',
              color: 'text.secondary',
              fontWeight: 700,
              display: '-webkit-box',
              WebkitLineClamp: expanded ? 1 : 2,
              WebkitBoxOrient: 'vertical',
              overflow: 'hidden',
              textOverflow: 'ellipsis',
            }}
          >
            {path.potential_impact}
          </Typography>
        </Box>

        {/* Stats */}
        <Stack direction="row" spacing={{ xs: 1, sm: 2 }} sx={{ alignItems: 'center', flexShrink: 0, ml: 'auto' }}>
          <Tooltip title="Risk score 0–10: weighted combination of CVSS severity, exploitability, attack-chain depth, and lateral movement potential." arrow placement="top">
            <Stack sx={{ alignItems: 'center', cursor: 'help' }}>
              <Typography sx={{ fontSize: { xs: '0.8rem', sm: '1rem' }, fontWeight: 900, color: riskColor, fontFamily: 'Orbitron' }}>
                {path.score.toFixed(2)}<Box component="span" sx={{ fontSize: '0.55rem', color: 'text.disabled', ml: 0.25 }}>/10</Box>
              </Typography>
              <Typography sx={{ fontSize: '0.55rem', color: 'text.disabled', fontWeight: 700 }}>SCORE</Typography>
            </Stack>
          </Tooltip>
          <Stack sx={{ alignItems: 'center' }}>
            <Typography sx={{ fontSize: { xs: '0.8rem', sm: '1rem' }, fontWeight: 900, color: tokens.accent.primary, fontFamily: 'Orbitron' }}>
              {path.step_count}
            </Typography>
            <Typography sx={{ fontSize: '0.55rem', color: 'text.disabled', fontWeight: 700 }}>STEPS</Typography>
          </Stack>
          <IconButton size="small" sx={{ color: 'text.secondary', display: { xs: 'none', sm: 'inline-flex' } }}>
            {expanded ? <ChevronDown size={16} /> : <ChevronRight size={16} />}
          </IconButton>
        </Stack>
      </Stack>

      {/* Step counts bar */}
      <Box sx={{ px: 2, pb: expanded ? 0 : 1 }}>
        <Stack direction="row" spacing={1} sx={{ alignItems: 'center' }}>
          <Chip
            icon={<CheckCircle2 size={10} />}
            label={`${validatedCount} validated`}
            size="small"
            sx={{
              height: 18,
              fontSize: '0.6rem',
              fontWeight: 700,
              bgcolor: isLight ? 'rgba(16,185,129,0.08)' : 'rgba(0,255,98,0.08)',
              border: '1px solid',
              borderColor: isLight ? 'rgba(16,185,129,0.2)' : 'rgba(0,255,98,0.2)',
              color: tokens.accent.success,
              '& .MuiChip-icon': { color: tokens.accent.success, ml: '4px' },
            }}
          />
          <Chip
            icon={<HelpCircle size={10} />}
            label={`${inferredCount} inferred`}
            size="small"
            sx={{
              height: 18,
              fontSize: '0.6rem',
              fontWeight: 700,
              bgcolor: isLight ? 'rgba(245,158,11,0.08)' : 'rgba(255,159,0,0.08)',
              border: '1px solid',
              borderColor: isLight ? 'rgba(245,158,11,0.2)' : 'rgba(255,159,0,0.2)',
              color: tokens.accent.warning,
              '& .MuiChip-icon': { color: tokens.accent.warning, ml: '4px' },
            }}
          />
        </Stack>
      </Box>

      {/* MITRE tactic strip */}
      {path.mitre_tactics && path.mitre_tactics.length > 0 && (
        <Box sx={{ px: 2, pb: expanded ? 0 : 1.5, pt: 0.5 }}>
          <Stack direction="row" spacing={0.5} sx={{ flexWrap: 'wrap', gap: 0.5 }}>
            {path.mitre_tactics.map((tactic) => {
              const color = TACTIC_COLORS[tactic] ?? '#888888';
              const label = tactic.replace(/-/g, ' ').toUpperCase();
              return (
                <Box
                  key={tactic}
                  sx={{
                    display: 'inline-flex',
                    alignItems: 'center',
                    px: 0.75,
                    py: 0.2,
                    borderRadius: 4,
                    bgcolor: `${color}10`,
                    border: `1px solid ${color}30`,
                    color,
                    fontSize: '0.45rem',
                    fontWeight: 900,
                    fontFamily: 'Orbitron',
                    letterSpacing: 0.5,
                    whiteSpace: 'nowrap',
                  }}
                >
                  {label}
                </Box>
              );
            })}
          </Stack>
        </Box>
      )}

      {/* Expanded steps */}
      <Collapse in={expanded}>
        <Divider sx={{ borderColor: `${riskColor}20`, my: 0.5 }} />
        <Box sx={{ px: 2.5, pb: 2.5, pt: 1.5 }}>
          {/* Executive Narrative */}
          <Box
            sx={{
              mb: 3,
              p: 2,
              borderRadius: 1.5,
              bgcolor: isLight ? 'rgba(0,0,0,0.04)' : 'rgba(0, 0, 0, 0.25)',
              border: '1px solid',
              borderColor: 'divider',
            }}
          >
            <Typography
              sx={{
                fontSize: '0.62rem',
                color: riskColor,
                fontWeight: 900,
                fontFamily: 'Orbitron',
                letterSpacing: 1,
                mb: 1.5,
              }}
            >
              EXECUTIVE NARRATIVE
            </Typography>
            <Typography
              sx={{
                fontSize: '0.76rem',
                color: 'text.primary',
                lineHeight: 1.6,
                whiteSpace: 'pre-line',
              }}
            >
              {path.potential_impact}
            </Typography>
          </Box>

          {/* Explain Path Section */}
          <Box
            sx={{
              mb: 3,
              p: 2,
              borderRadius: 1.5,
              bgcolor: isLight ? 'rgba(14, 165, 233, 0.04)' : 'rgba(0, 243, 255, 0.02)',
              border: '1px solid',
              borderColor: isLight ? 'rgba(14, 165, 233, 0.15)' : 'rgba(0, 243, 255, 0.08)',
            }}
          >
            <Stack direction="row" sx={{ justifyContent: 'space-between', alignItems: 'center', mb: 1.5 }}>
              <Typography
                sx={{
                  fontSize: '0.62rem',
                  color: tokens.accent.primary,
                  fontWeight: 900,
                  fontFamily: 'Orbitron',
                  letterSpacing: 1,
                }}
              >
                TACTICAL AI EXPLANATION
              </Typography>
              {!path.explanation && (
                <Button
                  size="small"
                  variant="outlined"
                  onClick={handleExplain}
                  disabled={explainMutation.isPending}
                  startIcon={explainMutation.isPending ? <CircularProgress size={10} color="inherit" /> : <Brain size={12} />}
                  sx={{
                    fontSize: '0.55rem',
                    height: 20,
                    borderColor: `${tokens.accent.primary}4D`,
                    color: tokens.accent.primary,
                    fontFamily: 'Orbitron',
                    '&:hover': {
                      borderColor: tokens.accent.primary,
                      bgcolor: `${tokens.accent.primary}0D`,
                    },
                  }}
                >
                  {explainMutation.isPending ? 'GENERATING...' : 'EXPLAIN THIS'}
                </Button>
              )}
            </Stack>
            {path.explanation ? (
              <Typography
                sx={{
                  fontSize: '0.74rem',
                  color: 'text.secondary',
                  lineHeight: 1.6,
                  whiteSpace: 'pre-line',
                }}
              >
                {path.explanation}
              </Typography>
            ) : (
              <Typography
                sx={{
                  fontSize: '0.7rem',
                  color: 'text.secondary',
                  fontStyle: 'italic',
                }}
              >
                {explainMutation.isPending
                  ? 'Analyzing tactical vector patterns. This may take up to a minute...'
                  : 'Click "EXPLAIN THIS" to generate an in-depth, step-by-step intelligence breakdown of this attack vector.'}
              </Typography>
            )}
          </Box>


          <Typography
            sx={{ fontSize: '0.6rem', color: 'text.disabled', fontWeight: 800, mb: 2, letterSpacing: 1 }}
          >
            COMPROMISE CHAIN TIMELINE
          </Typography>
          
          <AttackPathTimeline steps={path.steps} projectSlug={projectSlug} />
          
          {path.steps.length > 0 && scanId && (
            <AttackTreeViewer scanId={scanId} targetId={path.steps[path.steps.length - 1].to} />
          )}
        </Box>
      </Collapse>
    </Box>
  );
};

// ─── Risk Summary Bar ─────────────────────────────────────────────────────────
const RiskSummaryBar: React.FC<{ paths: AttackPath[] }> = ({ paths }) => {
  const { tokens } = useThemeTokens();
  const counts = { critical: 0, high: 0, medium: 0, low: 0 };
  paths.forEach((p) => {
    if (p.risk in counts) counts[p.risk as keyof typeof counts]++;
  });
  const items = [
    { label: 'CRITICAL', count: counts.critical, color: tokens.accent.error },
    { label: 'HIGH',     count: counts.high,     color: '#f97316' },
    { label: 'MEDIUM',   count: counts.medium,   color: tokens.accent.warning },
    { label: 'LOW',      count: counts.low,      color: tokens.accent.success },
  ];
  return (
    <Box
      sx={{
        display: 'grid',
        gridTemplateColumns: 'repeat(4, 1fr)',
        gap: 1.5,
        mb: 2,
        p: 1.5,
        borderRadius: 1,
        border: 1,
        borderColor: 'divider',
        bgcolor: 'action.hover',
      }}
    >
      {items.map(({ label, count, color }) => (
        <Box key={label} sx={{ textAlign: 'center' }}>
          <Typography sx={{ fontSize: '1.2rem', fontWeight: 900, color, fontFamily: 'Orbitron', lineHeight: 1 }}>
            {count}
          </Typography>
          <Typography sx={{ fontSize: '0.5rem', color: 'text.disabled', fontWeight: 700, letterSpacing: 1, mt: 0.5 }}>
            {label}
          </Typography>
        </Box>
      ))}
    </Box>
  );
};

// ─── Priority badge ───────────────────────────────────────────────────────────
const PRIORITY_LABEL: Record<number, string> = { 1: 'LOW', 2: 'MED', 3: 'HIGH', 4: 'CRITICAL' };
const PRIORITY_COLOR = (tokens: ReturnType<typeof useThemeTokens>['tokens'], p: number): string =>
  p >= 4 ? tokens.accent.error : p === 3 ? '#f97316' : p === 2 ? tokens.accent.warning : tokens.accent.success;

const PriorityBadge: React.FC<{ priority: number }> = ({ priority }) => {
  const { tokens } = useThemeTokens();
  const color = PRIORITY_COLOR(tokens, priority);
  const label = PRIORITY_LABEL[priority] ?? String(priority);
  return (
    <Tooltip title={`Remediation priority: ${label}`} arrow placement="top">
      <Box
        sx={{
          display: 'inline-flex',
          alignItems: 'center',
          gap: 0.3,
          px: 0.75,
          py: 0.15,
          borderRadius: 0.5,
          bgcolor: `${color}15`,
          border: `1px solid ${color}40`,
          color,
          fontSize: '0.5rem',
          fontWeight: 900,
          fontFamily: 'Orbitron',
          letterSpacing: 0.5,
          cursor: 'default',
        }}
      >
        P{priority}
      </Box>
    </Tooltip>
  );
};

// ─── Speculative paths section ────────────────────────────────────────────────
const SpeculativePathsSection: React.FC<{ paths: AttackPath[]; projectSlug?: string }> = ({ paths, projectSlug }) => {
  const { tokens } = useThemeTokens();
  const [open, setOpen] = useState(false);
  if (!paths || paths.length === 0) return null;

  return (
    <Box
      sx={{
        mt: 3,
        borderRadius: 1.5,
        border: `1px solid ${tokens.accent.warning}30`,
        bgcolor: `${tokens.accent.warning}06`,
        overflow: 'hidden',
      }}
    >
      <Stack
        direction="row"
        spacing={1.5}
        sx={{
          px: 2,
          py: 1.5,
          alignItems: 'center',
          cursor: 'pointer',
          '&:hover': { bgcolor: 'action.hover' },
        }}
        onClick={() => setOpen((p) => !p)}
      >
        <HelpCircle size={16} color={tokens.accent.warning} />
        <Box sx={{ flex: 1 }}>
          <Typography sx={{ fontSize: '0.65rem', fontWeight: 900, fontFamily: 'Orbitron', color: tokens.accent.warning, letterSpacing: 1 }}>
            SPECULATIVE PATHS — {paths.length} AI-DERIVED
          </Typography>
          <Typography sx={{ fontSize: '0.65rem', color: 'text.secondary' }}>
            Hypothetical attack chains derived by AI with no direct vulnerability evidence. Use for proactive hardening.
          </Typography>
        </Box>
        <IconButton size="small" sx={{ color: tokens.accent.warning }}>
          {open ? <ChevronDown size={16} /> : <ChevronRight size={16} />}
        </IconButton>
      </Stack>

      <Collapse in={open}>
        <Divider sx={{ borderColor: `${tokens.accent.warning}20` }} />
        <Box sx={{ p: 2 }}>
          <Stack spacing={1.5}>
            {paths.map((path, i) => (
              <AttackPathCard key={path.path_id} path={path} rank={i} projectSlug={projectSlug} />
            ))}
          </Stack>
        </Box>
      </Collapse>
    </Box>
  );
};

// ─── Empty state ──────────────────────────────────────────────────────────────
const EmptyState: React.FC = () => {
  const { tokens } = useThemeTokens();
  return (
  <Box
    sx={{
      py: 8,
      textAlign: 'center',
      display: 'flex',
      flexDirection: 'column',
      alignItems: 'center',
      gap: 2,
      opacity: 0.5,
    }}
  >
    <GitBranch size={48} color={tokens.accent.primary} />
    <Box>
      <Typography sx={{ fontSize: '0.9rem', fontWeight: 800, color: 'text.primary', mb: 0.5 }}>
        No Attack Paths Found
      </Typography>
      <Typography sx={{ fontSize: '0.75rem', color: 'text.secondary', maxWidth: 320, mx: 'auto' }}>
        The Attack Path Modeling Engine (APME) runs automatically after vulnerability scanning.
        No exploitable paths were detected for this scan.
      </Typography>
    </Box>
  </Box>
);
};

// ─── Main Tab ─────────────────────────────────────────────────────────────────
interface AttackPathsTabProps {
  scanId: number;
}

export const AttackPathsTab: React.FC<AttackPathsTabProps> = ({ scanId }) => {
  const { tokens, isLight } = useThemeTokens();
  const { data, isLoading, isError, refetch } = useAttackPaths(scanId);
  const triggerAi = useTriggerAttackPathModeling();
  const recalculatePaths = useRecalculateAttackPaths();
  const { projectSlug } = useParams({ strict: false });

  const [snackbar, setSnackbar] = useState<{ open: boolean; message: string; severity: 'success' | 'error' }>({
    open: false,
    message: '',
    severity: 'success'
  });

  const handleTriggerAi = async () => {
    try {
      await triggerAi.mutateAsync(scanId);
      setSnackbar({ open: true, message: 'AI Modeling initiated in background', severity: 'success' });
      // Refresh after a delay to see if results started appearing
      setTimeout(refetch, 5000);
    } catch {
      setSnackbar({ open: true, message: 'Failed to trigger AI modeling', severity: 'error' });
    }
  };

  const handleRecalculatePaths = async () => {
    try {
      await recalculatePaths.mutateAsync(scanId);
      setSnackbar({ open: true, message: 'Recalculation initiated in background', severity: 'success' });
      // Refresh after a delay
      setTimeout(refetch, 5000);
    } catch {
      setSnackbar({ open: true, message: 'Failed to trigger recalculation', severity: 'error' });
    }
  };

  return (
    <TacticalPanel
      title="ATTACK PATH MODELING"
      icon={<ShieldAlert size={14} color={tokens.accent.error} />}
      headerAction={
        <Stack direction={{ xs: 'column', sm: 'row' }} spacing={2} sx={{ alignItems: { xs: 'flex-start', sm: 'center' }, gap: 1 }}>
          <Button
            size="small"
            variant="outlined"
            onClick={handleRecalculatePaths}
            disabled={recalculatePaths.isPending}
            startIcon={recalculatePaths.isPending ? <CircularProgress size={12} /> : <GitBranch size={14} />}
            sx={{
              fontSize: '0.6rem',
              height: 24,
              borderColor: `${tokens.accent.primary}4D`,
              color: tokens.accent.primary,
              fontFamily: 'Orbitron',
              '&:hover': {
                borderColor: tokens.accent.primary,
                bgcolor: `${tokens.accent.primary}0D`,
              },
            }}
          >
            {recalculatePaths.isPending ? 'RECALCULATING...' : 'RE-CALCULATE PATHS'}
          </Button>
          <Button
            size="small"
            variant="outlined"
            onClick={handleTriggerAi}
            disabled={triggerAi.isPending}
            startIcon={triggerAi.isPending ? <CircularProgress size={12} /> : <Bot size={14} />}
            sx={{
              fontSize: '0.6rem',
              height: 24,
              borderColor: `${tokens.accent.primary}4D`,
              color: tokens.accent.primary,
              fontFamily: 'Orbitron',
              '&:hover': {
                borderColor: tokens.accent.primary,
                bgcolor: `${tokens.accent.primary}0D`,
              },
            }}
          >
            {triggerAi.isPending ? 'MODELING...' : 'TRIGGER AI MODELING'}
          </Button>
          {data && data.total_paths > 0 && (
            <Stack direction="row" spacing={1} sx={{ alignItems: 'center' }}>
              <Zap size={12} color={tokens.accent.warning} />
              <Typography sx={{ fontSize: '0.65rem', color: tokens.accent.warning, fontWeight: 900, fontFamily: 'Orbitron' }}>
                {data.total_paths} PATHS FOUND
              </Typography>
            </Stack>
          )}
        </Stack>
      }
    >
      <Box sx={{ p: 2 }}>
        {/* Legend */}
        <Stack
          direction="row"
          spacing={2}
          sx={{
            mb: 2,
            p: 1.5,
            borderRadius: 1,
            bgcolor: isLight ? 'rgba(0,0,0,0.02)' : 'rgba(0,0,0,0.3)',
            border: 1, borderColor: 'divider',
            flexWrap: 'wrap',
            gap: 1,
          }}
        >
          <Stack direction="row" spacing={0.75} sx={{ alignItems: 'center' }}>
            <CheckCircle2 size={12} color={tokens.accent.success} />
            <Typography sx={{ fontSize: '0.65rem', color: 'text.secondary', fontWeight: 600 }}>
              <Box component="span" sx={{ color: tokens.accent.success, fontWeight: 800 }}>Validated</Box>
              {' — ERL-confirmed with direct evidence'}
            </Typography>
          </Stack>
          <Stack direction="row" spacing={0.75} sx={{ alignItems: 'center' }}>
            <HelpCircle size={12} color={tokens.accent.warning} />
            <Typography sx={{ fontSize: '0.65rem', color: 'text.secondary', fontWeight: 600 }}>
              <Box component="span" sx={{ color: tokens.accent.warning, fontWeight: 800 }}>Inferred</Box>
              {' — Rule-derived, no direct exploit evidence'}
            </Typography>
          </Stack>
          <Stack direction="row" spacing={0.75} sx={{ alignItems: 'center' }}>
            <AlertTriangle size={12} color={tokens.accent.error} />
            <Typography sx={{ fontSize: '0.65rem', color: 'text.secondary', fontWeight: 600 }}>
              Paths sorted by risk score (highest first)
            </Typography>
          </Stack>
          <Stack direction="row" spacing={0.75} sx={{ alignItems: 'center' }}>
            <Box sx={{
              display: 'inline-flex', px: 0.5, py: 0.1, borderRadius: 0.5,
              borderLeft: '3px solid #ff4444', bgcolor: 'rgba(255,68,68,0.08)',
              color: '#ff4444', fontSize: '0.5rem', fontWeight: 900, fontFamily: 'monospace',
            }}>
              ATT&amp;CK · T1190
            </Box>
            <Typography sx={{ fontSize: '0.65rem', color: 'text.secondary', fontWeight: 600 }}>
              <Box component="span" sx={{ color: '#ff4444', fontWeight: 800 }}>MITRE ATT&amp;CK</Box>
              {' — technique badge, colored by tactic'}
            </Typography>
          </Stack>
        </Stack>

        {/* Content */}
        {isLoading && (
          <Box sx={{ py: 6, textAlign: 'center' }}>
            <CircularProgress size={32} sx={{ color: tokens.accent.primary }} />
            <Typography sx={{ mt: 2, fontSize: '0.75rem', color: 'text.secondary' }}>
              Loading attack paths...
            </Typography>
          </Box>
        )}

        {isError && (
          <Box
            sx={{
              p: 2,
              bgcolor: isLight ? 'rgba(239, 68, 68, 0.08)' : 'rgba(255,0,60,0.05)',
              border: '1px solid',
              borderColor: 'error.main',
              borderRadius: 1,
              textAlign: 'center',
            }}
          >
            <Typography sx={{ fontSize: '0.75rem', color: tokens.accent.error, fontWeight: 700 }}>
              Failed to load attack paths. The APME may not have completed for this scan.
            </Typography>
          </Box>
        )}

        {!isLoading && !isError && data && (
          data.total_paths === 0 ? (
            <EmptyState />
          ) : (
            <>
              <RiskSummaryBar paths={data.paths} />
              <Stack spacing={1.5}>
                {data.paths.map((path, i) => (
                  <AttackPathCard key={path.path_id} path={path} rank={i} projectSlug={projectSlug} />
                ))}
              </Stack>
              {data.speculative_paths && data.speculative_paths.length > 0 && (
                <SpeculativePathsSection paths={data.speculative_paths} projectSlug={projectSlug} />
              )}
            </>
          )
        )}
      </Box>

      <Snackbar
        open={snackbar.open}
        autoHideDuration={5000}
        onClose={() => setSnackbar({ ...snackbar, open: false })}
        anchorOrigin={{ vertical: 'bottom', horizontal: 'right' }}
      >
        <Alert
          onClose={() => setSnackbar({ ...snackbar, open: false })}
          severity={snackbar.severity}
          variant="filled"
          sx={{
            fontFamily: 'Orbitron',
            fontSize: '0.8rem',
            fontWeight: 700,
            bgcolor: snackbar.severity === 'success' ? tokens.accent.success : tokens.accent.error,
            color: '#fff',
            border: '1px solid',
            borderColor: 'divider',
            '& .MuiAlert-icon': { color: '#fff' }
          }}
        >
          {snackbar.message}
        </Alert>
      </Snackbar>
    </TacticalPanel>
  );
};
