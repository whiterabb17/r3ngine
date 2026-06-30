import React, { useEffect, useRef, useState, useCallback } from 'react';
import {
  Box,
  Typography,
  CircularProgress,
  Stack,
  Button,
  Divider,
  Chip,
  IconButton,
  Tooltip
} from '@mui/material';
import {
  Maximize,
  RefreshCw,
  Download,
  ShieldAlert,
  Target,
  Activity,
  Bot
} from 'lucide-react';
import cytoscape from 'cytoscape';
import { TacticalPanel } from '../../../components/TacticalPanel';
import { useImpactGraphData, useImpactAssessment, useGenerateImpact } from '../api';
import { useThemeTokens } from '../../../theme/useThemeTokens';

interface ImpactExplorerProps {
  projectSlug: string;
  vulnId: number;
  vulnName: string;
  autoGenerate?: boolean;
}

export const ImpactExplorer: React.FC<ImpactExplorerProps> = ({ projectSlug, vulnId, vulnName, autoGenerate }) => {
  const containerRef = useRef<HTMLDivElement>(null);
  const cyRef = useRef<cytoscape.Core | null>(null);
  const [graphLoading, setGraphLoading] = useState(true);

  const { tokens, isLight } = useThemeTokens();

  const graphColors = {
    nodeBg:           isLight ? '#e2e8f0' : '#1e293b',
    nodeText:         isLight ? '#0f172a' : '#ffffff',
    nodeBorder:       tokens.accent.primary,
    edge:             tokens.accent.primary,
    domainNode:       '#0ea5e9',
    vulnNode:         '#ef4444',
    subdomainNode:    '#10b981',
    ipNode:           '#f59e0b',
    canvasBg:         isLight ? '#f8fafc' : '#0f172a',
    certificateNode:  '#06b6d4',
    identityNode:     '#a855f7',
    apiEndpointNode:  '#ec4899',
    applicationNode:  '#0d9488',
    organizationNode: '#d97706',
  };

  const { data: graphData, isLoading: isGraphDataLoading } = useImpactGraphData(projectSlug, vulnId);
  const { data: assessment, isLoading: isAssessmentLoading } = useImpactAssessment(projectSlug, vulnId);

  function initGraph(elements: unknown) {
    if (!containerRef.current) return;

    if (cyRef.current) {
      cyRef.current.destroy();
    }

    cyRef.current = cytoscape({
      container: containerRef.current,
      elements: elements as cytoscape.ElementsDefinition,
      style: [
        {
          selector: 'node',
          style: {
            'label': 'data(label)',
            'background-color': graphColors.nodeBg,
            'color': graphColors.nodeText,
            'font-size': '10px',
            'font-family': 'Inter, sans-serif',
            'text-valign': 'bottom',
            'text-margin-y': 5,
            'width': 35,
            'height': 35,
            'border-width': 2,
            'border-color': graphColors.nodeBorder,
            'border-opacity': 0.5,
            'overlay-padding': 6,
          }
        },
        {
          selector: 'node[type = "Domain"]',
          style: {
            'width': 55,
            'height': 55,
            'shape': 'diamond',
            'background-color': graphColors.domainNode,
            'border-color': graphColors.nodeText,
            'font-weight': 'bold',
            'font-size': '12px',
          }
        },
        {
          selector: 'node[type = "Vulnerability"]',
          style: {
            'width': 50,
            'height': 50,
            'shape': 'star',
            'background-color': graphColors.vulnNode,
            'border-color': graphColors.nodeText,
            'font-weight': 'bold',
            'font-size': '12px',
          }
        },
        {
          selector: 'node[type = "Subdomain"]',
          style: { 'background-color': graphColors.subdomainNode }
        },
        {
          selector: 'node[type = "IpAddress"]',
          style: { 'background-color': graphColors.ipNode }
        },
        {
          selector: 'node[type = "Certificate"]',
          style: { 'background-color': graphColors.certificateNode }
        },
        {
          selector: 'node[type = "IdentityInfra"]',
          style: { 'background-color': graphColors.identityNode }
        },
        {
          selector: 'node[type = "APIEndpoint"]',
          style: { 'background-color': graphColors.apiEndpointNode }
        },
        {
          selector: 'node[type = "Application"]',
          style: { 'background-color': graphColors.applicationNode }
        },
        {
          selector: 'node[type = "Organization"]',
          style: { 'background-color': graphColors.organizationNode }
        },
        {
          selector: 'edge',
          style: {
            'width': 2,
            'line-color': graphColors.edge,
            'target-arrow-color': graphColors.edge,
            'target-arrow-shape': 'triangle',
            'curve-style': 'bezier',
            'opacity': 0.6,
            'arrow-scale': 1.2
          }
        }
      ],
      layout: {
        name: 'breadthfirst',
        directed: true,
        padding: 50,
        animate: true,
      }
    });

    setGraphLoading(false);
  }

  useEffect(() => {
    if (graphData && containerRef.current) {
      initGraph(graphData);
    }
    return () => {
      if (cyRef.current) {
        cyRef.current.destroy();
        cyRef.current = null;
      }
    };
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [graphData, isLight]);

  const generateImpactMutation = useGenerateImpact(projectSlug);

  const handleTriggerAiImpact = useCallback(async () => {
    try {
      await generateImpactMutation.mutateAsync(vulnId);
    } catch (error) {
      console.error('Failed to trigger impact generation:', error);
    }
  }, [vulnId, generateImpactMutation]);

  const [hasAutoGenerated, setHasAutoGenerated] = useState(false);

  useEffect(() => {
    if (autoGenerate && assessment && assessment.status === false && !generateImpactMutation.isPending && !hasAutoGenerated) {
      setHasAutoGenerated(true);
      handleTriggerAiImpact();
    }
  }, [autoGenerate, assessment, handleTriggerAiImpact, hasAutoGenerated]);

  const resetZoom = () => cyRef.current?.fit(undefined, 50);
  const exportPNG = () => {
    if (!cyRef.current) return;
    const pngContent = cyRef.current.png({ full: true, bg: graphColors.canvasBg });
    const link = document.createElement('a');
    link.href = pngContent;
    link.download = `impact-path-${vulnId}.png`;
    link.click();
  };

  return (
    <Box sx={{ width: '100%', display: 'flex', flexDirection: 'column', gap: 3 }}>
      <Box sx={{ display: 'grid', gridTemplateColumns: { xs: '1fr', lg: '1fr 350px' }, gap: 3 }}>

        {/* Left: Graph Visualization */}
        <Box sx={{ display: 'flex', flexDirection: 'column', gap: 2 }}>
          <TacticalPanel
            title="ATTACK PATH VISUALIZATION"
            icon={<Target size={14} />}
            headerAction={
              <Stack direction="row" spacing={1}>
                <Tooltip title="Reset Zoom">
                  <IconButton size="small" onClick={resetZoom} sx={{ color: tokens.accent.primary }}>
                    <Maximize size={16} />
                  </IconButton>
                </Tooltip>
                <Tooltip title="Export PNG">
                  <IconButton size="small" onClick={exportPNG} sx={{ color: tokens.accent.success }}>
                    <Download size={16} />
                  </IconButton>
                </Tooltip>
              </Stack>
            }
          >
            <Box sx={{ position: 'relative', bgcolor: graphColors.canvasBg, height: '500px', borderRadius: 1, overflow: 'hidden' }}>
              {(isGraphDataLoading || graphLoading) && (
                <Box sx={{
                  position: 'absolute', inset: 0, display: 'flex', justifyContent: 'center', alignItems: 'center', zIndex: 5,
                  bgcolor: isLight ? 'rgba(248, 250, 252, 0.5)' : 'rgba(15, 23, 42, 0.5)'
                }}>
                  <CircularProgress sx={{ color: tokens.accent.primary }} />
                </Box>
              )}
              <div ref={containerRef} style={{ width: '100%', height: '100%' }} />

              {/* Graph Legend Overlay */}
              <Box sx={{
                position: 'absolute',
                bottom: 15,
                left: 15,
                bgcolor: isLight ? 'rgba(248,250,252,0.92)' : 'rgba(30, 41, 59, 0.9)',
                p: 1.5,
                borderRadius: 1,
                border: '1px solid',
                borderColor: 'divider',
                backdropFilter: 'blur(4px)'
              }}>
                <Typography sx={{ fontSize: '0.6rem', color: 'text.disabled', fontWeight: 900, mb: 1, letterSpacing: 1 }}>LEGEND</Typography>
                <Stack spacing={0.5}>
                  <LegendItem color="#0ea5e9" label="Root Domain" />
                  <LegendItem color="#10b981" label="Subdomain" />
                  <LegendItem color="#f59e0b" label="IP / Node" />
                  <LegendItem color="#ef4444" label="Vulnerability" />
                </Stack>
              </Box>
            </Box>
          </TacticalPanel>
        </Box>

        {/* Right: AI Impact Intelligence */}
        <Box sx={{ display: 'flex', flexDirection: 'column', gap: 2 }}>
          <TacticalPanel
            title="IMPACT INTELLIGENCE"
            icon={<Bot size={14} />}
            headerAction={
              assessment?.status && (
                <Tooltip title="Regenerate Assessment">
                  <IconButton
                    size="small"
                    onClick={handleTriggerAiImpact}
                    disabled={generateImpactMutation.isPending}
                    sx={{ color: tokens.accent.primary }}
                  >
                    {generateImpactMutation.isPending ? <CircularProgress size={14} /> : <RefreshCw size={14} />}
                  </IconButton>
                </Tooltip>
              )
            }
          >
            <Box sx={{ p: 2, display: 'flex', flexDirection: 'column', gap: 2, position: 'relative', minHeight: 200 }}>
              {/* Assessing Overlay */}
              {(generateImpactMutation.isPending || (assessment && assessment.status === false && autoGenerate)) && (
                <Box sx={{
                  position: 'absolute',
                  inset: 0,
                  bgcolor: isLight ? 'rgba(255,255,255,0.92)' : 'rgba(15, 23, 42, 0.9)',
                  zIndex: 10,
                  display: 'flex',
                  flexDirection: 'column',
                  alignItems: 'center',
                  justifyContent: 'center',
                  gap: 3,
                  backdropFilter: 'blur(8px)',
                  borderRadius: 1,
                  border: '1px solid',
                  borderColor: `${tokens.accent.primary}33`
                }}>
                  <Box sx={{ position: 'relative' }}>
                    <CircularProgress size={60} thickness={2} sx={{ color: tokens.accent.primary }} />
                    <Bot size={24} color={tokens.accent.primary} style={{ position: 'absolute', top: '50%', left: '50%', transform: 'translate(-50%, -50%)' }} />
                  </Box>
                  <Box sx={{ textAlign: 'center' }}>
                    <Typography sx={{ color: 'text.primary', fontFamily: 'Orbitron', fontWeight: 900, letterSpacing: 2, fontSize: '0.8rem', mb: 1 }}>
                      ASSESSING IMPACT
                    </Typography>
                    <Typography sx={{ color: 'text.secondary', fontSize: '0.65rem', fontWeight: 600 }}>
                      AI is analyzing the attack path and calculating risk...
                    </Typography>
                  </Box>
                  <Stack direction="row" spacing={1}>
                    <Box className="scanning-dot" sx={{ width: 4, height: 4, borderRadius: '50%', bgcolor: tokens.accent.primary, animation: 'pulse 1.5s infinite 0s' }} />
                    <Box className="scanning-dot" sx={{ width: 4, height: 4, borderRadius: '50%', bgcolor: tokens.accent.primary, animation: 'pulse 1.5s infinite 0.2s' }} />
                    <Box className="scanning-dot" sx={{ width: 4, height: 4, borderRadius: '50%', bgcolor: tokens.accent.primary, animation: 'pulse 1.5s infinite 0.4s' }} />
                  </Stack>
                </Box>
              )}

              {isAssessmentLoading ? (
                <Box sx={{ display: 'flex', flexDirection: 'column', alignItems: 'center', py: 4, gap: 2 }}>
                  <CircularProgress size={24} sx={{ color: tokens.accent.primary }} />
                  <Typography sx={{ fontSize: '0.7rem', color: 'text.secondary', fontWeight: 600 }}>Analyzing findings...</Typography>
                </Box>
              ) : assessment?.status ? (
                <>
                  <Box>
                    <Typography sx={{ fontSize: '0.65rem', color: tokens.accent.primary, fontWeight: 900, mb: 1, fontFamily: 'Orbitron' }}>
                      POTENTIAL IMPACT
                    </Typography>
                    <Typography sx={{ fontSize: '0.8rem', color: 'text.primary', lineHeight: 1.6 }}>
                      {assessment.potential_impact}
                    </Typography>
                  </Box>

                  <Divider sx={{ borderColor: 'divider' }} />

                  <Box sx={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
                    <Typography sx={{ fontSize: '0.65rem', color: tokens.accent.primary, fontWeight: 900, fontFamily: 'Orbitron' }}>
                      REMEDIATION PRIORITY
                    </Typography>
                    <Chip
                      label={getPriorityLabel(assessment.remediation_priority)}
                      size="small"
                      sx={{
                        height: 20,
                        fontSize: '0.6rem',
                        fontWeight: 900,
                        bgcolor: getPriorityColor(assessment.remediation_priority),
                        color: '#fff',
                        fontFamily: 'Orbitron'
                      }}
                    />
                  </Box>

                  <Divider sx={{ borderColor: 'divider' }} />

                  {assessment.potential_attack_chain && (
                    <Box>
                      <Typography sx={{ fontSize: '0.65rem', color: tokens.accent.primary, fontWeight: 900, mb: 2, fontFamily: 'Orbitron' }}>
                        POTENTIAL ATTACK CHAIN
                      </Typography>
                      <Stack spacing={1.5}>
                        {assessment.potential_attack_chain.steps?.map((step, idx) => (
                          <Box key={idx} sx={{ position: 'relative', pl: 3 }}>
                            {idx < assessment.potential_attack_chain!.steps.length - 1 && (
                              <Box sx={{
                                position: 'absolute',
                                left: 7,
                                top: 15,
                                bottom: -10,
                                width: '2px',
                                bgcolor: `${tokens.accent.primary}33`,
                                zIndex: 0
                              }} />
                            )}
                            <Box sx={{
                              position: 'absolute',
                              left: 0,
                              top: 0,
                              width: 16,
                              height: 16,
                              borderRadius: '50%',
                              bgcolor: graphColors.canvasBg,
                              border: '2px solid',
                              borderColor: tokens.accent.primary,
                              display: 'flex',
                              alignItems: 'center',
                              justifyContent: 'center',
                              zIndex: 1
                            }}>
                              <Typography sx={{ fontSize: '0.5rem', fontWeight: 900 }}>{idx + 1}</Typography>
                            </Box>
                            <Typography sx={{ fontSize: '0.65rem', color: tokens.accent.primary, fontWeight: 800, mb: 0.5, letterSpacing: 0.5 }}>
                              {step.phase.toUpperCase()}
                            </Typography>
                            <Typography sx={{ fontSize: '0.75rem', color: 'text.secondary', lineHeight: 1.4 }}>
                              {step.description}
                            </Typography>
                          </Box>
                        ))}
                      </Stack>
                      {assessment.potential_attack_chain.confidence && (
                        <Box sx={{ mt: 2, p: 1, bgcolor: `${tokens.accent.primary}0D`, borderRadius: 0.5, border: '1px solid', borderColor: `${tokens.accent.primary}1A` }}>
                          <Typography sx={{ fontSize: '0.6rem', color: tokens.accent.primary, fontWeight: 700 }}>
                            CONFIDENCE: {assessment.potential_attack_chain.confidence.toUpperCase()}
                          </Typography>
                        </Box>
                      )}
                    </Box>
                  )}

                  <Box sx={{ mt: 'auto', pt: 2 }}>
                    <Stack direction="row" spacing={1} sx={{ alignItems: "center" }}>
                      <Activity size={12} color={tokens.text.disabled} />
                      <Typography sx={{ fontSize: '0.6rem', color: 'text.disabled', fontWeight: 600 }}>
                        Generated at: {new Date(assessment.created_at ?? '').toLocaleString()}
                      </Typography>
                    </Stack>
                    {assessment.is_ai_generated && (
                      <Stack direction="row" spacing={1} sx={{ alignItems: "center", mt: 0.5 }}>
                        <Bot size={12} color={tokens.accent.success} />
                        <Typography sx={{ fontSize: '0.6rem', color: tokens.accent.success, fontWeight: 700 }}>
                          AI-DRIVEN ASSESSMENT
                        </Typography>
                      </Stack>
                    )}
                  </Box>
                </>
              ) : (
                <Box sx={{ display: 'flex', flexDirection: 'column', alignItems: 'center', py: 4, textAlign: 'center', gap: 2 }}>
                  <ShieldAlert size={32} color={tokens.text.disabled} />
                  <Typography sx={{ fontSize: '0.75rem', color: 'text.disabled', fontWeight: 600 }}>
                    No impact assessment found for this vulnerability.
                  </Typography>
                  <Button
                    variant="outlined"
                    size="small"
                    onClick={handleTriggerAiImpact}
                    disabled={generateImpactMutation.isPending}
                    startIcon={generateImpactMutation.isPending ? <CircularProgress size={14} /> : <RefreshCw size={14} />}
                    sx={{
                      borderColor: `${tokens.accent.primary}4D`,
                      color: tokens.accent.primary,
                      fontSize: '0.65rem',
                      fontWeight: 900,
                      fontFamily: 'Orbitron'
                    }}
                  >
                    GENERATE NOW
                  </Button>
                </Box>
              )}
            </Box>
          </TacticalPanel>
        </Box>
      </Box>
    </Box>
  );
};

const LegendItem = ({ color, label }: { color: string, label: string }) => (
  <Stack direction="row" spacing={1} sx={{ alignItems: "center" }}>
    <Box sx={{ width: 8, height: 8, borderRadius: 0.5, bgcolor: color }} />
    <Typography sx={{ fontSize: '0.6rem', color: 'text.secondary', fontWeight: 600 }}>{label}</Typography>
  </Stack>
);

const getPriorityLabel = (p: number | undefined) => {
  if (!p) return 'LOW';
  if (p >= 4) return 'CRITICAL';
  if (p === 3) return 'HIGH';
  if (p === 2) return 'MEDIUM';
  return 'LOW';
};

const getPriorityColor = (p: number | undefined) => {
  if (!p) return '#10b981';
  if (p >= 4) return '#ef4444';
  if (p === 3) return '#f97316';
  if (p === 2) return '#f59e0b';
  return '#10b981';
};
