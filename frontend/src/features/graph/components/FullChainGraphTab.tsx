import React, { useState } from 'react';
import {
  Box,
  Typography,
  CircularProgress,
  Stack,
  Chip,
} from '@mui/material';
import {
  Network,
  Building2,
  Globe,
  Server,
  Shield,
  Key,
  Code,
  AlertTriangle,
} from 'lucide-react';
import { useThemeTokens } from '../../../theme/useThemeTokens';
import {
  useFullChainGraph,
  useChainNodesByType,
  type ChainGraphNode,
} from '../api/useFullChainGraph';

interface FullChainGraphTabProps {
  scanId: number;
}

const NODE_TYPE_META: Record<
  string,
  { label: string; icon: React.ReactNode; color: string }
> = {
  Organization:  { label: 'Organization',   icon: <Building2 size={14} />,     color: '#d97706' },
  Subdomain:     { label: 'Subdomain',      icon: <Globe size={14} />,         color: '#3b82f6' },
  IPAddress:     { label: 'IP Address',     icon: <Server size={14} />,        color: '#6b7280' },
  Application:   { label: 'Application',   icon: <Code size={14} />,          color: '#0d9488' },
  Technology:    { label: 'Technology',    icon: <Server size={14} />,        color: '#8b5cf6' },
  Certificate:   { label: 'Certificate',   icon: <Shield size={14} />,        color: '#06b6d4' },
  IdentityInfra: { label: 'Identity',      icon: <Key size={14} />,           color: '#a855f7' },
  APIEndpoint:   { label: 'API Endpoint',  icon: <Code size={14} />,          color: '#ec4899' },
  Vulnerability: { label: 'Vulnerability', icon: <AlertTriangle size={14} />, color: '#ef4444' },
};

const NODE_TYPE_ORDER = [
  'Organization', 'Subdomain', 'Application', 'APIEndpoint',
  'IdentityInfra', 'Certificate', 'Technology', 'Vulnerability', 'IPAddress',
];

function NodeTypeLegend({
  typeCounts,
  selected,
  onSelect,
}: {
  typeCounts: Record<string, number>;
  selected: string | null;
  onSelect: (t: string | null) => void;
}) {
  return (
    <Stack direction="row" spacing={0.75} sx={{ flexWrap: 'wrap', gap: 0.75, mb: 2 }}>
      {NODE_TYPE_ORDER.filter((t) => typeCounts[t] > 0).map((nodeType) => {
        const meta = NODE_TYPE_META[nodeType];
        if (!meta) return null;
        const isSelected = selected === nodeType;
        return (
          <Chip
            key={nodeType}
            size="small"
            label={`${meta.label}: ${typeCounts[nodeType]}`}
            icon={<Box sx={{ color: meta.color }}>{meta.icon}</Box>}
            onClick={() => onSelect(isSelected ? null : nodeType)}
            sx={{
              cursor: 'pointer',
              bgcolor: isSelected ? `${meta.color}25` : `${meta.color}10`,
              border: `1px solid ${isSelected ? meta.color : 'transparent'}`,
              fontWeight: isSelected ? 700 : 400,
              fontSize: '0.65rem',
              height: 22,
            }}
          />
        );
      })}
    </Stack>
  );
}

function NodeCard({ node }: { node: ChainGraphNode }) {
  const { isLight } = useThemeTokens();
  const meta = NODE_TYPE_META[node.type] ?? {
    label: node.type,
    icon: <Server size={14} />,
    color: '#64748b',
  };
  const name =
    (node.properties.name as string) ||
    (node.properties.host as string) ||
    (node.properties.base_url as string) ||
    (node.properties.subdomain_name as string) ||
    node.id;

  return (
    <Box
      sx={{
        p: 1.5,
        border: `1px solid ${meta.color}30`,
        borderLeft: `3px solid ${meta.color}`,
        borderRadius: 1,
        bgcolor: isLight ? '#fff' : 'background.paper',
      }}
    >
      <Stack direction="row" spacing={1} sx={{ alignItems: 'center' }}>
        <Box sx={{ color: meta.color }}>{meta.icon}</Box>
        <Box sx={{ flex: 1, minWidth: 0 }}>
          <Typography
            variant="body2"
            sx={{ fontWeight: 600, fontFamily: 'monospace', fontSize: '0.75rem' }}
            noWrap
            title={String(name)}
          >
            {String(name)}
          </Typography>
          <Chip
            size="small"
            label={meta.label}
            sx={{
              height: 14,
              fontSize: '0.55rem',
              mt: 0.25,
              bgcolor: `${meta.color}15`,
              color: meta.color,
              fontWeight: 700,
            }}
          />
        </Box>
      </Stack>
    </Box>
  );
}

function DrilldownPanel({ scanId, nodeType }: { scanId: number; nodeType: string }) {
  const { data, isLoading } = useChainNodesByType(scanId, nodeType);
  const meta = NODE_TYPE_META[nodeType];
  if (isLoading) return <CircularProgress size={18} sx={{ m: 2 }} />;
  if (!data || data.count === 0) {
    return (
      <Typography variant="caption" color="text.disabled" sx={{ p: 1 }}>
        No {nodeType} nodes found.
      </Typography>
    );
  }
  return (
    <Stack spacing={0.75} sx={{ mt: 1 }}>
      {data.nodes.map((n, i) => (
        <Box
          key={i}
          sx={{
            p: 1.5,
            border: `1px solid ${meta?.color ?? '#64748b'}20`,
            borderRadius: 1,
            bgcolor: 'background.paper',
          }}
        >
          {Object.entries(n)
            .slice(0, 4)
            .map(([k, v]) => (
              <Stack key={k} direction="row" spacing={1} sx={{ mb: 0.25 }}>
                <Typography
                  variant="caption"
                  sx={{
                    fontWeight: 700,
                    color: 'text.disabled',
                    minWidth: 80,
                    fontSize: '0.6rem',
                  }}
                >
                  {k}:
                </Typography>
                <Typography
                  variant="caption"
                  sx={{ fontFamily: 'monospace', fontSize: '0.65rem' }}
                  noWrap
                >
                  {String(v)}
                </Typography>
              </Stack>
            ))}
        </Box>
      ))}
    </Stack>
  );
}

export const FullChainGraphTab: React.FC<FullChainGraphTabProps> = ({ scanId }) => {
  const { data, isLoading, isError } = useFullChainGraph(scanId);
  const { tokens, isLight } = useThemeTokens();
  const [selectedType, setSelectedType] = useState<string | null>(null);

  if (isLoading) {
    return (
      <Box sx={{ display: 'flex', justifyContent: 'center', p: 4 }}>
        <CircularProgress size={24} />
      </Box>
    );
  }

  if (isError || !data) {
    return (
      <Box sx={{ p: 2, textAlign: 'center' }}>
        <Network size={32} style={{ opacity: 0.4, marginBottom: 8 }} />
        <Typography variant="body2" color="text.secondary">
          Full chain graph not available for this scan.
        </Typography>
      </Box>
    );
  }

  if (data.nodes.length === 0) {
    return (
      <Box sx={{ p: 4, textAlign: 'center' }}>
        <Network size={32} style={{ opacity: 0.4 }} />
        <Typography variant="body2" color="text.secondary" sx={{ mt: 1 }}>
          No chain data collected yet. Run a scan to populate the expanded graph.
        </Typography>
      </Box>
    );
  }

  const typeCounts: Record<string, number> = {};
  for (const n of data.nodes) {
    typeCounts[n.type] = (typeCounts[n.type] || 0) + 1;
  }

  const displayNodes = selectedType
    ? data.nodes.filter((n) => n.type === selectedType)
    : data.nodes;

  return (
    <Box>
      <Box
        sx={{
          mb: 2.5,
          p: 2,
          borderRadius: 1.5,
          bgcolor: isLight ? 'rgba(0,0,0,0.02)' : 'rgba(0,0,0,0.25)',
          border: 1,
          borderColor: 'divider',
          display: 'grid',
          gridTemplateColumns: 'repeat(3, 1fr)',
          gap: 2,
        }}
      >
        {[
          { label: 'TOTAL NODES', value: data.nodes.length, color: tokens.accent.primary },
          {
            label: 'EDGE TYPES',
            value: new Set(data.edges.map((e) => e.type)).size,
            color: tokens.accent.info,
          },
          {
            label: 'NODE TYPES',
            value: Object.keys(typeCounts).length,
            color: tokens.accent.success,
          },
        ].map((stat) => (
          <Box key={stat.label} sx={{ textAlign: 'center' }}>
            <Typography
              sx={{
                fontSize: '1.1rem',
                fontWeight: 900,
                color: stat.color,
                fontFamily: 'Orbitron',
              }}
            >
              {stat.value}
            </Typography>
            <Typography
              sx={{
                fontSize: '0.55rem',
                color: 'text.disabled',
                fontWeight: 700,
                letterSpacing: 0.5,
              }}
            >
              {stat.label}
            </Typography>
          </Box>
        ))}
      </Box>

      <NodeTypeLegend
        typeCounts={typeCounts}
        selected={selectedType}
        onSelect={setSelectedType}
      />

      {selectedType ? (
        <Box>
          <Typography
            variant="caption"
            sx={{ color: 'text.disabled', mb: 1, display: 'block' }}
          >
            {typeCounts[selectedType] ?? 0} {selectedType} nodes
          </Typography>
          <DrilldownPanel scanId={scanId} nodeType={selectedType} />
        </Box>
      ) : (
        <Stack spacing={0.75}>
          {displayNodes.slice(0, 100).map((node) => (
            <NodeCard key={node.id} node={node} />
          ))}
          {displayNodes.length > 100 && (
            <Typography
              variant="caption"
              color="text.disabled"
              sx={{ textAlign: 'center', py: 1 }}
            >
              Showing 100 of {displayNodes.length} nodes. Click a type in the legend to
              filter.
            </Typography>
          )}
        </Stack>
      )}
    </Box>
  );
};
