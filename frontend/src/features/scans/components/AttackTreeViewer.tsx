import React from 'react';
import { Box, Typography, Stack, CircularProgress, Chip, Paper } from '@mui/material';
import { useThemeTokens } from '../../../theme/useThemeTokens';
import { useAttackTree, type AttackTreeNode } from '../api/useAttackPaths';
import { Target, GitMerge, List, Shield, ShieldAlert } from 'lucide-react';

interface AttackTreeViewerProps {
  scanId: number;
  targetId: string;
}

const TreeNode: React.FC<{ node: AttackTreeNode }> = ({ node }) => {
  const { tokens, isLight } = useThemeTokens();

  if (node.type === 'OR') {
    return (
      <Box sx={{ mb: 2, p: 2, border: `1px solid ${tokens.accent.primary}40`, borderRadius: 2, bgcolor: isLight ? 'rgba(0,0,0,0.02)' : 'rgba(255,255,255,0.02)' }}>
        <Stack direction="row" spacing={1} sx={{ alignItems: 'center', mb: 2 }}>
          <Target size={18} color={tokens.accent.primary} />
          <Typography sx={{ fontWeight: 800, fontFamily: 'Orbitron', color: tokens.accent.primary }}>
            GOAL: {node.goal}
          </Typography>
        </Stack>
        <Stack spacing={2}>
          {node.children?.map((child, idx) => (
            <TreeNode key={child.id || idx} node={child} />
          ))}
        </Stack>
      </Box>
    );
  }

  if (node.type === 'AND') {
    return (
      <Paper elevation={isLight ? 1 : 0} sx={{ p: 2, borderLeft: `3px solid ${tokens.accent.warning}`, bgcolor: isLight ? '#fff' : 'background.paper', borderRadius: 1 }}>
        <Stack direction="row" spacing={1} sx={{ alignItems: 'center', mb: 1.5 }}>
          <GitMerge size={16} color={tokens.accent.warning} />
          <Typography sx={{ fontWeight: 700, fontSize: '0.85rem' }}>
            {node.description || 'Attack Path'}
          </Typography>
          <Chip size="small" label="AND" sx={{ height: 18, fontSize: '0.6rem', fontWeight: 800, fontFamily: 'monospace' }} />
        </Stack>
        <Stack spacing={1} sx={{ pl: 2, borderLeft: `1px dashed ${tokens.accent.warning}50`, ml: 1 }}>
          {node.children?.map((child, idx) => (
            <TreeNode key={child.id || idx} node={child} />
          ))}
        </Stack>
      </Paper>
    );
  }

  if (node.type === 'LEAF') {
    return (
      <Box sx={{ p: 1.5, border: `1px solid ${tokens.accent.error}30`, borderRadius: 1, bgcolor: `${tokens.accent.error}0A` }}>
        <Stack direction="row" spacing={1} sx={{ alignItems: 'center', mb: 1 }}>
          <List size={14} color={tokens.accent.error} />
          <Typography sx={{ fontWeight: 700, fontSize: '0.75rem', color: 'text.primary' }}>
            {node.action}
          </Typography>
        </Stack>
        <Stack direction="row" spacing={1} sx={{ flexWrap: 'wrap', gap: 1 }}>
          {node.mitre_id && (
            <Chip size="small" label={`MITRE: ${node.mitre_id}`} sx={{ height: 16, fontSize: '0.6rem', bgcolor: 'transparent', border: '1px solid', borderColor: 'divider' }} />
          )}
          {node.cost && (
            <Chip size="small" label={`Cost: ${node.cost}`} sx={{ height: 16, fontSize: '0.6rem', bgcolor: 'transparent', border: '1px solid', borderColor: 'divider' }} />
          )}
          {node.skill && (
            <Chip size="small" label={`Skill: ${node.skill}`} sx={{ height: 16, fontSize: '0.6rem', bgcolor: 'transparent', border: '1px solid', borderColor: 'divider' }} />
          )}
          {node.detectability && (
            <Chip
              size="small"
              label={`Detect: ${node.detectability}`}
              sx={{
                height: 16,
                fontSize: '0.6rem',
                bgcolor: 'transparent',
                border: '1px solid',
                borderColor: 'divider',
                color: 'text.secondary',
              }}
            />
          )}
        </Stack>
        {node.mitigation && (
          <Box sx={{ mt: 1, p: 1, bgcolor: `${tokens.accent.success}10`, borderRadius: 1, borderLeft: `2px solid ${tokens.accent.success}` }}>
            <Stack direction="row" spacing={1} sx={{ alignItems: 'flex-start' }}>
              <Shield size={14} color={tokens.accent.success} style={{ marginTop: 2 }} />
              <Typography sx={{ fontSize: '0.7rem', color: 'text.secondary' }}>
                {node.mitigation}
              </Typography>
            </Stack>
          </Box>
        )}
      </Box>
    );
  }

  return null;
};

export const AttackTreeViewer: React.FC<AttackTreeViewerProps> = ({ scanId, targetId }) => {
  const { data, isLoading, isError } = useAttackTree(scanId, targetId);

  if (isLoading) {
    return (
      <Box sx={{ display: 'flex', justifyContent: 'center', p: 4 }}>
        <CircularProgress size={24} />
      </Box>
    );
  }

  if (isError || !data?.tree) {
    return (
      <Box sx={{ p: 2, textAlign: 'center' }}>
        <ShieldAlert size={32} style={{ opacity: 0.5, marginBottom: 8 }} />
        <Typography variant="body2" color="text.secondary">
          Could not load attack tree for this target.
        </Typography>
      </Box>
    );
  }

  return (
    <Box sx={{ mt: 2 }}>
      <Typography sx={{ mb: 2, fontSize: '0.75rem', fontWeight: 800, letterSpacing: 1, color: 'text.disabled', fontFamily: 'Orbitron' }}>
        ATTACK TREE ANALYSIS
      </Typography>
      <TreeNode node={data.tree} />
    </Box>
  );
};
