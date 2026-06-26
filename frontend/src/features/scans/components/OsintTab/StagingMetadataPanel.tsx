import React from 'react';
import { Box, Typography, Chip, IconButton, Tooltip, Button } from '@mui/material';
import { Copy, ExternalLink, Check } from 'lucide-react';
import type { OsintStaging } from '../../types';
import { useThemeTokens } from '../../../../theme/useThemeTokens';

interface StagingMetadataPanelProps {
  item: OsintStaging;
  onPromote: (id: number) => void;
}

const FieldRow: React.FC<{ label: string; value: React.ReactNode }> = ({ label, value }) => (
  <Box sx={{ display: 'flex', gap: 2, mb: 0.5, alignItems: 'flex-start' }}>
    <Typography sx={{
      fontSize: '0.65rem', color: 'text.disabled', fontWeight: 700,
      minWidth: 100, textTransform: 'uppercase', pt: 0.2,
    }}>
      {label}
    </Typography>
    <Box sx={{ flex: 1 }}>{value}</Box>
  </Box>
);

const MonoValue: React.FC<{ value: string; copyable?: boolean }> = ({ value, copyable }) => {
  const handleCopy = () => navigator.clipboard.writeText(value);
  return (
    <Box sx={{ display: 'flex', alignItems: 'center', gap: 0.5 }}>
      <Typography sx={{ fontFamily: 'monospace', fontSize: '0.72rem', color: 'rgba(255,255,255,0.8)' }}>
        {value}
      </Typography>
      {copyable && (
        <Tooltip title="Copy">
          <IconButton size="small" onClick={handleCopy}
            sx={{ p: 0.25, opacity: 0.5, '&:hover': { opacity: 1 } }}>
            <Copy size={11} />
          </IconButton>
        </Tooltip>
      )}
    </Box>
  );
};

const TypedContent: React.FC<{
  item: OsintStaging;
  meta: Record<string, unknown>;
  onPromote: (id: number) => void;
}> = ({ item, meta, onPromote }) => {
  switch (item.osint_type) {
    case 'SSL':
      return (
        <>
          <FieldRow label="Host" value={<MonoValue value={String(meta.host || item.content)} />} />
          {meta.subject_cn && <FieldRow label="Subject CN" value={<MonoValue value={String(meta.subject_cn)} />} />}
          {meta.issuer && <FieldRow label="Issuer" value={<MonoValue value={String(meta.issuer)} />} />}
          <Box sx={{ mt: 1.5 }}>
            <Button size="small" variant="outlined" color="info"
              startIcon={<Check size={12} />}
              onClick={() => onPromote(item.id)}
              sx={{ fontSize: '0.62rem', fontFamily: 'Orbitron', fontWeight: 900 }}>
              Confirm &amp; Rescan
            </Button>
          </Box>
        </>
      );

    case 'DNS':
      return (
        <>
          <FieldRow label="Record Type" value={
            <Chip label={String(meta.record_type || 'TXT')} size="small"
              sx={{ fontSize: '10px', height: 16, fontWeight: 800, bgcolor: 'rgba(63,81,181,0.2)', color: '#7986cb' }} />
          } />
          <FieldRow label="Hostname" value={<MonoValue value={String(meta.hostname || '')} />} />
          <FieldRow label="Value" value={<MonoValue value={String(meta.value || item.content)} copyable />} />
        </>
      );

    case 'Phone':
      return (
        <FieldRow label="Phone" value={
          <MonoValue value={String(meta.phone_number || item.content)} copyable />
        } />
      );

    case 'Social': {
      const profileUrl = String(meta.profile_url || item.content);
      const isSafe = /^https?:\/\//i.test(profileUrl);
      return (
        <>
          {meta.platform && (
            <FieldRow label="Platform" value={
              <Chip label={String(meta.platform)} size="small"
                sx={{ fontSize: '10px', height: 16, fontWeight: 800, bgcolor: 'rgba(233,30,99,0.2)', color: '#f48fb1' }} />
            } />
          )}
          <FieldRow label="Profile URL" value={
            <Box sx={{ display: 'flex', alignItems: 'center', gap: 0.5 }}>
              <Typography sx={{ fontFamily: 'monospace', fontSize: '0.72rem', color: 'rgba(255,255,255,0.8)' }}>
                {profileUrl}
              </Typography>
              {isSafe && (
                <Tooltip title="Open profile">
                  <IconButton size="small" component="a" href={profileUrl}
                    target="_blank" rel="noopener noreferrer"
                    sx={{ p: 0.25, opacity: 0.5, '&:hover': { opacity: 1 } }}>
                    <ExternalLink size={11} />
                  </IconButton>
                </Tooltip>
              )}
            </Box>
          } />
        </>
      );
    }

    case 'OS':
      return (
        <>
          <FieldRow label="OS" value={<MonoValue value={String(meta.os_name || item.content)} />} />
          {meta.source_host && (
            <FieldRow label="Source Host" value={<MonoValue value={String(meta.source_host)} />} />
          )}
        </>
      );

    case 'Crypto':
      return (
        <>
          {meta.address_type && (
            <FieldRow label="Type" value={
              <Chip label={String(meta.address_type)} size="small"
                sx={{ fontSize: '10px', height: 16, fontWeight: 800, bgcolor: 'rgba(255,193,7,0.2)', color: '#ffd54f' }} />
            } />
          )}
          <FieldRow label="Address" value={
            <MonoValue value={String(meta.address || item.content)} copyable />
          } />
        </>
      );

    case 'Hosting':
      return (
        <FieldRow label="Co-Hosted Domain" value={
          <MonoValue value={String(meta.co_hosted_domain || item.content)} />
        } />
      );

    default:
      return (
        <Typography sx={{
          fontFamily: 'monospace', fontSize: '0.7rem',
          color: 'rgba(255,255,255,0.6)', whiteSpace: 'pre-wrap',
        }}>
          {JSON.stringify(meta, null, 2)}
        </Typography>
      );
  }
};

export const StagingMetadataPanel: React.FC<StagingMetadataPanelProps> = ({ item, onPromote }) => {
  const { tokens } = useThemeTokens();

  let meta: Record<string, unknown> = {};
  try {
    meta = typeof item.metadata === 'string'
      ? JSON.parse(item.metadata as string)
      : (item.metadata ?? {});
  } catch {
    meta = {};
  }

  let content: React.ReactNode;
  try {
    content = <TypedContent item={item} meta={meta} onPromote={onPromote} />;
  } catch {
    content = (
      <Typography sx={{ fontFamily: 'monospace', fontSize: '0.7rem', color: 'error.main' }}>
        Failed to render metadata
      </Typography>
    );
  }

  return (
    <Box sx={{ p: 2, bgcolor: 'rgba(0,0,0,0.2)', borderBottom: 1, borderColor: 'divider' }}>
      <Typography sx={{
        fontSize: '0.7rem', color: tokens.accent.primary,
        fontWeight: 900, mb: 1, textTransform: 'uppercase',
      }}>
        {item.osint_type} Details
      </Typography>
      {content}
    </Box>
  );
};
