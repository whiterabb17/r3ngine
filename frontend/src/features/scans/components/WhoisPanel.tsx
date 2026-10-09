import React from 'react';
import { Box, Button, Chip, CircularProgress, Link, Stack, Typography } from '@mui/material';
import { RefreshCw, Search } from 'lucide-react';
import { useThemeTokens } from '../../../theme/useThemeTokens';
import { getSafeUrl } from '../../../utils/securityUtils';
import type { DomainInfoSummary, WhoisContact } from '../types';

interface WhoisPanelProps {
  domainInfo: DomainInfoSummary | null | undefined;
  /** Runs a fresh WHOIS lookup; the button is hidden when omitted. */
  onFetch?: () => void;
  isFetching?: boolean;
}

const CONTACT_ROLES = [
  ['registrant', 'Registrant'],
  ['admin', 'Admin'],
  ['tech', 'Tech'],
] as const;

const CONTACT_FIELDS: [keyof WhoisContact, string][] = [
  ['name', 'Name'],
  ['organization', 'Organization'],
  ['email', 'Email'],
  ['phone', 'Phone'],
  ['fax', 'Fax'],
  ['address', 'Address'],
  ['city', 'City'],
  ['state', 'State'],
  ['zip_code', 'Zip'],
  ['country', 'Country'],
];

const LABEL_SX = { fontSize: '0.6rem', color: 'text.disabled', textTransform: 'uppercase', letterSpacing: 1 } as const;
const VALUE_SX = { fontSize: '0.7rem', color: 'text.primary', wordBreak: 'break-word' } as const;

const hasWhoisData = (domainInfo: DomainInfoSummary | null | undefined): boolean => {
  const whois = domainInfo?.whois;
  return Boolean(
    domainInfo?.registrar?.name
    || domainInfo?.whois_server
    || whois?.statuses.length
    || whois?.registrant
    || whois?.admin
    || whois?.tech
    || whois?.raw,
  );
};

const Field: React.FC<{ label: string; children: React.ReactNode }> = ({ label, children }) => (
  <Box>
    <Typography sx={LABEL_SX}>{label}</Typography>
    <Typography component="div" sx={VALUE_SX}>{children}</Typography>
  </Box>
);

const ContactCard: React.FC<{ title: string; contact: WhoisContact }> = ({ title, contact }) => {
  const { tokens } = useThemeTokens();
  return (
    <Box sx={{ p: 1.5, border: 1, borderColor: 'divider', borderRadius: 1, minWidth: 0 }}>
      <Typography sx={{ fontSize: '0.65rem', fontWeight: 900, color: tokens.accent.primary, mb: 1, letterSpacing: 1 }}>
        {title.toUpperCase()}
      </Typography>
      <Stack spacing={0.75}>
        {CONTACT_FIELDS.filter(([key]) => contact[key]).map(([key, label]) => (
          <Field key={key} label={label}>{contact[key]}</Field>
        ))}
      </Stack>
    </Box>
  );
};

export const WhoisPanel: React.FC<WhoisPanelProps> = ({ domainInfo, onFetch, isFetching = false }) => {
  const { tokens } = useThemeTokens();
  const hasData = hasWhoisData(domainInfo);
  const fetchButton = onFetch && (
    <Button
      size="small"
      variant="outlined"
      startIcon={isFetching ? <CircularProgress size={12} /> : hasData ? <RefreshCw size={12} /> : <Search size={12} />}
      disabled={isFetching}
      onClick={onFetch}
      sx={{ color: tokens.accent.primary, borderColor: `${tokens.accent.primary}4D`, fontSize: '0.65rem', fontWeight: 900 }}
    >
      {isFetching ? 'FETCHING...' : hasData ? 'REFRESH' : 'FETCH WHOIS DATA'}
    </Button>
  );

  if (!domainInfo || !hasData) {
    return (
      <Box sx={{ p: 4, textAlign: 'center' }}>
        <Typography sx={{ fontSize: '0.8rem', color: 'text.secondary', mb: 2 }}>
          No WHOIS data available for this target.
        </Typography>
        {fetchButton}
      </Box>
    );
  }

  const { registrar, whois } = domainInfo;
  const registrarUrl = getSafeUrl(registrar.url);
  const contacts = CONTACT_ROLES.flatMap(([role, title]) => {
    const contact = whois[role];
    return contact ? [{ title, contact }] : [];
  });

  return (
    <Stack spacing={2} sx={{ maxHeight: 300, overflow: 'auto', pr: 0.5 }}>
      {fetchButton && <Stack direction="row" sx={{ justifyContent: 'flex-end' }}>{fetchButton}</Stack>}
      <Box sx={{ display: 'grid', gridTemplateColumns: { xs: '1fr', sm: 'repeat(2, minmax(0, 1fr))' }, gap: 1.5 }}>
        <Field label="Registrar">{registrar.name || 'N/A'}</Field>
        <Field label="WHOIS Server">{domainInfo.whois_server || 'N/A'}</Field>
        {registrarUrl && (
          <Field label="Registrar URL">
            <Link href={registrarUrl} target="_blank" rel="noopener noreferrer" sx={{ color: tokens.accent.primary }}>{registrarUrl}</Link>
          </Field>
        )}
        {registrar.email && <Field label="Registrar Email">{registrar.email}</Field>}
        {registrar.phone && <Field label="Registrar Phone">{registrar.phone}</Field>}
      </Box>
      {whois.statuses.length > 0 && (
        <Box>
          <Typography sx={{ ...LABEL_SX, mb: 0.5 }}>Status</Typography>
          <Stack direction="row" sx={{ flexWrap: 'wrap', gap: 0.5 }}>
            {whois.statuses.map((status) => (
              <Chip key={status} label={status} size="small" sx={{ height: 18, fontSize: '0.6rem', bgcolor: `${tokens.accent.primary}15`, color: tokens.accent.primary }} />
            ))}
          </Stack>
        </Box>
      )}
      {contacts.length > 0 && (
        <Box sx={{ display: 'grid', gridTemplateColumns: { xs: '1fr', sm: 'repeat(auto-fit, minmax(180px, 1fr))' }, gap: 1.5 }}>
          {contacts.map(({ title, contact }) => <ContactCard key={title} title={title} contact={contact} />)}
        </Box>
      )}
      {whois.raw && (
        <Box>
          <Typography sx={{ ...LABEL_SX, mb: 0.5 }}>Raw Record</Typography>
          <Box component="pre" sx={{ m: 0, p: 1.5, bgcolor: 'action.hover', borderRadius: 1, fontSize: '0.65rem', color: 'text.secondary', whiteSpace: 'pre-wrap', wordBreak: 'break-word' }}>
            {JSON.stringify(whois.raw, null, 2)}
          </Box>
        </Box>
      )}
    </Stack>
  );
};
