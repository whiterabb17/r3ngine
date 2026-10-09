import React from 'react';
import { Box, Grid, Typography } from '@mui/material';
import type { OsintConfig } from '../../types/engineConfig';
import { FlagCheckbox } from '../shared/FlagCheckbox';

type OsintFlag =
  | 'emailfinder' | 'whatbreach' | 'whatbreach_download_databases' | 'leaklookup' | 'leaksearch'
  | 'microsoft_recon' | 'credspy' | 'misconfig' | 'spoofcheck'
  | 'porch_pirate' | 'postleaks' | 'swaggerspy';

interface FlagSpec {
  field: OsintFlag;
  label: string;
  hint: string;
  /** True when the switch has no effect with this config, which disables it. */
  inactive?: (config: OsintConfig) => boolean;
}

interface FlagGroup {
  title: string;
  flags: FlagSpec[];
}

const GROUPS: FlagGroup[] = [
  {
    title: 'Emails & breaches',
    flags: [
      {
        field: 'emailfinder', label: 'EmailFinder',
        hint: 'Part of the emails lookup: runs only when Discover includes emails.',
        inactive: (c) => !c.discover.includes('emails'),
      },
      { field: 'whatbreach', label: 'WhatBreach', hint: 'Multi-source breach lookup for the domain.' },
      {
        field: 'whatbreach_download_databases', label: 'Download found databases',
        hint: 'Saves public breach databases WhatBreach finds to the results folder. Files can be very large.',
        inactive: (c) => !c.whatbreach,
      },
      {
        field: 'leaklookup', label: 'LeakLookup',
        hint: 'leak-lookup.com and ProjectDiscovery APIs; skipped without either API key.',
      },
      { field: 'leaksearch', label: 'LeakSearch', hint: 'Credential leak search; skipped without a LeakSearch API key.' },
    ],
  },
  {
    title: 'Infrastructure',
    flags: [
      { field: 'microsoft_recon', label: 'Microsoft recon', hint: 'msftrecon: Microsoft 365 / Azure tenant domains.' },
      {
        field: 'credspy', label: 'CredSpy (post-crawl)',
        hint: 'Runs in the post-crawl OSINT step so Microsoft MX and autodiscover hosts found by the scan are known; skipped when there are none.',
      },
      { field: 'misconfig', label: 'misconfig-mapper', hint: 'Third-party service misconfigurations for the domain.' },
      { field: 'spoofcheck', label: 'Spoofing check', hint: 'Spoofy SPF / DMARC analysis (domain_security.spoofcheck).' },
    ],
  },
  {
    title: 'API leaks',
    flags: [
      { field: 'porch_pirate', label: 'Porch Pirate', hint: 'Public Postman workspaces mentioning the domain.' },
      { field: 'postleaks', label: 'postleaksNg', hint: 'Credentials leaked in public Postman collections.' },
      {
        field: 'swaggerspy', label: 'SwaggerSpy search',
        hint: 'Published Swagger / OpenAPI specs found online. The probe of live hosts is in Post-Crawl OSINT.',
      },
    ],
  },
];

interface Props {
  config: OsintConfig;
  onChange: (patch: Partial<OsintConfig>) => void;
}

/** The OSINT tools switched on one by one under `osint`. */
export const OsintToolsFields: React.FC<Props> = ({ config, onChange }) => (
  <Grid container spacing={2} sx={{ mt: 0.5 }}>
    {GROUPS.map((group) => (
      <Grid key={group.title} size={{ xs: 12, md: 4 }}>
        <Typography variant="caption" sx={{ color: 'text.secondary', display: 'block', mb: 0.5 }}>
          {group.title}
        </Typography>
        <Box sx={{ display: 'flex', flexDirection: 'column', gap: 0.5 }}>
          {group.flags.map(({ field, label, hint, inactive }) => (
            <FlagCheckbox
              key={field}
              label={label}
              hint={hint}
              checked={config[field]}
              disabled={inactive?.(config) ?? false}
              onChange={(checked) => onChange({ [field]: checked })}
            />
          ))}
        </Box>
      </Grid>
    ))}
  </Grid>
);
