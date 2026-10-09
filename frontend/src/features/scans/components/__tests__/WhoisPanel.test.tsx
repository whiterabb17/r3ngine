import { fireEvent, render, screen } from '@testing-library/react';
import { ThemeProvider } from '@mui/material/styles';
import { describe, expect, it, vi } from 'vitest';
import { hackerTheme } from '../../../../theme';
import type { DomainInfoSummary } from '../../types';
import { WhoisPanel } from '../WhoisPanel';

vi.mock('../../../../theme/useThemeTokens', async () => {
  const { hackerTheme: theme } = await import('../../../../theme');
  const { getResolvedTokens: resolve } = await import('../../../../theme/tokens');
  return {
    useThemeTokens: () => ({
      tokens: resolve('hacker'),
      theme,
      isLight: false,
      isCyber: true,
      themeName: 'hacker',
    }),
  };
});

const emptyDomainInfo: DomainInfoSummary = {
  dnssec: false,
  geolocation_iso: null,
  created: null,
  updated: null,
  expires: null,
  whois_server: null,
  registrar: { name: null, phone: null, email: null, url: null },
  dns_records: [],
  name_servers: [],
  nameservers: [],
  historical_ips: [],
  whois: { statuses: [], registrant: null, admin: null, tech: null, raw: null },
};

const renderPanel = (props: Parameters<typeof WhoisPanel>[0]) => render(
  <ThemeProvider theme={hackerTheme}>
    <WhoisPanel {...props} />
  </ThemeProvider>,
);

describe('WhoisPanel', () => {
  it('offers a lookup when nothing is stored', () => {
    const onFetch = vi.fn();
    renderPanel({ domainInfo: emptyDomainInfo, onFetch });

    expect(screen.getByText('No WHOIS data available for this target.')).toBeInTheDocument();
    fireEvent.click(screen.getByRole('button', { name: /fetch whois data/i }));
    expect(onFetch).toHaveBeenCalledTimes(1);
  });

  it('renders registrar, statuses, contacts and the raw record', () => {
    renderPanel({
      domainInfo: {
        ...emptyDomainInfo,
        whois_server: 'whois.example.test',
        registrar: { name: 'Example Registrar', phone: null, email: null, url: 'https://registrar.example.test' },
        whois: {
          statuses: ['clientTransferProhibited'],
          registrant: {
            name: 'Jane Doe', organization: 'Example Org', email: 'jane@example.test', phone: null,
            fax: null, address: null, city: null, state: null, zip_code: null, country: 'ZZ',
          },
          admin: null,
          tech: null,
          raw: { domain: 'example.test' },
        },
      },
    });

    expect(screen.getByText('Example Registrar')).toBeInTheDocument();
    expect(screen.getByText('whois.example.test')).toBeInTheDocument();
    expect(screen.getByRole('link', { name: 'https://registrar.example.test' }))
      .toHaveAttribute('href', 'https://registrar.example.test');
    expect(screen.getByText('clientTransferProhibited')).toBeInTheDocument();
    expect(screen.getByText('REGISTRANT')).toBeInTheDocument();
    expect(screen.getByText('Jane Doe')).toBeInTheDocument();
    expect(screen.queryByText('ADMIN')).not.toBeInTheDocument();
    expect(screen.getByText(/"domain": "example.test"/)).toBeInTheDocument();
  });

  it('does not link a registrar URL with an unsafe scheme', () => {
    renderPanel({
      domainInfo: {
        ...emptyDomainInfo,
        registrar: { name: 'Example Registrar', phone: null, email: null, url: 'javascript:alert(1)' },
      },
    });

    expect(screen.getByText('Example Registrar')).toBeInTheDocument();
    expect(screen.queryByRole('link')).not.toBeInTheDocument();
  });
});
