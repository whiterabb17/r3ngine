import { fireEvent, render, screen } from '@testing-library/react';
import { ThemeProvider } from '@mui/material/styles';
import { describe, expect, it, vi } from 'vitest';
import { hackerTheme } from '../../../../../theme';
import { DEFAULT_ENGINE_CONFIG } from '../../../types/engineConfig';
import type { OsintConfig } from '../../../types/engineConfig';
import { OsintSection } from '../OsintSection';

vi.mock('../../../../../theme/useThemeTokens', async () => {
  const { hackerTheme: theme } = await import('../../../../../theme');
  const { getResolvedTokens: resolve } = await import('../../../../../theme/tokens');
  return {
    useThemeTokens: () => ({ tokens: resolve('hacker'), theme, isLight: false, isCyber: true, themeName: 'hacker' }),
  };
});

const renderSection = (overrides: Partial<OsintConfig> = {}) => {
  const onChange = vi.fn();
  render(
    <ThemeProvider theme={hackerTheme}>
      <OsintSection
        config={{ ...DEFAULT_ENGINE_CONFIG.osint.config, ...overrides }}
        enabled
        onToggle={vi.fn()}
        onChange={onChange}
      />
    </ThemeProvider>,
  );
  return onChange;
};

const checkbox = (label: string) => screen.getByRole('checkbox', { name: new RegExp(`^${label}`) });

describe('OsintSection', () => {
  it.each([
    ['Microsoft recon', 'microsoft_recon'],
    ['misconfig-mapper', 'misconfig'],
    ['Spoofing check', 'spoofcheck'],
    ['Porch Pirate', 'porch_pirate'],
    ['postleaksNg', 'postleaks'],
    ['SwaggerSpy search', 'swaggerspy'],
    ['LeakLookup', 'leaklookup'],
    ['CredSpy', 'credspy'],
  ] as const)('switches %s into %s', (label, field) => {
    const onChange = renderSection();
    fireEvent.click(checkbox(label));
    expect(onChange).toHaveBeenLastCalledWith({ [field]: true });
  });

  it('disables EmailFinder unless the emails lookup is selected', () => {
    renderSection({ discover: ['metainfo'] });
    expect(checkbox('EmailFinder')).toBeDisabled();
  });

  it('disables the documents limit unless the metainfo lookup is selected', () => {
    renderSection({ discover: ['emails'] });
    expect(screen.getByRole('spinbutton', { name: 'Documents Limit' })).toBeDisabled();
    expect(checkbox('EmailFinder')).toBeEnabled();
  });

  it('offers the dork engines the dorking task runs', () => {
    const onChange = renderSection();
    fireEvent.click(screen.getByText('xnldorker'));
    expect(onChange).toHaveBeenLastCalledWith({ dork_engines: ['xnldorker'] });
  });

  it('says how many structured custom dorks it keeps', () => {
    renderSection({ custom_dork_rules: [{ lookup_site: '_target_', lookup_extensions: 'php' }] });
    expect(screen.getByText(/Structured lookup_site dorks kept from the YAML: 1/)).toBeInTheDocument();
  });

  it('shows the GitHub options only while GitHub analysis is on', () => {
    const onChange = renderSection();
    expect(screen.queryByText('enumerepo')).not.toBeInTheDocument();
    fireEvent.click(checkbox('GitHub organisation analysis'));
    expect(onChange).toHaveBeenLastCalledWith({ github_analysis: true });
  });

  it('warns that the secret scanners need enumerepo', () => {
    const onChange = renderSection({ github_analysis: true, github_tools: ['trufflehog'] });
    expect(screen.getByText(/Without enumerepo no repositories are listed/)).toBeInTheDocument();
    fireEvent.click(checkbox('Gato'));
    expect(onChange).toHaveBeenLastCalledWith({ github_gato: true });
  });
});
