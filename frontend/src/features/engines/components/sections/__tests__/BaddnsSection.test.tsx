import { fireEvent, render, screen } from '@testing-library/react';
import { ThemeProvider } from '@mui/material/styles';
import { describe, expect, it, vi } from 'vitest';
import { hackerTheme } from '../../../../../theme';
import { DEFAULT_ENGINE_CONFIG } from '../../../types/engineConfig';
import { BaddnsSection } from '../BaddnsSection';

vi.mock('../../../../../theme/useThemeTokens', async () => {
  const { hackerTheme: theme } = await import('../../../../../theme');
  const { getResolvedTokens: resolve } = await import('../../../../../theme/tokens');
  return {
    useThemeTokens: () => ({ tokens: resolve('hacker'), theme, isLight: false, isCyber: true, themeName: 'hacker' }),
  };
});

const renderSection = (enabled: boolean, usesTools: string[], subdomainEnabled = true) => {
  const onSubdomainToolsChange = vi.fn();
  render(
    <ThemeProvider theme={hackerTheme}>
      <BaddnsSection
        enabled={enabled}
        onToggle={vi.fn()}
        subdomainDiscovery={{
          enabled: subdomainEnabled,
          config: { ...DEFAULT_ENGINE_CONFIG.subdomain_discovery.config, uses_tools: usesTools },
        }}
        onSubdomainToolsChange={onSubdomainToolsChange}
      />
    </ThemeProvider>,
  );
  return onSubdomainToolsChange;
};

describe('BaddnsSection', () => {
  it('warns about the double run and removes baddns from subdomain discovery on request', () => {
    const onSubdomainToolsChange = renderSection(true, ['subfinder', 'baddns']);
    expect(screen.getByText(/runs twice/)).toBeInTheDocument();

    fireEvent.click(screen.getByRole('button', { name: 'Run it only here' }));
    expect(onSubdomainToolsChange).toHaveBeenLastCalledWith(['subfinder']);
  });

  it.each([
    ['the card is off', false, ['baddns'], true],
    ['subdomain discovery does not list baddns', true, ['subfinder'], true],
    ['subdomain discovery is off', true, ['baddns'], false],
  ] as const)('does not warn when %s', (_case, enabled, tools, subdomainEnabled) => {
    renderSection(enabled, [...tools], subdomainEnabled);
    expect(screen.queryByText(/runs twice/)).not.toBeInTheDocument();
  });
});
