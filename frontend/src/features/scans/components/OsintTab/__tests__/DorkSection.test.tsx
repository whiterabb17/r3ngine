import { render, screen } from '@testing-library/react';
import { ThemeProvider } from '@mui/material/styles';
import { describe, expect, it, vi } from 'vitest';
import { hackerTheme } from '../../../../../theme';
import { DorkSection } from '../DorkSection';

vi.mock('../../../../../theme/useThemeTokens', async () => {
  const { hackerTheme: theme } = await import('../../../../../theme');
  const { getResolvedTokens: resolve } = await import('../../../../../theme/tokens');
  return {
    useThemeTokens: () => ({ tokens: resolve('hacker'), theme, isLight: false, isCyber: true, themeName: 'hacker' }),
  };
});

describe('DorkSection', () => {
  it('renders dorks whose nullable type or url is missing', () => {
    render(
      <ThemeProvider theme={hackerTheme}>
        <DorkSection
          dorks={[
            { id: 1, type: 'login_pages', url: 'https://example.test/login' },
            { id: 2, type: null, url: null },
          ]}
        />
      </ThemeProvider>,
    );

    expect(screen.getByText('LOGIN PAGES')).toBeInTheDocument();
    expect(screen.getByText('https://example.test/login')).toBeInTheDocument();
  });
});
