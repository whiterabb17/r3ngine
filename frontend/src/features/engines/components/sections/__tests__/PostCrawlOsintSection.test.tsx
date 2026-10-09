import { fireEvent, render, screen } from '@testing-library/react';
import { ThemeProvider } from '@mui/material/styles';
import { describe, expect, it, vi } from 'vitest';
import { hackerTheme } from '../../../../../theme';
import { PostCrawlOsintSection } from '../PostCrawlOsintSection';

vi.mock('../../../../../theme/useThemeTokens', async () => {
  const { hackerTheme: theme } = await import('../../../../../theme');
  const { getResolvedTokens: resolve } = await import('../../../../../theme/tokens');
  return {
    useThemeTokens: () => ({ tokens: resolve('hacker'), theme, isLight: false, isCyber: true, themeName: 'hacker' }),
  };
});

describe('PostCrawlOsintSection', () => {
  it.each([
    ['Document metadata', 'metagoofil'],
    ['SwaggerSpy path probe', 'swaggerspy'],
  ] as const)('switches %s into %s', (label, field) => {
    const onChange = vi.fn();
    render(
      <ThemeProvider theme={hackerTheme}>
        <PostCrawlOsintSection
          config={{ metagoofil: true, swaggerspy: true }}
          enabled
          onToggle={vi.fn()}
          onChange={onChange}
        />
      </ThemeProvider>,
    );
    const box = screen.getByRole('checkbox', { name: new RegExp(`^${label}`) });
    expect(box).toBeChecked();
    fireEvent.click(box);
    expect(onChange).toHaveBeenLastCalledWith({ [field]: false });
  });
});
