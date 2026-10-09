import { fireEvent, render, screen } from '@testing-library/react';
import { ThemeProvider } from '@mui/material/styles';
import { describe, expect, it, vi } from 'vitest';
import { hackerTheme } from '../../../../../theme';
import { AmassIntelSection } from '../AmassIntelSection';

vi.mock('../../../../../theme/useThemeTokens', async () => {
  const { hackerTheme: theme } = await import('../../../../../theme');
  const { getResolvedTokens: resolve } = await import('../../../../../theme/tokens');
  return {
    useThemeTokens: () => ({ tokens: resolve('hacker'), theme, isLight: false, isCyber: true, themeName: 'hacker' }),
  };
});

describe('AmassIntelSection', () => {
  it('switches the amass config file into use_amass_config', () => {
    const onChange = vi.fn();
    render(
      <ThemeProvider theme={hackerTheme}>
        <AmassIntelSection config={{ use_amass_config: false }} enabled onToggle={vi.fn()} onChange={onChange} />
      </ThemeProvider>,
    );
    fireEvent.click(screen.getByRole('checkbox', { name: /^Use amass config/ }));
    expect(onChange).toHaveBeenLastCalledWith({ use_amass_config: true });
  });
});
