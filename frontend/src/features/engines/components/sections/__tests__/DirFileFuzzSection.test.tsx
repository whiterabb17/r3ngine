import { fireEvent, render, screen } from '@testing-library/react';
import { ThemeProvider } from '@mui/material/styles';
import { describe, expect, it, vi } from 'vitest';
import { hackerTheme } from '../../../../../theme';
import { DEFAULT_ENGINE_CONFIG } from '../../../types/engineConfig';
import type { DirFileFuzzConfig } from '../../../types/engineConfig';
import { DirFileFuzzSection } from '../DirFileFuzzSection';

vi.mock('../../../../../theme/useThemeTokens', async () => {
  const { hackerTheme: theme } = await import('../../../../../theme');
  const { getResolvedTokens: resolve } = await import('../../../../../theme/tokens');
  return {
    useThemeTokens: () => ({ tokens: resolve('hacker'), theme, isLight: false, isCyber: true, themeName: 'hacker' }),
  };
});

const renderSection = (onChange = vi.fn(), overrides: Partial<DirFileFuzzConfig> = {}) => {
  render(
    <ThemeProvider theme={hackerTheme}>
      <DirFileFuzzSection
        config={{ ...DEFAULT_ENGINE_CONFIG.dir_file_fuzz.config, extensions: ['php'], ...overrides }}
        enabled
        onToggle={vi.fn()}
        onChange={onChange}
      />
    </ThemeProvider>,
  );
  return onChange;
};

describe('DirFileFuzzSection', () => {
  it('shows ffuf on by default and dirsearch / feroxbuster as optional extra passes', () => {
    renderSection();

    expect(screen.getByText(/ffuf fuzzes every target by default/)).toBeInTheDocument();
    const ffuf = screen.getByRole('checkbox', { name: 'ffuf' });
    expect(ffuf).toBeChecked();
    expect(ffuf).toBeEnabled();
    expect(screen.getByRole('checkbox', { name: 'dirsearch (extra pass)' })).toBeEnabled();
    expect(screen.getByRole('checkbox', { name: 'feroxbuster (extra pass)' })).toBeEnabled();
    expect(screen.queryByText(/will be skipped/)).not.toBeInTheDocument();
  });

  it('toggles run_ffuf from the ffuf checkbox', () => {
    const onChange = renderSection();
    fireEvent.click(screen.getByRole('checkbox', { name: 'ffuf' }));
    expect(onChange).toHaveBeenLastCalledWith({ run_ffuf: false });
  });

  it('warns that the step is skipped when every fuzzer is off', () => {
    renderSection(vi.fn(), { run_ffuf: false, run_dirsearch: false, run_feroxbuster: false });
    expect(screen.getByRole('alert')).toHaveTextContent(/step will be skipped/);
  });

  it('does not warn while one extra pass is still on', () => {
    renderSection(vi.fn(), { run_ffuf: false, run_dirsearch: true, run_feroxbuster: false });
    expect(screen.queryByRole('alert')).not.toBeInTheDocument();
  });

  it('defaults to ffuf on and dirsearch and feroxbuster off', () => {
    const { run_ffuf, run_dirsearch, run_feroxbuster, extensions } = DEFAULT_ENGINE_CONFIG.dir_file_fuzz.config;
    expect(run_ffuf).toBe(true);
    expect(run_dirsearch).toBe(false);
    expect(run_feroxbuster).toBe(false);
    expect(new Set(extensions).size).toBe(extensions.length);
  });

  it('ignores an extension that differs only by a dot or case', () => {
    const onChange = renderSection();
    const input = screen.getByRole('combobox', { name: 'Extensions' });
    fireEvent.change(input, { target: { value: '.PHP' } });
    fireEvent.keyDown(input, { key: 'Enter' });
    expect(onChange).toHaveBeenLastCalledWith({ extensions: ['php'] });
  });
});
