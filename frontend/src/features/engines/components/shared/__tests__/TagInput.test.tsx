import { fireEvent, render, screen } from '@testing-library/react';
import { ThemeProvider } from '@mui/material/styles';
import { describe, expect, it, vi } from 'vitest';
import { hackerTheme } from '../../../../../theme';
import { TagInput } from '../TagInput';

vi.mock('../../../../../theme/useThemeTokens', async () => {
  const { hackerTheme: theme } = await import('../../../../../theme');
  const { getResolvedTokens: resolve } = await import('../../../../../theme/tokens');
  return {
    useThemeTokens: () => ({ tokens: resolve('hacker'), theme, isLight: false, isCyber: true, themeName: 'hacker' }),
  };
});

const renderInput = (value: string[], onChange = vi.fn(), dedupeKey?: (tag: string) => string) => {
  render(
    <ThemeProvider theme={hackerTheme}>
      <TagInput label="Tags" value={value} onChange={onChange} dedupeKey={dedupeKey} />
    </ThemeProvider>,
  );
  return onChange;
};

const typeAndEnter = (text: string) => {
  const input = screen.getByRole('combobox');
  fireEvent.change(input, { target: { value: text } });
  fireEvent.keyDown(input, { key: 'Enter' });
};

describe('TagInput', () => {
  it('renders each value as a deletable chip', () => {
    const onChange = renderInput(['cve', 'rce']);

    expect(screen.getByText('cve')).toBeInTheDocument();
    expect(screen.getByText('rce')).toBeInTheDocument();

    const chip = screen.getByText('cve').closest('.MuiChip-root');
    const deleteIcon = chip?.querySelector('.MuiChip-deleteIcon');
    expect(deleteIcon).not.toBeNull();
    fireEvent.click(deleteIcon!);
    expect(onChange).toHaveBeenCalledWith(['rce']);
  });

  it('adds a typed value on Enter', () => {
    const onChange = renderInput([]);
    const input = screen.getByRole('combobox');
    fireEvent.change(input, { target: { value: 'xss' } });
    fireEvent.keyDown(input, { key: 'Enter' });
    expect(onChange).toHaveBeenCalledWith(['xss']);
  });

  it('ignores a value that is already present', () => {
    const onChange = renderInput(['php', 'html']);
    typeAndEnter(' php ');
    expect(onChange).not.toHaveBeenCalledWith(expect.arrayContaining([' php ']));
    expect(onChange).toHaveBeenLastCalledWith(['php', 'html']);
  });

  it('uses dedupeKey to detect duplicates', () => {
    const onChange = renderInput(['php'], vi.fn(), (tag) => tag.trim().replace(/^\./, '').toLowerCase());
    typeAndEnter('.PHP');
    expect(onChange).toHaveBeenLastCalledWith(['php']);
  });
});
