import { fireEvent, render, screen } from '@testing-library/react';
import { ThemeProvider } from '@mui/material/styles';
import { describe, expect, it, vi } from 'vitest';
import { hackerTheme } from '../../../../theme';
import { OpenAiCompatibleFields } from '../OpenAiCompatibleFields';

vi.mock('../../../../theme/useThemeTokens', async () => {
  const { hackerTheme: theme } = await import('../../../../theme');
  const { getResolvedTokens: resolve } = await import('../../../../theme/tokens');
  return {
    useThemeTokens: () => ({ tokens: resolve('hacker'), theme, isLight: false, isCyber: true, themeName: 'hacker' }),
  };
});

const renderFields = (props: Partial<React.ComponentProps<typeof OpenAiCompatibleFields>> = {}) => {
  const onBaseUrlChange = vi.fn();
  const onModelChange = vi.fn();
  render(
    <ThemeProvider theme={hackerTheme}>
      <OpenAiCompatibleFields
        baseUrl=""
        model=""
        models={[{ name: 'claude-opus-4-8' }, { name: 'gpt-oss-120b' }]}
        isModelsLoading={false}
        onBaseUrlChange={onBaseUrlChange}
        onModelChange={onModelChange}
        {...props}
      />
    </ThemeProvider>,
  );
  return { onBaseUrlChange, onModelChange };
};

describe('OpenAiCompatibleFields', () => {
  it('reports the base URL as typed', () => {
    const { onBaseUrlChange } = renderFields();
    fireEvent.change(screen.getByRole('textbox', { name: 'Base URL' }), { target: { value: 'https://gw.example.test/v1' } });
    expect(onBaseUrlChange).toHaveBeenLastCalledWith('https://gw.example.test/v1');
  });

  it('accepts a model id the gateway does not list', () => {
    const { onModelChange } = renderFields();
    fireEvent.change(screen.getByRole('combobox', { name: 'Model' }), { target: { value: 'my-private-model' } });
    expect(onModelChange).toHaveBeenLastCalledWith('my-private-model');
  });

  it('offers the listed models', () => {
    renderFields();
    fireEvent.mouseDown(screen.getByRole('combobox', { name: 'Model' }));
    expect(screen.getByRole('option', { name: 'claude-opus-4-8' })).toBeTruthy();
    expect(screen.getByRole('option', { name: 'gpt-oss-120b' })).toBeTruthy();
  });
});
