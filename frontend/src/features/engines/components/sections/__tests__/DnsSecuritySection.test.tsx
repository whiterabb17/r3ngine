import { fireEvent, render, screen } from '@testing-library/react';
import { ThemeProvider } from '@mui/material/styles';
import { describe, expect, it, vi } from 'vitest';
import { hackerTheme } from '../../../../../theme';
import { DEFAULT_ENGINE_CONFIG } from '../../../types/engineConfig';
import type { DnsSecurityConfig } from '../../../types/engineConfig';
import { DnsSecuritySection } from '../DnsSecuritySection';

vi.mock('../../../../../theme/useThemeTokens', async () => {
  const { hackerTheme: theme } = await import('../../../../../theme');
  const { getResolvedTokens: resolve } = await import('../../../../../theme/tokens');
  return {
    useThemeTokens: () => ({ tokens: resolve('hacker'), theme, isLight: false, isCyber: true, themeName: 'hacker' }),
  };
});

const renderSection = (overrides: Partial<DnsSecurityConfig> = {}) => {
  const onChange = vi.fn();
  render(
    <ThemeProvider theme={hackerTheme}>
      <DnsSecuritySection
        config={{ ...DEFAULT_ENGINE_CONFIG.dns_security.config, ...overrides }}
        enabled
        onToggle={vi.fn()}
        onChange={onChange}
      />
    </ThemeProvider>,
  );
  return onChange;
};

describe('DnsSecuritySection', () => {
  it('reflects the config in its checkboxes and threshold field', () => {
    renderSection({ enable_axfr: true, enable_dnssec_check: false, enable_dns_brute: true, amplification_threshold: 7 });

    expect(screen.getByRole('checkbox', { name: 'Zone transfer (AXFR) check' })).toBeChecked();
    expect(screen.getByRole('checkbox', { name: 'DNSSEC validation' })).not.toBeChecked();
    expect(screen.getByRole('checkbox', { name: 'DNS brute force' })).toBeChecked();
    expect(screen.getByRole('spinbutton', { name: 'Amplification threshold' })).toHaveValue(7);
  });

  it.each([
    ['Zone transfer (AXFR) check', 'enable_axfr'],
    ['DNSSEC validation', 'enable_dnssec_check'],
    ['DNS brute force', 'enable_dns_brute'],
  ] as const)('toggles %s into %s', (label, field) => {
    const onChange = renderSection({ enable_axfr: false, enable_dnssec_check: false, enable_dns_brute: false });
    fireEvent.click(screen.getByRole('checkbox', { name: label }));
    expect(onChange).toHaveBeenLastCalledWith({ [field]: true });
  });

  it('writes the amplification threshold as a number', () => {
    const onChange = renderSection();
    fireEvent.change(screen.getByRole('spinbutton', { name: 'Amplification threshold' }), { target: { value: '25' } });
    expect(onChange).toHaveBeenLastCalledWith({ amplification_threshold: 25 });
  });

  it('clamps the amplification threshold to at least 1', () => {
    const onChange = renderSection();
    fireEvent.change(screen.getByRole('spinbutton', { name: 'Amplification threshold' }), { target: { value: '0' } });
    expect(onChange).toHaveBeenLastCalledWith({ amplification_threshold: 1 });
  });
});
