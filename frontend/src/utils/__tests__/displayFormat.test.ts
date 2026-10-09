import { describe, expect, it } from 'vitest';

import { formatYesNo } from '../displayFormat';

describe('formatYesNo', () => {
  it('renders true as Yes', () => {
    expect(formatYesNo(true)).toBe('Yes');
  });

  it('renders false as No rather than the placeholder', () => {
    expect(formatYesNo(false)).toBe('No');
  });

  it.each([null, undefined])('renders %s as the placeholder', (value) => {
    expect(formatYesNo(value)).toBe('N/A');
    expect(formatYesNo(value, '-')).toBe('-');
  });
});
