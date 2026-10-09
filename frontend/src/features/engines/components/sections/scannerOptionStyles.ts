import { alpha } from '@mui/material/styles';
import { getFieldSx } from '../../../../theme/semanticColors';
import { useThemeTokens } from '../../../../theme/useThemeTokens';

/** Field, checkbox and indented sub-section styles shared by the per-scanner option blocks. */
export function useScannerOptionStyles() {
  const { tokens, isLight } = useThemeTokens();
  return {
    fieldSx: getFieldSx(isLight, tokens),
    chkSx: { color: tokens.accent.primary, '&.Mui-checked': { color: tokens.accent.primary } },
    subSectionSx: { mt: 2, pl: 2, borderLeft: `2px solid ${alpha(tokens.accent.primary, 0.25)}` },
  };
}
