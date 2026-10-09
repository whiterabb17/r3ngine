/**
 * Display text for a boolean field. `false` must read "No", not fall through to the
 * placeholder the way `value || 'N/A'` does; only a missing value gets the placeholder.
 */
export const formatYesNo = (value: boolean | null | undefined, missing = 'N/A'): string => {
  if (value === true) return 'Yes';
  if (value === false) return 'No';
  return missing;
};
