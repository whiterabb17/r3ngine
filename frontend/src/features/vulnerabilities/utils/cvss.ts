/** Format a CVSS score for display, marking LLM/severity-band estimates. */
export function formatCvssScoreLabel(
  score: number | null | undefined,
  estimated?: boolean | null,
  emptyLabel = 'N/A',
): string {
  if (score === null || score === undefined) {
    return emptyLabel;
  }
  const formatted = Number.isInteger(score) ? String(score) : score.toFixed(1);
  return estimated ? `${formatted} (est.)` : formatted;
}
