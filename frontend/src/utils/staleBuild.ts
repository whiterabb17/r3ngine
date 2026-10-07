/**
 * A tab opened before a redeploy still runs the previous build. When it then
 * loads a page it has not visited yet, the chunk it asks for is gone (404) or,
 * with a stable file name, comes from the new build and imports exports the old
 * modules do not have. Either way the fix is to load the new build: reload once.
 */

const RELOAD_KEY = 'r3ngine:stale-build-reload-at';
/** A second failure this soon after a reload is a real error, not a stale tab. */
const RELOAD_GUARD_MS = 30_000;

const STALE_BUILD_PATTERNS = [
  /Failed to fetch dynamically imported module/i, // Chromium
  /error loading dynamically imported module/i, // Firefox
  /Importing a module script failed/i, // Safari
  /does not provide an export named/i, // old and new modules mixed
  /Unable to preload CSS/i, // Vite preload helper
];

export function isStaleBuildError(error: unknown): boolean {
  const message = error instanceof Error ? error.message : String(error ?? '');
  return STALE_BUILD_PATTERNS.some((pattern) => pattern.test(message));
}

/** Reload to pick up the new build, unless that was just tried. Returns whether it reloads. */
export function reloadOnceForStaleBuild(
  reload: () => void = () => window.location.reload(),
  now: number = Date.now(),
): boolean {
  try {
    const last = Number(sessionStorage.getItem(RELOAD_KEY)) || 0;
    if (now - last < RELOAD_GUARD_MS) return false;
    sessionStorage.setItem(RELOAD_KEY, String(now));
  } catch {
    // Without storage the guard cannot stop a reload loop, so leave it to the user.
    return false;
  }
  reload();
  return true;
}
