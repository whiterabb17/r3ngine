#!/bin/bash
# Entrypoint for the Temporal Go Executor container.
#
# Go is the sole writer into the shared `wordlist` and `nuclei_templates`
# volumes (compose mounts them on both python and go, but only this script
# downloads/clones into them). Go must be self-sufficient: it never depends
# on the `/usr/src/app` Django tree (no `../web` bind-mount on this service)
# other than this entrypoint file itself, which compose bind-mounts directly
# at `/usr/src/app/executor-entrypoint.sh`. Auth/SMTP wordlists are baked
# into the image at `/opt/r3ngine/wordlist` for exactly this reason.
#
# Handles one-time setup and tool updates, then starts the Go executor worker.

# ---------------------------------------------------------------------------
# Tool updates (nuclei/vigolium/vulnx, template repo pulls) are network-bound
# and take minutes, so running them on every start made a GitHub or registry
# outage enough to block the worker from coming up at all. Run them at most
# once a week, tracked by a sentinel on the persistent tool_config volume.
# A first-ever start has no sentinel and therefore updates as before.
# ---------------------------------------------------------------------------
TOOL_UPDATE_STAMP="/root/.config/r3ngine/go-executor-tool-update.stamp"
TOOL_UPDATE_MAX_AGE_DAYS=7
TOOL_UPDATE_RC=0

mkdir -p "$(dirname "$TOOL_UPDATE_STAMP")"

if [ ! -f "$TOOL_UPDATE_STAMP" ]; then
  RUN_TOOL_UPDATES=1
  echo "[entrypoint] No tool-update sentinel found - running tool updates."
elif [ -n "$(find "$TOOL_UPDATE_STAMP" -mtime +"$TOOL_UPDATE_MAX_AGE_DAYS" 2>/dev/null)" ]; then
  RUN_TOOL_UPDATES=1
  echo "[entrypoint] Tool updates older than ${TOOL_UPDATE_MAX_AGE_DAYS} days - refreshing."
else
  RUN_TOOL_UPDATES=0
  echo "[entrypoint] Tool updates ran within ${TOOL_UPDATE_MAX_AGE_DAYS} days - skipping."
fi

# ---------------------------------------------------------------------------
# vulscan (nmap script) — cloned under /opt (not /usr/src/github, which is
# python's github_repos volume) and symlinked into nmap's scripts dir.
# ---------------------------------------------------------------------------
if [ ! -d "/opt/nmap-vulscan/.git" ]; then
  echo "Cloning Nmap Vulscan script..."
  rm -rf /opt/nmap-vulscan
  git clone --depth 1 https://github.com/scipag/vulscan /opt/nmap-vulscan || \
    echo "WARNING: vulscan clone failed; will retry next start"
fi
if [ ! -L "/usr/share/nmap/scripts/vulscan" ] && [ -d "/opt/nmap-vulscan" ]; then
  echo "Linking vulscan script..."
  ln -sf /opt/nmap-vulscan /usr/share/nmap/scripts/vulscan
fi

# ---------------------------------------------------------------------------
# kiterunner binary — compiled CLI, go-owned. Downloaded to a scratch tmpdir
# so this never touches /usr/src/app.
# ---------------------------------------------------------------------------
if [ ! -f '/usr/local/bin/kr' ]; then
  echo "Installing kiterunner..."
  kr_build_tmp=$(mktemp -d)
  ARCH=$(dpkg --print-architecture)
  if wget -q "https://github.com/assetnote/kiterunner/releases/download/v1.0.2/kiterunner_1.0.2_linux_${ARCH}.tar.gz" \
      -O "${kr_build_tmp}/kiterunner.tar.gz" \
    && tar -xf "${kr_build_tmp}/kiterunner.tar.gz" -C "${kr_build_tmp}" kr; then
    mv "${kr_build_tmp}/kr" /usr/local/bin/kr
  else
    echo "WARNING: could not install kiterunner; will retry next start"
  fi
  rm -rf "${kr_build_tmp}"
fi

# ---------------------------------------------------------------------------
# Wordlists — go is the sole writer into the shared `wordlist` volume.
# Each asset is independently idempotent via its own existence check.
# ---------------------------------------------------------------------------
mkdir -p /usr/src/wordlist

_fetch_wordlist() {
  # $1 = dest path, $2 = url. Retries next start if the file is missing or empty.
  dest="$1"
  url="$2"
  if [ -s "$dest" ]; then
    return 0
  fi
  echo "Downloading $(basename "$dest")..."
  tmp=$(mktemp)
  if wget -q "$url" -O "$tmp" && [ -s "$tmp" ]; then
    mv "$tmp" "$dest"
  else
    echo "WARNING: could not fetch $(basename "$dest"); will retry next start"
    rm -f "$tmp" "$dest"
    return 1
  fi
}

_fetch_wordlist "/usr/src/wordlist/dicc.txt" \
  "https://raw.githubusercontent.com/maurosoria/dirsearch/master/db/dicc.txt"
_fetch_wordlist "/usr/src/wordlist/raft-large-directories.txt" \
  "https://raw.githubusercontent.com/danielmiessler/SecLists/master/Discovery/Web-Content/raft-large-directories.txt"
_fetch_wordlist "/usr/src/wordlist/deepmagic.com-prefixes-top50000.txt" \
  "https://raw.githubusercontent.com/danielmiessler/SecLists/master/Discovery/DNS/deepmagic.com-prefixes-top50000.txt"
_fetch_wordlist "/usr/src/wordlist/api-endpoints.txt" \
  "https://wordlists-cdn.assetnote.io/data/automated/httparchive_apiroutes_2023_01_28.txt"

# Auth brute-force wordlists — copied from the image-baked path, never from
# a bind-mounted Django tree (go has no `../web` mount).
mkdir -p /usr/src/wordlist/auth
echo "Copying Auth Wordlists..."
cp -r /opt/r3ngine/wordlist/auth/* /usr/src/wordlist/auth/

# SMTP username enumeration wordlist — same image-baked source.
cp /opt/r3ngine/wordlist/smtp-usernames.txt /usr/src/wordlist/smtp-usernames.txt

if [ ! -s '/usr/src/wordlist/cpanel_users.txt' ]; then
  echo "Fetching cPanel2Shell wordlist..."
  cpanel_tmp=$(mktemp)
  if wget -qO- https://raw.githubusercontent.com/danielmiessler/SecLists/master/Usernames/top-usernames-shortlist.txt > "$cpanel_tmp" \
    && [ -s "$cpanel_tmp" ]; then
    sort -u "$cpanel_tmp" -o /usr/src/wordlist/cpanel_users.txt
  else
    echo "WARNING: could not fetch cpanel_users.txt; will retry next start"
    rm -f /usr/src/wordlist/cpanel_users.txt
  fi
  rm -f "$cpanel_tmp"
fi

# kiterunner route wordlists (.kite). Each is fetched on its own and only
# moved into place once fully extracted, so a failed or partial download is
# retried on the next start rather than leaving a truncated file behind.
mkdir -p /usr/src/wordlist/kr
for kite in routes-small routes-large; do
  if [ ! -s "/usr/src/wordlist/kr/${kite}.kite" ]; then
    kr_tmp=$(mktemp -d)
    if wget -q "https://wordlists-cdn.assetnote.io/data/kiterunner/${kite}.kite.tar.gz" -O "${kr_tmp}/${kite}.tar.gz" \
      && tar -xzf "${kr_tmp}/${kite}.tar.gz" -C "${kr_tmp}" \
      && [ -s "${kr_tmp}/${kite}.kite" ]; then
      mv "${kr_tmp}/${kite}.kite" "/usr/src/wordlist/kr/${kite}.kite"
    else
      echo "WARNING: could not fetch the kiterunner ${kite} wordlist; kiterunner skips it until the next start"
    fi
    rm -rf "${kr_tmp}"
  fi
done

# ---------------------------------------------------------------------------
# store scan_results
# ---------------------------------------------------------------------------
mkdir -p /usr/src/scan_results

# ---------------------------------------------------------------------------
# GF patterns — go owns `gf` now that it is in ROUTED_TOOLS, so go is the
# sole writer of /root/.gf.
# ---------------------------------------------------------------------------
mkdir -p /root/.gf
if ! compgen -G "/root/.gf/*.json" > /dev/null; then
  echo "Installing GF Patterns..."
  rm -rf /root/Gf-Patterns
  if git clone --depth 1 https://github.com/1ndianl33t/Gf-Patterns /root/Gf-Patterns; then
    mv /root/Gf-Patterns/*.json /root/.gf/ 2>/dev/null || true
  else
    echo "WARNING: Gf-Patterns clone failed; will retry next start"
    rm -rf /root/Gf-Patterns
  fi
fi

# ---------------------------------------------------------------------------
# Soft version checks, required for configuration. None of these may block
# worker startup if a binary is temporarily missing or misbehaving.
# ---------------------------------------------------------------------------
naabu -version || true
subfinder -version || true
amass -version || true
nuclei -version || true

# ---------------------------------------------------------------------------
# Community Nuclei Templates — go is the sole writer into the shared
# nuclei_templates volume. Layout matches what vuln.py / definitions.py
# expect (flat geeknik/aimap/missing-cve/etc. dirs directly under
# /root/nuclei-templates, which nuclei walks recursively via -t).
# ---------------------------------------------------------------------------
mkdir -p /root/nuclei-templates

GEEKNIK_DIR="/root/nuclei-templates/geeknik"
if [ ! -d "$GEEKNIK_DIR/.git" ]; then
  echo "Installing Geeknik Nuclei templates..."
  rm -rf "$GEEKNIK_DIR"
  git clone --depth 1 https://github.com/geeknik/the-nuclei-templates.git "$GEEKNIK_DIR"
elif [ "$RUN_TOOL_UPDATES" = "1" ]; then
  echo "Updating Geeknik Nuclei templates..."
  git -C "$GEEKNIK_DIR" pull --ff-only --quiet || TOOL_UPDATE_RC=1
fi

if [ ! -f "/root/nuclei-templates/ssrf_nagli.yaml" ]; then
  echo "Downloading ssrf_nagli for Nuclei..."
  wget -q https://raw.githubusercontent.com/NagliNagli/BountyTricks/main/ssrf.yaml -O "/root/nuclei-templates/ssrf_nagli.yaml" || true
fi

# BishopFox AI Map templates — LangServe, MCP, OpenAI-compat, prompt-leak detection
AI_TPL_DIR="/root/nuclei-templates/aimap"
mkdir -p "$AI_TPL_DIR"
for tpl in langserve-detect mcp-server-detect mcp-tool-enum openai-compat-detect prompt-leak; do
  if [ ! -f "$AI_TPL_DIR/${tpl}.yaml" ]; then
    wget -q "https://github.com/BishopFox/aimap/raw/refs/heads/main/templates/${tpl}.yaml" \
      -O "$AI_TPL_DIR/${tpl}.yaml" || true
  fi
done

# edoardottt/missing-cve-nuclei-templates — ~64k CVEs absent from the official set
if [ ! -d "/root/nuclei-templates/missing-cve/.git" ]; then
  echo "Installing missing-cve nuclei templates (~64k additional CVEs)..."
  rm -rf "/root/nuclei-templates/missing-cve"
  git clone --depth 1 https://github.com/edoardottt/missing-cve-nuclei-templates.git \
    "/root/nuclei-templates/missing-cve" || \
    echo "WARNING: missing-cve clone failed; will retry next start"
fi

# emadshanab/Nuclei-Templates-Collection — aggregates 400+ community repos
if [ ! -d "/root/nuclei-templates/community-collection/.git" ]; then
  echo "Installing Nuclei Templates Collection (400+ community repos)..."
  rm -rf "/root/nuclei-templates/community-collection"
  git clone --depth 1 https://github.com/emadshanab/Nuclei-Templates-Collection.git \
    "/root/nuclei-templates/community-collection" || \
    echo "WARNING: community-collection clone failed; will retry next start"
fi

# 0xKayala/Custom-Nuclei-Templates — bug-bounty focused custom templates
if [ ! -d "/root/nuclei-templates/kayala-custom/.git" ]; then
  echo "Installing 0xKayala custom nuclei templates..."
  rm -rf "/root/nuclei-templates/kayala-custom"
  git clone --depth 1 https://github.com/0xKayala/Custom-Nuclei-Templates.git \
    "/root/nuclei-templates/kayala-custom" || \
    echo "WARNING: kayala-custom clone failed; will retry next start"
fi

# topscoder/nuclei-wordfence-cve — 70k+ WordPress CVE templates (daily-updated)
if [ ! -d "/root/nuclei-templates/wordfence/.git" ]; then
  echo "Installing Wordfence nuclei templates..."
  rm -rf "/root/nuclei-templates/wordfence"
  git clone --depth 1 https://github.com/topscoder/nuclei-wordfence-cve.git \
    "/root/nuclei-templates/wordfence" || \
    echo "WARNING: wordfence clone failed; will retry next start"
elif [ "$RUN_TOOL_UPDATES" = "1" ]; then
  echo "Updating Wordfence nuclei templates..."
  git -C /root/nuclei-templates/wordfence pull --ff-only --quiet || TOOL_UPDATE_RC=1
fi
# Keep Wordfence under wordfence/ only — do not flatten into the volume root
# (Tool Settings lists root-level YAML as operator customs; a flatten would
# flood that UI with tens of thousands of CVE templates). nuclei -t walks
# /root/nuclei-templates recursively, so wordfence/ is still scanned.

# ---------------------------------------------------------------------------
# Seed sentinels — require substantive template content, not just mkdir.
# ---------------------------------------------------------------------------
if [ -s "/usr/src/wordlist/dicc.txt" ] \
  && [ -s "/usr/src/wordlist/raft-large-directories.txt" ] \
  && [ -d "/root/nuclei-templates/geeknik/.git" ] \
  && compgen -G "/root/.gf/*.json" > /dev/null; then
  touch /usr/src/wordlist/.seeded
  touch /root/nuclei-templates/.seeded
  echo "[entrypoint] Wordlist/nuclei-template seed sentinels written."
else
  echo "[entrypoint] WARNING: required wordlist/nuclei-template/GF assets missing; seed sentinels not written."
fi

# ---------------------------------------------------------------------------
# Configure vigolium (local config writes — stay on every start).
# ---------------------------------------------------------------------------
vigolium config set known_issue_scan.severities "critical,high,medium,low,info" || true
vigolium config set dynamic-assessment.max_feedback_rounds=3 || true
vigolium config set known_issue_scan.enrich_targets=true || true
vigolium config set discovery.enrich_targets=true || true
vigolium config set spidering.max_duration "20m" || true
vigolium config set known_issue_scan.templates_dir="/root/nuclei-templates" || true

# Weekly CLI updates run in the background so the worker can become healthy
# (seed sentinels + r3ngine-executor) without waiting on nuclei/vigolium/vulnx.
if [ "$RUN_TOOL_UPDATES" = "1" ]; then
  (
    upd_rc=0
    if [ -f /root/nuclei-templates/wordfence/requirements.txt ]; then
      pip3 install -q -r /root/nuclei-templates/wordfence/requirements.txt || upd_rc=1
    fi
    vigolium update || upd_rc=1
    vigolium doctor --fix || upd_rc=1
    nuclei -update || upd_rc=1
    vulnx update || upd_rc=1
    if [ "$upd_rc" = "0" ]; then
      touch "$TOOL_UPDATE_STAMP"
      echo "[entrypoint] Background tool updates completed; sentinel refreshed."
    else
      echo "[entrypoint] Background tool updates failed; sentinel left stale for retry."
    fi
  ) &
fi

echo "[entrypoint] Starting Temporal Go Executor..."
# Forward the container command (docker-compose.worker.yml passes --worker-name).
exec /usr/local/bin/r3ngine-executor "$@"
