#!/bin/bash
# Entrypoint for the Temporal Go Executor container.
# Handles one-time setup and tool updates then starts the Go executor worker.

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
# Start deferred tool installer in the background so normal setup tasks
# run in parallel. We wait for it to finish just before the executor starts.
# ---------------------------------------------------------------------------
# echo "[entrypoint] Starting deferred tool installer in background..."
# /usr/src/internal_tools.sh &
# INTERNAL_TOOLS_PID=$!

# vulscan (nmap script)
if [ ! -d "/usr/src/github/scipag_vulscan" ]; then
  echo "Cloning Nmap Vulscan script..."
  git clone https://github.com/scipag/vulscan /usr/src/github/scipag_vulscan
fi
if [ ! -L "/usr/share/nmap/scripts/vulscan" ] && [ -d "/usr/src/github/scipag_vulscan" ]; then
  echo "Linking vulscan script..."
  ln -sf /usr/src/github/scipag_vulscan /usr/share/nmap/scripts/vulscan
fi

# kiterunner
if [ ! -f '/usr/local/bin/kr' ]; then
  echo "Installing kiterunner..."
  cd /usr/src/github
  ARCH=$(dpkg --print-architecture) && \
  wget -q https://github.com/assetnote/kiterunner/releases/download/v1.0.2/kiterunner_1.0.2_linux_${ARCH}.tar.gz && \
  tar -xvf kiterunner_1.0.2_linux_${ARCH}.tar.gz && \
  mv kr /usr/local/bin/ && \
  rm -rf kiterunner_1.0.2_linux_${ARCH}.tar.gz
  cd /usr/src/app
fi

# clone dirsearch default wordlist
if [ ! -d "/usr/src/wordlist" ]; then
  echo "Making Wordlist directory..."
  mkdir -p /usr/src/wordlist
fi

if [ ! -f "/usr/src/wordlist/dicc.txt" ]; then
  echo "Downloading Default Directory Bruteforce Wordlist..."
  wget -q https://raw.githubusercontent.com/maurosoria/dirsearch/master/db/dicc.txt -O /usr/src/wordlist/dicc.txt
fi

if [ ! -f "/usr/src/wordlist/raft-large-directories.txt" ]; then
  echo "Downloading raft-large-directories.txt Wordlist..."
  wget -q https://raw.githubusercontent.com/danielmiessler/SecLists/master/Discovery/Web-Content/raft-large-directories.txt -O /usr/src/wordlist/raft-large-directories.txt
fi

if [ ! -f "/usr/src/wordlist/deepmagic.com-prefixes-top50000.txt" ]; then
  echo "Downloading Deepmagic top 50000 Wordlist..."
  wget -q https://raw.githubusercontent.com/danielmiessler/SecLists/master/Discovery/DNS/deepmagic.com-prefixes-top50000.txt -O /usr/src/wordlist/deepmagic.com-prefixes-top50000.txt
fi

# Setup Auth Brute-Force Wordlists
if [ ! -d "/usr/src/wordlist/auth" ]; then
  mkdir -p /usr/src/wordlist/auth
fi
echo "Copying Auth Wordlists..."
cp -r /usr/src/app/wordlist/auth/* /usr/src/wordlist/auth/

if [ ! -f '/usr/src/wordlist/cpanel_users.txt' ]; then
  echo "Fetching cPanel2Shell wordlist..."
  wget -qO- https://raw.githubusercontent.com/danielmiessler/SecLists/master/Usernames/top-usernames-shortlist.txt >> /usr/src/wordlist/cpanel_users.txt
  sort -u /usr/src/wordlist/cpanel_users.txt -o /usr/src/wordlist/cpanel_users.txt
fi

cd /usr/src/app

# install gf patterns
if [ ! -d "/root/Gf-Patterns" ]; then
  echo "Installing GF Patterns..."
  mkdir -p ~/.gf
  # Note: GOPATH is /go in the go-tools-builder, but in the final runtime it's not set.
  # We copy patterns if the builder directory exists, otherwise clone
  git clone https://github.com/1ndianl33t/Gf-Patterns ~/Gf-Patterns
  mv ~/Gf-Patterns/*.json ~/.gf
fi

# store scan_results
if [ ! -d "/usr/src/scan_results" ]; then
  mkdir -p /usr/src/scan_results
fi

# test tools, required for configuration
naabu -version || true
subfinder -version || true
amass -version || true
nuclei -version || true

# nuclei templates setup
# Every guard below uses "$HOME/..." rather than "~/...": a tilde does not
# expand inside double quotes, so these tests were all unconditionally true and
# re-downloaded (or re-cloned) the whole set on every container start.
GEEKNIK_DIR="$HOME/nuclei-templates/geeknik_nuclei_templates"
if [ ! -d "$GEEKNIK_DIR/.git" ]; then
  echo "Installing Geeknik Nuclei templates..."
  rm -rf "$GEEKNIK_DIR"
  git clone --depth 1 https://github.com/geeknik/the-nuclei-templates.git "$GEEKNIK_DIR"
elif [ "$RUN_TOOL_UPDATES" = "1" ]; then
  echo "Updating Geeknik Nuclei templates..."
  git -C "$GEEKNIK_DIR" pull --ff-only --quiet || TOOL_UPDATE_RC=1
fi

if [ ! -f "$HOME/nuclei-templates/ssrf_nagli.yaml" ]; then
  echo "Downloading ssrf_nagli for Nuclei..."
  wget -q https://raw.githubusercontent.com/NagliNagli/BountyTricks/main/ssrf.yaml -O "$HOME/nuclei-templates/ssrf_nagli.yaml"
fi

# AI Map Templates
echo "Checking for AI Map Templates..."
if [ ! -f "$HOME/nuclei-templates/langserve-detect.yaml" ]; then
  wget -q https://raw.githubusercontent.com/BishopFox/aimap/refs/heads/main/templates/langserve-detect.yaml -O "$HOME/nuclei-templates/langserve-detect.yaml"
fi

if [ ! -f "$HOME/nuclei-templates/mcp-server-detect.yaml" ]; then
  wget -q https://github.com/BishopFox/aimap/raw/refs/heads/main/templates/mcp-server-detect.yaml -O "$HOME/nuclei-templates/mcp-server-detect.yaml"
fi

if [ ! -f "$HOME/nuclei-templates/mcp-tool-enum.yaml" ]; then
  wget -q https://github.com/BishopFox/aimap/raw/refs/heads/main/templates/mcp-tool-enum.yaml -O "$HOME/nuclei-templates/mcp-tool-enum.yaml"
fi

if [ ! -f "$HOME/nuclei-templates/openai-compat-detect.yaml" ]; then
  wget -q https://github.com/BishopFox/aimap/raw/refs/heads/main/templates/openai-compat-detect.yaml -O "$HOME/nuclei-templates/openai-compat-detect.yaml"
fi

if [ ! -f "$HOME/nuclei-templates/prompt-leak.yaml" ]; then
  wget -q https://github.com/BishopFox/aimap/raw/refs/heads/main/templates/prompt-leak.yaml -O "$HOME/nuclei-templates/prompt-leak.yaml"
fi

# edoardottt/missing-cve-nuclei-templates — ~64k CVEs absent from the official set
# Covers XSS (22k), SQLi (12k), DoS (15k), RCE (3k), Path Traversal, SSRF, LFI, XXE, SSTI
echo "Checking for missing-cve nuclei templates"
if [ ! -d "$HOME/nuclei-templates/missing-cve" ]; then
  echo "Installing missing-cve nuclei templates (~64k additional CVEs)"
  git clone --depth 1 https://github.com/edoardottt/missing-cve-nuclei-templates.git \
    "$HOME/nuclei-templates/missing-cve"
fi

# emadshanab/Nuclei-Templates-Collection — aggregates 400+ community repos
# Includes Log4Shell, Spring RCE, F5, WAF detection, Kubernetes, SAP, Oracle, WebSphere
echo "Checking for Nuclei Templates Collection (400+ community repos)"
if [ ! -d "$HOME/nuclei-templates/community-collection" ]; then
  echo "Installing Nuclei Templates Collection (400+ community repos)"
  git clone --depth 1 https://github.com/emadshanab/Nuclei-Templates-Collection.git \
    "$HOME/nuclei-templates/community-collection"
fi

# 0xKayala/Custom-Nuclei-Templates — bug-bounty focused custom templates
  echo "Checking for 0xKayala custom nuclei templates"
if [ ! -d "$HOME/nuclei-templates/kayala-custom" ]; then
  echo "Installing 0xKayala custom nuclei templates"
  git clone --depth 1 https://github.com/0xKayala/Custom-Nuclei-Templates.git \
    "$HOME/nuclei-templates/kayala-custom"
fi

if [ "$RUN_TOOL_UPDATES" = "1" ]; then
  vulnx update || TOOL_UPDATE_RC=1
fi

# Configure vigolium to scan all severity levels for known issues.
# Local config writes, not network calls, so these stay on every start.
vigolium config set known_issue_scan.severities "critical,high,medium,low,info" || true
vigolium config set dynamic-assessment.max_feedback_rounds=3 || true
vigolium config set known_issue_scan.enrich_targets=true || true
vigolium config set discovery.enrich_targets=true || true
vigolium config set spidering.max_duration "20m" || true
vigolium config set known_issue_scan.templates_dir="/root/nuclei-templates" || true

if [ "$RUN_TOOL_UPDATES" = "1" ]; then
  vigolium update || TOOL_UPDATE_RC=1
  vigolium doctor --fix || TOOL_UPDATE_RC=1
  nuclei -update || TOOL_UPDATE_RC=1

  if [ "$TOOL_UPDATE_RC" = "0" ]; then
    touch "$TOOL_UPDATE_STAMP"
    echo "[entrypoint] Tool updates completed; sentinel refreshed."
  else
    echo "[entrypoint] Some tool updates failed; sentinel left stale so the next start retries."
  fi
fi
# Split oversized nuclei tags
# echo "[entrypoint] Running Nuclei tag splitter..."
# python3 /usr/src/scripts/nuclei_tag_splitter.py

# wait $INTERNAL_TOOLS_PID
echo "[entrypoint] Starting Temporal Go Executor..."
# Forward the container command (docker-compose.worker.yml passes --worker-name).
exec /usr/local/bin/r3ngine-executor "$@"
