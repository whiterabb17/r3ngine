#!/bin/bash
# Entrypoint for the Temporal Python Orchestrator container.
# Handles one-time Python-only setup/updates then starts the Temporal worker.
#
# Go owns the shared `wordlist` and `nuclei_templates` volumes (sole writer),
# and now owns `gf` (routed via ROUTED_TOOLS). This script must not download
# scanner wordlists, nuclei community templates, vulscan, `kr`, or run
# `vulnx update` — those belong to docker/temporal-go-executor/entrypoint.sh.

# ---------------------------------------------------------------------------
# GF patterns — go is the primary owner of /root/.gf now that `gf` is routed
# via ROUTED_TOOLS. This is a backup sync only: it copies the baked-in
# patterns shipped in the image if go hasn't seeded the shared volume yet
# (e.g. go hasn't started), so `gf` still has something to work with. It
# never clones the Gf-Patterns repo itself — that clone is go's job.
# ---------------------------------------------------------------------------
if [ -z "$(ls -A /root/.gf/*.json 2>/dev/null)" ]; then
  echo "No GF patterns found in /root/.gf yet (go executor may not have seeded); syncing backup patterns..."
  mkdir -p /root/.gf
  if [ -d "/usr/src/app/gf-patterns" ]; then
    cp -f /usr/src/app/gf-patterns/*.json /root/.gf/
  elif [ -d "/usr/src/gf-patterns" ]; then
    cp -f /usr/src/gf-patterns/*.json /root/.gf/
  else
    echo "Warning: no GF patterns directory found for backup sync!"
  fi
else
  echo "GF patterns already present in /root/.gf; skipping backup sync."
fi

# ---------------------------------------------------------------------------
# Tool updates (pip upgrades, whatportis, spiderfoot deps) are network-bound
# and take minutes, so running them on every start made a PyPI or GitHub
# outage enough to block the worker from coming up at all. Run them at most
# once a week, tracked by a sentinel on the persistent tool_config volume.
# A first-ever start has no sentinel and therefore updates as before.
# ---------------------------------------------------------------------------
TOOL_UPDATE_STAMP="/root/.config/r3ngine/python-orchestrator-tool-update.stamp"
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

# Python-only pip upgrades (OpenSSL/cryptography compatibility, retry backoff lib).
if [ "$RUN_TOOL_UPDATES" = "1" ]; then
  pip3 install --upgrade --no-cache-dir pyOpenSSL==24.0.0 tenacity==8.2.2 || TOOL_UPDATE_RC=1
fi

# Fixtures/engines/hardware profiles are loaded once by the web entrypoint
# (sole loaddata owner). Python does not reload any fixtures here.

# Temporary fix for whatportis bug
sed -i 's/purge()/truncate()/g' "$(python3 -c "import whatportis.cli; print(whatportis.cli.__file__)")"

# Temporary fix for Sublist3r get_csrftoken bug
if [ -f "/usr/src/github/Sublist3r/sublist3r.py" ]; then
  sed -i "s/token = csrf_regex.findall(resp)\[0\]/token = csrf_regex.findall(resp)[0] if csrf_regex.findall(resp) else ''/g" /usr/src/github/Sublist3r/sublist3r.py

  # Temporary fix for Sublist3r and subbrute invalid escape sequences in Python 3.12
  python3 << 'EOF'
import os
sublist3r_path = '/usr/src/github/Sublist3r/sublist3r.py'
subbrute_path = '/usr/src/github/Sublist3r/subbrute/subbrute.py'
if os.path.exists(sublist3r_path):
    with open(sublist3r_path, 'r', encoding='utf-8') as f:
        code = f.read()
    if 'print(r"""%' not in code:
        targets = [
            ('print("""%', 'print(r"""%'),
            ("re.compile('<cite.*?>(.*?)<\\/cite>')", "re.compile(r'<cite.*?>(.*?)<\\/cite>')"),
            ('re.sub("<(\\/)?b>", "", link)', 're.sub(r"<(\\/)?b>", "", link)'),
            ("re.sub('<(\\/)?strong>|<span.*?>|<|>', '', link)", "re.sub(r'<(\\/)?strong>|<span.*?>|<|>', '', link)"),
            ("re.compile('<a name=\"hostanchor\"><\\/a>Host Records.*?<table.*?>(.*?)</table>', re.S)", "re.compile(r'<a name=\"hostanchor\"><\\/a>Host Records.*?<table.*?>(.*?)</table>', re.S)"),
            ('re.compile("^(http|https)?[a-zA-Z0-9]+([\\-\\.]{1}[a-zA-Z0-9]+)*\\.[a-zA-Z]{2,}$")', 're.compile(r"^(http|https)?[a-zA-Z0-9]+([\\-\\.]{1}[a-zA-Z0-9]+)*\\.[a-zA-Z]{2,}$")'),
        ]
        for old, new in targets:
            code = code.replace(old, new)
        with open(sublist3r_path, 'w', encoding='utf-8') as f:
            f.write(code)
if os.path.exists(subbrute_path):
    with open(subbrute_path, 'r', encoding='utf-8') as f:
        code = f.read()
    sb_old = 'domain_match = re.compile("([a-zA-Z0-9_-]*\\.[a-zA-Z0-9_-]*\\.[a-zA-Z0-9_-]*)+")'
    sb_new = 'domain_match = re.compile(r"([a-zA-Z0-9_-]*\\.[a-zA-Z0-9_-]*\\.[a-zA-Z0-9_-]*)+")'
    if sb_old in code:
        code = code.replace(sb_old, sb_new)
        with open(subbrute_path, 'w', encoding='utf-8') as f:
            f.write(code)
EOF
fi

# Temporary fix for ctfr invalid escape sequences in Python 3.12
if [ -f "/usr/src/github/ctfr/ctfr.py" ]; then
  grep -qF "b = r'''" /usr/src/github/ctfr/ctfr.py || \
    sed -i "s/b = '''/b = r'''/g" /usr/src/github/ctfr/ctfr.py
  grep -qF "r'.*www\\.'" /usr/src/github/ctfr/ctfr.py || \
    sed -i "s/'.*www\\\\.'/r'.*www\\\\.'/g" /usr/src/github/ctfr/ctfr.py
fi

# Temporary fix for SwaggerSpy swaggerspy.py — two bugs in the regex_patterns dict:
#   1. Missing comma after 'JIRA Personal Access Token (PAT) Regex' entry
#   2. 'possible_Creds' uses r'...' with \-continuation inside the string (SyntaxError)
# Guard: py_compile exits non-zero while the SyntaxError is still present; skips once fixed
if [ -f "/usr/src/github/SwaggerSpy/swaggerspy.py" ] && \
   ! python3 -m py_compile /usr/src/github/SwaggerSpy/swaggerspy.py 2>/dev/null; then
  python3 << 'EOF'
path = '/usr/src/github/SwaggerSpy/swaggerspy.py'
with open(path, 'r', encoding='utf-8') as f:
    lines = f.readlines()

JIRA_OLD    = "\t'JIRA Personal Access Token (PAT) Regex'  : r'ATATTAC[a-zA-Z0-9]{24,48}'\n"
JIRA_NEW    = "\t'JIRA Personal Access Token (PAT) Regex'  : r'ATATTAC[a-zA-Z0-9]{24,48}',\n"
CREDS_START = "\t'possible_Creds' : r'"
CREDS_FIXED = "\t'possible_Creds' : r'(?i)(\"password\\s*[`=:\"]+\\s*[^\\s]+|password is\\s*[`=:\"]*\\s*[^\\s]+|pwd\\s*[`=:\"]*\\s*[^\\s]+|passwd\\s*[`=:\"]+\\s*[^\\s]+)',\n"

result = []
i = 0
while i < len(lines):
    line = lines[i]
    if line == JIRA_OLD:
        result.append(JIRA_NEW)
    elif line.startswith(CREDS_START):
        # Advance past all continuation lines until the closing )', line
        while i < len(lines) and not lines[i].rstrip('\n').endswith(")',"):
            i += 1
        result.append(CREDS_FIXED)
    else:
        result.append(line)
    i += 1

with open(path, 'w', encoding='utf-8') as f:
    f.writelines(result)
print('[entrypoint] SwaggerSpy regex patch applied')
EOF
fi

# update whatportis
if [ "$RUN_TOOL_UPDATES" = "1" ]; then
  yes | whatportis --update || TOOL_UPDATE_RC=1
fi

# ---------------------------------------------------------------------------
# Assetnote *2shell scanners are baked into the image under /usr/src/github,
# but the shared github_repos volume overlays that path and keeps whatever
# was on the volume when it was first created. Python owns github_repos'
# first populate, so it ensures any missing scanners land on the volume here.
# ---------------------------------------------------------------------------
mkdir -p /usr/src/github
ensure_github_tool() {
  # usage: ensure_github_tool <dir-name> <git-url>
  local name="$1" url="$2"
  if [ ! -f "/usr/src/github/${name}/scanner.py" ]; then
    echo "Installing ${name} into github_repos volume..."
    rm -rf "/usr/src/github/${name}"
    if git clone --depth 1 "$url" "/usr/src/github/${name}"; then
      if [ -f "/usr/src/github/${name}/requirements.txt" ]; then
        pip3 install -q -r "/usr/src/github/${name}/requirements.txt" || \
          echo "WARNING: pip install for ${name} failed; will retry next start"
      fi
      rm -rf "/usr/src/github/${name}/.git"
    else
      echo "WARNING: could not clone ${name}; will retry next start"
      rm -rf "/usr/src/github/${name}"
    fi
  fi
}
ensure_github_tool cpanel2shell-scanner https://github.com/assetnote/cpanel2shell-scanner
ensure_github_tool react2shell-scanner https://github.com/assetnote/react2shell-scanner
ensure_github_tool php2shell-scanner https://github.com/assetnote/php2shell-scanner
ensure_github_tool node2shell-scanner https://github.com/assetnote/node2shell-scanner

cd /usr/src/app

# store scan_results
mkdir -p /usr/src/scan_results

# Install spiderfoot packages
if [ -d '/usr/src/github/spiderfoot' ] && [ "$RUN_TOOL_UPDATES" = "1" ]; then
  echo "Installing Spiderfoot dependencies..."
  pip3 install -r /usr/src/github/spiderfoot/requirements.txt || TOOL_UPDATE_RC=1
  # Python 3.12 removed the 'imp' module. SpiderFoot's sfp_whois uses python-whois
  # which depends on the 'future' package — old versions of future still import imp.
  # Upgrade future and python-whois to Python 3.12-compatible releases.
  pip3 install 'future>=1.0.0' 'python-whois>=0.9.4' --upgrade || TOOL_UPDATE_RC=1
fi

if [ "$RUN_TOOL_UPDATES" = "1" ]; then
  if [ "$TOOL_UPDATE_RC" = "0" ]; then
    touch "$TOOL_UPDATE_STAMP"
    echo "[entrypoint] Tool updates completed; sentinel refreshed."
  else
    echo "[entrypoint] Some tool updates failed; sentinel left stale so the next start retries."
  fi
fi

echo "[entrypoint] Starting Temporal Python Orchestrator..."
exec python3 /usr/src/app/manage.py run_temporal_orchestrator "$@"
