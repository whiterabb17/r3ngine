#!/bin/bash
# Sync GF patterns from bind-mount or staged image into volume
echo "Syncing GF patterns..."
mkdir -p /root/.gf
if [ -d "/usr/src/app/gf-patterns" ]; then
  cp -f /usr/src/app/gf-patterns/*.json /root/.gf/
elif [ -d "/usr/src/gf-patterns" ]; then
  cp -f /usr/src/gf-patterns/*.json /root/.gf/
else
  echo "Warning: no GF patterns directory found!"
fi
echo "GF patterns synced: $(ls /root/.gf/*.json | wc -l) patterns installed"

# Entrypoint for the Temporal Python Orchestrator container.
# Handles one-time setup (wordlists, templates, tools) then starts the Temporal worker.


# ---------------------------------------------------------------------------
# Start deferred tool installer in the background so normal setup tasks
# (wordlists, nuclei templates, etc.) run in parallel. We wait for it to
# finish just before the Temporal worker starts.
# *Disabled temporarily*
# ---------------------------------------------------------------------------
# echo "[entrypoint] Starting deferred tool installer in background..."
# /usr/src/internal_tools.sh &
# INTERNAL_TOOLS_PID=$!

# ---------------------------------------------------------------------------
# Tool updates (pip upgrades, whatportis, vulnx, template repo pulls) are
# network-bound and take minutes, so running them on every start made a PyPI or
# GitHub outage enough to block the worker from coming up at all. Run them at
# most once a week, tracked by a sentinel on the persistent tool_config volume.
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

# Ensure OpenSSL compatibility
if [ "$RUN_TOOL_UPDATES" = "1" ]; then
  pip3 install --upgrade --no-cache-dir pyOpenSSL==24.0.0 tenacity==8.2.2 || TOOL_UPDATE_RC=1
fi



python3 manage.py loaddata \
    fixtures/default_keywords.yaml \
    fixtures/external_tools.yaml



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

# Shared wordlist volume seeding. Download to a temp path and only publish on
# success so a failed wget cannot leave an empty file that blocks later retries.
mkdir -p /usr/src/wordlist /usr/src/wordlist/auth

_fetch_wordlist() {
  # usage: _fetch_wordlist <dest> <url> [url...]
  local dest="$1"; shift
  local tmp url base
  if [ -s "$dest" ]; then
    return 0
  fi
  base=$(basename "$dest")
  echo "Downloading ${base}..."
  tmp="${dest}.tmp.$$"
  rm -f "$tmp" "$dest"
  for url in "$@"; do
    if wget -q --timeout=60 --tries=2 "$url" -O "$tmp" && [ -s "$tmp" ]; then
      mv -f "$tmp" "$dest"
      return 0
    fi
    rm -f "$tmp"
  done
  echo "WARNING: could not fetch ${base}; will retry next start"
  return 1
}

_fetch_wordlist /usr/src/wordlist/dicc.txt \
  https://raw.githubusercontent.com/maurosoria/dirsearch/master/db/dicc.txt

_fetch_wordlist /usr/src/wordlist/raft-large-directories.txt \
  https://raw.githubusercontent.com/danielmiessler/SecLists/master/Discovery/Web-Content/raft-large-directories.txt

_fetch_wordlist /usr/src/wordlist/deepmagic.com-prefixes-top50000.txt \
  https://raw.githubusercontent.com/danielmiessler/SecLists/master/Discovery/DNS/deepmagic.com-prefixes-top50000.txt

# Assetnote CDN is flaky; fall back to SecLists API wordlists.
_fetch_wordlist /usr/src/wordlist/api-endpoints.txt \
  https://wordlists-cdn.assetnote.io/data/automated/httparchive_apiroutes_2023_01_28.txt \
  https://raw.githubusercontent.com/danielmiessler/SecLists/master/Discovery/Web-Content/api/api-seen-in-wild.txt \
  https://raw.githubusercontent.com/danielmiessler/SecLists/master/Discovery/Web-Content/common-api-endpoints-mazen160.txt

# Curated auth + SMTP lists ship in the web tree (bind-mounted at /usr/src/app).
if [ -d /usr/src/app/wordlist/auth ] && [ -n "$(ls -A /usr/src/app/wordlist/auth 2>/dev/null)" ]; then
  echo "Copying Auth Wordlists"
  cp -r /usr/src/app/wordlist/auth/. /usr/src/wordlist/auth/
else
  echo "WARNING: /usr/src/app/wordlist/auth missing; auth fuzz will lack curated lists"
fi
if [ -f /usr/src/app/wordlist/smtp-usernames.txt ]; then
  cp /usr/src/app/wordlist/smtp-usernames.txt /usr/src/wordlist/smtp-usernames.txt
else
  echo "WARNING: /usr/src/app/wordlist/smtp-usernames.txt missing"
fi

# vulscan (nmap script)
if [ ! -d "/usr/src/github/scipag_vulscan" ]; then
  echo "Cloning Nmap Vulscan script"
  git clone https://github.com/scipag/vulscan /usr/src/github/scipag_vulscan
  ln -s /usr/src/github/scipag_vulscan /usr/share/nmap/scripts/vulscan
fi

# Required github-cloned tools live on the shared github_repos volume. Seed any
# missing clones here (internal_tools.sh is not used at startup). Sentinel is
# the pipeline entry script (scanner.py / linkfinder.py / …), not a PATH binary.
mkdir -p /usr/src/github
ensure_github_tool() {
  # usage: ensure_github_tool <dir-name> <git-url> <sentinel-relative-path> [post-install]
  # post-install: requirements | package | setup | none (default requirements)
  local name="$1" url="$2" sentinel="$3" mode="${4:-requirements}"
  local dest="/usr/src/github/${name}"
  if [ -f "${dest}/${sentinel}" ]; then
    return 0
  fi
  echo "Installing ${name} into github_repos volume..."
  rm -rf "${dest}"
  if ! git clone --depth 1 "$url" "${dest}"; then
    echo "WARNING: could not clone ${name}; will retry next start"
    rm -rf "${dest}"
    return 1
  fi
  case "$mode" in
    requirements)
      if [ -f "${dest}/requirements.txt" ]; then
        pip3 install -q -r "${dest}/requirements.txt" || \
          echo "WARNING: pip install for ${name} failed; will retry next start"
      fi
      ;;
    package)
      if [ -f "${dest}/acunetix/core.py" ]; then
        sed -i 's/Sent from Acunetix-Python/r3-external/g' "${dest}/acunetix/core.py" || true
      fi
      pip3 install -q --no-cache-dir "${dest}" || \
        echo "WARNING: pip package install for ${name} failed; will retry next start"
      ;;
    setup)
      if [ -f "${dest}/requirements.txt" ]; then
        pip3 install -q -r "${dest}/requirements.txt" || true
      fi
      if [ -f "${dest}/setup.py" ]; then
        (cd "${dest}" && python3 setup.py install -q) || \
          echo "WARNING: setup.py install for ${name} failed; will retry next start"
      fi
      pip3 install -q jsbeautifier || true
      ;;
  esac
  rm -rf "${dest}/.git"
}

# Assetnote *2shell scanners
ensure_github_tool cpanel2shell-scanner https://github.com/assetnote/cpanel2shell-scanner scanner.py
ensure_github_tool react2shell-scanner https://github.com/assetnote/react2shell-scanner scanner.py
ensure_github_tool php2shell-scanner https://github.com/assetnote/php2shell-scanner scanner.py
ensure_github_tool node2shell-scanner https://github.com/assetnote/node2shell-scanner scanner.py

# Subdomain / API discovery pipeline scripts
ensure_github_tool LinkFinder https://github.com/GerbenJavado/LinkFinder.git linkfinder.py setup
ensure_github_tool OneForAll https://github.com/shmilylty/OneForAll oneforall.py
ensure_github_tool Sublist3r https://github.com/aboul3la/Sublist3r sublist3r.py
ensure_github_tool ctfr https://github.com/UnaPibaGeek/ctfr ctfr.py
ensure_github_tool jwt_tool https://github.com/ticarpi/jwt_tool jwt_tool.py
ensure_github_tool graphql-cop https://github.com/dolevf/graphql-cop.git graphql-cop.py

# Acunetix Python API client (optional engine toggle; inventory expects pip package)
ensure_github_tool acunetix-python https://github.com/WazeHell/acunetix-python acunetix/__init__.py package

if [ ! -f '/usr/local/bin/kr' ]; then
  echo "Installing kiterunner"
  cd /usr/src/github
  ARCH=$(dpkg --print-architecture) && \
  wget https://github.com/assetnote/kiterunner/releases/download/v1.0.2/kiterunner_1.0.2_linux_${ARCH}.tar.gz && \
  tar -xvf kiterunner_1.0.2_linux_${ARCH}.tar.gz && \
  mv kr /usr/local/bin/ && \
  rm -rf kiterunner_1.0.2_linux_${ARCH}.tar.gz
  cd /usr/src/app
fi

# Each wordlist is fetched on its own and only moved into place once fully
# extracted, so a failed or partial download is retried on the next start.
mkdir -p /usr/src/wordlist/kr
for kite in routes-small routes-large; do
  if [ ! -s "/usr/src/wordlist/kr/${kite}.kite" ]; then
    kr_tmp=$(mktemp -d)
    if wget -q "https://wordlists-cdn.assetnote.io/data/kiterunner/${kite}.kite.tar.gz" -O "${kr_tmp}/${kite}.tar.gz" \
      && tar -xzf "${kr_tmp}/${kite}.tar.gz" -C "${kr_tmp}" \
      && [ -s "${kr_tmp}/${kite}.kite" ]; then
      cp "${kr_tmp}/${kite}.kite" "/usr/src/wordlist/kr/${kite}.kr"
      mv "${kr_tmp}/${kite}.kite" "/usr/src/wordlist/kr/${kite}.kite"
    else
      echo "WARNING: could not fetch the kiterunner ${kite} wordlist; kiterunner skips it until the next start"
    fi
    rm -rf "${kr_tmp}"
  fi
done

if [ ! -s /usr/src/wordlist/cpanel_users.txt ]; then
  echo "Fetching cPanel2Shell wordlist"
  _fetch_wordlist /usr/src/wordlist/cpanel_users.txt \
    https://raw.githubusercontent.com/danielmiessler/SecLists/master/Usernames/top-usernames-shortlist.txt \
    || true
  if [ -s /usr/src/wordlist/cpanel_users.txt ]; then
    sort -u /usr/src/wordlist/cpanel_users.txt -o /usr/src/wordlist/cpanel_users.txt
  fi
fi

cd /usr/src/app

# install gf patterns
if [ ! -d "/root/Gf-Patterns" ]; then
  echo "Installing GF Patterns"
  mkdir -p ~/.gf
  cp -r $GOPATH/src/github.com/tomnomnom/gf/examples/*.json ~/.gf
  git clone https://github.com/1ndianl33t/Gf-Patterns ~/Gf-Patterns
  mv ~/Gf-Patterns/*.json ~/.gf
fi

# store scan_results
if [ ! -d "/usr/src/scan_results" ]; then
  mkdir /usr/src/scan_results
fi

# test tools, required for configuration
naabu -version && subfinder -version && amass -version
nuclei -version

# Community Nuclei Templates
# All cloned into /root/nuclei-templates/ — the shared nuclei_templates volume.
# nuclei runs with -t /root/nuclei-templates so subdirs are picked up automatically.

if [ ! -d "/root/nuclei-templates/geeknik" ]; then
  echo "Installing Geeknik Nuclei templates"
  git clone --depth 1 https://github.com/geeknik/the-nuclei-templates.git /root/nuclei-templates/geeknik
fi

if [ ! -f "/root/nuclei-templates/ssrf_nagli.yaml" ]; then
  echo "Downloading ssrf_nagli SSRF template"
  wget -q https://raw.githubusercontent.com/NagliNagli/BountyTricks/main/ssrf.yaml \
    -O /root/nuclei-templates/ssrf_nagli.yaml || true
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
# Covers XSS (22k), SQLi (12k), DoS (15k), RCE (3k), Path Traversal, SSRF, LFI, XXE, SSTI
if [ ! -d "/root/nuclei-templates/missing-cve" ]; then
  echo "Installing missing-cve nuclei templates (~64k additional CVEs)"
  git clone --depth 1 https://github.com/edoardottt/missing-cve-nuclei-templates.git \
    /root/nuclei-templates/missing-cve
fi

# emadshanab/Nuclei-Templates-Collection — aggregates 400+ community repos
# Includes Log4Shell, Spring RCE, F5, WAF detection, Kubernetes, SAP, Oracle, WebSphere
if [ ! -d "/root/nuclei-templates/community-collection" ]; then
  echo "Installing Nuclei Templates Collection (400+ community repos)"
  git clone --depth 1 https://github.com/emadshanab/Nuclei-Templates-Collection.git \
    /root/nuclei-templates/community-collection
fi

# 0xKayala/Custom-Nuclei-Templates — bug-bounty focused custom templates
if [ ! -d "/root/nuclei-templates/kayala-custom" ]; then
  echo "Installing 0xKayala custom nuclei templates"
  git clone --depth 1 https://github.com/0xKayala/Custom-Nuclei-Templates.git \
    /root/nuclei-templates/kayala-custom
fi

# topscoder/nuclei-wordfence-cve — 70k+ WordPress CVE templates (daily-updated)
# Pre-loaded so WordPress scans don't incur a git clone mid-scan.
if [ ! -d "/root/nuclei-templates/wordfence/.git" ]; then
  echo "Installing Wordfence nuclei templates"
  git clone --depth 1 https://github.com/topscoder/nuclei-wordfence-cve.git \
    /root/nuclei-templates/wordfence
elif [ "$RUN_TOOL_UPDATES" = "1" ]; then
  echo "Updating Wordfence nuclei templates"
  git -C /root/nuclei-templates/wordfence pull --ff-only --quiet || TOOL_UPDATE_RC=1
fi
# Install repo dependencies
if [ "$RUN_TOOL_UPDATES" = "1" ]; then
  pip3 install -q -r /root/nuclei-templates/wordfence/requirements.txt || TOOL_UPDATE_RC=1
fi
# Merge wordfence nuclei-templates/ into the main templates directory so nuclei
# picks them up directly under /root/nuclei-templates without extra nesting.
cp -ru /root/nuclei-templates/wordfence/nuclei-templates/. /root/nuclei-templates/

# httpx alias
echo 'alias httpx="/usr/local/bin/httpx"' >> ~/.bashrc

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
  vulnx update || TOOL_UPDATE_RC=1

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
echo "[entrypoint] Starting Temporal Python Orchestrator..."
exec python3 /usr/src/app/manage.py run_temporal_orchestrator "$@"
