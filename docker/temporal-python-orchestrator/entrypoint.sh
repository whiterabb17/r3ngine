#!/bin/bash
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

# Ensure OpenSSL compatibility
pip3 install --upgrade --no-cache-dir pyOpenSSL==24.0.0 tenacity==8.2.2



python3 manage.py loaddata \
    fixtures/default_keywords.yaml \
    fixtures/external_tools.yaml



# Temporary fix for whatportis bug
sed -i 's/purge()/truncate()/g' "$(python3 -c "import whatportis.cli; print(whatportis.cli.__file__)")"

# Temporary fix for Sublist3r get_csrftoken bug
if [ -f "/usr/src/github/Sublist3r/sublist3r.py" ]; then
  sed -i "s/token = csrf_regex.findall(resp)\[0\]/token = csrf_regex.findall(resp)[0] if csrf_regex.findall(resp) else ''/g" /usr/src/github/Sublist3r/sublist3r.py
fi

# Temporary fix for ctfr invalid escape sequences in Python 3.12
if [ -f "/usr/src/github/ctfr/ctfr.py" ]; then
  sed -i "s/b = '''/b = r'''/g" /usr/src/github/ctfr/ctfr.py
  sed -i "s/'.*www\\\\.'/r'.*www\\\\.'/g" /usr/src/github/ctfr/ctfr.py
fi


# update whatportis
yes | whatportis --update

# clone dirsearch default wordlist
if [ ! -d "/usr/src/wordlist" ]; then
  echo "Making Wordlist directory"
  mkdir /usr/src/wordlist
fi

if [ ! -f "/usr/src/wordlist/dicc.txt" ]; then
  echo "Downloading Default Directory Bruteforce Wordlist"
  wget https://raw.githubusercontent.com/maurosoria/dirsearch/master/db/dicc.txt -O /usr/src/wordlist/dicc.txt
fi

if [ ! -f "/usr/src/wordlist/raft-large-directories.txt" ]; then
  echo "Downloading raft-large-directories.txt Wordlist"
  wget https://raw.githubusercontent.com/danielmiessler/SecLists/master/Discovery/Web-Content/raft-large-directories.txt -O /usr/src/wordlist/raft-large-directories.txt
fi

if [ ! -f "/usr/src/wordlist/deepmagic.com-prefixes-top50000.txt" ]; then
  echo "Downloading Deepmagic top 50000 Wordlist"
  wget https://raw.githubusercontent.com/danielmiessler/SecLists/master/Discovery/DNS/deepmagic.com-prefixes-top50000.txt -O /usr/src/wordlist/deepmagic.com-prefixes-top50000.txt
fi

if [ ! -f "/usr/src/wordlist/api-endpoints.txt" ]; then
  echo "Downloading API endpoints wordlist"
  wget -q https://wordlists-cdn.assetnote.io/data/automated/httparchive_apiroutes_2023_01_28.txt -O /usr/src/wordlist/api-endpoints.txt || true
fi

# Setup Auth Brute-Force Wordlists
if [ ! -d "/usr/src/wordlist/auth" ]; then
  mkdir -p /usr/src/wordlist/auth
fi
echo "Copying Auth Wordlists"
cp -r /usr/src/app/wordlist/auth/* /usr/src/wordlist/auth/

# SMTP username enumeration wordlist
cp /usr/src/app/wordlist/smtp-usernames.txt /usr/src/wordlist/smtp-usernames.txt

# vulscan (nmap script)
if [ ! -d "/usr/src/github/scipag_vulscan" ]; then
  echo "Cloning Nmap Vulscan script"
  git clone https://github.com/scipag/vulscan /usr/src/github/scipag_vulscan
  ln -s /usr/src/github/scipag_vulscan /usr/share/nmap/scripts/vulscan
fi

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

if [ ! -d '/usr/src/wordlist/kr' ]; then
  mkdir -p /usr/src/wordlist/kr
  cd /usr/src/wordlist/kr
  wget https://wordlists-cdn.assetnote.io/data/kiterunner/routes-large.kite.tar.gz -O routes-large.kite.tar.gz
  tar -xvf routes-large.kite.tar.gz
  rm -rf routes-large.kite.tar.gz
  wget https://wordlists-cdn.assetnote.io/data/kiterunner/routes-small.kite.tar.gz -O routes-small.kite.tar.gz
  tar -xvf routes-small.kite.tar.gz
  rm -rf routes-small.kite.tar.gz
  cp routes-large.kite routes-large.kr
  cp routes-small.kite routes-small.kr
  cd /usr/src/app
fi

if [ ! -f '/usr/src/wordlist/cpanel_users.txt' ]; then
  echo "Fetching cPanel2Shell wordlist"
  mkdir -p /usr/src/wordlist
  wget -qO- https://raw.githubusercontent.com/danielmiessler/SecLists/master/Usernames/top-usernames-shortlist.txt >> /usr/src/wordlist/cpanel_users.txt
  sort -u /usr/src/wordlist/cpanel_users.txt -o /usr/src/wordlist/cpanel_users.txt
fi

# Clone Exploit-DB for Searchsploit if not already present
if [ ! -d "/usr/src/exploitdb/.git" ]; then
  echo "Cloning Exploit-DB for searchsploit..."
  rm -rf /usr/src/exploitdb/* /usr/src/exploitdb/.* 2>/dev/null || true
  git clone --depth 1 https://gitlab.com/exploit-database/exploitdb /usr/src/exploitdb
fi

# Ensure searchsploit RC file is copied to root home directory
if [ -f "/usr/src/exploitdb/.searchsploit_rc" ]; then
  cp /usr/src/exploitdb/.searchsploit_rc /root/.searchsploit_rc
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
else
  echo "Updating Wordfence nuclei templates"
  git -C /root/nuclei-templates/wordfence pull --quiet || true
fi

# httpx alias
echo 'alias httpx="/usr/local/bin/httpx"' >> ~/.bashrc



vulnx update

# Configure vigolium to scan all severity levels for known issues
vigolium config set known_issue_scan.severities "critical,high,medium,low,info" || true

# wait $INTERNAL_TOOLS_PID
echo "[entrypoint] Starting Temporal Python Orchestrator..."
exec python3 /usr/src/app/manage.py run_temporal_orchestrator
