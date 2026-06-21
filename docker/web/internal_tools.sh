#!/bin/bash
# =============================================================================
# internal_tools.sh — deferred security tool installer
#
# Started in the background by temporal-python-orchestrator and
# temporal-go-executor entrypoints. Each entrypoint waits for this script
# before starting its worker.
#
# Locking strategy:
#   - Sections that write to the shared github_repos volume (/usr/src/github)
#     are serialised with flock so two containers cannot race on git clones.
#   - Per-container sections (binaries, pip3, pipx, gem, Playwright) run
#     concurrently in each container — they write to container-local paths.
#
# Idempotency per destination:
#   - /usr/src/github/<repo>  → [ -d ] guard  (shared volume, persists)
#   - /usr/local/bin/<tool>   → command -v guard (per-container)
#   - pipx venvs              → pipx list guard (per-container)
#   - pip3 packages           → python3 -c "import" guard (per-container)
#   - WPScan gem              → command -v guard (per-container)
#   - Playwright              → [ -d ~/.cache/ms-playwright ] (per-container)
# =============================================================================

set -euo pipefail
export DEBIAN_FRONTEND=noninteractive
export PATH="/root/.local/bin:${PATH}"

# ── Logging helpers ────────────────────────────────────────────────────────────
ts()          { date '+%H:%M:%S'; }
log()         { echo "[$(ts)] [internal_tools] $*"; }
log_section() { echo ""; echo "[$(ts)] [internal_tools] ───── $* ─────"; }
log_skip()    { echo "[$(ts)] [internal_tools]   ↳ already installed, skipping."; }
log_done()    { echo "[$(ts)] [internal_tools]   ↳ done."; }

log_section "START"
log "Deferred tool installer running (container: ${HOSTNAME:-unknown})."
log "Per-container sections run freely; shared-volume section is serialised via flock."
log "Note: Playwright Chromium is baked into the image (required at Django startup)."

# =============================================================================
# PER-CONTAINER SECTIONS — no locking needed
# =============================================================================

# ─────────────────────────────────────────────────────────────────────────────
# SECTION 1 — WPScan (Ruby gem)
# ─────────────────────────────────────────────────────────────────────────────
log_section "WPScan"
if ! command -v wpscan &>/dev/null; then
    log "Installing WPScan gem..."
    gem install wpscan --no-document 2>&1 | tail -5 | sed 's/^/  /'
    rm -rf /var/lib/gems/*/cache/*.gem
    log_done
else
    log_skip
fi

# ─────────────────────────────────────────────────────────────────────────────
# SECTION 2 — Binary tools (all install to /usr/local/bin — per-container)
# ─────────────────────────────────────────────────────────────────────────────
log_section "Binary tools"

# Trufflehog — latest release
if ! command -v trufflehog &>/dev/null; then
    log "Installing Trufflehog..."
    ARCH=$(dpkg --print-architecture)
    TH_VER=$(curl -s https://api.github.com/repos/trufflesecurity/trufflehog/releases/latest | jq -r .tag_name | sed 's/v//')
    wget -q "https://github.com/trufflesecurity/trufflehog/releases/download/v${TH_VER}/trufflehog_${TH_VER}_linux_${ARCH}.tar.gz" -O /tmp/th.tar.gz
    tar -xf /tmp/th.tar.gz -C /usr/local/bin trufflehog
    rm -f /tmp/th.tar.gz
    log_done
else
    log_skip
fi

# grype — pinned v0.114.0, SHA256 verified
if ! command -v grype &>/dev/null; then
    log "Installing grype v0.114.0..."
    curl -sSfL \
      "https://github.com/anchore/grype/releases/download/v0.114.0/grype_0.114.0_linux_amd64.tar.gz" \
      -o /tmp/grype.tar.gz
    echo "edda0968d8827daab01d32b3cd7de192ae0915005e7bbfcfef9e68e79bc43343  /tmp/grype.tar.gz" | sha256sum -c
    tar -xzf /tmp/grype.tar.gz -C /usr/local/bin grype
    rm -f /tmp/grype.tar.gz
    log_done
else
    log_skip
fi

# trivy — pinned v0.69.3, SHA256 verified (v0.69.4 was supply-chain compromised)
if ! command -v trivy &>/dev/null; then
    log "Installing trivy v0.69.3..."
    curl -sSfL \
      "https://github.com/aquasecurity/trivy/releases/download/v0.69.3/trivy_0.69.3_Linux-64bit.tar.gz" \
      -o /tmp/trivy.tar.gz
    echo "1816b632dfe529869c740c0913e36bd1629cb7688bd5634f4a858c1d57c88b75  /tmp/trivy.tar.gz" | sha256sum -c
    tar -xzf /tmp/trivy.tar.gz -C /usr/local/bin trivy
    rm -f /tmp/trivy.tar.gz
    log_done
else
    log_skip
fi

# k6 — pinned v0.50.0
if ! command -v k6 &>/dev/null; then
    log "Installing k6 v0.50.0..."
    ARCH=$(dpkg --print-architecture)
    if [ "${ARCH}" = "arm64" ]; then K6_ARCH="arm64"; else K6_ARCH="amd64"; fi
    wget -q "https://github.com/grafana/k6/releases/download/v0.50.0/k6-v0.50.0-linux-${K6_ARCH}.tar.gz" -O /tmp/k6.tar.gz
    tar -xf /tmp/k6.tar.gz -C /tmp
    mv "/tmp/k6-v0.50.0-linux-${K6_ARCH}/k6" /usr/local/bin/
    rm -rf /tmp/k6.tar.gz "/tmp/k6-v0.50.0-linux-${K6_ARCH}"
    log_done
else
    log_skip
fi

# brutus — HTTP brute force tool
if ! command -v brutus &>/dev/null; then
    log "Installing brutus..."
    curl -sL https://github.com/praetorian-inc/brutus/releases/latest/download/brutus-linux-amd64.tar.gz | \
        tar xz -C /usr/local/bin brutus
    log_done
else
    log_skip
fi

# Aquatone — visual recon / screenshot tool
if ! command -v aquatone &>/dev/null; then
    log "Installing Aquatone v1.7.0..."
    ARCH=$(dpkg --print-architecture)
    wget -q "https://github.com/michenriksen/aquatone/releases/download/v1.7.0/aquatone_linux_${ARCH}_1.7.0.zip" -O /tmp/aquatone.zip
    unzip -o /tmp/aquatone.zip aquatone -d /usr/local/bin
    rm -f /tmp/aquatone.zip
    log_done
else
    log_skip
fi

# Feroxbuster — recursive web content discovery
if ! command -v feroxbuster &>/dev/null; then
    log "Installing Feroxbuster (latest)..."
    FEROX_VERSION=$(curl -s https://api.github.com/repos/epi052/feroxbuster/releases/latest \
      | python3 -c "import sys,json; print(json.load(sys.stdin)['tag_name'].lstrip('v'))")
    wget -q "https://github.com/epi052/feroxbuster/releases/download/v${FEROX_VERSION}/x86-linux-feroxbuster.zip" \
      -O /tmp/feroxbuster.zip
    unzip /tmp/feroxbuster.zip feroxbuster -d /usr/local/bin
    chmod +x /usr/local/bin/feroxbuster
    rm -f /tmp/feroxbuster.zip
    log_done
else
    log_skip
fi

# ─────────────────────────────────────────────────────────────────────────────
# SECTION 3 — pip3 non-core tools (per-container site-packages)
# ─────────────────────────────────────────────────────────────────────────────
log_section "pip3 non-core tools"

pip3_install_if_missing() {
    local module="$1" pkg="${2:-$1}"
    if python3 -c "import $module" 2>/dev/null; then
        log "  $pkg already importable."
    else
        log "  Installing $pkg..."
        pip3 install -q "$pkg"
        log_done
    fi
}

pip3_install_if_missing fierce
pip3_install_if_missing dirsearch
pip3_install_if_missing arjun
pip3_install_if_missing netlas
pip3_install_if_missing holehe
command -v inql &>/dev/null \
    && log "  inql already installed." \
    || { log "  Installing inql..."; pip3 install -q inql; log_done; }

# ─────────────────────────────────────────────────────────────────────────────
# SECTION 4 — pipx tools (per-container venvs)
# ─────────────────────────────────────────────────────────────────────────────
log_section "pipx tools"

pipx_install() {
    local pkg="$1" name="${2:-$1}"
    if pipx list 2>/dev/null | grep -q "package ${name}"; then
        log "  $name already installed."
    else
        log "  Installing pipx: $name..."
        pipx install "$pkg" 2>&1 | tail -3 | sed 's/^/    /'
        log_done
    fi
}

pipx_install "git+https://github.com/blacklanternsecurity/baddns" "baddns"
pipx_install maigret
pipx_install semgrep
pipx_install dnsrecon
pipx_install "ssh-audit" "ssh-audit"
pipx_install "git+https://github.com/EnableSecurity/wafw00f.git" "wafw00f"
pipx_install whoisdomain
pipx_install "bypass-url-parser" "bypass-url-parser"
pipx_install bbot
pipx_install sploitscan

log "  Injecting setuptools into pipx venvs that need pkg_resources..."
for pkg in maigret semgrep dnsrecon; do
    pipx inject "$pkg" setuptools 2>/dev/null || true
done

# =============================================================================
# SHARED VOLUME SECTION — serialised with flock
#
# Only one container at a time may write to /usr/src/github.
# The second container waits at the flock, then acquires it and finds all
# [ -d ] guards already true, so it exits this section immediately.
# =============================================================================
log_section "Shared volume tools → /usr/src/github (flock serialised)"

mkdir -p /usr/src/github
SHARED_LOCK="/usr/src/github/.install.lock"

log "Acquiring shared-volume lock (${SHARED_LOCK})..."
(
    flock -x 9
    log "Lock acquired by ${HOSTNAME:-unknown}. Installing shared tools..."

    # Helper: shallow clone, run callback if new, strip .git
    clone_repo() {
        local name="$1" url="$2"
        local dest="/usr/src/github/$name"
        if [ ! -d "$dest" ]; then
            log "  Cloning $name..."
            git clone --depth 1 "$url" "$dest" 2>&1 | tail -3 | sed 's/^/    /'
            return 0   # new — caller should install deps
        else
            log "  $name already present."
            return 1   # skip
        fi
    }

    # GooFuzz — shell script, lives in shared volume
    if [ ! -d /usr/src/github/goofuzz ]; then
        log "  Installing GooFuzz..."
        wget -q -O /tmp/GooFuzz.zip "https://github.com/m3n0sd0n4ld/GooFuzz/releases/download/1.2.6/GooFuzz.v.1.2.6.zip"
        unzip -q /tmp/GooFuzz.zip -d /tmp/goofuzz_extract
        mv /tmp/goofuzz_extract/GooFuzz.v.1.2.6 /usr/src/github/goofuzz
        chmod +x /usr/src/github/goofuzz/GooFuzz
        rm -rf /tmp/GooFuzz.zip /tmp/goofuzz_extract
        log_done
    else
        log "  goofuzz already present."
    fi
    # Symlink is per-container — safe outside lock, but harmless here
    ln -sf /usr/src/github/goofuzz/GooFuzz /usr/local/bin/GooFuzz 2>/dev/null || true

    # SpiderFoot
    if clone_repo spiderfoot https://github.com/smicallef/spiderfoot; then
        pip3 install -q -r /usr/src/github/spiderfoot/requirements.txt
        rm -rf /usr/src/github/spiderfoot/.git
        log_done
    fi

    # cPanel2Shell scanner
    if clone_repo cpanel2shell-scanner https://github.com/assetnote/cpanel2shell-scanner; then
        pip3 install -q -r /usr/src/github/cpanel2shell-scanner/requirements.txt
        rm -rf /usr/src/github/cpanel2shell-scanner/.git
        log_done
    fi

    # React2Shell scanner
    if clone_repo react2shell-scanner https://github.com/assetnote/react2shell-scanner; then
        pip3 install -q -r /usr/src/github/react2shell-scanner/requirements.txt
        rm -rf /usr/src/github/react2shell-scanner/.git
        log_done
    fi
    pip3 install -q -r /usr/src/github/react2shell-scanner/requirements.txt

    # ctfr
    if clone_repo ctfr https://github.com/UnaPibaGeek/ctfr; then
        pip3 install -q -r /usr/src/github/ctfr/requirements.txt
        rm -rf /usr/src/github/ctfr/.git
        log_done
    fi
    pip3 install -q -r /usr/src/github/ctfr/requirements.txt

    # username-anarchy (no pip deps)
    if clone_repo username-anarchy https://github.com/urbanadventurer/username-anarchy; then
        log_done
    fi
    ln -sf /usr/src/github/username-anarchy/username-anarchy /usr/local/bin/username-anarchy 2>/dev/null || true

    # acunetix-python
    if clone_repo acunetix-python https://github.com/WazeHell/acunetix-python; then
        sed -i 's/Sent from Acunetix-Python/r3-external/g' /usr/src/github/acunetix-python/acunetix/core.py
        pip3 install -q --no-cache-dir /usr/src/github/acunetix-python
        rm -rf /usr/src/github/acunetix-python/.git
        log_done
    else
        pip3 install -q --no-cache-dir /usr/src/github/acunetix-python
    fi

    # OneForAll
    if clone_repo OneForAll https://github.com/shmilylty/OneForAll; then
        pip3 install -q -r /usr/src/github/OneForAll/requirements.txt
        rm -rf /usr/src/github/OneForAll/.git
        log_done
    else
        pip3 install -q -r /usr/src/github/OneForAll/requirements.txt
    fi

    # Sublist3r
    if clone_repo Sublist3r https://github.com/aboul3la/Sublist3r; then
        pip3 install -q -r /usr/src/github/Sublist3r/requirements.txt
        rm -rf /usr/src/github/Sublist3r/.git
        log_done
    else
        pip3 install -q -r /usr/src/github/Sublist3r/requirements.txt
    fi
    # theHarvester (uses uv sync)
    if [ ! -d /usr/src/github/theHarvester ]; then
        log "  Cloning theHarvester..."
        git clone --depth 1 https://github.com/laramies/theHarvester /usr/src/github/theHarvester 2>&1 | tail -3 | sed 's/^/    /'
        log "  Running uv sync for theHarvester..."
        cd /usr/src/github/theHarvester && uv sync 2>&1 | tail -5 | sed 's/^/    /' && cd -
        rm -rf /usr/src/github/theHarvester/.git
        log_done
    else
        log "  theHarvester already present."
        cd /usr/src/github/theHarvester && uv sync 2>&1 | tail -5 | sed 's/^/    /' && cd -
    fi

    # ParamSpider
    if clone_repo ParamSpider https://github.com/devanshbatham/ParamSpider; then
        cd /usr/src/github/ParamSpider && pip3 install -q . && python3 setup.py install && cd -
        rm -rf /usr/src/github/ParamSpider/.git
        log_done
    else
        cd /usr/src/github/ParamSpider && pip3 install -q . && python3 setup.py install && cd -
    fi

    # LinkFinder
    if clone_repo LinkFinder https://github.com/GerbenJavado/LinkFinder.git; then
        pip3 install -q -r /usr/src/github/LinkFinder/requirements.txt
        cd /usr/src/github/LinkFinder && python3 setup.py install -q && pip3 install jsbeautifier && cd -
        rm -rf /usr/src/github/LinkFinder/.git
        log_done
    else
        pip3 install -q -r /usr/src/github/LinkFinder/requirements.txt
        cd /usr/src/github/LinkFinder && python3 setup.py install -q && pip3 install jsbeautifier && cd -
    fi

    # CMSeeK
    if clone_repo CMSeeK https://github.com/Tuhinshubhra/CMSeeK; then
        pip3 install -q -r /usr/src/github/CMSeeK/requirements.txt
        rm -rf /usr/src/github/CMSeeK/.git
        log_done
    else
        pip3 install -q -r /usr/src/github/CMSeeK/requirements.txt
    fi

    # testssl.sh (shell script, no pip)
    if clone_repo testssl.sh https://github.com/drwetter/testssl.sh; then
        chmod +x /usr/src/github/testssl.sh/testssl.sh
        log_done
    fi
    ln -sf /usr/src/github/testssl.sh/testssl.sh /usr/local/bin/testssl.sh 2>/dev/null || true

    # jwt_tool
    if clone_repo jwt_tool https://github.com/ticarpi/jwt_tool; then
        pip3 install -q -r /usr/src/github/jwt_tool/requirements.txt
        rm -rf /usr/src/github/jwt_tool/.git
        log_done
    else
        pip3 install -q -r /usr/src/github/jwt_tool/requirements.txt
    fi

    # graphql-cop
    if clone_repo graphql-cop https://github.com/dolevf/graphql-cop.git; then
        pip3 install -q -r /usr/src/github/graphql-cop/requirements.txt
        rm -rf /usr/src/github/graphql-cop/.git
        log_done
    else
        pip3 install -q -r /usr/src/github/graphql-cop/requirements.txt
    fi

    # enum4linux-ng
    if clone_repo enum4linux-ng https://github.com/cddmp/enum4linux-ng; then
        pip3 install -q -r /usr/src/github/enum4linux-ng/requirements.txt
        rm -rf /usr/src/github/enum4linux-ng/.git
        log_done
    else
        pip3 install -q -r /usr/src/github/enum4linux-ng/requirements.txt
    fi
    ln -sf /usr/src/github/enum4linux-ng/enum4linux-ng.py /usr/local/bin/enum4linux-ng 2>/dev/null || true

    # rdp-sec-check (Perl)
    if clone_repo rdp-sec-check https://github.com/CiscoCXSecurity/rdp-sec-check; then
        cpan install Encoding::BER 2>&1 | tail -3 | sed 's/^/    /'
        log_done
    fi
    ln -sf /usr/src/github/rdp-sec-check/rdp-sec-check.pl /usr/local/bin/rdp-sec-check 2>/dev/null || true

    log "Releasing shared-volume lock."
) 9>"$SHARED_LOCK"

# =============================================================================
# DONE
# =============================================================================
log_section "COMPLETE"
log "All deferred tools installed and ready (container: ${HOSTNAME:-unknown})."
echo ""
