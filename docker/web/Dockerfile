# ===========================================================================
# Stage 1: Frontend Builder
# Compiles the React/Vite frontend. Only the /dist output is used downstream.
# ===========================================================================
FROM node:22-alpine AS frontend-builder
WORKDIR /app/frontend
COPY frontend/package*.json ./
RUN --mount=type=cache,target=/root/.npm \
    npm install
COPY frontend/ ./
RUN npm run build


# ===========================================================================
# Stage 2: Go Tools Builder
#
# Compiles all third-party Go security tools in a single RUN statement so the
# module download cache never bloats a committed image layer.
# libpcap-dev is required by naabu (raw packet capture via CGo).
#
# Only /go/bin/* binaries are exported to the final image — the entire Go SDK,
# module cache, and build cache stay inside this ephemeral stage.
# ===========================================================================
FROM golang:1.25-bookworm AS go-tools-builder

RUN apt-get update && \
    apt-get install -y --no-install-recommends libpcap-dev make && \
    rm -rf /var/lib/apt/lists/*

ENV GO111MODULE=on

# All tools in one RUN: single cache-invalidation point, no intermediate layers
# retaining module/build cache. -ldflags="-s -w" strips debug + DWARF symbols. 
RUN --mount=type=cache,target=/go/pkg/mod \
    --mount=type=cache,target=/root/.cache/go-build \
    go install -ldflags="-s -w" -v github.com/ibnaleem/gosearch@5d2e872aac3f && \
    go install -ldflags="-s -w" -v github.com/jaeles-project/gospider@latest && \
    go install -ldflags="-s -w" -v github.com/tomnomnom/gf@dcd4c361f9f5ba302294ed38b8ce278e8ba69006 && \
    go install -ldflags="-s -w" -v github.com/tomnomnom/unfurl@latest && \
    go install -ldflags="-s -w" -v github.com/tomnomnom/waybackurls@latest && \
    go install -ldflags="-s -w" -v github.com/projectdiscovery/httpx/cmd/httpx@latest && \
    go install -ldflags="-s -w" -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest && \
    go install -ldflags="-s -w" -v github.com/projectdiscovery/chaos-client/cmd/chaos@latest && \
    go install -ldflags="-s -w" -v github.com/projectdiscovery/nuclei/v3/cmd/nuclei@v3.9.0 && \
    go install -ldflags="-s -w" -v github.com/projectdiscovery/naabu/v2/cmd/naabu@latest && \
    go install -ldflags="-s -w" -v github.com/hakluke/hakrawler@latest && \
    go install -ldflags="-s -w" -v github.com/lc/gau/v2/cmd/gau@latest && \
    go install -ldflags="-s -w" -v github.com/owasp-amass/amass/v4/...@v4.2.0 && \
    go install -ldflags="-s -w" -v github.com/ffuf/ffuf/v2@latest && \
    go install -ldflags="-s -w" -v github.com/projectdiscovery/tlsx/cmd/tlsx@latest && \
    go install -ldflags="-s -w" -v github.com/projectdiscovery/katana/cmd/katana@latest && \
    go install -ldflags="-s -w" -v github.com/dwisiswant0/crlfuzz/cmd/crlfuzz@latest && \
    go install -ldflags="-s -w" -v github.com/sa7mon/s3scanner@b6c26d67bc2abe346555dd7010e6065889d66039 && \
    go install -ldflags="-s -w" -v github.com/zricethezav/gitleaks/v8@latest && \
    go install -ldflags="-s -w" -v github.com/xalgord/reconx/cmd/reconx@latest && \
    go install -ldflags="-s -w" -v github.com/projectdiscovery/vulnx/v2/cmd/vulnx@latest && \
    go install -ldflags="-s -w" -v github.com/projectdiscovery/dnsx/cmd/dnsx@latest && \
    go install -ldflags="-s -w" -v github.com/Vulnpire/getasn@latest && \
    go install -ldflags="-s -w" -v github.com/jschauma/jswhois@latest && \
    go install -ldflags="-s -w" -v github.com/projectdiscovery/mapcidr/cmd/mapcidr@latest && \
    go install -ldflags="-s -w" -v github.com/projectdiscovery/urlfinder/cmd/urlfinder@latest && \
    go install -ldflags="-s -w" -v github.com/Chocapikk/wpprobe@latest && \
    go install -ldflags="-s -w" -v github.com/hueristiq/xurlfind3r/cmd/xurlfind3r@latest && \
    go install -ldflags="-s -w" -v github.com/edoardottt/cariddi/cmd/cariddi@latest && \
    go install -ldflags="-s -w" -v github.com/dimasma0305/wp-taint-scan/cmd/taint-scan@latest

# betterleaks has no published go install path — clone and build directly.
RUN --mount=type=cache,target=/go/pkg/mod \
    --mount=type=cache,target=/root/.cache/go-build \
    git clone --depth 1 https://github.com/betterleaks/betterleaks /tmp/betterleaks && \
    cd /tmp/betterleaks && make build && \
    cp betterleaks /go/bin/betterleaks && \
    rm -rf /tmp/betterleaks


# ===========================================================================
# Stage 3: r3ngine Executor Builder
#
# Compiles the Temporal Go activity worker binary (r3ngine-executor).
# The executor is a pure-Go project (no CGo) so no special libs needed.
# ===========================================================================
FROM golang:1.25-bookworm AS executor-builder

WORKDIR /build
# Copy executor source from the repo root context
COPY web/executor/go.mod web/executor/go.sum ./
RUN --mount=type=cache,target=/go/pkg/mod \
    go mod download
COPY web/executor/ ./
RUN --mount=type=cache,target=/go/pkg/mod \
    --mount=type=cache,target=/root/.cache/go-build \
    CGO_ENABLED=0 GO111MODULE=on go build -ldflags="-s -w" -o /usr/local/bin/r3ngine-executor .

# ===========================================================================
# Stage: Vigolium Builder
#
# Vigolium requires Go 1.26+ and bun (for embedded vigolium-audit and jsscan
# binaries). Clone, build embedded deps, then compile the binary.
# The ~341MB binary is copied directly to /usr/local/bin in the runtime image.
# ===========================================================================
FROM golang:1.26-bookworm AS vigolium-builder

RUN apt-get update && \
    apt-get install -y --no-install-recommends curl git make unzip && \
    rm -rf /var/lib/apt/lists/*

# Install bun (needed for vigolium-audit and jsscan embedded binary builds)
RUN curl -fsSL https://bun.sh/install | bash -s "bun-v1.1.34"
ENV PATH="/root/.bun/bin:${PATH}"
ENV GO111MODULE=on

# Clone vigolium at the pinned release tag
RUN git clone --depth 1 https://github.com/vigolium/vigolium /build/vigolium

WORKDIR /build/vigolium

# Build embedded binaries (vigolium-audit via bun, jsscan via bun)
RUN make ensure-audit && make ensure-jsscan

# Compile vigolium binary
RUN --mount=type=cache,target=/go/pkg/mod \
    --mount=type=cache,target=/root/.cache/go-build \
    go build -ldflags="-s -w" -o /usr/local/bin/vigolium ./cmd/vigolium && \
    rm -rf /build/vigolium


# ===========================================================================
# Stage: Dalfox Builder
#
# Dalfox v3 is a Rust rewrite with no pre-built binaries; must be compiled
# from source. Targets x86_64-unknown-linux-musl to produce a fully static
# binary with no libc dependency in the runtime image.
# ===========================================================================
FROM rust:bookworm AS dalfox-builder

RUN apt-get update && apt-get install -y --no-install-recommends \
    musl-tools \
    pkg-config \
    git \
    && rm -rf /var/lib/apt/lists/*

RUN rustup target add x86_64-unknown-linux-musl

RUN git clone --depth 1 https://github.com/hahwul/dalfox /tmp/dalfox

WORKDIR /tmp/dalfox

RUN --mount=type=cache,target=/usr/local/cargo/registry \
    --mount=type=cache,target=/usr/local/cargo/git \
    --mount=type=cache,target=/tmp/dalfox/target \
    cargo build --release && \
    cp target/release/dalfox /usr/local/bin/dalfox


# ===========================================================================
# Stage 4: Runtime Image
#
# Ubuntu 22.04 base. Contains ONLY what r3ngine needs to run:
#   - Python + pip + runtime shared libs
#   - Ruby (WPScan)
#   - Node.js (Retire.js)
#   - Pre-compiled Go tool binaries (copied from go-tools-builder)
#   - r3ngine-executor binary (copied from executor-builder)
#   - Dalfox binary (copied from dalfox-builder)
#   - Built frontend dist (copied from frontend-builder)
#   - Python-based tools (shallow-cloned, .git stripped)
#   - Playwright Chromium
#
# NOT present: Go SDK, Rust toolchain, build caches, full git histories,
#              nuclei-templates (volume), wordlists (volume).
# ===========================================================================
FROM ubuntu:22.04

# Prevent interactive APT prompts during build
ENV DEBIAN_FRONTEND="noninteractive" \
    DATABASE="postgres" \
    PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1

LABEL \
    name="reNgine" \
    author="Reboot Dev: MistrHyd3 (https://github.com/whiterabb17) \
    Original By: Yogesh Ojha <yogesh.ojha11@gmail.com>" \
    description="reNgine is an automated recon pipeline for web application penetration testing."

# ---------------------------------------------------------------------------
# Add the PostgreSQL 16 APT repository.
# Ubuntu 22.04 ships postgresql-client 14 by default; pg_dump requires the
# client version to be >= the server version (now 16), so we pin to 16.
# ---------------------------------------------------------------------------
RUN apt-get update -y && \
    apt-get install -y --no-install-recommends ca-certificates gnupg curl lsb-release && \
    rm -rf /var/lib/apt/lists/* && \
    curl -fsSL https://www.postgresql.org/media/keys/ACCC4CF8.asc \
        | gpg --dearmor -o /usr/share/keyrings/pgdg.gpg && \
    echo "deb [signed-by=/usr/share/keyrings/pgdg.gpg] https://apt.postgresql.org/pub/repos/apt $(lsb_release -cs)-pgdg main" \
        > /etc/apt/sources.list.d/pgdg.list && \
    curl -fsSL "https://keyserver.ubuntu.com/pks/lookup?op=get&search=0xF23C5A6CF475977595C89F51BA6932366A755776" \
        | gpg --dearmor -o /usr/share/keyrings/deadsnakes.gpg && \
    echo "deb [signed-by=/usr/share/keyrings/deadsnakes.gpg] https://ppa.launchpadcontent.net/deadsnakes/ppa/ubuntu jammy main" \
        > /etc/apt/sources.list.d/deadsnakes.list


# ---------------------------------------------------------------------------
# System packages — single combined RUN to keep the layer count low.
# build-essential is kept because pip installs some packages that compile
# C extensions (cryptography, pycairo, etc.) and gems (wpscan) need gcc.
# ---------------------------------------------------------------------------
RUN apt-get update -y && \
    apt-get install -y --no-install-recommends \
    # Python 3.12 runtime
    python3.12 \
    python3.12-dev \
    python3.12-venv \
    # Ruby (WPScan)
    ruby-full \
    ruby-dev \
    # Shared libraries required by Python C-extension packages
    libcurl4-openssl-dev \
    libxml2 \
    libxml2-dev \
    libxslt1-dev \
    zlib1g-dev \
    liblzma-dev \
    libpq-dev \
    libffi-dev \
    libjpeg-dev \
    libopenjp2-7-dev \
    libcairo2-dev \
    libcairo2 \
    libpangocairo-1.0-0 \
    libgdk-pixbuf2.0-0 \
    libpango-1.0-0 \
    libpangoft2-1.0-0 \
    pkg-config \
    shared-mime-info \
    # libpcap runtime lib — needed by naabu binary at runtime
    libpcap-dev \
    # Capability bits for naabu raw sockets
    libcap2-bin \
    libcap2 \
    # EGL/PCI — required by Playwright/Chromium GPU path
    libpci-dev \
    libpciaccess-dev \
    libegl-dev \
    libegl1 \
    # Network and scanning tools
    git \
    wget \
    curl \
    nmap \
    netcat \
    ike-scan \
    sslscan \
    proxychains4 \
    hping3 \
    wrk \
    postgresql-client-16 \
    # Network protocol enumeration tools
    onesixtyone \
    snmp \
    ldap-utils \
    dnsutils \
    # Utilities
    jq \
    unzip \
    geoip-bin \
    geoip-database \
    patch \
    bsdmainutils \
    # Build tools — required by pip (C extensions) and gem installs
    build-essential \
    cmake \
    ninja-build \
    gcc \
    fping \
    arp-scan \
    && rm -rf /var/lib/apt/lists/*

# ---------------------------------------------------------------------------
# Make Python 3.12 the system default and redirect pip3 to it.
# ensurepip installs pip into 3.12's site-packages; the symlinks ensure
# all pip3/pip invocations in subsequent RUN blocks use 3.12.
# ---------------------------------------------------------------------------
RUN python3.12 -m ensurepip --upgrade && \
    python3.12 -m pip install --upgrade pip && \
    update-alternatives --install /usr/bin/python3 python3 /usr/bin/python3.12 1 && \
    update-alternatives --install /usr/bin/python  python  /usr/bin/python3.12 1 && \
    ln -sf /usr/local/bin/pip3 /usr/bin/pip3 && \
    ln -sf /usr/local/bin/pip3 /usr/bin/pip

# ---------------------------------------------------------------------------
# Install uv (fast Python package manager — used by theHarvester)
# ---------------------------------------------------------------------------
RUN curl -LsSf https://astral.sh/uv/install.sh | sh
ENV PATH="/root/.local/bin:${PATH}"

# ---------------------------------------------------------------------------
# Node.js 20 + Retire.js (JS dependency vulnerability scanner)
# Node runtime is needed at runtime for `retire` — not just build time.
# ---------------------------------------------------------------------------
RUN curl -fsSL https://deb.nodesource.com/setup_20.x | bash - && \
    apt-get install -y --no-install-recommends nodejs && \
    npm install -g retire && \
    rm -rf /var/lib/apt/lists/* /root/.npm

# ---------------------------------------------------------------------------
# Copy compiled Go tool binaries from the builder stage.
# The entire Go SDK stays in the builder — only ~100MB of binaries come here.
# ---------------------------------------------------------------------------
COPY --from=go-tools-builder /go/bin/* /usr/local/bin/

# ---------------------------------------------------------------------------
# Copy the r3ngine Temporal executor binary
# ---------------------------------------------------------------------------
COPY --from=executor-builder /usr/local/bin/r3ngine-executor /usr/local/bin/r3ngine-executor

# Vigolium — web vulnerability scanner (built separately due to Go 1.26 + bun requirement)
COPY --from=vigolium-builder /usr/local/bin/vigolium /usr/local/bin/vigolium

# ---------------------------------------------------------------------------
# Install pre-built binary tools (no compilation needed at runtime)
# ---------------------------------------------------------------------------

# Trufflehog — secret scanning binary (pinned to avoid GitHub API rate-limit failures at build time)
RUN ARCH=$(dpkg --print-architecture) && \
    TRUFFLEHOG_VERSION="3.89.1" && \
    wget -q "https://github.com/trufflesecurity/trufflehog/releases/download/v${TRUFFLEHOG_VERSION}/trufflehog_${TRUFFLEHOG_VERSION}_linux_${ARCH}.tar.gz" && \
    tar -xf "trufflehog_${TRUFFLEHOG_VERSION}_linux_${ARCH}.tar.gz" trufflehog && \
    mv trufflehog /usr/local/bin/ && \
    rm -f "trufflehog_${TRUFFLEHOG_VERSION}_linux_${ARCH}.tar.gz"

# k6 — load/stress testing tool
RUN ARCH=$(dpkg --print-architecture) && \
    K6_VERSION="0.50.0" && \
    if [ "${ARCH}" = "arm64" ]; then K6_ARCH="arm64"; else K6_ARCH="amd64"; fi && \
    wget -q "https://github.com/grafana/k6/releases/download/v${K6_VERSION}/k6-v${K6_VERSION}-linux-${K6_ARCH}.tar.gz" && \
    tar -xf "k6-v${K6_VERSION}-linux-${K6_ARCH}.tar.gz" "k6-v${K6_VERSION}-linux-${K6_ARCH}/k6" && \
    mv "k6-v${K6_VERSION}-linux-${K6_ARCH}/k6" /usr/local/bin/ && \
    rm -rf "k6-v${K6_VERSION}-linux-${K6_ARCH}"*

# Brutus — HTTP brute force tool
RUN curl -L https://github.com/praetorian-inc/brutus/releases/latest/download/brutus-linux-amd64.tar.gz | \
    tar xz && mv brutus /usr/local/bin/

# Dalfox v3 — XSS scanner (Rust rewrite; built from source in dalfox-builder stage)
COPY --from=dalfox-builder /usr/local/bin/dalfox /usr/local/bin/dalfox

# Aquatone — visual recon / screenshot tool (needs Chromium at runtime)
RUN ARCH=$(dpkg --print-architecture) && \
    wget -q "https://github.com/michenriksen/aquatone/releases/download/v1.7.0/aquatone_linux_${ARCH}_1.7.0.zip" && \
    unzip -o "aquatone_linux_${ARCH}_1.7.0.zip" aquatone && \
    mv aquatone /usr/local/bin/ && \
    rm -f "aquatone_linux_${ARCH}_1.7.0.zip"

# Feroxbuster — recursive web content discovery (pinned to avoid GitHub API rate-limit failures at build time)
RUN FEROX_VERSION="2.11.0" && \
    wget -q "https://github.com/epi052/feroxbuster/releases/download/v${FEROX_VERSION}/x86-linux-feroxbuster.zip" \
      -O /tmp/feroxbuster.zip && \
    unzip /tmp/feroxbuster.zip feroxbuster -d /usr/local/bin && \
    chmod +x /usr/local/bin/feroxbuster && \
    rm /tmp/feroxbuster.zip

# Searchsploit — offline Exploit-DB CLI search
RUN git clone --depth 1 https://gitlab.com/exploit-database/exploitdb /usr/src/exploitdb && \
    ln -sf /usr/src/exploitdb/searchsploit /usr/local/bin/searchsploit && \
    cp /usr/src/exploitdb/.searchsploit_rc /root/.searchsploit_rc

# WPScan — WordPress vulnerability scanner
RUN gem install wpscan --no-document

# GooFuzz — Google-dork based fuzzer (shell script, no compilation)
RUN mkdir -p /usr/src/github && \
    wget -q -O /tmp/GooFuzz.zip "https://github.com/m3n0sd0n4ld/GooFuzz/releases/download/1.2.6/GooFuzz.v.1.2.6.zip" && \
    unzip -q /tmp/GooFuzz.zip -d /tmp/goofuzz_extract && \
    mv /tmp/goofuzz_extract/GooFuzz.v.1.2.6 /usr/src/github/goofuzz && \
    chmod +x /usr/src/github/goofuzz/GooFuzz && \
    rm -rf /tmp/GooFuzz.zip /tmp/goofuzz_extract

WORKDIR /usr/src/app

# ---------------------------------------------------------------------------
# Clone Python-based security tools
# All clones are shallow (--depth 1) and .git directories are removed after
# installation to eliminate full git history from the image.
# ---------------------------------------------------------------------------
RUN git clone --depth 1 https://github.com/smicallef/spiderfoot /usr/src/github/spiderfoot && \
    pip3 install -r /usr/src/github/spiderfoot/requirements.txt && \
    rm -rf /usr/src/github/spiderfoot/.git

RUN git clone --depth 1 https://github.com/assetnote/cpanel2shell-scanner /usr/src/github/cpanel2shell-scanner && \
    pip3 install -r /usr/src/github/cpanel2shell-scanner/requirements.txt && \
    rm -rf /usr/src/github/cpanel2shell-scanner/.git

RUN git clone --depth 1 https://github.com/assetnote/react2shell-scanner /usr/src/github/react2shell-scanner && \
    pip3 install -r /usr/src/github/react2shell-scanner/requirements.txt && \
    rm -rf /usr/src/github/react2shell-scanner/.git

RUN git clone --depth 1 https://github.com/UnaPibaGeek/ctfr /usr/src/github/ctfr && \
    pip3 install -r /usr/src/github/ctfr/requirements.txt && \
    rm -rf /usr/src/github/ctfr/.git

RUN git clone --depth 1 https://github.com/urbanadventurer/username-anarchy /usr/src/github/username-anarchy && \
    ln -sf /usr/src/github/username-anarchy/username-anarchy /usr/local/bin/username-anarchy

RUN git clone --depth 1 https://github.com/WazeHell/acunetix-python /usr/src/github/acunetix-python && \
    sed -i 's/Sent from Acunetix-Python/r3-external/g' /usr/src/github/acunetix-python/acunetix/core.py && \
    pip3 install --no-cache-dir /usr/src/github/acunetix-python && \
    rm -rf /usr/src/github/acunetix-python/.git

RUN git clone --depth 1 https://github.com/shmilylty/OneForAll /usr/src/github/OneForAll && \
    pip3 install -r /usr/src/github/OneForAll/requirements.txt && \
    rm -rf /usr/src/github/OneForAll/.git

RUN git clone --depth 1 https://github.com/aboul3la/Sublist3r /usr/src/github/Sublist3r && \
    pip3 install -r /usr/src/github/Sublist3r/requirements.txt && \
    sed -i "s/token = csrf_regex.findall(resp)\[0\]/token = csrf_regex.findall(resp)[0] if csrf_regex.findall(resp) else ''/g" /usr/src/github/Sublist3r/sublist3r.py && \
    rm -rf /usr/src/github/Sublist3r/.git

RUN git clone --depth 1 https://github.com/laramies/theHarvester /usr/src/github/theHarvester && \
    cd /usr/src/github/theHarvester && uv sync && \
    rm -rf /usr/src/github/theHarvester/.git

RUN git clone --depth 1 https://github.com/devanshbatham/ParamSpider /usr/src/github/ParamSpider && \
    cd /usr/src/github/ParamSpider && pip3 install . && \
    rm -rf /usr/src/github/ParamSpider/.git

RUN git clone --depth 1 https://github.com/GerbenJavado/LinkFinder.git /usr/src/github/LinkFinder && \
    pip3 install -r /usr/src/github/LinkFinder/requirements.txt && \
    cd /usr/src/github/LinkFinder && python3 setup.py install && \
    rm -rf /usr/src/github/LinkFinder/.git

RUN git clone --depth 1 https://github.com/Tuhinshubhra/CMSeeK /usr/src/github/CMSeeK && \
    pip3 install -r /usr/src/github/CMSeeK/requirements.txt && \
    rm -rf /usr/src/github/CMSeeK/.git

RUN git clone --depth 1 https://github.com/drwetter/testssl.sh /usr/src/github/testssl.sh && \
    chmod +x /usr/src/github/testssl.sh/testssl.sh && \
    ln -sf /usr/src/github/testssl.sh/testssl.sh /usr/local/bin/testssl.sh

RUN git clone --depth 1 https://github.com/ticarpi/jwt_tool /usr/src/github/jwt_tool && \
    pip3 install -r /usr/src/github/jwt_tool/requirements.txt && \
    rm -rf /usr/src/github/jwt_tool/.git

# ---------------------------------------------------------------------------
# Install Python security tools via pip (no source clone needed)
#
# Tools with no version conflicts are installed into system site-packages.
# Tools that conflict with each other or with the Django app's requirements
# (dirsearch, maigret, semgrep) are isolated in their own pipx virtual
# environments so their transitive dependencies cannot clash.
#
# Conflicts resolved by pipx isolation:
#   dirsearch 0.4.3.post1 — requires requests>=2.27.0  (system: 2.25.1)
#   maigret   0.6.1       — requires requests>=2.32.4, chardet>=5, idna>=3.4
#   semgrep   1.165.0     — requires urllib3~=2.0       (system: 1.26.x)
#
# /root/.local/bin is already on PATH (set earlier in this Dockerfile), so
# all pipx shims are immediately available to subsequent RUN steps and at
# container runtime without any additional PATH configuration.
# ---------------------------------------------------------------------------
RUN --mount=type=cache,target=/root/.cache/pip \
    pip3 install --upgrade pip setuptools wheel pyOpenSSL h8mail && \
    pip3 install --upgrade fierce dirsearch meson ninja arjun inql netlas holehe

# Ensure pipx is available and install baddns
RUN --mount=type=cache,target=/root/.cache/pip \
    python3 -m pip install pipx && \
    pipx install git+https://github.com/blacklanternsecurity/baddns

# Install conflicting tools in isolated pipx environments.
# Each venv gets setuptools installed via its own pip to guarantee pkg_resources
# is available under Python 3.12 (pipx inject can be silently skipped by layer cache).
RUN --mount=type=cache,target=/root/.cache/pip \
    pipx install maigret && \
    pipx inject maigret setuptools && \
    pipx install semgrep && \
    pipx inject semgrep setuptools && \
    pipx install dnsrecon && \
    pipx inject dnsrecon setuptools && \
    pipx install ssh-audit --force && \
    pipx install "git+https://github.com/EnableSecurity/wafw00f.git" --force && \
    pipx install whoisdomain --force && \
    pipx install "bypass-url-parser" --force && \
    pipx install bbot --force && \
    pipx install sploitscan --force

# grype — Anchore filesystem CVE scanner
# PINNED to v0.114.0 — downloaded directly from GitHub Releases (NOT install.sh)
# SHA256 verified against official grype_0.114.0_checksums.txt
RUN GRYPE_VERSION="0.114.0" && \
    curl -sSfL \
      "https://github.com/anchore/grype/releases/download/v${GRYPE_VERSION}/grype_${GRYPE_VERSION}_linux_amd64.tar.gz" \
      -o /tmp/grype.tar.gz && \
    echo "edda0968d8827daab01d32b3cd7de192ae0915005e7bbfcfef9e68e79bc43343  /tmp/grype.tar.gz" | sha256sum -c && \
    tar -xzf /tmp/grype.tar.gz -C /usr/local/bin grype && \
    rm /tmp/grype.tar.gz

# trivy — filesystem secrets scanner
# PINNED to v0.69.3 — downloaded directly from GitHub Releases (NOT install.sh)
# v0.69.4 was compromised in a March 2026 supply chain attack (credential-stealing binary)
# SHA256 verified against official trivy_0.69.3_checksums.txt
RUN TRIVY_VERSION="0.69.3" && \
    curl -sSfL \
      "https://github.com/aquasecurity/trivy/releases/download/v${TRIVY_VERSION}/trivy_${TRIVY_VERSION}_Linux-64bit.tar.gz" \
      -o /tmp/trivy.tar.gz && \
    echo "1816b632dfe529869c740c0913e36bd1629cb7688bd5634f4a858c1d57c88b75  /tmp/trivy.tar.gz" | sha256sum -c && \
    tar -xzf /tmp/trivy.tar.gz -C /usr/local/bin trivy && \
    rm /tmp/trivy.tar.gz

RUN git clone --depth 1 https://github.com/dolevf/graphql-cop.git /usr/src/github/graphql-cop \
    && pip3 install -r /usr/src/github/graphql-cop/requirements.txt \
    && rm -rf /usr/src/github/graphql-cop/.git

RUN git clone --depth 1 https://github.com/cddmp/enum4linux-ng /usr/src/github/enum4linux-ng \
    && pip3 install -r /usr/src/github/enum4linux-ng/requirements.txt \
    && ln -sf /usr/src/github/enum4linux-ng/enum4linux-ng.py /usr/local/bin/enum4linux-ng \
    && rm -rf /usr/src/github/enum4linux-ng/.git

RUN git clone --depth 1 https://github.com/CiscoCXSecurity/rdp-sec-check /usr/src/github/rdp-sec-check \
    && cpan install Encoding::BER \
    && ln -sf /usr/src/github/rdp-sec-check/rdp-sec-check.pl /usr/local/bin/rdp-sec-check

# ---------------------------------------------------------------------------
# Copy and install the application's Python requirements
# This layer is intentionally placed after tool installs so requirements.txt
# changes don't invalidate the tool-install cache layers above.
# ---------------------------------------------------------------------------
COPY web/requirements.txt /tmp/requirements.txt
RUN --mount=type=cache,target=/root/.cache/pip \
    pip3 install -r /tmp/requirements.txt --ignore-installed blinker

# pip's httpx Python package installs a CLI wrapper at /usr/local/bin/httpx that
# overwrites the ProjectDiscovery Go tool copied earlier. Restore the Go binary.
COPY --from=go-tools-builder /go/bin/httpx /usr/local/bin/httpx

# ---------------------------------------------------------------------------
# Install Playwright Chromium (required for Aquatone screenshot capability)
# ---------------------------------------------------------------------------
RUN playwright install-deps chromium && \
    playwright install chromium && \
    ln -sf /root/.cache/ms-playwright/chromium-*/chrome-linux/chrome /usr/bin/chromium

# ---------------------------------------------------------------------------
# Copy application source (placed last — changes most frequently, so layers
# above this line are fully cached on code-only rebuilds)
# ---------------------------------------------------------------------------
COPY web/ /usr/src/app/
COPY docker/web/entrypoint.sh /usr/src/app/entrypoint.sh
COPY docker/temporal-python-orchestrator/entrypoint.sh /usr/src/app/temporal-entrypoint.sh
COPY docker/temporal-go-executor/entrypoint.sh /usr/src/app/executor-entrypoint.sh
RUN chmod +x /usr/src/app/entrypoint.sh /usr/src/app/temporal-entrypoint.sh /usr/src/app/executor-entrypoint.sh

#RUN mkdir -p /usr/src/app/frontend
#COPY frontend/ /usr/src/app/frontend/
#WORKDIR /usr/src/app/frontend
#RUN npm install
#WORKDIR /usr/src/app

# ---------------------------------------------------------------------------
# Copy built frontend from frontend-builder
# ---------------------------------------------------------------------------
COPY --from=frontend-builder /app/frontend/dist /usr/src/frontend/dist

# ---------------------------------------------------------------------------
# Final cleanup: strip Python bytecode and __pycache__ from all tool repos
# to remove files that are regenerated on first import anyway.
# ---------------------------------------------------------------------------
RUN find /usr/src -name "*.pyc" -delete 2>/dev/null; \
    find /usr/src -type d -name "__pycache__" -exec rm -rf {} + 2>/dev/null; \
    true
