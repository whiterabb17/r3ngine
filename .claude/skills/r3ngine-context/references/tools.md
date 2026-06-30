# r3ngine — Integrated Security Tools

Tools compiled into the Docker image and invoked via Temporal activities (Python orchestrator or Go executor). Authoritative source: `docker/web/Dockerfile`.

---

## Reconnaissance

### DNS / Subdomains

| Tool | Description | Source |
|------|-------------|--------|
| **subfinder** | Passive subdomain discovery from OSINT sources | [projectdiscovery/subfinder](https://github.com/projectdiscovery/subfinder) |
| **dnsx** | Fast multi-purpose DNS toolkit | [projectdiscovery/dnsx](https://github.com/projectdiscovery/dnsx) |
| **amass** v4.2.0 | In-depth DNS enumeration and OSINT | [owasp-amass/amass](https://github.com/owasp-amass/amass) |
| **Sublist3r** | Subdomain enumeration via search engines | [aboul3la/Sublist3r](https://github.com/aboul3la/Sublist3r) |
| **OneForAll** | Comprehensive subdomain collection | [shmilylty/OneForAll](https://github.com/shmilylty/OneForAll) |
| **chaos** | Passive DNS from Chaos dataset | [projectdiscovery/chaos-client](https://github.com/projectdiscovery/chaos-client) |
| **dnsrecon** | DNS enumeration and zone transfer | [darkoperator/dnsrecon](https://github.com/darkoperator/dnsrecon) (pipx) |
| **baddns** | Subdomain takeover detection | [blacklanternsecurity/baddns](https://github.com/blacklanternsecurity/baddns) (pipx) |
| **dnsx** | Multi-purpose DNS toolkit | [projectdiscovery/dnsx](https://github.com/projectdiscovery/dnsx) |
| **mapcidr** | IP range / CIDR operations | [projectdiscovery/mapcidr](https://github.com/projectdiscovery/mapcidr) |
| **getasn** | ASN enumeration | [Vulnpire/getasn](https://github.com/Vulnpire/getasn) |
| **ctfr** | Subdomain discovery via Certificate Transparency | [UnaPibaGeek/ctfr](https://github.com/UnaPibaGeek/ctfr) |
| **jswhois** | WHOIS lookup tool | [jschauma/jswhois](https://github.com/jschauma/jswhois) |

### Port Scanning

| Tool | Description | Source |
|------|-------------|--------|
| **naabu** | Fast port discovery (Go, raw packets) | [projectdiscovery/naabu](https://github.com/projectdiscovery/naabu) |
| **nmap** | Port / service / OS / vuln scanning with NSE | system package |
| **fping** | Fast ICMP ping sweep | system package |
| **arp-scan** | ARP-based host discovery | system package |

### WHOIS / ASN / IP Intel

| Tool | Description | Source |
|------|-------------|--------|
| **whoisdomain** | WHOIS domain lookups | pipx |
| **netlas** | Internet asset intelligence API | pip |
| **spiderfoot** | Automated OSINT / threat intelligence | [smicallef/spiderfoot](https://github.com/smicallef/spiderfoot) |

---

## HTTP & Crawling

| Tool | Description | Source |
|------|-------------|--------|
| **httpx** | Fast HTTP prober — status, title, tech stack | [projectdiscovery/httpx](https://github.com/projectdiscovery/httpx) |
| **katana** | Next-generation crawling and spidering | [projectdiscovery/katana](https://github.com/projectdiscovery/katana) |
| **gau** | Offline URL fetcher (Wayback, AlienVault, CommonCrawl) | [lc/gau](https://github.com/lc/gau) |
| **hakrawler** | Fast web crawler for endpoint discovery | [hakluke/hakrawler](https://github.com/hakluke/hakrawler) |
| **gospider** | Fast web spider (Go) | [jaeles-project/gospider](https://github.com/jaeles-project/gospider) |
| **cariddi** | Web crawler and endpoint extraction | [edoardottt/cariddi](https://github.com/edoardottt/cariddi) |
| **xurlfind3r** | URL discovery from passive sources | [hueristiq/xurlfind3r](https://github.com/hueristiq/xurlfind3r) |
| **urlfinder** | URL discovery (ProjectDiscovery) | [projectdiscovery/urlfinder](https://github.com/projectdiscovery/urlfinder) |
| **waybackurls** | Pull URLs from Wayback Machine | [tomnomnom/waybackurls](https://github.com/tomnomnom/waybackurls) |
| **unfurl** | Extract components from URLs | [tomnomnom/unfurl](https://github.com/tomnomnom/unfurl) |
| **gf** | Pattern-based URL filtering | [tomnomnom/gf](https://github.com/tomnomnom/gf) |
| **ParamSpider** | Parameter discovery from web archives | [devanshbatham/ParamSpider](https://github.com/devanshbatham/ParamSpider) |
| **LinkFinder** | JavaScript endpoint discovery | [GerbenJavado/LinkFinder](https://github.com/GerbenJavado/LinkFinder) |
| **arjun** | HTTP parameter discovery | pip |

---

## Fuzzing

| Tool | Description | Source |
|------|-------------|--------|
| **ffuf** | Fast web fuzzer — directories, parameters, vhosts | [ffuf/ffuf](https://github.com/ffuf/ffuf) |
| **dirsearch** | Web path discovery (Python) | pip (pipx-isolated) |
| **feroxbuster** v2.11.0 | Recursive web content discovery (Rust) | [epi052/feroxbuster](https://github.com/epi052/feroxbuster) |
| **GooFuzz** v1.2.6 | Google-dork based fuzzer | [m3n0sd0n4ld/GooFuzz](https://github.com/m3n0sd0n4ld/GooFuzz) |

---

## Screenshots

| Tool | Description | Source |
|------|-------------|--------|
| **Playwright** 1.42.0 | Headless Chromium — primary screenshot tool | pip |
| **aquatone** v1.7.0 | Visual recon / web screenshot tool | [michenriksen/aquatone](https://github.com/michenriksen/aquatone) |

---

## OSINT

| Tool | Description | Source |
|------|-------------|--------|
| **theHarvester** | Email, subdomain, host OSINT gathering | [laramies/theHarvester](https://github.com/laramies/theHarvester) |
| **holehe** | Email registration check across sites | pip |
| **maigret** | Hunt for user accounts across 2000+ sites | pipx |
| **h8mail** | Email OSINT and breach hunting | pip |
| **gosearch** | Username/profile OSINT | [ibnaleem/gosearch](https://github.com/ibnaleem/gosearch) |
| **username-anarchy** | Username permutation for OSINT | [urbanadventurer/username-anarchy](https://github.com/urbanadventurer/username-anarchy) |
| **bbot** | OSINT automation framework | pipx |
| **reconx** | Recon aggregation tool | [xalgord/reconx](https://github.com/xalgord/reconx) |

---

## Vulnerability Scanning

| Tool | Description | Source |
|------|-------------|--------|
| **nuclei** v3.9.0 | Fast configurable vuln scanner (YAML templates) | [projectdiscovery/nuclei](https://github.com/projectdiscovery/nuclei) |
| **dalfox** v3 | XSS scanning and parameter analysis (Rust rewrite) | [hahwul/dalfox](https://github.com/hahwul/dalfox) |
| **wpscan** | WordPress security scanner | [wpscanteam/wpscan](https://github.com/wpscanteam/wpscan) (gem) |
| **taint-scan** (WPTaint) | WordPress taint-flow vulnerability analysis | [dimasma0305/wp-taint-scan](https://github.com/dimasma0305/wp-taint-scan) |
| **wpprobe** | WordPress plugin/version detection | [Chocapikk/wpprobe](https://github.com/Chocapikk/wpprobe) |
| **vulnx** | Vulnerability discovery via cert/tech intel | [projectdiscovery/vulnx](https://github.com/projectdiscovery/vulnx) |
| **crlfuzz** | CRLF injection scanner | [dwisiswant0/crlfuzz](https://github.com/dwisiswant0/crlfuzz) |
| **nikto** | Web server scanner | system (see `internal_tools.sh`) |
| **sploitscan** | Exploit search and scoring | pipx |
| **fierce** | DNS reconnaissance / zone walk | pip |
| **searchsploit** | Offline Exploit-DB search CLI | [exploit-database/exploitdb](https://gitlab.com/exploit-database/exploitdb) |
| **CMSeeK** | CMS detection and exploitation | [Tuhinshubhra/CMSeeK](https://github.com/Tuhinshubhra/CMSeeK) |
| **bypass-url-parser** | URL WAF bypass testing | pipx |

---

## Static Code & Secret Scanning

| Tool | Description | Source |
|------|-------------|--------|
| **vigolium** | Static web vulnerability scanner (JS/PHP/code) | [vigolium/vigolium](https://github.com/vigolium/vigolium) (built from source) |
| **semgrep** | Static analysis — multi-language SAST | pipx |
| **gitleaks** | Git secret scanning | [zricethezav/gitleaks](https://github.com/zricethezav/gitleaks) |
| **trufflehog** v3.89.1 | Secret scanning in code / git history | [trufflesecurity/trufflehog](https://github.com/trufflesecurity/trufflehog) |
| **betterleaks** | Advanced credential leak detection | [betterleaks/betterleaks](https://github.com/betterleaks/betterleaks) |
| **s3scanner** | S3 bucket exposure scanner | [sa7mon/s3scanner](https://github.com/sa7mon/s3scanner) |

---

## Supply Chain / Container Scanning

| Tool | Description | Source |
|------|-------------|--------|
| **grype** v0.114.0 | Anchore filesystem / container CVE scanner | [anchore/grype](https://github.com/anchore/grype) |
| **retire** | JS dependency vulnerability scanner (Node) | npm |

---

## SSL / TLS

| Tool | Description | Source |
|------|-------------|--------|
| **tlsx** | TLS certificate and configuration scanner | [projectdiscovery/tlsx](https://github.com/projectdiscovery/tlsx) |
| **testssl.sh** | Comprehensive TLS/SSL testing script | [drwetter/testssl.sh](https://github.com/drwetter/testssl.sh) |
| **sslscan** | SSL/TLS cipher and certificate scanner | system package |
| **ssh-audit** | SSH server configuration auditor | pipx |

---

## GraphQL / API

| Tool | Description | Source |
|------|-------------|--------|
| **inql** | GraphQL security testing | pip |

---

## Credential / Auth Testing

| Tool | Description | Source |
|------|-------------|--------|
| **hydra** | Multi-service auth brute force | system (see `internal_tools.sh`) |
| **brutus** | HTTP brute force tool | [praetorian-inc/brutus](https://github.com/praetorian-inc/brutus) |
| **jwt_tool** | JWT attack and analysis tool | [ticarpi/jwt_tool](https://github.com/ticarpi/jwt_tool) |

---

## WAF Detection

| Tool | Description | Source |
|------|-------------|--------|
| **wafw00f** | WAF fingerprinting and detection | pipx |

---

## Network / Protocol

| Tool | Description | Source |
|------|-------------|--------|
| **ike-scan** | IKE/IPsec VPN scanner | system package |
| **onesixtyone** | SNMP scanner | system package |
| **snmp** | SNMP tools | system package |
| **ldap-utils** | LDAP enumeration tools | system package |
| **dnsutils** | dig, nslookup, etc. | system package |
| **netcat** | TCP/IP utility | system package |
| **proxychains4** | TCP proxy chaining | system package |
| **hping3** | TCP/IP packet assembler / stress test | system package |

---

## Stress Testing

| Tool | Description | Source |
|------|-------------|--------|
| **k6** v0.50.0 | Load and stress testing (JavaScript scripts) | [grafana/k6](https://github.com/grafana/k6) |
| **wrk** | HTTP benchmarking | system package |
| **hping3** | TCP/IP packet assembler / analyser | system package |

---

## CPanel / Hosting Attack Surface

| Tool | Description | Source |
|------|-------------|--------|
| **cpanel2shell-scanner** | cPanel shell upload scanner | [assetnote/cpanel2shell-scanner](https://github.com/assetnote/cpanel2shell-scanner) |
| **react2shell-scanner** | React shell upload detection | [assetnote/react2shell-scanner](https://github.com/assetnote/react2shell-scanner) |
| **acunetix-python** | Acunetix API integration | [WazeHell/acunetix-python](https://github.com/WazeHell/acunetix-python) |

---

*Tool list reflects the v3.6.x Docker image build (`docker/web/Dockerfile`). Some heavy tools (hydra, nikto, hashcat, etc.) are installed on-demand at runtime via `docker/web/internal_tools.sh` to reduce base image size.*
