#!/usr/bin/python
import logging
import re

###############################################################################
# TOOLS DEFINITIONS
###############################################################################
logger = logging.getLogger('django')

###############################################################################
# TOOLS DEFINITIONS
###############################################################################

EMAIL_REGEX = re.compile(r'[\w\.-]+@[\w\.-]+')

###############################################################################
# TOOL COLORS DEFINITIONS (ANSI Escape Codes)
###############################################################################
COLOR_RESET = "\033[0m"
COLOR_WHITE = "\033[37m"
COLOR_RED = "\033[91m"
COLOR_GREEN = "\033[92m"
COLOR_YELLOW = "\033[93m"
COLOR_BLUE = "\033[94m"
COLOR_MAGENTA = "\033[95m"
COLOR_CYAN = "\033[96m"
COLOR_ORANGE = "\033[38;5;208m"
COLOR_PURPLE = "\033[38;5;135m"

TOOL_COLORS = {
    'httpx': COLOR_BLUE,
    'nuclei': COLOR_MAGENTA,
    'subfinder': COLOR_CYAN,
    'amass': COLOR_YELLOW,
    'naabu': COLOR_GREEN,
    'dirsearch': COLOR_ORANGE,
    'wpscan': COLOR_RED,
    'gofuzz': COLOR_PURPLE,
    'sublist3r': COLOR_CYAN,
    'ctfr': COLOR_BLUE,
    'ffuf': COLOR_YELLOW,
    'nmap': COLOR_GREEN,
    'dalfox': COLOR_MAGENTA,
    's3scanner': COLOR_BLUE,
    'crlfuzz': COLOR_RED,
    'aquatone': COLOR_CYAN,
    'arjun': COLOR_YELLOW,
    'inql': COLOR_MAGENTA,
    'netlas': COLOR_BLUE,
    'holehe': COLOR_GREEN,
    'maigret': COLOR_MAGENTA,
    'retire': COLOR_YELLOW,
    'gitleaks': COLOR_RED,
    'trufflehog': COLOR_ORANGE,
    'k6': COLOR_PURPLE,
    'whatportis': COLOR_CYAN,
    'cmseek': COLOR_MAGENTA,
    'linkfinder': COLOR_BLUE,
    'paramspider': COLOR_YELLOW,
    'semgrep': COLOR_GREEN,
    'oneforall': COLOR_CYAN,
    'theharvester': COLOR_BLUE,
    'spiderfoot': COLOR_MAGENTA,
    'cpanel2shell-scanner': COLOR_RED,
    'h8mail': COLOR_PURPLE,
    'baddns': COLOR_CYAN,
    'betterleaks': COLOR_RED,
    'gosearch': COLOR_GREEN,
    'username-anarchy': COLOR_YELLOW,
    'testssl.sh': COLOR_GREEN,
    'jwt_tool': COLOR_MAGENTA,
    'graphql-cop': COLOR_BLUE,
    'enum4linux-ng': COLOR_YELLOW,
    'dnsrecon': COLOR_CYAN,
    'fierce': COLOR_ORANGE,
}

###############################################################################
# YAML CONFIG DEFINITIONS
###############################################################################

ALL = 'all'
AMASS_WORDLIST = 'amass_wordlist'
AUTO_CALIBRATION = 'auto_calibration'
CUSTOM_HEADERS = 'custom_headers'
CUSTOM_HEADER = 'custom_header'
FETCH_GPT_REPORT = 'fetch_gpt_report'
RUN_NUCLEI = 'run_nuclei'
RUN_ACUNETIX = 'run_acunetix'
RUN_CRLFUZZ = 'run_crlfuzz'
RUN_DALFOX = 'run_dalfox'
RUN_S3SCANNER = 'run_s3scanner'
DIR_FILE_FUZZ = 'dir_file_fuzz'
FOLLOW_REDIRECT = 'follow_redirect'
EXTENSIONS = 'extensions'
EXCLUDED_SUBDOMAINS = 'exclude_subdomains'
EXCLUDE_EXTENSIONS = 'exclude_extensions'
EXCLUDE_TEXT = 'exclude_text'
FETCH_URL = 'fetch_url'
GF_PATTERNS = 'gf_patterns'
HTTP_CRAWL = 'http_crawl'
IGNORE_FILE_EXTENSION = 'ignore_file_extensions'
INTENSITY = 'intensity'
MATCH_HTTP_STATUS = 'match_http_status'
MAX_TIME = 'max_time'
NAABU_EXCLUDE_PORTS = 'exclude_ports'
NAABU_EXCLUDE_SUBDOMAINS = 'exclude_subdomains'
ENABLE_NMAP = 'enable_nmap'
NMAP_COMMAND = 'nmap_cmd'
NMAP_SCRIPT = 'nmap_script'
NMAP_SCRIPT_ARGS = 'nmap_script_args'
NAABU_PASSIVE = 'passive'
NAABU_RATE = 'rate'
NUCLEI_CUSTOM_TEMPLATE = 'custom_templates'
NUCLEI_TAGS = 'tags'
NUCLEI_TEMPLATE = 'templates'
NUCLEI_SEVERITY = 'severities'
NUCLEI_CONCURRENCY = 'concurrency'
# Maximum concurrency and rate when routing nuclei through a proxy file.
# nuclei v3.9.0 AdaptiveWaitGroup deadlocks at high concurrency when the
# proxy error rate exceeds ~60% — these caps prevent the semaphore hang.
NUCLEI_PROXY_MAX_CONCURRENCY = 10
NUCLEI_PROXY_MAX_RATE_LIMIT = 10
NUCLEI_MAX_TEMPLATES_PER_BATCH = 'max_templates_per_batch'
OSINT = 'osint'
OSINT_DOCUMENTS_LIMIT = 'documents_limit'
OSINT_DISCOVER = 'discover'
OSINT_DORK = 'dorks'
OSINT_CUSTOM_DORK = 'custom_dorks'
PORT = 'port'
PORTS = 'ports'
RECURSIVE = 'recursive'
RECURSIVE_LEVEL = 'recursive_level'
PORT_SCAN = 'port_scan'
RATE_LIMIT = 'rate_limit'
RETRIES = 'retries'
SCREENSHOT = 'screenshot'
SUBDOMAIN_DISCOVERY = 'subdomain_discovery'
STOP_ON_ERROR = 'stop_on_error'
ENABLE_HTTP_CRAWL = 'enable_http_crawl'
THREADS = 'threads'
TIMEOUT = 'timeout'
USE_AMASS_CONFIG = 'use_amass_config'
USE_NAABU_CONFIG = 'use_naabu_config'
USE_NUCLEI_CONFIG = 'use_nuclei_config'
USE_SUBFINDER_CONFIG = 'use_subfinder_config'
USES_TOOLS = 'uses_tools'
VULNERABILITY_SCAN = 'vulnerability_scan'
WAF_DETECTION = 'waf_detection'
WORDLIST = 'wordlist_name'
REMOVE_DUPLICATE_ENDPOINTS = 'remove_duplicate_endpoints'
DUPLICATE_REMOVAL_FIELDS = 'duplicate_fields'
DALFOX = 'dalfox'
S3SCANNER = 's3scanner'
NUCLEI = 'nuclei'
NMAP = 'nmap'
CRLFUZZ = 'crlfuzz'
WAF_EVASION = 'waf_evasion'
BLIND_XSS_SERVER = 'blind_xss_server'
USER_AGENT = 'user_agent'
DELAY = 'delay'
PROVIDERS = 'providers'
FIREWALL_VPN_SCAN = 'firewall_vpn_scan'

SPIDERFOOT_SCAN = 'spiderfoot_scan'
WEB_API_DISCOVERY = 'web_api_discovery'
ATTACK_PATH_MODELING = 'attack_path_modeling'
KITERUNNER_WORDLIST = 'kr_wordlist'
SERVICES = 'services'
SCAN_ONLY_ACTIVE = 'scan_only_active'
ARJUN_METHODS = 'arjun_methods'
LEAKS_AND_SECRETS = 'leaks_and_secrets'
LEAKLOOKUP = 'leaklookup'
PROJECTDISCOVERY = 'projectdiscovery'
GITLEAKS = 'gitleaks'
TRUFFLEHOG = 'trufflehog'
RUN_CPANEL2SHELL = 'run_cpanel2shell'
CPANEL_USER_WORDLIST = 'cpanel_user_wordlist'
CPANEL_SCANNER_PROXY_TYPE = 'proxy_type'
CPANEL_SCANNER_DEFAULT_WORDLIST = '/usr/src/app/wordlist/auth/cpanel_users.txt'

RUN_REACT2SHELL = 'run_react2shell'
USE_WORDFENCE_CANDIDATE = 'use_wordfence_candidate'

BADDNS = 'baddns'
BETTERLEAKS = 'betterleaks'
GOSEARCH = 'gosearch'
USERNAME_ANARCHY = 'username-anarchy'
AMASS_INTEL = 'amass_intel'
DIRSEARCH = 'dirsearch'
RUN_DIRSEARCH = 'run_dirsearch'

# TLS deep audit
ENABLE_TESTSSL = 'enable_testssl'
ENABLE_CRT_SH = 'enable_crt_sh'

# Network protocol enumeration
ENABLE_NETWORK_ENUM = 'enable_network_enum'

# API security
JWT_TOOL = 'jwt_tool'
GRAPHQL_COP = 'graphql-cop'
USE_API_WORDLIST = 'use_api_wordlist'
FFUF_DEFAULT_API_WORDLIST_PATH = '/usr/src/wordlist/api-endpoints.txt'

# DNS security
DNS_SECURITY = 'dns_security'
ENABLE_AXFR = 'enable_axfr'
ENABLE_DNSSEC_CHECK = 'enable_dnssec_check'
ENABLE_DNS_BRUTE = 'enable_dns_brute'
DNS_AMPLIFICATION_THRESHOLD = 'amplification_threshold'


RUN_WPSCAN = 'run_wpscan'
RUN_WPTAINT_SCAN = 'run_wptaint_scan'
WPSCAN_ENUMERATION = 'wpscan_enumeration'
WPSCAN_DETECTION_MODE = 'wpscan_detection_mode'
WPSCAN_SCAN_DEFAULT_CONFIG = {
    'run_wpscan': True,
    'run_wptaint_scan': True,
    'wpscan_enumeration': 'vp,vt,u',
    'wpscan_detection_mode': 'mixed'
}

# ─── Vigolium ─────────────────────────────────────────────────────────────────
RUN_VIGOLIUM = 'run_vigolium'
RUN_VIGOLIUM_DISCOVERY = 'run_vigolium_discovery'
RUN_VIGOLIUM_ANALYSIS = 'run_vigolium_analysis'
VIGOLIUM = 'vigolium'
VIGOLIUM_STRATEGY = 'strategy'
VIGOLIUM_CONCURRENCY = 'concurrency'
VIGOLIUM_RATE_LIMIT = 'rate_limit'
VIGOLIUM_TIMEOUT = 'timeout'
VIGOLIUM_MODULES = 'modules'
VIGOLIUM_SEVERITY_FILTER = 'severity_filter'

VIGOLIUM_DEFAULT_CONFIG = {
    'run_vigolium': True,
    'strategy': 'balanced',
    'concurrency': 50,
    'rate_limit': 100,
    'timeout': '15s',
}

VIGOLIUM_DEFAULT_DISCOVERY_CONFIG = {
    'run_vigolium_discovery': True,
    'strategy': 'balanced',
    'concurrency': 20,
    'rate_limit': 50,
    'timeout': '10s',
}

VIGOLIUM_DEFAULT_ANALYSIS_CONFIG = {
    'run_vigolium_analysis': True,
    'strategy': 'balanced',
    'concurrency': 20,
    'rate_limit': 50,
    'timeout': '10s',
}

RUN_VIGOLIUM_AUDIT = 'run_vigolium_audit'
VIGOLIUM_AUDIT = 'vigolium_audit'
VIGOLIUM_AUDIT_INTENSITY = 'intensity'
VIGOLIUM_AUDIT_USE_AI = 'use_ai'
VIGOLIUM_AUDIT_TIMEOUT = 'timeout'

VIGOLIUM_DEFAULT_AUDIT_CONFIG = {
    'run_vigolium_audit': True,
    'intensity': 'balanced',
    'use_ai': False,
    'timeout': 3600,
}

ATTACK_PATH_MODELING = 'attack_path_modeling'
ATTACK_PATH_MODELING_DEFAULT_CONFIG = {
    'enabled': True,
    'top_n': 5
}



###############################################################################
# Scan DEFAULTS
###############################################################################

LIVE_SCAN = 1
SCHEDULED_SCAN = 0
MONITORING_SCAN = 2

DEFAULT_SCAN_INTENSITY = 'normal'

###############################################################################
# Tools DEFAULTS
###############################################################################

# amass
AMASS_DEFAULT_WORDLIST_PATH = (
    'wordlist/default_wordlist/deepmagic.com-prefixes-top50000.txt'
)

# dorks
DORKS_DEFAULT_NAMES = [
    'stackoverflow',
    '3rdparty',
    'social_media',
    'project_management',
    'code_sharing',
    'config_files',
    'jenkins',
    'cloud_buckets',
    'php_error',
    'exposed_documents',
    'struts_rce',
    'db_files',
    'traefik',
    'git_exposed'
]

# ffuf
FFUF_DEFAULT_WORDLIST_PATH = '/usr/src/wordlist/raft-large-directories.txt'
FFUF_DEFAULT_MATCH_HTTP_STATUS = [200, 204, 301, 302, 307, 401, 403, 405]
FFUF_DEFAULT_RECURSIVE_LEVEL = 2
FFUF_DEFAULT_FOLLOW_REDIRECT = False

# naabu
NAABU_DEFAULT_PORTS = ['top-100']

# nuclei
NUCLEI_DEFAULT_TEMPLATES_PATH = '/root/nuclei-templates'
NUCLEI_SEVERITY_MAP = {
    'info': 0,
    'low': 1,
    'medium': 2,
    'high': 3,
    'critical': 4,
    'unknown': -1,
}
NUCLEI_REVERSE_SEVERITY_MAP = {v: k for k, v in NUCLEI_SEVERITY_MAP.items()}
NUCLEI_DEFAULT_SEVERITIES = list(NUCLEI_SEVERITY_MAP.keys())

# semgrep
SEMGREP_SEVERITY_MAP = {
    'INFO': 0,
    'WARNING': 2,
    'ERROR': 3,
}



# s3scanner
S3SCANNER_DEFAULT_PROVIDERS = ['gcp', 'aws', 'digitalocean', 'dreamhost', 'linode']

# dalfox
DALFOX_SEVERITY_MAP = {
    'Low': 1,
    'Medium': 2,
    'High': 3,
    'unknown': -1,
}

# osint
OSINT_DEFAULT_LOOKUPS = ['emails', 'metainfo', 'employees']
OSINT_DEFAULT_DORKS = [
    'stackoverflow',
    '3rdparty',
    'social_media',
    'project_management',
    'code_sharing',
    'config_files',
    'jenkins',
    'wordpress_files',
    'cloud_buckets',
    'php_error',
    'exposed_documents',
    'struts_rce',
    'db_files',
    'traefik',
    'git_exposed',
]

# Arjun
ARJUN_DEFAULT_METHODS = 'GET,POST,JSON,XML,FETCH,PUT,DELETE,PATCH'
OSINT_DEFAULT_CONFIG = {
    'discover': OSINT_DEFAULT_LOOKUPS,
    'dork': OSINT_DEFAULT_DORKS,
    'leaks_and_secrets': {
        'leaklookup': True,
        'gitleaks': True,
        'trufflehog': True,
    }
}

# subdomain scan
SUBDOMAIN_SCAN_DEFAULT_TOOLS = ['subfinder', 'ctfr', 'sublist3r', 'tlsx', 'baddns']

# endpoints scan
ENDPOINT_SCAN_DEFAULT_TOOLS = ['gospider']
ENDPOINT_SCAN_DEFAULT_DUPLICATE_FIELDS = ['content_length', 'page_title']


###############################################################################
# Logger DEFINITIONS
###############################################################################

CONFIG_FILE_NOT_FOUND = 'Config file not found'

###############################################################################
# Preferences DEFINITIONS
###############################################################################

SMALL = '100px'
MEDIM = '200px'
LARGE = '400px'
XLARGE = '500px'

# Discord message colors
DISCORD_INFO_COLOR = '0xfbbc00' # yellow
DISCORD_WARNING_COLOR = '0xf75b00' # orange
DISCORD_ERROR_COLOR = '0xf70000'
DISCORD_SUCCESS_COLOR = '0x00ff78'
DISCORD_SEVERITY_COLORS = {
    'info': DISCORD_INFO_COLOR,
    'warning': DISCORD_WARNING_COLOR,
    'error': DISCORD_ERROR_COLOR,
    'aborted': DISCORD_ERROR_COLOR,
    'success': DISCORD_SUCCESS_COLOR
}

STATUS_TO_SEVERITIES = {
    'RUNNING': 'info',
    'SUCCESS': 'success',
    'FAILED': 'error',
    'ABORTED': 'error',
    'PARTIALLY COMPLETE': 'warning'
}

###############################################################################
# Interesting Subdomain DEFINITIONS
###############################################################################
MATCHED_SUBDOMAIN = 'Subdomain'
MATCHED_PAGE_TITLE = 'Page Title'

###############################################################################
# Celery Task Status CODES
###############################################################################
INITIATED_TASK = -1
FAILED_TASK = 0
RUNNING_TASK = 1
SUCCESS_TASK = 2
ABORTED_TASK = 3
PARTIALLY_COMPLETE_TASK = 4
PAUSED_TASK = 5

CELERY_TASK_STATUS_MAP = {
    INITIATED_TASK: 'INITITATED',
    FAILED_TASK: 'FAILED',
    RUNNING_TASK: 'RUNNING',
    SUCCESS_TASK: 'SUCCESS',
    ABORTED_TASK: 'ABORTED',
    PARTIALLY_COMPLETE_TASK: 'PARTIALLY COMPLETE',
    PAUSED_TASK: 'PAUSED'
}

TASK_STATUSES = (
    (INITIATED_TASK, INITIATED_TASK),
    (FAILED_TASK, FAILED_TASK),
    (RUNNING_TASK, RUNNING_TASK),
    (SUCCESS_TASK, SUCCESS_TASK),
    (ABORTED_TASK, ABORTED_TASK),
    (PARTIALLY_COMPLETE_TASK, PARTIALLY_COMPLETE_TASK),
    (PAUSED_TASK, PAUSED_TASK)
)
CELERY_TASK_STATUSES = TASK_STATUSES  # deprecated alias — remove after all references updated
DYNAMIC_ID = -1

###############################################################################
# Uncommon Ports
# Source: https://github.com/six2dez/reconftw/blob/main/reconftw.cfg
###############################################################################
UNCOMMON_WEB_PORTS = [
    81,
    300,
    591,
    593,
    832,
    981,
    1010,
    1311,
    1099,
    2082,
    2095,
    2096,
    2480,
    3000,
    3128,
    3333,
    4243,
    4567,
    4711,
    4712,
    4993,
    5000,
    5104,
    5108,
    5280,
    5281,
    5601,
    5800,
    6543,
    7000,
    7001,
    7396,
    7474,
    8000,
    8001,
    8008,
    8014,
    8042,
    8060,
    8069,
    8080,
    8081,
    8083,
    8088,
    8090,
    8091,
    8095,
    8118,
    8123,
    8172,
    8181,
    8222,
    8243,
    8280,
    8281,
    8333,
    8337,
    8443,
    8500,
    8834,
    8880,
    8888,
    8983,
    9000,
    9001,
    9043,
    9060,
    9080,
    9090,
    9091,
    9200,
    9443,
    9502,
    9800,
    9981,
    10000,
    10250,
    11371,
    12443,
    15672,
    16080,
    17778,
    18091,
    18092,
    20720,
    32000,
    55440,
    55672,
]

###############################################################################
# WHOIS DEFINITIONS
# IGNORE_WHOIS_RELATED_KEYWORD: To ignore and disable finding generic related domains
###############################################################################

IGNORE_WHOIS_RELATED_KEYWORD = [
    'Registration Private',
    'Domains By Proxy Llc',
    'Redacted For Privacy',
    'Digital Privacy Corporation',
    'Private Registrant',
    'Domain Administrator',
    'Administrator',
]


# Default FETCH URL params
DEFAULT_IGNORE_FILE_EXTENSIONS = [
    'png',
    'jpg',
    'jpeg',
    'gif',
    'mp4',
    'mpeg',
    'mp3',
]

DEFAULT_GF_PATTERNS = [
    'debug_logic',
    'idor',
    'interestingEXT',
    'interestingparams',
    'interestingsubs',
    'lfi',
    'rce',
    'redirect',
    'sqli',
    'ssrf',
    'ssti',
    'xss'
]


# Default Dir File Fuzz Params
DEFAULT_DIR_FILE_FUZZ_EXTENSIONS =  [
    '.html',
    '.php',
    '.git',
    '.yaml',
    '.conf',
    '.cnf',
    '.config',
    '.gz',
    '.env',
    '.log',
    '.db',
    '.mysql',
    '.bak',
    '.asp',
    '.aspx',
    '.txt',
    '.conf',
    '.sql',
    '.json',
    '.yml',
    '.pdf',
]

# Default Excluded Paths during Initate Scan
# Mostly static files and directories
DEFAULT_EXCLUDED_PATHS = [
    # Static assets (using regex patterns)
    '/static/.*',
    '/assets/.*',
    '/css/.*',
    '/js/.*',
    '/images/.*',
    '/img/.*',
    '/fonts/.*',

    # File types (using regex patterns)
    r'.*\.ico',
]

# Roles and Permissions
PERM_MODIFY_SYSTEM_CONFIGURATIONS = 'modify_system_configurations'
PERM_MODIFY_SCAN_CONFIGURATIONS = 'modify_scan_configurations'
PERM_MODIFY_TARGETS = 'modify_targets' # projects and targets
PERM_MODIFY_SCAN_RESULTS = 'modify_scan_results'
PERM_MODIFY_WORDLISTS = 'modify_wordlists'
PERM_MODIFY_INTERESTING_LOOKUP = 'modify_interesting_lookup'
PERM_MODIFY_SCAN_REPORT = 'modify_scan_report'
PERM_INITATE_SCANS_SUBSCANS = 'initiate_scans_subscans'

# 404 page url
FOUR_OH_FOUR_URL = '/404/'


###############################################################################
# OLLAMA DEFINITIONS
###############################################################################

# LLM Providers
OLLAMA = 'ollama'
OPENAI = 'openai'
ANTHROPIC = 'anthropic'
GEMINI = 'gemini'

SUGGESTED_OLLAMA_MODELS = [
    {
        'name': 'llama3',
        'expertise': 'General Summarization & Reasoning',
        'size': '4.7GB',
        'suggested_ram': '8GB+',
        'description': 'Latest general purpose model from Meta, excellent for distilling complex security findings into summaries.'
    },
    {
        'name': 'mistral',
        'expertise': 'Efficient Context Analysis',
        'size': '4.1GB',
        'suggested_ram': '8GB+',
        'description': 'Highly efficient model known for its performance-to-size ratio, great for fast report generation.'
    },
    {
        'name': 'codellama',
        'expertise': 'Code & Exploit Analysis',
        'size': '3.8GB',
        'suggested_ram': '8GB+',
        'description': 'Optimized for code-related tasks; helps in explaining vulnerable code snippets and remediation steps.'
    },
    {
        'name': 'phi3',
        'expertise': 'Lightweight Summarization',
        'size': '2.3GB',
        'suggested_ram': '4GB+',
        'description': 'Microsoft\'s lightweight model, perfect for environments with limited resources.'
    },
    {
        'name': 'deepseek-coder',
        'expertise': 'Vulnerability Pattern Matching',
        'size': '4.5GB',
        'suggested_ram': '8GB+',
        'description': 'Trained on high-quality code, helpful for summarizing complex vulnerability patterns.'
    }
]

OLLAMA_INSTANCE = 'http://ollama:11434'

DEFAULT_GPT_MODELS = [
    {
        'name': 'gpt-3',
        'model': 'gpt-3',
        'modified_at': '',
        'details': {
            'family': 'GPT',
            'parameter_size': '~175B',
        }
    },
    {
        'name': 'gpt-3.5-turbo',
        'model': 'gpt-3.5-turbo',
        'modified_at': '',
        'details': {
            'family': 'GPT',
            'parameter_size': '~7B',
        }
    },
    {
        'name': 'gpt-4',
        'model': 'gpt-4',
        'modified_at': '',
        'details': {
            'family': 'GPT',
            'parameter_size': '~1.7T',
        }
    },
    {
        'name': 'gpt-4-turbo',
        'model': 'gpt-4',
        'modified_at': '',
        'details': {
            'family': 'GPT',
            'parameter_size': '~1.7T',
        }
    }
]



# GPT Vulnerability Report Generator
VULNERABILITY_DESCRIPTION_SYSTEM_MESSAGE = """
You are an expert penetration tester who has just completed a comprehensive security assessment. Based on the provided vulnerability title, vulnerable URL, and vulnerability description, your task is to generate a detailed, technical penetration testing report in plain text format.
Your task is to generate a detailed, technical penetration testing report. This report should offer an in-depth analysis of the discovered vulnerabilities, adhering to industry best practices and standards.

The output should adhere to the following structure:

Description:
A comprehensive explanation of the vulnerability, including: Detailed technical analysis, Associated CVE IDs (if any), Related known vulnerabilities, Exploitation methods

Impact:
A thorough assessment of the vulnerability's potential impact on web applications, including: Data confidentiality breaches, System integrity compromises, Service availability disruptions, Potential for further exploitation

Remediation:
A prioritized list of specific, actionable steps to address the vulnerability, such as: Code modifications, Configuration changes, Security patch applications, Implementation of security controls

References:
Relevant, authoritative sources supporting your analysis, such as: Official CVE database entries, Vendor security advisories, Respected security research publications, Applicable industry standards or guidelines


Ensure that:
1. Each section (Description, Impact, Remediation, References) is separated by ONLY ONE blank line and no multiple new lines. The content must be immediately after the section title.
2. Do not make title as bold, italic or underline. It must be Title ending with a colon. Example: Description:
3. All URLs in the 'references' section begin with 'http://' or 'https://'.
4. Remediation steps should be specific and actionable and should not contain any ambiguous or general recommendations.
5. Refrain from including any personal opinions or subjective assessments in your report.
"""


ATTACK_SUGGESTION_GPT_SYSTEM_PROMPT = """
    You are a highly skilled penetration tester who has recently completed a reconnaissance on a target.
    As a penetration tester, you've conducted a thorough reconnaissance on a specific subdomain.
    Based on the reconnaissance you will be given with a
        - Subdomain Name
        - Subdomain Page Title
        - Open Ports if any detected
        - HTTP Status
        - Technologies Detected
        - Content Type
        - Web Server
        - Page Content Length
    I'm seeking insights into potential technical web application attacks that could be executed on this subdomain, along with explanations for why these attacks are feasible given the discovered information.
    Please provide a detailed list of these attack types and their underlying technical rationales on every attacks you suggested.
    Also suggest if any CVE ID, known exploits, existing vulnerabilities, any news articles URL related to the information provided to you.
"""


LLM_REPORT_OVERVIEW_SYSTEM_PROMPT = """
You are an expert penetration tester. Based on the provided assessment data, write a professional 'Overview' section for a security assessment report.
The overview should provide a high-level summary of the assessment's scope, objectives, and key findings.
Ensure the tone is technical yet accessible to project managers.

FORMATTING REQUIREMENTS:
1. Use clean and structured Markdown formatting. The output will be compiled directly to HTML, so proper Markdown tags must be used.
2. Structure the "Key Findings" and detailed vulnerability areas/attributes as bulleted lists using `-` or `*` on separate lines.
3. Ensure there is a blank line before starting any list, and a blank line between list items or major points to allow the markdown parser to render lists correctly.
4. Use bold text (e.g., **Key Findings:**, **Severity Distribution:**, **Notable Insights:**, etc.) to label items and structure findings clearly.
5. Avoid using markdown headers like # or ##. Use bold text for emphasis instead.
6. CRITICAL: Do NOT output findings as a continuous line/paragraph separated by hyphens (e.g. "Key findings - Finding 1 - Finding 2..."). Each finding must be a separate, clean bullet point.
7. CRITICAL: Do NOT include any sign-offs, signatures, or placeholders like 'Sincerely', '[Your Name]', or '[Company Name]' at the end.
"""

LLM_REPORT_EXECUTIVE_BRIEF_SYSTEM_PROMPT = """
You are an expert penetration tester. Based on the provided assessment data, write a professional 'Executive Brief' section for a security assessment report.
The executive brief should be concise and aimed at non-technical stakeholders (CTOs, CEOs), highlighting the overall risk posture and the most critical findings.

FORMATTING REQUIREMENTS:
1. Use clean and structured Markdown formatting. The output will be compiled directly to HTML, so proper Markdown tags must be used.
2. Use clear paragraphs separated by a blank line (double newlines).
3. If highlighting specific key risks or recommendations, organize them as a clean bulleted list using `-` or `*` on separate lines with a blank line before starting the list.
4. Avoid using markdown headers like # or ##. Use bold text for emphasis instead.
5. CRITICAL: Do NOT include any sign-offs, signatures, or placeholders like 'Sincerely', '[Your Name]', '[Company Name]', or 'Penetration Testing Expert' at the end. The text should end immediately after the final paragraph of the brief.
"""

LLM_REPORT_CONCLUSION_SYSTEM_PROMPT = """
You are an expert penetration tester. Based on the provided assessment data, write a professional 'Conclusion' section for a security assessment report.
The conclusion should wrap up the assessment, provide final thoughts on the security posture of the target, and emphasize the importance of remediation.

FORMATTING REQUIREMENTS:
1. Use clean and structured Markdown formatting. The output will be compiled directly to HTML, so proper Markdown tags must be used.
2. Use clear paragraphs separated by a blank line (double newlines).
3. Organize remediation priorities or key takeaways as a clean bulleted list using `-` or `*` on separate lines.
4. Avoid using markdown headers like # or ##. Use bold text for emphasis instead.
5. CRITICAL: Do NOT include any sign-offs, signatures, or placeholders like 'Sincerely', '[Your Name]', or '[Company Name]' at the end.
"""

LLM_ATTACK_SCENARIO_SYSTEM_PROMPT = """
You are an expert penetration tester. You are provided with a vulnerability that has a known exploit.
Your task is to describe a realistic attack scenario where an attacker leverages this vulnerability to compromise the system or achieve a specific impact.
Explain the steps an attacker might take, the tools they might use, and the potential outcome (e.g., data theft, system takeover, etc.).
Ensure the tone is technical, professional, and objective.
Avoid using markdown headers like # or ##. Use bold text for emphasis if needed.
CRITICAL: Do NOT include any sign-offs, signatures, or placeholders.
"""

LLM_IMPACT_ASSESSMENT_SYSTEM_PROMPT = """
You are an expert Cyber Risk Strategist. Your task is to analyze a security finding and describe its potential business impact.
Instead of focusing on specific threat actors, focus on the **Potential Attack Chain** (the sequence of technical steps an attacker would likely take to pivot or escalate) and the **Business Impact**.
Describe how this vulnerability fits into a broader attack path (e.g., Initial Access -> Lateral Movement -> Data Exfiltration).
Provide a prioritized list of business consequences.
Format the response clearly with sections for 'Potential Attack Chain' and 'Impact Summary'.
"""


CWE_INFO_SYSTEM_PROMPT = """
You are an expert application security engineer. Given a CWE (Common Weakness Enumeration) identifier, provide a concise but thorough security reference in JSON format.

Return ONLY valid JSON with these exact keys:
{
  "name": "short CWE name (e.g. Cross-Site Scripting)",
  "description": "2-3 sentence technical description of the weakness",
  "impact": "1-2 sentence description of the security impact to systems and data",
  "remediation": "2-3 concrete, actionable remediation steps as a single string",
  "examples": ["brief real-world example 1", "brief real-world example 2"],
  "severity": "Critical|High|Medium|Low"
}

Be precise and technical. Do not include markdown, code blocks, or any text outside the JSON object.
"""


# OSINT GooFuzz Path
GOFUZZ_EXEC_PATH = '/usr/src/github/goofuzz/GooFuzz'

# Auth Brute-Force Paths
BRUTUS_EXEC_PATH = '/usr/local/bin/brutus'
REACT2SHELL_PATH = '/usr/src/github/react2shell-scanner/scanner.py'
PROXYCHAINS_EXEC_PATH = '/usr/bin/proxychains4'
AUTH_WORDLIST_PATH = '/usr/src/wordlist/auth'
DEFAULT_AUTH_USER_WORDLIST = 'top_default_usernames.txt'
DEFAULT_AUTH_PASS_WORDLIST = 'top_default_passwords.txt'
COMPREHENSIVE_USER_WORDLIST = 'most_common_usernames.txt'
COMPREHENSIVE_PASS_WORDLIST = 'most_common_passwords.txt'


# In App Notification Definitions
SYSTEM_LEVEL_NOTIFICATION = 'system'
PROJECT_LEVEL_NOTIFICATION = 'project'
NOTIFICATION_TYPES = (
    ('system', SYSTEM_LEVEL_NOTIFICATION),
    ('project', PROJECT_LEVEL_NOTIFICATION),
)
NOTIFICATION_STATUS_TYPES = (
    ('success', 'Success'),
    ('info', 'Informational'),
    ('warning', 'Warning'),
    ('error', 'Error'),
)

# Bountyhub Definitions
HACKERONE_ALLOWED_ASSET_TYPES = ["WILDCARD", "DOMAIN", "IP_ADDRESS", "URL"]

# ---------------------------------------------------------------------------
# Target type constants — used by Domain.target_type and target_router.py
# ---------------------------------------------------------------------------
TARGET_TYPE_DOMAIN = 'domain'
TARGET_TYPE_HOST = 'host'
TARGET_TYPE_SUBDOMAIN = 'subdomain'
TARGET_TYPE_URL = 'url'
TARGET_TYPE_IP = 'ip'
TARGET_TYPE_CIDR = 'cidr'
TARGET_TYPE_EMAIL = 'email'
TARGET_TYPE_USERNAME = 'username'
TARGET_TYPE_PHONE = 'phone'
TARGET_TYPE_CRYPTO_ADDRESS = 'crypto_address'
TARGET_TYPE_CODE_PATH = 'code_path'

TARGET_TYPE_CHOICES = [
    (TARGET_TYPE_DOMAIN, 'Domain'),
    (TARGET_TYPE_HOST, 'Host'),
    (TARGET_TYPE_SUBDOMAIN, 'Subdomain'),
    (TARGET_TYPE_URL, 'URL'),
    (TARGET_TYPE_IP, 'IP Address'),
    (TARGET_TYPE_CIDR, 'CIDR Range'),
    (TARGET_TYPE_EMAIL, 'Email Address'),
    (TARGET_TYPE_USERNAME, 'Username'),
    (TARGET_TYPE_PHONE, 'Phone Number'),
    (TARGET_TYPE_CRYPTO_ADDRESS, 'Crypto Address'),
    (TARGET_TYPE_CODE_PATH, 'Code Path / Repository'),
]