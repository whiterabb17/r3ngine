import environ

env = environ.FileAwareEnv()

import mimetypes
import os
import reNgine.patches

from reNgine.init import first_run
from reNgine.utilities import RengineTaskFormatter

mimetypes.add_type("text/javascript", ".js", True)
mimetypes.add_type("text/css", ".css", True)

# !!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!
#       RENGINE CONFIGURATIONS
# !!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

# Take environment variables from .env file
environ.Env.read_env(os.path.join(BASE_DIR, os.pardir, '.env'))

# Root env vars
RENGINE_HOME = env('RENGINE_HOME', default='/usr/src/app')
RENGINE_RESULTS = env('RENGINE_RESULTS', default='/usr/src/scan_results')
RENGINE_CACHE_ENABLED = env.bool('RENGINE_CACHE_ENABLED', default=False)
RENGINE_RECORD_ENABLED = env.bool('RENGINE_RECORD_ENABLED', default=True)
RENGINE_RAISE_ON_ERROR = env.bool('RENGINE_RAISE_ON_ERROR', default=False)
RENGINE_APME_ENABLED = env.bool('RENGINE_APME_ENABLED', default=True)

# Common env vars
DEBUG = env.bool('DEBUG', default=False)
DOMAIN_NAME = env('DOMAIN_NAME', default='localhost:8000')
TEMPLATE_DEBUG = env.bool('TEMPLATE_DEBUG', default=False)
SECRET_FILE = os.path.join(RENGINE_HOME, 'secret')
DEFAULT_ENABLE_HTTP_CRAWL = env.bool('DEFAULT_ENABLE_HTTP_CRAWL', default=True)
DEFAULT_RATE_LIMIT = env.int('DEFAULT_RATE_LIMIT', default=150) # requests / second
DEFAULT_HTTP_TIMEOUT = env.int('DEFAULT_HTTP_TIMEOUT', default=5) # seconds
DEFAULT_RETRIES = env.int('DEFAULT_RETRIES', default=1)
DEFAULT_THREADS = env.int('DEFAULT_THREADS', default=30)
DEFAULT_GET_GPT_REPORT = env.bool('DEFAULT_GET_GPT_REPORT', default=True)

# Acunetix (AWVS) Configuration
ACUNETIX_POLL_INTERVAL = env.int('ACUNETIX_POLL_INTERVAL', default=30)  # seconds
ACUNETIX_MAX_RETRIES = env.int('ACUNETIX_MAX_RETRIES', default=720)     # 12 hours
ACUNETIX_REQUEST_TIMEOUT = env.int('ACUNETIX_REQUEST_TIMEOUT', default=30)  # seconds
VITE_DEV_SERVER_URL = env('VITE_DEV_SERVER_URL', default='https://localhost:5173')
VITE_ENABLED = env.bool('VITE_ENABLED', default=DEBUG)

# Neo4j Configurations — NEO4J_PASSWORD must be set via environment variable
NEO4J_URI = env('NEO4J_URI', default='bolt://neo4j:7687')
NEO4J_USER = env('NEO4J_USER', default='neo4j')
NEO4J_PASSWORD = env('NEO4J_PASSWORD', default='')

# ALLOWED_HOSTS is driven by environment variable.
# In production set ALLOWED_HOSTS=your.domain.com,other.host in the environment.
# The DOMAIN_NAME block below additionally appends the configured domain host at startup.
ALLOWED_HOSTS = env.list('ALLOWED_HOSTS', default=['localhost', '127.0.0.1', 'web', 'nginx'])


# Automatically extract host from DOMAIN_NAME and add it to ALLOWED_HOSTS
# to ensure out-of-the-box support for the configured domain name.
if DOMAIN_NAME:
    # Strip protocol if present (e.g. http:// or https://)
    domain_clean = DOMAIN_NAME
    if '://' in domain_clean:
        domain_clean = domain_clean.split('://')[1]
    # Strip port if present (e.g. :8000)
    domain_host = domain_clean.split(':')[0]
    if domain_host and domain_host not in ALLOWED_HOSTS:
        ALLOWED_HOSTS.append(domain_host)


SECRET_KEY = first_run(SECRET_FILE, BASE_DIR)

# Rengine version
# reads current version from a file called .version
VERSION_FILE = os.path.join(BASE_DIR, '.version')
if os.path.exists(VERSION_FILE):
    with open(VERSION_FILE, 'r') as f:
        _version = f.read().strip()
else:
    _version = 'unknown'

# removes v from _version if exists
if _version.startswith('v'):
    _version = _version[1:]

RENGINE_CURRENT_VERSION = _version

# Databases
DATABASES = {
    'default': {
        'ENGINE': 'django.db.backends.postgresql',
        'NAME': env('POSTGRES_DB'),
        'USER': env('POSTGRES_USER'),
        'PASSWORD': env('POSTGRES_PASSWORD'),
        'HOST': env('POSTGRES_HOST'),
        'PORT': env('POSTGRES_PORT'),
        'CONN_MAX_AGE': 0,
        'CONN_HEALTH_CHECKS': True,
        'OPTIONS': {
            'sslmode': env('POSTGRES_SSLMODE', default='prefer'),
            'sslrootcert': os.path.join(BASE_DIR, 'ca.crt'),
        }
    }
}

# Application definition
INSTALLED_APPS = [
    'django.contrib.admin',
    'django.contrib.auth',
    'django.contrib.contenttypes',
    'django.contrib.sessions',
    'django.contrib.messages',
    'django.contrib.staticfiles',
    'django.contrib.humanize',
    'rest_framework',
    'rest_framework_datatables',
    'dashboard.apps.DashboardConfig',
    'targetApp.apps.TargetappConfig',
    'scanEngine.apps.ScanengineConfig',
    'startScan.apps.StartscanConfig',
    'recon_note.apps.ReconNoteConfig',
    'django_ace',
    'mathfilters',
    'drf_yasg',
    'rolepermissions',
    'plugins.apps.PluginsConfig',
    'apme.apps.ApmeConfig',
    'channels',
    'rest_framework_simplejwt',
    'rest_framework_simplejwt.token_blacklist',
    'corsheaders',
]

# Dynamically add enabled plugins to INSTALLED_APPS
PLUGINS_DIR = os.path.join(BASE_DIR, 'plugins_data')
if os.path.exists(PLUGINS_DIR):
    # Ensure plugins_data is a python package
    init_file = os.path.join(PLUGINS_DIR, '__init__.py')
    if not os.path.exists(init_file):
        try:
            with open(init_file, 'w') as f:
                pass
        except IOError:
            pass

    for item in os.listdir(PLUGINS_DIR):
        plugin_path = os.path.join(PLUGINS_DIR, item)
        if os.path.isdir(plugin_path) and not item.startswith('.'):
            backend_dir = os.path.join(plugin_path, 'backend')
            if os.path.exists(backend_dir) and os.path.isdir(backend_dir):
                # Ensure plugin_slug and backend have __init__.py
                for d in [plugin_path, backend_dir]:
                    init_f = os.path.join(d, '__init__.py')
                    if not os.path.exists(init_f):
                        try:
                            with open(init_f, 'w') as f:
                                pass
                        except IOError:
                            pass
                
                app_module = f"plugins_data.{item}.backend"
                if app_module not in INSTALLED_APPS:
                    INSTALLED_APPS.append(app_module)

MIDDLEWARE = [
    'django.middleware.security.SecurityMiddleware',
    'reNgine.middleware.ContentSecurityPolicyMiddleware',
    'reNgine.middleware.SystemVersionMiddleware',
    'corsheaders.middleware.CorsMiddleware',
    'django.contrib.sessions.middleware.SessionMiddleware',
    'django.middleware.common.CommonMiddleware',
    'django.middleware.csrf.CsrfViewMiddleware',
    'django.contrib.auth.middleware.AuthenticationMiddleware',
    'reNgine.middleware.LoginRequiredMiddleware',
    'django.contrib.messages.middleware.MessageMiddleware',
    'django.middleware.clickjacking.XFrameOptionsMiddleware',
    'reNgine.middleware.UserPreferencesMiddleware',
]
TEMPLATES = [
    {
        'BACKEND': 'django.template.backends.django.DjangoTemplates',
        'DIRS': [
            os.path.join(BASE_DIR, 'templates'),
        ],
        'APP_DIRS': True,
        'OPTIONS': {
            'context_processors': [
                'django.template.context_processors.debug',
                'django.template.context_processors.request',
                'django.contrib.auth.context_processors.auth',
                'django.contrib.messages.context_processors.messages',
                'reNgine.context_processors.projects',
                'reNgine.context_processors.version_context',
                'reNgine.context_processors.user_preferences',
                'reNgine.context_processors.vite_settings',
            ],
    },
}]
ROOT_URLCONF = 'reNgine.urls'
REST_FRAMEWORK = {
    'DEFAULT_RENDERER_CLASSES': (
        'rest_framework.renderers.JSONRenderer',
        'rest_framework.renderers.BrowsableAPIRenderer',
        'rest_framework_datatables.renderers.DatatablesRenderer',
    ),
    'DEFAULT_FILTER_BACKENDS': (
        'rest_framework_datatables.filters.DatatablesFilterBackend',
    ),
    'DEFAULT_PAGINATION_CLASS': 'rest_framework_datatables.pagination.DatatablesPageNumberPagination',
    'PAGE_SIZE': 500,
    'DEFAULT_THROTTLE_CLASSES': [
        'rest_framework.throttling.AnonRateThrottle',
        'rest_framework.throttling.UserRateThrottle',
    ],
    'DEFAULT_THROTTLE_RATES': {
        'anon': '5/min',
        'user': '200/min',
        'auth': '5/min',
    },
    'DEFAULT_AUTHENTICATION_CLASSES': (
        'rest_framework_simplejwt.authentication.JWTAuthentication',
        'rest_framework.authentication.SessionAuthentication',
    ),
    'DEFAULT_PERMISSION_CLASSES': (
        'rest_framework.permissions.IsAuthenticated',
    ),
}

SWAGGER_SETTINGS = {
    'DEFAULT_INFO': 'reNgine.openapi_info.info',
    'SECURITY_DEFINITIONS': {
        'Bearer': {
            'type': 'apiKey',
            'name': 'Authorization',
            'in': 'header',
            'description': 'JWT token — prefix with "Bearer ": `Bearer <token>`',
        }
    },
    'USE_SESSION_AUTH': True,
    'LOGIN_URL': '/login/',
    'LOGOUT_URL': '/logout/',
}
WSGI_APPLICATION = 'reNgine.wsgi.application'
ASGI_APPLICATION = 'reNgine.routing.application'

CHANNEL_LAYERS = {
    'default': {
        'BACKEND': 'channels_redis.core.RedisChannelLayer',
        'CONFIG': {
            "hosts": [os.environ.get('REDIS_URL', 'redis://redis:6379/0')],
        },
    },
}

# Password validation
# https://docs.djangoproject.com/en/2.2/ref/settings/#auth-password-validators
AUTH_PASSWORD_VALIDATORS = [
    {
        'NAME': 'django.contrib.auth.password_validation.' +
                'UserAttributeSimilarityValidator',
    },
    {
        'NAME': 'django.contrib.auth.password_validation.' +
                'MinimumLengthValidator',
    },
    {
        'NAME': 'django.contrib.auth.password_validation.' +
                'CommonPasswordValidator',
    },
    {
        'NAME': 'django.contrib.auth.password_validation.' +
                'NumericPasswordValidator',
    },
]


# Internationalization
# https://docs.djangoproject.com/en/2.2/topics/i18n/
LANGUAGE_CODE = 'en-us'
TIME_ZONE = 'UTC'
USE_I18N = True
USE_TZ = True

MEDIA_URL = '/media/'
MEDIA_ROOT = RENGINE_RESULTS
FILE_UPLOAD_MAX_MEMORY_SIZE = 100000000
FILE_UPLOAD_PERMISSIONS = 0o644
# Static files (CSS, JavaScript, Images)
# https://docs.djangoproject.com/en/2.2/howto/static-files/

STATIC_URL = '/staticfiles/'
STATIC_ROOT = os.path.join(BASE_DIR, 'staticfiles')

# Deduplicate static files sources to prevent collectstatic warnings
# and ensure the correct files are collected.
_static_dirs = [
    os.path.join(BASE_DIR, "static"),
]

# Prefer the dynamically built/mounted local frontend dist directory if it exists,
# otherwise fall back to the baked-in Docker version
_local_dist = os.path.join(env('RENGINE_HOME', default='/usr/src/app'), "frontend", "dist")
if os.path.exists(_local_dist):
    _frontend_dist = _local_dist
else:
    _frontend_dist = '/usr/src/frontend/dist'

if os.path.exists(_frontend_dist):
    _static_dirs.append(_frontend_dist)

# Use list(dict.fromkeys()) to preserve order while removing duplicates
STATICFILES_DIRS = list(dict.fromkeys(_static_dirs))

FIXTURE_DIRS = [
    os.path.join(BASE_DIR, "fixtures"),
]

LOGIN_REQUIRED_IGNORE_VIEW_NAMES = [
    'login',
    'logout',
    'onboarding',
]

LOGIN_URL = 'login'
LOGIN_REDIRECT_URL = 'onboarding'
LOGOUT_REDIRECT_URL = 'login'

# Tool Location
TOOL_LOCATION = '/usr/src/app/tools/'

# Number of endpoints that have the same content_length
DELETE_DUPLICATES_THRESHOLD = 10

import urllib.parse
REDIS_URL = os.environ.get('REDIS_URL', 'redis://redis:6379/0')
_parsed_redis = urllib.parse.urlparse(REDIS_URL)
REDIS_HOST = _parsed_redis.hostname or 'redis'
REDIS_PORT = _parsed_redis.port or 6379
REDIS_PASSWORD = _parsed_redis.password or None
'''
ROLES and PERMISSIONS
'''
ROLEPERMISSIONS_MODULE = 'reNgine.roles'
ROLEPERMISSIONS_REDIRECT_TO_LOGIN = True

'''
Cache settings
'''
RENGINE_TASK_IGNORE_CACHE_KWARGS = ['ctx']


DEFAULT_AUTO_FIELD = 'django.db.models.BigAutoField'

'''
LOGGING settings
'''
LOGGING = {
    'version': 1,
    'disable_existing_loggers': False,
    'handlers': {
        'console': {
            'class': 'logging.StreamHandler',
            'formatter': 'brief',
        },
        'task': {
            'class': 'logging.StreamHandler',
            'formatter': 'task',
        },
        'error_file': {
            'level': 'ERROR',
            'class': 'logging.FileHandler',
            'filename': '/usr/src/app/errors.log',
            'formatter': 'verbose',
        },
        'null': {
            'class': 'logging.NullHandler',
        },
        'temporal_file': {
            'level': 'INFO',
            'class': 'logging.FileHandler',
            'filename': '/usr/src/app/temporal.log',
            'formatter': 'verbose',
        },
    },
    'formatters': {
        'verbose': {
            'format': '{levelname} {asctime} {module} {process:d} {thread:d} {message}',
            'style': '{',
        },
        'brief': {
            'format': '%(levelname)s %(asctime)s %(name)s %(message)s',
            'datefmt': '%H:%M:%S',
        },
        'task': {
            '()': lambda: RengineTaskFormatter('%(task_name)-34s | %(levelname)s | %(message)s'),
        },
    },
    'loggers': {
        # Root — catches everything not explicitly routed below
        '': {
            'handlers': ['console', 'error_file'],
            'level': 'DEBUG' if DEBUG else 'INFO',
            'propagate': False,
        },
        # Django internals — only errors to file, not console spam
        'django': {
            'handlers': ['error_file'],
            'level': 'ERROR',
            'propagate': False,
        },
        'django.server': {
            'handlers': ['console'],
            'level': 'WARNING',
            'propagate': False,
        },
        'django.db.backends': {
            'handlers': ['null'],
            'level': 'ERROR',
            'propagate': False,
        },
        # Temporal activities — write INFO+ to temporal.log; propagate to 'reNgine' for console
        'reNgine.temporal_activities': {
            'handlers': ['temporal_file'],
            'level': 'INFO',
            'propagate': True,
        },
        # Scan tasks — use the task formatter so output is easy to grep
        'reNgine.tasks': {
            'handlers': ['task', 'error_file'],
            'level': 'DEBUG' if DEBUG else 'INFO',
            'propagate': False,
        },
        # All reNgine modules — use the task formatter for consistent grep-friendly output.
        # The task formatter produces: module.funcName | LEVEL | message
        # Specific child loggers (e.g. reNgine.tasks, reNgine.temporal_activities) are
        # listed above with propagate=False to override this catch-all where needed.
        'reNgine': {
            'handlers': ['task', 'error_file'],
            'level': 'DEBUG' if DEBUG else 'INFO',
            'propagate': False,
        },
        # Plugin code
        'plugins': {
            'handlers': ['task', 'error_file'],
            'level': 'DEBUG' if DEBUG else 'INFO',
            'propagate': False,
        },
        # API views
        'api': {
            'handlers': ['console', 'error_file'],
            'level': 'DEBUG' if DEBUG else 'INFO',
            'propagate': False,
        },
        # Temporal SDK — suppress noise, only errors
        'temporalio': {
            'handlers': ['error_file'],
            'level': 'ERROR',
            'propagate': False,
        },
    },
}

'''
File upload settings
'''
DATA_UPLOAD_MAX_NUMBER_FIELDS = None

'''
    Caching Settings
'''
CACHES = {
    'default': {
        'BACKEND': 'django_redis.cache.RedisCache',
        'LOCATION': os.environ.get('REDIS_URL', 'redis://redis:6379/0'),
        'OPTIONS': {
            'CLIENT_CLASS': 'django_redis.client.DefaultClient',
        },
        'TIMEOUT': 60 * 30,
    }
}

'''
    Security Settings
    The application is served exclusively over HTTPS.
    All secure cookie and HSTS settings are permanently enabled.
'''

# Session security
SESSION_COOKIE_HTTPONLY = True
SESSION_COOKIE_SAMESITE = 'Lax'
SESSION_COOKIE_SECURE = True  # HTTPS only

# CSRF hardening
CSRF_COOKIE_HTTPONLY = False  # Must be False so JS can read the token for API calls
CSRF_COOKIE_SAMESITE = 'Lax'
CSRF_COOKIE_SECURE = True  # HTTPS only

# NOTE: Leave SECURE_SSL_REDIRECT=False — the upstream nginx reverse proxy handles
# HTTP→HTTPS redirects. Enabling this in Django would cause a redirect loop.
SECURE_SSL_REDIRECT = False
SECURE_PROXY_SSL_HEADER = ('HTTP_X_FORWARDED_PROTO', 'https')

CSRF_TRUSTED_ORIGINS = env.list('CSRF_TRUSTED_ORIGINS', default=[
    # Web frontend (dev + prod)
    'https://localhost',
    'https://127.0.0.1',
    'http://localhost:5173',
    'https://localhost:5173',
    # r3ngine-mobile — Android emulator routes host machine via 10.0.2.2
    'http://10.0.2.2',
    'http://10.0.2.2:8000',
    # r3ngine-mobile — iOS simulator and physical devices on local networks
    'http://10.0.0.0',
    'http://10.0.1.0',
    'http://192.168.0.0',
    'http://192.168.1.0',
    'http://192.168.88.0',
    # Add additional origins via CSRF_TRUSTED_ORIGINS env var, e.g.:
    # CSRF_TRUSTED_ORIGINS=http://192.168.10.5:8000,https://my.rengine.host
])


# HSTS — tell browsers to always use HTTPS for this domain (1 year)
SECURE_HSTS_SECONDS = env.int('SECURE_HSTS_SECONDS', default=31536000)
SECURE_HSTS_INCLUDE_SUBDOMAINS = env.bool('SECURE_HSTS_INCLUDE_SUBDOMAINS', default=True)
SECURE_HSTS_PRELOAD = env.bool('SECURE_HSTS_PRELOAD', default=False)  # opt-in for HSTS preload list

# Security headers
SECURE_CONTENT_TYPE_NOSNIFF = True
SECURE_BROWSER_XSS_FILTER = True
X_FRAME_OPTIONS = 'DENY'

# Referrer policy
SECURE_REFERRER_POLICY = 'strict-origin-when-cross-origin'

# Login required middleware configurations
LOGIN_REQUIRED_IGNORE_PATHS = [
    r'^/logout/',
    r'^/login/',
    r'^/api/auth/token/',
    r'^/api/auth/token/refresh/',
    r'^/mapi/auth/token/',
    r'^/mapi/auth/token/refresh/',
    r'^/mapi/.*$',
]

from datetime import timedelta
SIMPLE_JWT = {
    'ACCESS_TOKEN_LIFETIME': timedelta(minutes=60),
    'REFRESH_TOKEN_LIFETIME': timedelta(days=30),
    'ROTATE_REFRESH_TOKENS': True,
    'BLACKLIST_AFTER_ROTATION': True,
    'ALGORITHM': 'HS256',
    'SIGNING_KEY': SECRET_KEY,
    'AUTH_HEADER_TYPES': ('Bearer',),
    'USER_ID_FIELD': 'id',
    'USER_ID_CLAIM': 'user_id',
}

CORS_ALLOW_ALL_ORIGINS = False
CORS_ALLOWED_ORIGINS = env.list('CORS_ALLOWED_ORIGINS', default=['http://localhost:5173', 'http://127.0.0.1:5173', 'https://localhost:5173', 'https://127.0.0.1:5173'])
CORS_ALLOW_CREDENTIALS = True

