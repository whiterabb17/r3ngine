import re as _re

from django.conf import settings as _settings
from django.contrib.auth.views import redirect_to_login
from dashboard.models import UserPreferences


class ContentSecurityPolicyMiddleware:
	"""Sets a Content-Security-Policy header on every response."""

	# External origins used by the application:
	# - cdn.jsdelivr.net           : flag-icons CSS/images/fonts, marked.min.js
	# - cdnjs.cloudflare.com      : highlight.js scripts and CSS (update.js)
	# - api.dicebear.com          : user avatar SVGs
	# - flagcdn.com               : country flag PNG images
	# - *.basemaps.cartocdn.com   : Leaflet dark tile layer images (GeoMap)
	# - raw.githubusercontent.com : GeoMap GeoJSON; official plugin marketplace icons
	# - fonts.googleapis.com      : Google Fonts CSS (404 page, report templates)
	# - fonts.gstatic.com         : Google Fonts woff2 files
	# - localhost:5173             : Vite HMR dev server (no-op in production)
	_CSP = (
		"default-src 'self'; "
		"script-src 'self' 'unsafe-inline' 'unsafe-eval' "
		"https://cdn.jsdelivr.net https://cdnjs.cloudflare.com https://localhost:5173; "
		"style-src 'self' 'unsafe-inline' "
		"https://cdn.jsdelivr.net https://cdnjs.cloudflare.com https://fonts.googleapis.com; "
		"img-src 'self' data: blob: "
		"https://cdn.jsdelivr.net https://api.dicebear.com https://flagcdn.com "
		"https://*.basemaps.cartocdn.com https://raw.githubusercontent.com; "
		"font-src 'self' data: https://cdn.jsdelivr.net https://fonts.gstatic.com; "
		"connect-src 'self' ws: wss: "
		"https://raw.githubusercontent.com https://localhost:5173 wss://localhost:5173; "
		"frame-ancestors 'none';"
	)

	def __init__(self, get_response):
		self.get_response = get_response

	def __call__(self, request):
		response = self.get_response(request)
		if 'Content-Security-Policy' not in response:
			response['Content-Security-Policy'] = self._CSP
		return response

class UserPreferencesMiddleware:
	def __init__(self, get_response):
		self.get_response = get_response

	def __call__(self, request):
		# print(f"DEBUG: Request {request.method} {request.path}", flush=True)
		if request.user.is_authenticated:
			from django.utils.functional import SimpleLazyObject
			request.user_preferences = SimpleLazyObject(lambda: UserPreferences.objects.get_or_create(user=request.user)[0])
		return self.get_response(request)


class LoginRequiredMiddleware:
	"""
	Drop-in replacement for the abandoned django-login-required-middleware package.
	Redirects unauthenticated users to LOGIN_URL, honouring the existing
	LOGIN_REQUIRED_IGNORE_VIEW_NAMES and LOGIN_REQUIRED_IGNORE_PATHS settings.
	"""

	def __init__(self, get_response):
		self.get_response = get_response
		self._ignore_view_names = set(
			getattr(_settings, 'LOGIN_REQUIRED_IGNORE_VIEW_NAMES', [])
		)
		self._ignore_paths = [
			_re.compile(p)
			for p in getattr(_settings, 'LOGIN_REQUIRED_IGNORE_PATHS', [])
		]

	def __call__(self, request):
		if not request.user.is_authenticated:
			resolver_match = getattr(request, 'resolver_match', None)
			if resolver_match and resolver_match.url_name in self._ignore_view_names:
				return self.get_response(request)
			for pattern in self._ignore_paths:
				if pattern.match(request.path):
					return self.get_response(request)
			return redirect_to_login(request.get_full_path())
		return self.get_response(request)


import os
from django.conf import settings

class SystemVersionMiddleware:
    """
    Middleware to inject the X-System-Version header into all HTTP responses.
    The version is read once on initialization from the web/.version file.
    """
    def __init__(self, get_response):
        self.get_response = get_response
        self.system_version = "Unknown"
        
        # Read the version from web/.version file
        version_file_path = os.path.join(settings.BASE_DIR, '.version')
        if os.path.exists(version_file_path):
            try:
                with open(version_file_path, 'r') as f:
                    self.system_version = f.read().strip()
            except OSError:
                pass  # keep "Unknown"

    def __call__(self, request):
        response = self.get_response(request)
        response['X-System-Version'] = self.system_version
        
        # Also expose the header to the frontend via CORS if needed
        # (Useful if the frontend is making cross-origin requests)
        expose_headers = response.get('Access-Control-Expose-Headers', '')
        if 'X-System-Version' not in expose_headers:
            if expose_headers:
                response['Access-Control-Expose-Headers'] = f"{expose_headers}, X-System-Version"
            else:
                response['Access-Control-Expose-Headers'] = "X-System-Version"
                
        return response


from channels.db import database_sync_to_async
from django.contrib.auth.models import AnonymousUser
from rest_framework_simplejwt.exceptions import TokenError
from rest_framework_simplejwt.tokens import AccessToken
from django.contrib.auth import get_user_model
import urllib.parse

@database_sync_to_async
def get_user_from_token(token_string):
    """
    Authenticate a user from a JWT token string.
    
    Args:
        token_string (str): The raw JWT token.
        
    Returns:
        User/AnonymousUser: The authenticated user or AnonymousUser.
    """
    User = get_user_model()
    try:
        token = AccessToken(token_string)
        user_id = token.payload.get('user_id')
        if user_id:
            # Same rule as DRF's JWTAuthentication: a deactivated account keeps
            # no access through a token issued before it was disabled.
            return User.objects.get(id=user_id, is_active=True)
    except (TokenError, User.DoesNotExist):
        # Invalid/expired token or unknown user: stay anonymous (fail closed).
        pass
    return AnonymousUser()


class JWTAuthMiddleware:
    """
    Middleware for Django Channels to authenticate WebSocket connections
    using JWT access tokens passed via query parameters or headers.
    """
    def __init__(self, inner):
        self.inner = inner

    async def __call__(self, scope, receive, send):
        # Only authenticate if not already authenticated by session middleware
        user = scope.get('user')
        if not user or not user.is_authenticated:
            scope['user'] = AnonymousUser()

            # 1. Check query parameters (e.g. ?token=...)
            query_string = scope.get('query_string', b'').decode('utf-8')
            query_params = urllib.parse.parse_qs(query_string)
            token_string = query_params.get('token', [None])[0]

            # 2. Check Authorization header (e.g. Authorization: Bearer ...)
            if not token_string:
                headers = dict(scope.get('headers', []))
                auth_header = headers.get(b'authorization', b'').decode('utf-8')
                if auth_header.startswith('Bearer '):
                    token_string = auth_header.split(' ')[1]

            # Resolve the token to a user
            if token_string:
                scope['user'] = await get_user_from_token(token_string)

        return await self.inner(scope, receive, send)

