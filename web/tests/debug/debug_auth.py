import os
import django
import logging

# Configure basic logging to console
logging.basicConfig(level=logging.INFO)

os.environ.setdefault("DJANGO_SETTINGS_MODULE", "reNgine.settings")
django.setup()

from startScan.models import ScanHistory
from reNgine.tasks.auth_discovery import extract_auth_candidates

scan = ScanHistory.objects.get(id=3)
class MockTask:
    def __init__(self, scan):
        self.scan = scan
        self.scan_id = scan.id

task = MockTask(scan)

# Reset status of wp-login endpoints to 0
from startScan.models import EndPoint, AuthCandidate
EndPoint.objects.filter(scan_history_id=3, http_url__icontains='wp-login').update(http_status=0)

# Delete any existing auth candidates for scan 3 to ensure we see the new ones
AuthCandidate.objects.filter(scan_history_id=3).delete()

print("Starting auth form extraction for scan 3...")

from unittest.mock import patch

orig_filter = EndPoint.objects.filter
def custom_filter(*args, **kwargs):
    qs = orig_filter(*args, **kwargs)
    return qs.filter(http_url__icontains='wp-login')

# Mock HTML content for a standard WordPress login form
wp_login_html = """
<form name="loginform" id="loginform" action="https://bosmanadama.co.za/wp-login.php" method="post">
	<p>
		<label for="user_login">Username or Email Address</label>
		<input type="text" name="log" id="user_login" class="input" value="" size="20" autocapitalize="off" autocomplete="username" />
	</p>
	<p>
		<label for="user_pass">Password</label>
		<input type="password" name="pwd" id="user_pass" class="input" value="" size="20" autocomplete="current-password" />
	</p>
	<p class="forgetmenot"><label for="rememberme"><input name="rememberme" type="checkbox" id="rememberme" value="forever" /> Remember Me</label></p>
	<p class="submit">
		<input type="submit" name="wp-submit" id="wp-submit" class="button button-primary button-large" value="Log In" />
		<input type="hidden" name="redirect_to" value="https://bosmanadama.co.za/wp-admin/" />
		<input type="hidden" name="testcookie" value="1" />
	</p>
</form>
"""

class MockResponse:
    def __init__(self, status_code, text):
        self.status_code = status_code
        self.text = text

def mock_fetch(url, proxy_list, timeout=10):
    return MockResponse(200, wp_login_html), None

# Patching both the Endpoint filtering and the fetch function, and also http_crawl (to prevent background crawler calls)
with patch.object(EndPoint.objects, 'filter', side_effect=custom_filter):
    with patch('reNgine.auth_discovery_tasks._fetch_with_proxy_retry', side_effect=mock_fetch):
        with patch('reNgine.tasks.http_crawl') as mock_crawl:
            result = extract_auth_candidates(task, ctx={})
            print("http_crawl called:", mock_crawl.called)
            if mock_crawl.called:
                print("http_crawl args:", mock_crawl.call_args)

print("Done. Result:", result)

# Print any created candidates
candidates = AuthCandidate.objects.filter(scan_history_id=3)
print(f"Created {candidates.count()} candidates:")
for c in candidates:
    print(f"- Target: {c.target}, Tool: {c.source_tool}, Metadata: {c.metadata}")

# Check endpoint status in DB
eps = EndPoint.objects.filter(scan_history_id=3, http_url__icontains='wp-login')
for ep in eps:
    print(f"- Endpoint: {ep.http_url}, Status in DB: {ep.http_status}")


