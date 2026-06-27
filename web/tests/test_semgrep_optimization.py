from django.test import TestCase
from reNgine.tasks import clean_and_validate_url

class SemgrepOptimizationTests(TestCase):
	"""Test suite for verifying Semgrep scan URL cleaning and domain scoping optimizations.
	"""

	def test_clean_and_validate_url_valid(self):
		"""Test clean_and_validate_url with valid, clean URLs.
		"""
		url = "https://sub.target.com/assets/main.js"
		result = clean_and_validate_url(url, base_domain="target.com")
		self.assertEqual(result, "https://sub.target.com/assets/main.js")

	def test_clean_and_validate_url_with_gospider_metadata(self):
		"""Test clean_and_validate_url with trailing metadata from gospider.
		"""
		url = "http://target.com/wp-includes/js/jquery/jquery.min.js?ver=3.7.1] - text/html"
		result = clean_and_validate_url(url, base_domain="target.com")
		self.assertEqual(result, "http://target.com/wp-includes/js/jquery/jquery.min.js?ver=3.7.1")

	def test_clean_and_validate_url_with_leading_metadata(self):
		"""Test clean_and_validate_url with leading metadata bracket structures.
		"""
		url = "[javascript] - http://target.com/assets/main.js"
		result = clean_and_validate_url(url, base_domain="target.com")
		self.assertEqual(result, "http://target.com/assets/main.js")

	def test_clean_and_validate_url_relative_path(self):
		"""Test clean_and_validate_url with a relative path.
		"""
		url = "/js/app.js"
		result = clean_and_validate_url(url, base_domain="target.com")
		self.assertEqual(result, "https://target.com/js/app.js")

	def test_clean_and_validate_url_external_domain(self):
		"""Test clean_and_validate_url with an out-of-scope third-party domain.
		"""
		url = "https://cdnjs.cloudflare.com/ajax/libs/react/18.2.0/umd/react.production.min.js"
		result = clean_and_validate_url(url, base_domain="target.com")
		self.assertIsNone(result)

	def test_clean_and_validate_url_invalid(self):
		"""Test clean_and_validate_url with an entirely invalid URL string.
		"""
		url = "not_a_url_at_all"
		result = clean_and_validate_url(url, base_domain="target.com")
		# Returns https://target.com/not_a_url_at_all which is checked if it starts with http/https
		self.assertEqual(result, "https://target.com/not_a_url_at_all")

	def test_clean_semgrep_check_id(self):
		"""Test clean_semgrep_check_id with various check ID structures.

		NOTE: clean_semgrep_check_id now returns human-readable labels.
		Known slugs resolve via the lookup table; unknown slugs are smart-parsed
		into title-case words with boilerplate ('detected', 'generic', 'security') stripped.
		"""
		from reNgine.common_func import clean_semgrep_check_id

		# Test case 1: Unknown slug — smart-parsed, boilerplate 'security' stripped
		dirty_id_1 = "usr.src.github.semgrep_rules.typescript.react.security.audit.react-dangerouslysetinnerhtml.react-dangerouslysetinnerhtml"
		self.assertEqual(
			clean_semgrep_check_id(dirty_id_1),
			"React Dangerouslysetinnerhtml"
		)

		# Test case 2: Unknown slug — smart-parsed, boilerplate stripped
		dirty_id_2 = "app.rules.javascript.browser.security.wildcard-postmessage-configuration.wildcard-postmessage-configuration"
		self.assertEqual(
			clean_semgrep_check_id(dirty_id_2),
			"Wildcard Postmessage Configuration"
		)

		# Test case 3: Known slug via lookup table
		dirty_id_3 = "p.secrets.generic-api-key"
		self.assertEqual(
			clean_semgrep_check_id(dirty_id_3),
			"Generic API Key"
		)

		# Test case 4: Unknown slug — smart-parsed
		clean_id = "python.django.security.injection.sql-injection"
		self.assertEqual(
			clean_semgrep_check_id(clean_id),
			"Sql Injection"
		)

		# Test case 5: Empty/None values
		self.assertEqual(clean_semgrep_check_id(""), "")
		self.assertEqual(clean_semgrep_check_id(None), "")


from reNgine.common_func import clean_semgrep_check_id, categorize_secret_type


class SemgrepLabelTests(TestCase):
	"""Test clean_semgrep_check_id lookup + parse and categorize_secret_type."""

	# --- clean_semgrep_check_id ---

	def test_known_slug_facebook_oauth(self):
		result = clean_semgrep_check_id('generic.secrets.security.detected-facebook-oauth')
		self.assertEqual(result, 'Facebook OAuth Token')

	def test_known_slug_aws_access_key(self):
		result = clean_semgrep_check_id('generic.secrets.security.detected-aws-access-key')
		self.assertEqual(result, 'AWS Access Key')

	def test_known_slug_github_pat(self):
		result = clean_semgrep_check_id('generic.secrets.security.github-personal-access-token')
		self.assertEqual(result, 'GitHub Personal Access Token')

	def test_known_slug_jwt(self):
		result = clean_semgrep_check_id('jwt-token')
		self.assertEqual(result, 'JWT Token')

	def test_unknown_slug_smart_parse(self):
		# unknown slug — should fall through to smart parse
		result = clean_semgrep_check_id('generic.secrets.security.detected-example-api-token')
		# 'detected' and 'generic' stripped; 'Example', 'Token' remain
		self.assertIn('Example', result)
		self.assertIn('Token', result)

	def test_empty_string_returns_empty(self):
		self.assertEqual(clean_semgrep_check_id(''), '')

	def test_path_prefix_stripped(self):
		result = clean_semgrep_check_id('usr.src.github.semgrep_rules.secrets.stripe-secret-key')
		self.assertEqual(result, 'Stripe Secret Key')

	# --- categorize_secret_type ---

	def test_category_api_key(self):
		cat, color = categorize_secret_type('AWS Access Key')
		self.assertEqual(cat, 'API Key')
		self.assertEqual(color, 'warning')

	def test_category_oauth(self):
		cat, color = categorize_secret_type('Facebook OAuth Token')
		self.assertEqual(cat, 'OAuth Token')
		self.assertEqual(color, 'info')

	def test_category_credential(self):
		cat, color = categorize_secret_type('Hardcoded Password')
		self.assertEqual(cat, 'Credential')
		self.assertEqual(color, 'error')

	def test_category_private_key(self):
		cat, color = categorize_secret_type('RSA Private Key')
		self.assertEqual(cat, 'Private Key')
		self.assertEqual(color, 'error')

	def test_category_ssh_private_key(self):
		cat, color = categorize_secret_type('SSH Private Key')
		self.assertEqual(cat, 'Private Key')
		self.assertEqual(color, 'error')

	def test_category_fallback(self):
		cat, color = categorize_secret_type('Something Unrecognised')
		self.assertEqual(cat, 'Secret')
		self.assertEqual(color, 'warning')
