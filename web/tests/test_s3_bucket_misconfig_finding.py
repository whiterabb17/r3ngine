"""Misconfigured cloud buckets must become Vulnerability findings."""
from unittest import TestCase

from reNgine.tasks.parsers import (
	build_s3_bucket_misconfig_vuln,
	parse_s3scanner_result,
	s3_bucket_misconfig_severity,
	s3_bucket_public_issues,
)


def _bucket_line(**overrides):
	bucket = {
		'name': 'admin.example.com',
		'region': 'de-fra-1',
		'provider': 'linode',
		'owner_display_name': '',
		'owner_id': '',
		'perm_auth_users_read': 0,
		'perm_auth_users_write': 0,
		'perm_auth_users_read_acl': 0,
		'perm_auth_users_write_acl': 0,
		'perm_auth_users_full_control': 0,
		'perm_all_users_read': 0,
		'perm_all_users_write': 0,
		'perm_all_users_read_acl': 0,
		'perm_all_users_write_acl': 0,
		'perm_all_users_full_control': 0,
		'num_objects': 0,
		'bucket_size': 0,
		'exists': 1,
	}
	bucket.update(overrides)
	return {'bucket': bucket}


class TestS3BucketMisconfigHelpers(TestCase):

	def test_private_bucket_has_no_issues(self):
		result = parse_s3scanner_result(_bucket_line())
		self.assertEqual(s3_bucket_public_issues(result), [])
		self.assertIsNone(build_s3_bucket_misconfig_vuln(result))

	def test_public_write_is_high(self):
		result = parse_s3scanner_result(_bucket_line(perm_all_users_write=1, num_objects=0))
		self.assertEqual(s3_bucket_public_issues(result), ['public write'])
		self.assertEqual(s3_bucket_misconfig_severity(result), 3)
		vuln = build_s3_bucket_misconfig_vuln(result)
		self.assertEqual(vuln['severity'], 3)
		self.assertEqual(vuln['source'], 's3scanner')
		self.assertIn('public write', vuln['description'])
		self.assertEqual(vuln['http_url'], 's3://linode/admin.example.com')
		self.assertEqual(
			vuln['name'],
			'Misconfigured Cloud Bucket (linode): admin.example.com',
		)

	def test_public_read_is_medium(self):
		result = parse_s3scanner_result(_bucket_line(perm_all_users_read=1))
		self.assertEqual(s3_bucket_misconfig_severity(result), 2)
		vuln = build_s3_bucket_misconfig_vuln(result)
		self.assertEqual(vuln['severity'], 2)
		self.assertIn('public read', vuln['description'])
