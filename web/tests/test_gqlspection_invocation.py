"""GQLSpection was invoked under a name and a flag that do not exist.

The installed console script is `gqlspection`, lowercase, and its URL option is
`-u/--url`; the code called `GQLSpection -e <url>`, so every run ended at exit
code 127 without reaching the tool. Nothing downstream had ever been exercised,
which hid two more defects in the same block: the result check looked for the
word "enabled", which the tool prints only in its own help text, and the tool
was run once per URL with no gate and no per-host deduplication.
"""
import os
import re
import unittest

from reNgine.tasks.crawl import gqlspection_schema_dumped

CRAWL_SOURCE = os.path.join(
    os.path.dirname(os.path.abspath(__file__)), '..', 'reNgine', 'tasks', 'crawl', 'api_discovery.py'
)


def _gqlspection_block():
    with open(CRAWL_SOURCE, encoding='utf-8') as handle:
        source = handle.read()
    start = source.index('# GQLSpection')
    end = source.index("GQLSpection: finished", start)
    return source[start:end]


class TestSchemaDumpDetection(unittest.TestCase):
    """A dump that worked is the finding; the tool has no 'is it on?' mode."""

    def test_successful_dump_counts(self):
        self.assertTrue(
            gqlspection_schema_dumped(0, 'query user(id: ID!): User\nmutation login(...)')
        )

    def test_non_zero_exit_does_not_count(self):
        self.assertFalse(gqlspection_schema_dumped(1, 'query user(id: ID!): User'))

    def test_command_not_found_does_not_count(self):
        """The state this code was actually in: exit 127, no output."""
        self.assertFalse(gqlspection_schema_dumped(127, '/bin/sh: 1: GQLSpection: not found'))

    def test_empty_output_does_not_count(self):
        self.assertFalse(gqlspection_schema_dumped(0, ''))
        self.assertFalse(gqlspection_schema_dumped(0, '   \n  '))
        self.assertFalse(gqlspection_schema_dumped(0, None))

    def test_traceback_does_not_count(self):
        """A missing dependency exits zero in some wrappers — do not report it."""
        self.assertFalse(
            gqlspection_schema_dumped(
                0, "Traceback (most recent call last):\nModuleNotFoundError: No module named 'click'"
            )
        )

    def test_the_word_enabled_alone_is_not_evidence(self):
        """The old check fired on any output containing "enabled"."""
        self.assertFalse(
            gqlspection_schema_dumped(1, 'URL of the GraphQL endpoint with enabled introspection.')
        )

    def test_a_schema_mentioning_errors_still_counts(self):
        """Field names must not be mistaken for failure markers."""
        self.assertTrue(gqlspection_schema_dumped(0, 'query errors: [Error!]!'))


class TestInvocationShape(unittest.TestCase):
    """Pin the command line, since only a real run proves the rest."""

    def setUp(self):
        self.block = _gqlspection_block()

    def test_uses_the_installed_command_name(self):
        self.assertIn('gqlspection -u ', self.block)

    def test_does_not_use_the_name_that_does_not_exist(self):
        self.assertNotIn('GQLSpection -e', self.block)

    def test_does_not_inject_dependencies_during_a_scan(self):
        """click belongs in the image, not in a network call mid-scan."""
        self.assertNotIn('pipx inject', self.block)

    def test_runs_only_against_graphql_endpoints(self):
        self.assertIn('is_graphql_endpoint_url(url)', self.block)

    def test_deduplicates_by_host(self):
        self.assertIn('seen_hosts', self.block)


class TestDependencyIsInstalledAtBuildTime(unittest.TestCase):

    def test_dockerfile_injects_click(self):
        dockerfile = os.path.join(
            os.path.dirname(os.path.abspath(__file__)),
            '..', '..', 'docker', 'web', 'Dockerfile',
        )
        with open(dockerfile, encoding='utf-8') as handle:
            content = handle.read()
        self.assertTrue(
            re.search(r'pipx inject\s+gqlspection\s+click', content),
            'GQLSpection needs click injected at build time or its entry point raises',
        )
