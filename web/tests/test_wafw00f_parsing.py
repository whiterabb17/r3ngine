"""One unparseable line from wafw00f used to fail the whole task.

Waf.name and Waf.manufacturer are CharField(max_length=500). The parser sliced
on `str.find('(')` without checking for -1, so a line with no parenthesis
produced "the whole line minus its last character" as the WAF name. On a long
line Postgres rejected it with

    DataError: value too long for type character varying(500)

which failed waf_detection, exhausted its retries, and took Tier 5 — and with
it every tier after — down with it.
"""
from unittest import TestCase

from reNgine.tasks.waf import parse_wafw00f_entry


class TestWellFormedEntries(TestCase):

    def test_name_and_manufacturer(self):
        self.assertEqual(
            parse_wafw00f_entry('Cloudflare (Cloudflare Inc.)'),
            ('Cloudflare', 'Cloudflare Inc'),
        )

    def test_dots_are_stripped_from_the_manufacturer(self):
        """Matches the original behaviour, which the UI depends on."""
        self.assertEqual(
            parse_wafw00f_entry('Sucuri (Sucuri Inc.)')[1], 'Sucuri Inc',
        )

    def test_empty_manufacturer(self):
        self.assertEqual(parse_wafw00f_entry('SomeWAF ()'), ('SomeWAF', ''))

    def test_extra_text_after_the_closing_parenthesis_is_ignored(self):
        self.assertEqual(
            parse_wafw00f_entry('Imperva (Imperva Inc.) and 1 more'),
            ('Imperva', 'Imperva Inc'),
        )


class TestLinesThatAreNotEntries(TestCase):
    """These are what produced the overflow."""

    def test_line_without_a_parenthesis_is_skipped(self):
        self.assertEqual(parse_wafw00f_entry('no parenthesis anywhere'), (None, None))

    def test_long_line_without_a_parenthesis_is_skipped(self):
        """The failing case: a line longer than the column, and no '('."""
        self.assertEqual(parse_wafw00f_entry('x' * 900), (None, None))

    def test_unclosed_parenthesis_is_skipped(self):
        self.assertEqual(parse_wafw00f_entry('Cloudflare (Cloudflare Inc'), (None, None))

    def test_closing_before_opening_is_skipped(self):
        self.assertEqual(parse_wafw00f_entry(') odd ('), (None, None))

    def test_literal_none_is_skipped(self):
        self.assertEqual(parse_wafw00f_entry('None (None)'), (None, None))

    def test_empty_name_is_skipped(self):
        self.assertEqual(parse_wafw00f_entry(' (Someone)'), (None, None))

    def test_empty_line(self):
        self.assertEqual(parse_wafw00f_entry(''), (None, None))


class TestValuesAlwaysFitTheColumn(TestCase):

    def test_overlong_name_is_truncated(self):
        name, _ = parse_wafw00f_entry('%s (Vendor)' % ('W' * 900))
        self.assertEqual(len(name), 500)

    def test_overlong_manufacturer_is_truncated(self):
        _, manufacturer = parse_wafw00f_entry('WAF (%s)' % ('V' * 900))
        self.assertEqual(len(manufacturer), 500)

    def test_every_parsed_value_fits(self):
        samples = [
            'Cloudflare (Cloudflare Inc.)',
            '%s (%s)' % ('N' * 700, 'M' * 700),
            'AWS (Amazon)',
        ]
        for sample in samples:
            name, manufacturer = parse_wafw00f_entry(sample)
            if name is None:
                continue
            self.assertLessEqual(len(name), 500)
            self.assertLessEqual(len(manufacturer), 500)
