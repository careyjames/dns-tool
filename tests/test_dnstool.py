import sys
import types
import pytest

# Provide minimal dummy modules so dnstool can be imported without optional
# dependencies such as requests or dnspython. These tests only exercise
# helper functions that do not require network access.
sys.modules.setdefault('requests', types.SimpleNamespace())
dns_stub = types.SimpleNamespace(resolver=types.SimpleNamespace())
sys.modules.setdefault('dns', dns_stub)
sys.modules.setdefault('dns.resolver', dns_stub.resolver)

import dnstool


def test_domain_to_ascii_basic():
    assert dnstool.domain_to_ascii('example.com') == 'example.com'


def test_domain_to_ascii_unicode():
    assert dnstool.domain_to_ascii('ex\u00e4mple.test') == 'xn--exmple-cua.test'


def test_domain_to_ascii_trailing_dot():
    assert dnstool.domain_to_ascii('example.com.') == 'example.com'


def test_domain_to_ascii_invalid():
    assert dnstool.domain_to_ascii('\u2603.com') == '\u2603.com'


def test_validate_domain_valid():
    assert dnstool.validate_domain('example.com')
    assert dnstool.validate_domain('sub.example.co.uk')


@pytest.mark.parametrize('dom', [
    'invalid_domain',
    'bad_domain!.com',
    'domain.c',
    '.leading.com',
    ''
])
def test_validate_domain_invalid(dom):
    assert not dnstool.validate_domain(dom)
