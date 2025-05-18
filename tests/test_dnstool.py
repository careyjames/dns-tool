import sys
import types
import pytest

import pathlib, sys
sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[1]))

# Provide minimal dummy modules so dnstool can be imported without optional
# dependencies such as requests or dnspython. These tests only exercise
# helper functions that do not require network access.
sys.modules.setdefault('requests', types.SimpleNamespace())
dns_stub = types.SimpleNamespace(
    resolver=types.SimpleNamespace(Resolver=None)
)
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
    'example.com.',
    'example.com-',
    ''
])
def test_validate_domain_invalid(dom):
    assert not dnstool.validate_domain(dom)


def test_authoritative_lookup(monkeypatch):
    # prepare fake dns_query responses
    query_map = {
        ("NS", "example.com"): ["ns1.example.com"],
        ("A", "ns1.example.com"): ["192.0.2.1"],
        ("AAAA", "ns1.example.com"): [],
    }

    def fake_dns_query(rdtype, domain):
        return query_map.get((rdtype, domain), [])

    class DummyResolver:
        def __init__(self, configure=False):
            self.nameservers = []
            self.timeout = None
            self.lifetime = None

        def resolve(self, domain, rdtype):
            key = (self.nameservers[0], domain, rdtype)
            data = {
                # 203.0.113.10 is a TEST-NET address reserved for documentation
                # per RFC 5737, avoiding use of real-world IPs in tests.
                ("192.0.2.1", "example.com", "A"): ["203.0.113.10"],
                ("192.0.2.1", "example.com", "MX"): ["10 mail.example.com"],
            }
            return data.get(key, [])

    monkeypatch.setattr(dnstool, "dns_query", fake_dns_query)
    monkeypatch.setattr(dnstool.dns.resolver, "Resolver", DummyResolver)

    out = dnstool.authoritative_lookup("example.com", ["A", "MX"])
    assert out["A"] == ["203.0.113.10"]
    assert out["MX"] == ["10 mail.example.com"]


def test_get_spf_record(monkeypatch, capsys):
    def fake_dns_query(rdtype, domain):
        if rdtype == "TXT" and domain == "example.com":
            return ["v=spf1 ip4:203.0.113.0/24 -all"]
        return []

    monkeypatch.setattr(dnstool, "dns_query", fake_dns_query)

    dnstool.get_spf_record("example.com")
    out = capsys.readouterr().out
    assert "SPF found" in out
    assert "v=spf1" in out


def test_get_dmarc_record(monkeypatch, capsys):
    def fake_dns_query(rdtype, domain):
        if rdtype == "TXT" and domain == "_dmarc.example.com":
            return ["v=DMARC1; p=reject;"]
        return []

    monkeypatch.setattr(dnstool, "dns_query", fake_dns_query)

    dnstool.get_dmarc_record("example.com")
    out = capsys.readouterr().out
    assert "DMARC p=reject" in out
    assert "v=DMARC1" in out


def test_get_mx_records(monkeypatch, capsys):
    def fake_dns_query(rdtype, domain):
        if rdtype == "MX" and domain == "example.com":
            return [
                "10 aspmx.l.google.com",
                "20 aspmx2.googlemail.com",
            ]
        return []

    monkeypatch.setattr(dnstool, "dns_query", fake_dns_query)

    dnstool.get_mx_records("example.com")
    out = capsys.readouterr().out
    assert "aspmx2.googlemail.com" in out
    assert "older Google MX lines" in out


def test_run_all_checks_batch_mode(monkeypatch):
    called = []

    def make_dummy(name):
        def _dummy(*args, **kwargs):
            called.append(name)
        return _dummy

    funcs = [
        "get_registrar",
        "get_ns_records",
        "get_mx_records",
        "get_txt_records",
        "get_dmarc_record",
        "get_spf_record",
        "get_dkim_record",
        "get_mta_sts",
        "get_dane_records",
        "get_bimi_record",
        "get_dnssec_status",
        "get_a_record",
        "get_aaaa_record",
        "get_caa_record",
        "get_soa_record",
        "get_ptr_record",
    ]

    for f in funcs:
        monkeypatch.setattr(dnstool, f, make_dummy(f))

    monkeypatch.setattr(dnstool, "dns_query", lambda *args, **kwargs: [])

    dnstool.run_all_checks("example.com", authoritative=False)

    for f in funcs:
        assert f in called
