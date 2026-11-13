"""Tests for the scope authorization boundary.

Two things we care about most: the matcher is correct, and the parser is
*fail-closed* -- any surprise in the file denies rather than silently widening
scope. These tests import only husksec.scope (pure stdlib), so they run with no
install and no kernel.
"""
import textwrap

import pytest

from husksec.scope import Scope, ScopeError, matches, normalize_target, parse_scope_text

GOOD = textwrap.dedent(
    """
    engagement: "lab"
    authorized: true
    in_scope:
      - 10.10.11.0/24
      - 10.129.42.7
      - target.htb
      - "*.target.htb"
      - "https://juice-shop.local"
    out_of_scope:
      - 10.10.11.1          # gateway
      - "*.prod.target.htb"
    notes: practice only
    """
)


# --- normalization --------------------------------------------------------- #

@pytest.mark.parametrize(
    "raw,expected",
    [
        ("https://TARGET.htb:8443/admin", "target.htb"),
        ("http://target.htb", "target.htb"),
        ("10.10.10.5:443", "10.10.10.5"),
        ("10.10.10.5", "10.10.10.5"),
        ("[::1]:8080", "::1"),
        ("target.htb/login", "target.htb"),
        ("Target.HTB.", "target.htb"),
        ("", ""),
    ],
)
def test_normalize_target(raw, expected):
    assert normalize_target(raw) == expected


# --- matching -------------------------------------------------------------- #

def test_cidr_matches_member_ip_only():
    assert matches("10.10.11.0/24", "10.10.11.5")
    assert not matches("10.10.11.0/24", "10.10.12.5")
    # a hostname never matches a CIDR (we do not resolve DNS)
    assert not matches("10.10.11.0/24", "target.htb")


def test_single_ip_pattern():
    assert matches("10.129.42.7", "10.129.42.7")
    assert not matches("10.129.42.7", "10.129.42.8")


def test_exact_hostname():
    assert matches("target.htb", "target.htb")
    assert not matches("target.htb", "evil.com")
    # an IP target never matches a hostname pattern
    assert not matches("target.htb", "10.0.0.1")


def test_wildcard_subdomain_but_not_apex():
    assert matches("*.target.htb", "api.target.htb")
    assert matches("*.target.htb", "a.b.target.htb")
    assert not matches("*.target.htb", "target.htb")        # apex excluded
    assert not matches("*.target.htb", "nottarget.htb")


# --- end-to-end authorization decisions ------------------------------------ #

def test_in_scope_allows():
    s = Scope.from_text(GOOD)
    assert s.allows("10.10.11.50")
    assert s.allows("http://10.129.42.7/")
    assert s.allows("target.htb")
    assert s.allows("https://api.target.htb/v1")
    assert s.allows("juice-shop.local")


def test_out_of_scope_overrides_in_scope():
    s = Scope.from_text(GOOD)
    # 10.10.11.1 is inside the in_scope /24 but explicitly excluded
    allowed, reason = s.check("10.10.11.1")
    assert not allowed
    assert "out_of_scope" in reason
    # a production subdomain matches *.target.htb (in) AND *.prod.target.htb (out)
    assert not s.allows("db.prod.target.htb")


def test_unlisted_target_denied():
    s = Scope.from_text(GOOD)
    allowed, reason = s.check("8.8.8.8")
    assert not allowed
    assert "not in the declared scope" in reason


def test_not_authorized_denies_everything():
    s = Scope.from_text(GOOD.replace("authorized: true", "authorized: false"))
    assert not s.allows("10.10.11.50")        # would be in scope, but no go-ahead
    _, reason = s.check("10.10.11.50")
    assert "authorized" in reason


def test_authorized_defaults_to_false():
    # a file that forgets 'authorized' allows nothing
    s = Scope.from_text("in_scope:\n  - 10.0.0.1\n")
    assert not s.allows("10.0.0.1")


# --- fail-closed parser ---------------------------------------------------- #

def test_unknown_key_raises():
    # a typo like 'out_scope' must NOT silently drop the exclusion list
    with pytest.raises(ScopeError):
        parse_scope_text("authorized: true\nout_scope:\n  - 10.0.0.1\n")


def test_bad_authorized_value_raises():
    with pytest.raises(ScopeError):
        parse_scope_text("authorized: maybe\n")


def test_list_key_with_inline_value_raises():
    with pytest.raises(ScopeError):
        parse_scope_text("in_scope: 10.0.0.1\n")


def test_duplicate_key_raises():
    with pytest.raises(ScopeError):
        parse_scope_text("authorized: true\nauthorized: false\n")


def test_unterminated_quote_raises():
    with pytest.raises(ScopeError):
        parse_scope_text('engagement: "oops\n')


def test_stray_indented_line_raises():
    with pytest.raises(ScopeError):
        parse_scope_text("authorized: true\n  - 10.0.0.1\n")


def test_missing_file_raises_scopeerror(tmp_path):
    with pytest.raises(ScopeError):
        Scope.load(tmp_path / "does_not_exist.yaml")


def test_comments_and_blanks_ignored():
    s = Scope.from_text(
        "# a comment\n\nauthorized: true  # inline\nin_scope:\n  - 10.0.0.1  # a box\n"
    )
    assert s.authorized is True
    assert s.in_scope == ["10.0.0.1"]
    assert s.allows("10.0.0.1")


def test_roundtrip_load_from_file(tmp_path):
    p = tmp_path / "scope.yaml"
    p.write_text(GOOD, encoding="utf-8")
    s = Scope.load(p)
    assert s.engagement == "lab"
    assert s.allows("10.10.11.50")
    assert not s.allows("10.10.11.1")
