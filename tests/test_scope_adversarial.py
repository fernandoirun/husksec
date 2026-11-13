"""Adversarial scope tests: the classic ways an allowlist gets bypassed.

The property we defend: an attacker-influenced target string can never make an
out-of-scope host look in-scope, and ambiguity always denies.
"""
from husksec.scope import Scope, normalize_target

S = Scope.from_text(
    "authorized: true\n"
    "in_scope:\n  - target.htb\n  - 10.10.11.0/24\n  - 2001:db8::/32\n"
    "out_of_scope:\n  - 10.10.11.1\n"
)


def test_url_userinfo_cannot_smuggle_an_in_scope_name():
    # http://<in-scope>@<out-of-scope>/ -- the REAL host is evil.com, must be denied
    assert normalize_target("http://target.htb@evil.com/") == "evil.com"
    assert not S.allows("http://target.htb@evil.com/")


def test_url_with_port_and_path():
    assert S.allows("https://target.htb:8443/admin?x=1")


def test_ipv6_cidr_match():
    assert S.allows("2001:db8::1")
    assert S.allows("http://[2001:db8::dead]:8080/")
    assert not S.allows("2001:dead::1")


def test_trailing_dot_and_case_are_normalized():
    assert S.allows("TARGET.HTB.")
    assert S.allows("Target.HTB")


def test_deny_wins_even_via_url():
    assert not S.allows("http://10.10.11.1/")        # excluded gateway, as a URL
    assert not S.allows("10.10.11.1:22")             # ...and as host:port


def test_subdomain_is_not_implicitly_in_scope():
    # exact hostname in scope must NOT grant subdomains or look-alikes
    assert not S.allows("admin.target.htb")
    assert not S.allows("target.htb.evil.com")


def test_encoded_ip_does_not_bypass_to_in_scope():
    # a hex-encoded form of 10.10.11.5 is not parsed as that IP, so it cannot
    # sneak into the in_scope CIDR -- it simply fails closed (denied)
    assert not S.allows("http://0x0a0a0b05/")


def test_empty_and_garbage_targets_denied():
    assert not S.allows("")
    assert not S.allows("   ")
    assert not S.allows("not a url or host")
