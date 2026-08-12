"""The boot-time config-validation pass (#80).

The spec here is negative-heavy on purpose: the point of the pass is to
refuse the dangerous combinations, so those are what the tests pin.
"""

import pytest

from torii import startup


def test_https_without_session_secret_fails():
    """The worst combination in the issue: an internet-facing (https) origin
    whose session secret is unset and therefore forgeable."""
    env = {"PUBLIC_BASE_URL": "https://torii.example.com"}
    report = startup.evaluate(env)
    assert not report.ok
    assert any("SESSION_SECRET" in f for f in report.failures)

    with pytest.raises(startup.InsecureConfiguration):
        startup.validate(env)


def test_https_with_session_secret_passes():
    """A correctly-configured public deployment starts clean of failures."""
    env = {
        "PUBLIC_BASE_URL": "https://torii.example.com",
        "SESSION_SECRET": "a" * 64,
        "SESSION_HTTPS_ONLY": "true",
        "TORII_ENCRYPTION_KEY": "k" * 44,
    }
    report = startup.validate(env)  # must not raise
    assert report.ok
    assert report.failures == []
    assert report.warnings == []


def test_localhost_without_secret_only_warns():
    """Local dev (http://localhost, no secret) is a warning, not a hard stop —
    otherwise the documented `python -m torii.server` run would not boot."""
    env = {"PUBLIC_BASE_URL": "http://localhost:8400"}
    report = startup.evaluate(env)
    assert report.ok  # no failures
    assert any("SESSION_SECRET" in w for w in report.warnings)
    assert any("localhost" in w for w in report.warnings)
    # And validate() does not raise on a warning-only report.
    startup.validate(env)


def test_https_without_secure_cookie_warns():
    env = {
        "PUBLIC_BASE_URL": "https://torii.example.com",
        "SESSION_SECRET": "a" * 64,
        "SESSION_HTTPS_ONLY": "false",
    }
    report = startup.evaluate(env)
    assert report.ok
    assert any("SESSION_HTTPS_ONLY" in w for w in report.warnings)


def test_missing_encryption_key_warns():
    env = {
        "PUBLIC_BASE_URL": "https://torii.example.com",
        "SESSION_SECRET": "a" * 64,
        "SESSION_HTTPS_ONLY": "true",
    }
    report = startup.evaluate(env)
    assert report.ok
    assert any("TORII_ENCRYPTION_KEY" in w for w in report.warnings)


def test_allow_insecure_downgrades_failure_to_warning():
    """The documented escape hatch: an operator who accepts the risk can
    start anyway, but the report still records the failure."""
    env = {
        "PUBLIC_BASE_URL": "https://torii.example.com",
        "TORII_ALLOW_INSECURE": "1",
    }
    report = startup.validate(env)  # must not raise despite the failure
    assert report.failures  # the failure is still recorded, not hidden
    assert report.allow_insecure


def test_posture_lists_every_checked_setting():
    """Each setting's posture is printed at boot regardless of pass/fail."""
    env = {"PUBLIC_BASE_URL": "https://torii.example.com", "SESSION_SECRET": "a" * 64}
    report = startup.evaluate(env)
    joined = "\n".join(report.postures)
    for key in (
        "PUBLIC_BASE_URL",
        "SESSION_SECRET",
        "SESSION_HTTPS_ONLY",
        "TORII_ENCRYPTION_KEY",
        "METRICS_TOKEN",
    ):
        assert key in joined
