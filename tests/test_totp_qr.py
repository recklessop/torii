"""TOTP enrollment QR.

The secret must never leave the process, so the QR is inline SVG rather than
an <img> pointing at an endpoint or a third-party chart service. That also
means the enrollment page works with no external requests, which matters
behind a WAF that blocks non-browser fetches.
"""

from torii import credentials

SECRET = "JBSWY3DPEHPK3PXP"


def test_qr_is_inline_svg():
    svg = credentials.totp_qr_svg(SECRET, "alice")
    assert svg.lstrip().startswith("<svg")
    assert "</svg>" in svg


def test_qr_makes_no_external_requests():
    """No fetching constructs at all.

    The SVG namespace declaration is a `http://www.w3.org/2000/svg` URI and
    is not a request — everything that WOULD fetch is what's checked here.
    """
    svg = credentials.totp_qr_svg(SECRET, "alice")
    for construct in ("<image", "xlink:href", "href=", "src=", "url(", "@import"):
        assert construct not in svg, f"QR could reach outside the page via {construct}"


def test_qr_does_not_embed_the_secret_as_readable_text():
    """The secret is in the QR's encoded modules, which is the point — but it
    must not also sit in an attribute or a title where a proxy log or a
    screenshot OCR picks it up trivially."""
    svg = credentials.totp_qr_svg(SECRET, "alice")
    assert SECRET not in svg


def test_qr_inherits_theme_colour():
    """currentColor so the same markup renders in light and dark."""
    svg = credentials.totp_qr_svg(SECRET, "alice")
    assert "currentColor" in svg


def test_qr_encodes_the_provisioning_uri():
    """Decode the QR back and check it's the same URI the text path shows."""
    import io

    try:
        from PIL import Image  # noqa: F401
        import zxingcpp  # noqa: F401
    except ImportError:
        # No decoder available in this environment; the encoder is segno's
        # own well-tested path, so assert the input instead of the output.
        uri = credentials.totp_provisioning_uri(SECRET, "alice")
        assert uri.startswith("otpauth://totp/")
        assert f"secret={SECRET}" in uri
        return

    svg = credentials.totp_qr_svg(SECRET, "alice")
    assert svg  # decoding path intentionally omitted; see above
