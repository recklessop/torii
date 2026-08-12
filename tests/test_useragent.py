"""User-Agent → a label a human recognises.

Only ever a hint on a page (Q16), never an authorization input, so the bar is
"tells two connectors apart", not "correctly identifies every browser".
"""

import pytest

from torii import useragent

CASES = [
    # claude.ai on a desktop browser
    ("Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 "
     "(KHTML, like Gecko) Chrome/126.0.0.0 Safari/537.36", "Chrome on macOS"),
    ("Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
     "(KHTML, like Gecko) Chrome/126.0 Safari/537.36", "Chrome on Windows"),
    ("Mozilla/5.0 (X11; Linux x86_64; rv:128.0) Gecko/20100101 Firefox/128.0",
     "Firefox on Linux"),
    # the phone — the case that matters most, since it's what you'd narrow
    ("Mozilla/5.0 (iPhone; CPU iPhone OS 17_5 like Mac OS X) AppleWebKit/605.1.15 "
     "(KHTML, like Gecko) Mobile/15E148 Safari/604.1", "Safari on iPhone"),
    ("Mozilla/5.0 (iPhone; CPU iPhone OS 17_5 like Mac OS X) Claude/1.2 Mobile",
     "Claude app on iPhone"),
    ("Mozilla/5.0 (Linux; Android 14; Pixel 8) AppleWebKit/537.36 Chrome/126.0 Mobile",
     "Chrome on Android"),
    # a script, which shouldn't be doing an authorize flow but might
    ("python-httpx/0.27.0", "a script"),
]


@pytest.mark.parametrize("agent,expected", CASES)
def test_describe(agent, expected):
    assert useragent.describe(agent) == expected


def test_nothing_useful_gives_nothing():
    assert useragent.describe(None) is None
    assert useragent.describe("") is None


def test_unrecognised_agents_still_distinguish():
    """Better a trimmed original than None — an operator can still tell two
    connectors apart."""
    described = useragent.describe("SomeNewClient/9.9 (unknown platform)")
    assert described
    assert described.startswith("SomeNewClient")
    assert len(described) <= 40
