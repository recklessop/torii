"""Turn a User-Agent string into something a human can recognise.

Only used to label OAuth connectors (Q16). Every claude.ai surface registers
with the same client_name, so without this a phone and a desktop are two
identical rows. Deliberately crude: this is a hint on a page, never an
authorization input, so being wrong costs a confusing label and nothing more.
"""

import re

# Order matters — the first match wins, and the specific cases come first
# because a Claude mobile webview also contains "Safari".
_PLATFORMS = [
    (re.compile(r"\biPhone\b", re.I), "iPhone"),
    (re.compile(r"\biPad\b", re.I), "iPad"),
    (re.compile(r"\bAndroid\b", re.I), "Android"),
    (re.compile(r"\bMac OS X\b|\bMacintosh\b", re.I), "macOS"),
    (re.compile(r"\bWindows NT\b", re.I), "Windows"),
    (re.compile(r"\bCrOS\b", re.I), "ChromeOS"),
    (re.compile(r"\bLinux\b", re.I), "Linux"),
]

_BROWSERS = [
    (re.compile(r"\bClaude\b", re.I), "Claude app"),
    (re.compile(r"\bEdg/", re.I), "Edge"),
    (re.compile(r"\bOPR/|\bOpera\b", re.I), "Opera"),
    (re.compile(r"\bFirefox/", re.I), "Firefox"),
    (re.compile(r"\bChrome/", re.I), "Chrome"),
    (re.compile(r"\bSafari/", re.I), "Safari"),
    (re.compile(r"python-httpx|curl|python-requests", re.I), "a script"),
]


def describe(user_agent: str | None) -> str | None:
    """"Chrome on macOS", "Claude app on iPhone", or None if it says nothing."""
    if not user_agent:
        return None
    browser = next((name for pattern, name in _BROWSERS if pattern.search(user_agent)), None)
    platform = next((name for pattern, name in _PLATFORMS if pattern.search(user_agent)), None)
    if browser and platform:
        return f"{browser} on {platform}"
    if browser:
        return browser
    if platform:
        return platform
    # Something unrecognised: show a trimmed original rather than nothing, so
    # an operator can still tell two connectors apart.
    return user_agent[:40]
