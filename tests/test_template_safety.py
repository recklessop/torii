"""Structural guard against a trap that has now bitten twice.

Jinja resolves `thing.keys` to the dict METHOD before it looks for an item of
that name, so a context dict with a key called `keys`, `items` or `values`
renders as "<built-in method keys of dict object at 0x…>" — which is what
shipped to production once (the overview tiles) and was caught in review once
(the services key list). Neither was a logic error; both were a name collision
no reviewer reliably spots.

So: fail the build if a template dereferences one of those names.
"""

import pathlib
import re

TEMPLATES = pathlib.Path(__file__).resolve().parent.parent / "torii" / "templates"

# `x.keys` / `x.items` / `x.values` anywhere in an expression or tag.
DANGEROUS = re.compile(r"\.(keys|items|values)\b")


def test_no_template_dereferences_a_dict_method():
    offenders = []
    for path in sorted(TEMPLATES.rglob("*.html")):
        for number, line in enumerate(path.read_text().splitlines(), start=1):
            # Only Jinja expressions matter; plain prose mentioning "the keys
            # page" is fine.
            if "{{" not in line and "{%" not in line:
                continue
            for match in DANGEROUS.finditer(line):
                # A method CALL is deliberate and safe: `x.items()`.
                if line[match.end():match.end() + 1] == "(":
                    continue
                offenders.append(f"{path.name}:{number}: {line.strip()[:90]}")

    assert not offenders, (
        "Template dereferences a dict method — Jinja returns the method, not "
        "your value. Rename the context key (e.g. api_keys, live_keys):\n  "
        + "\n  ".join(offenders)
    )
