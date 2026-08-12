"""`<upstream>__<tool>` splitting. On the authorization path, so a name that
can't be split must raise rather than resolve to something plausible."""

import pytest

from torii import naming


def test_roundtrip():
    assert naming.namespaced("knowledge", "search_knowledge") == (
        "knowledge__search_knowledge"
    )
    assert naming.split("knowledge__search_knowledge") == (
        "knowledge",
        "search_knowledge",
    )


def test_tool_names_keep_their_underscores():
    """Upstream names exclude underscores (schema CHECK), so the first `__`
    is unambiguously the separator and the tool keeps the rest."""
    assert naming.split("acme-admin__run_sql") == ("acme-admin", "run_sql")
    assert naming.split("brain__BRAIN__capture_thought") == ("brain", "BRAIN__capture_thought")


@pytest.mark.parametrize(
    "bad",
    ["", "notnamespaced", "__tool", "upstream__", "__", "upstream_tool"],
)
def test_malformed_names_raise(bad):
    with pytest.raises(naming.MalformedToolName):
        naming.split(bad)
