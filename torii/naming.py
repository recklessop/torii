"""Tool namespacing: `<upstream>__<tool>`.

MetaMCP's scheme, kept deliberately so migrating a client is a
URL swap rather than a config rewrite. Upstream names are constrained in the
schema to exclude underscores, which is what makes the split unambiguous:
the FIRST `__` separates upstream from tool, and the tool name may contain
underscores freely (`search_knowledge`, `run_sql`).
"""


SEPARATOR = "__"


class MalformedToolName(ValueError):
    """A client sent something that isn't `<upstream>__<tool>`."""


def namespaced(upstream: str, tool: str) -> str:
    return f"{upstream}{SEPARATOR}{tool}"


def split(name: str) -> tuple[str, str]:
    """Split a namespaced tool name into (upstream, tool).

    Raises MalformedToolName rather than guessing. A caller that can't be
    resolved to a specific upstream and tool must be denied, not
    approximated — this is on the authorization path.
    """
    upstream, separator, tool = name.partition(SEPARATOR)
    if not separator or not upstream or not tool:
        raise MalformedToolName(name)
    return upstream, tool
