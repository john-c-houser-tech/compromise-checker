"""Words for reasons."""


def show(value) -> str:
    """A value the server sent, fit to put in a reason: quoted, cut short."""
    text = str(value)
    return repr(text[:60] + ("..." if len(text) > 60 else ""))
