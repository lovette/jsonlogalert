from __future__ import annotations

from typing import TYPE_CHECKING, Callable

if TYPE_CHECKING:
    import datetime
    from collections.abc import Sequence
    from pathlib import Path

from jinja2 import Environment, FileSystemLoader, pass_eval_context
from markupsafe import Markup, escape
from minify_html import minify

######################################################################
# Custom template filters


def _jinja_format_iso(value: datetime.datetime, sep: str = "T", timespec: str = "auto") -> str | None:
    """Return a string representing the date and time in ISO 8601 format.

    Args:
        value (datetime.datetime): Jinja template variable.
        sep (str, optional): One-character separator, placed between the date and time portions of the result. Defaults to 'T'.
        timespec (str, optional): Specifies the number of additional components of the time to include. Defaults to 'auto'.

    Returns:
        str or None
    """
    return None if value is None else value.isoformat(sep, timespec)


def _jinja_format_date(value: datetime.datetime, fmt: str = "%Y-%m-%d") -> str | None:
    """Return a string representing the date.

    Args:
        value (datetime.datetime): Jinja template variable.
        fmt (str, optional): Date format spec. Defaults to '%Y-%m-%d'.

    Returns:
        str or None
    """
    return None if value is None else value.strftime(fmt)


def _jinja_format_time(value: datetime.datetime, fmt: str = "%H:%M:%S") -> str | None:
    """Return a string representing the time.

    Args:
        value (datetime.datetime): Jinja template variable.
        fmt (str, optional): Time format spec. Defaults to '%H:%M:%S'.

    Returns:
        str or None
    """
    return None if value is None else value.strftime(fmt)


@pass_eval_context
def _jinja_nl2br(eval_ctx: object, value: str) -> str:
    """Return string with newlines replaced with <br>.

    Args:
        eval_ctx (EvalContext): Jinja template context.
        value (str): Jinja template variable.

    Returns:
        str
    """
    result = escape(value).replace("\n", Markup("<br>\n"))
    if eval_ctx.autoescape:
        result = Markup(result)  # tell Jinja that result is already escaped
    return result


######################################################################
# LogAlertFileSystemLoader


class LogAlertFileSystemLoader(FileSystemLoader):
    """Custom FileSystemLoader that can minify HTML template contents."""

    def __init__(self, *args, **kwargs) -> None:
        """Constructor.

        Args:
            args: See base class.
            kwargs: See base class.
        """
        super().__init__(*args, **kwargs)

        self.minify_html = False

    def get_source(self, *args) -> tuple[str, str, Callable[[], bool]]:
        """Get template source content, minified if configured.

        Args:
            args: See base class.

        Returns:
            See base class.
        """
        contents, filepath, fnuptodate = super().get_source(*args)

        if self.minify_html:
            contents = minify(
                contents,
                do_not_minify_doctype=True,
                ensure_spec_compliant_unquoted_attribute_values=True,
                keep_closing_tags=True,
                keep_html_and_head_opening_tags=True,
                keep_spaces_between_attributes=True,
                minify_css=True,
            )

        return contents, filepath, fnuptodate


######################################################################
# LogAlertJinjaEnvironment


class LogAlertJinjaEnvironment(Environment):
    """Custom Jinja Environment."""

    def __init__(self, template_dirs: Sequence[Path], minify_html: bool) -> None:
        """Constructor.

        Args:
            template_dirs (Path): Directories containing output template files.
            minify_html (bool): True if template is HTML content and should be minified.
        """
        super().__init__(loader=LogAlertFileSystemLoader(template_dirs))

        self.loader.minify_html = minify_html

        self.filters["nl2br"] = _jinja_nl2br
        self.filters["format_iso"] = _jinja_format_iso
        self.filters["format_date"] = _jinja_format_date
        self.filters["format_time"] = _jinja_format_time
