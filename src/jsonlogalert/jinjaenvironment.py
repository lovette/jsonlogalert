from __future__ import annotations

from collections import defaultdict
from typing import TYPE_CHECKING, Callable

if TYPE_CHECKING:
    import datetime
    from collections.abc import ItemsView, Sequence
    from pathlib import Path

    from jinja2 import runtime

    from jsonlogalert.logentry import LogEntry

from jinja2 import Environment, FileSystemLoader, pass_context, pass_eval_context
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


@pass_context
def _jinja_logentries_groupby(
    context: runtime.Context,
    fields: str | Sequence,
    default_group: str | Sequence | None = None,
    default_last: bool = True,
) -> ItemsView[str | tuple[str], list[LogEntry]]:
    """Group logentries by field value.

    Default group is sorted last.

    Args:
        context (runtime.Context): Jinja template context.
        fields (str | Sequence): Field name or sequence of fields (list or tuple).
        default_group (str | Sequence | None, optional): Default group value or sequence of values. Defaults to 'fields'.
        default_last (bool): Sort default group first or last. Defaults to last.

    Returns:
        ItemsView: ItemsView[(group, logentries)] where `group` is a field value or tuple of field values.
    """
    groupby_entries = defaultdict(list)

    if not isinstance(fields, str) and len(fields) == 1:
        fields = fields[0]

    if isinstance(fields, str):
        default_group = default_group if isinstance(default_group, str) else fields

        for entry in context.parent.get("logentries"):
            group = entry.rawfields.get(fields, default_group)
            groupby_entries[group].append(entry)
    else:
        if isinstance(default_group, str):
            default_group = [default_group] * len(fields)
        elif not default_group or len(default_group) != len(fields):
            default_group = fields

        default_group = tuple(default_group)
        groupby_fields = [None] * len(fields)

        for entry in context.parent.get("logentries"):
            for i, field in enumerate(fields):
                groupby_fields[i] = entry.rawfields.get(field, default_group[i])
            groupby_entries[tuple(groupby_fields)].append(entry)

    # Sort by key
    groupby_entries = dict(sorted(groupby_entries.items()))

    if default_group in groupby_entries and len(groupby_entries) > 1:
        default_entries = groupby_entries[default_group]
        del groupby_entries[default_group]

        if default_last:
            groupby_entries[default_group] = default_entries
        else:
            groupby_entries = {default_group: default_entries} | groupby_entries

    return groupby_entries.items()


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

        self.globals["logentries_groupby"] = _jinja_logentries_groupby
