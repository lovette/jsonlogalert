from __future__ import annotations

from typing import TYPE_CHECKING

if TYPE_CHECKING:
    import datetime
    from collections.abc import Sequence

from functools import cached_property

######################################################################
# LogEntry


class LogEntry:
    """A single structured log entry."""

    def __init__(self, rawfields: dict, timestamp_field: str, message_field: str) -> None:
        """Constructor.

        Args:
            rawfields (dict): Log entry fields dictionary.
            timestamp_field (str): Name of field containing entry timestamp.
            message_field (str): Name of field containing entry message.
        """
        self.rawfields = rawfields
        self.conceal_fields: set[str] = None
        self.timestamp_field = timestamp_field
        self.message_field = message_field

    def __getattr__(self, key: str) -> str | None:
        """Return log entry field value using attribute notation.

        It's not an error to ask for a non-existent field, None is returned.

        Args:
            key (str): Field

        Returns:
            Optional[Any]: Field value
        """
        return self.rawfields.get(key, None)

    def __repr__(self) -> str:
        """Return the “official” string representation of an object.

        Returns:
            str
        """
        class_name = type(self).__name__
        return f'{class_name}({self.timestamp.isoformat(sep=" ")} {self.message})'

    @property
    def timestamp(self) -> datetime.datetime | None:
        """Log entry timestamp.

        Returns:
            datetime.datetime
        """
        return self.rawfields.get(self.timestamp_field)

    @property
    def message(self) -> str | None:
        """Log entry message field.

        Returns:
            str
        """
        return self.rawfields.get(self.message_field)

    @cached_property
    def fields(self) -> dict[str, str | int | float]:
        """Log entry fields sorted by key. Concealed fields are not included.

        Returns:
            dict
        """
        fields = {k: self.rawfields.get(k) for k in self.rawfields if k not in self.conceal_fields} if self.conceal_fields else self.rawfields

        return dict(sorted(fields.items()))

    def add_conceal_fields(self, fields: Sequence[str]) -> str:
        """Add fields to set of concealed fields.

        Allows a template to conceal fields. Keep in mind this may affect all log entries
        for the service if the service or source define 'conceal_fields'.

        Args:
            fields (Sequence[str]): Fields to conceal.

        Returns:
            Empty string
        """
        if self.conceal_fields:
            self.conceal_fields.update(fields)
        else:
            self.conceal_fields = set(fields)

        # Replace invocation with an empty string
        return ""
