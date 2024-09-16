from __future__ import annotations  # noqa: INP001

from datetime import datetime
from typing import TYPE_CHECKING

from jsonlogalert.logsourceparser import LogSourceParser

if TYPE_CHECKING:
    from jsonlogalert.logsource import LogSource

FIELD_CONVERTERS = {
    "tsiso": lambda ts: datetime.strptime(ts, "%Y-%m-%dT%H:%M:%S.%f%z"),
}

######################################################################
# LogAlertLogSourceParser


class LogAlertLogSourceParser(LogSourceParser):
    """Jsonlogalert parser for Caddyserver log files."""

    def __init__(self, log_source: LogSource) -> None:
        """Constructor.

        Args:
            log_source (LogSource): Log source for this parser.
        """
        super().__init__(log_source)

        # Converters will be applied to captured fields
        self.field_converters = FIELD_CONVERTERS
