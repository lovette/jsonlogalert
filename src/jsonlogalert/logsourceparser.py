from __future__ import annotations

import json
from typing import TYPE_CHECKING

from jsonlogalert.exceptions import LogAlertParserError

if TYPE_CHECKING:
    from jsonlogalert.logsource import LogSource


class LogSourceParser:
    """Generic app exception."""

    def __init__(self, log_source: LogSource) -> None:
        """Constructor.

        Args:
            log_source (LogSource): Log source for this parser.
        """
        self.log_source = log_source

        # Converters will be applied to captured fields
        self.field_converters = None

    def parse_line(self, log_line: str) -> dict | LogAlertParserError:
        """Parse source log entry into a dict of structured fields.

        Args:
            log_line (str): Log entry from source.

        Returns:
            dict: Parse success.
            LogAlertParserError: Parse failure.
        """
        try:
            fields = json.loads(log_line)
        except json.JSONDecodeError as err:
            return LogAlertParserError(f"{err}: {log_line}"), None

        return fields
