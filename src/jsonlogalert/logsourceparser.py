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
        self.source = log_source

        # Converters will be applied to captured fields
        self.field_converters = {}

    def parse_line(self, log_line: str) -> dict:
        """Parse source log entry into a dict of structured fields.

        Args:
            log_line (str): Log entry from source.

        Raises:
            LogAlertParserError: Parse failure.

        Returns:
            dict: Parse success.
        """
        if not (log_line.startswith("{") and log_line.endswith("}")):
            raise LogAlertParserError(f"Expected JSON dict: '{log_line}'")

        try:
            fields = json.loads(log_line)
        except json.JSONDecodeError as err:
            raise LogAlertParserError(f"Invalid JSON? {err}: '{log_line}'") from err

        return fields
