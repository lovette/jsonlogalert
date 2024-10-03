from __future__ import annotations

import os
from datetime import datetime, timezone
from functools import cached_property
from pathlib import Path
from typing import TYPE_CHECKING

from jsonlogalert.logalertoutput import LogAlertOutput
from jsonlogalert.utils import resolve_rel_path

if TYPE_CHECKING:
    from jsonlogalert.logservice import LogService

######################################################################
# LogAlertOutputToFile


class LogAlertOutputToFile(LogAlertOutput):
    """Logalert output to file."""

    def __init__(self, log_service: LogService) -> None:
        """Constructor.

        Args:
            log_service (LogService): Service using this output.
        """
        super().__init__(log_service)

        self.output_max_bytes_default = 25 * 1024 * 1024  # 25 MiB

    def __call__(self) -> None:
        """Save output to file."""
        output_file_name = self.output_file_name

        if not output_file_name:
            # We are saving files to a directory, so make up a unique file name
            name_parts = (
                "jsonlogalert",
                self.service.fullname.replace("/", "-").replace("[", "_").replace("]", ""),
                datetime.now(tz=timezone.utc).strftime("%Y%m%d_%H%M%S"),
            )

            output_file_name = "-".join(name_parts)

            for s, r in (("/", "-"), ("[", "_"), ("]", "")):
                output_file_name = output_file_name.replace(s, r)

        output_path = resolve_rel_path(output_file_name, self.output_file_dir).with_suffix(f".{self.output_content_type}")

        content = self.render_template()

        if self.output_max_bytes and self.output_max_bytes < len(content):
            # Not a fatal error
            self.log_error(f"Refusing to save output: Too much content; {len(content)} bytes")
        else:
            self._savefile(output_path, content)

    @cached_property
    def output_file_dir(self) -> Path:
        """Path of output file directory.

        Returns:
            Path
        """
        return Path(self.service.output_file_dir) if self.service.output_file_dir else Path.cwd()

    def validate_conf(self) -> None:
        """Initialize and verify output configuration properties.

        Raises:
            LogAlertConfigError: Invalid configuration.
        """
        super().validate_conf()

        if not self.output_file_dir:
            self.config_error("Cannot save output", "'output_file_dir' is not set.")

    def validate_scan(self) -> None:
        """Review scan configuration directives and see if they make sense.

        Raises:
            LogAlertConfigError
        """
        super().validate_scan()

        if not self.output_file_dir.is_dir():
            self.config_error("Cannot save output", f"{self.output_file_dir}: No such directory")

        if not os.access(self.output_file_dir, os.W_OK | os.X_OK):
            self.config_error(f"'output_file_dir' '{self.output_file_dir}' requires write permission")

    def _savefile(self, output_path: Path, content: str) -> None:
        """Save file to output directory.

        Args:
            output_path (Path): Write output to this file.
            content (str): Output content.
        """
        self.log_debug(f"Output written to {output_path}")

        try:
            with output_path.open("w", encoding="utf-8") as file:
                file.write(content)
        except OSError as err:
            self.log_error(f"Failed to save output: {err}")
