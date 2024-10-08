from __future__ import annotations

import logging
from functools import cached_property
from pathlib import Path
from typing import TYPE_CHECKING

from click import echo
from jinja2 import TemplateNotFound

from jsonlogalert.exceptions import LogAlertConfigError
from jsonlogalert.jinjaenvironment import LogAlertJinjaEnvironment

if TYPE_CHECKING:
    from jsonlogalert.logservice import LogService

######################################################################
# LogAlertOutput


class LogAlertOutput:
    """Logalert output base class."""

    def __init__(self, log_service: LogService) -> None:
        """Constructor.

        Args:
            log_service (LogService): Service using this output.
        """
        self.service = log_service

        self.output_max_bytes_default = 100 * 1024  # 100 KiB (arbitrary; overridden by subclasses)

        # Search these directories for template files
        template_dirs = (
            self.service.service_confdir_path,
            self.service.source.source_dir,
            self.service.source.source_dir.parent,
        )

        self.jinja_env = LogAlertJinjaEnvironment(template_dirs, self.output_template_minify_html)
        self.jinja_template = None

    def __getattr__(self, key: str) -> str | None:
        """Return output config field value using attribute notation.

        Args:
            key (str): Field

        Returns:
            Optional[Any]: Field value
        """
        try:
            if key.startswith("output_"):
                return self.service.service_config[key]
        except KeyError:
            pass

        raise AttributeError(f"'{type(self).__name__}' object has no attribute '{key}'")

    def __call__(self) -> None:
        """Output content.

        Must be implemented in derived classes.

        Args:
            content (str): Output content.
        """
        raise NotImplementedError

    @cached_property
    def output_template_minify_html(self) -> bool:
        """True if template content is HTML and should be minified.

        Returns:
            bool
        """
        output_template_minify_html = self.service.output_template_minify_html
        if output_template_minify_html is None:
            output_template_minify_html = self.output_content_type == "html"
        return bool(output_template_minify_html)

    @cached_property
    def output_max_bytes(self) -> int:
        """Fail output if content is larger than specified bytes.

        Returns:
            int
        """
        output_max_bytes = self.service.output_max_bytes
        if output_max_bytes is None:
            output_max_bytes = self.output_max_bytes_default
        return output_max_bytes

    @cached_property
    def output_content_type(self) -> str:
        """Service output content type; typically 'html' or 'txt'.

        Defaults to 'output_template_file' file extension.
        Used as the file extension for output files.

        Returns:
            str
        """
        output_content_type = self.service.output_content_type

        if not output_content_type:
            suffix = Path(self.output_template_file).suffix
            if suffix:
                output_content_type = "html" if suffix == ".jinja-html" else suffix.removeprefix(".")

        return output_content_type

    def validate_conf(self) -> None:
        """Valiate output configuration properties.

        Raises:
            LogAlertConfigError
        """
        # Load template to validate file paths
        self.load_template()

    def validate_scan(self) -> None:
        """Review output scan configuration directives and see if they make sense.

        Raises:
            LogAlertConfigError
        """

    def load_template(self) -> None:
        """Load template.

        Raises:
            LogAlertConfigError
        """
        if not self.output_template_file:
            self.config_error("Invalid configuration", "'output_template_file' is not set")

        try:
            self.jinja_template = self.jinja_env.get_template(self.output_template_file)
        except TemplateNotFound as err:
            self.config_error("Failed to load output template", err)

    def render_template(self) -> str:
        """Render content for service output.

        Returns:
            str
        """
        if not self.jinja_template:
            self.load_template()

        self.log_debug(f"Output template is '{self.jinja_template.filename}'")

        return self.service.render_template(self.jinja_template)

    def log_debug(self, message: str) -> None:
        """Log a debug message related to this output.

        Args:
            message (str): Message.
        """
        logging.debug(f"{self.service.fullname}: {message}")

    def log_info(self, message: str) -> None:
        """Log a info message related to this output.

        Args:
            message (str): Message.
        """
        logging.info(f"{self.service.fullname}: {message}")

    def log_warning(self, message: str) -> None:
        """Log a warning message related to this output.

        Args:
            message (str): Message.
        """
        logging.warning(f"{self.service.fullname}: {message}")

    def log_error(self, message: str) -> None:
        """Log a error message related to this output.

        Args:
            message (str): Message.
        """
        logging.error(f"{self.service.fullname}: {message}")

    def config_error(self, message: str, err: str | Exception | None = None) -> None:
        """Raise a 'LogAlertConfigError' exception related to this output.

        Args:
            message (str): Message.
            err (str | Exception | None): Error message or exception.

        Raises:
            LogAlertConfigError
        """
        if err:
            raise LogAlertConfigError(f"{self.service.fullname}: {message}: {err}")
        raise LogAlertConfigError(f"{self.service.fullname}: {message}")


######################################################################
# LogAlertOutputToStdout


class LogAlertOutputToStdout(LogAlertOutput):
    """Logalert output to stdout."""

    def __call__(self) -> None:
        """Print content to stdout.

        Args:
            content (str): Output content.
        """
        assert self.service is not None

        content = self.render_template()

        if self.output_max_bytes and self.output_max_bytes < len(content):
            # Not a fatal error
            self.log_error(f"Refusing to output: Too much content; {len(content)} bytes")
        else:
            echo(content)


######################################################################
# LogAlertOutputToDevNull


class LogAlertOutputToDevNull(LogAlertOutput):
    """Logalert output to /dev/null."""

    def __call__(self) -> None:
        """Print content to /dev/null."""
        self.log_debug("Output sent to dev/null")
