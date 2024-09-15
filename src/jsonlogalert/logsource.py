from __future__ import annotations

from pathlib import Path
from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    import io
    from collections.abc import Sequence

import importlib.util
import logging
import re
import subprocess
from functools import cached_property

from click import echo

from jsonlogalert.exceptions import LogAlertRuntimeError

if TYPE_CHECKING:
    from collections import List


from jsonlogalert.logentry import LogEntry
from jsonlogalert.logservice import LogService
from jsonlogalert.logsourceparser import LogSourceParser
from jsonlogalert.utils import read_config_file

MAX_PARSE_STREAM_FAIL_MSGS = 10
INCLUDE_FILTER_ALL = "*"
TIMESTAMP_FIELD_DEFAULT = "TIMESTAMP"
MESSAGE_FIELD_DEFAULT = "MESSAGE"

# Services will augment these with SERVICE_FIELD_DEFAULTS.
SOURCE_FIELD_DEFAULTS = {
    "capture_fields": None,
    "conceal_fields": None,
    "description": None,
    "ignore_fields": None,
    "journal_dir": None,
    "max_log_entries": 250,
    "onelog": False,
    "output_content_type": None,
    "output_devnull": False,
    "output_file_dir": None,
    "output_file_name": None,
    "output_smtp_auth_password": None,
    "output_smtp_auth_ssl": False,
    "output_smtp_auth_tls": False,
    "output_smtp_auth_username": None,
    "output_smtp_host": "localhost",
    "output_smtp_port": 25,
    "output_smtp_rcpt_name": None,
    "output_smtp_rcpt": None,
    "output_smtp_sender_name": None,
    "output_smtp_sender": None,
    "output_smtp_subject": "Unusual %SERVICEDESC% activity",
    "output_stdout": False,
    "output_template_file": None,
    "output_template_minify_html": False,
    "tail_debug": False,
    "tail_file_bin": "logtail2",
    "tail_file_paths": None,
    "tail_ignore": False,
    "tail_journal_bin": "logtail-journal",
    "tail_journal_dir": None,
    "tail_journal_since": "boot",
    "tail_reset": False,
    "tail_state_dir": "/var/lib/misc",
}

######################################################################
# LogSource


class LogSource:
    """Log source object."""

    def __init__(self, source_dir: Path, source_config: dict[str, Any]) -> None:
        """Constructor.

        Args:
            source_dir (Path): Path to directory containing log source configuration.
            source_config (dict[str, Any]): Log source configuration.
        """
        assert isinstance(source_config, dict)

        self.source_dir = source_dir
        self.source_config = source_config

        self.timestamp_field_default = TIMESTAMP_FIELD_DEFAULT
        self.message_field_default = MESSAGE_FIELD_DEFAULT

        # These need to be reset() between iterations
        self.log_services: tuple[LogService] = None

        # Will be an integer index if source is copied by deaggregate()
        self.replica_index = None

    def __repr__(self) -> str:
        """Return the “official” string representation of an object.

        Returns:
            str
        """
        class_name = type(self).__name__
        return f"{class_name}({self.source_dir}, {len(self.log_services)} services)"

    def __getattr__(self, key: str) -> str | None:
        """Return source config field value using attribute notation.

        Args:
            key (str): Field

        Returns:
            Optional[Any]: Field value
        """
        # This is how we implement this everywhere else:
        #
        # > if key not in self.source_config:
        # >     raise AttributeError(key)
        # > return self.source_config[key]
        #
        # But we use copy() on and it blows up with infinite recursion unless we use __dict__.
        # > RecursionError: maximum recursion depth exceeded in comparison
        #
        # I'm hoping it was solved in Python 3.12:
        # https://github.com/python/cpython/issues/103272

        try:
            return self.__dict__["source_config"][key]
        except KeyError:
            pass

        return super().__getattr__(key)

    # Cannot be a cached_property because name changes after deaggregate()
    @property
    def name(self) -> str:
        """Source name.

        Returns:
            str
        """
        if self.replica_index is not None:
            return f"{self.source_dir.name}[{self.replica_index}]"
        return self.source_dir.name

    @cached_property
    def enabled(self) -> bool:
        """True if service is enabled.

        Returns:
            bool
        """
        return bool(self.source_config.get("enabled", True))

    @cached_property
    def timestamp_field(self) -> str:
        """Log entry timestamp field for this source.

        Returns:
            str
        """
        return self.source_config.get("timestamp_field", self.timestamp_field_default)

    @cached_property
    def message_field(self) -> str:
        """Log entry message field for this source.

        Returns:
            str
        """
        return self.source_config.get("message_field", self.message_field_default)

    @cached_property
    def source_parser_path(self) -> Path:
        """Path to source parser module.

        Returns:
            Path
        """
        return self.source_dir / "source_parser.py"

    @cached_property
    def field_converters(self) -> dict[str, callable] | None:
        """Dictionary of converters to convert log entry values into native data types.

        Converters will be applied to captured fields

        Returns:
            Optional[dict[str, callable]]
        """
        return self.source_parser.field_converters

    @cached_property
    def onelog(self) -> bool:
        """True if 'logfiles' should be treated as one log.

        Returns:
            bool
        """
        return bool(self.source_config.get("onelog", False))

    def load_conf(self, cli_config: dict[str, Any], default_config: dict[str, Any]) -> None:
        """Apply source configuration and load service configurations.

        Args:
            cli_config (dict): Command line configuration options.
            default_config (dict): Default configuration options.
        """
        # Merge configs in order of precedence (before services are loaded!)
        self.source_config = SOURCE_FIELD_DEFAULTS | default_config | self.source_config | cli_config

        # These are unnecessary at runtime and don't need to show up in print_conf()
        for remove_directive in ["sources", "services"]:
            if remove_directive in self.source_config:
                del self.source_config[remove_directive]

        if self.source_parser_path.is_file():
            self.load_parser()
        else:
            self.source_parser = LogSourceParser(self)

        self.log_services = LogService.load_services(self, cli_config)

        if not self.log_services:
            # Consider ourself disabled if we have no services (perhaps all are disabled).
            self.enabled = False

        self.validate_conf()

    def load_parser(self) -> None:
        """Load source custom parser, if defined."""

        def _raise_load_parser_failure(err: str | Exception) -> None:
            message = f"Failed to load parser for log source '{self.name}': {self.source_parser_path}: {err}"

            if isinstance(err, Exception):
                raise LogAlertRuntimeError(message) from err
            raise LogAlertRuntimeError(message)

        spec = importlib.util.spec_from_file_location(self.source_parser_path.stem, self.source_parser_path)

        if not spec:
            _raise_load_parser_failure("Failed to determine loader spec")

        try:
            source_parser_module = importlib.util.module_from_spec(spec)
        except ImportError as err:
            _raise_load_parser_failure(err)
        else:
            spec.loader.exec_module(source_parser_module)

        if not source_parser_module:
            _raise_load_parser_failure("Failed to import module")

        try:
            self.source_parser = source_parser_module.LogAlertLogSourceParser(self)
        except AttributeError as err:
            _raise_load_parser_failure(err)

        if not self.source_parser:
            _raise_load_parser_failure("Source parser is not implemented")

    def tail_exec(self, exec_args: tuple[str]) -> None:
        """Execute a tail command and read its output with `parse_stream`.

        Args:
            exec_args (tuple[str]): Tail command line.

        Raises:
            LogAlertRuntimeError: Tail failed.
        """
        pipe_options = {
            "stdin": None,
            "stdout": subprocess.PIPE,
            "stderr": subprocess.PIPE,
            "bufsize": 1,
            "universal_newlines": True,
        }

        retcode = 100  # arbitrary
        stderr_data = "Popen failed"

        self.log_debug(f"Executing '{' '.join(exec_args)}'")

        with subprocess.Popen(exec_args, **pipe_options) as ps_tail:  # noqa: S603
            try:
                self.parse_stream(ps_tail.stdout, "<stdout>")
            except AssertionError:
                raise
            except Exception as err:
                # Wait for process to exit
                stderr_data = ps_tail.communicate()[1]
                retcode = ps_tail.returncode

                if retcode == 0:
                    raise LogAlertRuntimeError(f"Parse tail stream failed: {err}") from err
            else:
                # Wait for process to exit
                stderr_data = ps_tail.communicate()[1]
                retcode = ps_tail.returncode

        if retcode != 0:
            raise LogAlertRuntimeError(f"Read tail failed: {stderr_data} ({' '.join(exec_args)} exited {retcode})")

    def parse_stream(self, log_file_stream: io.TextIOWrapper, stream_name: str) -> None:  # noqa: C901
        """Parse a file stream where each line is a JSON structured message.

        The file content is expected to be a series of objects each separated by a newline.
        It is not parsed as a large blob of JSON.

        Args:
            log_file_stream (io.TextIOWrapper): Open file.
            stream_name (str): Name of stream (for logging)
        """
        self.log_debug(f"Parsing stream {stream_name}...")

        line_count = 0
        fail_line_count = 0
        unclaimed_line_count = 0

        for log_line in log_file_stream:
            line_count += 1

            try:
                fields = self.parse_line(log_line)
            except LogAlertRuntimeError as err:
                if fail_line_count <= MAX_PARSE_STREAM_FAIL_MSGS:
                    self.log_warning(f"Failed to read log entry (line {line_count}): {err}")
                    if fail_line_count == MAX_PARSE_STREAM_FAIL_MSGS:
                        self.log_warning(f">{MAX_PARSE_STREAM_FAIL_MSGS} warnings; failure messages will be suppressed")

                fail_line_count += 1
            else:
                claimed = False

                log_entry = self.create_log_entry(fields)

                # Add line to service that claims it
                for service in self.log_services:
                    if service.claim_entry(log_entry):
                        claimed = True
                        break

                if not claimed:
                    unclaimed_line_count += 1

        self.log_debug(f"Read {line_count} lines from stream")

        if fail_line_count:
            self.log_error(f"Failed to parse {fail_line_count} lines from stream")

        if unclaimed_line_count:
            self.log_error(f"Failed to claim {unclaimed_line_count} lines from stream")

    def parse_line(self, log_line: str) -> dict:
        """Parse source log entry into a dict of structured fields.

        Args:
            log_line (str): Log entry from source.

        Raises:
            LogAlertRuntimeError: Parse failed.

        Returns:
            dict
        """
        fields_or_exception = self.source_parser.parse_line(log_line)

        if not fields_or_exception:
            raise LogAlertRuntimeError("Failed to convert log line to dict")
        if isinstance(fields_or_exception, Exception):
            raise LogAlertRuntimeError(f"{fields_or_exception}")
        if not isinstance(fields_or_exception, dict):
            raise LogAlertRuntimeError("Parser did not return a dict")

        return fields_or_exception

    def create_log_entry(self, rawfields: dict) -> LogEntry:
        """Create a LogEntry object from a JSON string.

        Args:
            rawfields (dict): Log line fields and values.

        Returns:
            LogEntry
        """
        # Convert fields to native types
        if self.field_converters:
            for field, fn in self.field_converters.items():
                if field in rawfields:
                    rawfields[field] = fn(rawfields[field])

        return LogEntry(rawfields, self.timestamp_field, self.message_field)

    def tail_source(self) -> None:
        """Tail log source as configured.

        Must be implemented in derived classes.
        """
        raise NotImplementedError

    def get_tail_state_path(self, log_file_path: Path) -> Path:
        """Generate file path to use as a tail offset/cursor state file given a log file path.

        Args:
            log_file_path (Path): Log file path

        Returns:
            Path
        """
        # NOTE: Filespec must match glob used in `_delete_tail_state_files`
        return self.tail_state_dir / re.sub(
            r"[^a-z0-9_.]+",
            "-",
            f"jsonlogalert-{log_file_path}.offset",
            flags=re.IGNORECASE,
        )

    def output(self) -> None:
        """Output results for log source services."""
        for log_service in self.log_services:
            log_service.output()

    def validate_conf(self) -> None:
        """Review source configuration directives and see if they make sense."""
        if not self.message_field_default:
            raise LogAlertRuntimeError(f"{self.name}: Log source 'message_field' directive is not set.")

        if not self.timestamp_field_default:
            raise LogAlertRuntimeError(f"{self.name}: Log source 'timestamp_field' directive is not set.")

        if not self.tail_state_dir:
            raise LogAlertRuntimeError("'tail_state_dir' directive is not set.")
        if not self.tail_state_dir.is_dir():
            raise LogAlertRuntimeError(f"{self.tail_state_dir}: No such directory")

        select_all = [service.name for service in self.log_services if not service.select_rules and not service.drop_rules]
        if len(select_all) > 1:
            # It's ok if a single service wants all events (a catchall) but seems odd if 2+ do
            self.log_warning(f"{len(select_all)} services are configured to select all log entries ({', '.join(select_all)})")

    def force_enable(self) -> None:
        """Enable source and all it's services."""
        for log_service in self.log_services:
            log_service.enabled = True

        self.enabled = len(self.log_services) > 0

    def filter_disabled_services(self) -> None:
        """Filter out disabled services."""
        if self.log_services:
            disabled_services = [s for s in self.log_services if not s.enabled]
            self.log_services = [s for s in self.log_services if s.enabled]

            if self.log_services:
                self.log_debug(f"{len(self.log_services)} enabled services: [{', '.join([d.name for d in self.log_services])}]")
                if disabled_services:
                    self.log_debug(f"{len(disabled_services)} disabled services: [{', '.join([d.name for d in disabled_services])}]")
            else:
                self.log_info("No enabled services; source will be disabled")

        self.enabled = len(self.log_services) > 0

    def deaggregate(self) -> List[LogSource]:
        """Return a new list of sources after deaggreating logs.

        Returns:
            List[LogSource]
        """
        return [self]

    def reset(self) -> None:
        """Reset source internals to prepare for another source log iteration."""
        for service in self.log_services:
            service.reset(self)

    def print_conf(self) -> None:
        """Print configuration for source and its services."""
        echo(f"Source: {self.name}")
        echo("=================")

        # Using !r uses repr() which quotes strings.
        for k, v in sorted(self.source_config.items()):
            if isinstance(v, Path):
                v = str(v)  # noqa: PLW2901
            echo(f"{k}: {v!r}")

        for log_service in self.log_services:
            echo("")
            log_service.print_conf()

    def log_debug(self, message: str) -> None:
        """Log a debug message related to this source.

        Args:
            message (str): Message.
        """
        logging.debug(f"{self.name}: {message}")

    def log_info(self, message: str) -> None:
        """Log a info message related to this source.

        Args:
            message (str): Message.
        """
        logging.info(f"{self.name}: {message}")

    def log_warning(self, message: str) -> None:
        """Log a warning message related to this source.

        Args:
            message (str): Message.
        """
        logging.warning(f"{self.name}: {message}")

    def log_error(self, message: str) -> None:
        """Log a error message related to this source.

        Args:
            message (str): Message.
        """
        logging.error(f"{self.name}: {message}")

    def raise_error(self, message: str, err: str | Exception | None = None) -> None:
        """Raise a 'LogAlertRuntimeError' exception related to this source.

        Args:
            message (str): Message.
            err (str | Exception | None): Error message or exception.

        Raises:
            LogAlertRuntimeError
        """
        if err:
            raise LogAlertRuntimeError(f"{message} '{self.fullname}': {err}")
        raise LogAlertRuntimeError(f"{message} '{self.fullname}'")

    ######################################################################
    # Helper functions

    @staticmethod
    def _create_source(source_dir: Path) -> LogSource | None:
        """Create a LogSource object based on its source configuration.

        Args:
            source_dir (Path): Path to log source configuration.

        Returns:
            Optional[LogSource]: A LogSource object or None if directory does not appear to be a source.

        Raises:
            LogAlertRuntimeError: Failed to load log source configuration.
        """
        assert source_dir.is_dir()

        source_config_path = source_dir / "source.yaml"

        try:
            source_config = read_config_file(source_config_path)
        except LogAlertRuntimeError as err:
            raise LogAlertRuntimeError(f"{source_dir.name}: Failed to open '{source_config_path.name}': {err}") from err

        if not source_config:
            # Not fatal
            logging.warning(f"{source_dir}: Skipping source directory; '{source_config_path.name}' is missing")
            return None

        from jsonlogalert.logsource_file import LogSourceTextFile
        from jsonlogalert.logsource_journal import LogSourceSystemdJournal

        # Default source is TextFile since the source can be
        # defined and 'logfiles' specified on the command line.
        source_class = LogSourceTextFile

        if source_config.get("journal_dir"):
            source_class = LogSourceSystemdJournal

        return source_class(source_dir, source_config)

    @staticmethod
    def load_sources(config_dir: Path, cli_config: dict[str, Any], default_config: dict[str, Any]) -> tuple[LogSource]:
        """Iterate source directories and create LogSource objects with each enabled source.

        Args:
            config_dir (Path): Path to root source directory.
            cli_config (dict): Command line configuration options.
            default_config (dict): Default configuration options.

        Returns:
            tuple[LogSource]

        Raises:
            LogAlertRuntimeError: Failed to load sources.
        """
        assert config_dir.is_dir()

        log_sources: list[LogSource] = []

        log_source_dirs = sorted(d for d in config_dir.iterdir() if d.is_dir())
        if not log_source_dirs:
            raise LogAlertRuntimeError(
                f"'{config_dir}': Configuration directory contains no subdirectories; see '--config-dir' or 'config_dir' directive"
            )

        logging.debug(f"Configuration directory '{config_dir}' has {len(log_source_dirs)} sources")

        for source_dir in log_source_dirs:
            log_source = LogSource._create_source(source_dir)

            if log_source:
                log_source.load_conf(cli_config, default_config)
                log_sources.append(log_source)

        if not log_sources:
            raise LogAlertRuntimeError(f"'{config_dir}': No log sources found")

        return LogSource._apply_include_exclude_filters(log_sources, cli_config, default_config)

    @staticmethod
    def _include_exclude_list(names: Sequence[str]) -> tuple[list, list]:
        """Splits a list of names into include and exclude lists.

        Args:
            names (Sequence[str]): List of source or service names.

        Returns:
            tuple[list, list]: [Include, Exclude]
        """
        include_names = []
        exclude_names = []

        for name in names:
            if name.startswith("!"):
                exclude_names.append(name.removeprefix("!"))
            else:
                include_names.append(name)

        return include_names, exclude_names

    @staticmethod
    def _filter_disabled_sources(sources: Sequence[LogSource]) -> Sequence[LogSource]:
        """Return list of enabled sources.

        Args:
            sources (Sequence[LogSource]): List of sources.

        Returns:
            Sequence[LogSource]: List of sources.
        """
        if sources:
            disabled_sources = [s for s in sources if not s.enabled]
            sources = [s for s in sources if s.enabled]

            if sources:
                logging.debug(f"{len(sources)} sources enabled: [{', '.join([d.name for d in sources])}]")
                if disabled_sources:
                    logging.debug(f"{len(disabled_sources)} sources disabled: [{', '.join([d.name for d in disabled_sources])}]")
            else:
                logging.info("All sources are disabled")

        return sources

    @staticmethod
    def _apply_include_exclude_filters(  # noqa: C901, PLR0912
        sources: Sequence[LogSource],
        cli_config: dict[str, Any],
        default_config: dict[str, Any],
    ) -> tuple[LogSource]:
        """Filter sources and services based on configurations.

        Args:
            sources (Sequence[LogSource]): List of sources.
            cli_config (dict): Command line configuration options.
            default_config (dict): Default configuration options.

        Returns:
            tuple[LogSource]

        Raises:
            LogAlertRuntimeError: Invalid configuration.
        """
        include_sources, exclude_sources = LogSource._include_exclude_list(cli_config.get("sources") or default_config.get("sources"))
        include_services, exclude_services = LogSource._include_exclude_list(cli_config.get("services") or default_config.get("services"))

        if include_sources and exclude_sources:
            raise LogAlertRuntimeError("You cannot include some sources and exclude others at the same time")
        if include_services and exclude_services:
            raise LogAlertRuntimeError("You cannot include some services and exclude others at the same time")

        # Include and exclude sources
        if exclude_sources:
            sources = [s for s in sources if s.name not in exclude_sources]
        if include_sources and INCLUDE_FILTER_ALL not in include_sources:
            sources = [s for s in sources if s.name in include_sources]

        if include_sources or exclude_sources:
            logging.debug(f"Only loading sources: {', '.join([d.name for d in sources])}")
        else:
            logging.debug(f"Loading sources: {', '.join([d.name for d in sources])}")

        if len(sources) > 1:
            if include_services:
                raise LogAlertRuntimeError(f"Must use '--source' to define the SOURCE for included services: {', '.join(include_services)}")
            if exclude_services:
                raise LogAlertRuntimeError(f"Must use '--source' to define the SOURCE for excluded services: {', '.join(exclude_services)}")

        if include_services or exclude_services:
            # Include and exclude services
            assert len(sources) == 1
            source = sources[0]
            if exclude_services:
                source.log_services = [s for s in source.log_services if s.name not in exclude_services]
            if include_services and INCLUDE_FILTER_ALL not in include_services:
                source.log_services = [s for s in source.log_services if s.name in include_services]

            logging.debug(f"Only loading services: {', '.join([d.name for d in source.log_services])}")

        if include_sources or exclude_sources or include_services or exclude_services:
            # Since sources and services are explicitly referenced we enable everything
            for source in sources:
                source.force_enable()

        for source in sources:
            # Remove whatever services are disabled
            source.filter_disabled_services()

        sources = LogSource._filter_disabled_sources(sources)
        if not sources:
            raise LogAlertRuntimeError("No log sources enabled")

        if include_sources and INCLUDE_FILTER_ALL not in include_sources:
            # Ensure we find everything we are looking for
            for source_name in include_sources:
                found_sources = tuple(s for s in sources if s.name == source_name)
                if not found_sources:
                    raise LogAlertRuntimeError(f"{source_name}: No such source")

        if include_services and INCLUDE_FILTER_ALL not in include_services:
            # Ensure we find everything we are looking for
            assert len(sources) == 1
            source = sources[0]
            for service_name in include_services:
                found_services = tuple(s for s in source.log_services if s.name == service_name)
                if not found_services:
                    raise LogAlertRuntimeError(f"{service_name}: Log source '{source.name}' has no such service")

        return tuple(sources)
