from __future__ import annotations

import socket
import sys
from datetime import datetime
from pathlib import Path
from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    import io
    from collections.abc import Sequence

import importlib.util
import logging
import os
import re
import subprocess
import time
from functools import cached_property

from click import echo

if TYPE_CHECKING:
    from collections import List

from jsonlogalert.confcheck import SOURCE_CONF_DEFAULTS, source_conf_check, source_conf_clean
from jsonlogalert.exceptions import LogAlertConfigError, LogAlertParserError, LogAlertTailError
from jsonlogalert.logentry import LogEntry
from jsonlogalert.logservice import LogService
from jsonlogalert.logsourceparser import LogSourceParser
from jsonlogalert.utils import read_config_file

MAX_PARSE_STREAM_FAIL_MSGS = 10
INCLUDE_FILTER_ALL = "*"
TIMESTAMP_FIELD_DEFAULT = "TIMESTAMP"
MESSAGE_FIELD_DEFAULT = "MESSAGE"
DEFAULT_BLOB_FIELDS = {MESSAGE_FIELD_DEFAULT}
BATCH_MAX_SEC = 50  # just shy of one minute seems good

# Capture microseconds in ISO 8061 timestamp
RE_TIMESTAMP_MICRO = re.compile(r"\.(\d{4,})")


######################################################################
# LogSource


class LogSource:
    """Log source object."""

    # Shared among all sources
    hostname = None
    hostfqdn = None
    hostdomain = None

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

        self.batch_count = 0

        # These need to be reset() between iterations
        self.services: tuple[LogService] = None

        # Will be an integer index if source is copied by deaggregate()
        self.replica_index = None

    def __repr__(self) -> str:
        """Return the “official” string representation of an object.

        Returns:
            str
        """
        class_name = type(self).__name__
        return f"{class_name}({self.source_dir}, {len(self.services)} services)"

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

        raise AttributeError(f"'{type(self).__name__}' object has no attribute '{key}'")

    @cached_property
    def basename(self) -> str:
        """Source base name.

        Returns:
            str
        """
        return self.source_dir.name

    # Cannot be a cached_property because name changes after deaggregate()
    @property
    def name(self) -> str:
        """Source name.

        Returns:
            str
        """
        return self.basename if self.replica_index is None else f"{self.basename}[{self.replica_index}]"

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
        return self.source_config.get("timestamp_field") or self.timestamp_field_default

    @cached_property
    def message_field(self) -> str:
        """Log entry message field for this source.

        Returns:
            str
        """
        return self.source_config.get("message_field") or self.message_field_default

    @cached_property
    def blob_fields(self) -> set:
        """Set of blob fields.

        Returns:
            set
        """
        blob_fields = self.source_config.get("blob_fields")
        blob_fields = set(blob_fields) if blob_fields else set()
        return blob_fields | DEFAULT_BLOB_FIELDS

    @cached_property
    def promote_fields(self) -> list | None:
        """List of fields to promote.

        Returns:
            list
        """
        return self.source_config.get("promote_fields") or None

    @cached_property
    def rename_fields(self) -> dict | None:
        """Dictionary of fields to rename.

        Returns:
            dict
        """
        return self.source_config.get("rename_fields") or None

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
        return self.source_parser.field_converters or None

    @cached_property
    def onelog(self) -> bool:
        """True if 'logfiles' should be treated as one log.

        Returns:
            bool
        """
        return bool(self.source_config.get("onelog", False))

    @property
    def is_replica(self) -> bool:
        """Return True if this source is a deaggregation replica.

        Returns:
            bool
        """
        return self.replica_index is not None

    def load_conf(self, cli_config: dict[str, Any], default_config: dict[str, Any]) -> None:
        """Apply source configuration and load service configurations.

        Args:
            cli_config (dict): Command line configuration options.
            default_config (dict): Default configuration options.
        """
        # We do this once here so we fail early
        if LogSource.hostname is None:
            try:
                LogSource.hostname = socket.gethostname()
                LogSource.hostfqdn = socket.getfqdn() or LogSource.hostname
            except OSError as err:
                raise LogAlertConfigError(err) from err

            LogSource.hostdomain = LogSource.hostfqdn.replace(f"{LogSource.hostname}.", "", 1) or LogSource.hostname

            if LogSource.hostfqdn == LogSource.hostname:
                logging.info(f"Hostname and FQDN are both '{LogSource.hostname}'")

        # Sanity check configuration settings (it's easy to get confused what option goes where!)
        source_conf_check(self)

        # Merge configs in order of precedence (before services are loaded!)
        self.source_config = dict(sorted((SOURCE_CONF_DEFAULTS | default_config | self.source_config | cli_config).items()))

        # Delete settings that do not pertain to sources and don't need to show up in print_conf()
        source_conf_clean(self)

        if self.source_parser_path.is_file():
            self.load_parser()
        else:
            self.source_parser = LogSourceParser(self)

        # Convert timestamp field along with other fields
        if self.timestamp_field_format:
            if self.timestamp_field in self.source_parser.field_converters:
                self.config_error(f"'{self.timestamp_field}': Field converter already set; 'timestamp_field_format' cannot be applied.")

            if self.timestamp_field_format == "iso":
                ts_func = LogSource.fromisoformat if sys.version_info < (3, 11, 0) else datetime.fromisoformat
            else:
                ts_func = lambda ts: datetime.strptime(ts, self.timestamp_field_format)  # noqa: DTZ007, E731

            self.source_parser.field_converters[self.timestamp_field] = ts_func

        self.services = LogService.load_services(self, cli_config)

        if not self.services:
            # Consider ourself disabled if we have no services (perhaps all are disabled).
            self.enabled = False

        self.validate_conf()

    def load_parser(self) -> None:
        """Load source custom parser, if defined."""

        def _raise_load_parser_failure(err: str | Exception) -> None:
            message = f"Failed to load parser for log source '{self.name}': {self.source_parser_path}: {err}"

            if isinstance(err, Exception):
                raise LogAlertConfigError(message) from err
            raise LogAlertConfigError(message)

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

    def scan_stream_exec(self, exec_args: tuple[str]) -> int:
        """Execute a command and scan its output with `scan_stream`.

        Args:
            exec_args (tuple[str]): Command arguments.

        Returns:
            Number of log lines scanned.

        Raises:
            LogAlertTailError: Tail failed.
        """

        def _tail_exc_msg(message: str, err: str | Exception, retcode: int | None) -> str:
            """Return tail exec failure exception message.

            Args:
                message (str): Error message.
                err (str | Exception): Failure exception or stderr output.
                retcode (int | None): Pipe return code or None.

            Returns:
                str
            """
            msg_parts = [
                message,
                str(err).rstrip(),
                f"'{' '.join(exec_args)}'",
            ]

            if retcode is not None:
                msg_parts.append(f"exit code {retcode}")

            return ": ".join(msg_parts)

        pipe_options = {
            "stdin": None,
            "stdout": subprocess.PIPE,
            "stderr": subprocess.PIPE,
            "bufsize": 1,
            "encoding": "utf-8",
            "universal_newlines": True,
        }

        self.log_debug(f"Executing '{' '.join(exec_args)}'")

        line_count = 0

        try:
            with subprocess.Popen(exec_args, **pipe_options) as ps_tail:  # noqa: S603
                try:
                    line_count += self.scan_stream(ps_tail.stdout, "<stdout>")

                except Exception as err:
                    # Wait for process to exit
                    stderr_data = ps_tail.communicate()[1]
                    retcode = ps_tail.returncode

                    if retcode == 0:
                        raise LogAlertTailError(_tail_exc_msg("Parse tail stream failed", err, None)) from err
                else:
                    # Wait for process to exit
                    stderr_data = ps_tail.communicate()[1]
                    retcode = ps_tail.returncode

                    if retcode != 0:
                        raise LogAlertTailError(_tail_exc_msg("Exec tail failed", stderr_data, retcode))

        except (TypeError, ValueError) as err:
            raise LogAlertTailError(_tail_exc_msg("Exec tail Popen failed", err, retcode)) from err

        return line_count

    def scan_stream(self, log_file_stream: io.TextIOWrapper, stream_name: str) -> int:
        """Parse a file stream where each line is a JSON structured message.

        The file content is expected to be a series of objects each separated by a newline.
        It is not parsed as a large blob of JSON.

        Args:
            log_file_stream (io.TextIOWrapper): Open file.
            stream_name (str): Name of stream (for logging)

        Returns:
            Number of log lines scanned.
        """
        self.log_debug(f"Parsing stream {stream_name}...")

        line_count = 0
        fail_line_count = 0
        unclaimed_line_count = 0

        for stream_line in log_file_stream:
            line_count += 1
            log_line = stream_line.rstrip()

            try:
                fields = self.parse_line(log_line)
                self.apply_field_converters(fields, log_line)
                log_entry = LogEntry(fields, self.timestamp_field, self.message_field)
                claimed = any(service.claim_entry(log_entry) for service in self.services)
            except (LogAlertParserError, TypeError, ValueError, KeyError) as err:
                if fail_line_count <= MAX_PARSE_STREAM_FAIL_MSGS:
                    self.log_warning(f"Failed to parse log entry (line {line_count}): {err}")
                    if fail_line_count == MAX_PARSE_STREAM_FAIL_MSGS:
                        self.log_warning(f">{MAX_PARSE_STREAM_FAIL_MSGS} warnings; failure messages will be suppressed")

                fail_line_count += 1
            else:
                if not claimed:
                    unclaimed_line_count += 1

        self.log_debug(f"Read {line_count} lines from stream")

        if fail_line_count:
            self.log_error(f"Failed to parse {fail_line_count} lines from stream")

        if unclaimed_line_count:
            self.log_error(f"Failed to claim {unclaimed_line_count} lines from stream")

        return line_count

    def parse_line(self, log_line: str) -> dict:
        """Parse source log entry into a dict of structured fields.

        Args:
            log_line (str): Log entry from source.

        Raises:
            LogAlertParserError: Parse failed.

        Returns:
            dict
        """
        fields = self.source_parser.parse_line(log_line)

        if not fields:
            raise LogAlertParserError("Parser returned an empty dict")
        if not isinstance(fields, dict):
            raise LogAlertParserError(f"Parser returned type '{type(fields).__name__}'; expected 'dict'")

        return fields

    def apply_field_converters(self, rawfields: dict, log_line: str) -> None:  # noqa: C901
        """Convert field values to native types using `self.field_converters`.

        Args:
            rawfields (dict): Log entry fields and values.
            log_line (str): Log line.
        """
        if self.promote_fields:
            for field in self.promote_fields:
                if field in rawfields:
                    promote_dict = rawfields[field]
                    if promote_dict:
                        if not isinstance(promote_dict, dict):
                            raise LogAlertParserError(
                                f"Field promotion failed: '{field}': type is '{type(promote_dict).__name__}'; expected 'dict': '{log_line}'"
                            )
                        promote_dict = {f"{field}_{k}": v for k, v in promote_dict.items()}
                        del rawfields[field]
                        rawfields.update(promote_dict)

        if self.rename_fields:
            for field, new_field in self.rename_fields.items():
                if field in rawfields:
                    rawfields[new_field] = rawfields[field]
                    del rawfields[field]

        # Convert fields to native types
        if self.field_converters:
            for field, fn in self.field_converters.items():
                if field in rawfields:
                    try:
                        rawfields[field] = fn(rawfields[field])
                    except ValueError as err:
                        raise LogAlertParserError(f"Field conversion failed: '{field}': {err}: '{log_line}'") from err

    def scan_source(self) -> int:
        """Scan log source once.

        Must be implemented in derived classes.

        Returns:
            Number of log lines scanned.

        Raises:
            LogAlertTailError: Tail failed.
        """
        raise NotImplementedError

    def scan_source_batch(self) -> int:
        """Scan log source and batch activity if configured.

        Returns:
            Number of log lines scanned.

        Raises:
            LogAlertTailError: Tail failed.
        """
        wait_sec = self.wait_sec
        batch_interval = self.batch_interval
        max_logentries = int(self.max_logentries * 0.75)
        batch_line_count = 0

        # Only wait on first batch
        if wait_sec and not self.batch_count:
            self.log_debug(f"Waiting {wait_sec}s before scan...")
            time.sleep(wait_sec)

        start_time = time.monotonic()

        while True:
            self.batch_count += 1

            line_count = self.scan_source()
            batch_line_count += line_count

            if not batch_interval:
                # Once and done!
                break

            if not line_count:
                self.log_debug("Batch ended; no activity")
                break

            self.log_debug(f"Batch continued; {line_count} more lines scanned")

            if max_logentries < batch_line_count:
                self.log_debug(f"Batch ended; >{max_logentries} lines scanned")
                break

            elapsed_time = time.monotonic() - start_time
            if elapsed_time > BATCH_MAX_SEC:
                self.log_debug(f"Batch ended; >{BATCH_MAX_SEC}s elapsed")
                break

            self.log_debug(f"Waiting {batch_interval}s for more log activity...")
            time.sleep(batch_interval)

        return batch_line_count

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
        for log_service in self.services:
            log_service.output()

            # Micro optimization - release logentries after output.
            log_service.reset(self)

    def validate_conf(self) -> None:
        """Review source configuration directives and see if they make sense.

        Raises:
            LogAlertConfigError
        """
        if not self.hostname:
            self.config_error("Failed to resolve hostname.")

        if not self.message_field_default:
            self.config_error("'message_field' directive is not set.")

        if not self.timestamp_field_default:
            self.config_error("'timestamp_field' directive is not set.")

        if not self.tail_state_dir:
            self.config_error("'tail_state_dir' directive is not set.")

        catchalls = [service.name for service in self.services if service.is_catchall]
        if len(catchalls) > 1:
            self.config_error(f"{len(catchalls)} services are configured to claim all log entries: [{', '.join(catchalls)}]")

    def validate_scan(self) -> None:
        """Review scan configuration directives and see if they make sense.

        Raises:
            LogAlertConfigError
        """
        if not self.dry_run:
            if not self.tail_state_dir.is_dir():
                self.config_error(f"'{self.tail_state_dir}': No such directory")
            if not os.access(self.tail_state_dir, os.W_OK | os.X_OK):
                self.config_error(f"'tail_state_dir' '{self.tail_state_dir}' requires write permission")

        for log_service in self.services:
            log_service.validate_scan()

    def force_enable(self) -> None:
        """Enable source and all it's services."""
        for log_service in self.services:
            log_service.enabled = True

        self.enabled = len(self.services) > 0

    def filter_disabled_services(self) -> None:
        """Filter out disabled services."""
        if self.services:
            disabled_services = [s for s in self.services if not s.enabled]
            self.services = [s for s in self.services if s.enabled]

            if self.services:
                self.log_debug(f"{len(self.services)} enabled services: [{', '.join([d.name for d in self.services])}]")
                if disabled_services:
                    self.log_debug(f"{len(disabled_services)} disabled services: [{', '.join([d.name for d in disabled_services])}]")
            else:
                self.log_info("No enabled services; source will be disabled")

        self.enabled = len(self.services) > 0

    def deaggregate(self) -> List[LogSource]:
        """Return a new list of sources after deaggreating logs.

        Returns:
            List[LogSource]
        """
        return [self]

    def reset(self) -> None:
        """Reset source internals to prepare for another source log iteration."""
        for service in self.services:
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

        for log_service in self.services:
            echo("")
            log_service.print_conf()

    def print_field_types(self) -> None:
        """Print source field types."""
        echo(f"Source: {self.name}")
        echo("=================")

        # Using !r uses repr() which quotes strings.
        for k, v in sorted(self.field_converters.items()):
            if k == self.timestamp_field and self.timestamp_field_format:
                echo(f"{k}: datetime({self.timestamp_field_format!r})")
            else:
                echo(f"{k}: {v.__name__!r}")

        for log_service in self.services:
            if log_service.field_types:
                echo("")
                log_service.print_field_types()

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

    def config_error(self, message: str, err: str | Exception | None = None) -> None:
        """Raise a 'LogAlertConfigError' exception related to this source.

        Args:
            message (str): Message.
            err (str | Exception | None): Error message or exception.

        Raises:
            LogAlertConfigError
        """
        if err:
            raise LogAlertConfigError(f"{self.name}: {message}: {err}")
        raise LogAlertConfigError(f"{self.name}: {message}")

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
            LogAlertConfigError: Failed to load log source configuration.
        """
        assert source_dir.is_dir()

        source_config_path = source_dir / "source.yaml"

        try:
            source_config = read_config_file(source_config_path)
        except LogAlertConfigError as err:
            raise LogAlertConfigError(f"{source_dir.name}: Failed to open '{source_config_path.name}': {err}") from err

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
            LogAlertConfigError: Failed to load sources.
        """
        assert config_dir.is_dir()

        sources: list[LogSource] = []

        source_names = list(cli_config.get("sources") or default_config.get("sources") or [])
        service_names = list(cli_config.get("services") or default_config.get("services") or [])

        # Handle "--source source/service"
        for i, source_and_service in enumerate(source_names):
            if "/" in source_and_service:
                source_name, service_name = source_and_service.split("/", 1)
                source_names[i] = source_name
                service_names.append(service_name)

        include_sources, exclude_sources = LogSource._include_exclude_list(source_names)
        include_services, exclude_services = LogSource._include_exclude_list(service_names)

        source_dirs = sorted(d for d in config_dir.iterdir() if d.is_dir())
        if not source_dirs:
            raise LogAlertConfigError(
                f"'{config_dir}': Configuration directory contains no subdirectories; see '--config-dir' or 'config_dir' directive"
            )

        logging.debug(f"Configuration directory '{config_dir}' has {len(source_dirs)} sources")

        source_dirs = LogSource._filter_source_dirs(source_dirs, include_sources, exclude_sources)
        if not source_dirs:
            raise LogAlertConfigError("No log sources selected.")

        for source_dir in source_dirs:
            log_source = LogSource._create_source(source_dir)

            if log_source:
                log_source.load_conf(cli_config, default_config)
                sources.append(log_source)

        if not sources:
            raise LogAlertConfigError("No log sources found.")

        LogSource._apply_filter_services(sources, include_services, exclude_services)

        if include_sources or exclude_sources or include_services or exclude_services:
            # Since sources and services are explicitly referenced we enable everything
            for source in sources:
                source.force_enable()

        for source in sources:
            # Remove any disabled services; may disable the source too.
            source.filter_disabled_services()

        sources = LogSource._get_enabled_sources(sources)
        if not sources:
            raise LogAlertConfigError("No log sources enabled")

        return tuple(sources)

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
    def _get_enabled_sources(sources: Sequence[LogSource]) -> tuple[LogSource]:
        """Return list of enabled sources.

        Args:
            sources (Sequence[LogSource]): List of sources.

        Returns:
            tuple[LogSource]: List of sources.
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

        return tuple(sources)

    @staticmethod
    def _filter_source_dirs(source_dirs: Sequence[Path], include_sources: Sequence[str], exclude_sources: Sequence[str]) -> tuple[LogSource]:
        """Filter source directories based on configurations.

        Args:
            source_dirs (Sequence[Path]): List of source directories.
            include_sources (Sequence[str]): List of sources to include.
            exclude_sources (Sequence[str]): List of sources to exclude.

        Raises:
            LogAlertConfigError: Invalid configuration.
        """
        if include_sources and exclude_sources:
            raise LogAlertConfigError("You cannot include some sources and exclude others at the same time")

        if exclude_sources:
            source_dirs = [d for d in source_dirs if d.name not in exclude_sources]
        if include_sources and INCLUDE_FILTER_ALL not in include_sources:
            source_dirs = [d for d in source_dirs if d.name in include_sources]

        if include_sources or exclude_sources:
            logging.debug(f"Only loading sources: [{', '.join([d.name for d in source_dirs])}]")
        else:
            logging.debug(f"Loading sources: [{', '.join([d.name for d in source_dirs])}]")

        if include_sources and INCLUDE_FILTER_ALL not in include_sources:
            # Ensure we find everything we are looking for
            for source_name in include_sources:
                found_sources = tuple(s for s in source_dirs if s.name == source_name)
                if not found_sources:
                    raise LogAlertConfigError(f"{source_name}: No such source")

        return tuple(source_dirs)

    @staticmethod
    def _apply_filter_services(sources: Sequence[LogSource], include_services: Sequence[str], exclude_services: Sequence[str]) -> None:  # noqa: C901
        """Filter services based on configurations.

        Args:
            sources (Sequence[LogSource]): List of sources.
            include_services (Sequence[str]): List of services to include.
            exclude_services (Sequence[str]): List of services to exclude.

        Raises:
            LogAlertConfigError: Invalid configuration.
        """
        if include_services and exclude_services:
            raise LogAlertConfigError("You cannot include some services and exclude others at the same time")

        if len(sources) > 1:
            if include_services:
                raise LogAlertConfigError(f"Must use '--source' to define the SOURCE for included services: {', '.join(include_services)}")
            if exclude_services:
                raise LogAlertConfigError(f"Must use '--source' to define the SOURCE for excluded services: {', '.join(exclude_services)}")

        if include_services or exclude_services:
            # Include and exclude services
            assert len(sources) == 1
            source = sources[0]
            if exclude_services:
                source.services = [s for s in source.services if s.name not in exclude_services]
            if include_services and INCLUDE_FILTER_ALL not in include_services:
                source.services = [s for s in source.services if s.name in include_services]

            logging.debug(f"Only loading services: {', '.join([d.name for d in source.services])}")

        if include_services and INCLUDE_FILTER_ALL not in include_services:
            # Ensure we find everything we are looking for
            assert len(sources) == 1
            source = sources[0]
            for service_name in include_services:
                found_services = tuple(s for s in source.services if s.name == service_name)
                if not found_services:
                    raise LogAlertConfigError(f"{source.name}/{service_name}: No such service")

    @staticmethod
    def fromisoformat(date_string: str) -> datetime:
        """Return a datetime corresponding to a date_string in any valid ISO 8601 format.

        Used for Python versions prior to 3.11 when the formats it suppors were expanded.

        Args:
            date_string (str): Timestamp in ISO format.

        Returns:
            datetime
        """
        if date_string.endswith("Z"):
            # fromisoformat does support "Z" time zone specifier until 3.11
            date_string = date_string.removesuffix("Z") + "+00:00"

        try:
            return datetime.fromisoformat(date_string)
        except ValueError:
            pass

        def _fix_micro(m: re.Match) -> str:
            micro = m.group(1)[:6].rjust(6, "0")
            return f".{micro}"

        # fromisoformat (and strptime %f) requires 6 digit microseconds.
        # I've seen timestamps with 5 and 9 digit microseconds.
        date_string = RE_TIMESTAMP_MICRO.sub(_fix_micro, date_string)

        # If this fails, scan_stream will catch and report exception
        return datetime.fromisoformat(date_string)
