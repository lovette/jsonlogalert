from __future__ import annotations

import logging
import re
from functools import cached_property
from pathlib import Path
from types import SimpleNamespace
from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from collections import List
    from collections.abc import Sequence

    from jsonlogalert.logentry import LogEntry
    from jsonlogalert.logsource import LogSource

from click import echo

from jsonlogalert.exceptions import LogAlertConfigError
from jsonlogalert.logalertoutput import LogAlertOutput, LogAlertOutputToDevNull, LogAlertOutputToStdout
from jsonlogalert.logalertoutput_file import LogAlertOutputToFile
from jsonlogalert.logalertoutput_smtp import LogAlertOutputToSMTP
from jsonlogalert.logfieldrule import FieldRule
from jsonlogalert.utils import read_config_file

# These are in addition to SOURCE_FIELD_DEFAULTS.
SERVICE_FIELD_DEFAULTS = {
    "rewrite_fields": None,
}

######################################################################
# LogService


class LogService:
    """Service definition describing how related log entries should be grouped and processed."""

    def __init__(self, log_source: LogSource, service_confdir_path: Path) -> None:
        """Constructor.

        Args:
            log_source (LogSource): Log source service is associated with.
            service_confdir_path (Path): Path to directory containing service configuration.
        """
        self.log_source = log_source
        self.service_confdir_path = service_confdir_path
        self.service_config: dict = None
        self.select_rules: tuple = None
        self.pass_rules: tuple = None
        self.drop_rules: tuple = None

        # These need to be reset() between iterations
        self.discard_count = 0
        self.log_entries: List[LogEntry] = None

    def __repr__(self) -> str:
        """Return the “official” string representation of an object.

        Returns:
            str
        """
        class_name = type(self).__name__
        return f"{class_name}({self.service_confdir_path})"

    def __getattr__(self, key: str) -> str | None:
        """Return service config field value using attribute notation.

        Args:
            key (str): Field

        Returns:
            Optional[Any]: Field value
        """
        if key in self.service_config:
            return self.service_config.get(key)
        raise AttributeError(f"'{type(self).__name__}' object has no attribute '{key}'")

    @property
    def has_entries(self) -> bool:
        """True if service has log entries.

        Returns:
            bool
        """
        return bool(self.log_entries)

    @cached_property
    def name(self) -> str:
        """Service name.

        Returns:
            str
        """
        # Default name is the directory without the "digit prefix" used for sorting
        return self.service_config.get("name", re.sub(r"^\d+-", "", self.service_confdir_path.name))

    @property  # Cannot be a cached_property because name changes after deaggregate()
    def fullname(self) -> str:
        """Source/service name.

        Returns:
            str
        """
        # We're not comparing with 'source.name' because it may have a 'replica_index' suffix
        if self.name == self.log_source.source_dir.name:
            return self.log_source.name
        return f"{self.log_source.name}/{self.name}"

    @cached_property
    def enabled(self) -> bool:
        """True if service is enabled.

        Returns:
            bool
        """
        return bool(self.service_config.get("enabled", True))

    @cached_property
    def max_log_entries(self) -> int:
        """Maximum number of entries to report.

        Returns:
            int
        """
        return self.service_config.get("max_log_entries", 250)

    @cached_property
    def service_config_path(self) -> Path:
        """Service configuration file path.

        Returns:
            Path
        """
        return self.service_confdir_path / "service.yaml"

    @cached_property
    def select_rules_path(self) -> Path:
        """Service select rules configuration path.

        Returns:
            Path
        """
        return self.service_confdir_path / self.service_config.get("select_rules_path", "select.yaml")

    @cached_property
    def pass_rules_path(self) -> Path:
        """Service pass rules configuration path.

        Returns:
            Path
        """
        return self.service_confdir_path / self.service_config.get("pass_rules_path", "pass.yaml")

    @cached_property
    def drop_rules_path(self) -> Path:
        """Service drop rules configuration path.

        Returns:
            Path
        """
        return self.service_confdir_path / self.service_config.get("drop_rules_path", "drop.yaml")

    @cached_property
    def rewrite_fields(self) -> Sequence[tuple[str, re.Pattern]]:
        """Patterns used to rewrite field values.

        Raises:
            LogAlertConfigError: Invalid configuration.

        Returns:
            Sequence[tuple[str, re.Pattern]]: tuple(tuple(field name, regex pattern), ...)
        """
        rewrite_fields = self.service_config.get("rewrite_fields")
        if not rewrite_fields:
            return None

        if not isinstance(rewrite_fields, (dict, list)):
            self.config_error("Invalid configuration: 'rewrite_fields' must be key/value pairs.")

        rewrite_field_patterns = []

        if isinstance(rewrite_fields, dict):
            rewrite_fields = [rewrite_fields]

        for rewrite_field in rewrite_fields:
            for field, regex in rewrite_field.items():
                rewrite_field_patterns.append((field, re.compile(regex)))

        return tuple(rewrite_field_patterns)

    def load_conf(self, cli_config: dict[str, Any]) -> None:
        """Load service configuration.

        Args:
            cli_config (dict): Command line configuration options.

        Raises:
            LogAlertConfigError: Load config failure.
        """
        self.service_config = self._load_config_json(self.service_config_path)

        merged_fields = {}

        # Always conceal timestamp and message
        merged_fields["conceal_fields"] = {self.log_source.timestamp_field, self.log_source.message_field}

        # Merge conceal fields before merging configs (which will overwrite the directive)
        for directive in ("capture_fields", "ignore_fields", "conceal_fields"):
            for fields in (self.log_source.source_config.get(directive), self.service_config.get(directive)):
                if fields:
                    if directive in merged_fields:
                        merged_fields[directive] |= set(fields)
                    else:
                        merged_fields[directive] = set(fields)

        # Merge configs in order of precedence
        self.service_config = SERVICE_FIELD_DEFAULTS | self.log_source.source_config | self.service_config | cli_config | merged_fields

        # These do not pertain to services and don't need to show up in print_conf()
        for remove_directive in ["onelog", "logfiles", "sources", "services"]:
            if remove_directive in self.service_config:
                del self.service_config[remove_directive]
        for remove_prefix in ["tail_"]:
            for k in list(self.service_config.keys()):
                if k.startswith(remove_prefix):
                    del self.service_config[k]

        self.select_rules = self._build_rules(self.select_rules_path)
        self.pass_rules = self._build_rules(self.pass_rules_path)
        self.drop_rules = self._build_rules(self.drop_rules_path)

        self.validate_conf()

    def print_rules(self) -> None:
        """Print rules for debugging."""
        echo(f"Rules for '{self.fullname}':")

        if not self.select_rules and not self.drop_rules:
            echo("> No rules are defined; all log entries will be SELECTED.")
        else:
            if self.select_rules:
                echo("> Entries matching these rules will be SELECTED:")
                FieldRule.print_rules(self.select_rules)
            else:
                echo("> No select rules are defined; all log entries will be SELECTED.")

            if self.pass_rules:
                echo("> Entries matching these rules will be PASSED:")
                FieldRule.print_rules(self.pass_rules)

            if self.drop_rules:
                echo("> Entries matching these rules will be DROPPED:")
                FieldRule.print_rules(self.drop_rules)

    def _load_config_json(self, config_path: Path) -> dict[str, Any]:
        """Load a service JSON configuration file.

        Returns an empty dict if configuration file does not exist or is empty.

        Args:
            config_path (Path): Configuration file path.

        Returns:
            dict[str, Any]

        Raises:
            LogAlertConfigError: Failed to load configuration.
        """
        service_config = {}

        try:
            service_config = read_config_file(config_path)
        except LogAlertConfigError as err:
            self.config_error(f"Failed to open config file '{config_path.name}'", err)

        return service_config

    def claim_entry(self, log_entry: LogEntry) -> bool:
        """Evaluate a LogEntry and determine if this service claims it.

        Args:
            log_entry (LogEntry): Log entry.

        Returns:
            bool: True if this service claims an entry.
        """
        rewrittenfields = self._get_rewrite_fields(log_entry)

        # Include rewrite fields so they are available to select/drop rules
        # but don't change 'LogEntry.rawfields' until *after* we claim the entry.
        service_rawfields = (log_entry.rawfields | rewrittenfields) if rewrittenfields else log_entry.rawfields

        # Select means: Entry belongs to us; empty select = select everything.
        if self.select_rules and not FieldRule.match_rules(service_rawfields, self.select_rules):
            return False

        # Pass means: Entry belongs to us but let someone else deal with it.
        if self.pass_rules and FieldRule.match_rules(service_rawfields, self.pass_rules):
            return False

        # Drop means: Entry belongs to us but we don't care about it.
        if self.drop_rules and FieldRule.match_rules(service_rawfields, self.drop_rules):
            return True

        # Capture/ignore fields as configured
        capture_fields = self.capture_fields
        if not capture_fields and self.ignore_fields:
            capture_fields = set(service_rawfields.keys()) - self.ignore_fields
        if capture_fields:
            service_rawfields = {k: service_rawfields.get(k) for k in capture_fields}

        log_entry.rawfields = service_rawfields
        log_entry.conceal_fields = self.conceal_fields

        self.log_entries.append(log_entry)

        if self.max_log_entries and self.max_log_entries < len(self.log_entries):
            self.log_entries.pop(0)
            self.discard_count += 1

        return True

    def _get_rewrite_fields(self, log_entry: LogEntry) -> dict:
        """Applies 'rewrite_fields' rules to create new log entry fields.

        Args:
            log_entry (LogEntry): Log entry.

        Returns:
            dict
        """
        newfields = {}

        if self.rewrite_fields:
            for field, pattern in self.rewrite_fields:
                # Rewrites can be applied to the same field more than once
                field_value = newfields.get(field) if field in newfields else log_entry.rawfields.get(field)
                matches = pattern.match(field_value) if field_value else None
                if matches:
                    named_groups = matches.groupdict()
                    if named_groups:
                        newfields.update(named_groups)

        return newfields

    def _build_rules(self, rules_config_path: Path) -> tuple[dict] | None:
        """Build ruleset for given configuration file.

        Args:
            rules_config_path (Path): Path to a rules file.

        Returns:
            tuple[dict[str, FieldRule]] or None

        Raises:
            LogAlertConfigError: Invalid rules.
        """
        rules_config = self._load_config_json(rules_config_path)
        if not rules_config:
            return None

        if isinstance(rules_config, dict):
            rules_config = [rules_config]

        if not isinstance(rules_config, list):
            self.config_error(f"Invalid rules configuration: {rules_config_path.name}: rules must be key/value pairs")

        return FieldRule.build_rules(rules_config)

    def reset(self, log_source: LogSource) -> None:
        """Reset service internals to prepare for another source log iteration."""
        self.discard_count = 0

        # Empty (and release memory held by) log entries and prepare for the next source log iteration.
        # https://stackoverflow.com/questions/12417498/how-to-release-used-memory-immediately-in-python-list
        # "If sys.getrefcount gives you 2, that means you are the only one who had the reference of the object"
        self.log_entries = None
        self.log_entries = []
        self.log_source = log_source  # change so our 'name' reflects new source

    def validate_conf(self) -> None:
        """Review service rules and see if they make sense."""
        if self.capture_fields and self.ignore_fields:
            self.log_warning("Both 'capture_fields' and 'ignore_fields' are set; only 'capture_fields' will be used.")

        # Reference rewrite_fields to validate and compile them
        if self.rewrite_fields:
            pass

        # Check output configurations now, prior to tailing sources
        for output in self._create_outputs():
            output.validate_conf()

    def _create_outputs(self) -> tuple[LogAlertOutput]:
        """Create outputs based on service configuration.

        Raises:
            LogAlertConfigError

        Returns:
            tuple[LogAlertOutput]
        """
        outputs = []
        ns = SimpleNamespace(**self.service_config)

        if ns.output_devnull:
            outputs.append(LogAlertOutputToDevNull(self))
        else:
            if ns.output_file_dir:
                outputs.append(LogAlertOutputToFile(self))
            if ns.output_smtp_rcpt:
                outputs.append(LogAlertOutputToSMTP(self))
            if ns.output_stdout:
                outputs.append(LogAlertOutputToStdout(self))

        if not outputs:
            self.log_warning("No outputs are configured")

        return outputs

    def output(self) -> None:
        """Output results for this service.

        Args:
            output (LogAlertOutput): Output target.
        """
        if self.discard_count:
            self.log_warning(f"Claimed {len(self.log_entries)} log entries; {self.discard_count} were discarded")
        else:
            self.log_info(f"Claimed {len(self.log_entries)} log entries")

        if self.has_entries:
            # We create outputs for each output() so memory is released between services
            for output in self._create_outputs():
                output()

    def print_conf(self) -> None:
        """Print service configuration."""
        echo(f"Service: {self.log_source.name}/{self.name}")
        echo("=================")

        # Using !r uses repr() which quotes strings.
        for k, v in sorted(self.service_config.items()):
            if isinstance(v, Path):
                v = str(v)  # noqa: PLW2901
            echo(f"{k}: {v!r}")

    def log_debug(self, message: str) -> None:
        """Log a debug message related to this service.

        Args:
            message (str): Message.
        """
        logging.debug(f"{self.fullname}: {message}")

    def log_info(self, message: str) -> None:
        """Log a info message related to this service.

        Args:
            message (str): Message.
        """
        logging.info(f"{self.fullname}: {message}")

    def log_warning(self, message: str) -> None:
        """Log a warning message related to this service.

        Args:
            message (str): Message.
        """
        logging.warning(f"{self.fullname}: {message}")

    def log_error(self, message: str) -> None:
        """Log a error message related to this service.

        Args:
            message (str): Message.
        """
        logging.error(f"{self.fullname}: {message}")

    def config_error(self, message: str, err: str | Exception | None = None) -> None:
        """Raise a 'LogAlertConfigError' exception related to this service.

        Args:
            message (str): Message.
            err (str | Exception | None): Error message or exception.

        Raises:
            LogAlertConfigError
        """
        if err:
            raise LogAlertConfigError(f"{self.fullname}: {message}: {err}")
        raise LogAlertConfigError(f"{self.fullname}: {message}")

    @cached_property
    def is_catchall(self) -> bool:
        """Return True if this service claims all log entries.

        Returns:
            bool
        """
        return not self.select_rules and not self.drop_rules

    ######################################################################
    # Helper functions

    @staticmethod
    def load_services(log_source: LogSource, cli_config: dict[str, Any]) -> tuple[LogService]:
        """Iterate service directories for a log source and creates
        LogService objects with each configured service.

        Args:
            log_source (LogSource): Log source service is associated with.
            cli_config (dict): Command line configuration options.

        Returns:
            tuple[LogService]

        Raises:
            LogAlertConfigError: Failed to load services.
        """
        assert log_source.source_dir.is_dir()

        services: list[LogService] = []
        catchalls: list[LogService] = []
        service_dirs = []

        # Source directory can also define the service
        service_config_path = log_source.source_dir / "service.yaml"
        if service_config_path.is_file():
            log_source.log_debug("Is itself a service")
            service_dirs.append(log_source.source_dir)

        if not service_dirs:
            # Services are defined in subdirectories of the source
            for service_dir in sorted(d for d in log_source.source_dir.iterdir() if d.is_dir()):
                service_config_path = service_dir / "service.yaml"
                if service_config_path.is_file():
                    service_dirs.append(service_dir)

            log_source.log_debug(f"{len(service_dirs)} services defined")

        for service_dir in service_dirs:
            s = LogService(log_source, service_dir)

            s.load_conf(cli_config)

            if s.is_catchall:
                catchalls.append(s)
            else:
                services.append(s)

        if catchalls:
            services.extend(catchalls)

        return tuple(services)
