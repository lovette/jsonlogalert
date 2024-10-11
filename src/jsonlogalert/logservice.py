from __future__ import annotations

import json
import logging
import re
from email.utils import formataddr, parseaddr
from functools import cached_property
from pathlib import Path
from types import SimpleNamespace
from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from collections import List
    from collections.abc import Sequence

    from jinja2 import Template

    from jsonlogalert.logentry import LogEntry
    from jsonlogalert.logsource import LogSource

from click import echo

from jsonlogalert.confcheck import SERVICE_CONF_DEFAULTS, service_conf_check, service_conf_clean
from jsonlogalert.exceptions import LogAlertConfigError, LogAlertParserError
from jsonlogalert.jinjaenvironment import LogAlertJinjaStringEnvironment
from jsonlogalert.logalertoutput import LogAlertOutput, LogAlertOutputToDevNull, LogAlertOutputToStdout
from jsonlogalert.logalertoutput_file import LogAlertOutputToFile
from jsonlogalert.logalertoutput_smtp import LogAlertOutputToSMTP
from jsonlogalert.logfieldrule import FieldRule, FieldRuleError
from jsonlogalert.utils import read_config_file, resolve_rel_path

MAX_RULE_FAIL_MSGS = 10

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
        self.source = log_source
        self.service_confdir_path = service_confdir_path
        self.service_config: dict = None
        self.select_rules: tuple = None
        self.pass_rules: tuple = None
        self.drop_rules: tuple = None

        # These need to be reset() between iterations
        self.discard_count = 0
        self.pass_count = 0
        self.drop_count = 0
        self.rule_fail_count = 0
        self.logentries: List[LogEntry] = None

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
        if not self.service_config:
            raise AttributeError(f"'{type(self).__name__}' object has no attribute '{key}'; 'service_config' is not set")

        try:
            return self.service_config[key]
        except KeyError:
            pass

        raise AttributeError(f"'{type(self).__name__}' object has no attribute '{key}'")

    @property
    def has_entries(self) -> bool:
        """True if service has log entries.

        Returns:
            bool
        """
        return bool(self.logentries)

    @cached_property
    def name(self) -> str:
        """Service name.

        Returns:
            str
        """
        # Default name is the directory without the "digit prefix" used for sorting
        return re.sub(r"^\d+-", "", self.service_confdir_path.name)

    @property  # Cannot be a cached_property because name changes after deaggregate()
    def fullname(self) -> str:
        """Source/service name with replica index suffix.

        Returns:
            str
        """
        return self.source.name if self.name == self.source.basename else f"{self.source.name}/{self.name}"

    @cached_property
    def fullbasename(self) -> str:
        """Source/service name without replica index suffix.

        Returns:
            str
        """
        return self.source.basename if self.name == self.source.basename else f"{self.source.basename}/{self.name}"

    @cached_property
    def enabled(self) -> bool:
        """True if service is enabled.

        Returns:
            bool
        """
        return bool(self.service_config.get("enabled", True))

    @cached_property
    def max_logentries(self) -> int:
        """Maximum number of entries to report.

        Returns:
            int
        """
        return self.service_config.get("max_logentries", 250)

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
        select_rules_path = self.service_config.get("select_rules_path")
        return resolve_rel_path(select_rules_path or "select.yaml", self.service_confdir_path)

    @cached_property
    def pass_rules_path(self) -> Path:
        """Service pass rules configuration path.

        Returns:
            Path
        """
        pass_rules_path = self.service_config.get("pass_rules_path")
        return resolve_rel_path(pass_rules_path or "pass.yaml", self.service_confdir_path)

    @cached_property
    def drop_rules_path(self) -> Path:
        """Service drop rules configuration path.

        Returns:
            Path
        """
        drop_rules_path = self.service_config.get("drop_rules_path")
        return resolve_rel_path(drop_rules_path or "drop.yaml", self.service_confdir_path)

    @cached_property
    def field_types(self) -> dict[str, type]:
        """Field type conversions.

        Raises:
            LogAlertConfigError: Invalid configuration.

        Returns:
            dict[str, type]
        """
        field_types = self.service_config.get("field_types")
        if not field_types:
            return None

        if not isinstance(field_types, dict):
            self.config_error("Invalid configuration: 'field_types' must be key/value pairs.")

        for k, v in field_types.items():
            if v == "int":
                field_types[k] = int
            elif v == "bool":
                field_types[k] = bool
            else:
                self.config_error(f"Invalid configuration: 'field_types': '{k}' choices are ['int', 'bool'].")

        return field_types

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

    @cached_property
    def conceal_fields(self) -> set[str] | None:
        """Return set of log entry fields concealed for this service.

        Returns:
            set[str] | None
        """
        conceal_fields = self.service_config.get("conceal_fields")
        if conceal_fields and not self.skip_conceal_fields:
            return set(conceal_fields)
        return None

    def load_conf(self, cli_config: dict[str, Any]) -> None:  # noqa: C901, PLR0912
        """Load service configuration.

        Args:
            cli_config (dict): Command line configuration options.

        Raises:
            LogAlertConfigError: Load config failure.
        """
        try:
            # Config file must exist but can be empty
            self.service_config = read_config_file(self.service_config_path) or {}
        except LogAlertConfigError as err:
            self.config_error(f"Failed to read configuration file '{self.service_config_path.name}'", err)

        # Sanity check configuration settings (it's easy to get confused what option goes where!)
        service_conf_check(self)

        merged_fields = {}

        # Always conceal timestamp and message
        merged_fields["conceal_fields"] = {self.source.timestamp_field, self.source.message_field}

        # Merge field set() before merging configs (which will overwrite the directive)
        for directive in ("capture_fields", "ignore_fields", "conceal_fields"):
            for fields in (self.source.source_config.get(directive), self.service_config.get(directive)):
                if fields:
                    if not isinstance(fields, list):
                        self.config_error(f"'{directive}': Must be a list of field names.")
                    if directive in merged_fields:
                        merged_fields[directive] |= set(fields)
                    else:
                        merged_fields[directive] = set(fields)

        # Merge field dict() before merging configs (which will overwrite the directive)
        for directive in ("field_types",):
            for fields in (self.source.source_config.get(directive), self.service_config.get(directive)):
                if fields:
                    if not isinstance(fields, dict):
                        self.config_error(f"'{directive}': Must be a list of 'field: type' pairs.")
                    if directive in merged_fields:
                        merged_fields[directive] |= fields
                    else:
                        merged_fields[directive] = fields

        # Merge configs in order of precedence
        self.service_config = dict(
            sorted((SERVICE_CONF_DEFAULTS | self.source.source_config | self.service_config | cli_config | merged_fields).items())
        )

        # Delete settings that do not pertain to services and don't need to show up in print_conf()
        service_conf_clean(self)

        self.select_rules = self._build_rules(self.select_rules_path)
        self.pass_rules = self._build_rules(self.pass_rules_path)
        self.drop_rules = self._build_rules(self.drop_rules_path)

        # Expand and validate "output_smtp" addresses
        for opt in ("output_smtp_rcpt", "output_smtp_rcpt_name", "output_smtp_sender", "output_smtp_sender_name"):
            val = self.service_config.get(opt)
            if val:
                self.service_config[opt] = self.render_template_str(val)

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

    def claim_entry(self, log_entry: LogEntry) -> bool:  # noqa: C901
        """Evaluate a LogEntry and determine if this service claims it.

        Args:
            log_entry (LogEntry): Log entry.

        Returns:
            bool: True if this service claims an entry.

        Raises:
            LogAlertParserError
        """
        # Operate on a copy of fields so we can rewrite and apply conversions
        # without influencing other services.
        rawfields = log_entry.rawfields | {}

        # Apply converters so they are available to select/drop rules
        if self.rstrip_fields:
            self._apply_rstrip_fields(rawfields)
        if self.rewrite_fields:
            self._apply_rewrite_fields(rawfields)
        if self.field_types:
            self._apply_field_types(rawfields)

        # Select means: Entry belongs to us; empty select = select everything.
        if self.select_rules and not self._match_rules(rawfields, self.select_rules):
            return False

        # Parse JSON fields *after* `select_rules`, otherwise it applies to *every* event!
        if self.json_field:
            self._apply_json_field(rawfields)

        # Pass means: Entry belongs to us but let someone else deal with it.
        if self.pass_rules and self._match_rules(rawfields, self.pass_rules):
            self.pass_count += 1
            return False

        # Drop means: Entry belongs to us but we don't care about it.
        if self.drop_rules and not self.skip_drop_rules and self._match_rules(rawfields, self.drop_rules):
            self.drop_count += 1
            return True

        # Capture/ignore fields as configured
        capture_fields = self.capture_fields if not self.skip_capture_fields else None
        if not capture_fields and self.ignore_fields and not self.skip_ignore_fields:
            capture_fields = set(rawfields.keys()) - self.ignore_fields
        if capture_fields:
            rawfields = {k: rawfields.get(k) for k in capture_fields}

        log_entry.service = self
        log_entry.rawfields = rawfields

        self.logentries.append(log_entry)

        if self.max_logentries and self.max_logentries < len(self.logentries):
            self.logentries.pop(0)
            self.discard_count += 1

        return True

    def _apply_rstrip_fields(self, rawfields: dict) -> None:
        """Apply 'rstrip' operations to field values.

        Args:
            rawfields (dict): Log entry fields.
        """
        # Some service include newlines in log messages!
        if self.rstrip_fields:
            for field in self.rstrip_fields:
                if field in rawfields and isinstance(rawfields[field], str):
                    rawfields[field] = rawfields[field].rstrip()

    def _apply_field_types(self, rawfields: dict) -> None:
        """Convert fields to native types as defined in `field_types`.

        Same function as `source.field_converters` but defined by the service.

        Args:
            rawfields (dict): Log entry fields.
        """
        if self.field_types:
            for field, field_type in self.field_types.items():
                if field in rawfields:
                    rawfields[field] = field_type(rawfields[field])

    def _apply_json_field(self, rawfields: dict) -> None:  # noqa: C901, PLR0912
        """Apply `json_field` to field values.

        Args:
            rawfields (dict): Log entry fields.

        Raises:
            LogAlertParserError
        """
        if self.json_field:
            field_value = rawfields.get(self.json_field)
            if field_value:
                field_value = field_value.rstrip()
                if field_value.startswith("{") and field_value.endswith("}"):
                    try:
                        json_value = json.loads(field_value)
                    except json.JSONDecodeError as err:
                        if self.json_field_warn:
                            raise LogAlertParserError(f"'{self.json_field}': Invalid JSON? {err}: '{field_value}'") from err
                    else:
                        if not isinstance(json_value, dict):
                            raise LogAlertParserError(f"'{self.json_field}': Expected JSON dict: '{field_value}'")

                        if self.json_field_prefix:
                            json_value = {f"{self.json_field_prefix}{k}": v for k, v in json_value.items()}

                        if self.rstrip_fields:
                            self._apply_rstrip_fields(json_value)
                        if self.rewrite_fields:
                            self._apply_rewrite_fields(json_value)
                        if self.field_types:
                            self._apply_field_types(json_value)

                        rawfields.update(json_value)

                        if self.json_field_unset:
                            del rawfields[self.json_field]
                        if self.json_field_promote and self.json_field_promote in rawfields:
                            rawfields[self.json_field] = rawfields[self.json_field_promote]
                            del rawfields[self.json_field_promote]

                elif self.json_field_warn:
                    raise LogAlertParserError(f"'{self.json_field}': Expected JSON: '{field_value}'")

    def _match_rules(self, fields: dict, block_rules_list: list[dict[str, FieldRule]]) -> bool:
        """Evaluates list of rule blocks against log entry fields.

        Args:
            fields (dict): Log entry fields.
            block_rules_list (list[dict[str, FieldRule]]): List of field blocks rules.

        Returns:
            bool: True if all the rules for *any* field block are True.
        """
        match_found = False

        try:
            match_found = FieldRule.match_rules(fields, block_rules_list)
        except FieldRuleError as err:
            if self.rule_fail_count <= MAX_RULE_FAIL_MSGS:
                self.log_warning(f"{err}")
                if self.rule_fail_count == MAX_RULE_FAIL_MSGS:
                    self.log_warning(f">{MAX_RULE_FAIL_MSGS} warnings; rule failure messages will be suppressed")
            self.rule_fail_count += 1

        return match_found

    def _apply_rewrite_fields(self, rawfields: dict) -> None:
        """Applies 'rewrite_fields' rules to create new log entry fields.

        Args:
            rawfields (dict): Log entry fields.

        Raises:
            LogAlertParserError
        """
        if self.rewrite_fields:
            for field, pattern in self.rewrite_fields:
                # Rewrites can be applied to the same field more than once
                field_value = rawfields.get(field)

                try:
                    matches = pattern.match(field_value) if field_value else None
                except TypeError as err:
                    raise LogAlertParserError(f"'{field}': Failed to rewrite field: '{field_value}': {err}") from err
                else:
                    if matches:
                        named_groups = matches.groupdict()
                        if named_groups:
                            rawfields.update(named_groups)

    def _build_rules(self, rules_config_path: Path) -> tuple[dict] | None:
        """Build ruleset for given configuration file.

        Args:
            rules_config_path (Path): Path to a rules file.

        Returns:
            tuple[dict[str, FieldRule]] or None

        Raises:
            LogAlertConfigError: Invalid rules.
        """
        try:
            rules_config = read_config_file(rules_config_path)
        except LogAlertConfigError as err:
            self.config_error(f"Failed to read rules file '{rules_config_path.name}'", err)

        try:
            service_rules = FieldRule.build_rules(rules_config)
        except FieldRuleError as err:
            self.config_error(f"'{rules_config_path.name}': {err}")

        return service_rules

    def reset(self, log_source: LogSource) -> None:
        """Reset service internals to prepare for another source log iteration."""
        self.source = log_source  # change so our 'name' reflects new source

        self.discard_count = 0
        self.pass_count = 0
        self.drop_count = 0
        self.rule_fail_count = 0

        # Empty (and release memory held by) log entries and prepare for the next source log iteration.
        # https://stackoverflow.com/questions/12417498/how-to-release-used-memory-immediately-in-python-list
        # "If sys.getrefcount gives you 2, that means you are the only one who had the reference of the object"
        self.logentries = None
        self.logentries = []

    def validate_conf(self) -> None:
        """Review service rules and see if they make sense.

        Raises:
            LogAlertConfigError
        """

        def _validate_smtp_addr(config_opt: str, name_addr: tuple[str, str]) -> None:
            # Sanity check address by seeing if we can parse it and get the same result
            rfc_addr = formataddr(name_addr)
            if parseaddr(rfc_addr) != name_addr:
                self.config_error(f"{config_opt}: Malformed address: '{rfc_addr}'")

        if self.output_smtp_rcpt and self.output_smtp:
            _validate_smtp_addr("output_smtp_sender", (self.output_smtp_sender_name or "", self.output_smtp_sender))
            _validate_smtp_addr("output_smtp_rcpt", (self.output_smtp_rcpt_name or "", self.output_smtp_rcpt))

        if self.capture_fields and self.ignore_fields:
            self.log_warning("Both 'capture_fields' and 'ignore_fields' are set; only 'capture_fields' will be used.")

        # Reference cached_properties to validate and compile them
        if self.rewrite_fields:
            pass
        if self.field_types:
            pass

        # Check output configurations now, prior to tailing sources
        for output in self._create_outputs():
            output.validate_conf()

    def validate_scan(self) -> None:
        """Review scan configuration directives and see if they make sense.

        Raises:
            LogAlertConfigError
        """
        for output in self._create_outputs():
            output.validate_scan()

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
            if ns.output_smtp_rcpt and not ns.output_smtp:
                if not self.source.is_replica:
                    self.log_info(f"SMTP is disabled; mail will not be sent to '{ns.output_smtp_rcpt}'")
                ns.output_smtp_rcpt = None

            if ns.output_file_dir or ns.output_file_name:
                outputs.append(LogAlertOutputToFile(self))

            # SMTP will output message to stdout itself, so it's mutex with 'output_stdout'
            if ns.output_smtp_rcpt:
                outputs.append(LogAlertOutputToSMTP(self))
            elif ns.output_stdout:
                outputs.append(LogAlertOutputToStdout(self))

        if not outputs:
            self.log_warning("No outputs are enabled")

        return outputs

    def output(self) -> None:
        """Output results for this service.

        Args:
            output (LogAlertOutput): Output target.
        """
        status_parts = [f"claimed:{len(self.logentries)}"]

        if self.pass_count:
            status_parts.append(f"passed:{self.pass_count}")
        if self.drop_count:
            status_parts.append(f"dropped:{self.drop_count}")
        if self.rule_fail_count:
            status_parts.append(f"rulefail:{self.rule_fail_count}")
        if self.discard_count:
            status_parts.append(f"discarded:{self.discard_count}")

        if self.rule_fail_count or self.discard_count:
            self.log_warning(" ".join(status_parts))
        else:
            self.log_info(" ".join(status_parts))

        if self.has_entries:
            # We create outputs for each output() so memory is released between services
            for output in self._create_outputs():
                output()

    def print_conf(self) -> None:
        """Print service configuration."""
        echo(f"Service: {self.fullname}")
        echo("=================")

        # Using !r uses repr() which quotes strings.
        for k, v in sorted(self.service_config.items()):
            if isinstance(v, Path):
                v = str(v)  # noqa: PLW2901
            echo(f"{k}: {v!r}")

    def print_field_types(self) -> None:
        """Print service field type conversions."""
        if self.field_types:
            echo(f"Service: {self.fullname}")
            echo("=================")

            # Using !r uses repr() which quotes strings.
            for k, v in sorted(self.field_types.items()):
                echo(f"{k}: {v.__name__!r}")

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
        return not bool(self.select_rules or self.drop_rules)

    def render_template(self, template: Template) -> str:
        """Render content for service output.

        Args:
            template (Template): Jinja template.

        Returns:
            str
        """
        template_vars = {
            "service": self,
            "logservice": self,
            "source": self.source,
            "logsource": self.source,
            "entries": self.logentries,
            "logentries": self.logentries,
            "hostname": self.source.hostname,
            "hostdomain": self.source.hostdomain,
            "hostfqdn": self.source.hostfqdn,
        }

        return template.render(**template_vars)

    def render_template_str(self, template_str: str, one_line: bool = True) -> str:
        """Render given string template as an output template.

        Args:
            template_str (str): Template string.
            one_line (bool, optional): True if result should be a single line. Defaults to True.

        Returns:
            str
        """
        if "{" in template_str:
            template = LogAlertJinjaStringEnvironment().from_string(template_str)
            template_str = self.render_template(template)
            if one_line:
                # Remove newlines, tabs, strings of spaces, etc.
                template_str = re.sub(r"\s+", " ", template_str).strip()

        return template_str

    def add_conceal_fields(self, fields: str | Sequence[str]) -> str:
        """Add fields to set of concealed fields.

        Allows a template to conceal fields.
        Affects all log entries for the service.

        Args:
            fields (str|Sequence[str]): Field or fields to conceal.

        Returns:
            Empty string
        """
        if isinstance(fields, str):
            fields = [fields]

        if self.conceal_fields:
            self.conceal_fields.update(fields)
        else:
            self.conceal_fields = set(fields)

        # Replace invocation with an empty string
        return ""

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
