from __future__ import annotations

from typing import TYPE_CHECKING

from jsonlogalert.exceptions import LogAlertConfigError

if TYPE_CHECKING:
    from collections.abc import Sequence

    from jsonlogalert.logservice import LogService
    from jsonlogalert.logsource import LogSource

######################################################################
# Functions


def conf_del_keys(conf: dict, del_keys: Sequence) -> None:
    """Delete given keys from dictionary.

    Args:
        conf (dict): Dictionary.
        del_keys (Sequence): Key names.
    """
    for key in del_keys:
        if key in conf:
            del conf[key]


######################################################################
# Command line options that only apply to main()
#
# Note: "tail_reset" applies only to main but we don't put it here
# so we can warn when it's included in the config file.

MAIN_OPTS_DIRECTIVES = {
    "config_dir",
    "log_file_streams",
    "print_conf",
    "print_rules",
    "verbose",
}

######################################################################
# Command line options that can be set in the main configuration file.
# Actual default values are those specified in click.option().
# Some may apply to sources and services.

COMMAND_OPTS_DEFAULTS = {
    "dry_run": False,
    "journal_dir": None,
    "max_logentries": 250,
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
    "output_smtp_subject": None,
    "output_smtp": True,
    "output_stdout": False,
    "output_template_file": None,
    "services": (),
    "sources": (),
    "tail_debug": False,
    "tail_file_bin": "logtail2",
    "tail_file_paths": (),
    "tail_ignore": False,
    "tail_journal_bin": "logtail-journal",
    "tail_journal_since": None,
    "tail_reset": False,
    "tail_state_dir": "/var/lib/misc",
}

COMMAND_OPTS_DIRECTIVES = set(COMMAND_OPTS_DEFAULTS.keys())
COMMAND_OPTS_ONLY = ("sources", "services")

COMMAND_OPTS_SOURCE_ONLY = set()
for opt_prefix in ("journal", "tail"):
    for k in COMMAND_OPTS_DIRECTIVES:
        if k.startswith(opt_prefix):
            COMMAND_OPTS_SOURCE_ONLY.add(k)


######################################################################
# Options that can be set in `service.yaml`

SERVICE_CONF_DEFAULTS = COMMAND_OPTS_DEFAULTS | {
    "capture_fields": None,
    "conceal_fields": None,
    "description": None,
    "drop_rules_path": None,
    "enabled": True,
    "ignore_fields": None,
    "output_content_type": None,
    "output_template_minify_html": False,
    "pass_rules_path": None,
    "rewrite_fields": None,
    "select_rules_path": None,
}

# Remove directives that only apply to main configuration file.
conf_del_keys(SERVICE_CONF_DEFAULTS, COMMAND_OPTS_ONLY)
conf_del_keys(SERVICE_CONF_DEFAULTS, COMMAND_OPTS_SOURCE_ONLY)

SERVICE_CONFFILE_DIRECTIVES = set(SERVICE_CONF_DEFAULTS.keys())

######################################################################
# Options that can be set in `source.yaml`

SOURCE_CONF_DEFAULTS = (
    COMMAND_OPTS_DEFAULTS
    | SERVICE_CONF_DEFAULTS
    | {
        "blob_fields": None,
        "logfiles": (),
        "message_field": None,
        "onelog": False,
        "timestamp_field": None,
    }
)

# Remove directives that only apply to main configuration file.
conf_del_keys(SOURCE_CONF_DEFAULTS, COMMAND_OPTS_ONLY)

SOURCE_CONFFILE_DIRECTIVES = set(SOURCE_CONF_DEFAULTS.keys())

FILE_SOURCE_ONLY_DIRECTIVES = {"logfiles", "onelog"}
for opt_prefix in ("tail_file",):
    for k in SOURCE_CONFFILE_DIRECTIVES:
        if k.startswith(opt_prefix):
            FILE_SOURCE_ONLY_DIRECTIVES.add(k)

JOURNAL_SOURCE_ONLY_DIRECTIVES = set()
for opt_prefix in ("journal", "tail_journal"):
    for k in SOURCE_CONFFILE_DIRECTIVES:
        if k.startswith(opt_prefix):
            JOURNAL_SOURCE_ONLY_DIRECTIVES.add(k)

FILE_SOURCE_CONFFILE_DIRECTIVES = SOURCE_CONFFILE_DIRECTIVES - JOURNAL_SOURCE_ONLY_DIRECTIVES
JOURNAL_SOURCE_CONFFILE_DIRECTIVES = SOURCE_CONFFILE_DIRECTIVES - FILE_SOURCE_ONLY_DIRECTIVES

######################################################################
# Functions


def main_conf_check(cli_config: dict, default_config: dict) -> None:
    """Raise an exception if configuration contains unrecognized directives.

    Args:
        cli_config (dict): Command line options.
        default_config (dict): Configuration file options.

    Raises:
        LogAlertConfigError
    """
    bad_directives = (set(cli_config.keys()) | set(default_config.keys())) - COMMAND_OPTS_DIRECTIVES
    if bad_directives:
        bad_directives = "', '".join(sorted(bad_directives))
        raise LogAlertConfigError(f"Unrecognized main configuration file directives: ['{bad_directives}']")

    if default_config.get("tail_reset"):
        raise LogAlertConfigError("Use the '--tail-reset' command line option instead of 'tail_reset' in the configuration file.")


def source_conf_check(source: LogSource) -> None:
    """Raise an exception if a source configuration contains unrecognized directives.

    Args:
        source (LogSource): The source.

    Raises:
        LogAlertConfigError
    """
    bad_directives = set(source.source_config.keys()) - SOURCE_CONFFILE_DIRECTIVES
    if bad_directives:
        bad_directives = "', '".join(sorted(bad_directives))
        source.config_error(f"Unrecognized source configuration file directives: ['{bad_directives}']")


def service_conf_check(service: LogService) -> None:
    """Raise an exception if a service configuration contains unrecognized directives.

    Args:
        service (LogService): The service.

    Raises:
        LogAlertConfigError
    """
    bad_directives = set(service.service_config.keys()) - SERVICE_CONFFILE_DIRECTIVES
    if bad_directives:
        bad_directives = "', '".join(sorted(bad_directives))
        service.config_error(f"Unrecognized service configuration file directives: ['{bad_directives}']")


def source_conf_clean(source: LogSource) -> None:
    """Delete config settings that do not pertain to sources.

    Args:
        source (LogSource): The source.
    """
    conf_del_keys(source.source_config, set(source.source_config.keys()) - SOURCE_CONFFILE_DIRECTIVES)


def service_conf_clean(service: LogService) -> None:
    """Delete config settings that do not pertain to services.

    Args:
        service (LogService): The service.
    """
    conf_del_keys(service.service_config, set(service.service_config.keys()) - SERVICE_CONFFILE_DIRECTIVES)
