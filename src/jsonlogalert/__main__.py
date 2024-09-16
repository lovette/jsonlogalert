#!/usr/bin/env python3

import io
import logging
import shutil
import sys
from collections.abc import Sequence
from pathlib import Path

import click
from click.core import ParameterSource
from click_option_group import optgroup

from jsonlogalert.confcheck import MAIN_OPTS_DIRECTIVES, main_conf_check
from jsonlogalert.exceptions import LogAlertConfigError
from jsonlogalert.logsource import LogSource
from jsonlogalert.logsource_journal import LogSourceSystemdJournal
from jsonlogalert.utils import read_config_file, resolve_rel_path

JSONLOGALERT_VER = "0.1"

VERBOSE_LOGGING_LEVELS = (
    logging.ERROR,  # default
    logging.WARNING,  # -v
    logging.INFO,  # -vv
    logging.DEBUG,  # -vvv
)

LOGGING_FORMAT = "[%(levelname)s] %(message)s"

# Setup logging
# Runtime verbose level will be set in cli()
logging.basicConfig(level=VERBOSE_LOGGING_LEVELS[0], format=LOGGING_FORMAT)

######################################################################
# Helper functions


def config_set_default(ctx: click.Context, param: click.Option, value: Path) -> str:  # noqa: ARG001
    """Handle `--config` command option.

    Args:
        ctx (click.core.Context): Click context object.
        param (click.Option): Click option object.
        value (str): Option value.

    Returns:
        str: Option value.
    """
    if value and value.is_file():
        try:
            config = read_config_file(value)
        except LogAlertConfigError as err:
            raise LogAlertConfigError(f"Failed to read config file {value}: {err}") from err
        else:
            if config:
                ctx.default_map = config

    return value


def resolve_bin(name_or_path: Path, conf_directive: str) -> Path:
    """Search $PATH for an executable file.

    Args:
        name_or_path (Path): File name or absolute path.
        conf_directive (str): Config file directive being resolved.

    Returns:
        Path: Absolute path to file if it's executable; otherwise None.

    Raises:
        LogAlertConfigError: Command not found
    """
    which = shutil.which(name_or_path)

    if not which:
        raise LogAlertConfigError(f"{name_or_path}: command not found; set '{conf_directive}' if necessary.")

    logging.debug(f"Resolved command '{name_or_path}' to '{which}'")

    return resolve_rel_path(which)


def _delete_tail_state_files(tail_state_dir: Path) -> None:
    """Delete any tail offset/cursor state files.

    Args:
        tail_state_dir (Path): Directory containing tail state files.
    """
    if tail_state_dir is None:
        raise LogAlertConfigError("'tail_state_dir' directive is not set.")
    if not tail_state_dir.is_dir():
        raise LogAlertConfigError(f"{tail_state_dir}: No such directory")

    # NOTE: Glob must match spec in LogSource.get_tail_state_path
    for state_file in tail_state_dir.glob("jsonlogalert-*.offset"):
        logging.info(f"Deleted: {state_file}")
        state_file.unlink()


######################################################################
# Command


@click.command(context_settings={"auto_envvar_prefix": "JSONLOGALERT"})
@click.option(
    "--config-file",
    "-c",
    default="/etc/jsonlogalert.conf",
    type=click.Path(
        exists=False,
        dir_okay=False,
        path_type=Path,
        resolve_path=True,
    ),
    callback=config_set_default,
    is_eager=True,
    expose_value=False,
    show_default=True,
    help="Read options from configuration FILE.",
)
@click.option(
    "--config-dir",
    "-d",
    type=click.Path(
        exists=True,
        file_okay=False,
        dir_okay=True,
        path_type=Path,
        resolve_path=True,
    ),
    default="/etc/jsonlogalert.d",
    show_default=True,
    help="Set path to directory containing source and service definitions.",
)
@click.option(
    "--verbose",
    "-v",
    count=True,
    help="Be more verbose; can specify more than once.",
)
@click.version_option(
    version=JSONLOGALERT_VER,
    prog_name="jsonlogalert",
    message="%(prog)s version %(version)s",
)
@click.option(
    "--source",
    "-s",
    "sources",
    type=str,
    multiple=True,
    default=None,
    metavar="SOURCE",
    help="Read only this log SOURCE; can specify more than once.",
)
@click.option(
    "--service",
    "services",
    type=str,
    multiple=True,
    default=None,
    metavar="SERVICE",
    help="Enable only this SERVICE for a log SOURCE; can specify more than once.",
)
@optgroup.group("TAIL LOG OPTIONS")
@optgroup.option(
    "--tail-journal-dir",
    "-J",
    type=click.Path(
        exists=True,
        file_okay=False,
        dir_okay=True,
        path_type=Path,
        resolve_path=True,
    ),
    default=None,
    help="Tail systemd journal DIRECTORY.",
)
@optgroup.option(
    "--tail-journal-bin",
    type=click.Path(
        exists=False,
        executable=True,
        path_type=Path,
    ),
    default="logtail-journal",
    show_default=True,
    help="Set path of executable to tail systemd journal.",
)
@optgroup.option(
    "--tail-journal-since",
    type=click.Choice(("boot", "all"), case_sensitive=False),
    default=None,
    help="Read all systemd journal entries or since last boot (ignores cursor.)",
)
@optgroup.option(
    "--tail-file",
    "-f",
    "tail_file_paths",
    type=click.Path(
        exists=True,
        dir_okay=False,
        path_type=Path,
        resolve_path=True,
    ),
    multiple=True,
    default=None,
    metavar="LOGFILE",
    help="Tail text log LOGFILE; can specify more than once.",
)
@optgroup.option(
    "--tail-file-bin",
    type=click.Path(
        exists=False,
        executable=True,
        path_type=Path,
    ),
    default="logtail2",
    show_default=True,
    help="Set path of executable to tail log files.",
)
@optgroup.option(
    "--tail-state-dir",
    type=click.Path(
        exists=True,
        file_okay=False,
        dir_okay=True,
        path_type=Path,
        resolve_path=True,
    ),
    default="/var/lib/misc",
    show_default=True,
    help="Set path of DIRECTORY to save tail offset/cursor state.",
)
@optgroup.option(
    "--tail-reset",
    type=bool,
    is_flag=True,
    default=False,
    help="Delete offset/cursor state files and exit.",
)
@optgroup.option(
    "--tail-debug",
    type=bool,
    is_flag=True,
    default=False,
    help="Use but do not update tail offset/cursor.",
)
@optgroup.option(
    "--tail-ignore",
    type=bool,
    is_flag=True,
    default=False,
    help="Ignore and do not update tail offset/cursor.",
)
@optgroup.group("GENERAL OUTPUT OPTIONS")
@optgroup.option(
    "--output-stdout",
    type=bool,
    is_flag=True,
    default=False,
    help="Output results to stdout.",
)
@optgroup.option(
    "--output-devnull",
    type=bool,
    is_flag=True,
    default=False,
    help="Output results to /dev/null.",
)
@optgroup.option(
    "--output-template-file",
    type=str,
    default=None,
    metavar="FILENAME",
    help="Use FILENAME instead of default output template.",
)
@optgroup.group("FILE OUTPUT OPTIONS")
@optgroup.option(
    "--output-file-dir",
    type=click.Path(
        exists=True,
        file_okay=False,
        dir_okay=True,
        path_type=Path,
        resolve_path=True,
    ),
    default=None,
    help="Output results to file in DIRECTORY.",
)
@optgroup.option(
    "--output-file-name",
    type=str,
    default=None,
    metavar="FILENAME",
    help="Output results to FILENAME in DIRECTORY when a single SERVICE is specified.",
)
@optgroup.group("SMTP OUTPUT OPTIONS")
@optgroup.option(
    "--output-smtp-host",
    type=str,
    default="localhost",
    show_default=True,
    metavar="HOSTNAME",
    help="Mail server hostname or address.",
)
@optgroup.option(
    "--output-smtp-port",
    type=int,
    default=25,
    show_default=True,
    help="Mail server port.",
)
@optgroup.option(
    "--output-smtp-auth-ssl",
    type=bool,
    is_flag=True,
    default=False,
    show_default=True,
    help="Mail server uses SSL connection.",
)
@optgroup.option(
    "--output-smtp-auth-tls",
    type=bool,
    is_flag=True,
    default=False,
    show_default=True,
    help="Mail server uses TLS.",
)
@optgroup.option(
    "--output-smtp-auth-username",
    type=str,
    default=None,
    show_default=True,
    metavar="USERNAME",
    help="Mail server authentication username.",
)
@optgroup.option(
    "--output-smtp-auth-password",
    type=str,
    default=None,
    show_default=True,
    metavar="PASSWORD",
    help="Mail server authentication password.",
)
@optgroup.option(
    "--output-smtp-rcpt",
    type=str,
    default=None,
    show_default=True,
    metavar="EMAIL",
    help="Email recipient address. Required.",
)
@optgroup.option(
    "--output-smtp-sender",
    type=str,
    default=None,
    show_default=True,
    metavar="EMAIL",
    help="Email sender address.  [default: recipient address]",
)
@optgroup.option(
    "--output-smtp-rcpt-name",
    type=str,
    default=None,
    show_default=True,
    metavar="NAME",
    help="Email recipient name.",
)
@optgroup.option(
    "--output-smtp-sender-name",
    type=str,
    default=None,
    show_default=True,
    metavar="NAME",
    help="Email sender name.  [default: recipient name]",
)
@optgroup.option(
    "--output-smtp-subject",
    type=str,
    default=None,
    show_default=True,
    metavar="SUBJECT",
    help="Email subject line.",
)
@optgroup.group("DIAGNOSTIC OPTIONS")
@optgroup.option(
    "--print-rules",
    type=bool,
    is_flag=True,
    default=False,
    help="Print rules and exit.",
)
@optgroup.option(
    "--print-conf",
    type=bool,
    is_flag=True,
    default=False,
    help="Print source and service configurations and exit.",
)
@click.argument(
    "log_file_streams",
    type=click.File("r"),
    metavar="[LOGFILE]...",
    nargs=-1,
)
@click.pass_context
def cli(  # noqa: C901, PLR0912, PLR0913, PLR0915
    ctx: click.Context,
    config_dir: Path,
    log_file_streams: tuple[io.TextIOWrapper],
    output_devnull: bool,
    output_file_dir: Path,  ## noqa: ARG001
    output_file_name: str,
    output_smtp_auth_password: str,  ## noqa: ARG001
    output_smtp_auth_ssl: bool,  ## noqa: ARG001
    output_smtp_auth_tls: bool,  ## noqa: ARG001
    output_smtp_auth_username: str,  ## noqa: ARG001
    output_smtp_host: str,  ## noqa: ARG001
    output_smtp_port: int,  ## noqa: ARG001
    output_smtp_rcpt_name: str,  ## noqa: ARG001
    output_smtp_rcpt: str,  ## noqa: ARG001
    output_smtp_sender_name: str,  ## noqa: ARG001
    output_smtp_sender: str,  ## noqa: ARG001
    output_smtp_subject: str,  ## noqa: ARG001
    output_stdout: bool,
    output_template_file: str,  ## noqa: ARG001
    print_rules: bool,
    print_conf: bool,
    services: tuple[str],  ## noqa: ARG001
    sources: tuple[str],  ## noqa: ARG001
    tail_debug: bool,  ## noqa: ARG001
    tail_file_bin: Path,  ## noqa: ARG001
    tail_file_paths: tuple[Path],
    tail_ignore: bool,  ## noqa: ARG001
    tail_journal_bin: Path,  ## noqa: ARG001
    tail_journal_dir: Path,  ## noqa: ARG001
    tail_journal_since: str,  ## noqa: ARG001
    tail_reset: bool,
    tail_state_dir: Path,
    verbose: int,
) -> int:
    """Read JSON structured logs and filter entries for unusual activity.

    When no LOGFILE(s) are provided, read/tail and filter logs for configured log sources.
    Alternatively, read and/or tail and filter LOGFILE(s) for a specified SOURCE.
    When LOGFILE is -, read standard input.
    """
    # Adjust logging level
    loglevel = VERBOSE_LOGGING_LEVELS[min(verbose, len(VERBOSE_LOGGING_LEVELS) - 1)]
    logging.getLogger().setLevel(loglevel)

    logging.debug(f"jsonlogalert version {JSONLOGALERT_VER}")

    if tail_reset:
        _delete_tail_state_files(tail_state_dir)
        sys.exit(0)

    cli_config = {}
    default_config = {}

    # Command line options override config file options (for sources and services too)
    for param, param_value in ctx.params.items():
        if param not in MAIN_OPTS_DIRECTIVES:
            if ctx.get_parameter_source(param) == ParameterSource.COMMANDLINE:
                cli_config[param] = param_value
            else:
                default_config[param] = param_value

    # Click only loads options it knows about, so this is mostly an assertion
    main_conf_check(cli_config, default_config)

    # Command line overrides source/service output configurations
    if output_devnull:
        logging.info("Directing all output to /dev/null")
        cli_config["output_stdout"] = False
        cli_config["output_file_dir"] = None
        cli_config["output_smtp_rcpt"] = None
    elif output_stdout:
        logging.info("Directing all output to stdout")
        cli_config["output_file_dir"] = None

        if "output_smtp_rcpt" not in cli_config:
            cli_config["output_smtp_rcpt"] = None  # Debug SMTP only if explicitly enabled
        else:
            logging.info("SMTP output will be sent to stdout")

    # Resolve full path to executables
    for binopt in ("tail_file_bin", "tail_journal_bin"):
        if binopt in default_config:
            default_config[binopt] = resolve_bin(default_config[binopt], binopt)

    # Load sources
    log_sources = LogSource.load_sources(config_dir, cli_config, default_config)

    file_sources = tuple(s for s in log_sources if not isinstance(s, LogSourceSystemdJournal))
    journal_sources = tuple(s for s in log_sources if isinstance(s, LogSourceSystemdJournal))

    # Only one journal makes sense
    if len(journal_sources) > 1:
        raise LogAlertConfigError(f"Only one journal source can be enabled ({len(journal_sources)} found)")

    logging.debug("Configuration complete, ready to read logs!")

    if print_rules:
        i = 0
        for log_source in log_sources:
            for log_service in log_source.log_services:
                if i:
                    click.echo("")
                log_service.print_rules()
                i += 1

        sys.exit(0)

    if print_conf:
        for i, log_source in enumerate(log_sources):
            if i:
                click.echo("")
            log_source.print_conf()

        sys.exit(0)

    if tail_file_paths or log_file_streams:
        if not file_sources:
            raise LogAlertConfigError("A single logfile source must be enabled to parse given files")
        if len(file_sources) > 1:
            # We need to know how to parse provided file
            raise LogAlertConfigError("A single '--source' must be specified to know how to parse given files")

    if tail_file_paths:
        assert isinstance(tail_file_paths, Sequence)
        # Source default logs are not read if LOGFILEs are specified.
        file_sources[0].logfiles = tail_file_paths

    if log_file_streams:
        assert isinstance(log_file_streams, Sequence)
        # Source default logs are not read if LOGFILEs are specified.
        file_sources[0].logstreams = log_file_streams

    # Deaggregate sources that need to be
    new_sources = []
    for log_source in log_sources:
        new_sources.extend(log_source.deaggregate())
    log_sources = tuple(new_sources)

    # Count services *after* deaggregation
    services_count = 0
    for log_source in log_sources:
        services_count += len(log_source.log_services)

    if output_file_name and services_count > 1:
        raise LogAlertConfigError("A single '--service' with a single log file must be specified to use '--output-file-name'")

    for log_source in log_sources:
        log_source.reset()
        log_source.tail_source()
        log_source.output()

    logging.debug("Done!")


if __name__ == "__main__":
    sys.exit(cli())
