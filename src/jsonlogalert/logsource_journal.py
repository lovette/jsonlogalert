from __future__ import annotations

import sys
from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from pathlib import Path

from functools import cached_property
from uuid import UUID

from jsonlogalert.confcheck import JOURNAL_SOURCE_CONFFILE_DIRECTIVES, conf_del_keys
from jsonlogalert.logsource import LogSource

try:
    from systemd import journal  # type: ignore[reportMissingImports]
except ImportError as err:
    print(f"Python ImportError: {err}; see install instructions for https://github.com/systemd/python-systemd", file=sys.stderr)  # noqa: T201
    sys.exit(1)

# Known fields can be converted to native types (int, datetime, etc.)
# https://www.freedesktop.org/software/systemd/man/systemd.journal-fields.html
JOURNAL_FIELD_CONVERTERS = journal.DEFAULT_CONVERTERS | {
    "_BOOT_ID": UUID,
    "_MACHINE_ID": UUID,
    "MESSAGE_ID": UUID,
    "__REALTIME_TIMESTAMP": lambda ts: journal.DEFAULT_CONVERTERS["__REALTIME_TIMESTAMP"](int(ts)),
    "__MONOTONIC_TIMESTAMP": int,
}

JOURNAL_TIMESTAMP_FIELD_DEFAULT = "__REALTIME_TIMESTAMP"
JOURNAL_MESSAGE_FIELD_DEFAULT = "MESSAGE"

# Map non-printable characters to None so translate() can remove them.
# Thanks to https://stackoverflow.com/a/54451873/437518
_NONPRINTABLE_CHARACTERS = {i: None for i in range(sys.maxunicode + 1) if not chr(i).isprintable() and chr(i) not in {"\n", "\r"}}


######################################################################
# LogSourceSystemdJournal


class LogSourceSystemdJournal(LogSource):
    """Log source that tails journald."""

    def __init__(self, source_dir: Path, source_config: dict[str, Any]) -> None:
        """Constructor.

        Args:
            source_dir (Path): Path to directory containing log source configuration.
            source_config (dict[str, Any]): Log source configuration.
        """
        super().__init__(source_dir, source_config)

        # Converters will be applied to captured fields
        self.field_converters = JOURNAL_FIELD_CONVERTERS.copy()

        self.timestamp_field_default = JOURNAL_TIMESTAMP_FIELD_DEFAULT
        self.message_field_default = JOURNAL_MESSAGE_FIELD_DEFAULT

    @cached_property
    def journal_dir(self) -> str | None:
        """Journal directory or None for systemd default.

        Returns:
            Optional[str]
        """
        journal_dir = self.source_config.get("journal_dir")

        if journal_dir and journal_dir.startswith("default"):
            # Use None instead of "default" internally
            journal_dir = None

        return journal_dir

    def load_conf(self, cli_config: dict[str, Any], default_config: dict[str, Any]) -> None:
        """Apply source configuration and load service configurations.

        Args:
            cli_config (dict): Command line configuration options.
            default_config (dict): Default configuration options.
        """
        super().load_conf(cli_config, default_config)

        # These are unnecessary at runtime and don't need to show up in print_conf()
        conf_del_keys(self.source_config, set(self.source_config.keys()) - JOURNAL_SOURCE_CONFFILE_DIRECTIVES)

    def tail_source(self) -> None:
        """Tail systemd journal as configured.

        Raises:
            LogAlertTailError: Tail failed.
        """
        self.log_debug(f"Tailing systemd-journal: {self.journal_dir or 'default'}")

        tail_ignore = self.tail_ignore or self.tail_journal_since
        tail_dryrun = self.tail_dryrun or tail_ignore
        tail_cursor_path = self.get_tail_state_path(self.journal_dir or "systemd-journal")

        exec_args = [str(self.tail_journal_bin)]

        # Be explicit that we want *all* data.
        exec_args.append("-a")

        if tail_ignore:
            self.log_debug("Tail cursor state file is ignored")

            if not self.tail_journal_since or self.tail_journal_since == "today":
                self.log_debug("Tail will start with today's events")
                exec_args.extend(("-r",))
            elif self.tail_journal_since == "boot":
                self.log_debug("Tail will start at the current boot")
                exec_args.extend(("-b",))
            elif self.tail_journal_since == "all":
                self.log_debug("Tail will start at the beginning of the journal")
                exec_args.extend(("-A",))
            else:
                self.log_error(f"'{self.tail_journal_since}' is not a valid '--tail-journal-since' option")
        else:
            if tail_cursor_path.is_file():
                self.log_debug(f"Tail will continue from previous cursor: {tail_cursor_path}")
            else:
                self.log_debug("Tail will start with today's events")
            exec_args.extend(("-o", str(tail_cursor_path)))

        if tail_dryrun:
            self.log_debug("Tail cursor state file will not be updated")
            exec_args.extend(("-t",))

        if self.journal_dir:
            exec_args.extend(("-D", str(self.journal_dir)))

        self.tail_exec(tuple(exec_args))

    def apply_field_converters(self, rawfields: dict, log_line: str) -> None:
        """Convert field values to native types using `self.field_converters`.

        Args:
            rawfields (dict): Log entry fields and values.
            log_line (str): Log line.
        """
        # According to the journalctl man page the option '--all' should decode "blob data" best it can.
        # The source code supports this understanding (see json_escape):
        # https://github.com/systemd/systemd/blob/9671efff78e44310743d5e49d512846615777263/src/shared/logs-show.c#L1
        #
        # But as I'm testing this on RHEL 9.4 in 9/2024, "MESSAGE" fields are decoded **unless**
        # the output format is JSON. I can't explain this behavior.
        #
        # An apparent fix was applied in 2016.
        # https://github.com/systemd/systemd/issues/3416
        #
        # Vector implemented a workaround for this issue in 2020.
        # https://github.com/vectordotdev/vector/issues/1714

        for field in self.blob_fields:
            if field in rawfields and isinstance(rawfields[field], list):
                rawfields[field] = bytes(rawfields[field]).decode(errors="replace").translate(_NONPRINTABLE_CHARACTERS)

        super().apply_field_converters(rawfields, log_line)
