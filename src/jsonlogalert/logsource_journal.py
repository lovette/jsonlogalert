from __future__ import annotations

from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from pathlib import Path

from functools import cached_property
from uuid import UUID

from jsonlogalert.exceptions import LogAlertRuntimeError
from jsonlogalert.logsource import LogSource
from systemd import journal  # type: ignore[reportMissingImports]

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

        if journal_dir and journal_dir.startswith("system"):
            # Use None instead of "system" internally
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
        for remove_prefix in ["tail_file"]:
            for k in list(self.source_config.keys()):
                if k.startswith(remove_prefix):
                    del self.source_config[k]

    def tail_source(self) -> None:
        """Tail systemd journal as configured.

        Raises:
            LogAlertRuntimeError: Tail failed.
        """
        self.log_debug(f"Tailing systemd-journal: {self.journal_dir or 'default'}")

        # Use but do not update tail offset
        tail_test_mode = self.tail_debug

        tail_cursor_path = self.get_tail_state_path(self.journal_dir or "systemd-journal")

        exec_args = [str(self.tail_journal_bin)]

        if self.tail_journal_since:
            if self.tail_journal_since == "boot":
                self.log_debug("Tail will start at the current boot")
                exec_args.extend(("-b",))
            elif self.tail_journal_since == "all":
                self.log_debug("Tail will start at the beginning of the journal")
                exec_args.extend(("-A",))
            else:
                raise LogAlertRuntimeError(f"'{self.tail_journal_since}' is not a valid '--tail-journal-since' option")

        elif not self.tail_ignore:
            if tail_cursor_path.is_file():
                self.log_debug(f"Tail will continue from previous cursor: {tail_cursor_path}")
            else:
                self.log_debug("Tail will start with today's events")

        if self.tail_ignore:
            self.log_debug("Tail cursor state file is ignored")
            tail_test_mode = True
        else:
            exec_args.extend(("-o", str(tail_cursor_path)))

        if tail_test_mode:
            self.log_debug("Tail cursor state file will not be updated")
            exec_args.extend(("-t",))

        if self.journal_dir:
            exec_args.extend(("-D", str(self.journal_dir)))

        self.tail_exec(tuple(exec_args))
