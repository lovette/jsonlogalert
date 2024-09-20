from __future__ import annotations

import copy
import logging
from collections.abc import Sequence
from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from collections import List
    from io import TextIOWrapper
    from pathlib import Path

from jsonlogalert.confcheck import FILE_SOURCE_CONFFILE_DIRECTIVES, conf_del_keys
from jsonlogalert.logsource import LogSource

######################################################################
# LogSourceTextFile


class LogSourceTextFile(LogSource):
    """Log source that tails a set of text files."""

    def __init__(self, source_dir: Path, source_config: dict[str, Any]) -> None:
        """Constructor.

        Args:
            source_dir (Path): Path to directory containing log source configuration.
            source_config (dict[str, Any]): Log source configuration.
        """
        super().__init__(source_dir, source_config)

        # Log files can be empty since they may be supplied on the command line
        self.logfiles: Sequence[str] = tuple(source_config.get("logfiles", []))

        # Streams are always specified on the command line
        self.logstreams: Sequence[TextIOWrapper] = ()

    def load_conf(self, cli_config: dict[str, Any], default_config: dict[str, Any]) -> None:
        """Apply source configuration and load service configurations.

        Args:
            cli_config (dict): Command line configuration options.
            default_config (dict): Default configuration options.
        """
        super().load_conf(cli_config, default_config)

        # These are unnecessary at runtime and don't need to show up in print_conf()
        conf_del_keys(self.source_config, set(self.source_config.keys()) - FILE_SOURCE_CONFFILE_DIRECTIVES)

    def tail_source(self) -> None:
        """Tail source 'logfiles' as configured.

        Raises:
            LogAlertTailError: Tail failed.
        """
        if not (self.logfiles or self.logstreams):
            logging.warning(f"Log source '{self.name}' has no logs to read")

        if self.logfiles:
            if self.onelog:
                self.log_debug(f"Reading {len(self.logfiles)} log files (onelog)")
            else:
                self.log_debug(f"Reading {len(self.logfiles)} log files")

            for log_file_path in self.logfiles:
                self._tail_file(log_file_path)

        if self.logstreams:
            self.log_debug(f"Reading {len(self.logstreams)} file streams from command line...")

            for logstream in self.logstreams:
                self.parse_stream(logstream, logstream.name)

    def _tail_file(self, log_file_path: Path) -> None:
        """Tail a file.

        Args:
            log_file_path (Path): File path.

        Raises:
            LogAlertTailError: Tail failed.
        """
        self.log_debug(f"Tailing {log_file_path}")

        tail_dryrun = self.tail_dryrun or self.tail_ignore

        log_offset_path = self.get_tail_state_path(log_file_path)

        # Note: If neither -t or -o is specified, logtail2 will (attempt) create
        # an offset file in the log file directory.

        exec_args = [str(self.tail_file_bin)]

        if self.tail_ignore:
            self.log_debug("Tail offset state is ignored; reading whole file")
        else:
            if log_offset_path.is_file():
                self.log_debug(f"Tail will continue from previous offset: {log_offset_path}")
            exec_args.extend(("-o", str(log_offset_path)))

        if tail_dryrun:
            self.log_debug("Tail offset state file will not be updated")
            exec_args.extend(("-t",))

        exec_args.extend(("-f", str(log_file_path)))

        self.tail_exec(tuple(exec_args))

    def deaggregate(self) -> List[LogSource]:
        """Return a new list of sources after deaggreating logs.

        Returns:
            List[LogSource]
        """
        if self.onelog or (len(self.logfiles) + len(self.logstreams)) == 1:
            return [self]

        # We make shallow copies of the source because 99% of the source
        # properties don't change once the configuration is loaded.
        # Everything that does change between iterations is cleared by reset().

        # Add one source for each logfile and each logstream.
        # The first source is always 'self'.

        new_sources = []

        for logfile in tuple(self.logfiles):
            new_source = copy.copy(self) if len(new_sources) else self
            new_source.replica_index = len(new_sources)
            new_source.logfiles = (logfile,)
            new_sources.append(new_source)

        for logstream in tuple(self.logstreams):
            new_source = copy.copy(self) if len(new_sources) else self
            new_source.replica_index = len(new_sources)
            new_source.logstreams = (logstream,)
            new_sources.append(new_source)

        self.log_debug(f"Deaggregated into {len(new_sources)} sources")

        return new_sources

    def setlogfiles(self, logfiles: Sequence[str]) -> None:
        """Set log files to read instead of default log files.

        Args:
            logfiles (Sequence[str]): List of log files.
        """
        assert isinstance(logfiles, Sequence)
        self.logfiles = logfiles
        self.logstreams = ()

    def setlogstreams(self, streams: Sequence[TextIOWrapper]) -> None:
        """Set log streams to read instead of default log files.

        Args:
            streams (Sequence[TextIOWrapper]): List of text streams.
        """
        assert isinstance(streams, Sequence)
        self.logfiles = ()
        self.logstreams = streams
