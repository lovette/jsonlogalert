from __future__ import annotations  # noqa: INP001

import re
from collections import defaultdict
from collections.abc import Sequence
from datetime import datetime, timezone
from typing import TYPE_CHECKING

from jsonlogalert.exceptions import LogAlertParserError
from jsonlogalert.logsourceparser import LogSourceParser

if TYPE_CHECKING:
    from jsonlogalert.logsource import LogSource

MSG_ACTION_ARRIVAL = "<="  # message arrival
MSG_ACTION_FAKEREJECT = "(="  # message fakereject
MSG_ACTION_DELIVERY = "=>"  # normal message delivery
MSG_ACTION_DELIVERY_ADDL = "->"  # additional address in same delivery
MSG_ACTION_DELIVERY_CUTTHROUGH = ">>"  # cutthrough message delivery
MSG_ACTION_SUPPRESSED = "*>"  # delivery suppressed by -N
MSG_ACTION_FAILED = "**"  # delivery failed; address bounced
MSG_ACTION_DEFERRED = "=="  # delivery deferred; temporary problem

MSG_ACTIONS = (
    MSG_ACTION_ARRIVAL,
    MSG_ACTION_FAKEREJECT,
    MSG_ACTION_DELIVERY,
    MSG_ACTION_DELIVERY_ADDL,
    MSG_ACTION_DELIVERY_CUTTHROUGH,
    MSG_ACTION_SUPPRESSED,
    MSG_ACTION_FAILED,
    MSG_ACTION_DEFERRED,
)

DELIVERY_STATUS_PRETTY = {
    MSG_ACTION_ARRIVAL: "received",
    MSG_ACTION_FAKEREJECT: "fakereject",
    MSG_ACTION_DELIVERY: "success",
    MSG_ACTION_DELIVERY_ADDL: "success (additional)",
    MSG_ACTION_DELIVERY_CUTTHROUGH: "success (cutthrough)",
    MSG_ACTION_SUPPRESSED: "suppressed",
    MSG_ACTION_FAILED: "failed",
    MSG_ACTION_DEFERRED: "deferred",
}

# https://www.exim.org/exim-html-current/doc/html/spec_html/ch-log_files.html
# (Field identifier, (message actions), capture name, re_pattern)
# Default re_pattern is r"[^\s]+"
# All re_pattern will include but not capture trailing "\s?"
FIELD_IDENTIFIERS: tuple[str, tuple[str] | None, str] = (
    # authenticator name (and optional id and sender)
    ("A", None, "AUTHENTICATOR_NAME", r"\w+"),
    # SMTP confirmation on delivery
    ("C", ("=>",), None, r"\"(?P<DELIVERY_MESSAGE>[^\"]+)\""),
    # command list for “no mail in SMTP session”
    ("C", None, "SMTP_COMMAND_LIST", None),
    # certificate verification status
    ("CV", None, None, r"(?P<CERT_VERIFY>\w+):?"),
    # duration of “no mail in SMTP session”
    ("D", None, "DURATION", None),
    # domain verified in incoming message
    ("DKIM", None, "DKIM_VERIFY", None),
    # distinguished name from peer certificate
    ("DN", None, "PEER_DN", None),
    # DNSSEC secured lookups
    ("DS", None, "DNSSEC_LOOKUP", None),
    # on =>, == and ** lines: time taken for, or to attempt, a delivery
    ("DT", ("=>", "==", "**"), "TIME_TAKEN", None),
    # sender address (on delivery lines)
    ("F", None, "SENDER", None),
    # host name and IP address
    ("H", None, None, r"(?P<HOST_NAME>[-.\w]+)\s\[(?P<HOST_IP>[.\d]+)\]:?"),
    # local interface used
    ("I", None, "LOCAL_IFACE", None),
    # message id (from header) for incoming message
    ("id", None, "H_MESSAGEID", None),
    # CHUNKING extension used
    ("K", None, "EXT_CHUNKING", None),
    # on <= and => lines: PIPELINING extension used
    ("L", ("<=", "=>"), "EXT_PIPELINING", None),
    # 8BITMIME status for incoming message
    ("M8S", None, "EIGHTBITMIME", None),
    # on <= lines: protocol used
    ("P", ("<=",), "CONN_PROTO", r"\w+"),
    # on => and ** lines: return path
    ("P", ("=>", "**"), "RETURN_PATH", None),
    # PRDR extension used
    ("PRDR", None, "EXT_PRDR", None),
    # on <= and => lines: proxy address
    ("PRX", ("<=", "=>"), "PROXY_ADDR", None),
    # alternate queue name
    ("Q", None, "ALTERNATE_QUEUE", None),
    # on => lines: time spent on queue so far
    ("QT", ("=>",), "QUEUE_TIME_PENDING", None),
    # on “Completed” lines: time spent on queue
    ("QT", None, "QUEUE_TIME_TOTAL", None),
    # on <= lines: reference for local bounce
    ("R", ("<=",), "LOCAL_BOUNCE_REF", None),
    # on =>  >> ** and == lines: router name
    ("R", ("=>", ">>", "**", "=="), "ROUTER", r"[-\w]+"),
    # on <= lines: time taken for reception
    ("RT", ("<=",), "TIME_TAKEN_RCPT", None),
    # size of message in bytes
    ("S", None, "MSGSIZE", r"\d+"),
    # server name indication from TLS client hello
    ("SNI", None, "TLS_HELO", None),
    # shadow transport name
    ("ST", None, "TRANSPORT_SHADOW", None),
    # on <= lines: message subject (topic)
    ("T", ("<=",), None, r"\"(?P<H_SUBJECT>[^\"]+)\""),
    # on => ** and == lines: transport name
    ("T", ("=>", "**", "=="), "TRANSPORT", r"[-\w]+"),
    # connection took advantage of TCP Fast Open
    ("TFO", None, "TCP_FAST_OPEN", None),
    # local user or RFC 1413 identity
    ("U", None, "USER_IDENT", None),
    # TLS cipher suite
    ("X", None, "TLS_CIPHER_SUITE", None),
)

WARN_KEYWORDS = (
    "closed connection",
    "daemon started",
    "unfrozen",
)

ERROR_KEYWORDS = (
    "denied",
    "error",
    "failed",
    "freezing",
    "frozen",
    "invalid",
    "problem",
    "rejected",
)

FIELD_CONVERTERS = {
    "DURATION": int,
    "MSGSIZE": int,
    "QUEUE_TIME_PENDING": int,
    "QUEUE_TIME_TOTAL": int,
    "DELIVERY_CODE": int,
    "TIME_TAKEN_RCPT": int,
    "TIME_TAKEN": int,
}

######################################################################
# LogAlertLogSourceParser


class LogAlertLogSourceParser(LogSourceParser):
    """Jsonlogalert parser for Exim mail server log files."""

    def __init__(self, log_source: LogSource) -> None:
        """Constructor.

        Args:
            log_source (LogSource): Log source for this parser.
        """
        super().__init__(log_source)

        # Converters will be applied to captured fields
        self.field_converters = FIELD_CONVERTERS

        p_timestamp = r"(?P<TIMESTAMP>[-\d]+\s[:\d]+)"
        p_msgid = r"(?P<MSGID>\w+-\w+-\w{2})"
        p_message = r"(?P<MESSAGE>.*)$"

        self.re_extract_timestamp = (
            # DATE TIME MSGID MESSAGE
            re.compile(rf"{p_timestamp}\s{p_msgid}\s{p_message}"),
            # DATE TIME MESSAGE
            re.compile(rf"{p_timestamp}\s{p_message}"),
        )

        p_actions = "|".join(map(re.escape, MSG_ACTIONS))
        self.re_message_action = re.compile(rf"^(?P<MSG_ACTION>({p_actions}))\s(?P<MSG_ACTION_EMAIL>[^@]+@[^\s]+)\s?")

        p_warn_keywords = "|".join(WARN_KEYWORDS)
        self.re_warn_keywords = re.compile(rf"\b({p_warn_keywords})\b")

        p_error_keywords = "|".join(ERROR_KEYWORDS)
        self.re_error_keywords = re.compile(rf"\b({p_error_keywords})\b")

        p_field_identifiers = "|".join(sorted({t[0] for t in FIELD_IDENTIFIERS}))
        self.re_field_identifier_keys = re.compile(rf"\b({p_field_identifiers})=")

        # Parse components of C= field.
        self.re_delivery_confirm_status = re.compile(r"(?P<DELIVERY_CODE>\d+)\s(?P<DELIVERY_MESSAGE>.+)$")

        self.re_delivery_error_status = (
            # SMTP error from remote mail server after pipelined end of data: 550 MESSAGE
            re.compile(r"SMTP error from remote mail server [^:]+: (?P<DELIVERY_CODE>\d+)"),
        )

        self.field_identifier_map: dict[str, dict[str | None, re.Pattern]] = defaultdict(dict)

        for field_key, actions, capture_name, re_field_idpattern in FIELD_IDENTIFIERS:
            assert field_key is not None
            re_pattern = re_field_idpattern

            if not re_pattern:
                re_pattern = r"[^\s]+"

            if capture_name:
                re_pattern = rf"(?P<{capture_name}>{re_pattern})"

            re_pattern = re.compile(rf"\b{field_key}={re_pattern}\s?")

            if actions:
                assert isinstance(actions, Sequence)
                for action in actions:
                    assert action not in self.field_identifier_map[field_key]
                    self.field_identifier_map[field_key][action] = re_pattern
            else:
                assert actions not in self.field_identifier_map[field_key]
                self.field_identifier_map[field_key][actions] = re_pattern

    def _add_match_group_fields(self, fields: dict[str, str], re_pattern: re.Pattern, text: str) -> bool:
        """Match a regular expression with the beginning of a text string
        and set any named groups captured by the expression as log entry fields.

        Args:
            fields (dict[str, str]): Log entry fields.
            re_pattern (re.Pattern): Regular expression.
            text (str): Text to search.

        Returns:
            bool: True if named groups were added to fields.
        """
        matches = re_pattern.match(text)
        if matches:
            named_groups = matches.groupdict()
            if named_groups:
                fields.update(named_groups)
                return True

        return False

    def _extract_field(self, fields: dict[str, str], re_pattern: re.Pattern) -> bool:
        """Search log entry MESSAGE field for the first regular expression match
        and set any named groups captured by the expression as log entry fields.
        The matched subtring is then removed from MESSAGE.

        Args:
            fields (dict[str, str]): Log entry fields.
            re_pattern (re.Pattern): Regular expression.
        """
        message = fields["MESSAGE"]
        matches = re_pattern.search(message)
        if matches:
            named_groups = matches.groupdict()
            if named_groups:
                fields.update(named_groups)
                fields["MESSAGE"] = self._remove_match(matches, message)
                return True

        return False

    def _remove_match(self, matches: re.Match, text: str) -> str:
        """Remove matched substring from text.

        An alternative would be: re_pattern.sub("", text, count=1)
        This function keeps from having to evaluate RE twice so maybe it's more efficient?

        Args:
            matches (re.Match): Regular expression match.
            text (str): Text to remove from.

        Returns:
            str: New text.
        """
        start, end, length = matches.start(), matches.end(), len(text)
        if start == 0:
            return text[end:] if end < length else ""
        if end == length:
            return text[:start]
        return text[:start] + text[end:]

    def parse_line(self, log_line: str) -> dict:  # noqa: C901, PLR0912
        """Parse source log entry into a dict of structured fields.

        Args:
            log_line (str): Log entry from source.

        Raises:
            LogAlertParserError: Parse failure.

        Returns:
            dict: Parse success.
        """
        fields = {}

        # First, extract timestamp and MESSAGE
        for re_timestamp in self.re_extract_timestamp:
            if self._add_match_group_fields(fields, re_timestamp, log_line):
                break

        if "TIMESTAMP" not in fields:
            raise LogAlertParserError(f"Failed to parse date and time fields: '{log_line}'")

        try:
            fields["TIMESTAMP"] = datetime.strptime(fields["TIMESTAMP"], "%Y-%m-%d %H:%M:%S").replace(tzinfo=timezone.utc)
        except ValueError as err:
            raise LogAlertParserError(f"{err}: '{log_line}'") from err

        # Try to capture delivery action and email address
        self._extract_field(fields, self.re_message_action)

        msgaction = fields.get("MSG_ACTION")

        if msgaction:
            fields["DELIVERY_STATUS"] = DELIVERY_STATUS_PRETTY.get(msgaction)

        # Does the message contain any FIELD= identifiers?
        identifier_keys = self.re_field_identifier_keys.findall(fields["MESSAGE"]) or None

        if identifier_keys:
            for identifier_key in identifier_keys:
                identifier_patterns = self.field_identifier_map.get(identifier_key)

                # identifier can have different regex for different message actions
                re_identifier = identifier_patterns.get(msgaction)
                if not re_identifier:
                    re_identifier = identifier_patterns.get(None)

                if re_identifier:
                    self._extract_field(fields, re_identifier)

            # Try to capture delivery success status code
            if "DELIVERY_MESSAGE" in fields:
                self._add_match_group_fields(fields, self.re_delivery_confirm_status, fields["DELIVERY_MESSAGE"])

        if msgaction == MSG_ACTION_FAILED:
            # Try to capture delivery failure status code
            for re_error in self.re_delivery_error_status:
                if self._add_match_group_fields(fields, re_error, fields["MESSAGE"]):
                    fields["DELIVERY_MESSAGE"] = fields["MESSAGE"]
                    fields["MESSAGE"] = ""
                    break

        # Assign a priority based on message keywords
        priority = "info"
        if self.re_error_keywords.search(fields["MESSAGE"]):
            priority = "err"
        elif self.re_warn_keywords.search(fields["MESSAGE"]):
            priority = "warn"
        fields["PRIORITY"] = priority

        if not fields["MESSAGE"]:
            # Entire message was parsed into fields
            fields["MESSAGE"] = None

        return fields
