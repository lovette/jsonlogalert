from __future__ import annotations

import platform
import ssl
from datetime import datetime, timezone
from email.mime.text import MIMEText
from email.utils import formataddr
from functools import cached_property
from smtplib import SMTP, SMTP_SSL, SMTPException
from typing import TYPE_CHECKING

from click import echo

from jsonlogalert.logalertoutput import LogAlertOutput

if TYPE_CHECKING:
    from jsonlogalert.logservice import LogService

SMTP_SUBJECT_DEFAULT = "Log alert for %HOSTNAME%"


######################################################################
# LogAlertOutputToSMTP


class LogAlertOutputToSMTP(LogAlertOutput):
    """Logalert output to SMTP server."""

    def __init__(self, log_service: LogService) -> None:
        """Constructor.

        Args:
            log_service (LogService): Service using this output.
        """
        super().__init__(log_service)

        self.output_max_bytes_default = 1024 * 1024  # 1 MiB

        self.smtp_host = self.output_smtp_host or "localhost"
        self.smtp_port = self.output_smtp_port or 25
        self.auth_username = self.output_smtp_auth_username
        self.auth_password = self.output_smtp_auth_password
        self.smtp_ssl = self.output_smtp_auth_ssl
        self.smtp_tls = self.output_smtp_auth_tls
        self.rcpt_addr = self.output_smtp_rcpt
        self.rcpt_name = self.output_smtp_rcpt_name
        self.sender_addr = self.output_smtp_sender or self.rcpt_addr
        self.sender_name = self.output_smtp_sender_name or self.rcpt_name
        self.subject = self.output_smtp_subject or SMTP_SUBJECT_DEFAULT
        self.ssl_context = ssl.create_default_context() if self.smtp_ssl or self.smtp_tls else None

    def __call__(self) -> None:
        """Transmit content to SMTP server."""
        content = self.render_template()

        subtype = self.output_content_type
        if subtype != "html":
            subtype = "plain"

        email = MIMEText(content.encode("utf-8"), subtype, "utf-8")

        self._set_message_headers(email)

        message = email.as_string()

        if self.output_max_bytes and len(message) > self.output_max_bytes:
            # Not a fatal error
            self.log_error(f"Refusing to submit SMTP message: Too much content; {len(message)} bytes")
        elif self.output_stdout:
            echo(message)
        else:
            self._send_message(message)

    @cached_property
    def connect_desc(self) -> str:
        """Return connection description for debug output.

        Returns:
            str
        """
        parts = []

        if self.auth_username:
            parts.append(self.auth_username)
        if self.auth_password:
            parts.append(":***")
        if self.auth_username:
            parts.append("@")
        if self.smtp_host:
            parts.append(self.smtp_host)
        if self.smtp_port:
            parts.append(f":{self.smtp_port}")
        if self.smtp_ssl:
            parts.append("/ssl")
        if self.smtp_tls:
            parts.append("/tls")

        return "".join(parts)

    def validate_conf(self) -> None:
        """Initialize and verify output configuration properties.

        Raises:
            LogAlertConfigError: Invalid configuration.
        """
        super().validate_conf()

        if not self.smtp_host:
            self.config_error("SMTP output configuration error", "'output_smtp_host' is not defined")
        if not self.smtp_port:
            self.config_error("SMTP output configuration error", "'output_smtp_port' is not defined")
        if self.auth_password and not self.auth_username:
            self.config_error("SMTP output configuration error", "'output_smtp_auth_password' is set but 'output_smtp_auth_username' is not")
        if not self.rcpt_addr:
            self.config_error("SMTP output configuration error", "'output_smtp_rcpt' is not defined")
        if not self.sender_addr:
            self.config_error("SMTP output configuration error", "'output_smtp_sender' is not defined")
        if not self.subject:
            self.config_error("SMTP output configuration error", "'output_smtp_subject' is not defined")

    def _send_message(self, message: str) -> None:
        """Submit MIME message to SMTP server.

        Args:
            message (str): MIME message.
        """
        self.log_debug(f"Output SMTP submitted to '{self.connect_desc}'")

        try:
            if self.smtp_ssl:
                with SMTP_SSL(self.smtp_host, self.smtp_port, context=self.ssl_context) as server:
                    self._sendmail(server, message)
            else:
                with SMTP(self.smtp_host, self.smtp_port) as server:
                    self._sendmail(server, message)
        except (OSError, SMTPException) as err:
            self.log_error(f"Failed to submit SMTP message to '{self.connect_desc}': {err}")

    def _sendmail(self, server: SMTP, message: str) -> None:
        """Submit message to SMTP server.

        Args:
            server (SMTP): Server object.
            message (str): MIME message.

        Raises:
            OSError
            SMTPException
        """
        if self.smtp_tls:
            server.starttls(context=self.ssl_context)

        if self.auth_username:
            server.login(self.auth_username, self.auth_password)

        server.sendmail(self.sender_addr, self.rcpt_addr, message)

    def _set_message_headers(self, email: MIMEText) -> None:
        """Set message headers.

        Args:
            email (MIMEText): Message
        """

        def _replace_multi(s: str, d: dict[str, str]) -> str:
            if s:
                for k, v in d.items():
                    s = s.replace(k, v)
            return s

        hostname = platform.node()

        placeholders = {
            "%HOSTNAME%": hostname,
            "%SOURCENAME%": self.service.source.name,
            "%SERVICENAME%": self.service.name,
            "%SERVICEDESC%": self.service.description,
        }

        sender_name = _replace_multi(self.sender_name, placeholders)
        rcpt_name = _replace_multi(self.rcpt_name, placeholders)

        email["From"] = formataddr((sender_name, self.sender_addr)) if sender_name else self.sender_addr
        email["To"] = formataddr((rcpt_name, self.rcpt_addr)) if rcpt_name else self.rcpt_addr
        email["Subject"] = _replace_multi(self.subject, placeholders)

        email["X-JsonLogAlert-Date"] = datetime.now(tz=timezone.utc).isoformat()
        email["X-JsonLogAlert-Host"] = hostname
        email["X-JsonLogAlert-Source"] = self.service.source.name
        email["X-JsonLogAlert-Service"] = self.service.name
