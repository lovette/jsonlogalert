from click import ClickException


class LogAlertRuntimeError(ClickException):
    """Generic app exception."""


class LogAlertParserError(LogAlertRuntimeError):
    """Parser exception."""


class LogAlertConfigError(LogAlertRuntimeError):
    """Configuration exception."""
