"""
Structured, colored logger for r3ngine modules.

Ported from rengine-ng's BaseLogger + ModuleLogger system.
SecatorAPILogger and RunnerLogger are not included (Secator-specific).

Usage::

    from reNgine.utils.logger import get_module_logger

    logger = get_module_logger(__name__)
    logger.log_line("[SCAN]", "START", "beginning port scan for %s" % target)
    logger.info("plain info %s", value)
"""

import json
import logging
import os
import sys
from abc import ABC, abstractmethod
from typing import Any, Dict, Optional


class BaseLogger(ABC):
    """Generic base logger with ANSI color support and structured formatting."""

    COLOR_RESET = "\033[0m"
    COLOR_GREEN = "\033[32m"
    COLOR_YELLOW = "\033[33m"
    COLOR_RED = "\033[31m"
    COLOR_CYAN = "\033[36m"
    COLOR_BLUE = "\033[34m"
    COLOR_MAGENTA = "\033[35m"
    COLOR_VIOLET = "\033[95m"
    COLOR_BRIGHT_BLUE = "\033[94m"

    def __init__(self, logger_name: Optional[str] = None) -> None:
        self._logger = logging.getLogger(logger_name or self.__class__.__module__)
        self._use_colors = self._detect_color_support()

    @abstractmethod
    def _get_prefix_color(self, prefix: str) -> str: ...

    def _detect_color_support(self) -> bool:
        if os.environ.get("FORCE_COLOR") in ("1", "true", "yes"):
            return True
        if os.environ.get("NO_COLOR"):
            return False
        if hasattr(sys.stdout, "isatty") and sys.stdout.isatty():
            return True
        if hasattr(sys.stderr, "isatty") and sys.stderr.isatty():
            return True
        loggers_to_check = [self._logger]
        current = self._logger
        while current.parent:
            loggers_to_check.append(current.parent)
            current = current.parent
        for lg in loggers_to_check:
            for handler in lg.handlers:
                if isinstance(handler, logging.StreamHandler):
                    stream = handler.stream
                    if hasattr(stream, "isatty") and stream.isatty():
                        return True
        return True  # default: ANSI codes are harmless when not supported

    def _colorize(self, text: str, color: str) -> str:
        return f"{color}{text}{self.COLOR_RESET}" if self._use_colors else text

    def _format_line(self, prefix: str, action: str, message: str, action_color: str) -> str:
        prefix_colored = self._colorize(prefix, self._get_prefix_color(prefix))
        action_colored = self._colorize(action, action_color)
        return f"{prefix_colored} {action_colored} | {message}"

    def _format_info_line(
        self,
        prefix: str,
        action: str,
        details: Dict[str, Any],
        result: str,
        result_color: str = COLOR_GREEN,
    ) -> str:
        detail_parts = [f"{k}={v}" for k, v in details.items() if v is not None]
        detail_str = " ".join(detail_parts)
        result_str = self._colorize(result, result_color)
        prefix_colored = self._colorize(prefix, self._get_prefix_color(prefix))
        action_colored = self._colorize(action, self.COLOR_BRIGHT_BLUE)
        if detail_str:
            return f"{prefix_colored} {action_colored} | {detail_str} → {result_str}"
        return f"{prefix_colored} {action_colored} | → {result_str}"

    def log_error(self, error: Exception, context: Dict[str, Any], exc_info: bool = True) -> None:
        prefix = context.get("prefix", "[ERROR]")
        action = context.get("action", "ERROR")
        details = {k: v for k, v in context.items() if k not in ("prefix", "action", "error")}
        line = self._format_info_line(prefix, action, details, f"ERROR: {error}", self.COLOR_RED)
        self._logger.error(line, exc_info=exc_info)

    def log_warning(self, message: str, context: Optional[Dict[str, Any]] = None) -> None:
        prefix = (context or {}).get("prefix", "[WARNING]")
        action = (context or {}).get("action", "WARNING")
        details = {k: v for k, v in (context or {}).items() if k not in ("prefix", "action")}
        line = self._format_info_line(prefix, action, details, message, self.COLOR_YELLOW)
        self._logger.warning(line)

    def log_debug(self, prefix: str, action: str, message: str) -> None:
        self._logger.debug(self._format_line(prefix, action, message, self.COLOR_VIOLET))

    def log_data_structure(self, data: Any, prefix: str, data_type: str) -> None:
        prefix_colored = self._colorize(prefix, self._get_prefix_color(prefix))
        action_colored = self._colorize("STRUCTURE", self.COLOR_VIOLET)
        self._logger.debug(
            "%s %s | Full %s structure:\n%s", prefix_colored, action_colored, data_type, json.dumps(data, indent=2, default=str)
        )


_ALLOWED_LOG_LEVELS = frozenset({"debug", "info", "warning", "error"})


def format_exception_for_log(exc: BaseException) -> str:
    """Format an exception for server-side log messages (never expose raw to clients)."""
    msg = str(exc).strip() or "(no message)"
    return "%s: %s" % (type(exc).__name__, msg)


class ModuleLogger(BaseLogger):
    """
    Drop-in structured logger for r3ngine modules.

    Usage::

        logger = get_module_logger(__name__)
        logger.log_line("[SCAN]", "START", "running nuclei on %s" % target)
        logger.info("plain log %s", value)
        logger.error("failed: %s", format_exception_for_log(exc), exc_info=True)
    """

    def __init__(self, logger_name: str) -> None:
        super().__init__(logger_name=logger_name)

    def _get_prefix_color(self, prefix: str) -> str:
        return self.COLOR_BLUE

    def log_line(
        self,
        prefix: str,
        action: str,
        message: str,
        level: str = "info",
        exc_info: bool = False,
    ) -> None:
        """
        Log a section-style line: [PREFIX] ACTION | message with ANSI colors.

        Args:
            prefix: Section prefix, e.g. "[SCAN]" or "[FUZZING]"
            action: Short action label, e.g. "START", "RESULT", "ERROR"
            message: Log message text
            level: "debug", "info", "warning", or "error"
            exc_info: If True, append current exception traceback
        """
        if level not in _ALLOWED_LOG_LEVELS:
            raise ValueError(
                "log_line level must be one of %s, got %r" % (sorted(_ALLOWED_LOG_LEVELS), level)
            )
        action_colors = {
            "debug": self.COLOR_VIOLET,
            "info": self.COLOR_BRIGHT_BLUE,
            "warning": self.COLOR_YELLOW,
            "error": self.COLOR_RED,
        }
        line = self._format_line(prefix, action, message, action_colors[level])
        if level == "debug":
            self._logger.debug(line, exc_info=exc_info)
        elif level == "warning":
            self._logger.warning(line, exc_info=exc_info)
        elif level == "error":
            self._logger.error(line, exc_info=exc_info)
        else:
            self._logger.info(line, exc_info=exc_info)

    def debug(self, msg: str, *args: Any, **kwargs: Any) -> None:
        self._logger.debug(msg, *args, **kwargs)

    def info(self, msg: str, *args: Any, **kwargs: Any) -> None:
        self._logger.info(msg, *args, **kwargs)

    def warning(self, msg: str, *args: Any, **kwargs: Any) -> None:
        self._logger.warning(msg, *args, **kwargs)

    def error(self, msg: str, *args: Any, **kwargs: Any) -> None:
        self._logger.error(msg, *args, **kwargs)

    def exception(self, msg: str, *args: Any, **kwargs: Any) -> None:
        self._logger.exception(msg, *args, **kwargs)

    def critical(self, msg: str, *args: Any, **kwargs: Any) -> None:
        self._logger.critical(msg, *args, **kwargs)


def get_module_logger(name: str) -> ModuleLogger:
    """
    Return a ModuleLogger for the given module.

    Call once per module at module level::

        from reNgine.utils.logger import get_module_logger
        logger = get_module_logger(__name__)
    """
    return ModuleLogger(name)
