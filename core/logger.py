"""Minimal logger with prefixes."""

from datetime import datetime


class Logger:
    """Simple console logger with timestamps."""

    def info(self, msg: str):
        self._log("*", msg)

    def success(self, msg: str):
        self._log("+", msg)

    def warning(self, msg: str):
        self._log("!", msg)

    def error(self, msg: str):
        self._log("ERROR", msg)

    def fail(self, msg: str):
        self._log("-", msg)

    def _log(self, prefix: str, msg: str):
        ts = datetime.now().strftime("%H:%M:%S")
        print(f"[{ts}] [{prefix}] {msg}")
