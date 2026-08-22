# utils/logger.py

from __future__ import annotations

import logging
import os
import sys
from datetime import datetime
from typing import Optional


# ============================================================
# PAG SECURITY BOT
# utils/logger.py
#
# Hafif merkezi terminal logger.
#
# Özellikler:
# - Renkli terminal çıktısı
# - INFO / WARNING / ERROR / CRITICAL / DEBUG
# - Tarih + saat
# - Cog / Service adı
# - Exception traceback
# - Dosyaya log yazma desteği
# - Duplicate handler koruması
# - Discord API çağrısı yok
# - Database bağımlılığı yok
# ============================================================


# ============================================================
# ANSI COLORS
# ============================================================

RESET = "\033[0m"

BLACK = "\033[30m"
RED = "\033[31m"
GREEN = "\033[32m"
YELLOW = "\033[33m"
BLUE = "\033[34m"
MAGENTA = "\033[35m"
CYAN = "\033[36m"
WHITE = "\033[37m"

BRIGHT_BLACK = "\033[90m"
BRIGHT_RED = "\033[91m"
BRIGHT_GREEN = "\033[92m"
BRIGHT_YELLOW = "\033[93m"
BRIGHT_BLUE = "\033[94m"
BRIGHT_MAGENTA = "\033[95m"
BRIGHT_CYAN = "\033[96m"
BRIGHT_WHITE = "\033[97m"


# ============================================================
# LOG LEVEL COLORS
# ============================================================

LEVEL_COLORS = {
    logging.DEBUG: BRIGHT_BLACK,
    logging.INFO: BRIGHT_CYAN,
    logging.WARNING: BRIGHT_YELLOW,
    logging.ERROR: BRIGHT_RED,
    logging.CRITICAL: BRIGHT_MAGENTA,
}


LEVEL_NAMES = {
    logging.DEBUG: "DEBUG",
    logging.INFO: "INFO",
    logging.WARNING: "WARN",
    logging.ERROR: "ERROR",
    logging.CRITICAL: "CRITICAL",
}


# ============================================================
# EMOJI
# ============================================================

LEVEL_EMOJIS = {
    logging.DEBUG: "🔍",
    logging.INFO: "ℹ️",
    logging.WARNING: "⚠️",
    logging.ERROR: "❌",
    logging.CRITICAL: "🚨",
}


# ============================================================
# TERMINAL SUPPORT
# ============================================================

def supports_color() -> bool:
    """
    Terminal ANSI renkleri destekliyor mu?

    Windows / Termux / Linux / macOS ortamlarında mümkün
    olduğunca renkleri aktif bırakır.
    """

    if os.getenv("NO_COLOR") is not None:
        return False

    if os.getenv("FORCE_COLOR") is not None:
        return True

    if not sys.stdout.isatty():
        return False

    return True


USE_COLORS = supports_color()


# ============================================================
# FORMATTER
# ============================================================

class SecurityFormatter(logging.Formatter):
    """
    PAG Security terminal formatter'ı.

    Örnek:

    16:42:18 │ INFO     │ MAIN       │ Bot started
    16:42:19 │ INFO     │ ANTI-NUKE  │ Protection enabled
    16:42:25 │ WARNING  │ SECURITY   │ Suspicious activity
    16:42:27 │ ERROR    │ DATABASE   │ Connection failed
    """

    def format(self, record: logging.LogRecord) -> str:
        timestamp = datetime.fromtimestamp(
            record.created
        ).strftime("%H:%M:%S")

        level_name = LEVEL_NAMES.get(
            record.levelno,
            record.levelname,
        )

        emoji = LEVEL_EMOJIS.get(
            record.levelno,
            "•",
        )

        logger_name = record.name[:16]

        message = record.getMessage()

        if record.exc_info:
            message = (
                f"{message}\n"
                f"{self.formatException(record.exc_info)}"
            )

        if USE_COLORS:
            color = LEVEL_COLORS.get(
                record.levelno,
                WHITE,
            )

            timestamp_text = (
                f"{BRIGHT_BLACK}{timestamp}{RESET}"
            )

            level_text = (
                f"{color}{level_name:<8}{RESET}"
            )

            logger_text = (
                f"{BRIGHT_BLUE}"
                f"{logger_name:<16}"
                f"{RESET}"
            )

            return (
                f"{timestamp_text} "
                f"│ {level_text} "
                f"│ {logger_text} "
                f"│ {emoji} {message}"
            )

        return (
            f"{timestamp} "
            f"│ {level_name:<8} "
            f"│ {logger_name:<16} "
            f"│ {emoji} {message}"
        )


# ============================================================
# FILE FORMATTER
# ============================================================

class FileFormatter(logging.Formatter):
    """
    Dosya logları için renksiz formatter.
    """

    def __init__(self) -> None:
        super().__init__(
            fmt=(
                "%(asctime)s "
                "│ %(levelname)-8s "
                "│ %(name)-16s "
                "│ %(message)s"
            ),
            datefmt="%Y-%m-%d %H:%M:%S",
        )


# ============================================================
# LOGGER CREATION
# ============================================================

def get_logger(
    name: str,
    *,
    level: int = logging.INFO,
) -> logging.Logger:
    """
    Merkezi PAG Security logger oluşturur.

    Örnek:

        logger = get_logger("ANTI-NUKE")

        logger.info("Protection enabled")
    """

    name = str(name).strip() or "PAG-SECURITY"

    logger = logging.getLogger(name)

    logger.setLevel(level)

    logger.propagate = False

    # Daha önce handler oluşturulduysa tekrar ekleme.
    if logger.handlers:
        return logger

    # --------------------------------------------------------
    # Terminal Handler
    # --------------------------------------------------------

    console_handler = logging.StreamHandler(
        sys.stdout
    )

    console_handler.setLevel(level)
    console_handler.setFormatter(
        SecurityFormatter()
    )

    logger.addHandler(console_handler)

    return logger


# ============================================================
# FILE HANDLER
# ============================================================

def add_file_handler(
    logger: logging.Logger,
    filepath: str = "logs/security.log",
    *,
    level: int = logging.INFO,
) -> bool:
    """
    Logger'a dosya handler ekler.

    Aynı filepath için duplicate handler oluşturmaz.
    """

    filepath = os.path.abspath(filepath)

    directory = os.path.dirname(filepath)

    if directory:
        os.makedirs(
            directory,
            exist_ok=True,
        )

    # Duplicate kontrolü
    for handler in logger.handlers:
        if not isinstance(
            handler,
            logging.FileHandler,
        ):
            continue

        if os.path.abspath(
            getattr(handler, "baseFilename", "")
        ) == filepath:
            return False

    file_handler = logging.FileHandler(
        filepath,
        encoding="utf-8",
    )

    file_handler.setLevel(level)
    file_handler.setFormatter(
        FileFormatter()
    )

    logger.addHandler(file_handler)

    return True


# ============================================================
# SET LEVEL
# ============================================================

def set_level(
    logger: logging.Logger,
    level: int,
) -> None:
    """
    Logger seviyesini değiştirir.
    """

    logger.setLevel(level)

    for handler in logger.handlers:
        handler.setLevel(level)


# ============================================================
# COMMON LOGGERS
# ============================================================

main_logger = get_logger("MAIN")

security_logger = get_logger("SECURITY")

anti_nuke_logger = get_logger("ANTI-NUKE")

anti_raid_logger = get_logger("ANTI-RAID")

anti_spam_logger = get_logger("ANTI-SPAM")

anti_scam_logger = get_logger("ANTI-SCAM")

emergency_logger = get_logger("EMERGENCY")

database_logger = get_logger("DATABASE")

moderation_logger = get_logger("MODERATION")


# ============================================================
# STARTUP BANNER
# ============================================================

def print_banner() -> None:
    """
    PAG Security Bot başlangıç banner'ı.
    """

    banner = r"""
╔══════════════════════════════════════════════╗
║                                              ║
║        🛡️  PAG SECURITY BOT                 ║
║                                              ║
║        Pain And Gain Security System         ║
║                                              ║
║        ⚡ Fast  │  🔒 Secure  │  Lightweight ║
║                                              ║
╚══════════════════════════════════════════════╝
"""

    if USE_COLORS:
        print(
            f"{BRIGHT_CYAN}"
            f"{banner}"
            f"{RESET}"
        )
    else:
        print(banner)


# ============================================================
# SECURITY EVENT HELPERS
# ============================================================

def log_security_event(
    event: str,
    message: str,
    *,
    level: int = logging.INFO,
) -> None:
    """
    Security event'i merkezi security logger'a gönderir.
    """

    event = str(event).strip().upper()

    security_logger.log(
        level,
        f"[{event}] {message}",
    )


def log_emergency(
    message: str,
) -> None:
    """
    Emergency event'i özel logger ile gösterir.
    """

    emergency_logger.critical(
        f"🚨 {message}"
    )


# ============================================================
# EXCEPTION HELPER
# ============================================================

def log_exception(
    logger: logging.Logger,
    message: str,
    exception: Optional[BaseException] = None,
) -> None:
    """
    Exception traceback'iyle beraber loglar.
    """

    if exception is None:
        logger.exception(message)
        return

    logger.error(
        message,
        exc_info=(
            type(exception),
            exception,
            exception.__traceback__,
        ),
    )


# ============================================================
# DISABLE COLORS
# ============================================================

def disable_colors() -> None:
    """
    Terminal renklerini kapatır.

    Runtime sırasında kullanılabilir.
    """

    global USE_COLORS

    USE_COLORS = False


# ============================================================
# ENABLE COLORS
# ============================================================

def enable_colors() -> None:
    """
    Terminal renklerini açar.
    """

    global USE_COLORS

    USE_COLORS = True


# ============================================================
# EXPORTS
# ============================================================

__all__ = [
    # Core
    "get_logger",
    "add_file_handler",
    "set_level",

    # Formatters
    "SecurityFormatter",
    "FileFormatter",

    # Banner
    "print_banner",

    # Security
    "log_security_event",
    "log_emergency",
    "log_exception",

    # Colors
    "disable_colors",
    "enable_colors",

    # Global loggers
    "main_logger",
    "security_logger",
    "anti_nuke_logger",
    "anti_raid_logger",
    "anti_spam_logger",
    "anti_scam_logger",
    "emergency_logger",
    "database_logger",
    "moderation_logger",
]