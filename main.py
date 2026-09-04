from __future__ import annotations

"""PAG Security Bot application entry point.

This file deliberately stays small.  Runtime ownership belongs to
``core.bot.PAGSecurityBot``; ``main.py`` is responsible only for configuration,
logging and starting the Discord client.
"""

import logging
import sys

from config import BotConfig, ConfigurationError
from core.bot import PAGSecurityBot
from utils.logger import main_logger, security_logger, set_level


LOG_LEVELS: dict[str, int] = {
    "DEBUG": logging.DEBUG,
    "INFO": logging.INFO,
    "WARNING": logging.WARNING,
    "ERROR": logging.ERROR,
    "CRITICAL": logging.CRITICAL,
}


def _configure_logging(config: BotConfig) -> None:
    """Apply the configured log level to PAG Security loggers."""

    level = LOG_LEVELS.get(config.log_level, logging.INFO)

    # utils.logger owns the handlers; do not call basicConfig and create a
    # second, duplicate console pipeline.
    set_level(main_logger, level)
    set_level(security_logger, level)



def run() -> None:
    """Load configuration, construct the bot and start Discord."""

    try:
        config = BotConfig.from_env()
        config.prepare_directories()
        _configure_logging(config)

        main_logger.info("Starting PAG Security...")
        main_logger.info(
            "Configuration loaded | prefix=%r | sync_commands=%s | sync_guild=%s",
            config.prefix,
            config.sync_commands,
            config.sync_guild_id or "global",
        )

        bot = PAGSecurityBot(config)
        bot.run(config.token, log_handler=None)

    except ConfigurationError as exc:
        print(f"[PAG Security] Configuration error: {exc}", file=sys.stderr)
        raise SystemExit(2) from exc

    except KeyboardInterrupt:
        main_logger.info("PAG Security stopped by user.")
        raise SystemExit(0)

    except Exception:
        # discord.py's Bot.run() normally handles its own shutdown.  Any
        # unexpected startup/runtime exception is still logged and surfaced.
        main_logger.exception("PAG Security terminated because of an unexpected error.")
        raise SystemExit(1) from None


if __name__ == "__main__":
    run()
  
