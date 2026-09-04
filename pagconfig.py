from __future__ import annotations

"""PAG Security application configuration.

This module contains only environment and filesystem configuration.
Discord runtime objects and services belong to ``core.bot.PAGSecurityBot``.
"""

import os
from dataclasses import dataclass, field
from pathlib import Path
from typing import Final


# ============================================================
# PROJECT
# ============================================================

PROJECT_ROOT: Final[Path] = Path(__file__).resolve().parent


# ============================================================
# ERRORS
# ============================================================


class ConfigurationError(RuntimeError):
    """Raised when PAG Security configuration is missing or invalid."""


# ============================================================
# DOTENV
# ============================================================


def _load_dotenv(path: Path | None = None) -> None:
    """Load a small dependency-free .env file.

    Existing process environment variables always take precedence.
    """

    env_path = path or PROJECT_ROOT / ".env"

    if not env_path.is_file():
        return

    try:
        lines = env_path.read_text(
            encoding="utf-8",
        ).splitlines()

    except OSError:
        return

    for raw in lines:
        line = raw.strip()

        if (
            not line
            or line.startswith("#")
            or "=" not in line
        ):
            continue

        key, value = line.split(
            "=",
            1,
        )

        key = key.strip()
        value = value.strip()

        if not key:
            continue

        # Environment variables already supplied by the host
        # always have priority over .env.
        if key in os.environ:
            continue

        # Remove matching quotes.
        if (
            len(value) >= 2
            and value[0] == value[-1]
            and value[0] in {"'", '"'}
        ):
            value = value[1:-1]

        os.environ[key] = value


# ============================================================
# ENVIRONMENT HELPERS
# ============================================================


def _env(
    name: str,
    default: str | None = None,
) -> str | None:
    """Return a stripped environment variable."""

    value = os.getenv(
        name,
        default,
    )

    if value is None:
        return None

    value = value.strip()

    return value if value else default


def _env_bool(
    name: str,
    default: bool,
) -> bool:
    """Read a strict boolean environment variable."""

    value = _env(name)

    if value is None:
        return default

    normalized = value.lower()

    if normalized in {
        "1",
        "true",
        "yes",
        "y",
        "on",
    }:
        return True

    if normalized in {
        "0",
        "false",
        "no",
        "n",
        "off",
    }:
        return False

    raise ConfigurationError(
        f"{name} must be a boolean value (true/false)."
    )


def _env_int(
    name: str,
    default: int,
    *,
    minimum: int | None = None,
) -> int:
    """Read an integer environment variable."""

    value = _env(name)

    if value is None:
        result = default

    else:
        try:
            result = int(value)

        except ValueError as exc:
            raise ConfigurationError(
                f"{name} must be an integer."
            ) from exc

    if (
        minimum is not None
        and result < minimum
    ):
        raise ConfigurationError(
            f"{name} must be >= {minimum}."
        )

    return result


def _env_float(
    name: str,
    default: float,
    *,
    minimum: float | None = None,
) -> float:
    """Read a floating-point environment variable."""

    value = _env(name)

    if value is None:
        result = default

    else:
        try:
            result = float(value)

        except ValueError as exc:
            raise ConfigurationError(
                f"{name} must be a number."
            ) from exc

    if (
        minimum is not None
        and result < minimum
    ):
        raise ConfigurationError(
            f"{name} must be >= {minimum}."
        )

    return result


# ============================================================
# ID PARSING
# ============================================================


def _parse_ids(
    *names: str,
) -> tuple[int, ...]:
    """Read comma/space/semicolon separated Discord IDs."""

    raw_values: list[str] = []

    for name in names:
        value = _env(name)

        if value:
            raw_values.append(value)

    result: list[int] = []
    seen: set[int] = set()

    for raw in raw_values:
        normalized = (
            raw
            .replace(";", ",")
            .replace(" ", ",")
        )

        for item in normalized.split(","):
            item = item.strip()

            if not item:
                continue

            try:
                user_id = int(item)

            except ValueError as exc:
                raise ConfigurationError(
                    (
                        "Invalid Discord ID in "
                        f"{', '.join(names)}: {item!r}"
                    )
                ) from exc

            if user_id <= 0:
                raise ConfigurationError(
                    f"Discord IDs must be positive: {item!r}"
                )

            if user_id not in seen:
                seen.add(user_id)
                result.append(user_id)

    return tuple(result)


def _parse_optional_id(
    name: str,
) -> int | None:
    """Read an optional single Discord ID."""

    value = _env(name)

    if value is None:
        return None

    try:
        result = int(value)

    except ValueError as exc:
        raise ConfigurationError(
            f"{name} must be an integer."
        ) from exc

    if result <= 0:
        raise ConfigurationError(
            f"{name} must be positive."
        )

    return result


# ============================================================
# PATH
# ============================================================


def _resolve_path(
    raw: str | None,
    default: Path,
) -> Path:
    """Resolve a configured path relative to the project root."""

    path = Path(raw) if raw else default

    if not path.is_absolute():
        path = PROJECT_ROOT / path

    return path.resolve()


# ============================================================
# CONFIGURATION
# ============================================================


@dataclass(frozen=True, slots=True)
class BotConfig:
    """Immutable runtime configuration for PAG Security."""

    # --------------------------------------------------------
    # Discord
    # --------------------------------------------------------

    token: str

    prefix: str = "!"

    owners: tuple[int, ...] = ()

    trusted_users: tuple[int, ...] = ()

    # --------------------------------------------------------
    # Filesystem
    # --------------------------------------------------------

    data_dir: Path = field(
        default_factory=lambda:
        PROJECT_ROOT / "data"
    )

    database_path: Path = field(
        default_factory=lambda:
        PROJECT_ROOT
        / "database"
        / "pag_security.db"
    )

    # --------------------------------------------------------
    # Runtime
    # --------------------------------------------------------

    log_level: str = "INFO"

    extension_timeout: float = 30.0

    sync_commands: bool = True

    sync_guild_id: int | None = None

    # --------------------------------------------------------
    # Discord intents
    # --------------------------------------------------------

    members_intent: bool = True

    message_content_intent: bool = True

    # ========================================================
    # TRUST
    # ========================================================

    @property
    def all_trusted_users(
        self,
    ) -> tuple[int, ...]:
        """Return owners and trusted users without duplicates."""

        return tuple(
            dict.fromkeys(
                (
                    *self.owners,
                    *self.trusted_users,
                )
            )
        )

    # ========================================================
    # ENVIRONMENT
    # ========================================================

    @classmethod
    def from_env(
        cls,
    ) -> "BotConfig":
        """Build and validate configuration from environment."""

        _load_dotenv()

        # ----------------------------------------------------
        # TOKEN
        # ----------------------------------------------------

        token = (
            _env("DISCORD_TOKEN")
            or _env("BOT_TOKEN")
            or _env("TOKEN")
        )

        if not token:
            raise ConfigurationError(
                (
                    "Discord bot token is missing. "
                    "Set DISCORD_TOKEN in the environment "
                    "or .env."
                )
            )

        # ----------------------------------------------------
        # PREFIX
        # ----------------------------------------------------

        prefix = (
            _env(
                "BOT_PREFIX",
                "!",
            )
            or "!"
        ).strip()

        if not prefix:
            raise ConfigurationError(
                "BOT_PREFIX cannot be empty."
            )

        if len(prefix) > 32:
            raise ConfigurationError(
                "BOT_PREFIX cannot exceed 32 characters."
            )

        # ----------------------------------------------------
        # OWNERS
        # ----------------------------------------------------

        owners = _parse_ids(
            "OWNER_IDS",
            "BOT_OWNER_IDS",
        )

        # ----------------------------------------------------
        # TRUSTED USERS
        # ----------------------------------------------------
        #
        # Velgrath / Riwnex IDs can be supplied directly
        # through the .env.
        #

        trusted_users = _parse_ids(
            "TRUSTED_USER_IDS",
            "TRUSTED_IDS",
            "VELGRATH_ID",
            "RIWNEX_ID",
        )

        # ----------------------------------------------------
        # SYNC GUILD
        # ----------------------------------------------------

        sync_guild_id = _parse_optional_id(
            "SYNC_GUILD_ID"
        )

        # ----------------------------------------------------
        # LOG LEVEL
        # ----------------------------------------------------

        log_level = (
            _env(
                "LOG_LEVEL",
                "INFO",
            )
            or "INFO"
        ).upper()

        if log_level not in {
            "DEBUG",
            "INFO",
            "WARNING",
            "ERROR",
            "CRITICAL",
        }:
            raise ConfigurationError(
                (
                    "LOG_LEVEL must be DEBUG, INFO, "
                    "WARNING, ERROR or CRITICAL."
                )
            )

        # ----------------------------------------------------
        # BUILD
        # ----------------------------------------------------

        return cls(
            token=token,
            prefix=prefix,
            owners=owners,
            trusted_users=trusted_users,

            data_dir=_resolve_path(
                _env("DATA_DIR"),
                PROJECT_ROOT / "data",
            ),

            database_path=_resolve_path(
                _env("DATABASE_PATH"),
                PROJECT_ROOT
                / "database"
                / "pag_security.db",
            ),

            log_level=log_level,

            extension_timeout=_env_float(
                "EXTENSION_TIMEOUT",
                30.0,
                minimum=0.1,
            ),

            sync_commands=_env_bool(
                "SYNC_COMMANDS",
                True,
            ),

            sync_guild_id=sync_guild_id,

            members_intent=_env_bool(
                "MEMBERS_INTENT",
                True,
            ),

            message_content_intent=_env_bool(
                "MESSAGE_CONTENT_INTENT",
                True,
            ),
        )

    # ========================================================
    # DIRECTORIES
    # ========================================================

    def prepare_directories(self) -> None:
        """Create runtime directories."""

        self.data_dir.mkdir(
            parents=True,
            exist_ok=True,
        )

        self.database_path.parent.mkdir(
            parents=True,
            exist_ok=True,
        )


# ============================================================
# EXPORTS
# ============================================================

__all__ = [
    "BotConfig",
    "ConfigurationError",
    "PROJECT_ROOT",
    "_env",
    "_env_bool",
    "_env_int",
  ]
