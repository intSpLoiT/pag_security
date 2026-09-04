from __future__ import annotations

"""PAG Security Bot runtime.

Central Discord runtime for PAG Security.

Responsibilities:
    - Discord client initialization
    - Runtime service creation
    - Extension loading
    - Application command synchronization
    - Runtime error handling
    - Graceful shutdown

Cogs must use the services exposed on the bot instance:

    bot.database_service
    bot.panel_service
    bot.moderation_service
    bot.security_service

Services must not create parallel global runtime instances.
"""

import asyncio
import contextlib
import logging
from typing import Any

import discord
from discord.ext import commands

from config import BotConfig, ConfigurationError, _env, _env_bool, _env_int
from core.loader import ExtensionLoader
from services.database_service import DatabaseService
from services.moderation_service import ModerationService, setup_moderation_service
from services.panel_service import PanelService
from services.security_service import (
    SecurityConfig,
    SecurityService,
    setup_security_service,
)
from utils.logger import security_logger


# ============================================================
# CONSTANTS
# ============================================================

DEFAULT_SECURITY_WINDOW = 12
DEFAULT_KICK_THRESHOLD = 5
DEFAULT_CHANNEL_DELETE_THRESHOLD = 5
DEFAULT_CHANNEL_CREATE_THRESHOLD = 10
DEFAULT_ROLE_DELETE_THRESHOLD = 3
DEFAULT_ROLE_CREATE_THRESHOLD = 5
DEFAULT_ROLE_UPDATE_THRESHOLD = 5
DEFAULT_PERMISSION_CHANGE_THRESHOLD = 3
DEFAULT_BOT_ADD_THRESHOLD = 2
DEFAULT_WEBHOOK_THRESHOLD = 3
DEFAULT_EMERGENCY_COOLDOWN = 30

# ============================================================
# LOGGER
# ============================================================

logger = security_logger


# ============================================================
# BOT
# ============================================================


class PAGSecurityBot(commands.Bot):
    """Main Discord runtime for PAG Security."""

    def __init__(self, config: BotConfig) -> None:
        self.config = config

        # ----------------------------------------------------
        # Runtime state
        # ----------------------------------------------------

        self._shutdown_lock = asyncio.Lock()
        self._startup_lock = asyncio.Lock()

        self._closed = False
        self._started = False
        self._services_ready = False
        self._extensions_loaded = False

        # ----------------------------------------------------
        # Discord intents
        # ----------------------------------------------------

        intents = self._build_intents(config)

        super().__init__(
            command_prefix=commands.when_mentioned_or(config.prefix),
            intents=intents,
            help_command=None,
            case_insensitive=True,
            strip_after_prefix=True,
            max_messages=1000,
        )

        # ----------------------------------------------------
        # Runtime service registry
        # ----------------------------------------------------
        #
        # These attributes are intentionally stable.
        # Cogs should access services through these references.
        #

        self.database_service: DatabaseService | None = None
        self.panel_service: PanelService | None = None
        self.moderation_service: ModerationService | None = None
        self.security_service: SecurityService | None = None

        # ----------------------------------------------------
        # Extension loader
        # ----------------------------------------------------

        self.loader = ExtensionLoader(
            self,
            root_directory=config.data_dir.parent,
            cog_directory="cogs",
            timeout=config.extension_timeout,
        )

    # ========================================================
    # INTENTS
    # ========================================================

    @staticmethod
    def _build_intents(config: BotConfig) -> discord.Intents:
        """Build only the intents required by PAG Security."""

        intents = discord.Intents.none()

        # Guild lifecycle / channels / roles
        intents.guilds = True

        # Member join/remove/update + moderation
        intents.members = config.members_intent

        # Ban events
        intents.bans = True

        # Message events required by anti-spam.
        intents.messages = True
        intents.message_content = config.message_content_intent

        # Webhook update events.
        intents.webhooks = True

        # Moderation related gateway events.
        intents.moderation = True

        return intents

    # ========================================================
    # SETUP HOOK
    # ========================================================

    async def setup_hook(self) -> None:
        """Initialize all runtime components before connecting to Discord."""

        async with self._startup_lock:
            if self._services_ready:
                return

            if self._closed:
                raise RuntimeError(
                    "PAGSecurityBot cannot be started because it is already closed."
                )

            logger.info("Initializing PAG Security runtime...")

            try:
                # ------------------------------------------------
                # Filesystem
                # ------------------------------------------------

                self.config.prepare_directories()

                # ------------------------------------------------
                # Services
                # ------------------------------------------------

                await self._initialize_services()

                self._services_ready = True

                # ------------------------------------------------
                # Extensions
                # ------------------------------------------------

                await self._load_extensions()

                self._extensions_loaded = True

                # ------------------------------------------------
                # Application commands
                # ------------------------------------------------

                if self.config.sync_commands:
                    await self._sync_commands()

                logger.info("PAG Security runtime initialization complete.")

            except Exception:
                logger.exception(
                    "Fatal error during PAG Security startup."
                )

                # setup_hook başarısız olursa yarım runtime bırakma.
                await self._cleanup_runtime()

                raise

    # ========================================================
    # SERVICE INITIALIZATION
    # ========================================================

    async def _initialize_services(self) -> None:
        """Create and initialize PAG Security services in dependency order."""

        # ----------------------------------------------------
        # Database
        # ----------------------------------------------------

        logger.info("Initializing DatabaseService...")

        database = DatabaseService(
            str(self.config.database_path)
        )

        await database.initialize()

        self.database_service = database

        logger.info("DatabaseService initialized.")

        # ----------------------------------------------------
        # Panel
        # ----------------------------------------------------

        logger.info("Initializing PanelService...")

        self.panel_service = PanelService(
            data_dir=self.config.data_dir
        )

        logger.info("PanelService initialized.")

        # ----------------------------------------------------
        # Moderation
        # ----------------------------------------------------

        logger.info("Initializing ModerationService...")

        self.moderation_service = setup_moderation_service(
            self,
            self.database_service,
        )

        logger.info("ModerationService initialized.")

        # ----------------------------------------------------
        # Security
        # ----------------------------------------------------

        logger.info("Initializing SecurityService...")

        security_config = self._build_security_config()

        self.security_service = setup_security_service(
            self,
            moderation=self.moderation_service,
            panel=self.panel_service,
            config=security_config,
        )

        logger.info("SecurityService initialized.")

    # ========================================================
    # SECURITY CONFIG
    # ========================================================

    @staticmethod
    def _build_security_config() -> SecurityConfig:
        """Build SecurityConfig from environment overrides."""

        return SecurityConfig(
            window_seconds=_env_int(
                "SECURITY_WINDOW_SECONDS",
                DEFAULT_SECURITY_WINDOW,
                minimum=1,
            ),

            kick_threshold=_env_int(
                "SECURITY_KICK_THRESHOLD",
                DEFAULT_KICK_THRESHOLD,
                minimum=1,
            ),

            channel_delete_threshold=_env_int(
                "SECURITY_CHANNEL_DELETE_THRESHOLD",
                DEFAULT_CHANNEL_DELETE_THRESHOLD,
                minimum=1,
            ),

            channel_create_threshold=_env_int(
                "SECURITY_CHANNEL_CREATE_THRESHOLD",
                DEFAULT_CHANNEL_CREATE_THRESHOLD,
                minimum=1,
            ),

            role_delete_threshold=_env_int(
                "SECURITY_ROLE_DELETE_THRESHOLD",
                DEFAULT_ROLE_DELETE_THRESHOLD,
                minimum=1,
            ),

            role_create_threshold=_env_int(
                "SECURITY_ROLE_CREATE_THRESHOLD",
                DEFAULT_ROLE_CREATE_THRESHOLD,
                minimum=1,
            ),

            role_update_threshold=_env_int(
                "SECURITY_ROLE_UPDATE_THRESHOLD",
                DEFAULT_ROLE_UPDATE_THRESHOLD,
                minimum=1,
            ),

            permission_change_threshold=_env_int(
                "SECURITY_PERMISSION_CHANGE_THRESHOLD",
                DEFAULT_PERMISSION_CHANGE_THRESHOLD,
                minimum=1,
            ),

            bot_add_threshold=_env_int(
                "SECURITY_BOT_ADD_THRESHOLD",
                DEFAULT_BOT_ADD_THRESHOLD,
                minimum=1,
            ),

            webhook_threshold=_env_int(
                "SECURITY_WEBHOOK_THRESHOLD",
                DEFAULT_WEBHOOK_THRESHOLD,
                minimum=1,
            ),

            emergency_cooldown=_env_int(
                "SECURITY_EMERGENCY_COOLDOWN",
                DEFAULT_EMERGENCY_COOLDOWN,
                minimum=0,
            ),

            require_approval_for_kick=_env_bool(
                "SECURITY_REQUIRE_KICK_APPROVAL",
                True,
            ),

            require_approval_for_ban=_env_bool(
                "SECURITY_REQUIRE_BAN_APPROVAL",
                True,
            ),

            emergency_remove_roles=_env_bool(
                "SECURITY_EMERGENCY_REMOVE_ROLES",
                True,
            ),

            emergency_lockdown=_env_bool(
                "SECURITY_EMERGENCY_LOCKDOWN",
                True,
            ),

            emergency_quarantine=_env_bool(
                "SECURITY_EMERGENCY_QUARANTINE",
                True,
            ),
        )

    # ========================================================
    # EXTENSIONS
    # ========================================================

    async def _load_extensions(self) -> None:
        """Load all available PAG Security cogs."""

        logger.info("Loading PAG Security extensions...")

        summary = await self.loader.load_all(
            stop_on_error=False,
            timeout=self.config.extension_timeout,
        )

        logger.info(
            (
                "Extension loading complete | "
                "total=%d successful=%d failed=%d skipped=%d "
                "duration=%.2fs"
            ),
            summary.total,
            summary.successful,
            summary.failed,
            summary.skipped,
            summary.duration,
        )

        if summary.failed:
            failed_count = 0

            for result in summary.results:
                if result.success:
                    continue

                failed_count += 1

                logger.error(
                    (
                        "Extension failed | "
                        "extension=%s | "
                        "state=%s | "
                        "error_type=%s | "
                        "error=%s"
                    ),
                    result.extension,
                    result.state,
                    result.error_type,
                    result.error or result.message,
                )

            logger.warning(
                "PAG Security started with %d failed extension(s).",
                failed_count,
            )

    # ========================================================
    # COMMAND SYNC
    # ========================================================

    async def _sync_commands(self) -> None:
        """Synchronize application commands globally or to a dev guild."""

        try:
            if self.config.sync_guild_id:
                guild = discord.Object(
                    id=self.config.sync_guild_id
                )

                # Copy global commands into development guild.
                self.tree.copy_global_to(
                    guild=guild
                )

                synced = await self.tree.sync(
                    guild=guild
                )

                logger.info(
                    (
                        "Application commands synced | "
                        "scope=guild | guild=%d | count=%d"
                    ),
                    self.config.sync_guild_id,
                    len(synced),
                )

                return

            synced = await self.tree.sync()

            logger.info(
                (
                    "Application commands synced | "
                    "scope=global | count=%d"
                ),
                len(synced),
            )

        except discord.HTTPException as exc:
            # Command sync failure should be visible but does not
            # necessarily mean the security runtime itself is broken.
            logger.error(
                (
                    "Application command sync failed | "
                    "status=%s | code=%s | error=%s"
                ),
                exc.status,
                exc.code,
                exc,
            )

        except discord.Forbidden as exc:
            logger.error(
                "Application command sync forbidden | error=%s",
                exc,
            )

        except Exception:
            logger.exception(
                "Unexpected application command sync failure."
            )

    # ========================================================
    # READY
    # ========================================================

    async def on_ready(self) -> None:
        """Discord ready event."""

        user = self.user

        if user is None:
            logger.warning(
                "Discord reported READY but bot user is unavailable."
            )
            return

        self._started = True

        logger.info(
            (
                "PAG Security online | "
                "user=%s | id=%d | guilds=%d | "
                "services=%s | extensions=%s"
            ),
            user,
            user.id,
            len(self.guilds),
            "ready" if self._services_ready else "not-ready",
            "ready" if self._extensions_loaded else "not-ready",
        )

    # ========================================================
    # PREFIX COMMAND ERRORS
    # ========================================================

    async def on_command_error(
        self,
        ctx: commands.Context,
        error: commands.CommandError,
    ) -> None:
        """Handle prefix-command errors without crashing the bot."""

        # Ignore expected / harmless errors.
        if isinstance(
            error,
            (
                commands.CommandNotFound,
                commands.CheckFailure,
            ),
        ):
            return

        # Unwrap the real exception.
        original = getattr(
            error,
            "original",
            error,
        )

        logger.error(
            (
                "Command error | "
                "command=%s | "
                "user=%s | "
                "guild=%s | "
                "error_type=%s | "
                "error=%s"
            ),
            getattr(
                ctx.command,
                "qualified_name",
                "unknown",
            ),
            getattr(
                ctx.author,
                "id",
                "unknown",
            ),
            getattr(
                ctx.guild,
                "id",
                "DM",
            ),
            type(original).__name__,
            original,
            exc_info=(
                type(original),
                original,
                original.__traceback__,
            ),
        )

    # ========================================================
    # GLOBAL EVENT ERRORS
    # ========================================================

    async def on_error(
        self,
        event_method: str,
        *args: Any,
        **kwargs: Any,
    ) -> None:
        """Catch unexpected Discord event exceptions."""

        logger.exception(
            "Discord event error | event=%s",
            event_method,
        )

    # ========================================================
    # TREE ERROR
    # ========================================================

    async def on_app_command_error(
        self,
        interaction: discord.Interaction,
        error: discord.app_commands.AppCommandError,
    ) -> None:
        """Handle slash-command and interaction errors."""

        original = getattr(
            error,
            "original",
            error,
        )

        if isinstance(
            error,
            (
                discord.app_commands.CheckFailure,
                discord.app_commands.CommandNotFound,
            ),
        ):
            return

        logger.error(
            (
                "Application command error | "
                "command=%s | "
                "user=%s | "
                "guild=%s | "
                "error_type=%s | "
                "error=%s"
            ),
            getattr(
                getattr(interaction, "command", None),
                "qualified_name",
                "unknown",
            ),
            getattr(
                getattr(interaction, "user", None),
                "id",
                "unknown",
            ),
            getattr(
                getattr(interaction, "guild", None),
                "id",
                "DM",
            ),
            type(original).__name__,
            original,
            exc_info=(
                type(original),
                original,
                original.__traceback__,
            ),
        )

        # Do not attempt to respond if the interaction has already
        # been acknowledged or expired.
        if interaction.response.is_done():
            return

        with contextlib.suppress(discord.HTTPException):
            await interaction.response.send_message(
                "❌ Bir hata oluştu. İşlem loglandı.",
                ephemeral=True,
            )

    # ========================================================
    # SHUTDOWN
    # ========================================================

    async def close(self) -> None:
        """Gracefully close extensions, services and Discord."""

        async with self._shutdown_lock:
            if self._closed:
                return

            self._closed = True

            logger.info(
                "Shutting down PAG Security..."
            )

            # ------------------------------------------------
            # Extensions
            # ------------------------------------------------

            with contextlib.suppress(Exception):
                if not self.loader.closed:
                    await self.loader.close(
                        unload_extensions=True
                    )

            # ------------------------------------------------
            # Security service
            # ------------------------------------------------

            if self.security_service is not None:
                with contextlib.suppress(Exception):
                    await self.security_service.close()

            # ------------------------------------------------
            # Database
            # ------------------------------------------------

            if self.database_service is not None:
                with contextlib.suppress(Exception):
                    await self.database_service.close()

            # ------------------------------------------------
            # Discord client
            # ------------------------------------------------

            with contextlib.suppress(Exception):
                await super().close()

            logger.info(
                "PAG Security shutdown complete."
            )

    # ========================================================
    # STARTUP FAILURE CLEANUP
    # ========================================================

    async def _cleanup_runtime(self) -> None:
        """Clean partially initialized runtime after startup failure."""

        logger.warning(
            "Cleaning up partially initialized PAG Security runtime..."
        )

        # ----------------------------------------------------
        # Extensions
        # ----------------------------------------------------

        with contextlib.suppress(Exception):
            if not self.loader.closed:
                await self.loader.close(
                    unload_extensions=True
                )

        # ----------------------------------------------------
        # Security service
        # ----------------------------------------------------

        if self.security_service is not None:
            with contextlib.suppress(Exception):
                await self.security_service.close()

            self.security_service = None

        # ----------------------------------------------------
        # Database
        # ----------------------------------------------------

        if self.database_service is not None:
            with contextlib.suppress(Exception):
                await self.database_service.close()

            self.database_service = None

        self.moderation_service = None
        self.panel_service = None

        self._services_ready = False
        self._extensions_loaded = False

    # ========================================================
    # REPRESENTATION
    # ========================================================

    @property
    def runtime_ready(self) -> bool:
        """Whether the core runtime has completed initialization."""

        return (
            self._services_ready
            and self._extensions_loaded
            and not self._closed
        )


__all__ = [
    "PAGSecurityBot",
]
