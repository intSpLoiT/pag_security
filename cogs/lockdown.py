# cogs/lockdown.py

from __future__ import annotations

import asyncio
from dataclasses import dataclass, field
from typing import Optional

import discord
from discord.ext import commands

from services.panel_service import PanelService
from utils.logger import security_logger


# ============================================================
# CONSTANTS
# ============================================================

LOCKDOWN_ROLE_NAME = "PAG Security • Lockdown"

LOCKDOWN_REASON = (
    "PAG Security Lockdown"
)


# ============================================================
# RESULT
# ============================================================


@dataclass(slots=True)
class LockdownResult:
    """
    Lockdown operasyonunun sonucu.
    """

    success: bool = True

    guild_id: int = 0

    enabled: bool = False

    locked_channels: int = 0

    restored_channels: int = 0

    skipped_channels: int = 0

    failed_channels: int = 0

    errors: list[str] = field(
        default_factory=list
    )

    def add_error(
        self,
        error: str,
    ) -> None:

        self.errors.append(
            str(error)
        )

        self.success = False

        self.failed_channels += 1

    def to_dict(self) -> dict:

        return {
            "success": self.success,
            "guild_id": self.guild_id,
            "enabled": self.enabled,
            "locked_channels": self.locked_channels,
            "restored_channels": self.restored_channels,
            "skipped_channels": self.skipped_channels,
            "failed_channels": self.failed_channels,
            "errors": list(self.errors),
        }


# ============================================================
# COG
# ============================================================


class Lockdown(commands.Cog):
    """
    PAG Security Lockdown System.

    Görevleri:

    - Guild lockdown
    - Lockdown kaldırma
    - PanelService configuration
    - Channel overwrite yönetimi
    - Concurrent lockdown koruması
    - Hata izolasyonu
    - Emergency sistemiyle uyum

    PanelService:

        emergency.lockdown

    Lockdown state runtime'da tutulur.
    """

    def __init__(
        self,
        bot: commands.Bot,
    ) -> None:

        self.bot = bot

        self.panel: Optional[
            PanelService
        ] = getattr(
            bot,
            "panel_service",
            None,
        )

        if self.panel is None:

            raise RuntimeError(
                "PanelService is required by Lockdown cog."
            )

        # ----------------------------------------------------
        # Guild locks
        # ----------------------------------------------------

        self._locks: dict[
            int,
            asyncio.Lock,
        ] = {}

        # ----------------------------------------------------
        # Runtime state
        # ----------------------------------------------------

        self._active: set[int] = set()

        self._states: dict[
            int,
            bool,
        ] = {}

        # ----------------------------------------------------
        # Original overwrites
        #
        # guild_id
        #   channel_id
        #       overwrite
        # ----------------------------------------------------

        self._original_overwrites: dict[
            int,
            dict[
                int,
                discord.PermissionOverwrite,
            ],
        ] = {}

        security_logger.info(
            "Lockdown cog initialized."
        )

    # ========================================================
    # INTERNAL
    # ========================================================

    def _get_lock(
        self,
        guild_id: int,
    ) -> asyncio.Lock:

        lock = self._locks.get(
            guild_id
        )

        if lock is None:

            lock = asyncio.Lock()

            self._locks[
                guild_id
            ] = lock

        return lock

    # ========================================================
    # CONFIG
    # ========================================================

    async def is_enabled(
        self,
        guild_id: int,
    ) -> bool:

        try:

            value = await self.panel.get(
                guild_id,
                "emergency.lockdown",
                True,
            )

            return bool(value)

        except Exception:

            security_logger.exception(
                "Failed to read lockdown configuration | "
                "guild=%s",
                guild_id,
            )

            return False

    # ========================================================
    # CHANNEL FILTER
    # ========================================================

    def _can_lock_channel(
        self,
        channel: discord.abc.GuildChannel,
    ) -> bool:

        return isinstance(
            channel,
            (
                discord.TextChannel,
                discord.VoiceChannel,
                discord.StageChannel,
                discord.ForumChannel,
                discord.CategoryChannel,
            ),
        )

    # ========================================================
    # LOCKDOWN OVERWRITE
    # ========================================================

    @staticmethod
    def _build_lockdown_overwrite(
        original: discord.PermissionOverwrite,
    ) -> discord.PermissionOverwrite:

        overwrite = original.copy()

        overwrite.send_messages = False
        overwrite.add_reactions = False
        overwrite.create_public_threads = False
        overwrite.create_private_threads = False
        overwrite.send_messages_in_threads = False

        return overwrite

    # ========================================================
    # SAVE ORIGINAL
    # ========================================================

    def _save_original_overwrite(
        self,
        guild_id: int,
        channel: discord.abc.GuildChannel,
        overwrite: discord.PermissionOverwrite,
    ) -> None:

        guild_states = (
            self._original_overwrites.setdefault(
                guild_id,
                {},
            )
        )

        if channel.id not in guild_states:

            guild_states[
                channel.id
            ] = overwrite.copy()

    # ========================================================
    # LOCK
    # ========================================================

    async def lock(
        self,
        guild: discord.Guild,
        *,
        reason: str = LOCKDOWN_REASON,
    ) -> LockdownResult:

        result = LockdownResult(
            guild_id=guild.id,
            enabled=True,
        )

        lock = self._get_lock(
            guild.id
        )

        async with lock:

            if guild.id in self._active:

                result.add_error(
                    "Lockdown operation is already active."
                )

                return result

            self._active.add(
                guild.id
            )

            try:

                enabled = await self.is_enabled(
                    guild.id
                )

                if not enabled:

                    result.enabled = False

                    result.add_error(
                        "Lockdown is disabled in PanelService."
                    )

                    return result

                everyone = guild.default_role

                if everyone is None:

                    result.add_error(
                        "Guild @everyone role was not found."
                    )

                    return result

                for channel in guild.channels:

                    if not self._can_lock_channel(
                        channel
                    ):

                        result.skipped_channels += 1

                        continue

                    try:

                        original = (
                            channel.overwrites_for(
                                everyone
                            )
                        )

                        self._save_original_overwrite(
                            guild.id,
                            channel,
                            original,
                        )

                        overwrite = (
                            self._build_lockdown_overwrite(
                                original
                            )
                        )

                        # ------------------------------------
                        # Gereksiz API request engelleme
                        # ------------------------------------

                        if overwrite == original:

                            result.skipped_channels += 1

                            continue

                        await channel.set_permissions(
                            everyone,
                            overwrite=overwrite,
                            reason=reason,
                        )

                        result.locked_channels += 1

                    except discord.Forbidden as exc:

                        result.add_error(
                            f"Permission denied for "
                            f"channel {channel.id}: {exc}"
                        )

                    except discord.NotFound as exc:

                        result.add_error(
                            f"Channel not found "
                            f"{channel.id}: {exc}"
                        )

                    except discord.HTTPException as exc:

                        result.add_error(
                            f"Discord API error for "
                            f"channel {channel.id}: {exc}"
                        )

                    except Exception as exc:

                        result.add_error(
                            f"Unexpected channel error "
                            f"{channel.id}: {exc}"
                        )

                self._states[
                    guild.id
                ] = True

                security_logger.warning(
                    "Guild lockdown activated | "
                    "guild=%s locked=%s failed=%s",
                    guild.id,
                    result.locked_channels,
                    result.failed_channels,
                )

                return result

            finally:

                self._active.discard(
                    guild.id
                )

    # ========================================================
    # UNLOCK
    # ========================================================

    async def unlock(
        self,
        guild: discord.Guild,
        *,
        reason: str = "PAG Security Lockdown解除",
    ) -> LockdownResult:

        result = LockdownResult(
            guild_id=guild.id,
            enabled=True,
        )

        lock = self._get_lock(
            guild.id
        )

        async with lock:

            if guild.id in self._active:

                result.add_error(
                    "Lockdown operation is already active."
                )

                return result

            self._active.add(
                guild.id
            )

            try:

                everyone = guild.default_role

                if everyone is None:

                    result.add_error(
                        "Guild @everyone role was not found."
                    )

                    return result

                stored = (
                    self._original_overwrites.get(
                        guild.id,
                        {},
                    )
                )

                # --------------------------------------------
                # Sadece daha önce lockdown tarafından
                # değiştirilen kanalları restore et.
                # --------------------------------------------

                for channel_id, original in list(
                    stored.items()
                ):

                    channel = guild.get_channel(
                        channel_id
                    )

                    if channel is None:

                        result.skipped_channels += 1

                        continue

                    try:

                        await channel.set_permissions(
                            everyone,
                            overwrite=original,
                            reason=reason,
                        )

                        result.restored_channels += 1

                    except discord.Forbidden as exc:

                        result.add_error(
                            f"Permission denied while "
                            f"restoring {channel_id}: {exc}"
                        )

                    except discord.NotFound as exc:

                        result.add_error(
                            f"Channel not found while "
                            f"restoring {channel_id}: {exc}"
                        )

                    except discord.HTTPException as exc:

                        result.add_error(
                            f"Discord API error while "
                            f"restoring {channel_id}: {exc}"
                        )

                    except Exception as exc:

                        result.add_error(
                            f"Unexpected restore error "
                            f"for {channel_id}: {exc}"
                        )

                self._states[
                    guild.id
                ] = False

                # --------------------------------------------
                # Restore tamamlandıktan sonra cache temizlenir.
                # --------------------------------------------

                self._original_overwrites.pop(
                    guild.id,
                    None,
                )

                security_logger.info(
                    "Guild lockdown deactivated | "
                    "guild=%s restored=%s failed=%s",
                    guild.id,
                    result.restored_channels,
                    result.failed_channels,
                )

                return result

            finally:

                self._active.discard(
                    guild.id
                )

    # ========================================================
    # STATUS
    # ========================================================

    def is_locked(
        self,
        guild_id: int,
    ) -> bool:

        return self._states.get(
            guild_id,
            False,
        )

    def is_active(
        self,
        guild_id: int,
    ) -> bool:

        return guild_id in self._active

    # ========================================================
    # MANUAL COMMAND
    # ========================================================

    @commands.command(
        name="lockdown",
    )
    @commands.guild_only()
    @commands.has_permissions(
        administrator=True
    )
    @commands.bot_has_permissions(
        manage_channels=True
    )
    async def lockdown_command(
        self,
        ctx: commands.Context,
    ) -> None:
        """
        Kullanım:

            !lockdown
            !lockdown on
            !lockdown off
        """

        guild = ctx.guild

        if guild is None:
            return

        argument = ""

        if ctx.message.content:

            parts = ctx.message.content.split(
                maxsplit=1
            )

            if len(parts) == 2:

                argument = (
                    parts[1]
                    .strip()
                    .lower()
                )

        # ----------------------------------------------------
        # OFF
        # ----------------------------------------------------

        if argument in {
            "off",
            "disable",
            "unlock",
        }:

            result = await self.unlock(
                guild,
                reason=(
                    f"Manual lockdown解除 by "
                    f"{ctx.author}"
                ),
            )

            if result.success:

                await ctx.send(
                    "🔓 **Lockdown kaldırıldı.**\n"
                    f"Restored: `{result.restored_channels}`"
                )

            else:

                await ctx.send(
                    "⚠️ Lockdown kaldırıldı ancak "
                    "bazı kanallar restore edilemedi.\n"
                    f"Restored: `{result.restored_channels}`\n"
                    f"Errors: `{len(result.errors)}`"
                )

            return

        # ----------------------------------------------------
        # ON
        # ----------------------------------------------------

        if argument in {
            "",
            "on",
            "enable",
            "start",
        }:

            result = await self.lock(
                guild,
                reason=(
                    f"Manual PAG Security Lockdown "
                    f"by {ctx.author}"
                ),
            )

            if result.success:

                await ctx.send(
                    "🔒 **LOCKDOWN AKTİF**\n"
                    f"Locked: `{result.locked_channels}`"
                )

            else:

                await ctx.send(
                    "⚠️ Lockdown aktif edildi ancak "
                    "bazı işlemler başarısız oldu.\n"
                    f"Locked: `{result.locked_channels}`\n"
                    f"Errors: `{len(result.errors)}`"
                )

            return

        # ----------------------------------------------------
        # INVALID ARGUMENT
        # ----------------------------------------------------

        await ctx.send(
            "❌ Kullanım: `!lockdown [on/off]`"
        )

    # ========================================================
    # COMMAND ERROR
    # ========================================================

    @lockdown_command.error
    async def lockdown_command_error(
        self,
        ctx: commands.Context,
        error: commands.CommandError,
    ) -> None:

        if isinstance(
            error,
            commands.MissingPermissions,
        ):

            await ctx.send(
                "❌ Bu komut için Administrator yetkisi gerekiyor."
            )

            return

        if isinstance(
            error,
            commands.BotMissingPermissions,
        ):

            await ctx.send(
                "❌ Botun `Manage Channels` yetkisi bulunmuyor."
            )

            return

        if isinstance(
            error,
            commands.NoPrivateMessage,
        ):

            return

        security_logger.exception(
            "Lockdown command error | guild=%s error=%s",
            getattr(
                ctx.guild,
                "id",
                None,
            ),
            error,
        )

        try:

            await ctx.send(
                "❌ Lockdown işlemi sırasında "
                "beklenmeyen bir hata oluştu."
            )

        except (
            discord.HTTPException,
            discord.Forbidden,
        ):
            pass

    # ========================================================
    # COG UNLOAD
    # ========================================================

    def cog_unload(
        self,
    ) -> None:

        self._active.clear()
        self._locks.clear()

        self._states.clear()
        self._original_overwrites.clear()

        security_logger.info(
            "Lockdown cog unloaded."
        )


# ============================================================
# SETUP
# ============================================================


async def setup(
    bot: commands.Bot,
) -> None:

    await bot.add_cog(
        Lockdown(
            bot
        )
    )


__all__ = [
    "Lockdown",
    "LockdownResult",
    "setup",
]