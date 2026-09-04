from __future__ import annotations

# ============================================================
# PAG SECURITY BOT
# cogs/emergency.py
#
# Emergency Response Cog
#
# SORUMLULUKLAR
# ------------------------------------------------------------
# - Emergency mode kontrolü
# - Guild lockdown
# - Tehlikeli rol izinlerini kaldırma
# - Quarantine desteği
# - Everyone izinlerini koruma
# - Whitelist uyumu
# - PanelService üzerinden configuration
# - Anti-Nuke / Anti-Raid / Anti-Bot / Anti-Spam ile bağımsız
# - Hata izolasyonu
# ============================================================

import asyncio
from typing import Optional

import discord
from discord.ext import commands

from services.panel_service import PanelService
from utils.logger import security_logger


# ============================================================
# CONSTANTS
# ============================================================

EMERGENCY_COMMAND = "emergency"

DANGEROUS_PERMISSIONS = {
    "administrator": discord.Permissions.administrator,
    "manage_guild": discord.Permissions.manage_guild,
    "manage_channels": discord.Permissions.manage_channels,
    "manage_roles": discord.Permissions.manage_roles,
    "manage_webhooks": discord.Permissions.manage_webhooks,
    "kick_members": discord.Permissions.kick_members,
    "ban_members": discord.Permissions.ban_members,
    "moderate_members": discord.Permissions.moderate_members,
    "mention_everyone": discord.Permissions.mention_everyone,
}


# ============================================================
# RESULT
# ============================================================


class EmergencyResult:
    """
    Emergency işleminin runtime sonucunu temsil eder.
    """

    def __init__(
        self,
        *,
        success: bool = True,
    ) -> None:

        self.success = success

        self.roles_processed = 0
        self.roles_modified = 0

        self.channels_processed = 0
        self.channels_locked = 0

        self.users_quarantined = 0

        self.errors: list[str] = []

    def add_error(
        self,
        error: str,
    ) -> None:

        self.errors.append(
            str(error)
        )

        self.success = False

    def to_dict(self) -> dict:

        return {
            "success": self.success,
            "roles_processed": self.roles_processed,
            "roles_modified": self.roles_modified,
            "channels_processed": self.channels_processed,
            "channels_locked": self.channels_locked,
            "users_quarantined": self.users_quarantined,
            "errors": list(self.errors),
        }


# ============================================================
# COG
# ============================================================


class Emergency(commands.Cog):
    """
    PAG Security Emergency Response.

    PanelService config:

        security.emergency_mode

        emergency.remove_dangerous_roles
        emergency.quarantine
        emergency.lockdown

        emergency.remove_permissions

        emergency.minimum_actions_for_emergency

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
                "PanelService is required by Emergency cog."
            )

        # Aynı guild üzerinde aynı anda iki emergency
        # operasyonunun çalışmasını engeller.
        self._locks: dict[
            int,
            asyncio.Lock,
        ] = {}

        self._active: set[int] = set()

        self._last_results: dict[
            int,
            dict,
        ] = {}

        security_logger.info(
            "Emergency cog initialized."
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

    async def _is_enabled(
        self,
        guild_id: int,
    ) -> bool:

        try:

            return await self.panel.emergency_enabled(
                guild_id
            )

        except Exception:

            security_logger.exception(
                "Emergency mode check failed | guild=%s",
                guild_id,
            )

            return False

    async def _is_whitelisted_role(
        self,
        guild_id: int,
        role_id: int,
    ) -> bool:

        try:

            return await self.panel.is_whitelisted_role(
                guild_id,
                role_id,
            )

        except Exception:

            security_logger.exception(
                "Role whitelist check failed | "
                "guild=%s role=%s",
                guild_id,
                role_id,
            )

            return False

    async def _is_whitelisted_user(
        self,
        guild_id: int,
        user_id: int,
    ) -> bool:

        try:

            return await self.panel.is_whitelisted_user(
                guild_id,
                user_id,
            )

        except Exception:

            security_logger.exception(
                "User whitelist check failed | "
                "guild=%s user=%s",
                guild_id,
                user_id,
            )

            return False

    # ========================================================
    # BOT MEMBER
    # ========================================================

    def _get_bot_member(
        self,
        guild: discord.Guild,
    ) -> Optional[discord.Member]:

        if guild.me is not None:
            return guild.me

        if self.bot.user is None:
            return None

        return guild.get_member(
            self.bot.user.id
        )

    # ========================================================
    # ROLE SAFETY
    # ========================================================

    def _role_can_be_modified(
        self,
        guild: discord.Guild,
        role: discord.Role,
    ) -> bool:
        """
        Emergency sırasında hangi rollerin değiştirilebileceğini
        kontrol eder.

        Şunlara dokunulmaz:

        - @everyone
        - managed/integration rolleri
        - botun hiyerarşisindeki veya üstündeki roller
        """

        if role.is_default():
            return False

        if role.managed:
            return False

        me = self._get_bot_member(
            guild
        )

        if me is None:
            return False

        if role >= me.top_role:
            return False

        return True

    # ========================================================
    # REMOVE DANGEROUS ROLE PERMISSIONS
    # ========================================================

    async def remove_dangerous_role_permissions(
        self,
        guild: discord.Guild,
        result: EmergencyResult,
    ) -> None:
        """
        PanelService'de belirtilen tehlikeli izinleri rollerden
        kaldırır.

        Botun dokunamayacağı roller otomatik atlanır.
        """

        try:

            enabled = await self.panel.get(
                guild.id,
                "emergency.remove_dangerous_roles",
                True,
            )

        except Exception as exc:

            result.add_error(
                f"Emergency role configuration error: {exc}"
            )

            return

        if not bool(enabled):
            return

        configured_permissions = await self.panel.get(
            guild.id,
            "emergency.remove_permissions",
            [],
        )

        if not isinstance(
            configured_permissions,
            list,
        ):

            configured_permissions = []

        permissions_to_remove: list[str] = []

        for permission_name in configured_permissions:

            if not isinstance(
                permission_name,
                str,
            ):
                continue

            permission_name = (
                permission_name.strip()
                .lower()
            )

            if (
                permission_name
                in DANGEROUS_PERMISSIONS
            ):
                permissions_to_remove.append(
                    permission_name
                )

        if not permissions_to_remove:
            return

        for role in guild.roles:

            result.roles_processed += 1

            if not self._role_can_be_modified(
                guild,
                role,
            ):
                continue

            if await self._is_whitelisted_role(
                guild.id,
                role.id,
            ):
                continue

            old_permissions = role.permissions

            new_permissions = (
                old_permissions
            )

            changed = False

            for permission_name in permissions_to_remove:

                permission = (
                    DANGEROUS_PERMISSIONS[
                        permission_name
                    ]
                )

                if new_permissions.is_superset(
                    permission
                ):
                    new_permissions = (
                        new_permissions
                        & ~permission
                    )

                    changed = True

            if not changed:
                continue

            try:

                await role.edit(
                    permissions=new_permissions,
                    reason=(
                        "PAG Security Emergency Response"
                    ),
                )

                result.roles_modified += 1

                security_logger.warning(
                    "Emergency removed dangerous permissions | "
                    "guild=%s role=%s(%s)",
                    guild.id,
                    role.name,
                    role.id,
                )

            except (
                discord.Forbidden,
                discord.HTTPException,
                discord.NotFound,
            ) as exc:

                result.add_error(
                    "Role permission update failed "
                    f"for {role.id}: {exc}"
                )

            except Exception as exc:

                result.add_error(
                    "Unexpected role update error "
                    f"for {role.id}: {exc}"
                )

    # ========================================================
    # LOCKDOWN
    # ========================================================

    async def lockdown(
        self,
        guild: discord.Guild,
        result: EmergencyResult,
    ) -> None:
        """
        Guild kanallarını emergency lockdown moduna alır.

        @everyone için:

            send_messages=False
            add_reactions=False
            create_public_threads=False
            create_private_threads=False
            send_messages_in_threads=False

        Mevcut diğer izinler değiştirilmez.
        """

        enabled = await self.panel.get(
            guild.id,
            "emergency.lockdown",
            True,
        )

        if not bool(enabled):
            return

        everyone = guild.default_role

        if everyone is None:
            return

        for channel in guild.channels:

            result.channels_processed += 1

            if not isinstance(
                channel,
                discord.abc.GuildChannel,
            ):
                continue

            overwrite = (
                channel.overwrites_for(
                    everyone
                )
            )

            changed = False

            if overwrite.send_messages is not False:

                overwrite.send_messages = False
                changed = True

            if overwrite.add_reactions is not False:

                overwrite.add_reactions = False
                changed = True

            if overwrite.create_public_threads is not False:

                overwrite.create_public_threads = False
                changed = True

            if overwrite.create_private_threads is not False:

                overwrite.create_private_threads = False
                changed = True

            if overwrite.send_messages_in_threads is not False:

                overwrite.send_messages_in_threads = False
                changed = True

            if not changed:
                continue

            try:

                await channel.set_permissions(
                    everyone,
                    overwrite=overwrite,
                    reason=(
                        "PAG Security Emergency Lockdown"
                    ),
                )

                result.channels_locked += 1

            except (
                discord.Forbidden,
                discord.HTTPException,
                discord.NotFound,
            ) as exc:

                result.add_error(
                    "Channel lockdown failed "
                    f"for {channel.id}: {exc}"
                )

            except Exception as exc:

                result.add_error(
                    "Unexpected lockdown error "
                    f"for {channel.id}: {exc}"
                )

    # ========================================================
    # QUARANTINE
    # ========================================================

    async def quarantine_user(
        self,
        guild: discord.Guild,
        member: discord.Member,
        result: Optional[EmergencyResult] = None,
    ) -> bool:
        """
        Üyeyi quarantine rolüne almaya çalışır.

        PanelService:

            emergency.quarantine

        true değilse hiçbir işlem yapılmaz.

        Quarantine rolü yoksa otomatik olarak oluşturulur.
        """

        if result is None:
            result = EmergencyResult()

        enabled = await self.panel.get(
            guild.id,
            "emergency.quarantine",
            False,
        )

        if not bool(enabled):
            return False

        if await self._is_whitelisted_user(
            guild.id,
            member.id,
        ):
            return False

        if member.bot:
            return False

        me = self._get_bot_member(
            guild
        )

        if me is None:
            return False

        if member == me:
            return False

        if member.top_role >= me.top_role:
            return False

        quarantine_role = discord.utils.get(
            guild.roles,
            name="PAG Security • Quarantine",
        )

        if quarantine_role is None:

            try:

                quarantine_role = await guild.create_role(
                    name="PAG Security • Quarantine",
                    reason=(
                        "PAG Security Emergency Quarantine"
                    ),
                )

            except (
                discord.Forbidden,
                discord.HTTPException,
            ) as exc:

                result.add_error(
                    f"Quarantine role creation failed: {exc}"
                )

                return False

        if quarantine_role >= me.top_role:
            result.add_error(
                "Quarantine role is above bot hierarchy."
            )

            return False

        try:

            await member.add_roles(
                quarantine_role,
                reason=(
                    "PAG Security Emergency Quarantine"
                ),
            )

            result.users_quarantined += 1

            security_logger.warning(
                "User quarantined | guild=%s user=%s",
                guild.id,
                member.id,
            )

            return True

        except (
            discord.Forbidden,
            discord.HTTPException,
            discord.NotFound,
        ) as exc:

            result.add_error(
                f"Quarantine failed for {member.id}: {exc}"
            )

            return False

    # ========================================================
    # EXECUTE
    # ========================================================

    async def execute(
        self,
        guild: discord.Guild,
        *,
        actor_id: Optional[int] = None,
        force: bool = False,
    ) -> EmergencyResult:
        """
        Emergency response'u çalıştırır.

        force=False:
            PanelService emergency_mode kontrol edilir.

        force=True:
            Yetkili internal çağrı tarafından kullanılması beklenir.
        """

        result = EmergencyResult()

        if guild is None:

            result.add_error(
                "Guild is required."
            )

            return result

        lock = self._get_lock(
            guild.id
        )

        async with lock:

            if guild.id in self._active:

                result.add_error(
                    "Emergency operation is already active."
                )

                return result

            self._active.add(
                guild.id
            )

            try:

                if not force:

                    enabled = await self._is_enabled(
                        guild.id
                    )

                    if not enabled:

                        result.add_error(
                            "Emergency mode is disabled."
                        )

                        return result

                if actor_id is not None:

                    if await self._is_whitelisted_user(
                        guild.id,
                        actor_id,
                    ):
                        security_logger.info(
                            "Emergency actor is whitelisted | "
                            "guild=%s actor=%s",
                            guild.id,
                            actor_id,
                        )

                security_logger.critical(
                    "EMERGENCY RESPONSE STARTED | "
                    "guild=%s actor=%s force=%s",
                    guild.id,
                    actor_id,
                    force,
                )

                # ------------------------------------------------
                # 1. Dangerous permissions
                # ------------------------------------------------

                await self.remove_dangerous_role_permissions(
                    guild,
                    result,
                )

                # ------------------------------------------------
                # 2. Lockdown
                # ------------------------------------------------

                await self.lockdown(
                    guild,
                    result,
                )

                # ------------------------------------------------
                # Save result
                # ------------------------------------------------

                self._last_results[
                    guild.id
                ] = result.to_dict()

                security_logger.critical(
                    "EMERGENCY RESPONSE FINISHED | "
                    "guild=%s success=%s "
                    "roles=%s channels=%s errors=%s",
                    guild.id,
                    result.success,
                    result.roles_modified,
                    result.channels_locked,
                    len(result.errors),
                )

                return result

            finally:

                self._active.discard(
                    guild.id
                )

    # ========================================================
    # STATUS
    # ========================================================

    def is_active(
        self,
        guild_id: int,
    ) -> bool:

        return guild_id in self._active

    def get_last_result(
        self,
        guild_id: int,
    ) -> Optional[dict]:

        result = self._last_results.get(
            guild_id
        )

        if result is None:
            return None

        return dict(result)

    # ========================================================
    # COMMAND
    # ========================================================

    @commands.command(
        name="emergency",
    )
    @commands.guild_only()
    @commands.has_permissions(
        administrator=True
    )
    @commands.bot_has_permissions(
        manage_roles=True,
        manage_channels=True,
    )
    async def emergency_command(
        self,
        ctx: commands.Context,
    ) -> None:
        """
        Manuel emergency response.

        Kullanım:

            !emergency
        """

        guild = ctx.guild

        if guild is None:
            return

        enabled = await self._is_enabled(
            guild.id
        )

        if not enabled:

            await ctx.send(
                "❌ Emergency mode PanelService tarafından kapalı."
            )

            return

        result = await self.execute(
            guild,
            actor_id=ctx.author.id,
        )

        if result.success:

            message = (
                "🚨 **EMERGENCY RESPONSE AKTİF**\n\n"
                f"🛡️ Değiştirilen roller: "
                f"`{result.roles_modified}`\n"
                f"🔒 Kilitlenen kanallar: "
                f"`{result.channels_locked}`\n"
                f"⚠️ Hatalar: "
                f"`{len(result.errors)}`"
            )

        else:

            message = (
                "⚠️ **Emergency response tamamlandı "
                "ancak bazı işlemler başarısız oldu.**\n\n"
                f"🛡️ Değiştirilen roller: "
                f"`{result.roles_modified}`\n"
                f"🔒 Kilitlenen kanallar: "
                f"`{result.channels_locked}`\n"
                f"❌ Hatalar: "
                f"`{len(result.errors)}`"
            )

        await ctx.send(
            message
        )

    # ========================================================
    # ERROR HANDLER
    # ========================================================

    @emergency_command.error
    async def emergency_command_error(
        self,
        ctx: commands.Context,
        error: commands.CommandError,
    ) -> None:

        if isinstance(
            error,
            commands.MissingPermissions,
        ):

            await ctx.send(
                "❌ Bu komutu kullanmak için Administrator yetkisi gerekiyor."
            )

            return

        if isinstance(
            error,
            commands.BotMissingPermissions,
        ):

            await ctx.send(
                "❌ Botun Emergency işlemi için gerekli yetkileri yok."
            )

            return

        if isinstance(
            error,
            commands.NoPrivateMessage,
        ):

            return

        security_logger.exception(
            "Emergency command error | guild=%s error=%s",
            getattr(
                ctx.guild,
                "id",
                None,
            ),
            error,
        )

        try:

            await ctx.send(
                "❌ Emergency komutu çalıştırılırken beklenmeyen bir hata oluştu."
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

        security_logger.info(
            "Emergency cog unloaded."
        )


# ============================================================
# SETUP
# ============================================================


async def setup(
    bot: commands.Bot,
) -> None:

    await bot.add_cog(
        Emergency(
            bot
        )
    )


__all__ = [
    "Emergency",
    "EmergencyResult",
    "setup",
]