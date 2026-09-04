# cogs/quarantine.py

from __future__ import annotations

import asyncio
from dataclasses import dataclass
from typing import Optional

import discord
from discord.ext import commands

from utils.logger import security_logger


# ============================================================
# PAG SECURITY BOT
# cogs/quarantine.py
#
# Quarantine / izolasyon sistemi
#
# SORUMLULUKLAR
# ------------------------------------------------------------
# - Şüpheli kullanıcıyı karantinaya alma
# - Mevcut rollerini geçici olarak kaldırma
# - Quarantine rolü oluşturma
# - Quarantine rolünü güvenli şekilde yönetme
# - Kullanıcıyı karantinadan çıkarma
# - Guild bazlı quarantine durumu
# - PanelService whitelist uyumluluğu
# - Hata izolasyonu
#
# PanelService:
#     config:
#         emergency.quarantine
#
# Loader:
#     cogs.quarantine
#
# ============================================================


QUARANTINE_ROLE_NAME = "PAG • Quarantine"

QUARANTINE_COLOR = discord.Color.dark_grey()

QUARANTINE_REASON = (
    "PAG Security quarantine isolation"
)


# ============================================================
# DATA
# ============================================================


@dataclass(slots=True)
class QuarantineEntry:
    """
    Karantinaya alınan kullanıcı için runtime bilgisi.
    """

    user_id: int

    role_ids: list[int]

    reason: str

    created_at: float


# ============================================================
# COG
# ============================================================


class Quarantine(commands.Cog):
    """
    PAG Security quarantine sistemi.

    Sistem PanelService ile çalışır.

    PanelService zorunlu değildir:
    Bot üzerinde bulunmuyorsa Cog güvenli şekilde
    devre dışı kalır.
    """

    def __init__(
        self,
        bot: commands.Bot,
    ) -> None:

        self.bot = bot

        # ----------------------------------------------------
        # Runtime quarantine kayıtları
        #
        # guild_id -> user_id -> entry
        # ----------------------------------------------------

        self._entries: dict[
            int,
            dict[int, QuarantineEntry],
        ] = {}

        # ----------------------------------------------------
        # Guild lock
        # ----------------------------------------------------

        self._locks: dict[
            int,
            asyncio.Lock,
        ] = {}

        security_logger.info(
            "Quarantine cog initialized."
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

    def _get_entries(
        self,
        guild_id: int,
    ) -> dict[int, QuarantineEntry]:

        return self._entries.setdefault(
            guild_id,
            {},
        )

    def _get_panel_service(self):
        """
        Bot üzerindeki PanelService'i güvenli şekilde alır.

        Beklenen:
            bot.panel_service
        """

        return getattr(
            self.bot,
            "panel_service",
            None,
        )

    async def _is_enabled(
        self,
        guild_id: int,
    ) -> bool:

        panel = self._get_panel_service()

        if panel is None:
            return True

        try:

            return bool(
                await panel.is_enabled(
                    guild_id
                )
            )

        except Exception as exc:

            security_logger.warning(
                "PanelService security check failed | "
                "guild=%s error=%s",
                guild_id,
                exc,
            )

            # Config okunamazsa quarantine
            # işlemini tamamen kapatmak yerine
            # güvenli tarafta kal.
            return True

    async def _quarantine_enabled(
        self,
        guild_id: int,
    ) -> bool:

        panel = self._get_panel_service()

        if panel is None:
            return True

        try:

            return bool(
                await panel.get(
                    guild_id,
                    "emergency.quarantine",
                    False,
                )
            )

        except Exception as exc:

            security_logger.warning(
                "Quarantine config read failed | "
                "guild=%s error=%s",
                guild_id,
                exc,
            )

            return False

    async def _is_whitelisted(
        self,
        guild_id: int,
        user_id: int,
    ) -> bool:

        panel = self._get_panel_service()

        if panel is None:
            return False

        try:

            return bool(
                await panel.is_whitelisted_user(
                    guild_id,
                    user_id,
                )
            )

        except Exception as exc:

            security_logger.warning(
                "Whitelist check failed | "
                "guild=%s user=%s error=%s",
                guild_id,
                user_id,
                exc,
            )

            return False

    # ========================================================
    # ROLE
    # ========================================================

    async def _get_or_create_role(
        self,
        guild: discord.Guild,
    ) -> Optional[discord.Role]:
        """
        Quarantine rolünü bulur veya oluşturur.
        """

        existing = discord.utils.get(
            guild.roles,
            name=QUARANTINE_ROLE_NAME,
        )

        if existing is not None:
            return existing

        try:

            role = await guild.create_role(
                name=QUARANTINE_ROLE_NAME,
                colour=QUARANTINE_COLOR,
                reason=QUARANTINE_REASON,
            )

            security_logger.info(
                "Quarantine role created | "
                "guild=%s role=%s",
                guild.id,
                role.id,
            )

            return role

        except (
            discord.Forbidden,
            discord.HTTPException,
        ) as exc:

            security_logger.error(
                "Failed to create quarantine role | "
                "guild=%s error=%s",
                guild.id,
                exc,
            )

            return None

    # ========================================================
    # ROLE POSITION
    # ========================================================

    async def _ensure_role_position(
        self,
        guild: discord.Guild,
        role: discord.Role,
    ) -> None:
        """
        Botun yönetebileceği en güvenli pozisyona
        quarantine rolünü taşımaya çalışır.

        Bot rolünün üstüne çıkmaya çalışmaz.
        """

        me = guild.me

        if me is None:
            return

        top_role = me.top_role

        if top_role.position <= 1:
            return

        target_position = max(
            1,
            top_role.position - 1,
        )

        if role.position >= target_position:
            return

        try:

            await role.edit(
                position=target_position,
                reason=QUARANTINE_REASON,
            )

        except (
            discord.Forbidden,
            discord.HTTPException,
        ) as exc:

            security_logger.warning(
                "Failed to position quarantine role | "
                "guild=%s role=%s error=%s",
                guild.id,
                role.id,
                exc,
            )

    # ========================================================
    # MEMBER ROLE FILTER
    # ========================================================

    @staticmethod
    def _get_removable_roles(
        member: discord.Member,
        quarantine_role: discord.Role,
    ) -> list[discord.Role]:
        """
        Bot tarafından kaldırılabilecek roller.

        Şunlar korunur:
            - @everyone
            - managed roller
            - botun yönetemediği roller
            - quarantine rolü
        """

        result: list[discord.Role] = []

        guild = member.guild

        me = guild.me

        if me is None:
            return result

        for role in member.roles:

            if role.is_default():
                continue

            if role.managed:
                continue

            if role == quarantine_role:
                continue

            if role >= me.top_role:
                continue

            result.append(role)

        return result

    # ========================================================
    # APPLY QUARANTINE
    # ========================================================

    async def quarantine_member(
        self,
        member: discord.Member,
        *,
        reason: str = "Security quarantine",
        remove_roles: bool = True,
    ) -> bool:
        """
        Kullanıcıyı karantinaya alır.

        True:
            Başarılı

        False:
            İşlem başarısız
        """

        guild = member.guild

        if not await self._is_enabled(
            guild.id
        ):
            return False

        if not await self._quarantine_enabled(
            guild.id
        ):
            security_logger.debug(
                "Quarantine disabled by configuration | "
                "guild=%s",
                guild.id,
            )

            return False

        if await self._is_whitelisted(
            guild.id,
            member.id,
        ):
            security_logger.warning(
                "Quarantine blocked by whitelist | "
                "guild=%s user=%s",
                guild.id,
                member.id,
            )

            return False

        lock = self._get_lock(
            guild.id
        )

        async with lock:

            entries = self._get_entries(
                guild.id
            )

            # Zaten karantinadaysa
            if member.id in entries:

                quarantine_role = discord.utils.get(
                    guild.roles,
                    name=QUARANTINE_ROLE_NAME,
                )

                if (
                    quarantine_role is not None
                    and quarantine_role
                    not in member.roles
                ):

                    try:

                        await member.add_roles(
                            quarantine_role,
                            reason=reason,
                        )

                    except (
                        discord.Forbidden,
                        discord.HTTPException,
                    ):

                        return False

                return True

            quarantine_role = (
                await self._get_or_create_role(
                    guild
                )
            )

            if quarantine_role is None:
                return False

            await self._ensure_role_position(
                guild,
                quarantine_role,
            )

            roles_to_remove: list[
                discord.Role
            ] = []

            if remove_roles:

                roles_to_remove = (
                    self._get_removable_roles(
                        member,
                        quarantine_role,
                    )
                )

            entry = QuarantineEntry(
                user_id=member.id,
                role_ids=[
                    role.id
                    for role in roles_to_remove
                ],
                reason=reason,
                created_at=(
                    discord.utils.utcnow()
                    .timestamp()
                ),
            )

            try:

                # Önce mevcut roller kaldırılır.
                if roles_to_remove:

                    await member.remove_roles(
                        *roles_to_remove,
                        reason=reason,
                    )

                # Ardından quarantine rolü verilir.
                await member.add_roles(
                    quarantine_role,
                    reason=reason,
                )

            except discord.Forbidden as exc:

                security_logger.error(
                    "Quarantine permission denied | "
                    "guild=%s user=%s error=%s",
                    guild.id,
                    member.id,
                    exc,
                )

                # Kısmi işlem ihtimalinde
                # mümkünse quarantine rolünü eklemeyi dene.
                try:

                    if quarantine_role not in member.roles:

                        await member.add_roles(
                            quarantine_role,
                            reason=reason,
                        )

                except Exception:
                    pass

                return False

            except discord.HTTPException as exc:

                security_logger.error(
                    "Quarantine HTTP failure | "
                    "guild=%s user=%s error=%s",
                    guild.id,
                    member.id,
                    exc,
                )

                return False

            entries[
                member.id
            ] = entry

            security_logger.warning(
                "Member quarantined | "
                "guild=%s user=%s reason=%s",
                guild.id,
                member.id,
                reason,
            )

            return True

    # ========================================================
    # RELEASE
    # ========================================================

    async def release_member(
        self,
        member: discord.Member,
        *,
        reason: str = "Security quarantine release",
        restore_roles: bool = True,
    ) -> bool:
        """
        Kullanıcıyı karantinadan çıkarır.

        Kaydedilmiş roller mümkünse geri yüklenir.
        """

        guild = member.guild

        lock = self._get_lock(
            guild.id
        )

        async with lock:

            entries = self._get_entries(
                guild.id
            )

            entry = entries.get(
                member.id
            )

            quarantine_role = discord.utils.get(
                guild.roles,
                name=QUARANTINE_ROLE_NAME,
            )

            if entry is None:

                # Runtime kaydı yoksa bile
                # quarantine rolünü kaldırmayı dene.

                if quarantine_role is None:
                    return True

                if quarantine_role not in member.roles:
                    return True

                try:

                    await member.remove_roles(
                        quarantine_role,
                        reason=reason,
                    )

                    return True

                except (
                    discord.Forbidden,
                    discord.HTTPException,
                ) as exc:

                    security_logger.error(
                        "Failed to remove quarantine role | "
                        "guild=%s user=%s error=%s",
                        guild.id,
                        member.id,
                        exc,
                    )

                    return False

            try:

                if (
                    quarantine_role is not None
                    and quarantine_role in member.roles
                ):

                    await member.remove_roles(
                        quarantine_role,
                        reason=reason,
                    )

                if restore_roles:

                    me = guild.me

                    if me is not None:

                        roles_to_restore: list[
                            discord.Role
                        ] = []

                        for role_id in entry.role_ids:

                            role = guild.get_role(
                                role_id
                            )

                            if role is None:
                                continue

                            if role.managed:
                                continue

                            if role >= me.top_role:
                                continue

                            roles_to_restore.append(
                                role
                            )

                        if roles_to_restore:

                            await member.add_roles(
                                *roles_to_restore,
                                reason=reason,
                            )

            except (
                discord.Forbidden,
                discord.HTTPException,
            ) as exc:

                security_logger.error(
                    "Failed to release quarantined member | "
                    "guild=%s user=%s error=%s",
                    guild.id,
                    member.id,
                    exc,
                )

                return False

            entries.pop(
                member.id,
                None,
            )

            security_logger.info(
                "Member released from quarantine | "
                "guild=%s user=%s",
                guild.id,
                member.id,
            )

            return True

    # ========================================================
    # CHECK
    # ========================================================

    def is_quarantined(
        self,
        guild_id: int,
        user_id: int,
    ) -> bool:

        return (
            user_id
            in self._entries.get(
                guild_id,
                {},
            )
        )

    # ========================================================
    # LIST
    # ========================================================

    def get_quarantined(
        self,
        guild_id: int,
    ) -> list[int]:

        return list(
            self._entries.get(
                guild_id,
                {},
            ).keys()
        )

    # ========================================================
    # COMMAND GROUP
    # ========================================================

    @commands.group(
        name="quarantine",
        aliases=["q"],
        invoke_without_command=True,
    )
    @commands.has_guild_permissions(
        administrator=True
    )
    async def quarantine_command(
        self,
        ctx: commands.Context,
    ) -> None:
        """
        !quarantine

        Quarantine sistemi hakkında bilgi verir.
        """

        entries = self.get_quarantined(
            ctx.guild.id
        )

        embed = discord.Embed(
            title="🛡️ Quarantine",
            description=(
                "PAG Security izolasyon sistemi."
            ),
            colour=QUARANTINE_COLOR,
        )

        embed.add_field(
            name="Karantinadaki Kullanıcı",
            value=str(
                len(entries)
            ),
            inline=True,
        )

        embed.add_field(
            name="Komutlar",
            value=(
                "`!quarantine add @user`"
                "\n"
                "`!quarantine remove @user`"
                "\n"
                "`!quarantine list`"
            ),
            inline=False,
        )

        await ctx.send(
            embed=embed
        )

    # ========================================================
    # ADD
    # ========================================================

    @quarantine_command.command(
        name="add"
    )
    @commands.has_guild_permissions(
        administrator=True
    )
    async def quarantine_add(
        self,
        ctx: commands.Context,
        member: discord.Member,
        *,
        reason: str = "Manual quarantine",
    ) -> None:

        if await self.quarantine_member(
            member,
            reason=reason,
        ):

            await ctx.send(
                f"🛡️ {member.mention} karantinaya alındı."
            )

        else:

            await ctx.send(
                "❌ Kullanıcı karantinaya alınamadı."
            )

    # ========================================================
    # REMOVE
    # ========================================================

    @quarantine_command.command(
        name="remove",
        aliases=["release"],
    )
    @commands.has_guild_permissions(
        administrator=True
    )
    async def quarantine_remove(
        self,
        ctx: commands.Context,
        member: discord.Member,
    ) -> None:

        if await self.release_member(
            member
        ):

            await ctx.send(
                f"✅ {member.mention} karantinadan çıkarıldı."
            )

        else:

            await ctx.send(
                "❌ Kullanıcı karantinadan çıkarılamadı."
            )

    # ========================================================
    # LIST
    # ========================================================

    @quarantine_command.command(
        name="list"
    )
    @commands.has_guild_permissions(
        administrator=True
    )
    async def quarantine_list(
        self,
        ctx: commands.Context,
    ) -> None:

        user_ids = self.get_quarantined(
            ctx.guild.id
        )

        if not user_ids:

            await ctx.send(
                "🛡️ Karantinada kullanıcı yok."
            )

            return

        lines: list[str] = []

        for user_id in user_ids:

            member = ctx.guild.get_member(
                user_id
            )

            if member is None:

                lines.append(
                    f"• `{user_id}`"
                )

            else:

                lines.append(
                    f"• {member.mention} (`{member.id}`)"
                )

        embed = discord.Embed(
            title="🛡️ Quarantine List",
            description="\n".join(lines),
            colour=QUARANTINE_COLOR,
        )

        await ctx.send(
            embed=embed
        )

    # ========================================================
    # ERROR HANDLER
    # ========================================================

    @quarantine_command.error
    async def quarantine_command_error(
        self,
        ctx: commands.Context,
        error: commands.CommandError,
    ) -> None:

        if isinstance(
            error,
            commands.MissingPermissions,
        ):

            await ctx.send(
                "❌ Bu işlem için Administrator yetkisi gerekiyor."
            )

            return

        if isinstance(
            error,
            commands.MemberNotFound,
        ):

            await ctx.send(
                "❌ Kullanıcı bulunamadı."
            )

            return

        if isinstance(
            error,
            commands.MissingRequiredArgument,
        ):

            await ctx.send(
                "❌ Kullanıcı belirtmelisin."
            )

            return

        if isinstance(
            error,
            commands.CommandInvokeError,
        ):

            security_logger.exception(
                "Quarantine command failed | "
                "guild=%s error=%s",
                getattr(
                    ctx.guild,
                    "id",
                    None,
                ),
                error.original,
            )

            await ctx.send(
                "❌ Quarantine işlemi sırasında bir hata oluştu."
            )

            return

        security_logger.error(
            "Unhandled quarantine command error | "
            "guild=%s error=%s",
            getattr(
                ctx.guild,
                "id",
                None,
            ),
            error,
        )

    # ========================================================
    # CLEANUP
    # ========================================================

    def cog_unload(
        self,
    ) -> None:

        self._entries.clear()
        self._locks.clear()

        security_logger.info(
            "Quarantine cog unloaded."
        )


# ============================================================
# SETUP
# ============================================================


async def setup(
    bot: commands.Bot,
) -> None:

    await bot.add_cog(
        Quarantine(bot)
    )


__all__ = [
    "Quarantine",
    "QuarantineEntry",
    "setup",
]