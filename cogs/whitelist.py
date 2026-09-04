# cogs/whitelist.py

from __future__ import annotations

import discord
from discord.ext import commands

from utils.logger import security_logger


# ============================================================
# PAG SECURITY BOT
# cogs/whitelist.py
#
# Guild whitelist yönetimi
#
# PanelService:
#     whitelist.users
#     whitelist.roles
#     whitelist.channels
#
# Komutlar:
#     !whitelist
#     !whitelist user add @user
#     !whitelist user remove @user
#     !whitelist user list
#     !whitelist role add @role
#     !whitelist role remove @role
#     !whitelist role list
#     !whitelist channel add #channel
#     !whitelist channel remove #channel
#     !whitelist channel list
#     !whitelist clear
#
# ============================================================


class Whitelist(commands.Cog):
    """
    PAG Security whitelist yönetim Cog'u.

    Tüm kalıcı veriler PanelService üzerinden tutulur.
    """

    def __init__(
        self,
        bot: commands.Bot,
    ) -> None:

        self.bot = bot

        security_logger.info(
            "Whitelist cog initialized."
        )

    # ========================================================
    # PANEL SERVICE
    # ========================================================

    def _get_panel_service(self):
        return getattr(
            self.bot,
            "panel_service",
            None,
        )

    async def _get_config(
        self,
        guild_id: int,
    ) -> dict:
        panel = self._get_panel_service()

        if panel is None:
            raise RuntimeError(
                "PanelService is not available."
            )

        config = await panel.get(
            guild_id,
            "whitelist",
            {},
        )

        if not isinstance(config, dict):
            config = {}

        return config

    # ========================================================
    # NORMALIZE
    # ========================================================

    @staticmethod
    def _normalize_ids(
        values,
    ) -> list[int]:

        result: list[int] = []

        if not isinstance(
            values,
            list,
        ):
            return result

        for value in values:

            try:
                value = int(value)
            except (
                TypeError,
                ValueError,
            ):
                continue

            if value <= 0:
                continue

            if value not in result:
                result.append(value)

        return result

    async def _get_ids(
        self,
        guild_id: int,
        category: str,
    ) -> list[int]:

        panel = self._get_panel_service()

        if panel is None:
            raise RuntimeError(
                "PanelService is not available."
            )

        values = await panel.get(
            guild_id,
            f"whitelist.{category}",
            [],
        )

        return self._normalize_ids(
            values
        )

    async def _save_ids(
        self,
        guild_id: int,
        category: str,
        values: list[int],
    ) -> None:

        panel = self._get_panel_service()

        if panel is None:
            raise RuntimeError(
                "PanelService is not available."
            )

        values = self._normalize_ids(
            values
        )

        await panel.set(
            guild_id,
            f"whitelist.{category}",
            values,
        )

    # ========================================================
    # ADD
    # ========================================================

    async def _add(
        self,
        guild_id: int,
        category: str,
        object_id: int,
    ) -> bool:

        values = await self._get_ids(
            guild_id,
            category,
        )

        if object_id in values:
            return False

        values.append(
            int(object_id)
        )

        await self._save_ids(
            guild_id,
            category,
            values,
        )

        security_logger.info(
            "Whitelist entry added | "
            "guild=%s category=%s id=%s",
            guild_id,
            category,
            object_id,
        )

        return True

    # ========================================================
    # REMOVE
    # ========================================================

    async def _remove(
        self,
        guild_id: int,
        category: str,
        object_id: int,
    ) -> bool:

        values = await self._get_ids(
            guild_id,
            category,
        )

        if object_id not in values:
            return False

        values.remove(
            object_id
        )

        await self._save_ids(
            guild_id,
            category,
            values,
        )

        security_logger.info(
            "Whitelist entry removed | "
            "guild=%s category=%s id=%s",
            guild_id,
            category,
            object_id,
        )

        return True

    # ========================================================
    # ROOT COMMAND
    # ========================================================

    @commands.group(
        name="whitelist",
        aliases=["wl"],
        invoke_without_command=True,
    )
    @commands.has_guild_permissions(
        administrator=True
    )
    async def whitelist(
        self,
        ctx: commands.Context,
    ) -> None:
        """
        !whitelist
        """

        config = await self._get_config(
            ctx.guild.id
        )

        users = self._normalize_ids(
            config.get(
                "users",
                [],
            )
        )

        roles = self._normalize_ids(
            config.get(
                "roles",
                [],
            )
        )

        channels = self._normalize_ids(
            config.get(
                "channels",
                [],
            )
        )

        embed = discord.Embed(
            title="🛡️ PAG Security • Whitelist",
            description=(
                "Security sistemlerinin koruma dışında "
                "bırakacağı kayıtları yönetir."
            ),
            colour=discord.Color.blurple(),
        )

        embed.add_field(
            name="👤 Users",
            value=str(
                len(users)
            ),
            inline=True,
        )

        embed.add_field(
            name="🎭 Roles",
            value=str(
                len(roles)
            ),
            inline=True,
        )

        embed.add_field(
            name="📁 Channels",
            value=str(
                len(channels)
            ),
            inline=True,
        )

        embed.add_field(
            name="Komutlar",
            value=(
                "`!whitelist user add @user`"
                "\n"
                "`!whitelist user remove @user`"
                "\n"
                "`!whitelist user list`"
                "\n\n"
                "`!whitelist role add @role`"
                "\n"
                "`!whitelist role remove @role`"
                "\n"
                "`!whitelist role list`"
                "\n\n"
                "`!whitelist channel add #channel`"
                "\n"
                "`!whitelist channel remove #channel`"
                "\n"
                "`!whitelist channel list`"
                "\n\n"
                "`!whitelist clear`"
            ),
            inline=False,
        )

        await ctx.send(
            embed=embed
        )

    # ========================================================
    # USER GROUP
    # ========================================================

    @whitelist.group(
        name="user",
        aliases=["users"],
        invoke_without_command=True,
    )
    @commands.has_guild_permissions(
        administrator=True
    )
    async def whitelist_user(
        self,
        ctx: commands.Context,
    ) -> None:

        await ctx.send(
            "Kullanım: "
            "`!whitelist user add/remove/list`"
        )

    # ========================================================
    # USER ADD
    # ========================================================

    @whitelist_user.command(
        name="add"
    )
    @commands.has_guild_permissions(
        administrator=True
    )
    async def whitelist_user_add(
        self,
        ctx: commands.Context,
        member: discord.Member,
    ) -> None:

        added = await self._add(
            ctx.guild.id,
            "users",
            member.id,
        )

        if added:

            await ctx.send(
                f"✅ {member.mention} whitelist'e eklendi."
            )

        else:

            await ctx.send(
                f"ℹ️ {member.mention} zaten whitelist'te."
            )

    # ========================================================
    # USER REMOVE
    # ========================================================

    @whitelist_user.command(
        name="remove",
    )
    @commands.has_guild_permissions(
        administrator=True
    )
    async def whitelist_user_remove(
        self,
        ctx: commands.Context,
        member: discord.Member,
    ) -> None:

        removed = await self._remove(
            ctx.guild.id,
            "users",
            member.id,
        )

        if removed:

            await ctx.send(
                f"✅ {member.mention} whitelist'ten çıkarıldı."
            )

        else:

            await ctx.send(
                f"ℹ️ {member.mention} whitelist'te değil."
            )

    # ========================================================
    # USER LIST
    # ========================================================

    @whitelist_user.command(
        name="list"
    )
    @commands.has_guild_permissions(
        administrator=True
    )
    async def whitelist_user_list(
        self,
        ctx: commands.Context,
    ) -> None:

        values = await self._get_ids(
            ctx.guild.id,
            "users",
        )

        embed = discord.Embed(
            title="👤 Whitelisted Users",
            colour=discord.Color.blurple(),
        )

        if not values:

            embed.description = (
                "Whitelist'te kullanıcı bulunmuyor."
            )

        else:

            lines: list[str] = []

            for user_id in values:

                member = ctx.guild.get_member(
                    user_id
                )

                if member is not None:

                    lines.append(
                        f"• {member.mention} (`{user_id}`)"
                    )

                else:

                    lines.append(
                        f"• `<@{user_id}>` (`{user_id}`)"
                    )

            embed.description = "\n".join(
                lines
            )

        await ctx.send(
            embed=embed
        )

    # ========================================================
    # ROLE GROUP
    # ========================================================

    @whitelist.group(
        name="role",
        aliases=["roles"],
        invoke_without_command=True,
    )
    @commands.has_guild_permissions(
        administrator=True
    )
    async def whitelist_role(
        self,
        ctx: commands.Context,
    ) -> None:

        await ctx.send(
            "Kullanım: "
            "`!whitelist role add/remove/list`"
        )

    # ========================================================
    # ROLE ADD
    # ========================================================

    @whitelist_role.command(
        name="add"
    )
    @commands.has_guild_permissions(
        administrator=True
    )
    async def whitelist_role_add(
        self,
        ctx: commands.Context,
        role: discord.Role,
    ) -> None:

        added = await self._add(
            ctx.guild.id,
            "roles",
            role.id,
        )

        if added:

            await ctx.send(
                f"✅ `{role.name}` whitelist'e eklendi."
            )

        else:

            await ctx.send(
                f"ℹ️ `{role.name}` zaten whitelist'te."
            )

    # ========================================================
    # ROLE REMOVE
    # ========================================================

    @whitelist_role.command(
        name="remove",
    )
    @commands.has_guild_permissions(
        administrator=True
    )
    async def whitelist_role_remove(
        self,
        ctx: commands.Context,
        role: discord.Role,
    ) -> None:

        removed = await self._remove(
            ctx.guild.id,
            "roles",
            role.id,
        )

        if removed:

            await ctx.send(
                f"✅ `{role.name}` whitelist'ten çıkarıldı."
            )

        else:

            await ctx.send(
                f"ℹ️ `{role.name}` whitelist'te değil."
            )

    # ========================================================
    # ROLE LIST
    # ========================================================

    @whitelist_role.command(
        name="list"
    )
    @commands.has_guild_permissions(
        administrator=True
    )
    async def whitelist_role_list(
        self,
        ctx: commands.Context,
    ) -> None:

        values = await self._get_ids(
            ctx.guild.id,
            "roles",
        )

        embed = discord.Embed(
            title="🎭 Whitelisted Roles",
            colour=discord.Color.blurple(),
        )

        if not values:

            embed.description = (
                "Whitelist'te rol bulunmuyor."
            )

        else:

            lines: list[str] = []

            for role_id in values:

                role = ctx.guild.get_role(
                    role_id
                )

                if role is not None:

                    lines.append(
                        f"• {role.mention} "
                        f"(`{role_id}`)"
                    )

                else:

                    lines.append(
                        f"• `<@&{role_id}>` "
                        f"(`{role_id}`)"
                    )

            embed.description = "\n".join(
                lines
            )

        await ctx.send(
            embed=embed
        )

    # ========================================================
    # CHANNEL GROUP
    # ========================================================

    @whitelist.group(
        name="channel",
        aliases=["channels"],
        invoke_without_command=True,
    )
    @commands.has_guild_permissions(
        administrator=True
    )
    async def whitelist_channel(
        self,
        ctx: commands.Context,
    ) -> None:

        await ctx.send(
            "Kullanım: "
            "`!whitelist channel add/remove/list`"
        )

    # ========================================================
    # CHANNEL ADD
    # ========================================================

    @whitelist_channel.command(
        name="add"
    )
    @commands.has_guild_permissions(
        administrator=True
    )
    async def whitelist_channel_add(
        self,
        ctx: commands.Context,
        channel: discord.TextChannel,
    ) -> None:

        added = await self._add(
            ctx.guild.id,
            "channels",
            channel.id,
        )

        if added:

            await ctx.send(
                f"✅ {channel.mention} whitelist'e eklendi."
            )

        else:

            await ctx.send(
                f"ℹ️ {channel.mention} zaten whitelist'te."
            )

    # ========================================================
    # CHANNEL REMOVE
    # ========================================================

    @whitelist_channel.command(
        name="remove",
    )
    @commands.has_guild_permissions(
        administrator=True
    )
    async def whitelist_channel_remove(
        self,
        ctx: commands.Context,
        channel: discord.TextChannel,
    ) -> None:

        removed = await self._remove(
            ctx.guild.id,
            "channels",
            channel.id,
        )

        if removed:

            await ctx.send(
                f"✅ {channel.mention} whitelist'ten çıkarıldı."
            )

        else:

            await ctx.send(
                f"ℹ️ {channel.mention} whitelist'te değil."
            )

    # ========================================================
    # CHANNEL LIST
    # ========================================================

    @whitelist_channel.command(
        name="list"
    )
    @commands.has_guild_permissions(
        administrator=True
    )
    async def whitelist_channel_list(
        self,
        ctx: commands.Context,
    ) -> None:

        values = await self._get_ids(
            ctx.guild.id,
            "channels",
        )

        embed = discord.Embed(
            title="📁 Whitelisted Channels",
            colour=discord.Color.blurple(),
        )

        if not values:

            embed.description = (
                "Whitelist'te kanal bulunmuyor."
            )

        else:

            lines: list[str] = []

            for channel_id in values:

                channel = ctx.guild.get_channel(
                    channel_id
                )

                if channel is not None:

                    lines.append(
                        f"• {channel.mention} "
                        f"(`{channel_id}`)"
                    )

                else:

                    lines.append(
                        f"• `<#{channel_id}>` "
                        f"(`{channel_id}`)"
                    )

            embed.description = "\n".join(
                lines
            )

        await ctx.send(
            embed=embed
        )

    # ========================================================
    # CLEAR
    # ========================================================

    @whitelist.command(
        name="clear"
    )
    @commands.has_guild_permissions(
        administrator=True
    )
    async def whitelist_clear(
        self,
        ctx: commands.Context,
    ) -> None:

        panel = self._get_panel_service()

        if panel is None:

            await ctx.send(
                "❌ PanelService kullanılamıyor."
            )

            return

        await panel.set(
            ctx.guild.id,
            "whitelist.users",
            [],
        )

        await panel.set(
            ctx.guild.id,
            "whitelist.roles",
            [],
        )

        await panel.set(
            ctx.guild.id,
            "whitelist.channels",
            [],
        )

        security_logger.warning(
            "Whitelist cleared | guild=%s",
            ctx.guild.id,
        )

        await ctx.send(
            "🧹 Guild whitelist tamamen temizlendi."
        )

    # ========================================================
    # ERROR HANDLER
    # ========================================================

    @whitelist.error
    async def whitelist_error(
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
            commands.RoleNotFound,
        ):

            await ctx.send(
                "❌ Rol bulunamadı."
            )

            return

        if isinstance(
            error,
            commands.ChannelNotFound,
        ):

            await ctx.send(
                "❌ Kanal bulunamadı."
            )

            return

        if isinstance(
            error,
            commands.CommandInvokeError,
        ):

            security_logger.exception(
                "Whitelist command failed | "
                "guild=%s error=%s",
                getattr(
                    ctx.guild,
                    "id",
                    None,
                ),
                error.original,
            )

            await ctx.send(
                "❌ Whitelist işlemi sırasında bir hata oluştu."
            )

            return

        security_logger.error(
            "Unhandled whitelist error | "
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

        security_logger.info(
            "Whitelist cog unloaded."
        )


# ============================================================
# SETUP
# ============================================================


async def setup(
    bot: commands.Bot,
) -> None:

    await bot.add_cog(
        Whitelist(bot)
    )


__all__ = [
    "Whitelist",
    "setup",
]