from __future__ import annotations

import logging
from collections import Counter
from dataclasses import dataclass, field
from datetime import datetime, timezone

import discord
from discord import app_commands
from discord.ext import commands

from services.panel_service import PanelService

logger = logging.getLogger("pag_security.statistics")


@dataclass(slots=True)
class GuildStats:
    """Runtime security statistics for a guild."""

    events: Counter[str] = field(default_factory=Counter)
    started_at: datetime = field(
        default_factory=lambda: datetime.now(timezone.utc)
    )


class Statistics(commands.Cog):
    """PAG Security statistics and security-status commands."""

    def __init__(self, bot: commands.Bot) -> None:
        self.bot = bot

        # Bot tarafından oluşturulan merkezi PanelService'i kullan.
        self.panel: PanelService = getattr(
            bot,
            "panel_service",
            None,
        )

        # Güvenli fallback.
        if self.panel is None:
            self.panel = PanelService()

        self._stats: dict[int, GuildStats] = {}

        logger.info("Statistics cog initialized")

    # ============================================================
    # INTERNAL
    # ============================================================

    def _get_stats(self, guild_id: int) -> GuildStats:
        stats = self._stats.get(guild_id)

        if stats is None:
            stats = GuildStats()
            self._stats[guild_id] = stats

        return stats

    def record(
        self,
        guild_id: int,
        event: str,
        amount: int = 1,
    ) -> None:
        """Record a runtime security event."""

        if not event:
            return

        try:
            amount = max(1, int(amount))
        except (TypeError, ValueError):
            amount = 1

        self._get_stats(guild_id).events[event] += amount

    def get_event_count(
        self,
        guild_id: int,
        event: str,
    ) -> int:
        return self._get_stats(guild_id).events.get(event, 0)

    def get_all_event_counts(
        self,
        guild_id: int,
    ) -> dict[str, int]:
        return dict(self._get_stats(guild_id).events)

    def clear_guild(self, guild_id: int) -> None:
        self._stats.pop(guild_id, None)

    def cog_unload(self) -> None:
        self._stats.clear()

    # ============================================================
    # SERVER SNAPSHOT
    # ============================================================

    @staticmethod
    def _server_snapshot(
        guild: discord.Guild,
    ) -> dict[str, int]:
        """Create a lightweight snapshot using cached Discord data."""

        members = guild.members

        bots = sum(
            1
            for member in members
            if member.bot
        )

        humans = len(members) - bots

        text_channels = sum(
            1
            for channel in guild.channels
            if isinstance(channel, discord.TextChannel)
        )

        voice_channels = sum(
            1
            for channel in guild.channels
            if isinstance(channel, discord.VoiceChannel)
        )

        categories = sum(
            1
            for channel in guild.channels
            if isinstance(channel, discord.CategoryChannel)
        )

        roles = len(guild.roles)

        managed_roles = sum(
            1
            for role in guild.roles
            if role.managed
        )

        return {
            "members": len(members),
            "humans": humans,
            "bots": bots,
            "channels": len(guild.channels),
            "text_channels": text_channels,
            "voice_channels": voice_channels,
            "categories": categories,
            "roles": roles,
            "managed_roles": managed_roles,
        }

    # ============================================================
    # EMBED
    # ============================================================

    @staticmethod
    def _base_embed(
        guild: discord.Guild,
        title: str,
    ) -> discord.Embed:
        embed = discord.Embed(
            title=title,
            color=discord.Color.blurple(),
            timestamp=datetime.now(timezone.utc),
        )

        if guild.icon:
            embed.set_thumbnail(url=guild.icon.url)

        embed.set_footer(
            text="PAG Security • Statistics"
        )

        return embed

    # ============================================================
    # /security-stats
    # ============================================================

    @app_commands.command(
        name="security-stats",
        description="Sunucunun güvenlik istatistiklerini gösterir.",
    )
    @app_commands.guild_only()
    async def security_stats(
        self,
        interaction: discord.Interaction,
    ) -> None:
        guild = interaction.guild

        if guild is None:
            await interaction.response.send_message(
                "❌ Bu komut sadece sunucularda kullanılabilir.",
                ephemeral=True,
            )
            return

        try:
            # PanelService.load() ASYNC olduğu için await gerekli.
            config = await self.panel.load(guild.id)

            snapshot = self._server_snapshot(guild)
            runtime = self._get_stats(guild.id)

            security = config.get("security", {})
            detection = config.get("detection", {})
            emergency = config.get("emergency", {})

            embed = self._base_embed(
                guild,
                "🛡️ PAG Security Statistics",
            )

            enabled = bool(
                security.get("enabled", True)
            )

            smart_detection = bool(
                security.get("smart_detection", True)
            )

            emergency_mode = bool(
                security.get("emergency_mode", True)
            )

            embed.add_field(
                name="🔐 Security",
                value=(
                    f"**Durum:** "
                    f"{'🟢 Aktif' if enabled else '🔴 Kapalı'}\n"
                    f"**Smart Detection:** "
                    f"{'🟢 Açık' if smart_detection else '🔴 Kapalı'}\n"
                    f"**Emergency Mode:** "
                    f"{'🟢 Açık' if emergency_mode else '🔴 Kapalı'}"
                ),
                inline=False,
            )

            embed.add_field(
                name="👥 Sunucu",
                value=(
                    f"**Üye:** `{snapshot['members']}`\n"
                    f"**Kullanıcı:** `{snapshot['humans']}`\n"
                    f"**Bot:** `{snapshot['bots']}`"
                ),
                inline=True,
            )

            embed.add_field(
                name="📁 Yapı",
                value=(
                    f"**Kanal:** `{snapshot['channels']}`\n"
                    f"**Rol:** `{snapshot['roles']}`\n"
                    f"**Kategori:** `{snapshot['categories']}`"
                ),
                inline=True,
            )

            embed.add_field(
                name="⚙️ Emergency",
                value=(
                    f"**Dangerous Roles:** "
                    f"{'🟢' if emergency.get('remove_dangerous_roles', True) else '🔴'}\n"
                    f"**Lockdown:** "
                    f"{'🟢' if emergency.get('lockdown', True) else '🔴'}\n"
                    f"**Quarantine:** "
                    f"{'🟢' if emergency.get('quarantine', False) else '🔴'}"
                ),
                inline=True,
            )

            events = runtime.events
            total_events = sum(events.values())

            embed.add_field(
                name="📈 Runtime Events",
                value=(
                    f"**Toplam:** `{total_events}`\n"
                    f"**Kick:** `{events.get('kick', 0)}`\n"
                    f"**Ban:** `{events.get('ban', 0)}`\n"
                    f"**Kanal Silme:** "
                    f"`{events.get('channel_delete', 0)}`\n"
                    f"**Rol Silme:** "
                    f"`{events.get('role_delete', 0)}`"
                ),
                inline=False,
            )

            thresholds = detection.get(
                "thresholds",
                {},
            )

            embed.add_field(
                name="🎯 Detection Thresholds",
                value=(
                    f"`Kick` → `{thresholds.get('kick', 5)}`\n"
                    f"`Ban` → `{thresholds.get('ban', 3)}`\n"
                    f"`Channel Delete` → "
                    f"`{thresholds.get('channel_delete', 5)}`\n"
                    f"`Role Delete` → "
                    f"`{thresholds.get('role_delete', 3)}`"
                ),
                inline=True,
            )

            embed.add_field(
                name="⏱️ Detection",
                value=(
                    f"**Window:** "
                    f"`{detection.get('window_seconds', 15)}s`\n"
                    f"**Emergency Min:** "
                    f"`{emergency.get('minimum_actions_for_emergency', 1)}`"
                ),
                inline=True,
            )

            await interaction.response.send_message(
                embed=embed,
                ephemeral=True,
            )

        except Exception:
            logger.exception(
                "Failed to generate security statistics "
                "for guild %s",
                guild.id,
            )

            if interaction.response.is_done():
                await interaction.followup.send(
                    "❌ İstatistikler oluşturulurken bir hata oluştu.",
                    ephemeral=True,
                )
            else:
                await interaction.response.send_message(
                    "❌ İstatistikler oluşturulurken bir hata oluştu.",
                    ephemeral=True,
                )

    # ============================================================
    # /security-events
    # ============================================================

    @app_commands.command(
        name="security-events",
        description="PAG Security runtime olaylarını gösterir.",
    )
    @app_commands.guild_only()
    @app_commands.default_permissions(
        administrator=True,
    )
    async def security_events(
        self,
        interaction: discord.Interaction,
    ) -> None:
        guild = interaction.guild

        if guild is None:
            await interaction.response.send_message(
                "❌ Bu komut sadece sunucularda kullanılabilir.",
                ephemeral=True,
            )
            return

        try:
            events = self._get_stats(guild.id).events

            if not events:
                await interaction.response.send_message(
                    "📊 Henüz kaydedilmiş bir security eventi yok.",
                    ephemeral=True,
                )
                return

            ordered = sorted(
                events.items(),
                key=lambda item: item[1],
                reverse=True,
            )

            lines = [
                f"`{event}` → **{count}**"
                for event, count in ordered[:20]
            ]

            embed = self._base_embed(
                guild,
                "📊 Security Events",
            )

            embed.description = "\n".join(lines)

            embed.add_field(
                name="Total",
                value=f"`{sum(events.values())}`",
                inline=False,
            )

            await interaction.response.send_message(
                embed=embed,
                ephemeral=True,
            )

        except Exception:
            logger.exception(
                "Failed to generate event statistics "
                "for guild %s",
                guild.id,
            )

            await interaction.response.send_message(
                "❌ Event istatistikleri alınamadı.",
                ephemeral=True,
            )

    # ============================================================
    # /server-stats
    # ============================================================

    @app_commands.command(
        name="server-stats",
        description="Sunucunun temel istatistiklerini gösterir.",
    )
    @app_commands.guild_only()
    async def server_stats(
        self,
        interaction: discord.Interaction,
    ) -> None:
        guild = interaction.guild

        if guild is None:
            await interaction.response.send_message(
                "❌ Bu komut sadece sunucularda kullanılabilir.",
                ephemeral=True,
            )
            return

        try:
            snapshot = self._server_snapshot(guild)

            embed = self._base_embed(
                guild,
                "📊 Server Statistics",
            )

            embed.add_field(
                name="👥 Members",
                value=(
                    f"**Total:** `{snapshot['members']}`\n"
                    f"**Humans:** `{snapshot['humans']}`\n"
                    f"**Bots:** `{snapshot['bots']}`"
                ),
                inline=True,
            )

            embed.add_field(
                name="📁 Channels",
                value=(
                    f"**Total:** `{snapshot['channels']}`\n"
                    f"**Text:** `{snapshot['text_channels']}`\n"
                    f"**Voice:** `{snapshot['voice_channels']}`\n"
                    f"**Categories:** `{snapshot['categories']}`"
                ),
                inline=True,
            )

            embed.add_field(
                name="🎭 Roles",
                value=(
                    f"**Total:** `{snapshot['roles']}`\n"
                    f"**Managed:** `{snapshot['managed_roles']}`"
                ),
                inline=True,
            )

            await interaction.response.send_message(
                embed=embed,
                ephemeral=True,
            )

        except Exception:
            logger.exception(
                "Failed to generate server statistics "
                "for guild %s",
                guild.id,
            )

            await interaction.response.send_message(
                "❌ Sunucu istatistikleri alınamadı.",
                ephemeral=True,
            )


async def setup(bot: commands.Bot) -> None:
    await bot.add_cog(
        Statistics(bot)
    )
