# cogs/panel.py

from __future__ import annotations

import logging
from typing import Any, Optional

import discord
from discord.ext import commands

from services.panel_service import PanelService


logger = logging.getLogger(__name__)


# ============================================================
# PAG SECURITY BOT
# cogs/panel.py
#
# Guild security configuration panel.
#
# Bu Cog:
# - PanelService üzerinden config yönetir.
# - Security Core'u KAPATAMAZ.
# - Modüler security sistemlerini açıp/kapatabilir.
# - Detection thresholdlarını yönetebilir.
# - Risk seviyelerini görüntüleyebilir.
# - Whitelist durumunu gösterebilir.
# - Config resetleyebilir.
#
# PanelService dışında doğrudan JSON işlemi yapılmaz.
# ============================================================


# ============================================================
# CONSTANTS
# ============================================================

MODULES: dict[str, str] = {
    "anti_nuke": "Anti-Nuke",
    "anti_raid": "Anti-Raid",
    "anti_spam": "Anti-Spam",
    "anti_scam": "Anti-Scam",
    "anti_bot": "Anti-Bot",
}

THRESHOLD_NAMES: dict[str, str] = {
    "kick": "Kick",
    "ban": "Ban",
    "channel_delete": "Channel Delete",
    "channel_create": "Channel Create",
    "role_delete": "Role Delete",
    "role_create": "Role Create",
    "webhook_create": "Webhook Create",
    "bot_add": "Bot Add",
    "permission_change": "Permission Change",
}

RISK_NAMES: dict[str, str] = {
    "suspicious": "Suspicious",
    "high": "High",
    "critical": "Critical",
}


# ============================================================
# HELPERS
# ============================================================


def _module_key_from_name(name: str) -> Optional[str]:
    """
    Kullanıcı tarafından verilen module adını normalize eder.
    """

    normalized = (
        name.strip()
        .lower()
        .replace("-", "_")
        .replace(" ", "_")
    )

    aliases = {
        "nuke": "anti_nuke",
        "antinuke": "anti_nuke",
        "anti_nuke": "anti_nuke",

        "raid": "anti_raid",
        "antiraid": "anti_raid",
        "anti_raid": "anti_raid",

        "spam": "anti_spam",
        "antispam": "anti_spam",
        "anti_spam": "anti_spam",

        "scam": "anti_scam",
        "antiscam": "anti_scam",
        "anti_scam": "anti_scam",

        "bot": "anti_bot",
        "antibot": "anti_bot",
        "anti_bot": "anti_bot",
    }

    return aliases.get(normalized)


def _bool_text(value: bool) -> str:
    return "🟢 Aktif" if value else "🔴 Pasif"


def _safe_int(
    value: Any,
    default: int,
    minimum: int = 1,
    maximum: int = 1000,
) -> int:
    """
    Güvenli integer conversion.
    """

    try:
        converted = int(value)
    except (TypeError, ValueError):
        converted = default

    return max(
        minimum,
        min(converted, maximum),
    )


# ============================================================
# PANEL VIEW
# ============================================================


class PanelView(discord.ui.View):
    """
    Basit interaktif security paneli.

    Butonların asıl config işlemleri PanelService üzerinden
    yapılır.
    """

    def __init__(
        self,
        cog: "Panel",
        guild_id: int,
    ) -> None:

        super().__init__(
            timeout=300
        )

        self.cog = cog
        self.guild_id = guild_id

    async def interaction_check(
        self,
        interaction: discord.Interaction,
    ) -> bool:

        if interaction.guild_id != self.guild_id:
            await interaction.response.send_message(
                "❌ Bu panel başka bir sunucuya ait.",
                ephemeral=True,
            )
            return False

        if interaction.user.guild_permissions.administrator:
            return True

        await interaction.response.send_message(
            "❌ Bu paneli kullanmak için Administrator yetkisi gerekir.",
            ephemeral=True,
        )

        return False

    @discord.ui.button(
        label="Durum",
        emoji="🛡️",
        style=discord.ButtonStyle.primary,
        row=0,
    )
    async def status_button(
        self,
        interaction: discord.Interaction,
        button: discord.ui.Button,
    ) -> None:

        await self.cog._send_status(
            interaction,
            self.guild_id,
        )

    @discord.ui.button(
        label="Modüller",
        emoji="⚙️",
        style=discord.ButtonStyle.secondary,
        row=0,
    )
    async def modules_button(
        self,
        interaction: discord.Interaction,
        button: discord.ui.Button,
    ) -> None:

        await self.cog._send_modules(
            interaction,
            self.guild_id,
        )

    @discord.ui.button(
        label="Threshold",
        emoji="📊",
        style=discord.ButtonStyle.secondary,
        row=0,
    )
    async def threshold_button(
        self,
        interaction: discord.Interaction,
        button: discord.ui.Button,
    ) -> None:

        await self.cog._send_thresholds(
            interaction,
            self.guild_id,
        )

    @discord.ui.button(
        label="Risk",
        emoji="⚠️",
        style=discord.ButtonStyle.secondary,
        row=1,
    )
    async def risk_button(
        self,
        interaction: discord.Interaction,
        button: discord.ui.Button,
    ) -> None:

        await self.cog._send_risk_levels(
            interaction,
            self.guild_id,
        )

    @discord.ui.button(
        label="Yenile",
        emoji="🔄",
        style=discord.ButtonStyle.success,
        row=1,
    )
    async def refresh_button(
        self,
        interaction: discord.Interaction,
        button: discord.ui.Button,
    ) -> None:

        await self.cog._send_panel(
            interaction,
            self.guild_id,
        )


# ============================================================
# PANEL COG
# ============================================================


class Panel(commands.Cog):
    """
    PAG Security configuration panel.
    """

    def __init__(
        self,
        bot: commands.Bot,
    ) -> None:

        self.bot = bot

        # Bot tarafından merkezi olarak oluşturulmuş service
        # varsa onu kullan.
        existing_service = getattr(
            bot,
            "panel_service",
            None,
        )

        if isinstance(
            existing_service,
            PanelService,
        ):
            self.panel_service = existing_service

        else:
            self.panel_service = PanelService()

            logger.warning(
                "Bot üzerinde merkezi PanelService bulunamadı. "
                "Panel Cog kendi PanelService instance'ını oluşturdu."
            )

    # ========================================================
    # PERMISSION
    # ========================================================

    @staticmethod
    def _is_admin(
        member: discord.Member,
    ) -> bool:

        return member.guild_permissions.administrator

    async def cog_check(
        self,
        ctx: commands.Context,
    ) -> bool:

        if ctx.guild is None:
            await ctx.send(
                "❌ Bu komut yalnızca sunucuda kullanılabilir."
            )
            return False

        if not isinstance(
            ctx.author,
            discord.Member,
        ):
            return False

        if not self._is_admin(ctx.author):
            await ctx.send(
                "❌ Bu paneli kullanmak için Administrator yetkisi gerekir."
            )
            return False

        return True

    # ========================================================
    # PANEL COMMAND
    # ========================================================

    @commands.hybrid_command(
        name="panel",
        description="PAG Security kontrol panelini açar.",
    )
    @commands.guild_only()
    @commands.has_permissions(
        administrator=True
    )
    async def panel(
        self,
        ctx: commands.Context,
    ) -> None:

        if ctx.guild is None:
            return

        try:

            embed = await self._build_panel_embed(
                ctx.guild.id
            )

            view = PanelView(
                self,
                ctx.guild.id,
            )

            await ctx.send(
                embed=embed,
                view=view,
            )

        except Exception as exc:

            logger.exception(
                "Panel command failed for guild %s: %s",
                ctx.guild.id,
                exc,
            )

            await ctx.send(
                "❌ Security paneli oluşturulurken beklenmeyen bir hata oluştu."
            )

    # ========================================================
    # PANEL EMBED
    # ========================================================

    async def _build_panel_embed(
        self,
        guild_id: int,
    ) -> discord.Embed:

        config = await self.panel_service.load(
            guild_id
        )

        embed = discord.Embed(
            title="🛡️ PAG SECURITY",
            description=(
                "Guild güvenlik kontrol paneli.\n\n"
                "Security Core **daima aktiftir** ve "
                "panel üzerinden kapatılamaz."
            ),
            color=discord.Color.dark_red(),
        )

        # ----------------------------------------------------
        # CORE
        # ----------------------------------------------------

        embed.add_field(
            name="🛡️ Security Core",
            value="🟢 **DAİMA AKTİF**",
            inline=False,
        )

        # ----------------------------------------------------
        # MODULES
        # ----------------------------------------------------

        module_lines: list[str] = []

        for key, name in MODULES.items():

            # PanelService config'i içinde bu modüller henüz
            # ayrı bir key olarak bulunmuyorsa detection/security
            # core'u üzerinden durum gösterilir.
            #
            # Yeni module config'i olmayan modüller varsayılan
            # olarak aktif kabul edilir.
            module_value = config.get(
                key,
                True,
            )

            if isinstance(
                module_value,
                dict,
            ):
                enabled = bool(
                    module_value.get(
                        "enabled",
                        True,
                    )
                )
            else:
                enabled = bool(
                    module_value
                )

            module_lines.append(
                f"{name}: {_bool_text(enabled)}"
            )

        embed.add_field(
            name="⚙️ Protection Modules",
            value="\n".join(module_lines),
            inline=False,
        )

        # ----------------------------------------------------
        # SECURITY MODE
        # ----------------------------------------------------

        smart_detection = bool(
            config.get(
                "security",
                {},
            ).get(
                "smart_detection",
                True,
            )
        )

        emergency_mode = bool(
            config.get(
                "security",
                {},
            ).get(
                "emergency_mode",
                True,
            )
        )

        embed.add_field(
            name="🧠 Smart Detection",
            value=_bool_text(
                smart_detection
            ),
            inline=True,
        )

        embed.add_field(
            name="🚨 Emergency Mode",
            value=_bool_text(
                emergency_mode
            ),
            inline=True,
        )

        # ----------------------------------------------------
        # DETECTION
        # ----------------------------------------------------

        detection = config.get(
            "detection",
            {},
        )

        window = _safe_int(
            detection.get(
                "window_seconds",
                15,
            ),
            15,
            1,
            3600,
        )

        embed.add_field(
            name="⏱️ Detection Window",
            value=f"`{window}` saniye",
            inline=True,
        )

        # ----------------------------------------------------
        # EMERGENCY
        # ----------------------------------------------------

        emergency = config.get(
            "emergency",
            {},
        )

        lockdown = bool(
            emergency.get(
                "lockdown",
                True,
            )
        )

        quarantine = bool(
            emergency.get(
                "quarantine",
                False,
            )
        )

        embed.add_field(
            name="🚨 Emergency Actions",
            value=(
                f"Lockdown: {_bool_text(lockdown)}\n"
                f"Quarantine: {_bool_text(quarantine)}"
            ),
            inline=False,
        )

        embed.set_footer(
            text="PAG Security • Administrator Panel"
        )

        return embed

    # ========================================================
    # STATUS
    # ========================================================

    async def _send_status(
        self,
        interaction: discord.Interaction,
        guild_id: int,
    ) -> None:

        try:

            embed = await self._build_panel_embed(
                guild_id
            )

            await interaction.response.edit_message(
                embed=embed,
                view=PanelView(
                    self,
                    guild_id,
                ),
            )

        except Exception as exc:

            logger.exception(
                "Panel status failed: %s",
                exc,
            )

            if interaction.response.is_done():
                await interaction.followup.send(
                    "❌ Durum alınamadı.",
                    ephemeral=True,
                )
            else:
                await interaction.response.send_message(
                    "❌ Durum alınamadı.",
                    ephemeral=True,
                )

    # ========================================================
    # MODULES
    # ========================================================

    async def _send_modules(
        self,
        interaction: discord.Interaction,
        guild_id: int,
    ) -> None:

        try:

            config = await self.panel_service.load(
                guild_id
            )

            lines: list[str] = []

            for key, name in MODULES.items():

                value = config.get(
                    key,
                    True,
                )

                if isinstance(
                    value,
                    dict,
                ):
                    enabled = bool(
                        value.get(
                            "enabled",
                            True,
                        )
                    )
                else:
                    enabled = bool(
                        value
                    )

                lines.append(
                    f"**{name}** → {_bool_text(enabled)}"
                )

            embed = discord.Embed(
                title="⚙️ Security Modules",
                description="\n".join(lines),
                color=discord.Color.blurple(),
            )

            embed.set_footer(
                text=(
                    "Security Core bu listeden bağımsızdır "
                    "ve daima aktiftir."
                )
            )

            await interaction.response.send_message(
                embed=embed,
                ephemeral=True,
            )

        except Exception as exc:

            logger.exception(
                "Module panel failed: %s",
                exc,
            )

            await self._safe_interaction_error(
                interaction,
                "❌ Modül bilgileri alınamadı.",
            )

    # ========================================================
    # THRESHOLDS
    # ========================================================

    async def _send_thresholds(
        self,
        interaction: discord.Interaction,
        guild_id: int,
    ) -> None:

        try:

            lines: list[str] = []

            for key, name in THRESHOLD_NAMES.items():

                value = await self.panel_service.get_threshold(
                    guild_id,
                    key,
                )

                lines.append(
                    f"**{name}** → `{value}`"
                )

            embed = discord.Embed(
                title="📊 Detection Thresholds",
                description="\n".join(lines),
                color=discord.Color.orange(),
            )

            await interaction.response.send_message(
                embed=embed,
                ephemeral=True,
            )

        except Exception as exc:

            logger.exception(
                "Threshold panel failed: %s",
                exc,
            )

            await self._safe_interaction_error(
                interaction,
                "❌ Threshold bilgileri alınamadı.",
            )

    # ========================================================
    # RISK LEVELS
    # ========================================================

    async def _send_risk_levels(
        self,
        interaction: discord.Interaction,
        guild_id: int,
    ) -> None:

        try:

            levels: list[str] = []

            for key, name in RISK_NAMES.items():

                value = await self.panel_service.get_risk_level(
                    guild_id,
                    key,
                )

                levels.append(
                    f"**{name}** → `{value}`"
                )

            embed = discord.Embed(
                title="⚠️ Risk Levels",
                description="\n".join(levels),
                color=discord.Color.gold(),
            )

            await interaction.response.send_message(
                embed=embed,
                ephemeral=True,
            )

        except Exception as exc:

            logger.exception(
                "Risk panel failed: %s",
                exc,
            )

            await self._safe_interaction_error(
                interaction,
                "❌ Risk bilgileri alınamadı.",
            )

    # ========================================================
    # REFRESH
    # ========================================================

    async def _send_panel(
        self,
        interaction: discord.Interaction,
        guild_id: int,
    ) -> None:

        try:

            self.panel_service.invalidate(
                guild_id
            )

            embed = await self._build_panel_embed(
                guild_id
            )

            await interaction.response.edit_message(
                embed=embed,
                view=PanelView(
                    self,
                    guild_id,
                ),
            )

        except Exception as exc:

            logger.exception(
                "Panel refresh failed: %s",
                exc,
            )

            await self._safe_interaction_error(
                interaction,
                "❌ Panel yenilenemedi.",
            )

    # ========================================================
    # MODULE SET
    # ========================================================

    async def set_module(
        self,
        guild_id: int,
        module: str,
        enabled: bool,
    ) -> bool:
        """
        Modül durumunu değiştirir.

        Security Core hiçbir şekilde bu fonksiyon üzerinden
        kapatılamaz.
        """

        key = _module_key_from_name(
            module
        )

        if key is None:
            return False

        return bool(
            await self.panel_service.set(
                guild_id,
                f"{key}.enabled",
                bool(enabled),
            )
        )

    # ========================================================
    # THRESHOLD SET
    # ========================================================

    async def set_threshold(
        self,
        guild_id: int,
        action: str,
        value: int,
    ) -> bool:
        """
        Detection threshold değiştirir.
        """

        action = action.strip().lower()

        if action not in THRESHOLD_NAMES:
            return False

        value = _safe_int(
            value,
            5,
            1,
            1000,
        )

        await self.panel_service.set(
            guild_id,
            f"detection.thresholds.{action}",
            value,
        )

        return True

    # ========================================================
    # RISK WEIGHT SET
    # ========================================================

    async def set_risk_weight(
        self,
        guild_id: int,
        action: str,
        value: int,
    ) -> bool:

        action = action.strip().lower()

        if action not in THRESHOLD_NAMES:
            return False

        value = _safe_int(
            value,
            10,
            0,
            1000,
        )

        await self.panel_service.set(
            guild_id,
            f"detection.risk_weights.{action}",
            value,
        )

        return True

    # ========================================================
    # WINDOW SET
    # ========================================================

    async def set_window(
        self,
        guild_id: int,
        seconds: int,
    ) -> bool:

        seconds = _safe_int(
            seconds,
            15,
            1,
            3600,
        )

        await self.panel_service.set(
            guild_id,
            "detection.window_seconds",
            seconds,
        )

        return True

    # ========================================================
    # RESET
    # ========================================================

    async def reset_config(
        self,
        guild_id: int,
    ) -> dict[str, Any]:

        return await self.panel_service.reset(
            guild_id
        )

    # ========================================================
    # ERROR HANDLER
    # ========================================================

    async def _safe_interaction_error(
        self,
        interaction: discord.Interaction,
        message: str,
    ) -> None:

        try:

            if interaction.response.is_done():

                await interaction.followup.send(
                    message,
                    ephemeral=True,
                )

            else:

                await interaction.response.send_message(
                    message,
                    ephemeral=True,
                )

        except (
            discord.HTTPException,
            discord.NotFound,
        ):
            pass

    # ========================================================
    # COMMAND ERROR
    # ========================================================

    @panel.error
    async def panel_error(
        self,
        ctx: commands.Context,
        error: commands.CommandError,
    ) -> None:

        if isinstance(
            error,
            commands.MissingPermissions,
        ):
            await ctx.send(
                "❌ Bu komut için Administrator yetkisi gerekir."
            )
            return

        if isinstance(
            error,
            commands.NoPrivateMessage,
        ):
            await ctx.send(
                "❌ Bu komut yalnızca sunucuda kullanılabilir."
            )
            return

        logger.exception(
            "Unhandled panel command error: %s",
            error,
        )

        try:
            await ctx.send(
                "❌ Panel işlemi sırasında beklenmeyen bir hata oluştu."
            )
        except discord.HTTPException:
            pass

    # ========================================================
    # COG LIFECYCLE
    # ========================================================

    async def cog_load(self) -> None:

        logger.info(
            "Panel Cog loaded."
        )

    async def cog_unload(self) -> None:

        logger.info(
            "Panel Cog unloaded."
        )


# ============================================================
# SETUP
# ============================================================


async def setup(
    bot: commands.Bot,
) -> None:

    await bot.add_cog(
        Panel(bot)
    )


__all__ = [
    "Panel",
    "PanelView",
    "setup",
] 