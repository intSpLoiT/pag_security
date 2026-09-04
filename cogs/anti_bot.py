# cogs/anti_bot.py

from __future__ import annotations

import discord
from discord.ext import commands

from utils.logger import security_logger


# ============================================================
# PAG SECURITY BOT
# ANTI BOT
#
# Sorumluluk:
# ------------------------------------------------------------
# - Yeni eklenen botları tespit eder
# - PanelService üzerinden Security ayarlarını okur
# - Whitelist kontrolü yapar
# - Audit Log üzerinden botu kimin eklediğini bulur
# - Olayı Security katmanına aktarılabilecek şekilde üretir
#
# ÖNEMLİ:
# ------------------------------------------------------------
# Bu Cog kendi başına kick / ban uygulamaz.
# Kararı SecurityService / Emergency sistemi verir.
# ============================================================


class AntiBot(commands.Cog):

    def __init__(
        self,
        bot: commands.Bot,
    ) -> None:

        self.bot = bot

        security_logger.info(
            "AntiBot initialized."
        )

    # ========================================================
    # SERVICES
    # ========================================================

    @property
    def panel_service(self):
        return getattr(
            self.bot,
            "panel_service",
            None,
        )

    @property
    def security_service(self):
        return getattr(
            self.bot,
            "security_service",
            None,
        )

    # ========================================================
    # CONFIG
    # ========================================================

    async def _get_config(
        self,
        guild_id: int,
    ) -> dict:

        panel = self.panel_service

        if panel is None:
            return {}

        try:

            config = await panel.get(
                guild_id
            )

            if isinstance(
                config,
                dict,
            ):
                return config

        except Exception as exc:

            security_logger.warning(
                "AntiBot config read failed | "
                "guild=%s error=%s",
                guild_id,
                exc,
            )

        return {}

    async def _is_enabled(
        self,
        guild_id: int,
    ) -> bool:

        panel = self.panel_service

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
                "AntiBot enabled check failed | "
                "guild=%s error=%s",
                guild_id,
                exc,
            )

            return True

    # ========================================================
    # WHITELIST
    # ========================================================

    async def _is_whitelisted(
        self,
        guild: discord.Guild,
        member: discord.Member,
    ) -> bool:

        panel = self.panel_service

        if panel is None:
            return False

        # ----------------------------------------------------
        # User whitelist
        # ----------------------------------------------------

        try:

            if await panel.is_whitelisted_user(
                guild.id,
                member.id,
            ):
                return True

        except Exception as exc:

            security_logger.debug(
                "AntiBot user whitelist check failed | "
                "guild=%s user=%s error=%s",
                guild.id,
                member.id,
                exc,
            )

        # ----------------------------------------------------
        # Role whitelist
        # ----------------------------------------------------

        for role in member.roles:

            if role.is_default():
                continue

            try:

                if await panel.is_whitelisted_role(
                    guild.id,
                    role.id,
                ):
                    return True

            except Exception:

                continue

        return False

    # ========================================================
    # AUDIT LOG
    # ========================================================

    async def _find_adder(
        self,
        guild: discord.Guild,
        bot_member: discord.Member,
    ) -> discord.Member | None:

        try:

            async for entry in guild.audit_logs(
                limit=10,
                action=discord.AuditLogAction.bot_add,
            ):

                target = entry.target

                if target is None:
                    continue

                if getattr(
                    target,
                    "id",
                    None,
                ) != bot_member.id:
                    continue

                user = entry.user

                if user is None:
                    return None

                return guild.get_member(
                    user.id
                )

        except discord.Forbidden:

            security_logger.warning(
                "AntiBot cannot access audit logs | "
                "guild=%s",
                guild.id,
            )

        except discord.HTTPException as exc:

            security_logger.warning(
                "AntiBot audit log request failed | "
                "guild=%s error=%s",
                guild.id,
                exc,
            )

        except Exception as exc:

            security_logger.exception(
                "AntiBot audit log failure | "
                "guild=%s error=%s",
                guild.id,
                exc,
            )

        return None

    # ========================================================
    # SECURITY EVENT
    # ========================================================

    async def _dispatch_security_event(
        self,
        *,
        guild: discord.Guild,
        bot_member: discord.Member,
        adder: discord.Member | None,
        risk_weight: int,
        threshold: int,
        whitelisted: bool,
    ) -> None:
        """
        SecurityService varsa olayı ona aktarır.

        SecurityService API'si mevcut değilse hiçbir şey
        çağrılmaz. Böylece Cog startup'ta crash olmaz.
        """

        service = self.security_service

        event = {
            "type": "bot_add",
            "guild_id": guild.id,
            "target_id": bot_member.id,
            "actor_id": (
                adder.id
                if adder is not None
                else None
            ),
            "risk_weight": risk_weight,
            "threshold": threshold,
            "whitelisted": whitelisted,
        }

        if service is None:

            security_logger.info(
                "AntiBot event detected | "
                "guild=%s bot=%s actor=%s "
                "risk=%s threshold=%s whitelisted=%s",
                guild.id,
                bot_member.id,
                getattr(
                    adder,
                    "id",
                    None,
                ),
                risk_weight,
                threshold,
                whitelisted,
            )

            return

        # ----------------------------------------------------
        # SecurityService üzerinde mevcut event API'sini
        # güvenli şekilde keşfet.
        # ----------------------------------------------------

        handler = getattr(
            service,
            "handle_security_event",
            None,
        )

        if callable(handler):

            try:

                result = handler(
                    event
                )

                if hasattr(
                    result,
                    "__await__",
                ):
                    await result

                return

            except Exception as exc:

                security_logger.exception(
                    "AntiBot SecurityService event "
                    "handling failed | "
                    "guild=%s error=%s",
                    guild.id,
                    exc,
                )

                return

        security_logger.info(
            "AntiBot event generated | "
            "guild=%s bot=%s actor=%s",
            guild.id,
            bot_member.id,
            getattr(
                adder,
                "id",
                None,
            ),
        )

    # ========================================================
    # BOT ADD
    # ========================================================

    @commands.Cog.listener()
    async def on_member_join(
        self,
        member: discord.Member,
    ) -> None:

        try:

            # Sadece botlar.
            if not member.bot:
                return

            guild = member.guild

            # Security kapalıysa hiçbir işlem yapma.
            if not await self._is_enabled(
                guild.id
            ):
                return

            # ------------------------------------------------
            # Panel config
            # ------------------------------------------------

            panel = self.panel_service

            threshold = 2
            risk_weight = 40

            if panel is not None:

                try:

                    threshold = await panel.get_threshold(
                        guild.id,
                        "bot_add",
                    )

                except Exception:

                    threshold = 2

                try:

                    risk_weight = await panel.get_risk_weight(
                        guild.id,
                        "bot_add",
                    )

                except Exception:

                    risk_weight = 40

            # ------------------------------------------------
            # Bot whitelist
            # ------------------------------------------------

            bot_whitelisted = (
                await self._is_whitelisted(
                    guild,
                    member,
                )
            )

            # ------------------------------------------------
            # Audit log
            # ------------------------------------------------

            adder = await self._find_adder(
                guild,
                member,
            )

            actor_whitelisted = False

            if adder is not None:

                actor_whitelisted = (
                    await self._is_whitelisted(
                        guild,
                        adder,
                    )
                )

            whitelisted = (
                bot_whitelisted
                or actor_whitelisted
            )

            # ------------------------------------------------
            # Whitelist edilmiş bot eklemelerini
            # risk engine'e normal olay olarak bildirmiyoruz.
            # ------------------------------------------------

            if whitelisted:

                security_logger.info(
                    "AntiBot whitelisted bot addition | "
                    "guild=%s bot=%s actor=%s",
                    guild.id,
                    member.id,
                    getattr(
                        adder,
                        "id",
                        None,
                    ),
                )

                return

            # ------------------------------------------------
            # Security event
            # ------------------------------------------------

            await self._dispatch_security_event(
                guild=guild,
                bot_member=member,
                adder=adder,
                risk_weight=risk_weight,
                threshold=threshold,
                whitelisted=False,
            )

        except Exception as exc:

            # Listener hiçbir zaman botu düşürmemeli.
            security_logger.exception(
                "AntiBot listener failure | "
                "guild=%s bot=%s error=%s",
                getattr(
                    getattr(
                        member,
                        "guild",
                        None,
                    ),
                    "id",
                    None,
                ),
                getattr(
                    member,
                    "id",
                    None,
                ),
                exc,
            )

    # ========================================================
    # UNLOAD
    # ========================================================

    def cog_unload(
        self,
    ) -> None:

        security_logger.info(
            "AntiBot unloaded."
        )


# ============================================================
# SETUP
# ============================================================

async def setup(
    bot: commands.Bot,
) -> None:

    await bot.add_cog(
        AntiBot(bot)
    )


__all__ = [
    "AntiBot",
    "setup",
]