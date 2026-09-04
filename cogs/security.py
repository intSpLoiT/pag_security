# cogs/security.py

from __future__ import annotations

import logging
from typing import Optional

import discord
from discord.ext import commands

from services.security_service import SecurityService


logger = logging.getLogger("pag_security.cog.security")


class Security(commands.Cog):
    """
    PAG SECURITY BOT
    ----------------

    SecurityService için Discord event katmanı.

    Bu Cog:
        - Discord eventlerini dinler
        - SecurityService'e aktarır
        - SecurityService'in karar vermesine izin verir

    Bu Cog:
        - Kendi güvenlik kararlarını vermez
        - ModerationService'i doğrudan kullanmaz
        - Audit log işlemlerini kendisi yapmaz
        - Emergency işlemlerini kendisi yapmaz

    Böylece güvenlik mantığının merkezi SecurityService
    içerisinde kalır.
    """

    def __init__(
        self,
        bot: commands.Bot,
    ) -> None:

        self.bot = bot

        self._service: Optional[SecurityService] = None

        logger.info(
            "Security Cog initialized."
        )

    # ========================================================
    # SERVICE
    # ========================================================

    def _get_service(
        self,
    ) -> Optional[SecurityService]:
        """
        Bot üzerinden SecurityService'i güvenli şekilde alır.

        Service henüz yüklenmemişse None döner.
        """

        service = getattr(
            self.bot,
            "security_service",
            None,
        )

        if service is None:
            return None

        if not isinstance(
            service,
            SecurityService,
        ):
            logger.error(
                "Invalid security_service instance: %r",
                type(service),
            )
            return None

        return service

    # ========================================================
    # READY
    # ========================================================

    @commands.Cog.listener()
    async def on_ready(
        self,
    ) -> None:
        """
        Bot hazır olduğunda SecurityService bağlantısını
        kontrol eder.

        Bot'un kendi yaptığı güvenlik işlemlerinin yanlış
        alarm üretmesini önlemek için bot kullanıcısı bütün
        guild'lerde trusted olarak işaretlenir.
        """

        service = self._get_service()

        if service is None:
            logger.critical(
                "SecurityService is not available on bot."
            )
            return

        self._service = service

        bot_user = self.bot.user

        if bot_user is None:
            logger.warning(
                "Bot user is not available yet."
            )
            return

        for guild in self.bot.guilds:

            try:

                service.add_trusted_user(
                    guild.id,
                    bot_user.id,
                )

            except Exception:
                logger.exception(
                    "Failed to trust bot user | guild=%s",
                    guild.id,
                )

        logger.info(
            "Security Cog ready | guilds=%s",
            len(self.bot.guilds),
        )

    # ========================================================
    # MEMBER REMOVE
    # ========================================================

    @commands.Cog.listener()
    async def on_member_remove(
        self,
        member: discord.Member,
    ) -> None:
        """
        Kick / Ban tespiti.

        Ayrımı SecurityService yapar.
        """

        service = self._get_service()

        if service is None:
            return

        try:

            await service.on_member_remove(
                member,
            )

        except Exception:
            logger.exception(
                "Security member_remove handler failed | "
                "guild=%s member=%s",
                member.guild.id,
                member.id,
            )

    # ========================================================
    # MEMBER JOIN
    # ========================================================

    @commands.Cog.listener()
    async def on_member_join(
        self,
        member: discord.Member,
    ) -> None:
        """
        Yeni bot eklenmesini SecurityService'e aktarır.

        Normal kullanıcılar SecurityService tarafından
        gereksiz yere işlenmez.
        """

        if not member.bot:
            return

        service = self._get_service()

        if service is None:
            return

        try:

            await service.on_member_join(
                member,
            )

        except Exception:
            logger.exception(
                "Security member_join handler failed | "
                "guild=%s member=%s",
                member.guild.id,
                member.id,
            )

    # ========================================================
    # MEMBER UPDATE
    # ========================================================

    @commands.Cog.listener()
    async def on_member_update(
        self,
        before: discord.Member,
        after: discord.Member,
    ) -> None:
        """
        Member role değişikliklerini SecurityService'e aktarır.

        SecurityService zaten değişiklik olup olmadığını
        kontrol ediyor.
        """

        service = self._get_service()

        if service is None:
            return

        try:

            await service.on_member_update(
                before,
                after,
            )

        except Exception:
            logger.exception(
                "Security member_update handler failed | "
                "guild=%s member=%s",
                after.guild.id,
                after.id,
            )

    # ========================================================
    # CHANNEL CREATE
    # ========================================================

    @commands.Cog.listener()
    async def on_guild_channel_create(
        self,
        channel: discord.abc.GuildChannel,
    ) -> None:
        """
        Kanal oluşturma eventini SecurityService'e aktarır.
        """

        guild = getattr(
            channel,
            "guild",
            None,
        )

        if guild is None:
            return

        service = self._get_service()

        if service is None:
            return

        try:

            await service.on_channel_create(
                channel,
            )

        except Exception:
            logger.exception(
                "Security channel_create handler failed | "
                "guild=%s channel=%s",
                guild.id,
                channel.id,
            )

    # ========================================================
    # CHANNEL DELETE
    # ========================================================

    @commands.Cog.listener()
    async def on_guild_channel_delete(
        self,
        channel: discord.abc.GuildChannel,
    ) -> None:
        """
        Kanal silme eventini SecurityService'e aktarır.
        """

        guild = getattr(
            channel,
            "guild",
            None,
        )

        if guild is None:
            return

        service = self._get_service()

        if service is None:
            return

        try:

            await service.on_channel_delete(
                channel,
            )

        except Exception:
            logger.exception(
                "Security channel_delete handler failed | "
                "guild=%s channel=%s",
                guild.id,
                channel.id,
            )

    # ========================================================
    # ROLE CREATE
    # ========================================================

    @commands.Cog.listener()
    async def on_guild_role_create(
        self,
        role: discord.Role,
    ) -> None:
        """
        Rol oluşturma eventini SecurityService'e aktarır.
        """

        service = self._get_service()

        if service is None:
            return

        try:

            await service.on_role_create(
                role,
            )

        except Exception:
            logger.exception(
                "Security role_create handler failed | "
                "guild=%s role=%s",
                role.guild.id,
                role.id,
            )

    # ========================================================
    # ROLE DELETE
    # ========================================================

    @commands.Cog.listener()
    async def on_guild_role_delete(
        self,
        role: discord.Role,
    ) -> None:
        """
        Rol silme eventini SecurityService'e aktarır.
        """

        service = self._get_service()

        if service is None:
            return

        try:

            await service.on_role_delete(
                role,
            )

        except Exception:
            logger.exception(
                "Security role_delete handler failed | "
                "guild=%s role=%s",
                role.guild.id,
                role.id,
            )

    # ========================================================
    # ROLE UPDATE
    # ========================================================

    @commands.Cog.listener()
    async def on_guild_role_update(
        self,
        before: discord.Role,
        after: discord.Role,
    ) -> None:
        """
        Rol değişikliklerini SecurityService'e aktarır.

        Permission değişikliği olup olmadığını
        SecurityService belirler.
        """

        service = self._get_service()

        if service is None:
            return

        try:

            await service.on_role_update(
                before,
                after,
            )

        except Exception:
            logger.exception(
                "Security role_update handler failed | "
                "guild=%s role=%s",
                after.guild.id,
                after.id,
            )

    # ========================================================
    # WEBHOOK UPDATE
    # ========================================================

    @commands.Cog.listener()
    async def on_webhooks_update(
        self,
        channel: discord.abc.GuildChannel,
    ) -> None:
        """
        Discord webhook değişikliği eventini yakalar.

        Discord bu eventte doğrudan webhook ID ve işlemin
        create/delete olduğunu vermediği için burada
        yanlış actor/event üretmemek adına tahminde
        bulunulmaz.

        İleride anti-scam / dedicated webhook watcher
        tarafından detaylandırılabilir.
        """

        # Bilerek boş bırakılmıştır.
        #
        # SecurityService:
        #     process_webhook_create()
        #     process_webhook_delete()
        #
        # fonksiyonlarına sahip olsa da Discord event'i
        # hangi webhook'un oluşturulduğunu/silindiğini
        # burada doğrudan bildirmiyor.
        #
        # Yanlış alarm üretmemek için tahmin yapılmaz.
        return

    # ========================================================
    # GUILD REMOVE
    # ========================================================

    @commands.Cog.listener()
    async def on_guild_remove(
        self,
        guild: discord.Guild,
    ) -> None:
        """
        Bot guild'den ayrıldığında ilgili runtime
        security state'ini temizler.

        SecurityService'in reset_guild() fonksiyonu
        mevcut olduğu için doğrudan kullanılır.
        """

        service = self._get_service()

        if service is None:
            return

        try:

            service.reset_guild(
                guild.id,
            )

        except Exception:
            logger.exception(
                "Security guild state cleanup failed | "
                "guild=%s",
                guild.id,
            )

    # ========================================================
    # COG UNLOAD
    # ========================================================

    async def cog_unload(
        self,
    ) -> None:
        """
        Cog unload edildiğinde SecurityService'in state'ine
        dokunulmaz.

        Çünkü SecurityService bot seviyesinde yaşayan merkezi
        service'dir ve başka Cog'lar tarafından da kullanılabilir.
        """

        self._service = None

        logger.info(
            "Security Cog unloaded."
        )


# ============================================================
# SETUP
# ============================================================

async def setup(
    bot: commands.Bot,
) -> None:
    """
    Cog loader tarafından çağrılır.
    """

    await bot.add_cog(
        Security(bot),
    )