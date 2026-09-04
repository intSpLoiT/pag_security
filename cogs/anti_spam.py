from __future__ import annotations

# ============================================================
# PAG SECURITY BOT
# cogs/anti_spam.py
#
# Anti-Spam Protection
#
# Özellikler:
# ------------------------------------------------------------
# - Guild bazlı spam detection
# - PanelService uyumlu
# - Sliding window
# - Aynı mesaj tekrar kontrolü
# - Çok hızlı mesaj kontrolü
# - Whitelist desteği
# - Bot mesajlarını ignore etme
# - Güvenli otomatik mesaj silme
# - Kullanıcı bazlı cooldown
# - Memory cleanup
# - Exception isolation
# - Discord rate-limit uyumu
# - Config bozuk olsa bile crash olmama
#
# Python 3.11+
# discord.py 2.x
# ============================================================

from collections import defaultdict, deque
from time import monotonic
from typing import Any

import discord
from discord.ext import commands, tasks

from utils.logger import security_logger


# ============================================================
# CONSTANTS
# ============================================================

DEFAULT_WINDOW_SECONDS = 10

DEFAULT_MESSAGE_THRESHOLD = 7

DEFAULT_DUPLICATE_THRESHOLD = 4

DEFAULT_MINIMUM_INTERVAL = 0.35

MAX_TRACKED_USERS = 10000

CLEANUP_INTERVAL = 60.0

MAX_MESSAGE_HISTORY = 25

DELETE_BATCH_LIMIT = 20


# ============================================================
# USER STATE
# ============================================================


class SpamState:
    """
    Tek kullanıcının spam state'i.

    Her kullanıcı için:
        timestamps
        recent message hashes
        strikes
    tutulur.
    """

    __slots__ = (
        "timestamps",
        "recent_messages",
        "strikes",
        "last_action",
        "last_seen",
    )

    def __init__(self) -> None:

        self.timestamps: deque[float] = deque(
            maxlen=MAX_MESSAGE_HISTORY
        )

        self.recent_messages: deque[str] = deque(
            maxlen=MAX_MESSAGE_HISTORY
        )

        self.strikes = 0

        self.last_action = 0.0

        self.last_seen = monotonic()


# ============================================================
# COG
# ============================================================


class AntiSpam(commands.Cog):
    """
    PAG Security Anti-Spam sistemi.

    PanelService:
        bot.panel_service

    beklenir.

    PanelService bulunamazsa sistem crash olmaz.
    Güvenli default değerlerle çalışmaya devam eder.
    """

    def __init__(
        self,
        bot: commands.Bot,
    ) -> None:

        self.bot = bot

        # ----------------------------------------------------
        # guild_id
        #     user_id
        #         SpamState
        # ----------------------------------------------------

        self._states: dict[
            int,
            dict[int, SpamState],
        ] = defaultdict(dict)

        # ----------------------------------------------------
        # Silinmesi gereken mesajların rate-limit
        # baskısını azaltmak için basit lock.
        # ----------------------------------------------------

        self._delete_locks: dict[
            int,
            Any,
        ] = {}

        self._cleanup_loop.start()

        security_logger.info(
            "AntiSpam initialized."
        )

    # ========================================================
    # PANEL SERVICE
    # ========================================================

    @property
    def panel_service(self):
        """
        Bot üzerindeki PanelService'i döndürür.

        Farklı main.py mimarilerinde bot.panel_service
        bulunmazsa None döner.
        """

        return getattr(
            self.bot,
            "panel_service",
            None,
        )

    async def _get_config(
        self,
        guild_id: int,
    ) -> dict[str, Any]:
        """
        PanelService config'ini güvenli şekilde alır.

        Herhangi bir hata AntiSpam'i düşürmez.
        """

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
                "AntiSpam config read failed | "
                "guild=%s error=%s",
                guild_id,
                exc,
            )

        return {}

    async def _get_window(
        self,
        guild_id: int,
    ) -> float:
        """
        PanelService:
            detection.window_seconds

        değerini kullanır.
        """

        panel = self.panel_service

        if panel is None:
            return DEFAULT_WINDOW_SECONDS

        try:

            value = await panel.get(
                guild_id,
                "detection.window_seconds",
                DEFAULT_WINDOW_SECONDS,
            )

            value = float(value)

            return max(
                1.0,
                min(
                    value,
                    60.0,
                ),
            )

        except Exception:

            return DEFAULT_WINDOW_SECONDS

    async def _get_threshold(
        self,
        guild_id: int,
    ) -> int:
        """
        AntiSpam için threshold.

        PanelService'te özel spam threshold'u yoksa
        güvenli default kullanılır.

        İleride panel config'ine:

            detection.thresholds.spam

        eklenirse otomatik olarak onu kullanır.
        """

        panel = self.panel_service

        if panel is None:
            return DEFAULT_MESSAGE_THRESHOLD

        try:

            value = await panel.get(
                guild_id,
                "detection.thresholds.spam",
                DEFAULT_MESSAGE_THRESHOLD,
            )

            value = int(value)

            return max(
                3,
                min(
                    value,
                    100,
                ),
            )

        except Exception:

            return DEFAULT_MESSAGE_THRESHOLD

    async def _is_enabled(
        self,
        guild_id: int,
    ) -> bool:
        """
        Security genel olarak aktif mi?
        """

        panel = self.panel_service

        if panel is None:
            return True

        try:

            return bool(
                await panel.is_enabled(
                    guild_id
                )
            )

        except Exception:

            return True

    async def _smart_detection_enabled(
        self,
        guild_id: int,
    ) -> bool:
        """
        Smart detection aktif mi?
        """

        panel = self.panel_service

        if panel is None:
            return True

        try:

            return bool(
                await panel.smart_detection_enabled(
                    guild_id
                )
            )

        except Exception:

            return True

    # ========================================================
    # WHITELIST
    # ========================================================

    async def _is_whitelisted(
        self,
        message: discord.Message,
    ) -> bool:
        """
        User veya role whitelist kontrolü.
        """

        if message.guild is None:
            return True

        panel = self.panel_service

        if panel is None:
            return False

        guild_id = message.guild.id

        # ----------------------------------------------------
        # USER
        # ----------------------------------------------------

        try:

            if await panel.is_whitelisted_user(
                guild_id,
                message.author.id,
            ):
                return True

        except Exception as exc:

            security_logger.debug(
                "AntiSpam user whitelist check failed | "
                "guild=%s user=%s error=%s",
                guild_id,
                message.author.id,
                exc,
            )

        # ----------------------------------------------------
        # ROLE
        # ----------------------------------------------------

        member = message.author

        if isinstance(
            member,
            discord.Member,
        ):

            for role in member.roles:

                if role.is_default():
                    continue

                try:

                    if await panel.is_whitelisted_role(
                        guild_id,
                        role.id,
                    ):
                        return True

                except Exception:

                    continue

        return False

    # ========================================================
    # STATE
    # ========================================================

    def _get_state(
        self,
        guild_id: int,
        user_id: int,
    ) -> SpamState:
        """
        Kullanıcının state'ini oluşturur/alır.
        """

        guild_states = self._states[
            guild_id
        ]

        state = guild_states.get(
            user_id
        )

        if state is None:

            # Çok fazla kullanıcı tutulmasını engelle.
            if len(guild_states) >= MAX_TRACKED_USERS:

                self._trim_guild_states(
                    guild_id
                )

            state = SpamState()

            guild_states[
                user_id
            ] = state

        state.last_seen = monotonic()

        return state

    def _trim_guild_states(
        self,
        guild_id: int,
    ) -> None:
        """
        En eski state'leri temizler.
        """

        guild_states = self._states.get(
            guild_id
        )

        if not guild_states:
            return

        if len(guild_states) <= MAX_TRACKED_USERS:
            return

        ordered = sorted(
            guild_states.items(),
            key=lambda item: item[1].last_seen,
        )

        remove_count = max(
            1,
            len(guild_states)
            - MAX_TRACKED_USERS
            + 100,
        )

        for user_id, _ in ordered[
            :remove_count
        ]:

            guild_states.pop(
                user_id,
                None,
            )

    # ========================================================
    # MESSAGE SIGNATURE
    # ========================================================

    @staticmethod
    def _message_signature(
        message: discord.Message,
    ) -> str:
        """
        Mesajın duplicate detection için normalize edilmiş
        imzasını oluşturur.

        İçeriğin tamamını uzun süre bellekte tutmaz.
        """

        content = (
            message.content
            or ""
        ).strip().lower()

        # Çok uzun mesajları sınırlıyoruz.
        content = content[:1000]

        return content

    # ========================================================
    # DETECTION
    # ========================================================

    async def _check_spam(
        self,
        message: discord.Message,
    ) -> tuple[
        bool,
        str,
        int,
    ]:
        """
        Spam detection.

        Dönen değer:

            detected
            reason
            severity
        """

        guild = message.guild

        if guild is None:
            return False, "", 0

        guild_id = guild.id

        user_id = message.author.id

        state = self._get_state(
            guild_id,
            user_id,
        )

        now = monotonic()

        window = await self._get_window(
            guild_id
        )

        threshold = await self._get_threshold(
            guild_id
        )

        # ----------------------------------------------------
        # Eski timestamp'leri temizle.
        # ----------------------------------------------------

        while (
            state.timestamps
            and now - state.timestamps[0]
            > window
        ):
            state.timestamps.popleft()

        state.timestamps.append(
            now
        )

        # ----------------------------------------------------
        # Mesaj signature
        # ----------------------------------------------------

        signature = self._message_signature(
            message
        )

        duplicate_count = 0

        if signature:

            duplicate_count = sum(
                1
                for item
                in state.recent_messages
                if item == signature
            )

            state.recent_messages.append(
                signature
            )

        # ----------------------------------------------------
        # RATE SPAM
        # ----------------------------------------------------

        message_count = len(
            state.timestamps
        )

        if message_count >= threshold:

            state.strikes += 1

            severity = min(
                3,
                1
                + (
                    message_count
                    // max(
                        threshold,
                        1,
                    )
                ),
            )

            return (
                True,
                "message_rate",
                severity,
            )

        # ----------------------------------------------------
        # DUPLICATE SPAM
        # ----------------------------------------------------

        if (
            duplicate_count
            >= DEFAULT_DUPLICATE_THRESHOLD - 1
        ):

            state.strikes += 1

            return (
                True,
                "duplicate_message",
                2,
            )

        # ----------------------------------------------------
        # BURST DETECTION
        #
        # 0.35 saniyeden daha kısa aralıklarla
        # arka arkaya mesaj gönderme.
        # ----------------------------------------------------

        if len(state.timestamps) >= 3:

            timestamps = list(
                state.timestamps
            )

            recent = timestamps[
                -3:
            ]

            if (
                len(recent) == 3
                and (
                    recent[-1]
                    - recent[0]
                )
                <= DEFAULT_MINIMUM_INTERVAL
            ):

                state.strikes += 1

                return (
                    True,
                    "message_burst",
                    2,
                )

        return False, "", 0

    # ========================================================
    # ACTION
    # ========================================================

    async def _handle_detection(
        self,
        message: discord.Message,
        reason: str,
        severity: int,
    ) -> None:
        """
        Spam tespit edildiğinde güvenli aksiyon.

        AntiSpam burada otomatik ban/kick uygulamaz.
        PanelService'teki:
            actions.auto_ban
            actions.auto_kick

        ayarları AntiSpam tarafından otomatik kullanılmaz.

        Böylece AntiSpam'in görevi spam mesajlarını
        sınırlamakla kalır.
        """

        guild = message.guild

        if guild is None:
            return

        guild_id = guild.id

        state = self._states.get(
            guild_id,
            {},
        ).get(
            message.author.id
        )

        if state is None:
            return

        now = monotonic()

        # ----------------------------------------------------
        # Aynı kullanıcı için çok sık action uygulama.
        # ----------------------------------------------------

        if (
            now - state.last_action
            < 2.0
        ):
            return

        state.last_action = now

        # ----------------------------------------------------
        # Botun mesaj silme yetkisi yoksa crash yok.
        # ----------------------------------------------------

        channel = message.channel

        permissions = getattr(
            channel,
            "permissions_for",
            None,
        )

        if permissions is not None:

            try:

                bot_member = guild.me

                if bot_member is None:
                    return

                channel_permissions = permissions(
                    bot_member
                )

                if not channel_permissions.manage_messages:

                    security_logger.warning(
                        "AntiSpam missing Manage Messages | "
                        "guild=%s channel=%s",
                        guild_id,
                        getattr(
                            channel,
                            "id",
                            0,
                        ),
                    )

                    return

            except Exception as exc:

                security_logger.debug(
                    "AntiSpam permission check failed | "
                    "guild=%s error=%s",
                    guild_id,
                    exc,
                )

        # ----------------------------------------------------
        # Mesajı sil.
        # ----------------------------------------------------

        try:

            await message.delete(
                reason=(
                    f"PAG Security AntiSpam: "
                    f"{reason}"
                )
            )

            security_logger.info(
                "AntiSpam action | "
                "guild=%s user=%s "
                "channel=%s reason=%s severity=%s",
                guild_id,
                message.author.id,
                getattr(
                    channel,
                    "id",
                    0,
                ),
                reason,
                severity,
            )

        except discord.NotFound:

            # Mesaj zaten silinmiş.
            return

        except discord.Forbidden:

            security_logger.warning(
                "AntiSpam forbidden | "
                "guild=%s channel=%s",
                guild_id,
                getattr(
                    channel,
                    "id",
                    0,
                ),
            )

        except discord.HTTPException as exc:

            security_logger.warning(
                "AntiSpam delete failed | "
                "guild=%s error=%s",
                guild_id,
                exc,
            )

        except Exception as exc:

            security_logger.exception(
                "AntiSpam unexpected error | "
                "guild=%s error=%s",
                guild_id,
                exc,
            )

    # ========================================================
    # MESSAGE LISTENER
    # ========================================================

    @commands.Cog.listener()
    async def on_message(
        self,
        message: discord.Message,
    ) -> None:
        """
        Her mesajı kontrol eder.

        ÖNEMLİ:
        Listener hiçbir zaman exception'ı dışarı
        bırakmaz.
        """

        try:

            # ------------------------------------------------
            # DM
            # ------------------------------------------------

            if message.guild is None:
                return

            # ------------------------------------------------
            # Botlar
            # ------------------------------------------------

            if message.author.bot:
                return

            # ------------------------------------------------
            # Security disabled
            # ------------------------------------------------

            if not await self._is_enabled(
                message.guild.id
            ):
                return

            # ------------------------------------------------
            # Whitelist
            # ------------------------------------------------

            if await self._is_whitelisted(
                message
            ):
                return

            # ------------------------------------------------
            # Smart detection
            # ------------------------------------------------

            if not await self._smart_detection_enabled(
                message.guild.id
            ):
                return

            # ------------------------------------------------
            # Detection
            # ------------------------------------------------

            detected, reason, severity = (
                await self._check_spam(
                    message
                )
            )

            if not detected:
                return

            # ------------------------------------------------
            # Action
            # ------------------------------------------------

            await self._handle_detection(
                message,
                reason,
                severity,
            )

        except Exception as exc:

            # AntiSpam hiçbir şartta botu düşürmemeli.
            security_logger.exception(
                "AntiSpam listener failure | "
                "guild=%s error=%s",
                getattr(
                    getattr(
                        message,
                        "guild",
                        None,
                    ),
                    "id",
                    None,
                ),
                exc,
            )

    # ========================================================
    # CLEANUP
    # ========================================================

    @tasks.loop(
        seconds=CLEANUP_INTERVAL
    )
    async def _cleanup_loop(
        self,
    ) -> None:
        """
        Eski user state'lerini temizler.
        """

        try:

            now = monotonic()

            removed = 0

            for guild_id in list(
                self._states.keys()
            ):

                guild_states = self._states.get(
                    guild_id
                )

                if not guild_states:
                    self._states.pop(
                        guild_id,
                        None,
                    )
                    continue

                for user_id in list(
                    guild_states.keys()
                ):

                    state = guild_states.get(
                        user_id
                    )

                    if state is None:
                        continue

                    if (
                        now - state.last_seen
                        > 300.0
                    ):

                        guild_states.pop(
                            user_id,
                            None,
                        )

                        removed += 1

                if not guild_states:

                    self._states.pop(
                        guild_id,
                        None,
                    )

            if removed:

                security_logger.debug(
                    "AntiSpam cleanup | "
                    "removed=%s",
                    removed,
                )

        except Exception as exc:

            security_logger.exception(
                "AntiSpam cleanup failed | "
                "error=%s",
                exc,
            )

    @_cleanup_loop.before_loop
    async def _before_cleanup(
        self,
    ) -> None:

        try:

            await self.bot.wait_until_ready()

        except Exception:
            return

    # ========================================================
    # COG UNLOAD
    # ========================================================

    def cog_unload(
        self,
    ) -> None:
        """
        Cog unload edildiğinde background task'ı kapatır.
        """

        if not self._cleanup_loop.is_being_cancelled():

            self._cleanup_loop.cancel()

        self._states.clear()

        self._delete_locks.clear()

        security_logger.info(
            "AntiSpam unloaded."
        )


# ============================================================
# SETUP
# ============================================================


async def setup(
    bot: commands.Bot,
) -> None:
    """
    discord.py extension entry point.
    """

    await bot.add_cog(
        AntiSpam(bot)
    )


# ============================================================
# EXPORTS
# ============================================================

__all__ = [
    "AntiSpam",
    "setup",
]