# cogs/anti_raid.py

from __future__ import annotations

import asyncio
import time
from collections import defaultdict, deque
from dataclasses import dataclass
from typing import Optional

import discord
from discord.ext import commands

from services.panel_service import PanelService
from utils.logger import security_logger


# ============================================================
# CONSTANTS
# ============================================================

DEFAULT_WINDOW_SECONDS = 15
DEFAULT_JOIN_THRESHOLD = 8
DEFAULT_BOT_THRESHOLD = 2

MAX_TRACKED_GUILDS = 10_000
MAX_TRACKED_USERS_PER_GUILD = 5_000

CLEANUP_INTERVAL = 60


# ============================================================
# DATA
# ============================================================


@dataclass(slots=True)
class RaidEvent:
    user_id: int
    timestamp: float


# ============================================================
# COG
# ============================================================


class AntiRaid(commands.Cog):
    """
    PAG Security - Anti Raid

    Amaç:
        Kısa zaman içerisinde olağan dışı miktarda
        kullanıcı girişini tespit etmek.

    PanelService üzerinden:
        detection.window_seconds
        whitelist.users
        actions.auto_ban
        actions.auto_kick
        security.enabled
        security.emergency_mode

    okunur.

    AntiRaid tek başına güvenlik botunu kapatmaz veya
    başka Cog'ların çalışmasını engellemez.
    """

    def __init__(
        self,
        bot: commands.Bot,
    ) -> None:

        self.bot = bot

        # ----------------------------------------------------
        # PanelService
        # ----------------------------------------------------

        panel_service = getattr(
            bot,
            "panel_service",
            None,
        )

        if panel_service is None:

            panel_service = PanelService()

            try:
                setattr(
                    bot,
                    "panel_service",
                    panel_service,
                )
            except Exception:
                pass

        self.panel: PanelService = panel_service

        # ----------------------------------------------------
        # Runtime tracking
        # ----------------------------------------------------

        self._joins: dict[
            int,
            deque[float],
        ] = defaultdict(deque)

        self._bot_adds: dict[
            int,
            deque[float],
        ] = defaultdict(deque)

        self._alerted_until: dict[
            int,
            float,
        ] = {}

        self._locks: dict[
            int,
            asyncio.Lock,
        ] = {}

        self._cleanup_task: Optional[
            asyncio.Task
        ] = None

        # ----------------------------------------------------
        # Statistics
        # ----------------------------------------------------

        self.total_joins_seen = 0
        self.total_raid_detections = 0
        self.total_bot_detections = 0
        self.total_actions = 0
        self.total_errors = 0

        # ----------------------------------------------------
        # Start cleanup task only when loop is ready.
        # ----------------------------------------------------

        self._cleanup_task = self.bot.loop.create_task(
            self._cleanup_loop()
        )

        security_logger.info(
            "AntiRaid initialized."
        )

    # ========================================================
    # LOCK
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

            self._locks[guild_id] = lock

        return lock

    # ========================================================
    # CONFIG
    # ========================================================

    async def _get_window(
        self,
        guild_id: int,
    ) -> int:

        value = await self.panel.get(
            guild_id,
            "detection.window_seconds",
            DEFAULT_WINDOW_SECONDS,
        )

        try:

            return max(
                1,
                min(
                    int(value),
                    3600,
                ),
            )

        except (
            TypeError,
            ValueError,
        ):

            return DEFAULT_WINDOW_SECONDS

    async def _get_join_threshold(
        self,
        guild_id: int,
    ) -> int:

        value = await self.panel.get(
            guild_id,
            "detection.thresholds.join",
            DEFAULT_JOIN_THRESHOLD,
        )

        try:

            return max(
                1,
                min(
                    int(value),
                    1000,
                ),
            )

        except (
            TypeError,
            ValueError,
        ):

            return DEFAULT_JOIN_THRESHOLD

    async def _get_bot_threshold(
        self,
        guild_id: int,
    ) -> int:

        value = await self.panel.get(
            guild_id,
            "detection.thresholds.bot_add",
            DEFAULT_BOT_THRESHOLD,
        )

        try:

            return max(
                1,
                min(
                    int(value),
                    1000,
                ),
            )

        except (
            TypeError,
            ValueError,
        ):

            return DEFAULT_BOT_THRESHOLD

    # ========================================================
    # ENABLE CHECK
    # ========================================================

    async def _is_enabled(
        self,
        guild_id: int,
    ) -> bool:

        try:

            return await self.panel.is_enabled(
                guild_id
            )

        except Exception as exc:

            self.total_errors += 1

            security_logger.error(
                "AntiRaid config check failed | "
                "guild=%s error=%s",
                guild_id,
                exc,
            )

            # Config okunamıyorsa güvenlik Cog'u
            # çalışmaya devam etsin.
            return True

    # ========================================================
    # WHITELIST
    # ========================================================

    async def _is_whitelisted(
        self,
        guild_id: int,
        user_id: int,
    ) -> bool:

        try:

            return await self.panel.is_whitelisted_user(
                guild_id,
                user_id,
            )

        except Exception as exc:

            self.total_errors += 1

            security_logger.error(
                "AntiRaid whitelist check failed | "
                "guild=%s user=%s error=%s",
                guild_id,
                user_id,
                exc,
            )

            return False

    # ========================================================
    # JOIN TRACKING
    # ========================================================

    def _record_join(
        self,
        guild_id: int,
        timestamp: float,
    ) -> None:

        events = self._joins[
            guild_id
        ]

        events.append(
            timestamp
        )

        # Belleğin sınırsız büyümesini engelle.
        if len(events) > MAX_TRACKED_USERS_PER_GUILD:

            while len(events) > (
                MAX_TRACKED_USERS_PER_GUILD
            ):

                events.popleft()

    # ========================================================
    # CLEAN OLD EVENTS
    # ========================================================

    @staticmethod
    def _cleanup_deque(
        events: deque[float],
        now: float,
        window: float,
    ) -> None:

        cutoff = now - window

        while events:

            if events[0] >= cutoff:
                break

            events.popleft()

    # ========================================================
    # RAID DETECTION
    # ========================================================

    async def _check_raid(
        self,
        guild: discord.Guild,
    ) -> None:

        guild_id = guild.id

        window = await self._get_window(
            guild_id
        )

        threshold = await self._get_join_threshold(
            guild_id
        )

        now = time.monotonic()

        events = self._joins.get(
            guild_id
        )

        if not events:
            return

        self._cleanup_deque(
            events,
            now,
            window,
        )

        count = len(events)

        if count < threshold:
            return

        # ----------------------------------------------------
        # Alert cooldown
        # ----------------------------------------------------

        cooldown_until = self._alerted_until.get(
            guild_id,
            0.0,
        )

        if now < cooldown_until:
            return

        self._alerted_until[
            guild_id
        ] = now + window

        self.total_raid_detections += 1

        security_logger.warning(
            "RAID DETECTED | "
            "guild=%s name=%s joins=%s window=%ss threshold=%s",
            guild_id,
            guild.name,
            count,
            window,
            threshold,
        )

        await self._handle_raid(
            guild,
            count,
            window,
            threshold,
        )

    # ========================================================
    # RAID RESPONSE
    # ========================================================

    async def _handle_raid(
        self,
        guild: discord.Guild,
        count: int,
        window: int,
        threshold: int,
    ) -> None:

        try:

            emergency = (
                await self.panel.emergency_enabled(
                    guild.id
                )
            )

        except Exception:

            emergency = True

        # ----------------------------------------------------
        # Emergency mode
        # ----------------------------------------------------

        if emergency:

            security_logger.warning(
                "AntiRaid emergency mode triggered | "
                "guild=%s",
                guild.id,
            )

        # ----------------------------------------------------
        # Auto kick
        # ----------------------------------------------------

        try:

            auto_kick = bool(
                await self.panel.get(
                    guild.id,
                    "actions.auto_kick",
                    False,
                )
            )

        except Exception:

            auto_kick = False

        if auto_kick:

            await self._execute_auto_kick(
                guild,
                window,
            )

    # ========================================================
    # AUTO KICK
    # ========================================================

    async def _execute_auto_kick(
        self,
        guild: discord.Guild,
        window: int,
    ) -> None:

        """
        Raid sırasında son katılan kullanıcılar arasından
        whitelist dışındakileri değerlendirir.

        Discord permission / hierarchy hataları tek tek
        izole edilir.
        """

        events = self._joins.get(
            guild.id
        )

        if not events:
            return

        now = time.monotonic()

        cutoff = now - window

        kicked = 0

        # ----------------------------------------------------
        # Guild member cache kullanılır.
        # Discord API'ye gereksiz request gönderilmez.
        # ----------------------------------------------------

        for member in list(
            guild.members
        ):

            if member.bot:
                continue

            joined_at = member.joined_at

            if joined_at is None:
                continue

            joined_timestamp = (
                joined_at.timestamp()
            )

            current_timestamp = (
                time.time()
            )

            if (
                current_timestamp
                - joined_timestamp
                > window
            ):
                continue

            if await self._is_whitelisted(
                guild.id,
                member.id,
            ):
                continue

            try:

                if not member.kickable:
                    continue

                await member.kick(
                    reason=(
                        "PAG Security Anti-Raid"
                    )
                )

                kicked += 1
                self.total_actions += 1

            except (
                discord.Forbidden,
                discord.HTTPException,
                discord.NotFound,
            ) as exc:

                self.total_errors += 1

                security_logger.warning(
                    "AntiRaid kick failed | "
                    "guild=%s user=%s error=%s",
                    guild.id,
                    member.id,
                    exc,
                )

            # Rate-limit baskısını azalt.
            if kicked >= 25:
                break

        if kicked:

            security_logger.warning(
                "AntiRaid action completed | "
                "guild=%s kicked=%s",
                guild.id,
                kicked,
            )

    # ========================================================
    # MEMBER JOIN
    # ========================================================

    @commands.Cog.listener()
    async def on_member_join(
        self,
        member: discord.Member,
    ) -> None:

        guild = member.guild

        if guild is None:
            return

        guild_id = guild.id

        if not await self._is_enabled(
            guild_id
        ):
            return

        # ----------------------------------------------------
        # Whitelist
        # ----------------------------------------------------

        if await self._is_whitelisted(
            guild_id,
            member.id,
        ):
            return

        now = time.monotonic()

        lock = self._get_lock(
            guild_id
        )

        async with lock:

            self.total_joins_seen += 1

            self._record_join(
                guild_id,
                now,
            )

            try:

                await self._check_raid(
                    guild
                )

            except Exception as exc:

                self.total_errors += 1

                security_logger.exception(
                    "AntiRaid join processing failed | "
                    "guild=%s user=%s error=%s",
                    guild_id,
                    member.id,
                    exc,
                )

    # ========================================================
    # BOT ADD
    # ========================================================

    @commands.Cog.listener()
    async def on_member_join_bot_check(
        self,
        member: discord.Member,
    ) -> None:
        """
        discord.py aynı on_member_join event'i içinde çalışır.

        Bot join'lerini ayrı takip eder.
        """

        if not member.bot:
            return

        guild = member.guild

        if guild is None:
            return

        guild_id = guild.id

        if not await self._is_enabled(
            guild_id
        ):
            return

        if await self._is_whitelisted(
            guild_id,
            member.id,
        ):
            return

        now = time.monotonic()

        events = self._bot_adds[
            guild_id
        ]

        events.append(
            now
        )

        if len(events) > MAX_TRACKED_USERS_PER_GUILD:

            while len(events) > (
                MAX_TRACKED_USERS_PER_GUILD
            ):

                events.popleft()

        window = await self._get_window(
            guild_id
        )

        threshold = await self._get_bot_threshold(
            guild_id
        )

        self._cleanup_deque(
            events,
            now,
            window,
        )

        count = len(events)

        if count < threshold:
            return

        self.total_bot_detections += 1

        security_logger.warning(
            "BOT RAID DETECTED | "
            "guild=%s bots=%s window=%ss threshold=%s",
            guild_id,
            count,
            window,
            threshold,
        )

    # ========================================================
    # CLEANUP LOOP
    # ========================================================

    async def _cleanup_loop(
        self,
    ) -> None:

        try:

            while True:

                await asyncio.sleep(
                    CLEANUP_INTERVAL
                )

                now = time.monotonic()

                # ------------------------------------------------
                # Join queues
                # ------------------------------------------------

                for guild_id in list(
                    self._joins.keys()
                ):

                    events = self._joins.get(
                        guild_id
                    )

                    if not events:
                        self._joins.pop(
                            guild_id,
                            None,
                        )
                        continue

                    window = DEFAULT_WINDOW_SECONDS

                    try:

                        window = await self._get_window(
                            guild_id
                        )

                    except Exception:
                        pass

                    self._cleanup_deque(
                        events,
                        now,
                        window,
                    )

                    if not events:

                        self._joins.pop(
                            guild_id,
                            None,
                        )

                # ------------------------------------------------
                # Bot queues
                # ------------------------------------------------

                for guild_id in list(
                    self._bot_adds.keys()
                ):

                    events = self._bot_adds.get(
                        guild_id
                    )

                    if not events:
                        self._bot_adds.pop(
                            guild_id,
                            None,
                        )
                        continue

                    self._cleanup_deque(
                        events,
                        now,
                        DEFAULT_WINDOW_SECONDS,
                    )

                    if not events:

                        self._bot_adds.pop(
                            guild_id,
                            None,
                        )

                # ------------------------------------------------
                # Alert cooldown
                # ------------------------------------------------

                for guild_id in list(
                    self._alerted_until.keys()
                ):

                    if (
                        self._alerted_until[
                            guild_id
                        ]
                        < now
                    ):

                        self._alerted_until.pop(
                            guild_id,
                            None,
                        )

                # ------------------------------------------------
                # Lock cleanup
                # ------------------------------------------------

                if len(self._locks) > MAX_TRACKED_GUILDS:

                    active_guilds = set(
                        self._joins.keys()
                    )

                    for guild_id in list(
                        self._locks.keys()
                    ):

                        if (
                            guild_id
                            not in active_guilds
                        ):

                            self._locks.pop(
                                guild_id,
                                None,
                            )

        except asyncio.CancelledError:

            raise

        except Exception as exc:

            self.total_errors += 1

            security_logger.exception(
                "AntiRaid cleanup loop crashed | "
                "error=%s",
                exc,
            )

    # ========================================================
    # STATUS
    # ========================================================

    def get_status(self) -> dict:
        """
        Diagnostics / panel için runtime durumu.
        """

        return {
            "enabled": True,
            "tracked_guilds": len(
                self._joins
            ),
            "tracked_bot_guilds": len(
                self._bot_adds
            ),
            "total_joins_seen": (
                self.total_joins_seen
            ),
            "total_raid_detections": (
                self.total_raid_detections
            ),
            "total_bot_detections": (
                self.total_bot_detections
            ),
            "total_actions": (
                self.total_actions
            ),
            "total_errors": (
                self.total_errors
            ),
        }

    # ========================================================
    # COG UNLOAD
    # ========================================================

    async def cog_unload(
        self,
    ) -> None:

        if self._cleanup_task is not None:

            self._cleanup_task.cancel()

            try:

                await self._cleanup_task

            except asyncio.CancelledError:

                pass

            except Exception as exc:

                security_logger.warning(
                    "AntiRaid cleanup task shutdown error | "
                    "error=%s",
                    exc,
                )

        self._joins.clear()
        self._bot_adds.clear()
        self._alerted_until.clear()
        self._locks.clear()

        security_logger.info(
            "AntiRaid unloaded."
        )


# ============================================================
# SETUP
# ============================================================


async def setup(
    bot: commands.Bot,
) -> None:

    await bot.add_cog(
        AntiRaid(bot)
    )


__all__ = [
    "AntiRaid",
    "setup",
]