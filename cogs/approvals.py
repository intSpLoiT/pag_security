# cogs/approvals.py
from __future__ import annotations

import asyncio
import secrets
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from typing import Optional

import discord
from discord.ext import commands, tasks

from utils.logger import security_logger


# ============================================================
# PAG SECURITY BOT
# cogs/approvals.py
#
# Güvenlik işlemleri için geçici onay sistemi.
#
# Özellikler:
#   - Guild bazlı approval
#   - Güvenli token
#   - Süre aşımı
#   - Tek kullanımlık onay
#   - İptal
#   - Otomatik cleanup
#   - Yetki kontrolü
#   - Memory leak önleme
#   - Hata izolasyonu
# ============================================================


DEFAULT_APPROVAL_TIMEOUT = 300
MAX_APPROVAL_TIMEOUT = 3600
MAX_PENDING_PER_GUILD = 100


# ============================================================
# DATA MODEL
# ============================================================


@dataclass(slots=True)
class ApprovalRequest:
    """
    Tek bir approval isteği.
    """

    approval_id: str
    guild_id: int
    requester_id: int

    action: str

    created_at: datetime
    expires_at: datetime

    metadata: dict

    approved_by: Optional[int] = None
    completed: bool = False
    cancelled: bool = False

    # --------------------------------------------------------
    # Helpers
    # --------------------------------------------------------

    @property
    def expired(self) -> bool:
        return datetime.now(
            timezone.utc
        ) >= self.expires_at

    @property
    def pending(self) -> bool:
        return (
            not self.completed
            and not self.cancelled
            and not self.expired
        )


# ============================================================
# APPROVALS COG
# ============================================================


class Approvals(commands.Cog):
    """
    PAG Security approval sistemi.

    Diğer security Cog'ları tarafından da kullanılabilir.

    Örnek:

        approval = await cog.create_approval(
            guild_id=guild.id,
            requester_id=user.id,
            action="lockdown",
        )

        result = await cog.approve(
            guild.id,
            approval.approval_id,
            moderator.id,
        )
    """

    def __init__(
        self,
        bot: commands.Bot,
    ) -> None:

        self.bot = bot

        # ----------------------------------------------------
        # Runtime storage
        # ----------------------------------------------------

        self._approvals: dict[
            str,
            ApprovalRequest,
        ] = {}

        self._guild_approvals: dict[
            int,
            set[str],
        ] = {}

        # ----------------------------------------------------
        # Locks
        # ----------------------------------------------------

        self._locks: dict[
            int,
            asyncio.Lock,
        ] = {}

        self._global_lock = asyncio.Lock()

        # ----------------------------------------------------
        # Statistics
        # ----------------------------------------------------

        self.created_count = 0
        self.approved_count = 0
        self.cancelled_count = 0
        self.expired_count = 0

        # ----------------------------------------------------
        # Background cleanup
        # ----------------------------------------------------

        self.cleanup_loop.start()

        security_logger.info(
            "Approvals cog initialized."
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

    @staticmethod
    def _generate_id() -> str:
        """
        Tahmin edilmesi zor approval ID.
        """

        return secrets.token_urlsafe(18)

    @staticmethod
    def _normalize_timeout(
        timeout: int,
    ) -> int:

        try:
            timeout = int(timeout)
        except (
            TypeError,
            ValueError,
        ):
            timeout = DEFAULT_APPROVAL_TIMEOUT

        return max(
            1,
            min(
                timeout,
                MAX_APPROVAL_TIMEOUT,
            ),
        )

    def _guild_count(
        self,
        guild_id: int,
    ) -> int:

        return len(
            self._guild_approvals.get(
                guild_id,
                set(),
            )
        )

    # ========================================================
    # CREATE
    # ========================================================

    async def create_approval(
        self,
        *,
        guild_id: int,
        requester_id: int,
        action: str,
        timeout: int = DEFAULT_APPROVAL_TIMEOUT,
        metadata: Optional[dict] = None,
    ) -> Optional[ApprovalRequest]:
        """
        Yeni approval oluşturur.

        Guild başına maksimum pending approval sınırı vardır.
        """

        if guild_id <= 0:
            return None

        if requester_id <= 0:
            return None

        if not isinstance(
            action,
            str,
        ):
            return None

        action = action.strip()

        if not action:
            return None

        lock = self._get_lock(
            guild_id
        )

        async with lock:

            # ------------------------------------------------
            # Eski approval'ları temizle
            # ------------------------------------------------

            await self._cleanup_guild_locked(
                guild_id
            )

            if (
                self._guild_count(guild_id)
                >= MAX_PENDING_PER_GUILD
            ):

                security_logger.warning(
                    "Approval limit reached | "
                    "guild=%s",
                    guild_id,
                )

                return None

            timeout = self._normalize_timeout(
                timeout
            )

            now = datetime.now(
                timezone.utc
            )

            approval = ApprovalRequest(
                approval_id=self._generate_id(),
                guild_id=guild_id,
                requester_id=requester_id,
                action=action,
                created_at=now,
                expires_at=(
                    now
                    + timedelta(
                        seconds=timeout
                    )
                ),
                metadata=dict(
                    metadata or {}
                ),
            )

            self._approvals[
                approval.approval_id
            ] = approval

            self._guild_approvals.setdefault(
                guild_id,
                set(),
            ).add(
                approval.approval_id
            )

            self.created_count += 1

            security_logger.info(
                "Approval created | "
                "guild=%s requester=%s action=%s "
                "approval=%s",
                guild_id,
                requester_id,
                action,
                approval.approval_id,
            )

            return approval

    # ========================================================
    # GET
    # ========================================================

    def get_approval(
        self,
        approval_id: str,
    ) -> Optional[ApprovalRequest]:

        if not isinstance(
            approval_id,
            str,
        ):
            return None

        approval = self._approvals.get(
            approval_id
        )

        if approval is None:
            return None

        if approval.expired:

            # Burada fiziksel silme yapılmaz.
            # Cleanup task halleder.
            return None

        return approval

    # ========================================================
    # APPROVE
    # ========================================================

    async def approve(
        self,
        *,
        guild_id: int,
        approval_id: str,
        approver_id: int,
    ) -> tuple[bool, str]:

        if guild_id <= 0:
            return False, "invalid_guild"

        if approver_id <= 0:
            return False, "invalid_approver"

        lock = self._get_lock(
            guild_id
        )

        async with lock:

            approval = self._approvals.get(
                approval_id
            )

            if approval is None:

                return (
                    False,
                    "approval_not_found",
                )

            if (
                approval.guild_id
                != guild_id
            ):

                return (
                    False,
                    "guild_mismatch",
                )

            if approval.completed:

                return (
                    False,
                    "already_approved",
                )

            if approval.cancelled:

                return (
                    False,
                    "already_cancelled",
                )

            if approval.expired:

                self._remove_approval_locked(
                    approval
                )

                self.expired_count += 1

                return (
                    False,
                    "approval_expired",
                )

            approval.approved_by = (
                approver_id
            )

            approval.completed = True

            self.approved_count += 1

            security_logger.info(
                "Approval approved | "
                "guild=%s approval=%s "
                "requester=%s approver=%s action=%s",
                guild_id,
                approval_id,
                approval.requester_id,
                approver_id,
                approval.action,
            )

            return (
                True,
                "approved",
            )

    # ========================================================
    # CANCEL
    # ========================================================

    async def cancel(
        self,
        *,
        guild_id: int,
        approval_id: str,
        user_id: int,
    ) -> tuple[bool, str]:

        lock = self._get_lock(
            guild_id
        )

        async with lock:

            approval = self._approvals.get(
                approval_id
            )

            if approval is None:

                return (
                    False,
                    "approval_not_found",
                )

            if (
                approval.guild_id
                != guild_id
            ):

                return (
                    False,
                    "guild_mismatch",
                )

            if approval.completed:

                return (
                    False,
                    "already_approved",
                )

            if approval.cancelled:

                return (
                    False,
                    "already_cancelled",
                )

            if approval.expired:

                self._remove_approval_locked(
                    approval
                )

                self.expired_count += 1

                return (
                    False,
                    "approval_expired",
                )

            # ------------------------------------------------
            # Sadece request sahibi iptal edebilir.
            # ------------------------------------------------

            if (
                approval.requester_id
                != user_id
            ):

                return (
                    False,
                    "not_requester",
                )

            approval.cancelled = True

            self.cancelled_count += 1

            self._remove_approval_locked(
                approval
            )

            security_logger.info(
                "Approval cancelled | "
                "guild=%s approval=%s user=%s",
                guild_id,
                approval_id,
                user_id,
            )

            return (
                True,
                "cancelled",
            )

    # ========================================================
    # REMOVE
    # ========================================================

    def _remove_approval_locked(
        self,
        approval: ApprovalRequest,
    ) -> None:

        self._approvals.pop(
            approval.approval_id,
            None,
        )

        approval_ids = (
            self._guild_approvals.get(
                approval.guild_id
            )
        )

        if approval_ids is not None:

            approval_ids.discard(
                approval.approval_id
            )

            if not approval_ids:

                self._guild_approvals.pop(
                    approval.guild_id,
                    None,
                )

    # ========================================================
    # CLEANUP GUILD
    # ========================================================

    async def _cleanup_guild_locked(
        self,
        guild_id: int,
    ) -> int:

        approval_ids = list(
            self._guild_approvals.get(
                guild_id,
                set(),
            )
        )

        removed = 0

        for approval_id in approval_ids:

            approval = self._approvals.get(
                approval_id
            )

            if approval is None:

                self._guild_approvals[
                    guild_id
                ].discard(
                    approval_id
                )

                continue

            if approval.expired:

                self._remove_approval_locked(
                    approval
                )

                self.expired_count += 1

                removed += 1

        return removed

    # ========================================================
    # CLEANUP ALL
    # ========================================================

    async def cleanup_expired(
        self,
    ) -> int:

        total_removed = 0

        async with self._global_lock:

            guild_ids = list(
                self._guild_approvals.keys()
            )

        for guild_id in guild_ids:

            lock = self._get_lock(
                guild_id
            )

            async with lock:

                total_removed += (
                    await self._cleanup_guild_locked(
                        guild_id
                    )
                )

        return total_removed

    # ========================================================
    # BACKGROUND LOOP
    # ========================================================

    @tasks.loop(
        seconds=30.0
    )
    async def cleanup_loop(
        self,
    ) -> None:

        try:

            removed = (
                await self.cleanup_expired()
            )

            if removed:

                security_logger.debug(
                    "Expired approvals cleaned | "
                    "count=%s",
                    removed,
                )

        except asyncio.CancelledError:

            raise

        except Exception:

            security_logger.exception(
                "Approval cleanup failed."
            )

    @cleanup_loop.before_loop
    async def before_cleanup_loop(
        self,
    ) -> None:

        try:

            await self.bot.wait_until_ready()

        except asyncio.CancelledError:

            raise

    # ========================================================
    # LIST
    # ========================================================

    def get_pending(
        self,
        guild_id: int,
    ) -> list[ApprovalRequest]:

        result: list[
            ApprovalRequest
        ] = []

        approval_ids = (
            self._guild_approvals.get(
                guild_id,
                set(),
            )
        )

        for approval_id in list(
            approval_ids
        ):

            approval = self._approvals.get(
                approval_id
            )

            if approval is None:
                continue

            if approval.pending:

                result.append(
                    approval
                )

        result.sort(
            key=lambda item: item.created_at
        )

        return result

    # ========================================================
    # CHECK
    # ========================================================

    def is_pending(
        self,
        approval_id: str,
    ) -> bool:

        approval = self._approvals.get(
            approval_id
        )

        if approval is None:
            return False

        return approval.pending

    # ========================================================
    # WAIT FOR APPROVAL
    # ========================================================

    async def wait_for_approval(
        self,
        approval_id: str,
        *,
        poll_interval: float = 1.0,
    ) -> Optional[ApprovalRequest]:
        """
        Approval tamamlanana veya süresi dolana kadar bekler.

        Timeout nedeniyle sonsuz bekleme oluşmaz.
        """

        try:
            poll_interval = float(
                poll_interval
            )
        except (
            TypeError,
            ValueError,
        ):
            poll_interval = 1.0

        poll_interval = max(
            0.1,
            min(
                poll_interval,
                10.0,
            ),
        )

        while True:

            approval = self._approvals.get(
                approval_id
            )

            if approval is None:
                return None

            if approval.completed:
                return approval

            if approval.cancelled:
                return approval

            if approval.expired:

                lock = self._get_lock(
                    approval.guild_id
                )

                async with lock:

                    current = (
                        self._approvals.get(
                            approval_id
                        )
                    )

                    if current is not None:

                        self._remove_approval_locked(
                            current
                        )

                        self.expired_count += 1

                return None

            await asyncio.sleep(
                poll_interval
            )

    # ========================================================
    # STATS
    # ========================================================

    def get_stats(
        self,
    ) -> dict:

        pending = sum(
            len(ids)
            for ids
            in self._guild_approvals.values()
        )

        return {
            "pending": pending,
            "total_created": (
                self.created_count
            ),
            "total_approved": (
                self.approved_count
            ),
            "total_cancelled": (
                self.cancelled_count
            ),
            "total_expired": (
                self.expired_count
            ),
            "guilds": len(
                self._guild_approvals
            ),
        }

    # ========================================================
    # COG UNLOAD
    # ========================================================

    def cog_unload(
        self,
    ) -> None:

        self.cleanup_loop.cancel()

        self._approvals.clear()

        self._guild_approvals.clear()

        self._locks.clear()

        security_logger.info(
            "Approvals cog unloaded."
        )


# ============================================================
# SETUP
# ============================================================


async def setup(
    bot: commands.Bot,
) -> None:

    await bot.add_cog(
        Approvals(bot)
    )


__all__ = [
    "Approvals",
    "ApprovalRequest",
]