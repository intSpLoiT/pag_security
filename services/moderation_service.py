# services/moderation_service.py

from __future__ import annotations

import asyncio
from dataclasses import dataclass
from typing import Iterable, Optional

import discord

from utils.logger import moderation_logger


# ============================================================
# PAG SECURITY BOT
# services/moderation_service.py
#
# Discord moderation işlemlerinin merkezi servisi.
#
# discord.py 2.x
#
# Özellikler:
# - Ban
# - Kick
# - Timeout
# - Role remove
# - Role restore
# - Quarantine
# - Lockdown
# - Unlock
# - Kanal izinlerini güvenli değiştirme
# - Bot / owner / hierarchy koruması
# - Hata yönetimi
# - Action sonucu döndürme
# - DatabaseService entegrasyonu
#
# NOT:
# Bu servis "karar" vermez.
# Kararı SecurityService verir.
#
# SecurityService:
#     "Bu kullanıcı tehlikeli."
#
# ModerationService:
#     "Verilen güvenli işlem uygulanabilir mi?"
# ============================================================


# ============================================================
# CONSTANTS
# ============================================================

MAX_REASON_LENGTH = 512

DEFAULT_TIMEOUT_SECONDS = 60 * 10

# Discord'un maksimum timeout süresi yaklaşık 28 gündür.
MAX_TIMEOUT_SECONDS = 28 * 24 * 60 * 60


# ============================================================
# RESULT
# ============================================================

@dataclass(slots=True)
class ModerationResult:
    """
    Moderation işleminin sonucunu temsil eder.
    """

    success: bool

    action: str

    guild_id: int

    target_id: Optional[int] = None

    reason: Optional[str] = None

    error: Optional[str] = None

    skipped: bool = False

    details: Optional[dict] = None

    @classmethod
    def ok(
        cls,
        *,
        action: str,
        guild_id: int,
        target_id: Optional[int] = None,
        reason: Optional[str] = None,
        details: Optional[dict] = None,
    ) -> "ModerationResult":

        return cls(
            success=True,
            action=action,
            guild_id=guild_id,
            target_id=target_id,
            reason=reason,
            details=details,
        )

    @classmethod
    def fail(
        cls,
        *,
        action: str,
        guild_id: int,
        target_id: Optional[int] = None,
        error: str,
        reason: Optional[str] = None,
    ) -> "ModerationResult":

        return cls(
            success=False,
            action=action,
            guild_id=guild_id,
            target_id=target_id,
            reason=reason,
            error=error,
        )

    @classmethod
    def skip(
        cls,
        *,
        action: str,
        guild_id: int,
        target_id: Optional[int] = None,
        reason: Optional[str] = None,
        error: Optional[str] = None,
    ) -> "ModerationResult":

        return cls(
            success=False,
            skipped=True,
            action=action,
            guild_id=guild_id,
            target_id=target_id,
            reason=reason,
            error=error,
        )


# ============================================================
# SERVICE
# ============================================================

class ModerationService:
    """
    PAG Security Bot moderation service.

    Discord tarafındaki bütün kritik moderasyon işlemleri
    mümkün olduğunca bu sınıf üzerinden geçirilir.
    """

    def __init__(
        self,
        bot: discord.Client,
        database=None,
    ) -> None:

        self.bot = bot

        self.database = database

        self._lock = asyncio.Lock()

    # ========================================================
    # HELPERS
    # ========================================================

    @staticmethod
    def _reason(
        reason: Optional[str],
    ) -> Optional[str]:
        """
        Discord audit-log reason'ını normalize eder.
        """

        if reason is None:
            return None

        reason = str(reason).strip()

        if not reason:
            return None

        return reason[:MAX_REASON_LENGTH]

    @staticmethod
    def _guild(
        guild: Optional[discord.Guild],
    ) -> Optional[discord.Guild]:

        return guild

    # ========================================================
    # BOT MEMBER
    # ========================================================

    def get_bot_member(
        self,
        guild: discord.Guild,
    ) -> Optional[discord.Member]:
        """
        Botun guild içerisindeki Member nesnesini döndürür.
        """

        if self.bot.user is None:
            return None

        return guild.me

    # ========================================================
    # TARGET RESOLUTION
    # ========================================================

    async def resolve_member(
        self,
        guild: discord.Guild,
        user_id: int,
    ) -> Optional[discord.Member]:
        """
        Guild içerisindeki Member'ı bulmaya çalışır.

        Önce cache kullanılır.
        Yoksa fetch_member denenir.
        """

        member = guild.get_member(user_id)

        if member is not None:
            return member

        try:
            return await guild.fetch_member(user_id)

        except (
            discord.NotFound,
            discord.Forbidden,
            discord.HTTPException,
        ):
            return None

    # ========================================================
    # HIERARCHY
    # ========================================================

    def can_target_member(
        self,
        guild: discord.Guild,
        target: discord.Member,
    ) -> tuple[bool, str]:
        """
        Bot bu kullanıcıyı hedefleyebilir mi?

        Kontroller:
        - Bot mevcut mu?
        - Owner mı?
        - Botun kendisi mi?
        - Botun rolü hedefin üzerinde mi?
        """

        bot_member = self.get_bot_member(guild)

        if bot_member is None:
            return False, "Bot guild member bulunamadı."

        if target.id == self.bot.user.id:
            return False, "Bot kendisini hedefleyemez."

        if target.id == guild.owner_id:
            return False, "Sunucu sahibi hedeflenemez."

        if target == bot_member:
            return False, "Bot kendi üyesini hedefleyemez."

        if target.top_role >= bot_member.top_role:
            return (
                False,
                "Hedef kullanıcının en yüksek rolü botun rolüne eşit veya üzerinde.",
            )

        return True, "OK"

    def can_manage_role(
        self,
        guild: discord.Guild,
        role: discord.Role,
    ) -> tuple[bool, str]:
        """
        Bot bu rolü yönetebilir mi?
        """

        bot_member = self.get_bot_member(guild)

        if bot_member is None:
            return False, "Bot guild member bulunamadı."

        if role.is_default():
            return False, "@everyone rolü yönetilemez."

        if role.managed:
            return False, "Entegrasyon/bot rolü yönetilemez."

        if role >= bot_member.top_role:
            return (
                False,
                "Rol botun en yüksek rolüne eşit veya üzerinde.",
            )

        return True, "OK"

    # ========================================================
    # SAFE PERMISSION CHECK
    # ========================================================

    def has_permission(
        self,
        guild: discord.Guild,
        permission: str,
    ) -> bool:
        """
        Botun belirtilen guild permission'ına sahip olup
        olmadığını kontrol eder.
        """

        member = self.get_bot_member(guild)

        if member is None:
            return False

        permissions = member.guild_permissions

        return bool(
            getattr(
                permissions,
                permission,
                False,
            )
        )

    # ========================================================
    # BAN
    # ========================================================

    async def ban(
        self,
        guild: discord.Guild,
        user: discord.User | discord.Member,
        *,
        reason: Optional[str] = None,
        delete_message_days: int = 0,
    ) -> ModerationResult:
        """
        Kullanıcıyı banlar.

        Güvenlik kontrolleri:
        - Ban permission
        - Owner protection
        - Bot hierarchy
        - Invalid message delete days
        """

        action = "BAN"

        if not self.has_permission(
            guild,
            "ban_members",
        ):
            return ModerationResult.fail(
                action=action,
                guild_id=guild.id,
                target_id=user.id,
                error="Botta ban_members izni yok.",
            )

        member = (
            user
            if isinstance(user, discord.Member)
            else await self.resolve_member(
                guild,
                user.id,
            )
        )

        if member is not None:
            allowed, error = self.can_target_member(
                guild,
                member,
            )

            if not allowed:
                return ModerationResult.skip(
                    action=action,
                    guild_id=guild.id,
                    target_id=user.id,
                    error=error,
                )

        days = max(
            0,
            min(
                int(delete_message_days),
                7,
            ),
        )

        audit_reason = self._reason(reason)

        try:
            await guild.ban(
                user,
                reason=audit_reason,
                delete_message_seconds=days * 86_400,
            )

            result = ModerationResult.ok(
                action=action,
                guild_id=guild.id,
                target_id=user.id,
                reason=audit_reason,
            )

            await self._record_action(
                guild=guild,
                action=action,
                target_id=user.id,
                success=True,
                reason=audit_reason,
            )

            moderation_logger.warning(
                "BAN | guild=%s user=%s reason=%s",
                guild.id,
                user.id,
                audit_reason,
            )

            return result

        except discord.Forbidden as exc:

            return await self._failure(
                guild,
                action,
                user.id,
                reason,
                "Discord ban işlemini reddetti.",
                exc,
            )

        except discord.NotFound as exc:

            return await self._failure(
                guild,
                action,
                user.id,
                reason,
                "Kullanıcı bulunamadı.",
                exc,
            )

        except discord.HTTPException as exc:

            return await self._failure(
                guild,
                action,
                user.id,
                reason,
                f"Discord API hatası: {exc}",
                exc,
            )

    # ========================================================
    # UNBAN
    # ========================================================

    async def unban(
        self,
        guild: discord.Guild,
        user: discord.User | discord.Object,
        *,
        reason: Optional[str] = None,
    ) -> ModerationResult:
        """
        Ban kaldırır.
        """

        action = "UNBAN"

        if not self.has_permission(
            guild,
            "ban_members",
        ):
            return ModerationResult.fail(
                action=action,
                guild_id=guild.id,
                target_id=getattr(
                    user,
                    "id",
                    None,
                ),
                error="Botta ban_members izni yok.",
            )

        user_id = getattr(
            user,
            "id",
            None,
        )

        if user_id is None:
            return ModerationResult.fail(
                action=action,
                guild_id=guild.id,
                error="Geçersiz kullanıcı.",
            )

        audit_reason = self._reason(reason)

        try:
            await guild.unban(
                discord.Object(id=user_id),
                reason=audit_reason,
            )

            await self._record_action(
                guild=guild,
                action=action,
                target_id=user_id,
                success=True,
                reason=audit_reason,
            )

            moderation_logger.info(
                "UNBAN | guild=%s user=%s",
                guild.id,
                user_id,
            )

            return ModerationResult.ok(
                action=action,
                guild_id=guild.id,
                target_id=user_id,
                reason=audit_reason,
            )

        except discord.NotFound as exc:

            return await self._failure(
                guild,
                action,
                user_id,
                reason,
                "Kullanıcı banlı değil veya bulunamadı.",
                exc,
            )

        except discord.Forbidden as exc:

            return await self._failure(
                guild,
                action,
                user_id,
                reason,
                "Discord unban işlemini reddetti.",
                exc,
            )

        except discord.HTTPException as exc:

            return await self._failure(
                guild,
                action,
                user_id,
                reason,
                f"Discord API hatası: {exc}",
                exc,
            )

    # ========================================================
    # KICK
    # ========================================================

    async def kick(
        self,
        guild: discord.Guild,
        member: discord.Member,
        *,
        reason: Optional[str] = None,
    ) -> ModerationResult:
        """
        Üyeyi sunucudan atar.
        """

        action = "KICK"

        if not self.has_permission(
            guild,
            "kick_members",
        ):
            return ModerationResult.fail(
                action=action,
                guild_id=guild.id,
                target_id=member.id,
                error="Botta kick_members izni yok.",
            )

        allowed, error = self.can_target_member(
            guild,
            member,
        )

        if not allowed:
            return ModerationResult.skip(
                action=action,
                guild_id=guild.id,
                target_id=member.id,
                error=error,
            )

        audit_reason = self._reason(reason)

        try:
            await member.kick(
                reason=audit_reason,
            )

            await self._record_action(
                guild=guild,
                action=action,
                target_id=member.id,
                success=True,
                reason=audit_reason,
            )

            moderation_logger.warning(
                "KICK | guild=%s user=%s reason=%s",
                guild.id,
                member.id,
                audit_reason,
            )

            return ModerationResult.ok(
                action=action,
                guild_id=guild.id,
                target_id=member.id,
                reason=audit_reason,
            )

        except discord.Forbidden as exc:

            return await self._failure(
                guild,
                action,
                member.id,
                reason,
                "Discord kick işlemini reddetti.",
                exc,
            )

        except discord.HTTPException as exc:

            return await self._failure(
                guild,
                action,
                member.id,
                reason,
                f"Discord API hatası: {exc}",
                exc,
            )

    # ========================================================
    # TIMEOUT
    # ========================================================

    async def timeout(
        self,
        member: discord.Member,
        *,
        seconds: int = DEFAULT_TIMEOUT_SECONDS,
        reason: Optional[str] = None,
    ) -> ModerationResult:
        """
        Kullanıcıya timeout uygular.
        """

        guild = member.guild

        action = "TIMEOUT"

        if not self.has_permission(
            guild,
            "moderate_members",
        ):
            return ModerationResult.fail(
                action=action,
                guild_id=guild.id,
                target_id=member.id,
                error="Botta moderate_members izni yok.",
            )

        allowed, error = self.can_target_member(
            guild,
            member,
        )

        if not allowed:
            return ModerationResult.skip(
                action=action,
                guild_id=guild.id,
                target_id=member.id,
                error=error,
            )

        seconds = max(
            1,
            min(
                int(seconds),
                MAX_TIMEOUT_SECONDS,
            ),
        )

        audit_reason = self._reason(reason)

        try:
            duration = discord.utils.utcnow() + discord.timedelta(
                seconds=seconds
            )

        except AttributeError:
            # discord.timedelta bazı sürümlerde bulunmaz.
            # Standart datetime kullanılır.
            from datetime import timedelta

            duration = (
                discord.utils.utcnow()
                + timedelta(
                    seconds=seconds
                )
            )

        try:
            await member.edit(
                timed_out_until=duration,
                reason=audit_reason,
            )

            await self._record_action(
                guild=guild,
                action=action,
                target_id=member.id,
                success=True,
                reason=audit_reason,
                details={
                    "seconds": seconds,
                },
            )

            moderation_logger.warning(
                "TIMEOUT | guild=%s user=%s duration=%ss",
                guild.id,
                member.id,
                seconds,
            )

            return ModerationResult.ok(
                action=action,
                guild_id=guild.id,
                target_id=member.id,
                reason=audit_reason,
                details={
                    "seconds": seconds,
                },
            )

        except discord.Forbidden as exc:

            return await self._failure(
                guild,
                action,
                member.id,
                reason,
                "Discord timeout işlemini reddetti.",
                exc,
            )

        except discord.HTTPException as exc:

            return await self._failure(
                guild,
                action,
                member.id,
                reason,
                f"Discord API hatası: {exc}",
                exc,
            )

    # ========================================================
    # REMOVE TIMEOUT
    # ========================================================

    async def remove_timeout(
        self,
        member: discord.Member,
        *,
        reason: Optional[str] = None,
    ) -> ModerationResult:
        """
        Timeout kaldırır.
        """

        guild = member.guild

        action = "TIMEOUT_REMOVE"

        if not self.has_permission(
            guild,
            "moderate_members",
        ):
            return ModerationResult.fail(
                action=action,
                guild_id=guild.id,
                target_id=member.id,
                error="Botta moderate_members izni yok.",
            )

        allowed, error = self.can_target_member(
            guild,
            member,
        )

        if not allowed:
            return ModerationResult.skip(
                action=action,
                guild_id=guild.id,
                target_id=member.id,
                error=error,
            )

        audit_reason = self._reason(reason)

        try:
            await member.edit(
                timed_out_until=None,
                reason=audit_reason,
            )

            await self._record_action(
                guild=guild,
                action=action,
                target_id=member.id,
                success=True,
                reason=audit_reason,
            )

            return ModerationResult.ok(
                action=action,
                guild_id=guild.id,
                target_id=member.id,
                reason=audit_reason,
            )

        except discord.Forbidden as exc:

            return await self._failure(
                guild,
                action,
                member.id,
                reason,
                "Discord timeout kaldırma işlemini reddetti.",
                exc,
            )

        except discord.HTTPException as exc:

            return await self._failure(
                guild,
                action,
                member.id,
                reason,
                f"Discord API hatası: {exc}",
                exc,
            )

    # ========================================================
    # REMOVE ROLE
    # ========================================================

    async def remove_role(
        self,
        member: discord.Member,
        role: discord.Role,
        *,
        reason: Optional[str] = None,
    ) -> ModerationResult:
        """
        Üyeden tek bir rol kaldırır.
        """

        guild = member.guild

        action = "ROLE_REMOVE"

        allowed_member, member_error = (
            self.can_target_member(
                guild,
                member,
            )
        )

        if not allowed_member:
            return ModerationResult.skip(
                action=action,
                guild_id=guild.id,
                target_id=member.id,
                error=member_error,
            )

        allowed_role, role_error = (
            self.can_manage_role(
                guild,
                role,
            )
        )

        if not allowed_role:
            return ModerationResult.skip(
                action=action,
                guild_id=guild.id,
                target_id=member.id,
                error=role_error,
            )

        if role not in member.roles:
            return ModerationResult.skip(
                action=action,
                guild_id=guild.id,
                target_id=member.id,
                error="Kullanıcıda bu rol bulunmuyor.",
            )

        audit_reason = self._reason(reason)

        try:
            await member.remove_roles(
                role,
                reason=audit_reason,
            )

            await self._record_action(
                guild=guild,
                action=action,
                target_id=member.id,
                success=True,
                reason=audit_reason,
                details={
                    "role_id": role.id,
                },
            )

            moderation_logger.warning(
                "ROLE REMOVE | guild=%s user=%s role=%s",
                guild.id,
                member.id,
                role.id,
            )

            return ModerationResult.ok(
                action=action,
                guild_id=guild.id,
                target_id=member.id,
                reason=audit_reason,
                details={
                    "role_id": role.id,
                },
            )

        except discord.Forbidden as exc:

            return await self._failure(
                guild,
                action,
                member.id,
                reason,
                "Discord rol kaldırma işlemini reddetti.",
                exc,
            )

        except discord.HTTPException as exc:

            return await self._failure(
                guild,
                action,
                member.id,
                reason,
                f"Discord API hatası: {exc}",
                exc,
            )

    # ========================================================
    # REMOVE MULTIPLE ROLES
    # ========================================================

    async def remove_roles(
        self,
        member: discord.Member,
        roles: Iterable[discord.Role],
        *,
        reason: Optional[str] = None,
    ) -> ModerationResult:
        """
        Üyeden birden fazla yönetilebilir rolü kaldırır.

        Emergency sırasında kullanılabilir.
        """

        guild = member.guild

        action = "ROLES_REMOVE"

        allowed_member, member_error = (
            self.can_target_member(
                guild,
                member,
            )
        )

        if not allowed_member:
            return ModerationResult.skip(
                action=action,
                guild_id=guild.id,
                target_id=member.id,
                error=member_error,
            )

        valid_roles: list[discord.Role] = []

        for role in roles:

            if role is None:
                continue

            allowed, _ = self.can_manage_role(
                guild,
                role,
            )

            if not allowed:
                continue

            if role in member.roles:
                valid_roles.append(role)

        if not valid_roles:
            return ModerationResult.skip(
                action=action,
                guild_id=guild.id,
                target_id=member.id,
                error="Kaldırılabilecek yönetilebilir rol bulunamadı.",
            )

        audit_reason = self._reason(reason)

        try:
            await member.remove_roles(
                *valid_roles,
                reason=audit_reason,
            )

            role_ids = [
                role.id
                for role in valid_roles
            ]

            await self._record_action(
                guild=guild,
                action=action,
                target_id=member.id,
                success=True,
                reason=audit_reason,
                details={
                    "role_ids": role_ids,
                },
            )

            moderation_logger.warning(
                "ROLES REMOVE | guild=%s user=%s roles=%s",
                guild.id,
                member.id,
                role_ids,
            )

            return ModerationResult.ok(
                action=action,
                guild_id=guild.id,
                target_id=member.id,
                reason=audit_reason,
                details={
                    "role_ids": role_ids,
                },
            )

        except discord.Forbidden as exc:

            return await self._failure(
                guild,
                action,
                member.id,
                reason,
                "Discord rol kaldırma işlemini reddetti.",
                exc,
            )

        except discord.HTTPException as exc:

            return await self._failure(
                guild,
                action,
                member.id,
                reason,
                f"Discord API hatası: {exc}",
                exc,
            )

    # ========================================================
    # ADD ROLE
    # ========================================================

    async def add_role(
        self,
        member: discord.Member,
        role: discord.Role,
        *,
        reason: Optional[str] = None,
    ) -> ModerationResult:
        """
        Üyeye rol ekler.
        """

        guild = member.guild

        action = "ROLE_ADD"

        allowed_member, member_error = (
            self.can_target_member(
                guild,
                member,
            )
        )

        if not allowed_member:
            return ModerationResult.skip(
                action=action,
                guild_id=guild.id,
                target_id=member.id,
                error=member_error,
            )

        allowed_role, role_error = (
            self.can_manage_role(
                guild,
                role,
            )
        )

        if not allowed_role:
            return ModerationResult.skip(
                action=action,
                guild_id=guild.id,
                target_id=member.id,
                error=role_error,
            )

        if role in member.roles:
            return ModerationResult.skip(
                action=action,
                guild_id=guild.id,
                target_id=member.id,
                error="Kullanıcı zaten bu role sahip.",
            )

        audit_reason = self._reason(reason)

        try:
            await member.add_roles(
                role,
                reason=audit_reason,
            )

            await self._record_action(
                guild=guild,
                action=action,
                target_id=member.id,
                success=True,
                reason=audit_reason,
                details={
                    "role_id": role.id,
                },
            )

            return ModerationResult.ok(
                action=action,
                guild_id=guild.id,
                target_id=member.id,
                reason=audit_reason,
                details={
                    "role_id": role.id,
                },
            )

        except discord.Forbidden as exc:

            return await self._failure(
                guild,
                action,
                member.id,
                reason,
                "Discord rol ekleme işlemini reddetti.",
                exc,
            )

        except discord.HTTPException as exc:

            return await self._failure(
                guild,
                action,
                member.id,
                reason,
                f"Discord API hatası: {exc}",
                exc,
            )

    # ========================================================
    # QUARANTINE
    # ========================================================

    async def quarantine(
        self,
        member: discord.Member,
        quarantine_role: discord.Role,
        *,
        reason: Optional[str] = None,
        save_snapshot: bool = True,
    ) -> ModerationResult:
        """
        Kullanıcıyı quarantine moduna alır.

        İşlem:
        1. Mevcut yönetilebilir roller kaydedilir.
        2. Yönetilebilir roller kaldırılır.
        3. Quarantine rolü eklenir.

        @everyone kaldırılmaz.
        Botun yönetemediği roller değiştirilmez.
        """

        guild = member.guild

        action = "QUARANTINE"

        allowed, error = self.can_target_member(
            guild,
            member,
        )

        if not allowed:
            return ModerationResult.skip(
                action=action,
                guild_id=guild.id,
                target_id=member.id,
                error=error,
            )

        role_allowed, role_error = (
            self.can_manage_role(
                guild,
                quarantine_role,
            )
        )

        if not role_allowed:
            return ModerationResult.fail(
                action=action,
                guild_id=guild.id,
                target_id=member.id,
                error=(
                    "Quarantine rolü yönetilemiyor: "
                    f"{role_error}"
                ),
            )

        removable_roles = []

        for role in member.roles:

            if role.is_default():
                continue

            manageable, _ = self.can_manage_role(
                guild,
                role,
            )

            if manageable:
                removable_roles.append(role)

        role_ids = [
            role.id
            for role in removable_roles
        ]

        # ----------------------------------------------------
        # Snapshot
        # ----------------------------------------------------

        snapshot_id = None

        if save_snapshot and self.database is not None:

            try:
                snapshot_id = (
                    await self.database.save_role_snapshot(
                        guild.id,
                        member.id,
                        role_ids,
                        reason=reason,
                    )
                )

            except Exception as exc:

                moderation_logger.error(
                    "Role snapshot failed | guild=%s user=%s error=%s",
                    guild.id,
                    member.id,
                    exc,
                )

                return ModerationResult.fail(
                    action=action,
                    guild_id=guild.id,
                    target_id=member.id,
                    error=(
                        "Quarantine öncesi role snapshot "
                        "oluşturulamadı."
                    ),
                )

        audit_reason = self._reason(reason)

        try:

            # Önce mevcut rolleri kaldır.
            if removable_roles:

                await member.remove_roles(
                    *removable_roles,
                    reason=audit_reason,
                )

            # Ardından quarantine rolü.
            await member.add_roles(
                quarantine_role,
                reason=audit_reason,
            )

            details = {
                "removed_role_ids": role_ids,
                "quarantine_role_id": quarantine_role.id,
            }

            if snapshot_id is not None:
                details["snapshot_id"] = snapshot_id

            await self._record_action(
                guild=guild,
                action=action,
                target_id=member.id,
                success=True,
                reason=audit_reason,
                details=details,
            )

            moderation_logger.warning(
                "QUARANTINE | guild=%s user=%s",
                guild.id,
                member.id,
            )

            return ModerationResult.ok(
                action=action,
                guild_id=guild.id,
                target_id=member.id,
                reason=audit_reason,
                details=details,
            )

        except discord.Forbidden as exc:

            return await self._failure(
                guild,
                action,
                member.id,
                reason,
                "Discord quarantine işlemini reddetti.",
                exc,
            )

        except discord.HTTPException as exc:

            return await self._failure(
                guild,
                action,
                member.id,
                reason,
                f"Discord API hatası: {exc}",
                exc,
            )

    # ========================================================
    # RESTORE ROLES
    # ========================================================

    async def restore_roles(
        self,
        member: discord.Member,
        *,
        snapshot: Optional[dict] = None,
        reason: Optional[str] = None,
        restored_by: Optional[int] = None,
    ) -> ModerationResult:
        """
        Daha önce alınmış role snapshot'ını geri yükler.
        """

        guild = member.guild

        action = "ROLE_RESTORE"

        if self.database is None:
            return ModerationResult.fail(
                action=action,
                guild_id=guild.id,
                target_id=member.id,
                error="DatabaseService bağlı değil.",
            )

        if snapshot is None:

            snapshot = (
                await self.database
                .get_active_role_snapshot(
                    guild.id,
                    member.id,
                )
            )

        if not snapshot:
            return ModerationResult.skip(
                action=action,
                guild_id=guild.id,
                target_id=member.id,
                error="Aktif role snapshot bulunamadı.",
            )

        role_ids = snapshot.get(
            "role_ids",
            [],
        )

        roles: list[discord.Role] = []

        for role_id in role_ids:

            role = guild.get_role(
                int(role_id)
            )

            if role is None:
                continue

            allowed, _ = self.can_manage_role(
                guild,
                role,
            )

            if not allowed:
                continue

            roles.append(role)

        if not roles:

            return ModerationResult.skip(
                action=action,
                guild_id=guild.id,
                target_id=member.id,
                error=(
                    "Restore edilebilecek geçerli "
                    "yönetilebilir rol bulunamadı."
                ),
            )

        audit_reason = self._reason(reason)

        try:

            await member.add_roles(
                *roles,
                reason=audit_reason,
            )

            snapshot_id = snapshot.get("id")

            if snapshot_id is not None:

                await self.database.mark_role_snapshot_restored(
                    int(snapshot_id),
                    restored_by=restored_by,
                )

            restored_ids = [
                role.id
                for role in roles
            ]

            await self._record_action(
                guild=guild,
                action=action,
                target_id=member.id,
                success=True,
                reason=audit_reason,
                details={
                    "role_ids": restored_ids,
                    "snapshot_id": snapshot_id,
                },
            )

            moderation_logger.info(
                "ROLE RESTORE | guild=%s user=%s roles=%s",
                guild.id,
                member.id,
                restored_ids,
            )

            return ModerationResult.ok(
                action=action,
                guild_id=guild.id,
                target_id=member.id,
                reason=audit_reason,
                details={
                    "role_ids": restored_ids,
                    "snapshot_id": snapshot_id,
                },
            )

        except discord.Forbidden as exc:

            return await self._failure(
                guild,
                action,
                member.id,
                reason,
                "Discord role restore işlemini reddetti.",
                exc,
            )

        except discord.HTTPException as exc:

            return await self._failure(
                guild,
                action,
                member.id,
                reason,
                f"Discord API hatası: {exc}",
                exc,
            )

    # ========================================================
    # CHANNEL LOCK
    # ========================================================

    async def lock_channel(
        self,
        channel: discord.TextChannel,
        *,
        reason: Optional[str] = None,
        role: Optional[discord.Role] = None,
    ) -> ModerationResult:
        """
        Kanalı mesaj gönderimine kapatır.

        Belirtilen role göre overwrite oluşturur.
        Role verilmezse @everyone kullanılır.
        """

        guild = channel.guild

        action = "CHANNEL_LOCK"

        if not self.has_permission(
            guild,
            "manage_channels",
        ):
            return ModerationResult.fail(
                action=action,
                guild_id=guild.id,
                target_id=channel.id,
                error="Botta manage_channels izni yok.",
            )

        if role is None:
            role = guild.default_role

        audit_reason = self._reason(reason)

        try:

            overwrite = channel.overwrites_for(
                role
            )

            overwrite.send_messages = False

            await channel.set_permissions(
                role,
                overwrite=overwrite,
                reason=audit_reason,
            )

            await self._record_action(
                guild=guild,
                action=action,
                target_id=channel.id,
                success=True,
                reason=audit_reason,
                details={
                    "role_id": role.id,
                },
            )

            return ModerationResult.ok(
                action=action,
                guild_id=guild.id,
                target_id=channel.id,
                reason=audit_reason,
            )

        except discord.Forbidden as exc:

            return await self._failure(
                guild,
                action,
                channel.id,
                reason,
                "Discord kanal kilitleme işlemini reddetti.",
                exc,
            )

        except discord.HTTPException as exc:

            return await self._failure(
                guild,
                action,
                channel.id,
                reason,
                f"Discord API hatası: {exc}",
                exc,
            )

    # ========================================================
    # CHANNEL UNLOCK
    # ========================================================

    async def unlock_channel(
        self,
        channel: discord.TextChannel,
        *,
        reason: Optional[str] = None,
        role: Optional[discord.Role] = None,
    ) -> ModerationResult:
        """
        Kanal kilidini kaldırır.
        """

        guild = channel.guild

        action = "CHANNEL_UNLOCK"

        if not self.has_permission(
            guild,
            "manage_channels",
        ):
            return ModerationResult.fail(
                action=action,
                guild_id=guild.id,
                target_id=channel.id,
                error="Botta manage_channels izni yok.",
            )

        if role is None:
            role = guild.default_role

        audit_reason = self._reason(reason)

        try:

            overwrite = channel.overwrites_for(
                role
            )

            overwrite.send_messages = None

            await channel.set_permissions(
                role,
                overwrite=overwrite,
                reason=audit_reason,
            )

            await self._record_action(
                guild=guild,
                action=action,
                target_id=channel.id,
                success=True,
                reason=audit_reason,
            )

            return ModerationResult.ok(
                action=action,
                guild_id=guild.id,
                target_id=channel.id,
                reason=audit_reason,
            )

        except discord.Forbidden as exc:

            return await self._failure(
                guild,
                action,
                channel.id,
                reason,
                "Discord kanal kilidi kaldırmayı reddetti.",
                exc,
            )

        except discord.HTTPException as exc:

            return await self._failure(
                guild,
                action,
                channel.id,
                reason,
                f"Discord API hatası: {exc}",
                exc,
            )

    # ========================================================
    # LOCKDOWN
    # ========================================================

    async def lockdown(
        self,
        guild: discord.Guild,
        *,
        reason: Optional[str] = None,
        channels: Optional[Iterable[discord.TextChannel]] = None,
    ) -> ModerationResult:
        """
        Birden fazla text kanalını hızlı şekilde kilitler.

        asyncio.gather kullanılır.

        Başarılı / başarısız kanallar ayrı raporlanır.
        """

        action = "LOCKDOWN"

        if not self.has_permission(
            guild,
            "manage_channels",
        ):
            return ModerationResult.fail(
                action=action,
                guild_id=guild.id,
                error="Botta manage_channels izni yok.",
            )

        if channels is None:

            selected = [
                channel
                for channel in guild.text_channels
                if not channel.is_news()
            ]

        else:

            selected = list(channels)

        if not selected:
            return ModerationResult.skip(
                action=action,
                guild_id=guild.id,
                error="Lockdown için kanal bulunamadı.",
            )

        audit_reason = self._reason(reason)

        async def lock(
            channel: discord.TextChannel,
        ) -> ModerationResult:

            return await self.lock_channel(
                channel,
                reason=audit_reason,
            )

        results = await asyncio.gather(
            *[
                lock(channel)
                for channel in selected
            ],
            return_exceptions=True,
        )

        successful = []
        failed = []

        for channel, result in zip(
            selected,
            results,
        ):

            if isinstance(
                result,
                ModerationResult,
            ):

                if result.success:
                    successful.append(
                        channel.id
                    )
                else:
                    failed.append(
                        {
                            "channel_id": channel.id,
                            "error": result.error,
                        }
                    )

            else:

                failed.append(
                    {
                        "channel_id": channel.id,
                        "error": str(result),
                    }
                )

        # Database lockdown kaydı.
        lockdown_id = None

        if (
            self.database is not None
            and successful
        ):

            try:

                lockdown_id = (
                    await self.database.create_lockdown(
                        guild.id,
                        reason=audit_reason,
                        affected_channels=successful,
                    )
                )

            except Exception as exc:

                moderation_logger.error(
                    "Lockdown database record failed: %s",
                    exc,
                )

        details = {
            "successful": successful,
            "failed": failed,
            "lockdown_id": lockdown_id,
        }

        moderation_logger.critical(
            "LOCKDOWN | guild=%s successful=%s failed=%s",
            guild.id,
            len(successful),
            len(failed),
        )

        return ModerationResult.ok(
            action=action,
            guild_id=guild.id,
            reason=audit_reason,
            details=details,
        )

    # ========================================================
    # UNLOCKDOWN
    # ========================================================

    async def unlockdown(
        self,
        guild: discord.Guild,
        *,
        reason: Optional[str] = None,
    ) -> ModerationResult:
        """
        Aktif lockdown'u kaldırır.
        """

        action = "UNLOCKDOWN"

        if self.database is None:
            return ModerationResult.fail(
                action=action,
                guild_id=guild.id,
                error="DatabaseService bağlı değil.",
            )

        lockdown = (
            await self.database
            .get_active_lockdown(
                guild.id
            )
        )

        if not lockdown:
            return ModerationResult.skip(
                action=action,
                guild_id=guild.id,
                error="Aktif lockdown bulunamadı.",
            )

        channel_ids = lockdown.get(
            "affected_channels",
            [],
        )

        audit_reason = self._reason(reason)

        successful = []
        failed = []

        for channel_id in channel_ids:

            channel = guild.get_channel(
                int(channel_id)
            )

            if not isinstance(
                channel,
                discord.TextChannel,
            ):
                continue

            result = await self.unlock_channel(
                channel,
                reason=audit_reason,
            )

            if result.success:
                successful.append(
                    channel.id
                )
            else:
                failed.append(
                    {
                        "channel_id": channel.id,
                        "error": result.error,
                    }
                )

        await self.database.resolve_lockdown(
            int(lockdown["id"]),
        )

        return ModerationResult.ok(
            action=action,
            guild_id=guild.id,
            reason=audit_reason,
            details={
                "successful": successful,
                "failed": failed,
                "lockdown_id": lockdown["id"],
            },
        )

    # ========================================================
    # DELETE CHANNEL
    # ========================================================

    async def delete_channel(
        self,
        channel: discord.abc.GuildChannel,
        *,
        reason: Optional[str] = None,
    ) -> ModerationResult:
        """
        Kanal siler.

        Güvenlik botunun kendi kontrolünde olmayan rastgele
        silme işlemlerinden ayrıdır; SecurityService karar verir.
        """

        guild = channel.guild

        action = "CHANNEL_DELETE"

        if not self.has_permission(
            guild,
            "manage_channels",
        ):
            return ModerationResult.fail(
                action=action,
                guild_id=guild.id,
                target_id=channel.id,
                error="Botta manage_channels izni yok.",
            )

        audit_reason = self._reason(reason)

        try:

            await channel.delete(
                reason=audit_reason
            )

            await self._record_action(
                guild=guild,
                action=action,
                target_id=channel.id,
                success=True,
                reason=audit_reason,
            )

            moderation_logger.warning(
                "CHANNEL DELETE | guild=%s channel=%s",
                guild.id,
                channel.id,
            )

            return ModerationResult.ok(
                action=action,
                guild_id=guild.id,
                target_id=channel.id,
                reason=audit_reason,
            )

        except discord.Forbidden as exc:

            return await self._failure(
                guild,
                action,
                channel.id,
                reason,
                "Discord kanal silme işlemini reddetti.",
                exc,
            )

        except discord.NotFound as exc:

            return await self._failure(
                guild,
                action,
                channel.id,
                reason,
                "Kanal zaten silinmiş.",
                exc,
            )

        except discord.HTTPException as exc:

            return await self._failure(
                guild,
                action,
                channel.id,
                reason,
                f"Discord API hatası: {exc}",
                exc,
            )

    # ========================================================
    # INTERNAL ACTION RECORD
    # ========================================================

    async def _record_action(
        self,
        *,
        guild: discord.Guild,
        action: str,
        target_id: Optional[int],
        success: bool,
        reason: Optional[str],
        details: Optional[dict] = None,
    ) -> None:
        """
        DatabaseService varsa action history kaydeder.
        """

        if self.database is None:
            return

        try:

            await self.database.add_action(
                guild.id,
                action,
                target_id=target_id,
                success=success,
                reason=reason,
                details=details,
            )

        except Exception as exc:

            # Database loglama hatası Discord moderasyon
            # işlemini başarısız saydırmamalı.
            moderation_logger.error(
                "Action history write failed | "
                "action=%s guild=%s target=%s error=%s",
                action,
                guild.id,
                target_id,
                exc,
            )

    # ========================================================
    # INTERNAL FAILURE
    # ========================================================

    async def _failure(
        self,
        guild: discord.Guild,
        action: str,
        target_id: Optional[int],
        reason: Optional[str],
        message: str,
        exception: Optional[Exception] = None,
    ) -> ModerationResult:
        """
        Merkezi hata sonucu oluşturur.
        """

        error_text = message

        if exception is not None:
            moderation_logger.error(
                "%s | guild=%s target=%s error=%s",
                action,
                guild.id,
                target_id,
                exception,
            )

        await self._record_action(
            guild=guild,
            action=action,
            target_id=target_id,
            success=False,
            reason=reason,
            details={
                "error": error_text,
            },
        )

        return ModerationResult.fail(
            action=action,
            guild_id=guild.id,
            target_id=target_id,
            reason=reason,
            error=error_text,
        )


# ============================================================
# GLOBAL INSTANCE
# ============================================================

moderation_service: Optional[ModerationService] = None


def setup_moderation_service(
    bot: discord.Client,
    database=None,
) -> ModerationService:
    """
    Global moderation service oluşturur.

    main.py:

        moderation_service = setup_moderation_service(
            bot,
            database_service,
        )
    """

    global moderation_service

    moderation_service = ModerationService(
        bot,
        database,
    )

    return moderation_service


# ============================================================
# EXPORTS
# ============================================================

__all__ = [
    "ModerationService",
    "ModerationResult",
    "moderation_service",
    "setup_moderation_service",
]