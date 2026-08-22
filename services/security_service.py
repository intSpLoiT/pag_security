# services/security.py

from __future__ import annotations

import asyncio
import time

from collections import defaultdict, deque
from dataclasses import dataclass, field
from typing import Optional, Iterable

import discord

from utils.logger import security_logger


# ============================================================
# PAG SECURITY BOT
# services/security.py
#
# Discord olaylarını izleyen düşük-overhead Security Engine.
#
# SORUMLULUKLAR:
# - Audit Log actor tespiti
# - Kick / Ban takibi
# - Channel delete / create takibi
# - Role delete / create / update takibi
# - Permission değişiklikleri
# - Bot ekleme takibi
# - Webhook takibi
# - Mass action detection
# - Emergency trigger
# - Risk hesaplama
# - Protected user sistemi
# - Approval sistemi
#
# BU DOSYA:
# - ModerationService'in yerine geçmez.
# - Nihai Discord moderasyon işlemlerini kendisi yapmaz.
# - SecurityService'e karar için veri sağlar.
#
# discord.py 2.x
# ============================================================


# ============================================================
# CONSTANTS
# ============================================================

DEFAULT_WINDOW_SECONDS = 12

MAX_EVENT_HISTORY = 200

AUDIT_LOG_LIMIT = 8

# Emergency eşikleri
DEFAULT_KICK_THRESHOLD = 5
DEFAULT_CHANNEL_DELETE_THRESHOLD = 5
DEFAULT_CHANNEL_CREATE_THRESHOLD = 10
DEFAULT_ROLE_DELETE_THRESHOLD = 3
DEFAULT_ROLE_CREATE_THRESHOLD = 5
DEFAULT_ROLE_UPDATE_THRESHOLD = 5
DEFAULT_PERMISSION_CHANGE_THRESHOLD = 3
DEFAULT_BOT_ADD_THRESHOLD = 2
DEFAULT_WEBHOOK_THRESHOLD = 3

# Aynı audit-log eventinin tekrar işlenmesini engeller.
AUDIT_CACHE_TTL = 30

# Emergency sonrası event'leri bir süre hızlı değerlendirme.
EMERGENCY_COOLDOWN = 30

# Risk puanları
RISK_KICK = 20
RISK_BAN = 30
RISK_CHANNEL_DELETE = 30
RISK_CHANNEL_CREATE = 20
RISK_ROLE_DELETE = 35
RISK_ROLE_CREATE = 25
RISK_ROLE_UPDATE = 25
RISK_PERMISSION_CHANGE = 45
RISK_BOT_ADD = 40
RISK_WEBHOOK = 30


# ============================================================
# EVENT TYPES
# ============================================================

EVENT_KICK = "KICK"
EVENT_BAN = "BAN"

EVENT_CHANNEL_DELETE = "CHANNEL_DELETE"
EVENT_CHANNEL_CREATE = "CHANNEL_CREATE"

EVENT_ROLE_DELETE = "ROLE_DELETE"
EVENT_ROLE_CREATE = "ROLE_CREATE"
EVENT_ROLE_UPDATE = "ROLE_UPDATE"

EVENT_PERMISSION_CHANGE = "PERMISSION_CHANGE"

EVENT_BOT_ADD = "BOT_ADD"

EVENT_WEBHOOK_CREATE = "WEBHOOK_CREATE"
EVENT_WEBHOOK_DELETE = "WEBHOOK_DELETE"

EVENT_MEMBER_ROLE_UPDATE = "MEMBER_ROLE_UPDATE"


# ============================================================
# SECURITY EVENT
# ============================================================

@dataclass(slots=True)
class SecurityEvent:
    """
    Security engine tarafından oluşturulan tek olay.
    """

    guild_id: int

    event_type: str

    actor_id: Optional[int] = None

    target_id: Optional[int] = None

    target_name: Optional[str] = None

    timestamp: float = field(
        default_factory=time.monotonic
    )

    risk: int = 0

    details: dict = field(
        default_factory=dict
    )

    trusted: bool = False


# ============================================================
# SECURITY DECISION
# ============================================================

@dataclass(slots=True)
class SecurityDecision:
    """
    Security engine karar sonucu.
    """

    emergency: bool = False

    quarantine: bool = False

    lockdown: bool = False

    remove_roles: bool = False

    require_approval: bool = False

    reason: str = ""

    risk: int = 0

    actor_id: Optional[int] = None

    event_type: Optional[str] = None

    details: dict = field(
        default_factory=dict
    )


# ============================================================
# CONFIG
# ============================================================

@dataclass(slots=True)
class SecurityConfig:
    """
    Security ayarları.

    Bunların çoğu ileride panel_service üzerinden
    değiştirilebilir.

    .env sadece kritik temel ayarları taşımalıdır.
    """

    window_seconds: int = DEFAULT_WINDOW_SECONDS

    kick_threshold: int = DEFAULT_KICK_THRESHOLD

    channel_delete_threshold: int = (
        DEFAULT_CHANNEL_DELETE_THRESHOLD
    )

    channel_create_threshold: int = (
        DEFAULT_CHANNEL_CREATE_THRESHOLD
    )

    role_delete_threshold: int = (
        DEFAULT_ROLE_DELETE_THRESHOLD
    )

    role_create_threshold: int = (
        DEFAULT_ROLE_CREATE_THRESHOLD
    )

    role_update_threshold: int = (
        DEFAULT_ROLE_UPDATE_THRESHOLD
    )

    permission_change_threshold: int = (
        DEFAULT_PERMISSION_CHANGE_THRESHOLD
    )

    bot_add_threshold: int = (
        DEFAULT_BOT_ADD_THRESHOLD
    )

    webhook_threshold: int = (
        DEFAULT_WEBHOOK_THRESHOLD
    )

    emergency_cooldown: int = (
        EMERGENCY_COOLDOWN
    )

    # Kritik işlemler için approval.
    require_approval_for_kick: bool = True

    require_approval_for_ban: bool = True

    # Emergency sırasında otomatik müdahale.
    emergency_remove_roles: bool = True

    emergency_lockdown: bool = True

    emergency_quarantine: bool = True


# ============================================================
# SECURITY SERVICE
# ============================================================

class SecurityService:
    """
    PAG Security Engine.

    Ana görev:

        Discord Event
              ↓
        Actor Detection
              ↓
        Event Tracking
              ↓
        Risk Calculation
              ↓
        Rule Evaluation
              ↓
        SecurityDecision
              ↓
        security_service.py
              ↓
        ModerationService

    Not:

    Bu sınıf mümkün olduğunca hafif tutulmuştur.
    Her event için ağır işlem çalıştırmak yerine küçük
    deque yapıları ve audit-log sorguları kullanır.
    """

    def __init__(
        self,
        bot: discord.Client,
        moderation=None,
        panel=None,
        config: Optional[SecurityConfig] = None,
    ) -> None:

        self.bot = bot

        self.moderation = moderation

        self.panel = panel

        self.config = (
            config
            or SecurityConfig()
        )

        # ----------------------------------------------------
        # Event history
        #
        # guild_id
        #     actor_id
        #         event_type -> deque[timestamp]
        # ----------------------------------------------------

        self._events: dict[
            int,
            dict[
                int,
                dict[
                    str,
                    deque[float]
                ]
            ]
        ] = defaultdict(
            lambda: defaultdict(
                lambda: defaultdict(
                    lambda: deque(
                        maxlen=MAX_EVENT_HISTORY
                    )
                )
            )
        )

        # Actor toplam risk.
        self._risk: dict[
            int,
            dict[int, int]
        ] = defaultdict(
            lambda: defaultdict(int)
        )

        # Son emergency zamanı.
        self._emergency_at: dict[
            int,
            float
        ] = {}

        # Audit-log event cache.
        self._audit_cache: dict[
            tuple[int, int, str],
            float
        ] = {}

        # Aynı anda birden fazla emergency işleminin
        # çalışmasını engeller.
        self._emergency_locks: dict[
            int,
            asyncio.Lock
        ] = defaultdict(
            asyncio.Lock
        )

        # Actor whitelist.
        self._trusted_users: dict[
            int,
            set[int]
        ] = defaultdict(set)

        # Approval sahipleri.
        self._approval_users: dict[
            int,
            set[int]
        ] = defaultdict(set)

        # Sistem açık mı?
        self.enabled = True

        # İstatistikler.
        self.events_processed = 0

        self.emergency_count = 0

        # Security log.
        security_logger.info(
            "SecurityService initialized."
        )

    # ========================================================
    # CONFIG
    # ========================================================

    def update_config(
        self,
        **values,
    ) -> None:
        """
        Panel tarafından runtime config güncellemek için.

        Örnek:

            security.update_config(
                kick_threshold=5,
                channel_delete_threshold=5,
            )
        """

        for key, value in values.items():

            if not hasattr(
                self.config,
                key,
            ):
                continue

            current = getattr(
                self.config,
                key,
            )

            try:

                if isinstance(
                    current,
                    bool,
                ):
                    value = bool(value)

                elif isinstance(
                    current,
                    int,
                ):
                    value = int(value)

            except (
                TypeError,
                ValueError,
            ):
                continue

            setattr(
                self.config,
                key,
                value,
            )

        security_logger.info(
            "Security configuration updated."
        )

    # ========================================================
    # TRUST
    # ========================================================

    def add_trusted_user(
        self,
        guild_id: int,
        user_id: int,
    ) -> None:
        """
        Güvenilir kullanıcı ekler.
        """

        self._trusted_users[
            guild_id
        ].add(user_id)

    def remove_trusted_user(
        self,
        guild_id: int,
        user_id: int,
    ) -> None:
        """
        Güvenilir kullanıcıyı kaldırır.
        """

        self._trusted_users[
            guild_id
        ].discard(user_id)

    def is_trusted(
        self,
        guild: discord.Guild,
        user_id: int,
    ) -> bool:
        """
        Actor güvenilir mi?

        ÖNEMLİ:

        Administrator olmak güvenilirlik anlamına gelmez.

        Sunucu sahibi ise Discord hierarchy gereği
        zaten bot tarafından hedeflenemez; ancak event
        güvenilirlik kontrolünde ayrı tutulur.
        """

        if user_id in self._trusted_users[
            guild.id
        ]:
            return True

        if user_id == guild.owner_id:
            return True

        return False

    # ========================================================
    # APPROVAL
    # ========================================================

    def add_approval_user(
        self,
        guild_id: int,
        user_id: int,
    ) -> None:
        """
        Kritik işlemleri onaylayabilecek kullanıcı.
        """

        self._approval_users[
            guild_id
        ].add(user_id)

    def remove_approval_user(
        self,
        guild_id: int,
        user_id: int,
    ) -> None:

        self._approval_users[
            guild_id
        ].discard(user_id)

    def requires_approval(
        self,
        event_type: str,
    ) -> bool:
        """
        Kick / Ban işlemleri için approval gerekir mi?
        """

        if event_type == EVENT_KICK:
            return self.config.require_approval_for_kick

        if event_type == EVENT_BAN:
            return self.config.require_approval_for_ban

        return False

    def can_approve(
        self,
        guild_id: int,
        user_id: int,
    ) -> bool:
        return user_id in self._approval_users[
            guild_id
        ]

    # ========================================================
    # CLEANUP
    # ========================================================

    def _cleanup_actor(
        self,
        guild_id: int,
        actor_id: int,
        event_type: str,
        now: float,
    ) -> None:
        """
        Eski eventleri deque'den temizler.
        """

        queue = self._events[
            guild_id
        ][
            actor_id
        ][
            event_type
        ]

        cutoff = (
            now
            - self.config.window_seconds
        )

        while queue and queue[0] < cutoff:
            queue.popleft()

    def _cleanup_audit_cache(
        self,
        now: float,
    ) -> None:
        """
        Eski audit cache kayıtlarını temizler.
        """

        expired = [
            key
            for key, timestamp
            in self._audit_cache.items()
            if (
                now - timestamp
                > AUDIT_CACHE_TTL
            )
        ]

        for key in expired:
            self._audit_cache.pop(
                key,
                None,
            )

    # ========================================================
    # EVENT COUNT
    # ========================================================

    def get_event_count(
        self,
        guild_id: int,
        actor_id: int,
        event_type: str,
    ) -> int:
        """
        Actor'ın aktif zaman penceresindeki event sayısı.
        """

        now = time.monotonic()

        self._cleanup_actor(
            guild_id,
            actor_id,
            event_type,
            now,
        )

        return len(
            self._events[
                guild_id
            ][
                actor_id
            ][
                event_type
            ]
        )

    # ========================================================
    # RECORD EVENT
    # ========================================================

    def record_event(
        self,
        event: SecurityEvent,
    ) -> SecurityDecision:
        """
        Security event'i kaydeder ve karar üretir.
        """

        if not self.enabled:
            return SecurityDecision()

        if event.actor_id is None:
            return SecurityDecision(
                reason="Actor bulunamadı."
            )

        self.events_processed += 1

        guild_id = event.guild_id
        actor_id = event.actor_id
        event_type = event.event_type

        now = time.monotonic()

        event.timestamp = now

        # ----------------------------------------------------
        # Trusted actor
        # ----------------------------------------------------

        guild = self.bot.get_guild(
            guild_id
        )

        if guild is not None:

            event.trusted = self.is_trusted(
                guild,
                actor_id,
            )

        # Trusted actor eventleri istatistik için
        # kaydedilebilir ancak emergency tetiklemez.
        self._events[
            guild_id
        ][
            actor_id
        ][
            event_type
        ].append(now)

        # ----------------------------------------------------
        # Risk
        # ----------------------------------------------------

        event.risk = self._risk_value(
            event_type
        )

        self._risk[
            guild_id
        ][
            actor_id
        ] += event.risk

        if event.trusted:

            security_logger.debug(
                "Trusted security event | "
                "guild=%s actor=%s event=%s",
                guild_id,
                actor_id,
                event_type,
            )

            return SecurityDecision(
                actor_id=actor_id,
                event_type=event_type,
                risk=event.risk,
                reason="Trusted actor.",
            )

        # ----------------------------------------------------
        # Threshold
        # ----------------------------------------------------

        count = self.get_event_count(
            guild_id,
            actor_id,
            event_type,
        )

        decision = self._evaluate(
            event=event,
            count=count,
        )

        if decision.emergency:

            security_logger.critical(
                "EMERGENCY TRIGGER | "
                "guild=%s actor=%s event=%s "
                "count=%s risk=%s reason=%s",
                guild_id,
                actor_id,
                event_type,
                count,
                decision.risk,
                decision.reason,
            )

        elif decision.quarantine:

            security_logger.warning(
                "SECURITY ACTION | "
                "guild=%s actor=%s event=%s "
                "count=%s reason=%s",
                guild_id,
                actor_id,
                event_type,
                count,
                decision.reason,
            )

        return decision

    # ========================================================
    # RISK
    # ========================================================

    @staticmethod
    def _risk_value(
        event_type: str,
    ) -> int:

        return {
            EVENT_KICK: RISK_KICK,
            EVENT_BAN: RISK_BAN,
            EVENT_CHANNEL_DELETE: RISK_CHANNEL_DELETE,
            EVENT_CHANNEL_CREATE: RISK_CHANNEL_CREATE,
            EVENT_ROLE_DELETE: RISK_ROLE_DELETE,
            EVENT_ROLE_CREATE: RISK_ROLE_CREATE,
            EVENT_ROLE_UPDATE: RISK_ROLE_UPDATE,
            EVENT_PERMISSION_CHANGE: RISK_PERMISSION_CHANGE,
            EVENT_BOT_ADD: RISK_BOT_ADD,
            EVENT_WEBHOOK_CREATE: RISK_WEBHOOK,
            EVENT_WEBHOOK_DELETE: RISK_WEBHOOK,
            EVENT_MEMBER_ROLE_UPDATE: RISK_PERMISSION_CHANGE,
        }.get(
            event_type,
            5,
        )

    # ========================================================
    # EVALUATION
    # ========================================================

    def _evaluate(
        self,
        event: SecurityEvent,
        count: int,
    ) -> SecurityDecision:
        """
        Event + count üzerinden security kararı verir.
        """

        event_type = event.event_type

        # ----------------------------------------------------
        # KICK
        # ----------------------------------------------------

        if event_type == EVENT_KICK:

            if count >= self.config.kick_threshold:

                return SecurityDecision(
                    emergency=True,
                    quarantine=True,
                    lockdown=True,
                    remove_roles=True,
                    require_approval=True,
                    reason=(
                        f"{count} kısa süre içinde "
                        "kick tespit edildi."
                    ),
                    risk=self._risk[
                        event.guild_id
                    ][
                        event.actor_id
                    ],
                    actor_id=event.actor_id,
                    event_type=event_type,
                    details={
                        "count": count,
                        "threshold": (
                            self.config.kick_threshold
                        ),
                    },
                )

        # ----------------------------------------------------
        # CHANNEL DELETE
        # ----------------------------------------------------

        if event_type == EVENT_CHANNEL_DELETE:

            if count >= (
                self.config.channel_delete_threshold
            ):

                return SecurityDecision(
                    emergency=True,
                    quarantine=True,
                    lockdown=True,
                    remove_roles=True,
                    reason=(
                        f"{count} kanal silme işlemi "
                        "tespit edildi."
                    ),
                    risk=self._risk[
                        event.guild_id
                    ][
                        event.actor_id
                    ],
                    actor_id=event.actor_id,
                    event_type=event_type,
                    details={
                        "count": count,
                        "threshold": (
                            self.config
                            .channel_delete_threshold
                        ),
                    },
                )

        # ----------------------------------------------------
        # CHANNEL CREATE
        # ----------------------------------------------------

        if event_type == EVENT_CHANNEL_CREATE:

            if count >= (
                self.config.channel_create_threshold
            ):

                return SecurityDecision(
                    emergency=True,
                    quarantine=True,
                    lockdown=True,
                    remove_roles=True,
                    reason=(
                        f"{count} kanal oluşturma işlemi "
                        "tespit edildi."
                    ),
                    risk=self._risk[
                        event.guild_id
                    ][
                        event.actor_id
                    ],
                    actor_id=event.actor_id,
                    event_type=event_type,
                    details={
                        "count": count,
                        "threshold": (
                            self.config
                            .channel_create_threshold
                        ),
                    },
                )

        # ----------------------------------------------------
        # ROLE DELETE
        # ----------------------------------------------------

        if event_type == EVENT_ROLE_DELETE:

            if count >= (
                self.config.role_delete_threshold
            ):

                return SecurityDecision(
                    emergency=True,
                    quarantine=True,
                    lockdown=True,
                    remove_roles=True,
                    reason=(
                        f"{count} rol silme işlemi "
                        "tespit edildi."
                    ),
                    risk=self._risk[
                        event.guild_id
                    ][
                        event.actor_id
                    ],
                    actor_id=event.actor_id,
                    event_type=event_type,
                    details={
                        "count": count,
                        "threshold": (
                            self.config
                            .role_delete_threshold
                        ),
                    },
                )

        # ----------------------------------------------------
        # ROLE CREATE
        # ----------------------------------------------------

        if event_type == EVENT_ROLE_CREATE:

            if count >= (
                self.config.role_create_threshold
            ):

                return SecurityDecision(
                    emergency=True,
                    quarantine=True,
                    lockdown=True,
                    remove_roles=True,
                    reason=(
                        f"{count} rol oluşturma işlemi "
                        "tespit edildi."
                    ),
                    risk=self._risk[
                        event.guild_id
                    ][
                        event.actor_id
                    ],
                    actor_id=event.actor_id,
                    event_type=event_type,
                    details={
                        "count": count,
                        "threshold": (
                            self.config
                            .role_create_threshold
                        ),
                    },
                )

        # ----------------------------------------------------
        # ROLE UPDATE
        # ----------------------------------------------------

        if event_type == EVENT_ROLE_UPDATE:

            if count >= (
                self.config.role_update_threshold
            ):

                return SecurityDecision(
                    emergency=True,
                    quarantine=True,
                    lockdown=True,
                    remove_roles=True,
                    reason=(
                        f"{count} rol güncellemesi "
                        "tespit edildi."
                    ),
                    risk=self._risk[
                        event.guild_id
                    ][
                        event.actor_id
                    ],
                    actor_id=event.actor_id,
                    event_type=event_type,
                    details={
                        "count": count,
                        "threshold": (
                            self.config
                            .role_update_threshold
                        ),
                    },
                )

        # ----------------------------------------------------
        # PERMISSION CHANGE
        # ----------------------------------------------------

        if event_type == EVENT_PERMISSION_CHANGE:

            if count >= (
                self.config.permission_change_threshold
            ):

                return SecurityDecision(
                    emergency=True,
                    quarantine=True,
                    lockdown=True,
                    remove_roles=True,
                    reason=(
                        f"{count} kritik permission "
                        "değişikliği tespit edildi."
                    ),
                    risk=self._risk[
                        event.guild_id
                    ][
                        event.actor_id
                    ],
                    actor_id=event.actor_id,
                    event_type=event_type,
                    details={
                        "count": count,
                        "threshold": (
                            self.config
                            .permission_change_threshold
                        ),
                    },
                )

        # ----------------------------------------------------
        # BOT ADD
        # ----------------------------------------------------

        if event_type == EVENT_BOT_ADD:

            if count >= (
                self.config.bot_add_threshold
            ):

                return SecurityDecision(
                    emergency=True,
                    quarantine=True,
                    lockdown=True,
                    remove_roles=True,
                    reason=(
                        f"{count} bot ekleme işlemi "
                        "tespit edildi."
                    ),
                    risk=self._risk[
                        event.guild_id
                    ][
                        event.actor_id
                    ],
                    actor_id=event.actor_id,
                    event_type=event_type,
                    details={
                        "count": count,
                        "threshold": (
                            self.config.bot_add_threshold
                        ),
                    },
                )

        # ----------------------------------------------------
        # WEBHOOK
        # ----------------------------------------------------

        if event_type in (
            EVENT_WEBHOOK_CREATE,
            EVENT_WEBHOOK_DELETE,
        ):

            if count >= (
                self.config.webhook_threshold
            ):

                return SecurityDecision(
                    emergency=True,
                    quarantine=True,
                    lockdown=True,
                    remove_roles=True,
                    reason=(
                        f"{count} webhook işlemi "
                        "tespit edildi."
                    ),
                    risk=self._risk[
                        event.guild_id
                    ][
                        event.actor_id
                    ],
                    actor_id=event.actor_id,
                    event_type=event_type,
                    details={
                        "count": count,
                        "threshold": (
                            self.config
                            .webhook_threshold
                        ),
                    },
                )

        # ----------------------------------------------------
        # HIGH RISK SINGLE EVENT
        # ----------------------------------------------------

        actor_risk = self._risk[
            event.guild_id
        ][
            event.actor_id
        ]

        if (
            event_type
            == EVENT_PERMISSION_CHANGE
            and actor_risk >= 100
        ):

            return SecurityDecision(
                quarantine=True,
                remove_roles=True,
                reason=(
                    "Actor yüksek risk seviyesine ulaştı."
                ),
                risk=actor_risk,
                actor_id=event.actor_id,
                event_type=event_type,
            )

        return SecurityDecision(
            actor_id=event.actor_id,
            event_type=event_type,
            risk=event.risk,
        )

    # ========================================================
    # AUDIT LOG ACTOR
    # ========================================================

    async def find_audit_actor(
        self,
        guild: discord.Guild,
        action: discord.AuditLogAction,
        *,
        target_id: Optional[int] = None,
        retries: int = 3,
        delay: float = 0.35,
    ) -> Optional[discord.User]:
        """
        Discord audit log üzerinden işlemi yapan kişiyi bulur.

        Discord audit log eventleri gerçek eventten biraz
        sonra gelebileceği için birkaç kısa retry yapılır.

        Bu sayede:

            channel delete
                    ↓
              audit log gecikmesi
                    ↓
                 actor

        problemi azaltılır.
        """

        if not guild.me:
            return None

        if not guild.me.guild_permissions.view_audit_log:
            security_logger.error(
                "Missing View Audit Log permission | guild=%s",
                guild.id,
            )

            return None

        now = time.monotonic()

        self._cleanup_audit_cache(now)

        for attempt in range(
            retries
        ):

            try:

                async for entry in guild.audit_logs(
                    limit=AUDIT_LOG_LIMIT,
                    action=action,
                ):

                    # Çok eski entry'leri kullanma.
                    if entry.created_at is not None:

                        age = (
                            discord.utils.utcnow()
                            - entry.created_at
                        ).total_seconds()

                        if age > 15:
                            continue

                    if target_id is not None:

                        entry_target = getattr(
                            entry.target,
                            "id",
                            None,
                        )

                        if (
                            entry_target
                            != target_id
                        ):
                            continue

                    actor = entry.user

                    if actor is None:
                        continue

                    cache_key = (
                        guild.id,
                        entry.id,
                        str(action),
                    )

                    if (
                        cache_key
                        in self._audit_cache
                    ):
                        continue

                    self._audit_cache[
                        cache_key
                    ] = now

                    return actor

            except discord.Forbidden:

                security_logger.error(
                    "Audit log access denied | guild=%s",
                    guild.id,
                )

                return None

            except discord.HTTPException as exc:

                security_logger.warning(
                    "Audit log request failed | "
                    "guild=%s attempt=%s error=%s",
                    guild.id,
                    attempt + 1,
                    exc,
                )

            except Exception as exc:

                security_logger.error(
                    "Unexpected audit log error | "
                    "guild=%s error=%s",
                    guild.id,
                    exc,
                )

            if attempt < retries - 1:
                await asyncio.sleep(delay)

        return None

    # ========================================================
    # PROCESS AUDIT EVENT
    # ========================================================

    async def process_audit_event(
        self,
        guild: discord.Guild,
        *,
        action: discord.AuditLogAction,
        event_type: str,
        target_id: Optional[int] = None,
        details: Optional[dict] = None,
    ) -> SecurityDecision:
        """
        Audit-log tabanlı event'i security engine'e aktarır.
        """

        actor = await self.find_audit_actor(
            guild,
            action,
            target_id=target_id,
        )

        if actor is None:

            security_logger.warning(
                "Unable to identify audit actor | "
                "guild=%s action=%s target=%s",
                guild.id,
                action,
                target_id,
            )

            return SecurityDecision(
                event_type=event_type,
                reason="Audit actor bulunamadı.",
            )

        event = SecurityEvent(
            guild_id=guild.id,
            event_type=event_type,
            actor_id=actor.id,
            target_id=target_id,
            target_name=getattr(
                actor,
                "name",
                None,
            ),
            details=details or {},
        )

        decision = self.record_event(
            event
        )

        # Emergency kararını dış service'e aktar.
        if decision.emergency:

            await self.handle_emergency(
                guild,
                decision,
            )

        return decision

    # ========================================================
    # MEMBER REMOVE
    # ========================================================

    async def on_member_remove(
        self,
        member: discord.Member,
    ) -> SecurityDecision:
        """
        Member remove event'i.

        Discord bunu doğrudan kick mi ban mı diye ayırmaz.
        Önce ban audit log kontrol edilir.
        """

        guild = member.guild

        # ----------------------------------------------------
        # BAN
        # ----------------------------------------------------

        actor = await self.find_audit_actor(
            guild,
            discord.AuditLogAction.ban,
            target_id=member.id,
            retries=2,
            delay=0.25,
        )

        if actor is not None:

            event = SecurityEvent(
                guild_id=guild.id,
                event_type=EVENT_BAN,
                actor_id=actor.id,
                target_id=member.id,
            )

            decision = self.record_event(
                event
            )

            if decision.emergency:
                await self.handle_emergency(
                    guild,
                    decision,
                )

            return decision

        # ----------------------------------------------------
        # KICK
        # ----------------------------------------------------

        actor = await self.find_audit_actor(
            guild,
            discord.AuditLogAction.kick,
            target_id=member.id,
            retries=2,
            delay=0.25,
        )

        if actor is not None:

            event = SecurityEvent(
                guild_id=guild.id,
                event_type=EVENT_KICK,
                actor_id=actor.id,
                target_id=member.id,
            )

            decision = self.record_event(
                event
            )

            if decision.emergency:
                await self.handle_emergency(
                    guild,
                    decision,
                )

            return decision

        return SecurityDecision(
            reason="Member remove kaynağı belirlenemedi."
        )

    # ========================================================
    # CHANNEL DELETE
    # ========================================================

    async def on_channel_delete(
        self,
        channel: discord.abc.GuildChannel,
    ) -> SecurityDecision:

        return await self.process_audit_event(
            channel.guild,
            action=discord.AuditLogAction.channel_delete,
            event_type=EVENT_CHANNEL_DELETE,
            target_id=channel.id,
            details={
                "channel_name": channel.name,
                "channel_type": str(
                    channel.type
                ),
            },
        )

    # ========================================================
    # CHANNEL CREATE
    # ========================================================

    async def on_channel_create(
        self,
        channel: discord.abc.GuildChannel,
    ) -> SecurityDecision:

        return await self.process_audit_event(
            channel.guild,
            action=discord.AuditLogAction.channel_create,
            event_type=EVENT_CHANNEL_CREATE,
            target_id=channel.id,
            details={
                "channel_name": channel.name,
                "channel_type": str(
                    channel.type
                ),
            },
        )

    # ========================================================
    # ROLE DELETE
    # ========================================================

    async def on_role_delete(
        self,
        role: discord.Role,
    ) -> SecurityDecision:

        return await self.process_audit_event(
            role.guild,
            action=discord.AuditLogAction.role_delete,
            event_type=EVENT_ROLE_DELETE,
            target_id=role.id,
            details={
                "role_name": role.name,
                "position": role.position,
            },
        )

    # ========================================================
    # ROLE CREATE
    # ========================================================

    async def on_role_create(
        self,
        role: discord.Role,
    ) -> SecurityDecision:

        return await self.process_audit_event(
            role.guild,
            action=discord.AuditLogAction.role_create,
            event_type=EVENT_ROLE_CREATE,
            target_id=role.id,
            details={
                "role_name": role.name,
                "position": role.position,
                "permissions": role.permissions.value,
            },
        )

    # ========================================================
    # ROLE UPDATE
    # ========================================================

    async def on_role_update(
        self,
        before: discord.Role,
        after: discord.Role,
    ) -> SecurityDecision:

        details = {
            "role_id": after.id,
            "before_permissions": (
                before.permissions.value
            ),
            "after_permissions": (
                after.permissions.value
            ),
        }

        permission_changed = (
            before.permissions.value
            != after.permissions.value
        )

        event_type = (
            EVENT_PERMISSION_CHANGE
            if permission_changed
            else EVENT_ROLE_UPDATE
        )

        return await self.process_audit_event(
            after.guild,
            action=discord.AuditLogAction.role_update,
            event_type=event_type,
            target_id=after.id,
            details=details,
        )

    # ========================================================
    # MEMBER ROLE UPDATE
    # ========================================================

    async def on_member_update(
        self,
        before: discord.Member,
        after: discord.Member,
    ) -> Optional[SecurityDecision]:
        """
        Member role değişikliklerini izler.

        Özellikle nuke sırasında saldırganın başka
        kullanıcılara Admin / Manage Guild gibi roller
        vermesi için kullanılabilir.
        """

        before_roles = {
            role.id
            for role in before.roles
        }

        after_roles = {
            role.id
            for role in after.roles
        }

        if before_roles == after_roles:
            return None

        added = after_roles - before_roles

        removed = before_roles - after_roles

        if not added and not removed:
            return None

        return await self.process_audit_event(
            after.guild,
            action=discord.AuditLogAction.member_role_update,
            event_type=EVENT_MEMBER_ROLE_UPDATE,
            target_id=after.id,
            details={
                "added_role_ids": list(
                    added
                ),
                "removed_role_ids": list(
                    removed
                ),
            },
        )

    # ========================================================
    # MEMBER JOIN
    # ========================================================

    async def on_member_join(
        self,
        member: discord.Member,
    ) -> Optional[SecurityDecision]:
        """
        Yeni katılan kullanıcı bot ise kim eklediğini
        audit log üzerinden kontrol eder.
        """

        if not member.bot:
            return None

        return await self.process_audit_event(
            member.guild,
            action=discord.AuditLogAction.bot_add,
            event_type=EVENT_BOT_ADD,
            target_id=member.id,
            details={
                "bot_id": member.id,
                "bot_name": member.name,
            },
        )

    # ========================================================
    # WEBHOOK
    # ========================================================

    async def process_webhook_create(
        self,
        guild: discord.Guild,
        webhook_id: Optional[int] = None,
    ) -> SecurityDecision:

        return await self.process_audit_event(
            guild,
            action=discord.AuditLogAction.webhook_create,
            event_type=EVENT_WEBHOOK_CREATE,
            target_id=webhook_id,
        )

    async def process_webhook_delete(
        self,
        guild: discord.Guild,
        webhook_id: Optional[int] = None,
    ) -> SecurityDecision:

        return await self.process_audit_event(
            guild,
            action=discord.AuditLogAction.webhook_delete,
            event_type=EVENT_WEBHOOK_DELETE,
            target_id=webhook_id,
        )

    # ========================================================
    # EMERGENCY
    # ========================================================

    async def handle_emergency(
        self,
        guild: discord.Guild,
        decision: SecurityDecision,
    ) -> None:
        """
        Emergency durumunu işler.

        ÖNEMLİ:

        Burada botun kendi ModerationService'i kullanılır.

        Öncelik:

        1. Saldırganın yönetilebilir rollerini kaldır
        2. Gerekirse quarantine
        3. Lockdown
        4. SecurityService'e bildir
        5. Logla

        Botun hiyerarşisinin üstündeki saldırgan rolü
        Discord tarafından kaldırılamaz.
        Bu nedenle ayrıca protected-role alarmı verilir.
        """

        actor_id = decision.actor_id

        if actor_id is None:
            return

        lock = self._emergency_locks[
            guild.id
        ]

        async with lock:

            now = time.monotonic()

            previous = self._emergency_at.get(
                guild.id,
                0,
            )

            # Aynı saldırı dalgasında emergency'i
            # tekrar tekrar başlatma.
            if (
                now - previous
                < self.config.emergency_cooldown
            ):
                security_logger.warning(
                    "Emergency already active | guild=%s",
                    guild.id,
                )

                return

            self._emergency_at[
                guild.id
            ] = now

            self.emergency_count += 1

            security_logger.critical(
                "========== EMERGENCY =========="
            )

            security_logger.critical(
                "guild=%s actor=%s event=%s",
                guild.id,
                actor_id,
                decision.event_type,
            )

            security_logger.critical(
                "reason=%s risk=%s",
                decision.reason,
                decision.risk,
            )

            # ------------------------------------------------
            # Actor çözümleme
            # ------------------------------------------------

            actor = guild.get_member(
                actor_id
            )

            if actor is None:

                actor = await self._resolve_member(
                    guild,
                    actor_id,
                )

            if actor is None:

                security_logger.error(
                    "Emergency actor could not be resolved | "
                    "guild=%s actor=%s",
                    guild.id,
                    actor_id,
                )

                # Lockdown yine de uygulanabilir.
                actor = None

            # ------------------------------------------------
            # ModerationService
            # ------------------------------------------------

            if self.moderation is None:

                security_logger.critical(
                    "Emergency moderation unavailable: "
                    "ModerationService not connected."
                )

            else:

                # --------------------------------------------
                # ROLE REMOVE
                # --------------------------------------------

                if (
                    actor is not None
                    and decision.remove_roles
                    and self.config.emergency_remove_roles
                ):

                    await self._emergency_remove_roles(
                        actor,
                        decision,
                    )

                # --------------------------------------------
                # QUARANTINE
                # --------------------------------------------

                if (
                    actor is not None
                    and decision.quarantine
                    and self.config.emergency_quarantine
                ):

                    await self._emergency_quarantine(
                        actor,
                        decision,
                    )

                # --------------------------------------------
                # LOCKDOWN
                # --------------------------------------------

                if (
                    decision.lockdown
                    and self.config.emergency_lockdown
                ):

                    await self._emergency_lockdown(
                        guild,
                        decision,
                    )

            # ------------------------------------------------
            # SecurityService callback
            # ------------------------------------------------

            await self._notify_security_service(
                guild,
                decision,
            )

            security_logger.critical(
                "========== EMERGENCY END =========="
            )

    # ========================================================
    # EMERGENCY ROLE REMOVE
    # ========================================================

    async def _emergency_remove_roles(
        self,
        member: discord.Member,
        decision: SecurityDecision,
    ) -> None:
        """
        Saldırganın botun yönetebildiği bütün rollerini
        hızlı şekilde kaldırır.

        Administrator / Manage Guild / Kick Members /
        Manage Channels vb. permission'lara sahip roller
        de böylece kaldırılmış olur.

        Discord hiyerarşisi engel koyarsa işlem yapılmaz.
        """

        roles = []

        for role in member.roles:

            if role.is_default():
                continue

            if role.managed:
                continue

            allowed, _ = (
                self.moderation.can_manage_role(
                    member.guild,
                    role,
                )
            )

            if not allowed:
                continue

            roles.append(role)

        if not roles:

            # Eğer top role botun üzerinde ise buraya gelir.
            security_logger.critical(
                "NO MANAGEABLE ROLES | "
                "Potential hierarchy protection | "
                "guild=%s actor=%s top_role=%s",
                member.guild.id,
                member.id,
                member.top_role.name,
            )

            return

        result = await self.moderation.remove_roles(
            member,
            roles,
            reason=(
                "PAG SECURITY EMERGENCY | "
                f"{decision.reason}"
            ),
        )

        if result.success:

            security_logger.critical(
                "ATTACKER ROLES REMOVED | "
                "guild=%s actor=%s roles=%s",
                member.guild.id,
                member.id,
                len(roles),
            )

        else:

            security_logger.error(
                "ATTACKER ROLE REMOVE FAILED | "
                "guild=%s actor=%s error=%s",
                member.guild.id,
                member.id,
                result.error,
            )

    # ========================================================
    # EMERGENCY QUARANTINE
    # ========================================================

    async def _emergency_quarantine(
        self,
        member: discord.Member,
        decision: SecurityDecision,
    ) -> None:
        """
        Quarantine role panel/config üzerinden alınır.

        Burada doğrudan .env'e bağımlı değiliz.
        """

        quarantine_role = (
            await self._get_quarantine_role(
                member.guild
            )
        )

        if quarantine_role is None:

            security_logger.warning(
                "Emergency quarantine skipped: "
                "quarantine role not configured | guild=%s",
                member.guild.id,
            )

            return

        result = await self.moderation.quarantine(
            member,
            quarantine_role,
            reason=(
                "PAG SECURITY EMERGENCY | "
                f"{decision.reason}"
            ),
            save_snapshot=True,
        )

        if result.success:

            security_logger.critical(
                "ATTACKER QUARANTINED | "
                "guild=%s actor=%s",
                member.guild.id,
                member.id,
            )

        else:

            security_logger.error(
                "Emergency quarantine failed | "
                "guild=%s actor=%s error=%s",
                member.guild.id,
                member.id,
                result.error,
            )

    # ========================================================
    # EMERGENCY LOCKDOWN
    # ========================================================

    async def _emergency_lockdown(
        self,
        guild: discord.Guild,
        decision: SecurityDecision,
    ) -> None:
        """
        Bütün text kanallarını hızlı lockdown'a alır.
        """

        result = await self.moderation.lockdown(
            guild,
            reason=(
                "PAG SECURITY EMERGENCY | "
                f"{decision.reason}"
            ),
        )

        if result.success:

            details = result.details or {}

            successful = details.get(
                "successful",
                [],
            )

            failed = details.get(
                "failed",
                [],
            )

            security_logger.critical(
                "LOCKDOWN COMPLETE | "
                "guild=%s successful=%s failed=%s",
                guild.id,
                len(successful),
                len(failed),
            )

        else:

            security_logger.error(
                "LOCKDOWN FAILED | "
                "guild=%s error=%s",
                guild.id,
                result.error,
            )

    # ========================================================
    # QUARANTINE ROLE RESOLUTION
    # ========================================================

    async def _get_quarantine_role(
        self,
        guild: discord.Guild,
    ) -> Optional[discord.Role]:
        """
        Quarantine rolünü panel/config üzerinden çözmeye çalışır.

        PanelService API'si değişebileceği için birkaç güvenli
        yöntem desteklenmiştir.
        """

        # ----------------------------------------------------
        # PanelService
        # ----------------------------------------------------

        if self.panel is not None:

            # get_quarantine_role_id()
            method = getattr(
                self.panel,
                "get_quarantine_role_id",
                None,
            )

            if callable(method):

                try:

                    role_id = method(
                        guild.id
                    )

                    if asyncio.iscoroutine(
                        role_id
                    ):
                        role_id = await role_id

                    if role_id:

                        role = guild.get_role(
                            int(role_id)
                        )

                        if role is not None:
                            return role

                except Exception as exc:

                    security_logger.error(
                        "Panel quarantine role lookup failed: %s",
                        exc,
                    )

            # get_guild_setting()
            method = getattr(
                self.panel,
                "get_guild_setting",
                None,
            )

            if callable(method):

                try:

                    role_id = method(
                        guild.id,
                        "quarantine_role_id",
                    )

                    if asyncio.iscoroutine(
                        role_id
                    ):
                        role_id = await role_id

                    if role_id:

                        role = guild.get_role(
                            int(role_id)
                        )

                        if role is not None:
                            return role

                except Exception as exc:

                    security_logger.error(
                        "Panel setting lookup failed: %s",
                        exc,
                    )

        # ----------------------------------------------------
        # Fallback
        # ----------------------------------------------------

        # Panel ayarlanmamışsa isme göre bul.
        for role in guild.roles:

            normalized = (
                role.name
                .strip()
                .lower()
            )

            if normalized in {
                "quarantine",
                "security quarantine",
                "pag quarantine",
            }:

                return role

        return None

    # ========================================================
    # MEMBER RESOLVE
    # ========================================================

    async def _resolve_member(
        self,
        guild: discord.Guild,
        user_id: int,
    ) -> Optional[discord.Member]:

        member = guild.get_member(
            user_id
        )

        if member is not None:
            return member

        try:

            return await guild.fetch_member(
                user_id
            )

        except (
            discord.NotFound,
            discord.Forbidden,
            discord.HTTPException,
        ):

            return None

    # ========================================================
    # SECURITY SERVICE CALLBACK
    # ========================================================

    async def _notify_security_service(
        self,
        guild: discord.Guild,
        decision: SecurityDecision,
    ) -> None:
        """
        Üst seviye security_service.py varsa emergency
        kararını ona aktarır.

        Circular import oluşturmamak için doğrudan import
        yerine bot attribute kullanılır.
        """

        service = getattr(
            self.bot,
            "security_service",
            None,
        )

        if service is None:
            return

        handler = getattr(
            service,
            "handle_security_decision",
            None,
        )

        if not callable(handler):
            return

        try:

            result = handler(
                guild,
                decision,
            )

            if asyncio.iscoroutine(
                result
            ):
                await result

        except Exception as exc:

            security_logger.error(
                "SecurityService callback failed | "
                "guild=%s error=%s",
                guild.id,
                exc,
            )

    # ========================================================
    # MANUAL EMERGENCY
    # ========================================================

    async def manual_emergency(
        self,
        guild: discord.Guild,
        *,
        actor_id: Optional[int] = None,
        reason: str = "Manual emergency",
    ) -> SecurityDecision:
        """
        Panel / owner tarafından manuel emergency.

        Saldırgan olmasa bile lockdown başlatabilir.
        """

        decision = SecurityDecision(
            emergency=True,
            quarantine=(
                actor_id is not None
            ),
            lockdown=True,
            remove_roles=(
                actor_id is not None
            ),
            reason=reason,
            risk=999,
            actor_id=actor_id,
            event_type="MANUAL",
        )

        await self.handle_emergency(
            guild,
            decision,
        )

        return decision

    # ========================================================
    # APPROVAL GUARD
    # ========================================================

    async def request_approval(
        self,
        guild: discord.Guild,
        *,
        action: str,
        target_id: int,
        reason: str,
    ) -> dict:
        """
        Kick / Ban gibi işlemler için approval kaydı.

        Asıl DM / buton sistemi daha sonra Cog veya
        SecurityService katmanında yapılabilir.

        Bu servis sadece güvenli approval state oluşturur.
        """

        return {
            "guild_id": guild.id,
            "action": action.upper(),
            "target_id": target_id,
            "reason": reason,
            "required_users": list(
                self._approval_users[
                    guild.id
                ]
            ),
            "approved_by": [],
            "approved": False,
            "created_at": time.time(),
        }

    # ========================================================
    # ACTOR RISK
    # ========================================================

    def get_actor_risk(
        self,
        guild_id: int,
        actor_id: int,
    ) -> int:

        return self._risk[
            guild_id
        ][
            actor_id
        ]

    def reset_actor(
        self,
        guild_id: int,
        actor_id: int,
    ) -> None:
        """
        Actor'ın runtime security geçmişini temizler.

        Panel / recovery sırasında kullanılabilir.
        """

        self._risk[
            guild_id
        ].pop(
            actor_id,
            None,
        )

        self._events[
            guild_id
        ].pop(
            actor_id,
            None,
        )

    # ========================================================
    # RESET GUILD
    # ========================================================

    def reset_guild(
        self,
        guild_id: int,
    ) -> None:

        self._events.pop(
            guild_id,
            None,
        )

        self._risk.pop(
            guild_id,
            None,
        )

        self._emergency_at.pop(
            guild_id,
            None,
        )

    # ========================================================
    # STATUS
    # ========================================================

    def get_status(
        self,
        guild_id: int,
    ) -> dict:
        """
        Panel için hızlı status.
        """

        now = time.monotonic()

        emergency_at = self._emergency_at.get(
            guild_id
        )

        emergency_active = (
            emergency_at is not None
            and (
                now - emergency_at
                < self.config.emergency_cooldown
            )
        )

        actors = {}

        guild_events = self._events.get(
            guild_id,
            {},
        )

        for actor_id, events in (
            guild_events.items()
        ):

            actor_data = {}

            for event_type, queue in (
                events.items()
            ):

                self._cleanup_actor(
                    guild_id,
                    actor_id,
                    event_type,
                    now,
                )

                if queue:
                    actor_data[
                        event_type
                    ] = len(queue)

            if actor_data:

                actors[
                    str(actor_id)
                ] = {
                    "risk": self.get_actor_risk(
                        guild_id,
                        actor_id,
                    ),
                    "events": actor_data,
                }

        return {
            "enabled": self.enabled,
            "emergency_active": emergency_active,
            "emergency_count": self.emergency_count,
            "events_processed": self.events_processed,
            "actors": actors,
        }

    # ========================================================
    # SHUTDOWN
    # ========================================================

    async def close(self) -> None:
        """
        Service kapatılırken runtime state temizliği.
        """

        self._events.clear()
        self._risk.clear()
        self._audit_cache.clear()
        self._emergency_at.clear()

        security_logger.info(
            "SecurityService closed."
        )


# ============================================================
# GLOBAL INSTANCE
# ============================================================

security_service: Optional[
    SecurityService
] = None


def setup_security_service(
    bot: discord.Client,
    moderation=None,
    panel=None,
    config: Optional[SecurityConfig] = None,
) -> SecurityService:
    """
    Global SecurityService oluşturur.

    main.py:

        security_service = setup_security_service(
            bot,
            moderation=moderation_service,
            panel=panel_service,
        )

        bot.security_service = security_service
    """

    global security_service

    security_service = SecurityService(
        bot=bot,
        moderation=moderation,
        panel=panel,
        config=config,
    )

    # Üst servislerin kolay erişebilmesi için.
    setattr(
        bot,
        "security_service",
        security_service,
    )

    return security_service


# ============================================================
# EXPORTS
# ============================================================

__all__ = [
    "SecurityService",
    "SecurityConfig",
    "SecurityEvent",
    "SecurityDecision",
    "security_service",
    "setup_security_service",
    "EVENT_KICK",
    "EVENT_BAN",
    "EVENT_CHANNEL_DELETE",
    "EVENT_CHANNEL_CREATE",
    "EVENT_ROLE_DELETE",
    "EVENT_ROLE_CREATE",
    "EVENT_ROLE_UPDATE",
    "EVENT_PERMISSION_CHANGE",
    "EVENT_BOT_ADD",
    "EVENT_WEBHOOK_CREATE",
    "EVENT_WEBHOOK_DELETE",
    "EVENT_MEMBER_ROLE_UPDATE",
]