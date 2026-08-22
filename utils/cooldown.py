# utils/cooldown.py

from __future__ import annotations

import asyncio
import time
from dataclasses import dataclass
from typing import Hashable, Optional


# ============================================================
# PAG SECURITY BOT
# utils/cooldown.py
#
# Hafif RAM tabanlı cooldown / rate-limit sistemi.
#
# Özellikler:
# - Async-safe
# - Background loop yok
# - Lazy cleanup
# - Per-user cooldown
# - Per-action cooldown
# - Rate limit desteği
# - Manuel reset
# - Kalan süre sorgulama
#
# Database kullanmaz.
# Bot yeniden başlarsa cooldown kayıtları sıfırlanır.
# ============================================================


# ============================================================
# DATA
# ============================================================

@dataclass(slots=True)
class CooldownEntry:
    """
    Tek bir cooldown kaydı.
    """

    expires_at: float


@dataclass(slots=True)
class RateLimitEntry:
    """
    Belirli bir zaman penceresindeki işlemleri takip eder.
    """

    timestamps: list[float]


# ============================================================
# COOLDOWN MANAGER
# ============================================================

class CooldownManager:
    """
    Hafif ve genel amaçlı cooldown yöneticisi.

    Örnek:

        cooldowns = CooldownManager()

        if cooldowns.is_on_cooldown(user_id):
            return

        cooldowns.set(user_id, 5)

    Aynı manager içerisinde farklı namespace'ler
    kullanılabilir.
    """

    __slots__ = (
        "_cooldowns",
        "_lock",
        "_cleanup_interval",
        "_last_cleanup",
    )

    def __init__(
        self,
        *,
        cleanup_interval: float = 30.0,
    ) -> None:
        if cleanup_interval <= 0:
            raise ValueError(
                "cleanup_interval 0'dan büyük olmalıdır."
            )

        self._cooldowns: dict[
            str,
            dict[Hashable, CooldownEntry],
        ] = {}

        self._lock = asyncio.Lock()

        self._cleanup_interval = cleanup_interval
        self._last_cleanup = time.monotonic()

    # ========================================================
    # INTERNAL
    # ========================================================

    @staticmethod
    def _now() -> float:
        """
        Monotonic clock döndürür.

        Cooldown hesaplarında time.time() yerine
        monotonic kullanmak sistem saatinin değişmesinden
        etkilenmememizi sağlar.
        """
        return time.monotonic()

    @staticmethod
    def _normalize_namespace(
        namespace: Optional[str],
    ) -> str:
        """
        Namespace'i normalize eder.
        """
        if namespace is None:
            return "default"

        namespace = str(namespace).strip()

        return namespace or "default"

    def _cleanup_namespace(
        self,
        namespace: str,
        now: Optional[float] = None,
    ) -> None:
        """
        Süresi geçmiş cooldown kayıtlarını temizler.
        """
        entries = self._cooldowns.get(namespace)

        if not entries:
            return

        if now is None:
            now = self._now()

        expired = [
            key
            for key, entry in entries.items()
            if entry.expires_at <= now
        ]

        for key in expired:
            entries.pop(key, None)

        if not entries:
            self._cooldowns.pop(namespace, None)

    def _maybe_cleanup(self) -> None:
        """
        Lazy cleanup.

        Her işlemde bütün dictionary'yi taramak yerine
        belirli aralıklarla temizler.
        """
        now = self._now()

        if now - self._last_cleanup < self._cleanup_interval:
            return

        self._last_cleanup = now

        for namespace in tuple(self._cooldowns):
            self._cleanup_namespace(namespace, now)

    # ========================================================
    # SET
    # ========================================================

    async def set_async(
        self,
        key: Hashable,
        duration: float,
        *,
        namespace: str = "default",
    ) -> None:
        """
        Async-safe cooldown oluşturur.
        """
        if duration <= 0:
            return

        namespace = self._normalize_namespace(namespace)

        async with self._lock:
            self._maybe_cleanup()

            entries = self._cooldowns.setdefault(
                namespace,
                {},
            )

            entries[key] = CooldownEntry(
                expires_at=self._now() + duration
            )

    def set(
        self,
        key: Hashable,
        duration: float,
        *,
        namespace: str = "default",
    ) -> None:
        """
        Senkron cooldown oluşturur.

        Event loop kilitlemeden basit kullanım için.

        Aynı dictionary event-loop içerisinde çalıştığı için
        küçük operasyonlarda ayrıca await gerektirmez.
        """
        if duration <= 0:
            return

        namespace = self._normalize_namespace(namespace)

        self._maybe_cleanup()

        entries = self._cooldowns.setdefault(
            namespace,
            {},
        )

        entries[key] = CooldownEntry(
            expires_at=self._now() + duration
        )

    # ========================================================
    # CHECK
    # ========================================================

    def is_on_cooldown(
        self,
        key: Hashable,
        *,
        namespace: str = "default",
    ) -> bool:
        """
        Key cooldown'da mı?
        """
        namespace = self._normalize_namespace(namespace)

        self._maybe_cleanup()

        entries = self._cooldowns.get(namespace)

        if not entries:
            return False

        entry = entries.get(key)

        if entry is None:
            return False

        now = self._now()

        if entry.expires_at <= now:
            entries.pop(key, None)

            if not entries:
                self._cooldowns.pop(namespace, None)

            return False

        return True

    # ========================================================
    # REMAINING
    # ========================================================

    def remaining(
        self,
        key: Hashable,
        *,
        namespace: str = "default",
    ) -> float:
        """
        Cooldown'un kalan süresini saniye olarak döndürür.

        Cooldown yoksa 0.0 döner.
        """
        namespace = self._normalize_namespace(namespace)

        self._maybe_cleanup()

        entries = self._cooldowns.get(namespace)

        if not entries:
            return 0.0

        entry = entries.get(key)

        if entry is None:
            return 0.0

        remaining = entry.expires_at - self._now()

        if remaining <= 0:
            entries.pop(key, None)

            if not entries:
                self._cooldowns.pop(namespace, None)

            return 0.0

        return remaining

    # ========================================================
    # RESET
    # ========================================================

    def reset(
        self,
        key: Hashable,
        *,
        namespace: str = "default",
    ) -> bool:
        """
        Belirli bir cooldown'u kaldırır.

        Returns:
            True  -> kayıt vardı ve kaldırıldı.
            False -> kayıt bulunamadı.
        """
        namespace = self._normalize_namespace(namespace)

        entries = self._cooldowns.get(namespace)

        if not entries:
            return False

        removed = entries.pop(key, None)

        if not entries:
            self._cooldowns.pop(namespace, None)

        return removed is not None

    async def reset_async(
        self,
        key: Hashable,
        *,
        namespace: str = "default",
    ) -> bool:
        """
        Async-safe reset.
        """
        async with self._lock:
            return self.reset(
                key,
                namespace=namespace,
            )

    # ========================================================
    # CLEAR
    # ========================================================

    def clear(
        self,
        *,
        namespace: Optional[str] = None,
    ) -> int:
        """
        Cooldown kayıtlarını temizler.

        namespace verilmezse tüm cooldownlar temizlenir.

        Returns:
            Silinen kayıt sayısı.
        """
        if namespace is None:
            count = sum(
                len(entries)
                for entries in self._cooldowns.values()
            )

            self._cooldowns.clear()

            return count

        namespace = self._normalize_namespace(namespace)

        entries = self._cooldowns.pop(namespace, None)

        if not entries:
            return 0

        return len(entries)

    # ========================================================
    # CONTAINS
    # ========================================================

    def __contains__(
        self,
        key: Hashable,
    ) -> bool:
        """
        'key in cooldowns' kullanımını sağlar.
        """
        return self.is_on_cooldown(key)

    # ========================================================
    # STATS
    # ========================================================

    def size(
        self,
        *,
        namespace: Optional[str] = None,
    ) -> int:
        """
        Aktif cooldown sayısını döndürür.
        """
        self._maybe_cleanup()

        if namespace is not None:
            namespace = self._normalize_namespace(namespace)

            return len(
                self._cooldowns.get(namespace, {})
            )

        return sum(
            len(entries)
            for entries in self._cooldowns.values()
        )


# ============================================================
# RATE LIMITER
# ============================================================

class RateLimiter:
    """
    Belirli bir zaman aralığında kaç işlem yapılabileceğini
    kontrol eder.

    Örnek:

        limiter = RateLimiter()

        allowed = limiter.allow(
            user_id,
            limit=5,
            window=10,
        )

    10 saniye içerisinde 5 işlemden fazlasına izin vermez.
    """

    __slots__ = (
        "_entries",
        "_lock",
        "_cleanup_interval",
        "_last_cleanup",
    )

    def __init__(
        self,
        *,
        cleanup_interval: float = 30.0,
    ) -> None:
        if cleanup_interval <= 0:
            raise ValueError(
                "cleanup_interval 0'dan büyük olmalıdır."
            )

        self._entries: dict[
            Hashable,
            RateLimitEntry,
        ] = {}

        self._lock = asyncio.Lock()

        self._cleanup_interval = cleanup_interval
        self._last_cleanup = time.monotonic()

    # ========================================================
    # INTERNAL
    # ========================================================

    @staticmethod
    def _now() -> float:
        return time.monotonic()

    def _maybe_cleanup(
        self,
        now: Optional[float] = None,
    ) -> None:
        """
        Eski rate-limit kayıtlarını temizler.
        """
        if now is None:
            now = self._now()

        if now - self._last_cleanup < self._cleanup_interval:
            return

        self._last_cleanup = now

        expired_keys: list[Hashable] = []

        for key, entry in self._entries.items():
            if not entry.timestamps:
                expired_keys.append(key)

        for key in expired_keys:
            self._entries.pop(key, None)

    @staticmethod
    def _trim(
        entry: RateLimitEntry,
        now: float,
        window: float,
    ) -> None:
        """
        Window dışındaki timestampleri temizler.
        """
        cutoff = now - window

        entry.timestamps = [
            timestamp
            for timestamp in entry.timestamps
            if timestamp > cutoff
        ]

    # ========================================================
    # ALLOW
    # ========================================================

    def allow(
        self,
        key: Hashable,
        *,
        limit: int,
        window: float,
    ) -> bool:
        """
        Yeni işlemin yapılmasına izin verilip verilmediğini
        kontrol eder.

        İşlem kabul edilirse timestamp kaydedilir.

        Returns:
            True  -> izin verildi.
            False -> rate limit aşıldı.
        """
        if limit <= 0:
            return False

        if window <= 0:
            return True

        now = self._now()

        self._maybe_cleanup(now)

        entry = self._entries.setdefault(
            key,
            RateLimitEntry(timestamps=[]),
        )

        self._trim(
            entry,
            now,
            window,
        )

        if len(entry.timestamps) >= limit:
            return False

        entry.timestamps.append(now)

        return True

    async def allow_async(
        self,
        key: Hashable,
        *,
        limit: int,
        window: float,
    ) -> bool:
        """
        Async-safe rate-limit kontrolü.
        """
        async with self._lock:
            return self.allow(
                key,
                limit=limit,
                window=window,
            )

    # ========================================================
    # COUNT
    # ========================================================

    def count(
        self,
        key: Hashable,
        *,
        window: float,
    ) -> int:
        """
        Belirtilen window içerisindeki işlem sayısını döndürür.
        """
        if window <= 0:
            return 0

        entry = self._entries.get(key)

        if entry is None:
            return 0

        now = self._now()

        self._trim(
            entry,
            now,
            window,
        )

        if not entry.timestamps:
            self._entries.pop(key, None)
            return 0

        return len(entry.timestamps)

    # ========================================================
    # REMAINING
    # ========================================================

    def remaining(
        self,
        key: Hashable,
        *,
        limit: int,
        window: float,
    ) -> int:
        """
        Window içerisinde kaç işlem hakkı kaldığını döndürür.
        """
        current = self.count(
            key,
            window=window,
        )

        return max(
            0,
            limit - current,
        )

    # ========================================================
    # RESET
    # ========================================================

    def reset(
        self,
        key: Hashable,
    ) -> bool:
        """
        Belirli kullanıcının rate-limit kaydını temizler.
        """
        return self._entries.pop(key, None) is not None

    async def reset_async(
        self,
        key: Hashable,
    ) -> bool:
        """
        Async-safe reset.
        """
        async with self._lock:
            return self.reset(key)

    # ========================================================
    # CLEAR
    # ========================================================

    def clear(self) -> int:
        """
        Tüm rate-limit kayıtlarını temizler.

        Returns:
            Silinen kayıt sayısı.
        """
        count = len(self._entries)

        self._entries.clear()

        return count

    # ========================================================
    # SIZE
    # ========================================================

    def size(self) -> int:
        """
        Aktif rate-limit kayıt sayısını döndürür.
        """
        self._maybe_cleanup()

        return len(self._entries)


# ============================================================
# COMBINED SECURITY LIMITER
# ============================================================

class SecurityLimiter:
    """
    PAG Security için CooldownManager ve RateLimiter'ı
    tek bir basit arayüzde toplar.

    Bu sınıf özellikle Cog'larda kullanışlıdır.
    """

    __slots__ = (
        "cooldowns",
        "rate_limits",
    )

    def __init__(self) -> None:
        self.cooldowns = CooldownManager()
        self.rate_limits = RateLimiter()

    # ========================================================
    # COOLDOWN
    # ========================================================

    def cooldown(
        self,
        key: Hashable,
        duration: float,
        *,
        namespace: str = "default",
    ) -> bool:
        """
        Cooldown yoksa oluşturur ve True döndürür.

        Cooldown zaten varsa False döndürür.

        Bu yapı command/event guard olarak kullanılabilir.
        """
        if self.cooldowns.is_on_cooldown(
            key,
            namespace=namespace,
        ):
            return False

        self.cooldowns.set(
            key,
            duration,
            namespace=namespace,
        )

        return True

    # ========================================================
    # RATE LIMIT
    # ========================================================

    def allow(
        self,
        key: Hashable,
        *,
        limit: int,
        window: float,
    ) -> bool:
        """
        Rate-limit kontrolü.
        """
        return self.rate_limits.allow(
            key,
            limit=limit,
            window=window,
        )

    # ========================================================
    # RESET
    # ========================================================

    def reset_cooldown(
        self,
        key: Hashable,
        *,
        namespace: str = "default",
    ) -> bool:
        """
        Cooldown reset.
        """
        return self.cooldowns.reset(
            key,
            namespace=namespace,
        )

    def reset_rate_limit(
        self,
        key: Hashable,
    ) -> bool:
        """
        Rate-limit reset.
        """
        return self.rate_limits.reset(key)

    # ========================================================
    # CLEAR
    # ========================================================

    def clear(self) -> None:
        """
        Tüm cooldown ve rate-limit kayıtlarını temizler.
        """
        self.cooldowns.clear()
        self.rate_limits.clear()


# ============================================================
# GLOBAL INSTANCE
# ============================================================

security_limiter = SecurityLimiter()


# ============================================================
# EXPORTS
# ============================================================

__all__ = [
    "CooldownEntry",
    "RateLimitEntry",
    "CooldownManager",
    "RateLimiter",
    "SecurityLimiter",
    "security_limiter",
]