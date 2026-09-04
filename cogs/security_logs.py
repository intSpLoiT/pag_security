# cogs/security_logs.py

from __future__ import annotations

import asyncio
import json
import time
from collections import deque
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any, Optional

from discord.ext import commands

from utils.logger import security_logger


# ============================================================
# PAG SECURITY BOT
# cogs/security_logs.py
#
# Merkezi Security Audit Log sistemi
#
# SORUMLULUKLAR
# ------------------------------------------------------------
# - Security olaylarını kaydetme
# - Guild bazlı log
# - Actor / action / severity filtreleme
# - Memory cache
# - JSONL persistence
# - Async file I/O
# - Log rotation
# - Eski log temizleme
# - Diğer Cog'lar tarafından kullanılabilir API
# - Hata izolasyonu
#
# NOT:
# Discord audit log ile aynı şey değildir.
# Bu sistem BOTUN kendi tespit ettiği olayları kaydeder.
# ============================================================


# ============================================================
# CONSTANTS
# ============================================================

DEFAULT_DATA_DIR = "data"

DEFAULT_LOG_DIRECTORY = "security_logs"

DEFAULT_CACHE_SIZE = 500

DEFAULT_MAX_FILE_SIZE = 5 * 1024 * 1024

DEFAULT_MAX_LOG_FILES = 5

DEFAULT_MAX_MEMORY_GUILDS = 1000


# ============================================================
# SEVERITY
# ============================================================


VALID_SEVERITIES = {
    "info",
    "low",
    "medium",
    "high",
    "critical",
}


# ============================================================
# DATACLASS
# ============================================================


@dataclass(slots=True)
class SecurityLogEntry:
    """
    Tek security log kaydı.
    """

    id: int

    guild_id: int

    timestamp: float

    action: str

    severity: str

    message: str

    actor_id: Optional[int] = None

    target_id: Optional[int] = None

    channel_id: Optional[int] = None

    metadata: dict[str, Any] | None = None

    source: str = "security"


# ============================================================
# COG
# ============================================================


class SecurityLogs(commands.Cog):
    """
    Merkezi PAG Security log sistemi.

    Diğer Cog'lar:

        await logs.log(
            guild_id=guild.id,
            action="channel_delete",
            severity="high",
            actor_id=user.id,
            target_id=channel.id,
            message="Channel deleted.",
        )

    şeklinde kullanabilir.
    """

    def __init__(
        self,
        bot: commands.Bot,
        *,
        data_dir: str | Path = DEFAULT_DATA_DIR,
        cache_size: int = DEFAULT_CACHE_SIZE,
        max_file_size: int = DEFAULT_MAX_FILE_SIZE,
        max_log_files: int = DEFAULT_MAX_LOG_FILES,
    ) -> None:

        self.bot = bot

        # ----------------------------------------------------
        # Paths
        # ----------------------------------------------------

        self.data_dir = Path(
            data_dir
        )

        self.log_dir = (
            self.data_dir
            / DEFAULT_LOG_DIRECTORY
        )

        self.log_dir.mkdir(
            parents=True,
            exist_ok=True,
        )

        # ----------------------------------------------------
        # Limits
        # ----------------------------------------------------

        self.cache_size = max(
            10,
            int(cache_size),
        )

        self.max_file_size = max(
            1024,
            int(max_file_size),
        )

        self.max_log_files = max(
            1,
            int(max_log_files),
        )

        # ----------------------------------------------------
        # Runtime cache
        # ----------------------------------------------------

        self._cache: dict[
            int,
            deque[SecurityLogEntry],
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
        # ID
        # ----------------------------------------------------

        self._sequence = 0

        # ----------------------------------------------------
        # Statistics
        # ----------------------------------------------------

        self.total_logs = 0

        self.total_write_errors = 0

        self.total_read_errors = 0

        self.total_rotations = 0

        security_logger.info(
            "SecurityLogs cog initialized | "
            "directory=%s",
            self.log_dir,
        )

    # ========================================================
    # INTERNAL LOCK
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

    # ========================================================
    # PATH
    # ========================================================

    def get_log_path(
        self,
        guild_id: int,
    ) -> Path:

        return (
            self.log_dir
            / f"{guild_id}.jsonl"
        )

    # ========================================================
    # ID
    # ========================================================

    def _next_id(self) -> int:

        self._sequence += 1

        return (
            int(time.time() * 1000)
            * 1000
            + self._sequence
        )

    # ========================================================
    # NORMALIZE
    # ========================================================

    @staticmethod
    def _normalize_severity(
        severity: str,
    ) -> str:

        if not isinstance(
            severity,
            str,
        ):
            return "info"

        severity = severity.lower().strip()

        if severity not in VALID_SEVERITIES:
            return "info"

        return severity

    @staticmethod
    def _normalize_action(
        action: str,
    ) -> str:

        if not isinstance(
            action,
            str,
        ):
            return "unknown"

        action = action.strip().lower()

        if not action:
            return "unknown"

        # Gereksiz aşırı uzun action'ları kes.
        return action[:100]

    @staticmethod
    def _normalize_message(
        message: str,
    ) -> str:

        if not isinstance(
            message,
            str,
        ):
            return ""

        return message[:2000]

    # ========================================================
    # CACHE
    # ========================================================

    def _get_cache(
        self,
        guild_id: int,
    ) -> deque[SecurityLogEntry]:

        cache = self._cache.get(
            guild_id
        )

        if cache is None:

            cache = deque(
                maxlen=self.cache_size
            )

            self._cache[
                guild_id
            ] = cache

        return cache

    # ========================================================
    # LOG
    # ========================================================

    async def log(
        self,
        *,
        guild_id: int,
        action: str,
        severity: str = "info",
        message: str = "",
        actor_id: Optional[int] = None,
        target_id: Optional[int] = None,
        channel_id: Optional[int] = None,
        metadata: Optional[
            dict[str, Any]
        ] = None,
        source: str = "security",
    ) -> Optional[SecurityLogEntry]:
        """
        Security olayını kaydeder.

        Dosya yazma başarısız olsa bile bot exception
        yüzünden düşmez.
        """

        if guild_id <= 0:
            return None

        action = self._normalize_action(
            action
        )

        severity = self._normalize_severity(
            severity
        )

        message = self._normalize_message(
            message
        )

        if not isinstance(
            source,
            str,
        ):
            source = "security"

        source = source.strip()[:100] or "security"

        # Metadata'nın referansını dışarıdan değiştirmesin.
        safe_metadata: dict[str, Any]

        if isinstance(
            metadata,
            dict,
        ):

            try:

                # JSON ile güvenli kopya.
                safe_metadata = json.loads(
                    json.dumps(
                        metadata,
                        ensure_ascii=False,
                        default=str,
                    )
                )

            except Exception:

                safe_metadata = {
                    "metadata_error": True
                }

        else:

            safe_metadata = {}

        entry = SecurityLogEntry(
            id=self._next_id(),
            guild_id=guild_id,
            timestamp=time.time(),
            action=action,
            severity=severity,
            message=message,
            actor_id=actor_id,
            target_id=target_id,
            channel_id=channel_id,
            metadata=safe_metadata,
            source=source,
        )

        lock = self._get_lock(
            guild_id
        )

        async with lock:

            cache = self._get_cache(
                guild_id
            )

            cache.append(entry)

            try:

                await self._write_entry(
                    entry
                )

            except Exception:

                self.total_write_errors += 1

                security_logger.exception(
                    "Security log write failed | "
                    "guild=%s action=%s",
                    guild_id,
                    action,
                )

                # Kritik nokta:
                # Log yazılamadı diye security botu düşmez.

            self.total_logs += 1

        return entry

    # ========================================================
    # WRITE
    # ========================================================

    async def _write_entry(
        self,
        entry: SecurityLogEntry,
    ) -> None:

        path = self.get_log_path(
            entry.guild_id
        )

        path.parent.mkdir(
            parents=True,
            exist_ok=True,
        )

        payload = (
            json.dumps(
                asdict(entry),
                ensure_ascii=False,
                separators=(",", ":"),
                default=str,
            )
            + "\n"
        )

        def write() -> None:

            with path.open(
                "a",
                encoding="utf-8",
            ) as file:

                file.write(
                    payload
                )

                file.flush()

        await asyncio.to_thread(
            write
        )

        await self._rotate_if_needed(
            path,
            entry.guild_id,
        )

    # ========================================================
    # ROTATION
    # ========================================================

    async def _rotate_if_needed(
        self,
        path: Path,
        guild_id: int,
    ) -> None:

        try:

            size = path.stat().st_size

        except OSError:

            return

        if size < self.max_file_size:
            return

        def rotate() -> None:

            # Eski dosyaları geriye kaydır.
            for index in range(
                self.max_log_files - 1,
                0,
                -1,
            ):

                old = path.with_name(
                    f"{path.stem}.{index}{path.suffix}"
                )

                new_index = index + 1

                new = path.with_name(
                    f"{path.stem}.{new_index}{path.suffix}"
                )

                if old.exists():

                    try:

                        if (
                            new_index
                            > self.max_log_files
                        ):
                            old.unlink()

                        else:
                            old.replace(
                                new
                            )

                    except OSError:
                        pass

            rotated = path.with_name(
                f"{path.stem}.1{path.suffix}"
            )

            try:

                path.replace(
                    rotated
                )

            except OSError:

                return

        await asyncio.to_thread(
            rotate
        )

        self.total_rotations += 1

        security_logger.info(
            "Security log rotated | guild=%s",
            guild_id,
        )

    # ========================================================
    # GET CACHE
    # ========================================================

    def get_cached(
        self,
        guild_id: int,
        *,
        limit: int = 50,
    ) -> list[SecurityLogEntry]:
        """
        Disk'e gitmeden son logları döndürür.
        """

        try:
            limit = int(limit)
        except (
            TypeError,
            ValueError,
        ):
            limit = 50

        limit = max(
            1,
            min(limit, self.cache_size),
        )

        cache = self._cache.get(
            guild_id
        )

        if not cache:
            return []

        return list(cache)[-limit:]

    # ========================================================
    # READ DISK
    # ========================================================

    async def read_logs(
        self,
        guild_id: int,
        *,
        limit: int = 100,
        action: Optional[str] = None,
        severity: Optional[str] = None,
        actor_id: Optional[int] = None,
    ) -> list[SecurityLogEntry]:
        """
        Disk üzerindeki logları okur.

        En yeni kayıtlar döndürülür.
        """

        if guild_id <= 0:
            return []

        try:
            limit = int(limit)
        except (
            TypeError,
            ValueError,
        ):
            limit = 100

        limit = max(
            1,
            min(limit, 1000),
        )

        if action is not None:

            action = self._normalize_action(
                action
            )

        if severity is not None:

            severity = self._normalize_severity(
                severity
            )

        path = self.get_log_path(
            guild_id
        )

        if not path.exists():
            return []

        lock = self._get_lock(
            guild_id
        )

        async with lock:

            try:

                lines = await asyncio.to_thread(
                    self._read_lines,
                    path,
                )

            except Exception:

                self.total_read_errors += 1

                security_logger.exception(
                    "Security log read failed | "
                    "guild=%s",
                    guild_id,
                )

                return []

        result: list[
            SecurityLogEntry
        ] = []

        # Dosyadan yeni -> eski.
        for line in reversed(lines):

            if not line.strip():
                continue

            try:

                raw = json.loads(
                    line
                )

                if not isinstance(
                    raw,
                    dict,
                ):
                    continue

                entry = (
                    self._entry_from_dict(
                        raw
                    )
                )

            except Exception:

                continue

            if (
                action is not None
                and entry.action
                != action
            ):
                continue

            if (
                severity is not None
                and entry.severity
                != severity
            ):
                continue

            if (
                actor_id is not None
                and entry.actor_id
                != actor_id
            ):
                continue

            result.append(
                entry
            )

            if len(result) >= limit:
                break

        return result

    @staticmethod
    def _read_lines(
        path: Path,
    ) -> list[str]:

        return path.read_text(
            encoding="utf-8"
        ).splitlines()

    # ========================================================
    # DESERIALIZE
    # ========================================================

    @staticmethod
    def _entry_from_dict(
        raw: dict[str, Any],
    ) -> SecurityLogEntry:

        return SecurityLogEntry(
            id=int(
                raw.get(
                    "id",
                    0,
                )
            ),
            guild_id=int(
                raw.get(
                    "guild_id",
                    0,
                )
            ),
            timestamp=float(
                raw.get(
                    "timestamp",
                    0,
                )
            ),
            action=str(
                raw.get(
                    "action",
                    "unknown",
                )
            ),
            severity=str(
                raw.get(
                    "severity",
                    "info",
                )
            ),
            message=str(
                raw.get(
                    "message",
                    "",
                )
            ),
            actor_id=(
                int(raw["actor_id"])
                if raw.get(
                    "actor_id"
                ) is not None
                else None
            ),
            target_id=(
                int(raw["target_id"])
                if raw.get(
                    "target_id"
                ) is not None
                else None
            ),
            channel_id=(
                int(raw["channel_id"])
                if raw.get(
                    "channel_id"
                ) is not None
                else None
            ),
            metadata=(
                raw.get(
                    "metadata",
                    {},
                )
                if isinstance(
                    raw.get(
                        "metadata",
                        {},
                    ),
                    dict,
                )
                else {}
            ),
            source=str(
                raw.get(
                    "source",
                    "security",
                )
            ),
        )

    # ========================================================
    # FILTER HELPERS
    # ========================================================

    async def get_actor_logs(
        self,
        guild_id: int,
        actor_id: int,
        *,
        limit: int = 50,
    ) -> list[SecurityLogEntry]:

        return await self.read_logs(
            guild_id,
            limit=limit,
            actor_id=actor_id,
        )

    async def get_action_logs(
        self,
        guild_id: int,
        action: str,
        *,
        limit: int = 50,
    ) -> list[SecurityLogEntry]:

        return await self.read_logs(
            guild_id,
            limit=limit,
            action=action,
        )

    async def get_critical_logs(
        self,
        guild_id: int,
        *,
        limit: int = 50,
    ) -> list[SecurityLogEntry]:

        return await self.read_logs(
            guild_id,
            limit=limit,
            severity="critical",
        )

    async def get_high_risk_logs(
        self,
        guild_id: int,
        *,
        limit: int = 50,
    ) -> list[SecurityLogEntry]:

        logs = await self.read_logs(
            guild_id,
            limit=1000,
        )

        high = {
            "high",
            "critical",
        }

        return [
            entry
            for entry in logs
            if entry.severity in high
        ][:limit]

    # ========================================================
    # CLEAR GUILD
    # ========================================================

    async def clear_guild_logs(
        self,
        guild_id: int,
    ) -> bool:
        """
        Guild log dosyasını siler.

        Dikkat:
        Bu işlemi ileride sadece owner/admin kontrollü
        bir panel komutundan çağırmak gerekir.
        """

        if guild_id <= 0:
            return False

        path = self.get_log_path(
            guild_id
        )

        lock = self._get_lock(
            guild_id
        )

        async with lock:

            try:

                if path.exists():

                    await asyncio.to_thread(
                        path.unlink
                    )

                # Rotation dosyalarını da temizle.
                for index in range(
                    1,
                    self.max_log_files + 1,
                ):

                    rotated = (
                        path.with_name(
                            f"{path.stem}.{index}"
                            f"{path.suffix}"
                        )
                    )

                    if rotated.exists():

                        try:

                            await asyncio.to_thread(
                                rotated.unlink
                            )

                        except OSError:
                            pass

                self._cache.pop(
                    guild_id,
                    None,
                )

                return True

            except Exception:

                security_logger.exception(
                    "Failed to clear guild security logs | "
                    "guild=%s",
                    guild_id,
                )

                return False

    # ========================================================
    # CACHE MANAGEMENT
    # ========================================================

    def clear_cache(
        self,
        guild_id: Optional[int] = None,
    ) -> None:

        if guild_id is None:

            self._cache.clear()

            return

        self._cache.pop(
            guild_id,
            None,
        )

    # ========================================================
    # STATUS
    # ========================================================

    def get_status(
        self,
    ) -> dict[str, Any]:

        return {
            "directory": str(
                self.log_dir
            ),
            "cached_guilds": len(
                self._cache
            ),
            "cached_entries": sum(
                len(cache)
                for cache in self._cache.values()
            ),
            "total_logs": (
                self.total_logs
            ),
            "write_errors": (
                self.total_write_errors
            ),
            "read_errors": (
                self.total_read_errors
            ),
            "rotations": (
                self.total_rotations
            ),
            "cache_size": (
                self.cache_size
            ),
            "max_file_size": (
                self.max_file_size
            ),
            "max_log_files": (
                self.max_log_files
            ),
        }

    # ========================================================
    # COG UNLOAD
    # ========================================================

    def cog_unload(
        self,
    ) -> None:

        self._cache.clear()

        self._locks.clear()

        security_logger.info(
            "SecurityLogs cog unloaded."
        )


# ============================================================
# SETUP
# ============================================================


async def setup(
    bot: commands.Bot,
) -> None:

    await bot.add_cog(
        SecurityLogs(bot)
    )


# ============================================================
# EXPORTS
# ============================================================


__all__ = [
    "SecurityLogs",
    "SecurityLogEntry",
]