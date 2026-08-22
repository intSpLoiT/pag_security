# services/database_service.py

from __future__ import annotations

import asyncio
import json
import sqlite3
import time
from pathlib import Path
from typing import Any, Iterable, Optional

from utils.logger import database_logger


# ============================================================
# PAG SECURITY BOT
# services/database_service.py
#
# Merkezi SQLite veritabanı servisi.
#
# Amaç:
# - Security event kayıtları
# - Emergency kayıtları
# - Whitelist
# - Approval sistemi
# - Role snapshot / restore
# - Threat history
# - Action history
# - Guild security settings
# - Backup metadata
# - Lockdown kayıtları
#
# Özellikler:
# - SQLite
# - WAL
# - Foreign key
# - Async wrapper
# - Transaction desteği
# - Otomatik schema oluşturma
# - Parametreli SQL
# - Thread-safe connection kullanımı
# ============================================================


# ============================================================
# CONSTANTS
# ============================================================

DEFAULT_DB_PATH = "database/security.db"

SCHEMA_VERSION = 1

MAX_EVENT_DETAILS = 16_000
MAX_REASON_LENGTH = 1_000


# ============================================================
# HELPERS
# ============================================================

def _now() -> int:
    """
    Unix timestamp döndürür.
    """
    return int(time.time())


def _safe_json(
    value: Any,
    *,
    default: Any = None,
) -> Any:
    """
    JSON decode işlemini güvenli hale getirir.
    """
    if value is None:
        return default

    try:
        return json.loads(value)
    except (TypeError, ValueError, json.JSONDecodeError):
        return default


def _json_dumps(value: Any) -> str:
    """
    JSON encode işlemi.
    """
    try:
        return json.dumps(
            value,
            ensure_ascii=False,
            separators=(",", ":"),
            default=str,
        )
    except (TypeError, ValueError):
        return "{}"


def _clean_reason(
    reason: Optional[str],
) -> Optional[str]:
    """
    Reason değerini normalize eder.
    """
    if reason is None:
        return None

    reason = str(reason).strip()

    if not reason:
        return None

    return reason[:MAX_REASON_LENGTH]


# ============================================================
# DATABASE SERVICE
# ============================================================

class DatabaseService:
    """
    PAG Security Bot SQLite database service.

    Connection uzun süre açık tutulmaz.
    Her operasyon gerektiğinde connection açar ve kapatır.

    Bu yaklaşım özellikle ücretsiz / düşük kaynaklı hosting
    ortamlarında basit ve güvenlidir.
    """

    def __init__(
        self,
        path: str = DEFAULT_DB_PATH,
    ) -> None:

        self.path = Path(path)

        self._lock = asyncio.Lock()

        self._initialized = False

    # ========================================================
    # CONNECTION
    # ========================================================

    def _connect(self) -> sqlite3.Connection:
        """
        SQLite connection oluşturur.
        """

        self.path.parent.mkdir(
            parents=True,
            exist_ok=True,
        )

        connection = sqlite3.connect(
            self.path,
            timeout=10.0,
            isolation_level=None,
        )

        connection.row_factory = sqlite3.Row

        connection.execute(
            "PRAGMA journal_mode=WAL;"
        )

        connection.execute(
            "PRAGMA synchronous=NORMAL;"
        )

        connection.execute(
            "PRAGMA foreign_keys=ON;"
        )

        connection.execute(
            "PRAGMA busy_timeout=10000;"
        )

        return connection

    async def _execute(
        self,
        callback,
    ) -> Any:
        """
        Blocking SQLite işlemini event loop dışına taşır.
        """

        async with self._lock:
            return await asyncio.to_thread(
                callback
            )

    # ========================================================
    # INITIALIZE
    # ========================================================

    async def initialize(self) -> None:
        """
        Database'i hazırlar ve bütün tabloları oluşturur.
        """

        if self._initialized:
            return

        await self._execute(
            self._initialize_sync
        )

        self._initialized = True

        database_logger.info(
            "Database initialized: %s",
            self.path,
        )

    def _initialize_sync(self) -> None:
        connection = self._connect()

        try:
            self._create_schema(connection)

        finally:
            connection.close()

    # ========================================================
    # SCHEMA
    # ========================================================

    @staticmethod
    def _create_schema(
        connection: sqlite3.Connection,
    ) -> None:

        connection.executescript(
            """
            PRAGMA foreign_keys = ON;

            CREATE TABLE IF NOT EXISTS schema_info (
                key TEXT PRIMARY KEY,
                value TEXT NOT NULL
            );

            INSERT OR IGNORE INTO schema_info
            (key, value)
            VALUES
            ('version', '1');


            --------------------------------------------------
            -- GUILD SETTINGS
            --------------------------------------------------

            CREATE TABLE IF NOT EXISTS guild_settings (
                guild_id INTEGER PRIMARY KEY,

                emergency_enabled INTEGER NOT NULL DEFAULT 1,
                emergency_threshold INTEGER NOT NULL DEFAULT 5,

                approval_enabled INTEGER NOT NULL DEFAULT 1,

                anti_nuke_enabled INTEGER NOT NULL DEFAULT 1,
                anti_raid_enabled INTEGER NOT NULL DEFAULT 1,
                anti_spam_enabled INTEGER NOT NULL DEFAULT 1,
                anti_scam_enabled INTEGER NOT NULL DEFAULT 1,

                lockdown_enabled INTEGER NOT NULL DEFAULT 1,

                log_channel_id INTEGER,

                created_at INTEGER NOT NULL,
                updated_at INTEGER NOT NULL
            );


            --------------------------------------------------
            -- SECURITY EVENTS
            --------------------------------------------------

            CREATE TABLE IF NOT EXISTS security_events (
                id INTEGER PRIMARY KEY AUTOINCREMENT,

                guild_id INTEGER NOT NULL,
                user_id INTEGER,

                event_type TEXT NOT NULL,
                severity TEXT NOT NULL DEFAULT 'INFO',

                action TEXT,
                target_id INTEGER,

                reason TEXT,
                details TEXT,

                created_at INTEGER NOT NULL
            );

            CREATE INDEX IF NOT EXISTS idx_security_events_guild
            ON security_events(guild_id);

            CREATE INDEX IF NOT EXISTS idx_security_events_user
            ON security_events(guild_id, user_id);

            CREATE INDEX IF NOT EXISTS idx_security_events_type
            ON security_events(guild_id, event_type);

            CREATE INDEX IF NOT EXISTS idx_security_events_created
            ON security_events(created_at);


            --------------------------------------------------
            -- ACTION HISTORY
            --------------------------------------------------

            CREATE TABLE IF NOT EXISTS action_history (
                id INTEGER PRIMARY KEY AUTOINCREMENT,

                guild_id INTEGER NOT NULL,
                executor_id INTEGER,

                action_type TEXT NOT NULL,
                target_id INTEGER,

                success INTEGER NOT NULL DEFAULT 0,

                reason TEXT,
                details TEXT,

                created_at INTEGER NOT NULL
            );

            CREATE INDEX IF NOT EXISTS idx_action_history_executor
            ON action_history(guild_id, executor_id);

            CREATE INDEX IF NOT EXISTS idx_action_history_type
            ON action_history(guild_id, action_type);

            CREATE INDEX IF NOT EXISTS idx_action_history_created
            ON action_history(created_at);


            --------------------------------------------------
            -- EMERGENCY EVENTS
            --------------------------------------------------

            CREATE TABLE IF NOT EXISTS emergency_events (
                id INTEGER PRIMARY KEY AUTOINCREMENT,

                guild_id INTEGER NOT NULL,

                triggered_by INTEGER,
                trigger_type TEXT NOT NULL,

                risk_score INTEGER NOT NULL DEFAULT 0,

                status TEXT NOT NULL DEFAULT 'ACTIVE',

                reason TEXT,
                details TEXT,

                started_at INTEGER NOT NULL,
                ended_at INTEGER,

                resolved_by INTEGER,
                resolution_reason TEXT
            );

            CREATE INDEX IF NOT EXISTS idx_emergency_guild
            ON emergency_events(guild_id);

            CREATE INDEX IF NOT EXISTS idx_emergency_status
            ON emergency_events(guild_id, status);


            --------------------------------------------------
            -- WHITELIST
            --------------------------------------------------

            CREATE TABLE IF NOT EXISTS whitelist (
                guild_id INTEGER NOT NULL,
                user_id INTEGER NOT NULL,

                added_by INTEGER,
                reason TEXT,

                created_at INTEGER NOT NULL,

                PRIMARY KEY (
                    guild_id,
                    user_id
                )
            );


            --------------------------------------------------
            -- APPROVALS
            --------------------------------------------------

            CREATE TABLE IF NOT EXISTS approvals (
                id INTEGER PRIMARY KEY AUTOINCREMENT,

                guild_id INTEGER NOT NULL,

                target_id INTEGER,
                action_type TEXT NOT NULL,

                requested_by INTEGER,

                approved_by INTEGER,
                rejected_by INTEGER,

                status TEXT NOT NULL DEFAULT 'PENDING',

                reason TEXT,
                details TEXT,

                created_at INTEGER NOT NULL,
                expires_at INTEGER,

                resolved_at INTEGER
            );

            CREATE INDEX IF NOT EXISTS idx_approvals_guild
            ON approvals(guild_id);

            CREATE INDEX IF NOT EXISTS idx_approvals_status
            ON approvals(guild_id, status);


            --------------------------------------------------
            -- ROLE SNAPSHOTS
            --------------------------------------------------

            CREATE TABLE IF NOT EXISTS role_snapshots (
                id INTEGER PRIMARY KEY AUTOINCREMENT,

                guild_id INTEGER NOT NULL,
                user_id INTEGER NOT NULL,

                role_ids TEXT NOT NULL,

                reason TEXT,

                active INTEGER NOT NULL DEFAULT 1,

                created_at INTEGER NOT NULL,
                restored_at INTEGER,

                restored_by INTEGER
            );

            CREATE INDEX IF NOT EXISTS idx_role_snapshots_user
            ON role_snapshots(guild_id, user_id);

            CREATE INDEX IF NOT EXISTS idx_role_snapshots_active
            ON role_snapshots(guild_id, user_id, active);


            --------------------------------------------------
            -- LOCKDOWNS
            --------------------------------------------------

            CREATE TABLE IF NOT EXISTS lockdowns (
                id INTEGER PRIMARY KEY AUTOINCREMENT,

                guild_id INTEGER NOT NULL,

                started_by INTEGER,

                status TEXT NOT NULL DEFAULT 'ACTIVE',

                reason TEXT,

                affected_channels TEXT,

                started_at INTEGER NOT NULL,
                ended_at INTEGER,

                ended_by INTEGER
            );

            CREATE INDEX IF NOT EXISTS idx_lockdowns_guild
            ON lockdowns(guild_id);

            CREATE INDEX IF NOT EXISTS idx_lockdowns_status
            ON lockdowns(guild_id, status);


            --------------------------------------------------
            -- THREAT HISTORY
            --------------------------------------------------

            CREATE TABLE IF NOT EXISTS threat_history (
                id INTEGER PRIMARY KEY AUTOINCREMENT,

                guild_id INTEGER NOT NULL,
                user_id INTEGER NOT NULL,

                threat_type TEXT NOT NULL,

                risk_score INTEGER NOT NULL DEFAULT 0,

                action_taken TEXT,

                evidence TEXT,

                created_at INTEGER NOT NULL
            );

            CREATE INDEX IF NOT EXISTS idx_threat_user
            ON threat_history(guild_id, user_id);

            CREATE INDEX IF NOT EXISTS idx_threat_created
            ON threat_history(created_at);


            --------------------------------------------------
            -- BACKUPS
            --------------------------------------------------

            CREATE TABLE IF NOT EXISTS backups (
                id INTEGER PRIMARY KEY AUTOINCREMENT,

                guild_id INTEGER NOT NULL,

                backup_type TEXT NOT NULL,

                location TEXT,

                metadata TEXT,

                created_by INTEGER,

                created_at INTEGER NOT NULL
            );

            CREATE INDEX IF NOT EXISTS idx_backups_guild
            ON backups(guild_id);
            """
        )

    # ========================================================
    # GUILD SETTINGS
    # ========================================================

    async def ensure_guild(
        self,
        guild_id: int,
    ) -> None:
        """
        Guild için default ayarları oluşturur.

        Zaten varsa hiçbir şeyi ezmez.
        """

        now = _now()

        def operation():
            connection = self._connect()

            try:
                connection.execute(
                    """
                    INSERT OR IGNORE INTO guild_settings
                    (
                        guild_id,
                        created_at,
                        updated_at
                    )
                    VALUES (?, ?, ?)
                    """,
                    (
                        guild_id,
                        now,
                        now,
                    ),
                )

            finally:
                connection.close()

        await self._execute(operation)

    async def get_guild_settings(
        self,
        guild_id: int,
    ) -> Optional[dict[str, Any]]:
        """
        Guild ayarlarını döndürür.
        """

        await self.ensure_guild(guild_id)

        def operation():
            connection = self._connect()

            try:
                row = connection.execute(
                    """
                    SELECT *
                    FROM guild_settings
                    WHERE guild_id = ?
                    """,
                    (guild_id,),
                ).fetchone()

                return dict(row) if row else None

            finally:
                connection.close()

        return await self._execute(operation)

    async def update_guild_settings(
        self,
        guild_id: int,
        **settings: Any,
    ) -> bool:
        """
        Guild ayarlarını güvenli şekilde günceller.

        Yalnızca mevcut kolon isimleri kabul edilir.
        """

        allowed = {
            "emergency_enabled",
            "emergency_threshold",
            "approval_enabled",
            "anti_nuke_enabled",
            "anti_raid_enabled",
            "anti_spam_enabled",
            "anti_scam_enabled",
            "lockdown_enabled",
            "log_channel_id",
        }

        updates = {
            key: value
            for key, value in settings.items()
            if key in allowed
        }

        if not updates:
            return False

        updates["updated_at"] = _now()

        columns = ", ".join(
            f"{key} = ?"
            for key in updates
        )

        values = list(updates.values())
        values.append(guild_id)

        def operation():
            connection = self._connect()

            try:
                cursor = connection.execute(
                    f"""
                    UPDATE guild_settings
                    SET {columns}
                    WHERE guild_id = ?
                    """,
                    values,
                )

                return cursor.rowcount > 0

            finally:
                connection.close()

        return await self._execute(operation)

    # ========================================================
    # SECURITY EVENTS
    # ========================================================

    async def add_security_event(
        self,
        guild_id: int,
        event_type: str,
        *,
        user_id: Optional[int] = None,
        severity: str = "INFO",
        action: Optional[str] = None,
        target_id: Optional[int] = None,
        reason: Optional[str] = None,
        details: Optional[dict[str, Any]] = None,
    ) -> int:
        """
        Security event kaydeder.

        Returns:
            Event ID
        """

        reason = _clean_reason(reason)

        details_json = _json_dumps(details)

        if len(details_json) > MAX_EVENT_DETAILS:
            details_json = details_json[
                :MAX_EVENT_DETAILS
            ]

        def operation():
            connection = self._connect()

            try:
                cursor = connection.execute(
                    """
                    INSERT INTO security_events
                    (
                        guild_id,
                        user_id,
                        event_type,
                        severity,
                        action,
                        target_id,
                        reason,
                        details,
                        created_at
                    )
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                    """,
                    (
                        guild_id,
                        user_id,
                        str(event_type),
                        str(severity).upper(),
                        action,
                        target_id,
                        reason,
                        details_json,
                        _now(),
                    ),
                )

                return int(cursor.lastrowid)

            finally:
                connection.close()

        return await self._execute(operation)

    async def get_security_events(
        self,
        guild_id: int,
        *,
        user_id: Optional[int] = None,
        event_type: Optional[str] = None,
        limit: int = 100,
    ) -> list[dict[str, Any]]:
        """
        Security event geçmişini getirir.
        """

        limit = max(1, min(limit, 1_000))

        conditions = ["guild_id = ?"]
        parameters: list[Any] = [guild_id]

        if user_id is not None:
            conditions.append("user_id = ?")
            parameters.append(user_id)

        if event_type is not None:
            conditions.append("event_type = ?")
            parameters.append(event_type)

        where = " AND ".join(conditions)

        parameters.append(limit)

        def operation():
            connection = self._connect()

            try:
                rows = connection.execute(
                    f"""
                    SELECT *
                    FROM security_events
                    WHERE {where}
                    ORDER BY created_at DESC
                    LIMIT ?
                    """,
                    parameters,
                ).fetchall()

                return [
                    {
                        **dict(row),
                        "details": _safe_json(
                            row["details"],
                            default={},
                        ),
                    }
                    for row in rows
                ]

            finally:
                connection.close()

        return await self._execute(operation)

    # ========================================================
    # ACTION HISTORY
    # ========================================================

    async def add_action(
        self,
        guild_id: int,
        action_type: str,
        *,
        executor_id: Optional[int] = None,
        target_id: Optional[int] = None,
        success: bool = False,
        reason: Optional[str] = None,
        details: Optional[dict[str, Any]] = None,
    ) -> int:
        """
        Gerçekleştirilen moderation/security action'ını kaydeder.
        """

        def operation():
            connection = self._connect()

            try:
                cursor = connection.execute(
                    """
                    INSERT INTO action_history
                    (
                        guild_id,
                        executor_id,
                        action_type,
                        target_id,
                        success,
                        reason,
                        details,
                        created_at
                    )
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                    """,
                    (
                        guild_id,
                        executor_id,
                        action_type,
                        target_id,
                        int(success),
                        _clean_reason(reason),
                        _json_dumps(details),
                        _now(),
                    ),
                )

                return int(cursor.lastrowid)

            finally:
                connection.close()

        return await self._execute(operation)

    async def get_recent_actions(
        self,
        guild_id: int,
        *,
        executor_id: Optional[int] = None,
        action_type: Optional[str] = None,
        seconds: Optional[int] = None,
        limit: int = 100,
    ) -> list[dict[str, Any]]:
        """
        Son moderation action'larını getirir.

        SecurityService'in:

        "Son 10 saniyede bu kişi kaç kanal sildi?"

        gibi kontrollerinde kullanılabilir.
        """

        limit = max(1, min(limit, 1_000))

        conditions = ["guild_id = ?"]
        parameters: list[Any] = [guild_id]

        if executor_id is not None:
            conditions.append(
                "executor_id = ?"
            )
            parameters.append(executor_id)

        if action_type is not None:
            conditions.append(
                "action_type = ?"
            )
            parameters.append(action_type)

        if seconds is not None:
            cutoff = _now() - max(
                0,
                seconds,
            )

            conditions.append(
                "created_at >= ?"
            )

            parameters.append(cutoff)

        parameters.append(limit)

        where = " AND ".join(conditions)

        def operation():
            connection = self._connect()

            try:
                rows = connection.execute(
                    f"""
                    SELECT *
                    FROM action_history
                    WHERE {where}
                    ORDER BY created_at DESC
                    LIMIT ?
                    """,
                    parameters,
                ).fetchall()

                return [dict(row) for row in rows]

            finally:
                connection.close()

        return await self._execute(operation)

    async def count_recent_actions(
        self,
        guild_id: int,
        executor_id: int,
        *,
        action_type: Optional[str] = None,
        seconds: int = 10,
    ) -> int:
        """
        Belirli bir kullanıcının son X saniyedeki action sayısını
        döndürür.

        Anti-Nuke için kritik fonksiyon.
        """

        cutoff = _now() - max(
            0,
            seconds,
        )

        def operation():
            connection = self._connect()

            try:
                if action_type is None:
                    row = connection.execute(
                        """
                        SELECT COUNT(*) AS count
                        FROM action_history
                        WHERE guild_id = ?
                        AND executor_id = ?
                        AND created_at >= ?
                        """,
                        (
                            guild_id,
                            executor_id,
                            cutoff,
                        ),
                    ).fetchone()

                else:
                    row = connection.execute(
                        """
                        SELECT COUNT(*) AS count
                        FROM action_history
                        WHERE guild_id = ?
                        AND executor_id = ?
                        AND action_type = ?
                        AND created_at >= ?
                        """,
                        (
                            guild_id,
                            executor_id,
                            action_type,
                            cutoff,
                        ),
                    ).fetchone()

                return int(row["count"])

            finally:
                connection.close()

        return await self._execute(operation)

    # ========================================================
    # EMERGENCY
    # ========================================================

    async def create_emergency(
        self,
        guild_id: int,
        trigger_type: str,
        *,
        triggered_by: Optional[int] = None,
        risk_score: int = 0,
        reason: Optional[str] = None,
        details: Optional[dict[str, Any]] = None,
    ) -> int:
        """
        Yeni Emergency olayı oluşturur.
        """

        def operation():
            connection = self._connect()

            try:
                cursor = connection.execute(
                    """
                    INSERT INTO emergency_events
                    (
                        guild_id,
                        triggered_by,
                        trigger_type,
                        risk_score,
                        status,
                        reason,
                        details,
                        started_at
                    )
                    VALUES (?, ?, ?, ?, 'ACTIVE', ?, ?, ?)
                    """,
                    (
                        guild_id,
                        triggered_by,
                        trigger_type,
                        max(0, min(risk_score, 100)),
                        _clean_reason(reason),
                        _json_dumps(details),
                        _now(),
                    ),
                )

                return int(cursor.lastrowid)

            finally:
                connection.close()

        return await self._execute(operation)

    async def get_active_emergency(
        self,
        guild_id: int,
    ) -> Optional[dict[str, Any]]:
        """
        Guild'de aktif Emergency var mı?
        """

        def operation():
            connection = self._connect()

            try:
                row = connection.execute(
                    """
                    SELECT *
                    FROM emergency_events
                    WHERE guild_id = ?
                    AND status = 'ACTIVE'
                    ORDER BY started_at DESC
                    LIMIT 1
                    """,
                    (guild_id,),
                ).fetchone()

                if not row:
                    return None

                result = dict(row)

                result["details"] = _safe_json(
                    result.get("details"),
                    default={},
                )

                return result

            finally:
                connection.close()

        return await self._execute(operation)

    async def resolve_emergency(
        self,
        emergency_id: int,
        *,
        resolved_by: Optional[int] = None,
        reason: Optional[str] = None,
    ) -> bool:
        """
        Emergency olayını kapatır.
        """

        def operation():
            connection = self._connect()

            try:
                cursor = connection.execute(
                    """
                    UPDATE emergency_events
                    SET
                        status = 'RESOLVED',
                        ended_at = ?,
                        resolved_by = ?,
                        resolution_reason = ?
                    WHERE id = ?
                    AND status = 'ACTIVE'
                    """,
                    (
                        _now(),
                        resolved_by,
                        _clean_reason(reason),
                        emergency_id,
                    ),
                )

                return cursor.rowcount > 0

            finally:
                connection.close()

        return await self._execute(operation)

    # ========================================================
    # WHITELIST
    # ========================================================

    async def add_whitelist(
        self,
        guild_id: int,
        user_id: int,
        *,
        added_by: Optional[int] = None,
        reason: Optional[str] = None,
    ) -> bool:
        """
        Kullanıcıyı whitelist'e ekler.
        """

        def operation():
            connection = self._connect()

            try:
                cursor = connection.execute(
                    """
                    INSERT OR REPLACE INTO whitelist
                    (
                        guild_id,
                        user_id,
                        added_by,
                        reason,
                        created_at
                    )
                    VALUES (?, ?, ?, ?, ?)
                    """,
                    (
                        guild_id,
                        user_id,
                        added_by,
                        _clean_reason(reason),
                        _now(),
                    ),
                )

                return cursor.rowcount > 0

            finally:
                connection.close()

        return await self._execute(operation)

    async def remove_whitelist(
        self,
        guild_id: int,
        user_id: int,
    ) -> bool:
        """
        Whitelist'ten kullanıcıyı kaldırır.
        """

        def operation():
            connection = self._connect()

            try:
                cursor = connection.execute(
                    """
                    DELETE FROM whitelist
                    WHERE guild_id = ?
                    AND user_id = ?
                    """,
                    (
                        guild_id,
                        user_id,
                    ),
                )

                return cursor.rowcount > 0

            finally:
                connection.close()

        return await self._execute(operation)

    async def is_whitelisted(
        self,
        guild_id: int,
        user_id: int,
    ) -> bool:
        """
        Kullanıcı whitelist'te mi?
        """

        def operation():
            connection = self._connect()

            try:
                row = connection.execute(
                    """
                    SELECT 1
                    FROM whitelist
                    WHERE guild_id = ?
                    AND user_id = ?
                    LIMIT 1
                    """,
                    (
                        guild_id,
                        user_id,
                    ),
                ).fetchone()

                return row is not None

            finally:
                connection.close()

        return await self._execute(operation)

    async def get_whitelist(
        self,
        guild_id: int,
    ) -> list[dict[str, Any]]:
        """
        Guild whitelist'ini getirir.
        """

        def operation():
            connection = self._connect()

            try:
                rows = connection.execute(
                    """
                    SELECT *
                    FROM whitelist
                    WHERE guild_id = ?
                    ORDER BY created_at ASC
                    """,
                    (guild_id,),
                ).fetchall()

                return [
                    dict(row)
                    for row in rows
                ]

            finally:
                connection.close()

        return await self._execute(operation)

    # ========================================================
    # APPROVALS
    # ========================================================

    async def create_approval(
        self,
        guild_id: int,
        action_type: str,
        *,
        target_id: Optional[int] = None,
        requested_by: Optional[int] = None,
        reason: Optional[str] = None,
        details: Optional[dict[str, Any]] = None,
        expires_in: int = 120,
    ) -> int:
        """
        Onay bekleyen bir işlem oluşturur.

        Özellikle:
            kick
            ban
            emergency-sensitive actions

        için kullanılabilir.
        """

        now = _now()

        expires_at = (
            now + max(1, expires_in)
            if expires_in > 0
            else None
        )

        def operation():
            connection = self._connect()

            try:
                cursor = connection.execute(
                    """
                    INSERT INTO approvals
                    (
                        guild_id,
                        target_id,
                        action_type,
                        requested_by,
                        status,
                        reason,
                        details,
                        created_at,
                        expires_at
                    )
                    VALUES (?, ?, ?, ?, 'PENDING', ?, ?, ?, ?)
                    """,
                    (
                        guild_id,
                        target_id,
                        action_type,
                        requested_by,
                        _clean_reason(reason),
                        _json_dumps(details),
                        now,
                        expires_at,
                    ),
                )

                return int(cursor.lastrowid)

            finally:
                connection.close()

        return await self._execute(operation)

    async def get_approval(
        self,
        approval_id: int,
    ) -> Optional[dict[str, Any]]:
        """
        Approval detayını getirir.
        """

        def operation():
            connection = self._connect()

            try:
                row = connection.execute(
                    """
                    SELECT *
                    FROM approvals
                    WHERE id = ?
                    """,
                    (approval_id,),
                ).fetchone()

                if not row:
                    return None

                result = dict(row)

                result["details"] = _safe_json(
                    result.get("details"),
                    default={},
                )

                return result

            finally:
                connection.close()

        return await self._execute(operation)

    async def get_pending_approvals(
        self,
        guild_id: int,
        *,
        requested_by: Optional[int] = None,
    ) -> list[dict[str, Any]]:
        """
        Bekleyen approval'ları getirir.

        Süresi geçmiş kayıtlar otomatik olarak EXPIRED yapılır.
        """

        await self.expire_approvals(guild_id)

        conditions = [
            "guild_id = ?",
            "status = 'PENDING'",
        ]

        parameters: list[Any] = [
            guild_id
        ]

        if requested_by is not None:
            conditions.append(
                "requested_by = ?"
            )
            parameters.append(requested_by)

        where = " AND ".join(conditions)

        def operation():
            connection = self._connect()

            try:
                rows = connection.execute(
                    f"""
                    SELECT *
                    FROM approvals
                    WHERE {where}
                    ORDER BY created_at ASC
                    """,
                    parameters,
                ).fetchall()

                return [
                    dict(row)
                    for row in rows
                ]

            finally:
                connection.close()

        return await self._execute(operation)

    async def resolve_approval(
        self,
        approval_id: int,
        *,
        approved: bool,
        resolver_id: int,
        reason: Optional[str] = None,
    ) -> bool:
        """
        Approval'ı approve/reject eder.
        """

        status = (
            "APPROVED"
            if approved
            else "REJECTED"
        )

        resolver_column = (
            "approved_by"
            if approved
            else "rejected_by"
        )

        def operation():
            connection = self._connect()

            try:
                cursor = connection.execute(
                    f"""
                    UPDATE approvals
                    SET
                        status = ?,
                        {resolver_column} = ?,
                        resolved_at = ?,
                        reason = COALESCE(?, reason)
                    WHERE id = ?
                    AND status = 'PENDING'
                    """,
                    (
                        status,
                        resolver_id,
                        _now(),
                        _clean_reason(reason),
                        approval_id,
                    ),
                )

                return cursor.rowcount > 0

            finally:
                connection.close()

        return await self._execute(operation)

    async def expire_approvals(
        self,
        guild_id: Optional[int] = None,
    ) -> int:
        """
        Süresi geçen approval'ları EXPIRED yapar.
        """

        now = _now()

        def operation():
            connection = self._connect()

            try:
                if guild_id is None:
                    cursor = connection.execute(
                        """
                        UPDATE approvals
                        SET
                            status = 'EXPIRED',
                            resolved_at = ?
                        WHERE status = 'PENDING'
                        AND expires_at IS NOT NULL
                        AND expires_at <= ?
                        """,
                        (
                            now,
                            now,
                        ),
                    )

                else:
                    cursor = connection.execute(
                        """
                        UPDATE approvals
                        SET
                            status = 'EXPIRED',
                            resolved_at = ?
                        WHERE guild_id = ?
                        AND status = 'PENDING'
                        AND expires_at IS NOT NULL
                        AND expires_at <= ?
                        """,
                        (
                            now,
                            guild_id,
                            now,
                        ),
                    )

                return cursor.rowcount

            finally:
                connection.close()

        return await self._execute(operation)

    # ========================================================
    # ROLE SNAPSHOT
    # ========================================================

    async def save_role_snapshot(
        self,
        guild_id: int,
        user_id: int,
        role_ids: Iterable[int],
        *,
        reason: Optional[str] = None,
    ) -> int:
        """
        Kullanıcının mevcut rollerini kaydeder.

        Emergency sırasında roller kaldırılmadan önce kullanılır.
        """

        roles = [
            int(role_id)
            for role_id in role_ids
        ]

        # Aynı kullanıcı için eski active snapshot'ı kapat.
        def operation():
            connection = self._connect()

            try:
                connection.execute(
                    """
                    UPDATE role_snapshots
                    SET active = 0
                    WHERE guild_id = ?
                    AND user_id = ?
                    AND active = 1
                    """,
                    (
                        guild_id,
                        user_id,
                    ),
                )

                cursor = connection.execute(
                    """
                    INSERT INTO role_snapshots
                    (
                        guild_id,
                        user_id,
                        role_ids,
                        reason,
                        active,
                        created_at
                    )
                    VALUES (?, ?, ?, ?, 1, ?)
                    """,
                    (
                        guild_id,
                        user_id,
                        _json_dumps(roles),
                        _clean_reason(reason),
                        _now(),
                    ),
                )

                return int(cursor.lastrowid)

            finally:
                connection.close()

        return await self._execute(operation)

    async def get_active_role_snapshot(
        self,
        guild_id: int,
        user_id: int,
    ) -> Optional[dict[str, Any]]:
        """
        Kullanıcının aktif role snapshot'ını getirir.
        """

        def operation():
            connection = self._connect()

            try:
                row = connection.execute(
                    """
                    SELECT *
                    FROM role_snapshots
                    WHERE guild_id = ?
                    AND user_id = ?
                    AND active = 1
                    ORDER BY created_at DESC
                    LIMIT 1
                    """,
                    (
                        guild_id,
                        user_id,
                    ),
                ).fetchone()

                if not row:
                    return None

                result = dict(row)

                result["role_ids"] = _safe_json(
                    result.get("role_ids"),
                    default=[],
                )

                return result

            finally:
                connection.close()

        return await self._execute(operation)

    async def mark_role_snapshot_restored(
        self,
        snapshot_id: int,
        *,
        restored_by: Optional[int] = None,
    ) -> bool:
        """
        Snapshot restore edildi olarak işaretler.
        """

        def operation():
            connection = self._connect()

            try:
                cursor = connection.execute(
                    """
                    UPDATE role_snapshots
                    SET
                        active = 0,
                        restored_at = ?,
                        restored_by = ?
                    WHERE id = ?
                    AND active = 1
                    """,
                    (
                        _now(),
                        restored_by,
                        snapshot_id,
                    ),
                )

                return cursor.rowcount > 0

            finally:
                connection.close()

        return await self._execute(operation)

    # ========================================================
    # LOCKDOWN
    # ========================================================

    async def create_lockdown(
        self,
        guild_id: int,
        *,
        started_by: Optional[int] = None,
        reason: Optional[str] = None,
        affected_channels: Optional[Iterable[int]] = None,
    ) -> int:
        """
        Lockdown kaydı oluşturur.
        """

        channels = [
            int(channel_id)
            for channel_id in (
                affected_channels or []
            )
        ]

        def operation():
            connection = self._connect()

            try:
                cursor = connection.execute(
                    """
                    INSERT INTO lockdowns
                    (
                        guild_id,
                        started_by,
                        status,
                        reason,
                        affected_channels,
                        started_at
                    )
                    VALUES (?, ?, 'ACTIVE', ?, ?, ?)
                    """,
                    (
                        guild_id,
                        started_by,
                        _clean_reason(reason),
                        _json_dumps(channels),
                        _now(),
                    ),
                )

                return int(cursor.lastrowid)

            finally:
                connection.close()

        return await self._execute(operation)

    async def get_active_lockdown(
        self,
        guild_id: int,
    ) -> Optional[dict[str, Any]]:
        """
        Aktif lockdown'ı getirir.
        """

        def operation():
            connection = self._connect()

            try:
                row = connection.execute(
                    """
                    SELECT *
                    FROM lockdowns
                    WHERE guild_id = ?
                    AND status = 'ACTIVE'
                    ORDER BY started_at DESC
                    LIMIT 1
                    """,
                    (guild_id,),
                ).fetchone()

                if not row:
                    return None

                result = dict(row)

                result["affected_channels"] = _safe_json(
                    result.get("affected_channels"),
                    default=[],
                )

                return result

            finally:
                connection.close()

        return await self._execute(operation)

    async def resolve_lockdown(
        self,
        lockdown_id: int,
        *,
        ended_by: Optional[int] = None,
    ) -> bool:
        """
        Lockdown'u sonlandırır.
        """

        def operation():
            connection = self._connect()

            try:
                cursor = connection.execute(
                    """
                    UPDATE lockdowns
                    SET
                        status = 'RESOLVED',
                        ended_at = ?,
                        ended_by = ?
                    WHERE id = ?
                    AND status = 'ACTIVE'
                    """,
                    (
                        _now(),
                        ended_by,
                        lockdown_id,
                    ),
                )

                return cursor.rowcount > 0

            finally:
                connection.close()

        return await self._execute(operation)

    # ========================================================
    # THREAT HISTORY
    # ========================================================

    async def add_threat(
        self,
        guild_id: int,
        user_id: int,
        threat_type: str,
        *,
        risk_score: int = 0,
        action_taken: Optional[str] = None,
        evidence: Optional[dict[str, Any]] = None,
    ) -> int:
        """
        Threat history kaydı oluşturur.
        """

        def operation():
            connection = self._connect()

            try:
                cursor = connection.execute(
                    """
                    INSERT INTO threat_history
                    (
                        guild_id,
                        user_id,
                        threat_type,
                        risk_score,
                        action_taken,
                        evidence,
                        created_at
                    )
                    VALUES (?, ?, ?, ?, ?, ?, ?)
                    """,
                    (
                        guild_id,
                        user_id,
                        threat_type,
                        max(
                            0,
                            min(risk_score, 100),
                        ),
                        action_taken,
                        _json_dumps(evidence),
                        _now(),
                    ),
                )

                return int(cursor.lastrowid)

            finally:
                connection.close()

        return await self._execute(operation)

    async def get_threat_history(
        self,
        guild_id: int,
        user_id: int,
        *,
        limit: int = 50,
    ) -> list[dict[str, Any]]:
        """
        Kullanıcının threat geçmişini getirir.
        """

        limit = max(
            1,
            min(limit, 500),
        )

        def operation():
            connection = self._connect()

            try:
                rows = connection.execute(
                    """
                    SELECT *
                    FROM threat_history
                    WHERE guild_id = ?
                    AND user_id = ?
                    ORDER BY created_at DESC
                    LIMIT ?
                    """,
                    (
                        guild_id,
                        user_id,
                        limit,
                    ),
                ).fetchall()

                return [
                    {
                        **dict(row),
                        "evidence": _safe_json(
                            row["evidence"],
                            default={},
                        ),
                    }
                    for row in rows
                ]

            finally:
                connection.close()

        return await self._execute(operation)

    # ========================================================
    # BACKUPS
    # ========================================================

    async def add_backup(
        self,
        guild_id: int,
        backup_type: str,
        *,
        location: Optional[str] = None,
        metadata: Optional[dict[str, Any]] = None,
        created_by: Optional[int] = None,
    ) -> int:
        """
        Backup metadata kaydeder.
        """

        def operation():
            connection = self._connect()

            try:
                cursor = connection.execute(
                    """
                    INSERT INTO backups
                    (
                        guild_id,
                        backup_type,
                        location,
                        metadata,
                        created_by,
                        created_at
                    )
                    VALUES (?, ?, ?, ?, ?, ?)
                    """,
                    (
                        guild_id,
                        backup_type,
                        location,
                        _json_dumps(metadata),
                        created_by,
                        _now(),
                    ),
                )

                return int(cursor.lastrowid)

            finally:
                connection.close()

        return await self._execute(operation)

    async def get_backups(
        self,
        guild_id: int,
        *,
        backup_type: Optional[str] = None,
        limit: int = 50,
    ) -> list[dict[str, Any]]:
        """
        Backup kayıtlarını getirir.
        """

        limit = max(
            1,
            min(limit, 500),
        )

        if backup_type is None:

            def operation():
                connection = self._connect()

                try:
                    rows = connection.execute(
                        """
                        SELECT *
                        FROM backups
                        WHERE guild_id = ?
                        ORDER BY created_at DESC
                        LIMIT ?
                        """,
                        (
                            guild_id,
                            limit,
                        ),
                    ).fetchall()

                    return [
                        dict(row)
                        for row in rows
                    ]

                finally:
                    connection.close()

        else:

            def operation():
                connection = self._connect()

                try:
                    rows = connection.execute(
                        """
                        SELECT *
                        FROM backups
                        WHERE guild_id = ?
                        AND backup_type = ?
                        ORDER BY created_at DESC
                        LIMIT ?
                        """,
                        (
                            guild_id,
                            backup_type,
                            limit,
                        ),
                    ).fetchall()

                    return [
                        dict(row)
                        for row in rows
                    ]

                finally:
                    connection.close()

        return await self._execute(operation)

    # ========================================================
    # CLEANUP
    # ========================================================

    async def cleanup_old_events(
        self,
        *,
        days: int = 30,
    ) -> dict[str, int]:
        """
        Eski logları temizler.

        Varsayılan olarak 30 günden eski:
        - security events
        - action history
        - threat history

        kayıtlarını temizler.

        Emergency / approval / snapshot gibi kritik veriler
        silinmez.
        """

        days = max(1, days)

        cutoff = _now() - (
            days * 86_400
        )

        def operation():
            connection = self._connect()

            try:
                connection.execute(
                    "BEGIN;"
                )

                events = connection.execute(
                    """
                    DELETE FROM security_events
                    WHERE created_at < ?
                    """,
                    (cutoff,),
                ).rowcount

                actions = connection.execute(
                    """
                    DELETE FROM action_history
                    WHERE created_at < ?
                    """,
                    (cutoff,),
                ).rowcount

                threats = connection.execute(
                    """
                    DELETE FROM threat_history
                    WHERE created_at < ?
                    """,
                    (cutoff,),
                ).rowcount

                connection.execute(
                    "COMMIT;"
                )

                return {
                    "security_events": events,
                    "action_history": actions,
                    "threat_history": threats,
                }

            except Exception:
                connection.execute(
                    "ROLLBACK;"
                )
                raise

            finally:
                connection.close()

        result = await self._execute(
            operation
        )

        database_logger.info(
            "Database cleanup completed: %s",
            result,
        )

        return result

    # ========================================================
    # STATISTICS
    # ========================================================

    async def get_statistics(
        self,
        guild_id: int,
    ) -> dict[str, int]:
        """
        Guild database istatistiklerini döndürür.
        """

        tables = {
            "security_events": "security_events",
            "actions": "action_history",
            "emergencies": "emergency_events",
            "whitelist": "whitelist",
            "approvals": "approvals",
            "threats": "threat_history",
            "snapshots": "role_snapshots",
            "lockdowns": "lockdowns",
            "backups": "backups",
        }

        def operation():
            connection = self._connect()

            try:
                result: dict[str, int] = {}

                for key, table in tables.items():
                    row = connection.execute(
                        f"""
                        SELECT COUNT(*) AS count
                        FROM {table}
                        WHERE guild_id = ?
                        """,
                        (guild_id,),
                    ).fetchone()

                    result[key] = int(
                        row["count"]
                    )

                return result

            finally:
                connection.close()

        return await self._execute(operation)

    # ========================================================
    # HEALTH
    # ========================================================

    async def health_check(self) -> bool:
        """
        Database'in erişilebilir olup olmadığını kontrol eder.
        """

        def operation():
            connection = self._connect()

            try:
                row = connection.execute(
                    "SELECT 1 AS ok"
                ).fetchone()

                return bool(
                    row and row["ok"] == 1
                )

            finally:
                connection.close()

        try:
            return await self._execute(
                operation
            )

        except Exception as exc:
            database_logger.error(
                "Database health check failed: %s",
                exc,
            )

            return False

    # ========================================================
    # CLOSE
    # ========================================================

    async def close(self) -> None:
        """
        Bu implementation'da persistent connection olmadığı
        için kapatılacak bağlantı bulunmaz.

        API uyumluluğu için tutulmuştur.
        """

        self._initialized = False

        database_logger.info(
            "Database service closed."
        )


# ============================================================
# GLOBAL INSTANCE
# ============================================================

database_service = DatabaseService()


# ============================================================
# EXPORTS
# ============================================================

__all__ = [
    "DatabaseService",
    "database_service",
    "DEFAULT_DB_PATH",
    "SCHEMA_VERSION",
]