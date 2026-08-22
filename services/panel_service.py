# services/panel_service.py

from __future__ import annotations

import asyncio
import copy
import json
import os
import tempfile
from pathlib import Path
from typing import Any, Optional


class PanelService:
    """
    PAG Security Bot - Panel Configuration Service.

    Görevi:
        - Guild bazlı ayarları yönetmek
        - JSON configuration oluşturmak
        - Ayarları değiştirmek
        - Güvenli varsayılanlar sağlamak
        - Atomic file write yapmak
        - SecurityService tarafından hızlı okunabilen
          config sağlamak

    .env içerisinde tutulmaması gereken ayarlar burada tutulur.

    Örnek:
        data/
            guilds/
                123456789.json
                987654321.json
    """

    DEFAULT_CONFIG: dict[str, Any] = {
        "version": 1,

        "security": {
            "enabled": True,
            "smart_detection": True,
            "emergency_mode": True,
        },

        "detection": {
            "window_seconds": 15,

            "thresholds": {
                "kick": 5,
                "ban": 3,
                "channel_delete": 5,
                "channel_create": 8,
                "role_delete": 3,
                "role_create": 8,
                "webhook_create": 4,
                "bot_add": 2,
                "permission_change": 3,
            },

            "risk_weights": {
                "kick": 20,
                "ban": 35,
                "channel_delete": 35,
                "channel_create": 15,
                "role_delete": 40,
                "role_create": 15,
                "webhook_create": 30,
                "bot_add": 40,
                "permission_change": 35,
            },

            "risk_levels": {
                "suspicious": 40,
                "high": 65,
                "critical": 85,
            },
        },

        "emergency": {
            "remove_dangerous_roles": True,
            "quarantine": False,
            "lockdown": True,

            "remove_permissions": [
                "administrator",
                "manage_guild",
                "manage_channels",
                "manage_roles",
                "manage_webhooks",
                "kick_members",
                "ban_members",
                "moderate_members",
                "mention_everyone",
            ],

            "minimum_actions_for_emergency": 1,
        },

        "protection": {
            "protect_owner": True,
            "protect_bot": True,
            "protect_verified_users": True,
            "protect_managed_roles": True,
            "protect_everyone_role": True,
        },

        "notifications": {
            "dm_enabled": True,
            "dm_on_high": True,
            "dm_on_emergency": True,
        },

        "actions": {
            "auto_ban": False,
            "auto_kick": False,
            "auto_delete_actor": False,
        },

        "whitelist": {
            "users": [],
            "roles": [],
            "channels": [],
        },
    }

    def __init__(
        self,
        *,
        data_dir: str | Path = "data",
    ) -> None:

        self.data_dir = Path(data_dir)
        self.guild_dir = self.data_dir / "guilds"

        self.guild_dir.mkdir(
            parents=True,
            exist_ok=True,
        )

        self._cache: dict[int, dict[str, Any]] = {}
        self._locks: dict[int, asyncio.Lock] = {}

        self._global_lock = asyncio.Lock()

    # =========================================================
    # PATH
    # =========================================================

    def get_path(
        self,
        guild_id: int,
    ) -> Path:

        return self.guild_dir / f"{guild_id}.json"

    # =========================================================
    # LOCK
    # =========================================================

    def _get_lock(
        self,
        guild_id: int,
    ) -> asyncio.Lock:

        lock = self._locks.get(guild_id)

        if lock is None:
            lock = asyncio.Lock()
            self._locks[guild_id] = lock

        return lock

    # =========================================================
    # DEFAULT CONFIG
    # =========================================================

    def default_config(self) -> dict[str, Any]:

        return copy.deepcopy(
            self.DEFAULT_CONFIG
        )

    # =========================================================
    # DEEP MERGE
    # =========================================================

    @staticmethod
    def _deep_merge(
        base: dict[str, Any],
        override: dict[str, Any],
    ) -> dict[str, Any]:
        """
        Nested dictionary merge.

        Böylece config'in sadece bir bölümü değiştirildiğinde
        diğer varsayılan ayarlar kaybolmaz.
        """

        result = copy.deepcopy(base)

        for key, value in override.items():

            if (
                key in result
                and isinstance(result[key], dict)
                and isinstance(value, dict)
            ):
                result[key] = PanelService._deep_merge(
                    result[key],
                    value,
                )

            else:
                result[key] = copy.deepcopy(
                    value
                )

        return result

    # =========================================================
    # VALIDATION
    # =========================================================

    def _validate(
        self,
        config: dict[str, Any],
    ) -> dict[str, Any]:
        """
        Config'i güvenli hale getirir.

        Bozuk / eksik config botu düşürmemeli.
        """

        safe = self._deep_merge(
            self.DEFAULT_CONFIG,
            config,
        )

        detection = safe["detection"]

        window = detection.get(
            "window_seconds",
            15,
        )

        try:
            window = int(window)
        except (TypeError, ValueError):
            window = 15

        detection["window_seconds"] = max(
            1,
            min(window, 3600),
        )

        thresholds = detection["thresholds"]

        for key in list(thresholds):

            try:
                value = int(
                    thresholds[key]
                )
            except (TypeError, ValueError):
                value = self.DEFAULT_CONFIG[
                    "detection"
                ]["thresholds"].get(
                    key,
                    1,
                )

            thresholds[key] = max(
                1,
                min(value, 1000),
            )

        weights = detection["risk_weights"]

        for key in list(weights):

            try:
                value = int(
                    weights[key]
                )
            except (TypeError, ValueError):
                value = 10

            weights[key] = max(
                0,
                min(value, 1000),
            )

        levels = detection["risk_levels"]

        for key in (
            "suspicious",
            "high",
            "critical",
        ):

            try:
                value = int(
                    levels[key]
                )
            except (TypeError, ValueError):
                value = self.DEFAULT_CONFIG[
                    "detection"
                ]["risk_levels"][key]

            levels[key] = max(
                1,
                min(value, 10000),
            )

        # Sıralama garantisi.
        levels["high"] = max(
            levels["high"],
            levels["suspicious"] + 1,
        )

        levels["critical"] = max(
            levels["critical"],
            levels["high"] + 1,
        )

        return safe

    # =========================================================
    # LOAD
    # =========================================================

    async def load(
        self,
        guild_id: int,
    ) -> dict[str, Any]:

        lock = self._get_lock(guild_id)

        async with lock:

            if guild_id in self._cache:
                return copy.deepcopy(
                    self._cache[guild_id]
                )

            path = self.get_path(
                guild_id
            )

            if not path.exists():

                config = self.default_config()

                await self._write(
                    guild_id,
                    config,
                )

                self._cache[guild_id] = config

                return copy.deepcopy(
                    config
                )

            try:

                raw = await asyncio.to_thread(
                    path.read_text,
                    encoding="utf-8",
                )

                parsed = json.loads(raw)

                if not isinstance(
                    parsed,
                    dict,
                ):
                    raise ValueError(
                        "Configuration root must be object."
                    )

                config = self._validate(
                    parsed
                )

            except (
                OSError,
                json.JSONDecodeError,
                ValueError,
                TypeError,
            ):

                # Bozuk dosya botu çökertmesin.
                config = self.default_config()

                await self._write(
                    guild_id,
                    config,
                )

            self._cache[guild_id] = config

            return copy.deepcopy(
                config
            )

    # =========================================================
    # SAVE
    # =========================================================

    async def save(
        self,
        guild_id: int,
        config: dict[str, Any],
    ) -> dict[str, Any]:

        lock = self._get_lock(guild_id)

        async with lock:

            validated = self._validate(
                config
            )

            await self._write(
                guild_id,
                validated,
            )

            self._cache[guild_id] = validated

            return copy.deepcopy(
                validated
            )

    # =========================================================
    # ATOMIC WRITE
    # =========================================================

    async def _write(
        self,
        guild_id: int,
        config: dict[str, Any],
    ) -> None:

        path = self.get_path(
            guild_id
        )

        path.parent.mkdir(
            parents=True,
            exist_ok=True,
        )

        payload = json.dumps(
            config,
            ensure_ascii=False,
            indent=4,
        )

        def write_atomic() -> None:

            fd, temp_path = tempfile.mkstemp(
                prefix=f".{guild_id}.",
                suffix=".tmp",
                dir=str(path.parent),
            )

            try:

                with os.fdopen(
                    fd,
                    "w",
                    encoding="utf-8",
                ) as file:

                    file.write(payload)
                    file.flush()
                    os.fsync(
                        file.fileno()
                    )

                os.replace(
                    temp_path,
                    path,
                )

            except Exception:

                try:
                    os.unlink(
                        temp_path
                    )
                except OSError:
                    pass

                raise

        await asyncio.to_thread(
            write_atomic
        )

    # =========================================================
    # GET
    # =========================================================

    async def get(
        self,
        guild_id: int,
        key: Optional[str] = None,
        default: Any = None,
    ) -> Any:

        config = await self.load(
            guild_id
        )

        if key is None:
            return config

        current: Any = config

        for part in key.split("."):

            if not isinstance(
                current,
                dict,
            ):
                return default

            if part not in current:
                return default

            current = current[part]

        return copy.deepcopy(
            current
        )

    # =========================================================
    # SET
    # =========================================================

    async def set(
        self,
        guild_id: int,
        key: str,
        value: Any,
    ) -> dict[str, Any]:

        config = await self.load(
            guild_id
        )

        parts = key.split(".")

        if not parts:
            raise ValueError(
                "Config key boş olamaz."
            )

        current = config

        for part in parts[:-1]:

            if part not in current:
                current[part] = {}

            if not isinstance(
                current[part],
                dict,
            ):
                current[part] = {}

            current = current[part]

        current[parts[-1]] = value

        return await self.save(
            guild_id,
            config,
        )

    # =========================================================
    # DELETE / RESET
    # =========================================================

    async def reset(
        self,
        guild_id: int,
    ) -> dict[str, Any]:

        config = self.default_config()

        await self.save(
            guild_id,
            config,
        )

        return config

    # =========================================================
    # CACHE
    # =========================================================

    def invalidate(
        self,
        guild_id: int,
    ) -> None:

        self._cache.pop(
            guild_id,
            None,
        )

    def clear_cache(self) -> None:

        self._cache.clear()

    # =========================================================
    # SECURITY HELPERS
    # =========================================================

    async def is_enabled(
        self,
        guild_id: int,
    ) -> bool:

        return bool(
            await self.get(
                guild_id,
                "security.enabled",
                True,
            )
        )

    async def emergency_enabled(
        self,
        guild_id: int,
    ) -> bool:

        return bool(
            await self.get(
                guild_id,
                "security.emergency_mode",
                True,
            )
        )

    async def smart_detection_enabled(
        self,
        guild_id: int,
    ) -> bool:

        return bool(
            await self.get(
                guild_id,
                "security.smart_detection",
                True,
            )
        )

    async def is_whitelisted_user(
        self,
        guild_id: int,
        user_id: int,
    ) -> bool:

        users = await self.get(
            guild_id,
            "whitelist.users",
            [],
        )

        try:
            return int(user_id) in {
                int(value)
                for value in users
            }
        except (
            TypeError,
            ValueError,
        ):
            return False

    async def is_whitelisted_role(
        self,
        guild_id: int,
        role_id: int,
    ) -> bool:

        roles = await self.get(
            guild_id,
            "whitelist.roles",
            [],
        )

        try:
            return int(role_id) in {
                int(value)
                for value in roles
            }
        except (
            TypeError,
            ValueError,
        ):
            return False

    async def get_threshold(
        self,
        guild_id: int,
        action: str,
    ) -> int:

        value = await self.get(
            guild_id,
            f"detection.thresholds.{action}",
            5,
        )

        try:
            return max(
                1,
                int(value),
            )
        except (
            TypeError,
            ValueError,
        ):
            return 5

    async def get_risk_weight(
        self,
        guild_id: int,
        action: str,
    ) -> int:

        value = await self.get(
            guild_id,
            f"detection.risk_weights.{action}",
            10,
        )

        try:
            return max(
                0,
                int(value),
            )
        except (
            TypeError,
            ValueError,
        ):
            return 10

    async def get_risk_level(
        self,
        guild_id: int,
        level: str,
    ) -> int:

        value = await self.get(
            guild_id,
            f"detection.risk_levels.{level}",
            85,
        )

        try:
            return max(
                1,
                int(value),
            )
        except (
            TypeError,
            ValueError,
        ):
            return 85


__all__ = [
    "PanelService",
]