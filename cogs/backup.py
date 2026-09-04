# cogs/backup.py

from __future__ import annotations

import asyncio
import copy
import json
import os
import tempfile
import time
import uuid
from pathlib import Path
from typing import Any, Optional

import discord
from discord.ext import commands

from utils.logger import security_logger


# ============================================================
# PAG SECURITY BOT
# cogs/backup.py
#
# Sunucu Backup Sistemi
#
# Özellikler:
#   !backup
#   !backup create
#   !backup list
#   !backup info <id>
#   !backup delete <id>
#   !backup restore <id>
#
# Panel:
#   📦 Create Backup
#   📋 List Backups
#   🔎 Backup Info
#   ♻️ Restore Backup
#   🗑️ Delete Backup
#
# NOT:
#   - Otomatik mesaj göndermez.
#   - Otomatik backup oluşturmaz.
#   - Otomatik restore yapmaz.
#   - Restore işlemi onay ister.
#   - Guild bazlı lock kullanır.
#   - Backup dosyaları atomic yazılır.
# ============================================================


BACKUP_ROOT = Path("data") / "backups"

MAX_BACKUPS_PER_GUILD = 50

BACKUP_VERSION = 1

COMMAND_TIMEOUT = 60


# ============================================================
# PERMISSIONS
# ============================================================


def has_backup_permission(
    member: discord.Member,
) -> bool:
    """
    Backup yönetimi için güvenli yetki kontrolü.

    Administrator:
        Her şeyi yapabilir.

    Manage Guild:
        Backup işlemlerini yapabilir.

    Restore:
        Ek olarak Administrator veya Manage Guild gerekir.
    """

    permissions = member.guild_permissions

    return (
        permissions.administrator
        or permissions.manage_guild
    )


# ============================================================
# HELPERS
# ============================================================


def utc_timestamp() -> int:
    return int(time.time())


def format_timestamp(timestamp: int) -> str:
    return discord.utils.format_dt(
        discord.utils.utcfromtimestamp(timestamp),
        style="F",
    )


def safe_backup_id(value: str) -> bool:
    """
    Backup ID path traversal engellemesi.
    """

    if not value:
        return False

    allowed = (
        "abcdefghijklmnopqrstuvwxyz"
        "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
        "0123456789-_"
    )

    return all(
        char in allowed
        for char in value
    )


# ============================================================
# BACKUP SERVICE
# ============================================================


class BackupService:
    """
    Sunucu backup verilerini yönetir.

    Discord API işlemlerini Cog yapar.
    Dosya yönetimini bu servis yapar.
    """

    def __init__(
        self,
        root: str | Path = BACKUP_ROOT,
    ) -> None:

        self.root = Path(root)

        self.root.mkdir(
            parents=True,
            exist_ok=True,
        )

        self._locks: dict[int, asyncio.Lock] = {}

    # ========================================================
    # LOCK
    # ========================================================

    def get_lock(
        self,
        guild_id: int,
    ) -> asyncio.Lock:

        lock = self._locks.get(guild_id)

        if lock is None:

            lock = asyncio.Lock()

            self._locks[guild_id] = lock

        return lock

    # ========================================================
    # PATH
    # ========================================================

    def guild_directory(
        self,
        guild_id: int,
    ) -> Path:

        path = self.root / str(guild_id)

        path.mkdir(
            parents=True,
            exist_ok=True,
        )

        return path

    def backup_path(
        self,
        guild_id: int,
        backup_id: str,
    ) -> Path:

        if not safe_backup_id(backup_id):

            raise ValueError(
                "Invalid backup ID."
            )

        return (
            self.guild_directory(guild_id)
            / f"{backup_id}.json"
        )

    # ========================================================
    # ATOMIC WRITE
    # ========================================================

    async def write(
        self,
        path: Path,
        data: dict[str, Any],
    ) -> None:

        payload = json.dumps(
            data,
            ensure_ascii=False,
            indent=2,
        )

        def atomic_write() -> None:

            path.parent.mkdir(
                parents=True,
                exist_ok=True,
            )

            fd, temp_path = tempfile.mkstemp(
                prefix=".backup-",
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
                    os.unlink(temp_path)
                except OSError:
                    pass

                raise

        await asyncio.to_thread(
            atomic_write
        )

    # ========================================================
    # READ
    # ========================================================

    async def read(
        self,
        guild_id: int,
        backup_id: str,
    ) -> dict[str, Any]:

        path = self.backup_path(
            guild_id,
            backup_id,
        )

        if not path.exists():

            raise FileNotFoundError(
                "Backup bulunamadı."
            )

        def read_file() -> dict[str, Any]:

            with path.open(
                "r",
                encoding="utf-8",
            ) as file:

                data = json.load(file)

            if not isinstance(
                data,
                dict,
            ):

                raise ValueError(
                    "Backup root object değil."
                )

            return data

        return await asyncio.to_thread(
            read_file
        )

    # ========================================================
    # LIST
    # ========================================================

    async def list_backups(
        self,
        guild_id: int,
    ) -> list[dict[str, Any]]:

        directory = self.guild_directory(
            guild_id
        )

        files = list(
            directory.glob("*.json")
        )

        results: list[dict[str, Any]] = []

        for path in files:

            try:

                data = await asyncio.to_thread(
                    self._read_metadata,
                    path,
                )

                if isinstance(data, dict):

                    results.append(data)

            except Exception:

                security_logger.warning(
                    "Invalid backup skipped | path=%s",
                    path,
                )

        results.sort(
            key=lambda item: int(
                item.get(
                    "created_at",
                    0,
                )
            ),
            reverse=True,
        )

        return results

    @staticmethod
    def _read_metadata(
        path: Path,
    ) -> dict[str, Any]:

        with path.open(
            "r",
            encoding="utf-8",
        ) as file:

            data = json.load(file)

        return {
            "id": data.get("id"),
            "guild_id": data.get("guild_id"),
            "guild_name": data.get("guild_name"),
            "created_at": data.get("created_at"),
            "created_by": data.get("created_by"),
            "created_by_name": data.get(
                "created_by_name"
            ),
            "version": data.get("version"),
            "category_count": len(
                data.get("categories", [])
            ),
            "channel_count": len(
                data.get("channels", [])
            ),
            "role_count": len(
                data.get("roles", [])
            ),
        }

    # ========================================================
    # DELETE
    # ========================================================

    async def delete(
        self,
        guild_id: int,
        backup_id: str,
    ) -> bool:

        path = self.backup_path(
            guild_id,
            backup_id,
        )

        if not path.exists():
            return False

        await asyncio.to_thread(
            path.unlink
        )

        return True

    # ========================================================
    # CLEANUP
    # ========================================================

    async def cleanup_old_backups(
        self,
        guild_id: int,
    ) -> None:

        backups = await self.list_backups(
            guild_id
        )

        if len(backups) <= MAX_BACKUPS_PER_GUILD:
            return

        remove = backups[
            MAX_BACKUPS_PER_GUILD:
        ]

        for backup in remove:

            backup_id = backup.get("id")

            if not backup_id:
                continue

            try:

                await self.delete(
                    guild_id,
                    str(backup_id),
                )

            except Exception:

                security_logger.exception(
                    "Failed to remove old backup | "
                    "guild=%s backup=%s",
                    guild_id,
                    backup_id,
                )


# ============================================================
# SNAPSHOT CREATION
# ============================================================


async def create_snapshot(
    guild: discord.Guild,
    actor: discord.Member,
) -> dict[str, Any]:

    created_at = utc_timestamp()

    backup_id = (
        f"{created_at}-"
        f"{uuid.uuid4().hex[:8]}"
    )

    snapshot: dict[str, Any] = {
        "version": BACKUP_VERSION,

        "id": backup_id,

        "guild_id": guild.id,

        "guild_name": guild.name,

        "created_at": created_at,

        "created_by": actor.id,

        "created_by_name": str(actor),

        "roles": [],

        "categories": [],

        "channels": [],
    }

    # ========================================================
    # ROLES
    # ========================================================

    for role in sorted(
        guild.roles,
        key=lambda item: item.position,
    ):

        # @everyone ayrı olarak Discord'a aittir.
        if role.is_default():
            continue

        # Managed roles bot/integration tarafından yönetilir.
        if role.managed:
            continue

        snapshot["roles"].append(
            {
                "id": role.id,
                "name": role.name,
                "colour": role.colour.value,
                "hoist": role.hoist,
                "mentionable": role.mentionable,
                "permissions": role.permissions.value,
                "position": role.position,
            }
        )

    # ========================================================
    # CATEGORIES
    # ========================================================

    for category in sorted(
        guild.categories,
        key=lambda item: item.position,
    ):

        snapshot["categories"].append(
            {
                "id": category.id,
                "name": category.name,
                "position": category.position,
                "nsfw": category.nsfw,
                "overwrites": serialize_overwrites(
                    category
                ),
            }
        )

    # ========================================================
    # CHANNELS
    # ========================================================

    for channel in sorted(
        guild.channels,
        key=lambda item: (
            getattr(item, "position", 0),
            item.id,
        ),
    ):

        if isinstance(
            channel,
            discord.CategoryChannel,
        ):
            continue

        item: dict[str, Any] = {
            "id": channel.id,
            "name": channel.name,
            "type": channel.type.value,
            "position": getattr(
                channel,
                "position",
                0,
            ),
            "category_id": (
                channel.category_id
                if channel.category
                else None
            ),
            "overwrites": serialize_overwrites(
                channel
            ),
        }

        if isinstance(
            channel,
            discord.TextChannel,
        ):

            item.update(
                {
                    "topic": channel.topic,
                    "nsfw": channel.nsfw,
                    "slowmode_delay": (
                        channel.slowmode_delay
                    ),
                    "default_auto_archive_duration": (
                        channel.default_auto_archive_duration
                    ),
                }
            )

        elif isinstance(
            channel,
            discord.VoiceChannel,
        ):

            item.update(
                {
                    "bitrate": channel.bitrate,
                    "user_limit": channel.user_limit,
                }
            )

        elif isinstance(
            channel,
            discord.StageChannel,
        ):

            item.update(
                {
                    "bitrate": channel.bitrate,
                    "user_limit": channel.user_limit,
                }
            )

        snapshot["channels"].append(
            item
        )

    return snapshot


# ============================================================
# OVERWRITE SERIALIZATION
# ============================================================


def serialize_overwrites(
    channel: discord.abc.GuildChannel,
) -> list[dict[str, Any]]:

    result: list[dict[str, Any]] = []

    for target, overwrite in (
        channel.overwrites.items()
    ):

        if isinstance(
            target,
            discord.Role,
        ):

            target_type = "role"

        elif isinstance(
            target,
            discord.Member,
        ):

            target_type = "member"

        else:

            continue

        allow, deny = (
            overwrite.pair()
        )

        result.append(
            {
                "target_type": target_type,
                "target_id": target.id,
                "allow": allow.value,
                "deny": deny.value,
            }
        )

    return result


# ============================================================
# BACKUP PANEL
# ============================================================


class BackupPanelView(
    discord.ui.View
):

    def __init__(
        self,
        cog: "Backup",
        guild_id: int,
        author_id: int,
    ) -> None:

        super().__init__(
            timeout=COMMAND_TIMEOUT
        )

        self.cog = cog
        self.guild_id = guild_id
        self.author_id = author_id

    async def interaction_check(
        self,
        interaction: discord.Interaction,
    ) -> bool:

        if interaction.user.id != self.author_id:

            await interaction.response.send_message(
                "Bu backup paneli başka bir kullanıcıya ait.",
                ephemeral=True,
            )

            return False

        if not isinstance(
            interaction.user,
            discord.Member,
        ):

            return False

        if not has_backup_permission(
            interaction.user
        ):

            await interaction.response.send_message(
                "Bu işlem için `Yönet` yetkisi gerekiyor.",
                ephemeral=True,
            )

            return False

        return True

    @discord.ui.button(
        label="Create Backup",
        emoji="📦",
        style=discord.ButtonStyle.success,
        row=0,
    )
    async def create_button(
        self,
        interaction: discord.Interaction,
        button: discord.ui.Button,
    ) -> None:

        await interaction.response.defer(
            ephemeral=True
        )

        guild = interaction.guild

        if guild is None:
            return

        result = await self.cog.create_backup(
            guild,
            interaction.user,
        )

        await interaction.followup.send(
            result,
            ephemeral=True,
        )

    @discord.ui.button(
        label="List Backups",
        emoji="📋",
        style=discord.ButtonStyle.primary,
        row=0,
    )
    async def list_button(
        self,
        interaction: discord.Interaction,
        button: discord.ui.Button,
    ) -> None:

        backups = (
            await self.cog.service.list_backups(
                self.guild_id
            )
        )

        embed = self.cog.build_backup_list(
            backups
        )

        await interaction.response.send_message(
            embed=embed,
            ephemeral=True,
        )

    @discord.ui.button(
        label="Backup Info",
        emoji="🔎",
        style=discord.ButtonStyle.secondary,
        row=1,
    )
    async def info_button(
        self,
        interaction: discord.Interaction,
        button: discord.ui.Button,
    ) -> None:

        await interaction.response.send_message(
            "Bilgi almak için `!backup info <backup_id>` kullanın.",
            ephemeral=True,
        )

    @discord.ui.button(
        label="Restore",
        emoji="♻️",
        style=discord.ButtonStyle.danger,
        row=1,
    )
    async def restore_button(
        self,
        interaction: discord.Interaction,
        button: discord.ui.Button,
    ) -> None:

        await interaction.response.send_message(
            "Restore işlemi için güvenlik amacıyla "
            "`!backup restore <backup_id>` kullanın. "
            "İşlem ayrıca onay ister.",
            ephemeral=True,
        )

    @discord.ui.button(
        label="Delete",
        emoji="🗑️",
        style=discord.ButtonStyle.danger,
        row=1,
    )
    async def delete_button(
        self,
        interaction: discord.Interaction,
        button: discord.ui.Button,
    ) -> None:

        await interaction.response.send_message(
            "Silme işlemi için `!backup delete <backup_id>` kullanın.",
            ephemeral=True,
        )


# ============================================================
# RESTORE CONFIRMATION
# ============================================================


class RestoreConfirmView(
    discord.ui.View
):

    def __init__(
        self,
        cog: "Backup",
        guild: discord.Guild,
        author_id: int,
        backup_id: str,
    ) -> None:

        super().__init__(
            timeout=30
        )

        self.cog = cog
        self.guild = guild
        self.author_id = author_id
        self.backup_id = backup_id
        self.confirmed = False

    async def interaction_check(
        self,
        interaction: discord.Interaction,
    ) -> bool:

        if interaction.user.id != self.author_id:

            await interaction.response.send_message(
                "Bu onay paneli size ait değil.",
                ephemeral=True,
            )

            return False

        return True

    @discord.ui.button(
        label="Restore",
        emoji="♻️",
        style=discord.ButtonStyle.danger,
    )
    async def confirm(
        self,
        interaction: discord.Interaction,
        button: discord.ui.Button,
    ) -> None:

        self.confirmed = True

        self.disable_all_items()

        await interaction.response.edit_message(
            content="♻️ Restore işlemi başlatılıyor...",
            view=self,
        )

        result = await self.cog.restore_backup(
            self.guild,
            interaction.user,
            self.backup_id,
        )

        await interaction.followup.send(
            result,
            ephemeral=True,
        )

        self.stop()

    @discord.ui.button(
        label="Cancel",
        emoji="✖️",
        style=discord.ButtonStyle.secondary,
    )
    async def cancel(
        self,
        interaction: discord.Interaction,
        button: discord.ui.Button,
    ) -> None:

        self.disable_all_items()

        await interaction.response.edit_message(
            content="❌ Restore iptal edildi.",
            view=self,
        )

        self.stop()


# ============================================================
# COG
# ============================================================


class Backup(commands.Cog):
    """
    PAG Security Backup Cog.
    """

    def __init__(
        self,
        bot: commands.Bot,
    ) -> None:

        self.bot = bot

        self.service = BackupService()

        self._active_operations: set[int] = set()

        security_logger.info(
            "Backup cog initialized."
        )

    # ========================================================
    # OPERATION LOCK
    # ========================================================

    async def _begin_operation(
        self,
        guild_id: int,
    ) -> bool:

        lock = self.service.get_lock(
            guild_id
        )

        if lock.locked():
            return False

        await lock.acquire()

        self._active_operations.add(
            guild_id
        )

        return True

    def _end_operation(
        self,
        guild_id: int,
    ) -> None:

        self._active_operations.discard(
            guild_id
        )

        lock = self.service.get_lock(
            guild_id
        )

        if lock.locked():
            lock.release()

    # ========================================================
    # CREATE
    # ========================================================

    async def create_backup(
        self,
        guild: discord.Guild,
        actor: discord.abc.User,
    ) -> str:

        if not isinstance(
            actor,
            discord.Member,
        ):

            return "❌ Geçersiz kullanıcı."

        if not has_backup_permission(actor):

            return (
                "❌ Bu işlem için "
                "`Yönet` yetkisi gerekiyor."
            )

        if not await self._begin_operation(
            guild.id
        ):

            return (
                "⏳ Bu sunucuda başka bir "
                "backup işlemi devam ediyor."
            )

        try:

            snapshot = await create_snapshot(
                guild,
                actor,
            )

            path = self.service.backup_path(
                guild.id,
                snapshot["id"],
            )

            await self.service.write(
                path,
                snapshot,
            )

            await self.service.cleanup_old_backups(
                guild.id
            )

            security_logger.info(
                "Backup created | guild=%s backup=%s actor=%s",
                guild.id,
                snapshot["id"],
                actor.id,
            )

            return (
                "✅ **Backup oluşturuldu.**\n\n"
                f"🆔 `{snapshot['id']}`\n"
                f"📁 Kategoriler: `{len(snapshot['categories'])}`\n"
                f"💬 Kanallar: `{len(snapshot['channels'])}`\n"
                f"🛡️ Roller: `{len(snapshot['roles'])}`"
            )

        except Exception as exc:

            security_logger.exception(
                "Backup creation failed | guild=%s",
                guild.id,
            )

            return (
                "❌ Backup oluşturulurken hata oluştu.\n"
                f"`{type(exc).__name__}`"
            )

        finally:

            self._end_operation(
                guild.id
            )

    # ========================================================
    # LIST EMBED
    # ========================================================

    def build_backup_list(
        self,
        backups: list[dict[str, Any]],
    ) -> discord.Embed:

        embed = discord.Embed(
            title="📋 PAG Security Backups",
            description=(
                "Bu sunucuda bulunan backup kayıtları."
            ),
        )

        if not backups:

            embed.description = (
                "Henüz backup bulunmuyor."
            )

            return embed

        for backup in backups[:10]:

            backup_id = backup.get(
                "id",
                "unknown",
            )

            created_at = backup.get(
                "created_at",
                0,
            )

            embed.add_field(
                name=f"📦 {backup_id}",
                value=(
                    f"👤 `{backup.get('created_by_name', 'Unknown')}`\n"
                    f"🕒 {format_timestamp(int(created_at))}\n"
                    f"📁 `{backup.get('category_count', 0)}` kategori • "
                    f"💬 `{backup.get('channel_count', 0)}` kanal • "
                    f"🛡️ `{backup.get('role_count', 0)}` rol"
                ),
                inline=False,
            )

        if len(backups) > 10:

            embed.set_footer(
                text=(
                    f"Toplam {len(backups)} backup • "
                    "İlk 10 gösteriliyor."
                )
            )

        return embed

    # ========================================================
    # INFO
    # ========================================================

    async def backup_info(
        self,
        guild_id: int,
        backup_id: str,
    ) -> discord.Embed:

        data = await self.service.read(
            guild_id,
            backup_id,
        )

        embed = discord.Embed(
            title="🔎 Backup Information",
        )

        embed.add_field(
            name="🆔 ID",
            value=f"`{data.get('id')}`",
            inline=False,
        )

        embed.add_field(
            name="🏠 Guild",
            value=(
                f"{data.get('guild_name', 'Unknown')}\n"
                f"`{data.get('guild_id')}`"
            ),
            inline=True,
        )

        created_at = int(
            data.get(
                "created_at",
                0,
            )
        )

        embed.add_field(
            name="🕒 Created",
            value=format_timestamp(
                created_at
            ),
            inline=True,
        )

        embed.add_field(
            name="👤 Created By",
            value=(
                f"{data.get('created_by_name', 'Unknown')}\n"
                f"`{data.get('created_by')}`"
            ),
            inline=True,
        )

        embed.add_field(
            name="📊 Contents",
            value=(
                f"📁 Categories: `{len(data.get('categories', []))}`\n"
                f"💬 Channels: `{len(data.get('channels', []))}`\n"
                f"🛡️ Roles: `{len(data.get('roles', []))}`"
            ),
            inline=False,
        )

        embed.set_footer(
            text=f"Backup version {data.get('version', '?')}"
        )

        return embed

    # ========================================================
    # RESTORE
    # ========================================================

    async def restore_backup(
        self,
        guild: discord.Guild,
        actor: discord.abc.User,
        backup_id: str,
    ) -> str:

        if not isinstance(
            actor,
            discord.Member,
        ):

            return "❌ Geçersiz kullanıcı."

        if not has_backup_permission(actor):

            return (
                "❌ Restore için "
                "`Yönet` yetkisi gerekiyor."
            )

        if not safe_backup_id(
            backup_id
        ):

            return "❌ Geçersiz backup ID."

        if not await self._begin_operation(
            guild.id
        ):

            return (
                "⏳ Bu sunucuda başka bir "
                "backup işlemi devam ediyor."
            )

        try:

            data = await self.service.read(
                guild.id,
                backup_id,
            )

            # ------------------------------------------------
            # Restore sırasında önce mevcut yapıyı silmek
            # yerine mümkün olduğunca mevcut nesneleri
            # eşleştiriyoruz.
            #
            # Bu ilk sürüm güvenli restore çekirdeğidir.
            # ------------------------------------------------

            role_map: dict[int, discord.Role] = {}

            # =================================================
            # ROLES
            # =================================================

            for role_data in data.get(
                "roles",
                [],
            ):

                old_id = role_data.get(
                    "id"
                )

                existing = (
                    guild.get_role(old_id)
                    if old_id
                    else None
                )

                if existing is not None:
                    role_map[old_id] = existing
                    continue

                name = str(
                    role_data.get(
                        "name",
                        "Restored Role",
                    )
                )

                permissions = discord.Permissions(
                    int(
                        role_data.get(
                            "permissions",
                            0,
                        )
                    )
                )

                try:

                    role = await guild.create_role(
                        name=name,
                        permissions=permissions,
                        colour=discord.Colour(
                            int(
                                role_data.get(
                                    "colour",
                                    0,
                                )
                            )
                        ),
                        hoist=bool(
                            role_data.get(
                                "hoist",
                                False,
                            )
                        ),
                        mentionable=bool(
                            role_data.get(
                                "mentionable",
                                False,
                            )
                        ),
                        reason=(
                            f"PAG Security backup restore "
                            f"{backup_id}"
                        ),
                    )

                    if old_id:
                        role_map[old_id] = role

                except discord.Forbidden:

                    security_logger.warning(
                        "Role restore forbidden | "
                        "guild=%s role=%s",
                        guild.id,
                        name,
                    )

                except discord.HTTPException:

                    security_logger.exception(
                        "Role restore HTTP failure | "
                        "guild=%s role=%s",
                        guild.id,
                        name,
                    )

            # =================================================
            # CATEGORIES
            # =================================================

            category_map: dict[
                int,
                discord.CategoryChannel,
            ] = {}

            for category_data in data.get(
                "categories",
                [],
            ):

                old_id = category_data.get(
                    "id"
                )

                existing = (
                    guild.get_channel(old_id)
                    if old_id
                    else None
                )

                if isinstance(
                    existing,
                    discord.CategoryChannel,
                ):

                    category_map[
                        old_id
                    ] = existing

                    continue

                try:

                    category = (
                        await guild.create_category(
                            name=str(
                                category_data.get(
                                    "name",
                                    "Restored Category",
                                )
                            ),
                            reason=(
                                f"PAG Security backup restore "
                                f"{backup_id}"
                            ),
                        )
                    )

                    if old_id:
                        category_map[
                            old_id
                        ] = category

                except (
                    discord.Forbidden,
                    discord.HTTPException,
                ):

                    security_logger.exception(
                        "Category restore failed | "
                        "guild=%s category=%s",
                        guild.id,
                        old_id,
                    )

            # =================================================
            # CHANNELS
            # =================================================

            for channel_data in data.get(
                "channels",
                [],
            ):

                old_id = channel_data.get(
                    "id"
                )

                existing = (
                    guild.get_channel(old_id)
                    if old_id
                    else None
                )

                if existing is not None:
                    continue

                channel_type = channel_data.get(
                    "type"
                )

                name = str(
                    channel_data.get(
                        "name",
                        "restored-channel",
                    )
                )

                category_id = channel_data.get(
                    "category_id"
                )

                category = (
                    category_map.get(
                        category_id
                    )
                    if category_id
                    else None
                )

                try:

                    if channel_type == discord.ChannelType.text.value:

                        await guild.create_text_channel(
                            name=name,
                            category=category,
                            topic=channel_data.get(
                                "topic"
                            ),
                            nsfw=bool(
                                channel_data.get(
                                    "nsfw",
                                    False,
                                )
                            ),
                            slowmode_delay=int(
                                channel_data.get(
                                    "slowmode_delay",
                                    0,
                                )
                            ),
                            reason=(
                                f"PAG Security backup restore "
                                f"{backup_id}"
                            ),
                        )

                    elif channel_type == discord.ChannelType.voice.value:

                        await guild.create_voice_channel(
                            name=name,
                            category=category,
                            bitrate=int(
                                channel_data.get(
                                    "bitrate",
                                    64000,
                                )
                            ),
                            user_limit=int(
                                channel_data.get(
                                    "user_limit",
                                    0,
                                )
                            ),
                            reason=(
                                f"PAG Security backup restore "
                                f"{backup_id}"
                            ),
                        )

                    elif channel_type == discord.ChannelType.stage_voice.value:

                        await guild.create_stage_channel(
                            name=name,
                            category=category,
                            topic=channel_data.get(
                                "topic"
                            ),
                            reason=(
                                f"PAG Security backup restore "
                                f"{backup_id}"
                            ),
                        )

                except discord.Forbidden:

                    security_logger.warning(
                        "Channel restore forbidden | "
                        "guild=%s channel=%s",
                        guild.id,
                        name,
                    )

                except discord.HTTPException:

                    security_logger.exception(
                        "Channel restore failed | "
                        "guild=%s channel=%s",
                        guild.id,
                        name,
                    )

            security_logger.info(
                "Backup restored | guild=%s backup=%s actor=%s",
                guild.id,
                backup_id,
                actor.id,
            )

            return (
                "✅ **Backup restore tamamlandı.**\n"
                f"🆔 `{backup_id}`\n\n"
                "ℹ️ Mevcut nesneler korunmuş, "
                "eksik nesneler backup'tan oluşturulmuştur."
            )

        except FileNotFoundError:

            return "❌ Backup bulunamadı."

        except json.JSONDecodeError:

            return "❌ Backup dosyası bozuk."

        except Exception as exc:

            security_logger.exception(
                "Backup restore failed | guild=%s backup=%s",
                guild.id,
                backup_id,
            )

            return (
                "❌ Restore sırasında hata oluştu.\n"
                f"`{type(exc).__name__}`"
            )

        finally:

            self._end_operation(
                guild.id
            )

    # ========================================================
    # MAIN PANEL
    # ========================================================

    @commands.command(
        name="backup",
    )
    @commands.guild_only()
    async def backup_command(
        self,
        ctx: commands.Context,
        action: Optional[str] = None,
        backup_id: Optional[str] = None,
    ) -> None:

        if not isinstance(
            ctx.author,
            discord.Member,
        ):

            return

        if not has_backup_permission(
            ctx.author
        ):

            await ctx.reply(
                "❌ Bu sistem için `Yönet` yetkisi gerekiyor.",
                mention_author=False,
            )

            return

        # ----------------------------------------------------
        # PANEL
        # ----------------------------------------------------

        if action is None:

            embed = discord.Embed(
                title="🛡️ PAG Security • Backup",
                description=(
                    "Sunucu backup yönetim paneli.\n\n"
                    "📦 **Create** — Yeni backup oluştur\n"
                    "📋 **List** — Backup listesini görüntüle\n"
                    "🔎 **Info** — Backup detaylarını görüntüle\n"
                    "♻️ **Restore** — Backup geri yükle\n"
                    "🗑️ **Delete** — Backup sil"
                ),
            )

            embed.set_footer(
                text=(
                    "Backup işlemleri otomatik çalışmaz."
                )
            )

            await ctx.reply(
                embed=embed,
                view=BackupPanelView(
                    self,
                    ctx.guild.id,
                    ctx.author.id,
                ),
                mention_author=False,
            )

            return

        action = action.lower().strip()

        # ====================================================
        # CREATE
        # ====================================================

        if action in {
            "create",
            "new",
            "oluştur",
        }:

            await ctx.reply(
                await self.create_backup(
                    ctx.guild,
                    ctx.author,
                ),
                mention_author=False,
            )

            return

        # ====================================================
        # LIST
        # ====================================================

        if action in {
            "list",
            "ls",
            "liste",
        }:

            backups = (
                await self.service.list_backups(
                    ctx.guild.id
                )
            )

            await ctx.reply(
                embed=self.build_backup_list(
                    backups
                ),
                mention_author=False,
            )

            return

        # ====================================================
        # INFO
        # ====================================================

        if action in {
            "info",
            "bilgi",
        }:

            if not backup_id:

                await ctx.reply(
                    "❌ Kullanım: `!backup info <backup_id>`",
                    mention_author=False,
                )

                return

            try:

                embed = await self.backup_info(
                    ctx.guild.id,
                    backup_id,
                )

            except FileNotFoundError:

                await ctx.reply(
                    "❌ Backup bulunamadı.",
                    mention_author=False,
                )

                return

            except Exception as exc:

                security_logger.exception(
                    "Backup info failed | guild=%s",
                    ctx.guild.id,
                )

                await ctx.reply(
                    f"❌ Backup okunamadı: `{type(exc).__name__}`",
                    mention_author=False,
                )

                return

            await ctx.reply(
                embed=embed,
                mention_author=False,
            )

            return

        # ====================================================
        # DELETE
        # ====================================================

        if action in {
            "delete",
            "remove",
            "sil",
        }:

            if not backup_id:

                await ctx.reply(
                    "❌ Kullanım: `!backup delete <backup_id>`",
                    mention_author=False,
                )

                return

            if not safe_backup_id(
                backup_id
            ):

                await ctx.reply(
                    "❌ Geçersiz backup ID.",
                    mention_author=False,
                )

                return

            try:

                deleted = await self.service.delete(
                    ctx.guild.id,
                    backup_id,
                )

            except Exception as exc:

                security_logger.exception(
                    "Backup delete failed | guild=%s",
                    ctx.guild.id,
                )

                await ctx.reply(
                    f"❌ Backup silinemedi: `{type(exc).__name__}`",
                    mention_author=False,
                )

                return

            if not deleted:

                await ctx.reply(
                    "❌ Backup bulunamadı.",
                    mention_author=False,
                )

                return

            await ctx.reply(
                f"🗑️ Backup `{backup_id}` silindi.",
                mention_author=False,
            )

            return

        # ====================================================
        # RESTORE
        # ====================================================

        if action in {
            "restore",
            "yükle",
            "geri",
        }:

            if not backup_id:

                await ctx.reply(
                    "❌ Kullanım: `!backup restore <backup_id>`",
                    mention_author=False,
                )

                return

            if not safe_backup_id(
                backup_id
            ):

                await ctx.reply(
                    "❌ Geçersiz backup ID.",
                    mention_author=False,
                )

                return

            try:

                data = await self.service.read(
                    ctx.guild.id,
                    backup_id,
                )

            except FileNotFoundError:

                await ctx.reply(
                    "❌ Backup bulunamadı.",
                    mention_author=False,
                )

                return

            except Exception as exc:

                security_logger.exception(
                    "Backup restore preparation failed | guild=%s",
                    ctx.guild.id,
                )

                await ctx.reply(
                    f"❌ Backup hazırlanamadı: `{type(exc).__name__}`",
                    mention_author=False,
                )

                return

            embed = discord.Embed(
                title="⚠️ Restore Confirmation",
                description=(
                    "Bu işlem backup içindeki eksik "
                    "sunucu yapılarını yeniden oluşturabilir.\n\n"
                    "**Mevcut nesneler otomatik olarak "
                    "silinmeyecektir.**\n\n"
                    f"📦 Backup: `{backup_id}`\n"
                    f"📁 Kategoriler: `{len(data.get('categories', []))}`\n"
                    f"💬 Kanallar: `{len(data.get('channels', []))}`\n"
                    f"🛡️ Roller: `{len(data.get('roles', []))}`"
                ),
            )

            view = RestoreConfirmView(
                self,
                ctx.guild,
                ctx.author.id,
                backup_id,
            )

            await ctx.reply(
                embed=embed,
                view=view,
                mention_author=False,
            )

            return

        # ====================================================
        # UNKNOWN
        # ====================================================

        await ctx.reply(
            (
                "❌ Bilinmeyen işlem.\n"
                "Kullanım: `!backup`"
            ),
            mention_author=False,
        )

    # ========================================================
    # ERROR HANDLER
    # ========================================================

    @backup_command.error
    async def backup_command_error(
        self,
        ctx: commands.Context,
        error: commands.CommandError,
    ) -> None:

        if isinstance(
            error,
            commands.NoPrivateMessage,
        ):

            return

        if isinstance(
            error,
            commands.CommandNotFound,
        ):

            return

        security_logger.exception(
            "Backup command error | guild=%s error=%s",
            getattr(
                ctx.guild,
                "id",
                None,
            ),
            error,
        )

        try:

            await ctx.reply(
                "❌ Backup komutu çalıştırılırken beklenmeyen bir hata oluştu.",
                mention_author=False,
            )

        except (
            discord.HTTPException,
            discord.Forbidden,
        ):
            pass


# ============================================================
# SETUP
# ============================================================


async def setup(
    bot: commands.Bot,
) -> None:

    await bot.add_cog(
        Backup(bot)
    )


__all__ = [
    "Backup",
    "BackupService",
    "setup",
]