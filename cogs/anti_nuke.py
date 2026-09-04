# cogs/anti_nuke.py

from __future__ import annotations

import asyncio
import time
from collections import defaultdict, deque
from typing import Optional

import discord
from discord.ext import commands


class AntiNuke(commands.Cog):
    """
    PAG Security Bot
    Anti-Nuke Protection System

    PanelService üzerinden guild bazlı configuration kullanır.

    Korunan olaylar:
        - Member kick
        - Member ban
        - Channel delete
        - Channel create
        - Role delete
        - Role create
        - Webhook create
        - Bot add
        - Permission changes

    Sistem:
        Event
            ↓
        Audit Log Actor
            ↓
        Whitelist kontrolü
            ↓
        Threshold / Risk Weight
            ↓
        Risk Score
            ↓
        Emergency Action
    """

    def __init__(self, bot: commands.Bot) -> None:
        self.bot = bot

        # -----------------------------------------------------
        # Actor -> Action -> timestamps
        # -----------------------------------------------------

        self._actions: dict[
            int,
            dict[int, dict[str, deque[float]]]
        ] = defaultdict(
            lambda: defaultdict(
                lambda: defaultdict(deque)
            )
        )

        # -----------------------------------------------------
        # Risk score
        # -----------------------------------------------------

        self._risk: dict[
            int,
            dict[int, int]
        ] = defaultdict(dict)

        # -----------------------------------------------------
        # Emergency state
        # -----------------------------------------------------

        self._emergency_active: set[int] = set()

        # -----------------------------------------------------
        # Locks
        # -----------------------------------------------------

        self._guild_locks: dict[
            int,
            asyncio.Lock
        ] = {}

        # -----------------------------------------------------
        # Audit log lookup lock
        # -----------------------------------------------------

        self._audit_locks: dict[
            int,
            asyncio.Lock
        ] = {}

        # -----------------------------------------------------
        # Cooldowns
        # -----------------------------------------------------

        self._emergency_cooldown: dict[
            int,
            float
        ] = {}

        # -----------------------------------------------------
        # Background cleanup
        # -----------------------------------------------------

        self._cleanup_task: Optional[
            asyncio.Task
        ] = None

    # =========================================================
    # LIFECYCLE
    # =========================================================

    async def cog_load(self) -> None:
        self._cleanup_task = asyncio.create_task(
            self._cleanup_loop()
        )

    async def cog_unload(self) -> None:

        if self._cleanup_task is not None:
            self._cleanup_task.cancel()

            try:
                await self._cleanup_task
            except asyncio.CancelledError:
                pass

        self._actions.clear()
        self._risk.clear()
        self._emergency_active.clear()

    # =========================================================
    # HELPERS
    # =========================================================

    def _get_panel(self):
        """
        Bot üzerindeki PanelService'i alır.

        Beklenen:
            bot.panel_service
        """

        return getattr(
            self.bot,
            "panel_service",
            None,
        )

    def _get_guild_lock(
        self,
        guild_id: int,
    ) -> asyncio.Lock:

        lock = self._guild_locks.get(
            guild_id
        )

        if lock is None:
            lock = asyncio.Lock()

            self._guild_locks[
                guild_id
            ] = lock

        return lock

    def _get_audit_lock(
        self,
        guild_id: int,
    ) -> asyncio.Lock:

        lock = self._audit_locks.get(
            guild_id
        )

        if lock is None:
            lock = asyncio.Lock()

            self._audit_locks[
                guild_id
            ] = lock

        return lock

    # =========================================================
    # CONFIG
    # =========================================================

    async def _get_config(
        self,
        guild_id: int,
    ) -> Optional[dict]:

        panel = self._get_panel()

        if panel is None:
            return None

        try:
            return await panel.load(
                guild_id
            )

        except Exception:
            # Security sistemi config yüzünden
            # botu düşürmemeli.
            return None

    async def _enabled(
        self,
        guild_id: int,
    ) -> bool:

        panel = self._get_panel()

        if panel is None:
            return False

        try:
            return await panel.is_enabled(
                guild_id
            )

        except Exception:
            return False

    # =========================================================
    # WHITELIST
    # =========================================================

    async def _is_whitelisted(
        self,
        guild: discord.Guild,
        actor: discord.Member | discord.User,
    ) -> bool:

        panel = self._get_panel()

        if panel is None:
            return False

        try:

            if await panel.is_whitelisted_user(
                guild.id,
                actor.id,
            ):
                return True

        except Exception:
            pass

        if isinstance(actor, discord.Member):

            for role in actor.roles:

                try:

                    if await panel.is_whitelisted_role(
                        guild.id,
                        role.id,
                    ):
                        return True

                except Exception:
                    continue

        return False

    # =========================================================
    # PROTECTION
    # =========================================================

    async def _is_protected_actor(
        self,
        guild: discord.Guild,
        actor: discord.Member | discord.User,
    ) -> bool:

        config = await self._get_config(
            guild.id
        )

        if not config:
            return False

        protection = config.get(
            "protection",
            {},
        )

        # -----------------------------------------------------
        # Owner
        # -----------------------------------------------------

        if protection.get(
            "protect_owner",
            True,
        ):

            if actor.id == guild.owner_id:
                return True

        # -----------------------------------------------------
        # Bot
        # -----------------------------------------------------

        if protection.get(
            "protect_bot",
            True,
        ):

            if actor.id == self.bot.user.id:
                return True

        # -----------------------------------------------------
        # Verified users
        # -----------------------------------------------------

        if (
            protection.get(
                "protect_verified_users",
                True,
            )
            and isinstance(actor, discord.Member)
        ):

            # Burada özel verified role ID
            # config'e eklenirse kullanılabilir.
            verified_role_id = (
                config
                .get("protection", {})
                .get("verified_role_id")
            )

            if verified_role_id:

                if any(
                    role.id == int(
                        verified_role_id
                    )
                    for role in actor.roles
                ):
                    return True

        return False

    # =========================================================
    # AUDIT LOG
    # =========================================================

    async def _get_audit_actor(
        self,
        guild: discord.Guild,
        action: discord.AuditLogAction,
        target_id: Optional[int] = None,
        *,
        max_age: float = 10.0,
    ) -> Optional[discord.Member]:

        lock = self._get_audit_lock(
            guild.id
        )

        async with lock:

            try:

                async for entry in guild.audit_logs(
                    limit=8,
                    action=action,
                ):

                    created_at = (
                        entry.created_at.timestamp()
                    )

                    if (
                        time.time()
                        - created_at
                        > max_age
                    ):
                        continue

                    if (
                        target_id is not None
                        and entry.target is not None
                    ):

                        try:

                            if (
                                int(
                                    entry.target.id
                                )
                                != int(target_id)
                            ):
                                continue

                        except (
                            AttributeError,
                            ValueError,
                            TypeError,
                        ):
                            continue

                    actor = entry.user

                    if actor is None:
                        continue

                    member = guild.get_member(
                        actor.id
                    )

                    if member is not None:
                        return member

                    try:
                        return await guild.fetch_member(
                            actor.id
                        )
                    except (
                        discord.NotFound,
                        discord.HTTPException,
                        discord.Forbidden,
                    ):
                        return actor

            except (
                discord.Forbidden,
                discord.HTTPException,
                discord.NotFound,
            ):
                return None

        return None

    # =========================================================
    # RECORD ACTION
    # =========================================================

    async def _record_action(
        self,
        guild: discord.Guild,
        actor: discord.Member | discord.User,
        action: str,
    ) -> None:

        guild_id = guild.id
        actor_id = actor.id

        config = await self._get_config(
            guild_id
        )

        if not config:
            return

        detection = config.get(
            "detection",
            {},
        )

        window = detection.get(
            "window_seconds",
            15,
        )

        try:
            window = max(
                1,
                int(window),
            )
        except (
            TypeError,
            ValueError,
        ):
            window = 15

        threshold = await self._get_threshold(
            guild_id,
            action,
        )

        weight = await self._get_weight(
            guild_id,
            action,
        )

        now = time.monotonic()

        lock = self._get_guild_lock(
            guild_id
        )

        async with lock:

            history = self._actions[
                guild_id
            ][actor_id][action]

            history.append(now)

            cutoff = now - window

            while history and history[0] < cutoff:
                history.popleft()

            count = len(history)

            # -------------------------------------------------
            # Risk calculation
            # -------------------------------------------------

            risk = self._risk[
                guild_id
            ].get(
                actor_id,
                0,
            )

            risk += weight

            self._risk[
                guild_id
            ][actor_id] = min(
                risk,
                10000,
            )

            total_risk = self._risk[
                guild_id
            ][actor_id]

        # -----------------------------------------------------
        # Threshold
        # -----------------------------------------------------

        threshold_triggered = (
            count >= threshold
        )

        # -----------------------------------------------------
        # Smart detection
        # -----------------------------------------------------

        smart_detection = bool(
            config
            .get("security", {})
            .get(
                "smart_detection",
                True,
            )
        )

        if smart_detection:

            level = await self._get_risk_level(
                guild_id,
                total_risk,
            )

            if level in (
                "high",
                "critical",
            ):

                await self._handle_risk(
                    guild,
                    actor,
                    action,
                    count,
                    threshold,
                    total_risk,
                    level,
                )

                return

        # -----------------------------------------------------
        # Normal threshold
        # -----------------------------------------------------

        if threshold_triggered:

            await self._handle_risk(
                guild,
                actor,
                action,
                count,
                threshold,
                total_risk,
                "threshold",
            )

    # =========================================================
    # CONFIG VALUES
    # =========================================================

    async def _get_threshold(
        self,
        guild_id: int,
        action: str,
    ) -> int:

        panel = self._get_panel()

        if panel is None:
            return 5

        try:
            return await panel.get_threshold(
                guild_id,
                action,
            )
        except Exception:
            return 5

    async def _get_weight(
        self,
        guild_id: int,
        action: str,
    ) -> int:

        panel = self._get_panel()

        if panel is None:
            return 10

        try:
            return await panel.get_risk_weight(
                guild_id,
                action,
            )
        except Exception:
            return 10

    async def _get_risk_level(
        self,
        guild_id: int,
        risk: int,
    ) -> str:

        panel = self._get_panel()

        if panel is None:
            return "normal"

        try:

            suspicious = (
                await panel.get_risk_level(
                    guild_id,
                    "suspicious",
                )
            )

            high = (
                await panel.get_risk_level(
                    guild_id,
                    "high",
                )
            )

            critical = (
                await panel.get_risk_level(
                    guild_id,
                    "critical",
                )
            )

            if risk >= critical:
                return "critical"

            if risk >= high:
                return "high"

            if risk >= suspicious:
                return "suspicious"

        except Exception:
            return "normal"

        return "normal"

    # =========================================================
    # RISK HANDLER
    # =========================================================

    async def _handle_risk(
        self,
        guild: discord.Guild,
        actor: discord.Member | discord.User,
        action: str,
        count: int,
        threshold: int,
        risk: int,
        level: str,
    ) -> None:

        # -----------------------------------------------------
        # Whitelist
        # -----------------------------------------------------

        if await self._is_whitelisted(
            guild,
            actor,
        ):
            return

        # -----------------------------------------------------
        # Protected actor
        # -----------------------------------------------------

        if await self._is_protected_actor(
            guild,
            actor,
        ):
            return

        config = await self._get_config(
            guild.id
        )

        if not config:
            return

        security = config.get(
            "security",
            {},
        )

        if not security.get(
            "enabled",
            True,
        ):
            return

        emergency = config.get(
            "emergency",
            {},
        )

        emergency_enabled = bool(
            security.get(
                "emergency_mode",
                True,
            )
        )

        # -----------------------------------------------------
        # Emergency
        # -----------------------------------------------------

        if (
            emergency_enabled
            and level in (
                "high",
                "critical",
                "threshold",
            )
        ):

            await self._trigger_emergency(
                guild,
                actor,
                action,
                count,
                threshold,
                risk,
                level,
            )

        # -----------------------------------------------------
        # Optional automatic actions
        # -----------------------------------------------------

        actions = config.get(
            "actions",
            {},
        )

        if (
            level == "critical"
            and actions.get(
                "auto_ban",
                False,
            )
        ):

            await self._safe_ban(
                guild,
                actor,
                reason=(
                    "PAG Security Anti-Nuke "
                    f"Critical Risk ({risk})"
                ),
            )

        elif (
            level in (
                "high",
                "critical",
            )
            and actions.get(
                "auto_kick",
                False,
            )
        ):

            await self._safe_kick(
                guild,
                actor,
                reason=(
                    "PAG Security Anti-Nuke "
                    f"Risk ({risk})"
                ),
            )

    # =========================================================
    # EMERGENCY
    # =========================================================

    async def _trigger_emergency(
        self,
        guild: discord.Guild,
        actor: discord.Member | discord.User,
        action: str,
        count: int,
        threshold: int,
        risk: int,
        level: str,
    ) -> None:

        now = time.monotonic()

        # -----------------------------------------------------
        # Cooldown
        # -----------------------------------------------------

        previous = self._emergency_cooldown.get(
            guild.id,
            0,
        )

        if now - previous < 5:
            return

        self._emergency_cooldown[
            guild.id
        ] = now

        self._emergency_active.add(
            guild.id
        )

        config = await self._get_config(
            guild.id
        )

        if not config:
            return

        emergency = config.get(
            "emergency",
            {},
        )

        # -----------------------------------------------------
        # Remove dangerous roles
        # -----------------------------------------------------

        if emergency.get(
            "remove_dangerous_roles",
            True,
        ):

            await self._remove_dangerous_roles(
                guild,
                actor,
                config,
            )

        # -----------------------------------------------------
        # Lockdown
        # -----------------------------------------------------

        if emergency.get(
            "lockdown",
            True,
        ):

            await self._lockdown(
                guild
            )

    # =========================================================
    # DANGEROUS ROLES
    # =========================================================

    async def _remove_dangerous_roles(
        self,
        guild: discord.Guild,
        actor: discord.Member | discord.User,
        config: dict,
    ) -> None:

        member = guild.get_member(
            actor.id
        )

        if member is None:
            return

        permissions_to_remove = set(
            config
            .get("emergency", {})
            .get(
                "remove_permissions",
                [],
            )
        )

        if not permissions_to_remove:
            return

        try:

            roles = list(
                member.roles
            )

        except AttributeError:
            return

        for role in roles:

            if role.is_default():
                continue

            if role.managed:
                continue

            permissions = role.permissions

            dangerous = False

            for permission_name in permissions_to_remove:

                if getattr(
                    permissions,
                    permission_name,
                    False,
                ):
                    dangerous = True
                    break

            if not dangerous:
                continue

            try:

                await member.remove_roles(
                    role,
                    reason=(
                        "PAG Security Anti-Nuke "
                        "Emergency"
                    ),
                )

            except (
                discord.Forbidden,
                discord.HTTPException,
            ):
                continue

    # =========================================================
    # LOCKDOWN
    # =========================================================

    async def _lockdown(
        self,
        guild: discord.Guild,
    ) -> None:

        """
        Basit ve güvenli lockdown.

        @everyone için Send Messages kapatılır.

        Botun yetkisi yoksa hata yutulur.
        """

        everyone = guild.default_role

        try:

            overwrite = everyone.permissions

            # Gereksiz API çağrısını engelle.
            if overwrite.send_messages is False:
                return

            for channel in list(
                guild.text_channels
            ):

                try:

                    current = channel.overwrites_for(
                        everyone
                    )

                    current.send_messages = False

                    await channel.set_permissions(
                        everyone,
                        overwrite=current,
                        reason=(
                            "PAG Security "
                            "Anti-Nuke Lockdown"
                        ),
                    )

                except (
                    discord.Forbidden,
                    discord.HTTPException,
                ):
                    continue

        except (
            discord.Forbidden,
            discord.HTTPException,
        ):
            return

    # =========================================================
    # SAFE BAN
    # =========================================================

    async def _safe_ban(
        self,
        guild: discord.Guild,
        actor: discord.Member | discord.User,
        *,
        reason: str,
    ) -> bool:

        if actor.id == guild.owner_id:
            return False

        if actor.id == self.bot.user.id:
            return False

        member = guild.get_member(
            actor.id
        )

        if member is None:
            return False

        try:

            await guild.ban(
                member,
                reason=reason,
                delete_message_seconds=0,
            )

            return True

        except (
            discord.Forbidden,
            discord.HTTPException,
        ):
            return False

    # =========================================================
    # SAFE KICK
    # =========================================================

    async def _safe_kick(
        self,
        guild: discord.Guild,
        actor: discord.Member | discord.User,
        *,
        reason: str,
    ) -> bool:

        if actor.id == guild.owner_id:
            return False

        if actor.id == self.bot.user.id:
            return False

        member = guild.get_member(
            actor.id
        )

        if member is None:
            return False

        try:

            await member.kick(
                reason=reason
            )

            return True

        except (
            discord.Forbidden,
            discord.HTTPException,
        ):
            return False

    # =========================================================
    # MEMBER KICK
    # =========================================================

    @commands.Cog.listener()
    async def on_member_remove(
        self,
        member: discord.Member,
    ) -> None:

        guild = member.guild

        if not await self._enabled(
            guild.id
        ):
            return

        actor = await self._get_audit_actor(
            guild,
            discord.AuditLogAction.kick,
            member.id,
        )

        if actor is None:
            return

        if actor.id == member.id:
            return

        await self._record_action(
            guild,
            actor,
            "kick",
        )

    # =========================================================
    # MEMBER BAN
    # =========================================================

    @commands.Cog.listener()
    async def on_member_ban(
        self,
        guild: discord.Guild,
        user: discord.User,
    ) -> None:

        if not await self._enabled(
            guild.id
        ):
            return

        actor = await self._get_audit_actor(
            guild,
            discord.AuditLogAction.ban,
            user.id,
        )

        if actor is None:
            return

        await self._record_action(
            guild,
            actor,
            "ban",
        )

    # =========================================================
    # CHANNEL DELETE
    # =========================================================

    @commands.Cog.listener()
    async def on_guild_channel_delete(
        self,
        channel: discord.abc.GuildChannel,
    ) -> None:

        guild = channel.guild

        if not await self._enabled(
            guild.id
        ):
            return

        actor = await self._get_audit_actor(
            guild,
            discord.AuditLogAction.channel_delete,
            channel.id,
        )

        if actor is None:
            return

        await self._record_action(
            guild,
            actor,
            "channel_delete",
        )

    # =========================================================
    # CHANNEL CREATE
    # =========================================================

    @commands.Cog.listener()
    async def on_guild_channel_create(
        self,
        channel: discord.abc.GuildChannel,
    ) -> None:

        guild = channel.guild

        if not await self._enabled(
            guild.id
        ):
            return

        actor = await self._get_audit_actor(
            guild,
            discord.AuditLogAction.channel_create,
            channel.id,
        )

        if actor is None:
            return

        await self._record_action(
            guild,
            actor,
            "channel_create",
        )

    # =========================================================
    # ROLE DELETE
    # =========================================================

    @commands.Cog.listener()
    async def on_guild_role_delete(
        self,
        role: discord.Role,
    ) -> None:

        guild = role.guild

        if not await self._enabled(
            guild.id
        ):
            return

        actor = await self._get_audit_actor(
            guild,
            discord.AuditLogAction.role_delete,
            role.id,
        )

        if actor is None:
            return

        await self._record_action(
            guild,
            actor,
            "role_delete",
        )

    # =========================================================
    # ROLE CREATE
    # =========================================================

    @commands.Cog.listener()
    async def on_guild_role_create(
        self,
        role: discord.Role,
    ) -> None:

        guild = role.guild

        if not await self._enabled(
            guild.id
        ):
            return

        actor = await self._get_audit_actor(
            guild,
            discord.AuditLogAction.role_create,
            role.id,
        )

        if actor is None:
            return

        await self._record_action(
            guild,
            actor,
            "role_create",
        )

    # =========================================================
    # WEBHOOK CREATE
    # =========================================================

    @commands.Cog.listener()
    async def on_webhooks_update(
        self,
        channel: discord.abc.GuildChannel,
    ) -> None:

        guild = channel.guild

        if not await self._enabled(
            guild.id
        ):
            return

        actor = await self._get_audit_actor(
            guild,
            discord.AuditLogAction.webhook_create,
        )

        if actor is None:
            return

        await self._record_action(
            guild,
            actor,
            "webhook_create",
        )

    # =========================================================
    # BOT ADD
    # =========================================================

    @commands.Cog.listener()
    async def on_member_join(
        self,
        member: discord.Member,
    ) -> None:

        if not member.bot:
            return

        guild = member.guild

        if not await self._enabled(
            guild.id
        ):
            return

        actor = await self._get_audit_actor(
            guild,
            discord.AuditLogAction.bot_add,
            member.id,
        )

        if actor is None:
            return

        await self._record_action(
            guild,
            actor,
            "bot_add",
        )

    # =========================================================
    # ROLE PERMISSION CHANGE
    # =========================================================

    @commands.Cog.listener()
    async def on_guild_role_update(
        self,
        before: discord.Role,
        after: discord.Role,
    ) -> None:

        if (
            before.permissions.value
            == after.permissions.value
        ):
            return

        guild = after.guild

        if not await self._enabled(
            guild.id
        ):
            return

        actor = await self._get_audit_actor(
            guild,
            discord.AuditLogAction.role_update,
            after.id,
        )

        if actor is None:
            return

        await self._record_action(
            guild,
            actor,
            "permission_change",
        )

    # =========================================================
    # CLEANUP
    # =========================================================

    async def _cleanup_loop(
        self,
    ) -> None:

        while True:

            try:

                await asyncio.sleep(
                    60
                )

                now = time.monotonic()

                # ---------------------------------------------
                # Action history
                # ---------------------------------------------

                for guild_id in list(
                    self._actions.keys()
                ):

                    guild_data = self._actions[
                        guild_id
                    ]

                    for actor_id in list(
                        guild_data.keys()
                    ):

                        actor_data = guild_data[
                            actor_id
                        ]

                        for action in list(
                            actor_data.keys()
                        ):

                            history = actor_data[
                                action
                            ]

                            while (
                                history
                                and now
                                - history[0]
                                > 3600
                            ):
                                history.popleft()

                            if not history:
                                del actor_data[
                                    action
                                ]

                        if not actor_data:
                            del guild_data[
                                actor_id
                            ]

                    if not guild_data:
                        del self._actions[
                            guild_id
                        ]

                # ---------------------------------------------
                # Risk reset
                # ---------------------------------------------

                for guild_id in list(
                    self._risk.keys()
                ):

                    guild_risk = self._risk[
                        guild_id
                    ]

                    for actor_id in list(
                        guild_risk.keys()
                    ):

                        # Risk zamanla temizlenir.
                        guild_risk[
                            actor_id
                        ] = max(
                            0,
                            guild_risk[
                                actor_id
                            ] - 10,
                        )

                        if (
                            guild_risk[
                                actor_id
                            ] <= 0
                        ):
                            del guild_risk[
                                actor_id
                            ]

                    if not guild_risk:
                        del self._risk[
                            guild_id
                        ]

                # ---------------------------------------------
                # Emergency cooldown
                # ---------------------------------------------

                for guild_id in list(
                    self._emergency_cooldown.keys()
                ):

                    if (
                        now
                        - self._emergency_cooldown[
                            guild_id
                        ]
                        > 60
                    ):

                        del self._emergency_cooldown[
                            guild_id
                        ]

            except asyncio.CancelledError:
                raise

            except Exception:
                # Cleanup hiçbir zaman botu düşürmez.
                continue


async def setup(
    bot: commands.Bot,
) -> None:

    await bot.add_cog(
        AntiNuke(bot)
    )


__all__ = [
    "AntiNuke",
]