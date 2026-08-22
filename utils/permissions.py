# utils/permissions.py

from __future__ import annotations

from dataclasses import dataclass
from enum import IntFlag
from typing import Any, Iterable, Optional

import discord


# ============================================================
# PAG SECURITY BOT
# utils/permissions.py
#
# Merkezi Discord permission yardımcıları.
#
# Bu dosyada:
# - Discord API çağrısı yok
# - Database yok
# - Punishment yok
# - Emergency kararı yok
#
# Sadece permission / role kontrolü yapılır.
# ============================================================


# ============================================================
# SECURITY PERMISSIONS
# ============================================================

class SecurityPermission(IntFlag):
    """
    Security Bot açısından kritik Discord izinleri.

    IntFlag kullanıldığı için birden fazla izin
    tek bir değer içerisinde tutulabilir.
    """

    NONE = 0

    ADMINISTRATOR = 1 << 0
    KICK_MEMBERS = 1 << 1
    BAN_MEMBERS = 1 << 2
    MANAGE_CHANNELS = 1 << 3
    MANAGE_ROLES = 1 << 4
    MANAGE_WEBHOOKS = 1 << 5
    MANAGE_GUILD = 1 << 6
    MENTION_EVERYONE = 1 << 7
    MANAGE_MESSAGES = 1 << 8
    MODERATE_MEMBERS = 1 << 9


# ============================================================
# PERMISSION RESULT
# ============================================================

@dataclass(slots=True, frozen=True)
class PermissionResult:
    """
    Permission kontrolünün sonucu.
    """

    allowed: bool
    administrator: bool
    permissions: SecurityPermission
    missing: SecurityPermission
    dangerous: SecurityPermission

    @property
    def has_dangerous_permissions(self) -> bool:
        """
        Kullanıcıda herhangi bir kritik izin var mı?
        """
        return self.dangerous != SecurityPermission.NONE


# ============================================================
# PERMISSION MAP
# ============================================================

_PERMISSION_MAP: dict[
    SecurityPermission,
    str,
] = {
    SecurityPermission.ADMINISTRATOR:
        "administrator",

    SecurityPermission.KICK_MEMBERS:
        "kick_members",

    SecurityPermission.BAN_MEMBERS:
        "ban_members",

    SecurityPermission.MANAGE_CHANNELS:
        "manage_channels",

    SecurityPermission.MANAGE_ROLES:
        "manage_roles",

    SecurityPermission.MANAGE_WEBHOOKS:
        "manage_webhooks",

    SecurityPermission.MANAGE_GUILD:
        "manage_guild",

    SecurityPermission.MENTION_EVERYONE:
        "mention_everyone",

    SecurityPermission.MANAGE_MESSAGES:
        "manage_messages",

    SecurityPermission.MODERATE_MEMBERS:
        "moderate_members",
}


# ============================================================
# DANGEROUS PERMISSIONS
# ============================================================

DANGEROUS_PERMISSIONS = (
    SecurityPermission.ADMINISTRATOR
    | SecurityPermission.KICK_MEMBERS
    | SecurityPermission.BAN_MEMBERS
    | SecurityPermission.MANAGE_CHANNELS
    | SecurityPermission.MANAGE_ROLES
    | SecurityPermission.MANAGE_WEBHOOKS
    | SecurityPermission.MANAGE_GUILD
    | SecurityPermission.MENTION_EVERYONE
)


# ============================================================
# EMERGENCY ROLE PERMISSIONS
# ============================================================

EMERGENCY_REVOKE_PERMISSIONS = (
    SecurityPermission.ADMINISTRATOR
    | SecurityPermission.KICK_MEMBERS
    | SecurityPermission.BAN_MEMBERS
    | SecurityPermission.MANAGE_CHANNELS
    | SecurityPermission.MANAGE_ROLES
    | SecurityPermission.MANAGE_WEBHOOKS
    | SecurityPermission.MANAGE_GUILD
    | SecurityPermission.MENTION_EVERYONE
)


# ============================================================
# CONVERSION
# ============================================================

def permission_from_discord(
    permissions: discord.Permissions,
) -> SecurityPermission:
    """
    discord.Permissions nesnesini SecurityPermission'a çevirir.
    """

    result = SecurityPermission.NONE

    if permissions.administrator:
        result |= SecurityPermission.ADMINISTRATOR

    if permissions.kick_members:
        result |= SecurityPermission.KICK_MEMBERS

    if permissions.ban_members:
        result |= SecurityPermission.BAN_MEMBERS

    if permissions.manage_channels:
        result |= SecurityPermission.MANAGE_CHANNELS

    if permissions.manage_roles:
        result |= SecurityPermission.MANAGE_ROLES

    if permissions.manage_webhooks:
        result |= SecurityPermission.MANAGE_WEBHOOKS

    if permissions.manage_guild:
        result |= SecurityPermission.MANAGE_GUILD

    if permissions.mention_everyone:
        result |= SecurityPermission.MENTION_EVERYONE

    if permissions.manage_messages:
        result |= SecurityPermission.MANAGE_MESSAGES

    if permissions.moderate_members:
        result |= SecurityPermission.MODERATE_MEMBERS

    return result


def permission_to_discord(
    permissions: SecurityPermission,
) -> discord.Permissions:
    """
    SecurityPermission değerini discord.Permissions'a çevirir.
    """

    result = discord.Permissions.none()

    if permissions & SecurityPermission.ADMINISTRATOR:
        result.administrator = True

    if permissions & SecurityPermission.KICK_MEMBERS:
        result.kick_members = True

    if permissions & SecurityPermission.BAN_MEMBERS:
        result.ban_members = True

    if permissions & SecurityPermission.MANAGE_CHANNELS:
        result.manage_channels = True

    if permissions & SecurityPermission.MANAGE_ROLES:
        result.manage_roles = True

    if permissions & SecurityPermission.MANAGE_WEBHOOKS:
        result.manage_webhooks = True

    if permissions & SecurityPermission.MANAGE_GUILD:
        result.manage_guild = True

    if permissions & SecurityPermission.MENTION_EVERYONE:
        result.mention_everyone = True

    if permissions & SecurityPermission.MANAGE_MESSAGES:
        result.manage_messages = True

    if permissions & SecurityPermission.MODERATE_MEMBERS:
        result.moderate_members = True

    return result


# ============================================================
# PERMISSION CHECKS
# ============================================================

def has_permission(
    permissions: discord.Permissions,
    required: SecurityPermission,
) -> bool:
    """
    Discord permission nesnesinde belirtilen permission'ların
    tamamının bulunup bulunmadığını kontrol eder.

    Administrator özel olarak tüm permission'ları karşılar.
    """

    if permissions.administrator:
        return True

    current = permission_from_discord(permissions)

    return (current & required) == required


def has_any_permission(
    permissions: discord.Permissions,
    required: SecurityPermission,
) -> bool:
    """
    Belirtilen permission'lardan en az birine sahip mi?
    """

    if permissions.administrator:
        return True

    current = permission_from_discord(permissions)

    return bool(current & required)


def missing_permissions(
    permissions: discord.Permissions,
    required: SecurityPermission,
) -> SecurityPermission:
    """
    Eksik security permission'ları döndürür.
    """

    if permissions.administrator:
        return SecurityPermission.NONE

    current = permission_from_discord(permissions)

    return required & ~current


# ============================================================
# DANGEROUS PERMISSION CHECK
# ============================================================

def get_dangerous_permissions(
    permissions: discord.Permissions,
) -> SecurityPermission:
    """
    Kullanıcının sahip olduğu kritik permission'ları döndürür.
    """

    if permissions.administrator:
        return DANGEROUS_PERMISSIONS

    current = permission_from_discord(permissions)

    return current & DANGEROUS_PERMISSIONS


def has_dangerous_permissions(
    permissions: discord.Permissions,
) -> bool:
    """
    Kullanıcıda kritik güvenlik izinlerinden biri var mı?
    """

    return bool(
        get_dangerous_permissions(permissions)
    )


# ============================================================
# MEMBER HELPERS
# ============================================================

def member_permissions(
    member: discord.Member,
) -> discord.Permissions:
    """
    Member'ın guild içerisindeki efektif permission'larını döndürür.
    """

    return member.guild_permissions


def member_has_permission(
    member: discord.Member,
    required: SecurityPermission,
) -> bool:
    """
    Member'ın gerekli permission'lara sahip olup olmadığını
    kontrol eder.
    """

    return has_permission(
        member.guild_permissions,
        required,
    )


def member_has_any_permission(
    member: discord.Member,
    required: SecurityPermission,
) -> bool:
    """
    Member'ın belirtilen kritik izinlerden en az birine
    sahip olup olmadığını kontrol eder.
    """

    return has_any_permission(
        member.guild_permissions,
        required,
    )


def member_dangerous_permissions(
    member: discord.Member,
) -> SecurityPermission:
    """
    Member'ın kritik permission'larını döndürür.
    """

    return get_dangerous_permissions(
        member.guild_permissions
    )


# ============================================================
# ROLE HELPERS
# ============================================================

def role_permissions(
    role: discord.Role,
) -> SecurityPermission:
    """
    Role üzerindeki Security permission'larını döndürür.
    """

    return permission_from_discord(
        role.permissions
    )


def role_has_permission(
    role: discord.Role,
    required: SecurityPermission,
) -> bool:
    """
    Role belirtilen permission'lara sahip mi?
    """

    return has_permission(
        role.permissions,
        required,
    )


def role_has_any_permission(
    role: discord.Role,
    required: SecurityPermission,
) -> bool:
    """
    Role belirtilen permission'lardan herhangi birine sahip mi?
    """

    return has_any_permission(
        role.permissions,
        required,
    )


def role_is_dangerous(
    role: discord.Role,
) -> bool:
    """
    Role kritik güvenlik permission'larından herhangi birine
    sahip mi?
    """

    return has_dangerous_permissions(
        role.permissions
    )


def get_dangerous_roles(
    roles: Iterable[discord.Role],
) -> list[discord.Role]:
    """
    Kritik permission taşıyan rolleri döndürür.
    """

    return [
        role
        for role in roles
        if role_is_dangerous(role)
    ]


# ============================================================
# ROLE RISK
# ============================================================

def role_risk_score(
    role: discord.Role,
) -> int:
    """
    Role'un güvenlik açısından kaba risk puanını döndürür.

    Bu bir karar motoru değildir.
    Sadece permission seviyesini sayısal olarak ifade eder.
    """

    permissions = role.permissions

    if permissions.administrator:
        return 100

    score = 0

    if permissions.ban_members:
        score += 25

    if permissions.kick_members:
        score += 20

    if permissions.manage_channels:
        score += 20

    if permissions.manage_roles:
        score += 20

    if permissions.manage_webhooks:
        score += 10

    if permissions.manage_guild:
        score += 10

    if permissions.mention_everyone:
        score += 5

    return min(score, 100)


# ============================================================
# ROLE REVOCATION ANALYSIS
# ============================================================

def should_revoke_role(
    role: discord.Role,
) -> bool:
    """
    Emergency sırasında rolün geçici olarak kaldırılması
    gerekip gerekmediğini kontrol eder.

    Burada yalnızca permission kontrolü yapılır.
    Emergency kararını emergency_service verir.
    """

    return role_has_any_permission(
        role,
        EMERGENCY_REVOKE_PERMISSIONS,
    )


def get_roles_to_revoke(
    member: discord.Member,
) -> list[discord.Role]:
    """
    Emergency role lock için kritik permission taşıyan
    rolleri döndürür.

    @everyone rolü hiçbir zaman döndürülmez.
    """

    result: list[discord.Role] = []

    for role in member.roles:
        if role.is_default():
            continue

        if should_revoke_role(role):
            result.append(role)

    return result


# ============================================================
# BOT PERMISSION CHECK
# ============================================================

def bot_can_manage_role(
    bot_member: discord.Member,
    target_role: discord.Role,
) -> bool:
    """
    Bot target role'u yönetebilir mi?

    Discord hierarchy nedeniyle bot yalnızca kendi
    en yüksek rolünün altındaki rolleri yönetebilir.
    """

    if target_role.is_default():
        return False

    if target_role.managed:
        return False

    return (
        bot_member.guild_permissions.manage_roles
        and target_role < bot_member.top_role
    )


def bot_can_modify_member_roles(
    bot_member: discord.Member,
    target_member: discord.Member,
) -> bool:
    """
    Bot hedef kullanıcının rollerini değiştirebilir mi?
    """

    if target_member == bot_member:
        return False

    if target_member == bot_member.guild.owner:
        return False

    if target_member.top_role >= bot_member.top_role:
        return False

    return bot_member.guild_permissions.manage_roles


# ============================================================
# KICK / BAN CHECK
# ============================================================

def can_kick_member(
    actor: discord.Member,
    target: discord.Member,
) -> bool:
    """
    Actor hedef üyeyi kickleyebilir mi?

    Bu fonksiyon sadece Discord hierarchy ve permission
    kontrolü yapar.
    """

    if target == actor:
        return False

    if target == actor.guild.owner:
        return False

    if not actor.guild_permissions.kick_members:
        return False

    return target.top_role < actor.top_role


def can_ban_member(
    actor: discord.Member,
    target: discord.Member,
) -> bool:
    """
    Actor hedef üyeyi banlayabilir mi?
    """

    if target == actor:
        return False

    if target == actor.guild.owner:
        return False

    if not actor.guild_permissions.ban_members:
        return False

    return target.top_role < actor.top_role


# ============================================================
# PERMISSION RESULT
# ============================================================

def check_permissions(
    permissions: discord.Permissions,
    required: SecurityPermission,
) -> PermissionResult:
    """
    Ayrıntılı permission sonucu üretir.
    """

    administrator = permissions.administrator

    current = permission_from_discord(
        permissions
    )

    if administrator:
        missing = SecurityPermission.NONE
        allowed = True
    else:
        missing = required & ~current
        allowed = missing == SecurityPermission.NONE

    dangerous = current & DANGEROUS_PERMISSIONS

    return PermissionResult(
        allowed=allowed,
        administrator=administrator,
        permissions=current,
        missing=missing,
        dangerous=dangerous,
    )


# ============================================================
# FORMATTING
# ============================================================

def permission_name(
    permission: SecurityPermission,
) -> str:
    """
    Tek permission'ı okunabilir Discord permission adına çevirir.
    """

    return _PERMISSION_MAP.get(
        permission,
        permission.name or "unknown",
    )


def permission_names(
    permissions: SecurityPermission,
) -> list[str]:
    """
    Permission flag'lerini okunabilir isim listesine çevirir.
    """

    if permissions == SecurityPermission.NONE:
        return []

    result: list[str] = []

    for flag, name in _PERMISSION_MAP.items():
        if permissions & flag:
            result.append(name)

    return result


# ============================================================
# EXPORTS
# ============================================================

__all__ = [
    # Types
    "SecurityPermission",
    "PermissionResult",

    # Constants
    "DANGEROUS_PERMISSIONS",
    "EMERGENCY_REVOKE_PERMISSIONS",

    # Conversion
    "permission_from_discord",
    "permission_to_discord",

    # Permission checks
    "has_permission",
    "has_any_permission",
    "missing_permissions",

    # Dangerous permissions
    "get_dangerous_permissions",
    "has_dangerous_permissions",

    # Member
    "member_permissions",
    "member_has_permission",
    "member_has_any_permission",
    "member_dangerous_permissions",

    # Roles
    "role_permissions",
    "role_has_permission",
    "role_has_any_permission",
    "role_is_dangerous",
    "get_dangerous_roles",

    # Risk
    "role_risk_score",

    # Emergency
    "should_revoke_role",
    "get_roles_to_revoke",

    # Bot hierarchy
    "bot_can_manage_role",
    "bot_can_modify_member_roles",

    # Kick / Ban
    "can_kick_member",
    "can_ban_member",

    # Result
    "check_permissions",

    # Formatting
    "permission_name",
    "permission_names",
]