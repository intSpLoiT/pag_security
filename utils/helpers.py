# utils/helpers.py

from __future__ import annotations

import asyncio
import re
from collections.abc import Iterable, Sequence
from datetime import datetime, timezone
from typing import Any, Optional


# ============================================================
# PAG SECURITY BOT
# utils/helpers.py
#
# Genel, hafif ve bağımsız yardımcı fonksiyonlar.
#
# Bu dosyada:
# - Security logic yok
# - Moderation logic yok
# - Discord API çağrısı yok
# - Database işlemi yok
#
# Amaç:
# Cog ve Service'lerde tekrar eden küçük işlemleri
# tek bir yerde toplamak.
# ============================================================


# ============================================================
# TIME
# ============================================================

def utc_now() -> datetime:
    """
    Güncel UTC zamanını timezone-aware datetime olarak döndürür.
    """
    return datetime.now(timezone.utc)


def unix_timestamp(dt: Optional[datetime] = None) -> int:
    """
    Datetime değerini Unix timestamp'e çevirir.

    Args:
        dt:
            Çevrilecek datetime.
            None verilirse şu anki UTC zamanı kullanılır.

    Returns:
        int: Unix timestamp.
    """
    if dt is None:
        dt = utc_now()

    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)

    return int(dt.timestamp())


def ensure_utc(dt: datetime) -> datetime:
    """
    Naive datetime değerlerini UTC kabul eder.
    Timezone-aware değerleri UTC'ye çevirir.
    """
    if dt.tzinfo is None:
        return dt.replace(tzinfo=timezone.utc)

    return dt.astimezone(timezone.utc)


def elapsed_seconds(
    start: datetime,
    end: Optional[datetime] = None,
) -> float:
    """
    İki datetime arasındaki saniye farkını döndürür.
    """
    start = ensure_utc(start)

    if end is None:
        end = utc_now()
    else:
        end = ensure_utc(end)

    return max(0.0, (end - start).total_seconds())


# ============================================================
# INTEGER / NUMBER HELPERS
# ============================================================

def clamp(
    value: float | int,
    minimum: float | int,
    maximum: float | int,
) -> float | int:
    """
    Bir sayıyı belirtilen aralıkta tutar.

    Örnek:
        clamp(120, 0, 100) -> 100
        clamp(-5, 0, 100) -> 0
    """
    if minimum > maximum:
        raise ValueError("minimum, maximum değerinden büyük olamaz.")

    return max(minimum, min(value, maximum))


def safe_int(
    value: Any,
    default: int = 0,
    minimum: Optional[int] = None,
    maximum: Optional[int] = None,
) -> int:
    """
    Güvenli şekilde integer dönüştürür.

    Hatalı değerlerde default döner.

    Opsiyonel olarak minimum/maximum sınırı uygulanabilir.
    """
    try:
        result = int(value)
    except (TypeError, ValueError, OverflowError):
        result = default

    if minimum is not None and result < minimum:
        result = minimum

    if maximum is not None and result > maximum:
        result = maximum

    return result


def safe_float(
    value: Any,
    default: float = 0.0,
    minimum: Optional[float] = None,
    maximum: Optional[float] = None,
) -> float:
    """
    Güvenli şekilde float dönüştürür.
    """
    try:
        result = float(value)
    except (TypeError, ValueError, OverflowError):
        result = default

    if minimum is not None and result < minimum:
        result = minimum

    if maximum is not None and result > maximum:
        result = maximum

    return result


# ============================================================
# STRING HELPERS
# ============================================================

def clean_text(
    text: Any,
    *,
    max_length: Optional[int] = None,
) -> str:
    """
    Metni güvenli şekilde normalize eder.

    - None -> ""
    - Baştaki/sondaki boşlukları temizler.
    - Ardışık whitespace karakterlerini tek boşluğa indirir.
    - İstenirse maksimum uzunluk uygular.
    """
    if text is None:
        return ""

    result = str(text)
    result = re.sub(r"\s+", " ", result).strip()

    if max_length is not None:
        if max_length < 0:
            raise ValueError("max_length negatif olamaz.")

        result = result[:max_length]

    return result


def normalize_text(text: Any) -> str:
    """
    Karşılaştırma için metni normalize eder.

    Büyük/küçük harf farklarını azaltır.
    """
    return clean_text(text).casefold()


def truncate(
    text: Any,
    max_length: int,
    suffix: str = "...",
) -> str:
    """
    Uzun metni belirtilen karakter sayısına indirir.
    """
    if max_length < 0:
        raise ValueError("max_length negatif olamaz.")

    value = str(text)

    if len(value) <= max_length:
        return value

    if max_length == 0:
        return ""

    if len(suffix) >= max_length:
        return suffix[:max_length]

    return value[: max_length - len(suffix)] + suffix


def is_blank(value: Any) -> bool:
    """
    Değer None veya boş/whitespace ise True döndürür.
    """
    return value is None or not str(value).strip()


# ============================================================
# DISCORD ID HELPERS
# ============================================================

_DISCORD_ID_RE = re.compile(r"^\d{15,25}$")


def is_valid_discord_id(value: Any) -> bool:
    """
    Bir değerin Discord snowflake ID formatına benzeyip
    benzemediğini kontrol eder.

    Bu fonksiyon Discord API'ye istek atmaz.
    """
    if value is None:
        return False

    return bool(_DISCORD_ID_RE.fullmatch(str(value).strip()))


def extract_discord_id(value: Any) -> Optional[int]:
    """
    String içerisinden Discord ID çıkarmayı dener.

    Örnek:
        "123456789012345678" -> 123456789012345678
    """
    if value is None:
        return None

    match = re.search(r"\b\d{15,25}\b", str(value))

    if not match:
        return None

    try:
        return int(match.group())
    except ValueError:
        return None


# ============================================================
# COLLECTION HELPERS
# ============================================================

def unique(
    values: Iterable[Any],
) -> list[Any]:
    """
    Sıralamayı koruyarak tekrar eden değerleri kaldırır.

    Hash edilemeyen objeler için repr tabanlı fallback kullanır.
    """
    result: list[Any] = []
    seen_hashable: set[Any] = set()
    seen_unhashable: set[str] = set()

    for value in values:
        try:
            if value in seen_hashable:
                continue

            seen_hashable.add(value)
            result.append(value)

        except TypeError:
            key = repr(value)

            if key in seen_unhashable:
                continue

            seen_unhashable.add(key)
            result.append(value)

    return result


def chunks(
    sequence: Sequence[Any],
    size: int,
) -> list[list[Any]]:
    """
    Sequence'ı küçük parçalara böler.

    Örnek:
        chunks([1, 2, 3, 4, 5], 2)

        [
            [1, 2],
            [3, 4],
            [5],
        ]
    """
    if size <= 0:
        raise ValueError("size 0'dan büyük olmalıdır.")

    return [
        list(sequence[index:index + size])
        for index in range(0, len(sequence), size)
    ]


# ============================================================
# DICT HELPERS
# ============================================================

def get_nested(
    data: Any,
    *keys: Any,
    default: Any = None,
) -> Any:
    """
    İç içe dictionary değerlerini güvenli şekilde alır.

    Örnek:
        get_nested(
            data,
            "security",
            "emergency",
            "enabled",
        )
    """
    current = data

    for key in keys:
        if not isinstance(current, dict):
            return default

        if key not in current:
            return default

        current = current[key]

    return current


def remove_none(
    data: dict[Any, Any],
) -> dict[Any, Any]:
    """
    Dictionary içerisindeki None değerleri kaldırır.
    """
    return {
        key: value
        for key, value in data.items()
        if value is not None
    }


# ============================================================
# ASYNC HELPERS
# ============================================================

async def safe_sleep(seconds: float) -> None:
    """
    Negatif değerlerde hata vermeyen asyncio.sleep wrapper'ı.
    """
    await asyncio.sleep(max(0.0, seconds))


async def cancel_task(
    task: Optional[asyncio.Task[Any]],
) -> None:
    """
    Async task'i güvenli şekilde iptal eder.

    Task zaten tamamlandıysa tekrar işlem yapmaz.
    """
    if task is None:
        return

    if task.done():
        return

    task.cancel()

    try:
        await task
    except asyncio.CancelledError:
        pass


# ============================================================
# BOOLEAN HELPERS
# ============================================================

_TRUE_VALUES = {
    "1",
    "true",
    "yes",
    "y",
    "on",
    "enabled",
    "enable",
}

_FALSE_VALUES = {
    "0",
    "false",
    "no",
    "n",
    "off",
    "disabled",
    "disable",
}


def parse_bool(
    value: Any,
    default: bool = False,
) -> bool:
    """
    .env gibi string değerleri boolean'a çevirir.

    Örnek:
        "true"  -> True
        "false" -> False
        "1"     -> True
        "0"     -> False
    """
    if isinstance(value, bool):
        return value

    if value is None:
        return default

    normalized = str(value).strip().casefold()

    if normalized in _TRUE_VALUES:
        return True

    if normalized in _FALSE_VALUES:
        return False

    return default


# ============================================================
# SECURITY HELPERS
# ============================================================

def risk_level(score: int | float) -> str:
    """
    Security risk puanını seviyeye dönüştürür.

    0-29   SAFE
    30-49  LOW
    50-69  HIGH
    70-89  CRITICAL
    90+    EMERGENCY
    """
    score = safe_int(score, minimum=0, maximum=100)

    if score >= 90:
        return "EMERGENCY"

    if score >= 70:
        return "CRITICAL"

    if score >= 50:
        return "HIGH"

    if score >= 30:
        return "LOW"

    return "SAFE"


def risk_emoji(score: int | float) -> str:
    """
    Risk puanına uygun emoji döndürür.
    """
    level = risk_level(score)

    return {
        "SAFE": "🟢",
        "LOW": "🟡",
        "HIGH": "🟠",
        "CRITICAL": "🔴",
        "EMERGENCY": "🚨",
    }[level]


def add_risk(
    current: int,
    amount: int,
) -> int:
    """
    Risk puanına güvenli şekilde değer ekler.

    Maksimum değer 100'dür.
    """
    return safe_int(
        current + amount,
        default=0,
        minimum=0,
        maximum=100,
    )


# ============================================================
# GENERAL HELPERS
# ============================================================

def first_not_none(*values: Any) -> Any:
    """
    None olmayan ilk değeri döndürür.
    Hiçbiri yoksa None döner.
    """
    for value in values:
        if value is not None:
            return value

    return None


def bool_to_status(value: bool) -> str:
    """
    Boolean değeri okunabilir status'a çevirir.
    """
    return "ENABLED" if value else "DISABLED"


def format_duration(seconds: float | int) -> str:
    """
    Saniyeyi okunabilir süreye çevirir.

    Örnek:
        3661 -> "1h 1m 1s"
    """
    total = max(0, int(seconds))

    days, remainder = divmod(total, 86400)
    hours, remainder = divmod(remainder, 3600)
    minutes, seconds = divmod(remainder, 60)

    parts: list[str] = []

    if days:
        parts.append(f"{days}d")

    if hours:
        parts.append(f"{hours}h")

    if minutes:
        parts.append(f"{minutes}m")

    if seconds or not parts:
        parts.append(f"{seconds}s")

    return " ".join(parts)


def format_count(value: int | float) -> str:
    """
    Büyük sayıları okunabilir hale getirir.

    Örnek:
        12500 -> "12,500"
    """
    try:
        return f"{value:,}"
    except (ValueError, TypeError):
        return "0"


# ============================================================
# EXPORTS
# ============================================================

__all__ = [
    # Time
    "utc_now",
    "unix_timestamp",
    "ensure_utc",
    "elapsed_seconds",

    # Numbers
    "clamp",
    "safe_int",
    "safe_float",

    # Strings
    "clean_text",
    "normalize_text",
    "truncate",
    "is_blank",

    # Discord IDs
    "is_valid_discord_id",
    "extract_discord_id",

    # Collections
    "unique",
    "chunks",

    # Dict
    "get_nested",
    "remove_none",

    # Async
    "safe_sleep",
    "cancel_task",

    # Boolean
    "parse_bool",

    # Security
    "risk_level",
    "risk_emoji",
    "add_risk",

    # General
    "first_not_none",
    "bool_to_status",
    "format_duration",
    "format_count",
]