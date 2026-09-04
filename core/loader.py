from __future__ import annotations

# ============================================================
# PAG SECURITY BOT
# core/loader.py
#
# Merkezi Extension / Cog Loader
#
# SORUMLULUKLAR
# ------------------------------------------------------------
# - Extension keşfi
# - Extension yükleme
# - Extension unload
# - Extension reload
# - Toplu extension yönetimi
# - Hata izolasyonu
# - Extension status takibi
# - Deterministik yükleme sırası
# - Timeout kontrolü
# - Concurrent load/reload koruması
# - Dry-run desteği
# - Zorunlu extension kontrolü
#
# discord.py 2.x
# Python 3.11+
# ============================================================

from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path
from time import monotonic
from typing import Iterable, Optional

from discord.ext import commands

from utils.logger import security_logger


# ============================================================
# CONSTANTS
# ============================================================

DEFAULT_EXTENSION_TIMEOUT = 30.0

DEFAULT_COG_DIRECTORY = "cogs"

EXTENSION_FILE_SUFFIX = ".py"

PRIVATE_FILE_PREFIX = "_"


# ============================================================
# ENUMS
# ============================================================


class ExtensionState(str, Enum):
    """
    Extension'ın mevcut runtime durumunu belirtir.
    """

    DISCOVERED = "discovered"
    LOADED = "loaded"
    FAILED = "failed"
    UNLOADED = "unloaded"
    SKIPPED = "skipped"
    UNKNOWN = "unknown"


# ============================================================
# RESULT
# ============================================================


@dataclass(slots=True)
class ExtensionResult:
    """
    Tek bir extension işleminin sonucudur.
    """

    extension: str

    success: bool

    state: ExtensionState

    operation: str

    duration: float = 0.0

    error: Optional[str] = None

    error_type: Optional[str] = None

    message: str = ""

    already_loaded: bool = False

    was_loaded_before: bool = False

    metadata: dict = field(
        default_factory=dict
    )


# ============================================================
# LOAD SUMMARY
# ============================================================


@dataclass(slots=True)
class LoaderSummary:
    """
    Toplu loader işlemlerinin özeti.
    """

    operation: str

    total: int = 0

    successful: int = 0

    failed: int = 0

    skipped: int = 0

    duration: float = 0.0

    results: list[ExtensionResult] = field(
        default_factory=list
    )

    @property
    def success(self) -> bool:
        """
        Hiçbir extension başarısız olmadıysa True.
        """

        return self.failed == 0

    @property
    def partial_success(self) -> bool:
        """
        En az bir başarılı ve en az bir başarısız
        extension varsa True.
        """

        return (
            self.successful > 0
            and self.failed > 0
        )


# ============================================================
# LOADER
# ============================================================


class ExtensionLoader:
    """
    PAG Security merkezi extension loader.

    Temel kullanım:

        loader = ExtensionLoader(bot)

        await loader.load_all()

    veya:

        await loader.load_extension(
            "cogs.security"
        )

    """

    def __init__(
        self,
        bot: commands.Bot,
        *,
        root_directory: str | Path = ".",
        cog_directory: str | Path = DEFAULT_COG_DIRECTORY,
        timeout: float = DEFAULT_EXTENSION_TIMEOUT,
    ) -> None:

        if bot is None:
            raise ValueError(
                "ExtensionLoader requires a bot instance."
            )

        if timeout <= 0:
            raise ValueError(
                "Extension timeout must be greater than 0."
            )

        self.bot = bot

        self.root_directory = Path(
            root_directory
        ).resolve()

        self.cog_directory = Path(
            cog_directory
        )

        if self.cog_directory.is_absolute():
            self.cog_path = (
                self.cog_directory.resolve()
            )
        else:
            self.cog_path = (
                self.root_directory
                / self.cog_directory
            ).resolve()

        self.timeout = float(timeout)

        # ----------------------------------------------------
        # Runtime state
        # ----------------------------------------------------

        self._states: dict[
            str,
            ExtensionState,
        ] = {}

        self._results: dict[
            str,
            ExtensionResult,
        ] = {}

        self._load_times: dict[
            str,
            float,
        ] = {}

        # ----------------------------------------------------
        # Concurrency protection
        #
        # Aynı extension üzerinde aynı anda:
        #
        # load + reload
        # reload + unload
        #
        # gibi işlemlerin çakışmasını engeller.
        # ----------------------------------------------------

        import asyncio

        self._lock = asyncio.Lock()

        self._extension_locks: dict[
            str,
            asyncio.Lock,
        ] = {}

        # ----------------------------------------------------
        # Lifecycle
        # ----------------------------------------------------

        self.initialized = False

        self.closed = False

        # ----------------------------------------------------
        # Statistics
        # ----------------------------------------------------

        self.total_load_attempts = 0

        self.total_successful_loads = 0

        self.total_failed_loads = 0

        self.total_reloads = 0

        self.total_unloads = 0

        security_logger.info(
            "ExtensionLoader initialized | "
            "root=%s cogs=%s timeout=%.2fs",
            self.root_directory,
            self.cog_path,
            self.timeout,
        )

    # ========================================================
    # INTERNAL
    # ========================================================

    def _get_extension_lock(
        self,
        extension: str,
    ):
        """
        Extension'a özel lock döndürür.
        """

        lock = self._extension_locks.get(
            extension
        )

        if lock is None:

            import asyncio

            lock = asyncio.Lock()

            self._extension_locks[
                extension
            ] = lock

        return lock

    def _normalize_extension(
        self,
        extension: str,
    ) -> str:
        """
        Extension ismini normalize eder.

        Kabul edilen örnekler:

            cogs.security
            cogs/security.py
            ./cogs/security.py
        """

        if not isinstance(
            extension,
            str,
        ):
            raise TypeError(
                "Extension name must be a string."
            )

        extension = extension.strip()

        if not extension:
            raise ValueError(
                "Extension name cannot be empty."
            )

        extension = extension.replace(
            "\\",
            "/",
        )

        if extension.startswith("./"):
            extension = extension[2:]

        if extension.endswith(
            EXTENSION_FILE_SUFFIX
        ):
            extension = extension[
                : -len(
                    EXTENSION_FILE_SUFFIX
                )
            ]

        extension = extension.replace(
            "/",
            ".",
        )

        while ".." in extension:
            extension = extension.replace(
                "..",
                ".",
            )

        extension = extension.strip(".")

        if not extension:
            raise ValueError(
                "Invalid extension name."
            )

        return extension

    def _extension_to_path(
        self,
        extension: str,
    ) -> Path:
        """
        Extension adını fiziksel .py dosyasına çevirir.
        """

        extension = self._normalize_extension(
            extension
        )

        relative = Path(
            *extension.split(".")
        ).with_suffix(
            EXTENSION_FILE_SUFFIX
        )

        return (
            self.root_directory
            / relative
        ).resolve()

    def _is_valid_extension_name(
        self,
        extension: str,
    ) -> bool:
        """
        Extension isminin güvenli olup olmadığını kontrol eder.
        """

        try:

            normalized = (
                self._normalize_extension(
                    extension
                )
            )

        except (
            TypeError,
            ValueError,
        ):
            return False

        parts = normalized.split(".")

        if not parts:
            return False

        for part in parts:

            if not part:
                return False

            if part.startswith(
                PRIVATE_FILE_PREFIX
            ):
                return False

        return True

    def _record_result(
        self,
        result: ExtensionResult,
    ) -> ExtensionResult:
        """
        Sonucu runtime state'e kaydeder.
        """

        self._results[
            result.extension
        ] = result

        self._states[
            result.extension
        ] = result.state

        if result.success:
            self._load_times[
                result.extension
            ] = result.duration

        return result

    # ========================================================
    # DISCOVERY
    # ========================================================

    def discover_extensions(
        self,
        *,
        directory: str | Path | None = None,
        recursive: bool = False,
        include_private: bool = False,
    ) -> list[str]:
        """
        Python extension dosyalarını keşfeder.

        Örnek:

            [
                "cogs.anti_bot",
                "cogs.anti_nuke",
                "cogs.security",
            ]

        Varsayılan olarak deterministik alfabetik sıralama
        uygulanır.
        """

        base = (
            self.cog_path
            if directory is None
            else Path(directory).resolve()
        )

        if not base.exists():

            security_logger.warning(
                "Extension directory does not exist | "
                "path=%s",
                base,
            )

            return []

        if not base.is_dir():

            security_logger.error(
                "Extension path is not a directory | "
                "path=%s",
                base,
            )

            return []

        pattern = (
            "**/*.py"
            if recursive
            else "*.py"
        )

        extensions: list[str] = []

        for file in base.glob(pattern):

            if not file.is_file():
                continue

            if file.suffix != EXTENSION_FILE_SUFFIX:
                continue

            if (
                not include_private
                and file.name.startswith(
                    PRIVATE_FILE_PREFIX
                )
            ):
                continue

            # __init__.py extension değildir.
            if file.name == "__init__.py":
                continue

            try:

                relative = file.relative_to(
                    self.root_directory
                )

            except ValueError:

                security_logger.warning(
                    "Skipping extension outside root | "
                    "path=%s",
                    file,
                )

                continue

            extension = (
                str(relative)
                .replace("\\", "/")
                .replace("/", ".")
            )

            if extension.endswith(
                EXTENSION_FILE_SUFFIX
            ):
                extension = extension[
                    : -len(
                        EXTENSION_FILE_SUFFIX
                    )
                ]

            if not self._is_valid_extension_name(
                extension
            ):
                security_logger.warning(
                    "Skipping invalid extension name | "
                    "extension=%s",
                    extension,
                )

                continue

            extensions.append(
                extension
            )

            self._states[
                extension
            ] = ExtensionState.DISCOVERED

        extensions = sorted(
            set(extensions),
            key=str.lower,
        )

        security_logger.debug(
            "Extensions discovered | count=%s",
            len(extensions),
        )

        return extensions

    # ========================================================
    # DISCOVERY FILTER
    # ========================================================

    def filter_extensions(
        self,
        extensions: Iterable[str],
        *,
        include: Optional[
            Iterable[str]
        ] = None,
        exclude: Optional[
            Iterable[str]
        ] = None,
    ) -> list[str]:
        """
        Extension listesini include/exclude ile filtreler.

        Örnek:

            loader.filter_extensions(
                extensions,
                exclude={
                    "cogs.statistics"
                }
            )
        """

        extension_list = [
            self._normalize_extension(
                extension
            )
            for extension in extensions
        ]

        include_set = None

        if include is not None:

            include_set = {
                self._normalize_extension(
                    item
                )
                for item in include
            }

        exclude_set = set()

        if exclude is not None:

            exclude_set = {
                self._normalize_extension(
                    item
                )
                for item in exclude
            }

        result: list[str] = []

        for extension in extension_list:

            if (
                include_set is not None
                and extension not in include_set
            ):
                continue

            if extension in exclude_set:
                continue

            result.append(
                extension
            )

        return sorted(
            set(result),
            key=str.lower,
        )

    # ========================================================
    # VALIDATION
    # ========================================================

    def validate_extension(
        self,
        extension: str,
    ) -> tuple[bool, Optional[str]]:
        """
        Extension fiziksel olarak mevcut mu ve
        temel isim kurallarına uygun mu kontrol eder.

        Import gerçekleştirmez.
        """

        try:

            normalized = (
                self._normalize_extension(
                    extension
                )
            )

        except (
            TypeError,
            ValueError,
        ) as exc:

            return False, str(exc)

        if not self._is_valid_extension_name(
            normalized
        ):
            return (
                False,
                "Invalid extension name.",
            )

        path = self._extension_to_path(
            normalized
        )

        if not path.exists():

            return (
                False,
                f"Extension file not found: {path}",
            )

        if not path.is_file():

            return (
                False,
                f"Extension path is not a file: {path}",
            )

        if path.suffix != ".py":

            return (
                False,
                "Extension is not a Python file.",
            )

        return True, None

    # ========================================================
    # LOAD SINGLE
    # ========================================================

    async def load_extension(
        self,
        extension: str,
        *,
        timeout: Optional[float] = None,
        force: bool = False,
    ) -> ExtensionResult:
        """
        Tek bir extension yükler.

        force=False:
            Zaten yüklüyse işlem tekrar edilmez.

        force=True:
            discord.py extension reload değildir.
            Bu durumda mevcut extension unload edilip
            yeniden yüklenir.
        """

        if self.closed:

            return self._record_result(
                ExtensionResult(
                    extension=str(
                        extension
                    ),
                    success=False,
                    state=ExtensionState.FAILED,
                    operation="load",
                    error=(
                        "ExtensionLoader is closed."
                    ),
                    error_type="RuntimeError",
                )
            )

        try:

            normalized = (
                self._normalize_extension(
                    extension
                )
            )

        except Exception as exc:

            return self._record_result(
                ExtensionResult(
                    extension=str(
                        extension
                    ),
                    success=False,
                    state=ExtensionState.FAILED,
                    operation="load",
                    error=str(exc),
                    error_type=type(
                        exc
                    ).__name__,
                )
            )

        lock = self._get_extension_lock(
            normalized
        )

        async with lock:

            started = monotonic()

            was_loaded = (
                normalized
                in self.bot.extensions
            )

            if was_loaded and not force:

                result = ExtensionResult(
                    extension=normalized,
                    success=True,
                    state=ExtensionState.LOADED,
                    operation="load",
                    duration=(
                        monotonic()
                        - started
                    ),
                    message=(
                        "Extension already loaded."
                    ),
                    already_loaded=True,
                    was_loaded_before=True,
                )

                security_logger.debug(
                    "Extension already loaded | %s",
                    normalized,
                )

                return self._record_result(
                    result
                )

            valid, error = (
                self.validate_extension(
                    normalized
                )
            )

            if not valid:

                result = ExtensionResult(
                    extension=normalized,
                    success=False,
                    state=ExtensionState.FAILED,
                    operation="load",
                    duration=(
                        monotonic()
                        - started
                    ),
                    error=error,
                    error_type="ValidationError",
                )

                security_logger.error(
                    "Extension validation failed | "
                    "extension=%s error=%s",
                    normalized,
                    error,
                )

                return self._record_result(
                    result
                )

            self.total_load_attempts += 1

            try:

                if force and was_loaded:

                    security_logger.info(
                        "Force reload requested | %s",
                        normalized,
                    )

                    await self._run_with_timeout(
                        self.bot.reload_extension(
                            normalized
                        ),
                        timeout,
                        operation=(
                            f"reload:{normalized}"
                        ),
                    )

                    operation = "reload"

                else:

                    security_logger.info(
                        "Loading extension | %s",
                        normalized,
                    )

                    await self._run_with_timeout(
                        self.bot.load_extension(
                            normalized
                        ),
                        timeout,
                        operation=(
                            f"load:{normalized}"
                        ),
                    )

                    operation = "load"

                duration = (
                    monotonic()
                    - started
                )

                self.total_successful_loads += 1

                self.initialized = True

                result = ExtensionResult(
                    extension=normalized,
                    success=True,
                    state=ExtensionState.LOADED,
                    operation=operation,
                    duration=duration,
                    message=(
                        "Extension loaded successfully."
                    ),
                    was_loaded_before=was_loaded,
                )

                security_logger.info(
                    "Extension loaded | "
                    "extension=%s duration=%.3fs",
                    normalized,
                    duration,
                )

                return self._record_result(
                    result
                )

            except Exception as exc:

                duration = (
                    monotonic()
                    - started
                )

                self.total_failed_loads += 1

                error_message = str(
                    exc
                ) or repr(exc)

                result = ExtensionResult(
                    extension=normalized,
                    success=False,
                    state=ExtensionState.FAILED,
                    operation="load",
                    duration=duration,
                    error=error_message,
                    error_type=type(
                        exc
                    ).__name__,
                    message=(
                        "Extension failed to load."
                    ),
                    was_loaded_before=was_loaded,
                    metadata={
                        "exception_repr": repr(
                            exc
                        ),
                    },
                )

                security_logger.exception(
                    "Extension load failed | "
                    "extension=%s error=%s",
                    normalized,
                    error_message,
                )

                return self._record_result(
                    result
                )

    # ========================================================
    # LOAD ALL
    # ========================================================

    async def load_all(
        self,
        *,
        extensions: Optional[
            Iterable[str]
        ] = None,
        include: Optional[
            Iterable[str]
        ] = None,
        exclude: Optional[
            Iterable[str]
        ] = None,
        required: Optional[
            Iterable[str]
        ] = None,
        dry_run: bool = False,
        stop_on_error: bool = False,
        timeout: Optional[float] = None,
    ) -> LoaderSummary:
        """
        Birden fazla extension yükler.

        ÖNEMLİ:

        Varsayılan olarak bir Cog başarısız olduğunda
        diğer Cog'ların yüklenmesine devam eder.

        Bu PAG Security için özellikle önemlidir.

        Örneğin:

            anti_spam.py
                  ↓
              IMPORT ERROR

        olsa bile:

            anti_nuke.py
            anti_bot.py
            security.py

        yüklenmeye devam eder.
        """

        started = monotonic()

        if extensions is None:

            discovered = (
                self.discover_extensions()
            )

        else:

            discovered = [
                self._normalize_extension(
                    extension
                )
                for extension in extensions
            ]

        selected = self.filter_extensions(
            discovered,
            include=include,
            exclude=exclude,
        )

        required_set = {
            self._normalize_extension(
                extension
            )
            for extension in (
                required or []
            )
        }

        summary = LoaderSummary(
            operation="dry_run"
            if dry_run
            else "load_all"
        )

        summary.total = len(
            selected
        )

        if not selected:

            security_logger.warning(
                "No extensions selected for loading."
            )

        for extension in selected:

            if dry_run:

                valid, error = (
                    self.validate_extension(
                        extension
                    )
                )

                if valid:

                    result = ExtensionResult(
                        extension=extension,
                        success=True,
                        state=(
                            ExtensionState.DISCOVERED
                        ),
                        operation="dry_run",
                        message=(
                            "Extension validation passed."
                        ),
                    )

                    summary.successful += 1

                else:

                    result = ExtensionResult(
                        extension=extension,
                        success=False,
                        state=ExtensionState.FAILED,
                        operation="dry_run",
                        error=error,
                        error_type="ValidationError",
                    )

                    summary.failed += 1

                summary.results.append(
                    result
                )

                self._record_result(
                    result
                )

                if (
                    not valid
                    and stop_on_error
                ):
                    break

                continue

            result = await self.load_extension(
                extension,
                timeout=timeout,
            )

            summary.results.append(
                result
            )

            if result.success:

                summary.successful += 1

            elif result.state == (
                ExtensionState.SKIPPED
            ):

                summary.skipped += 1

            else:

                summary.failed += 1

                if (
                    stop_on_error
                ):
                    break

        # ----------------------------------------------------
        # Required extension validation
        # ----------------------------------------------------

        if required_set:

            loaded_extensions = set(
                self.bot.extensions
            )

            missing_required = (
                required_set
                - loaded_extensions
            )

            for extension in sorted(
                missing_required
            ):

                if any(
                    result.extension
                    == extension
                    and not result.success
                    for result in summary.results
                ):
                    continue

                result = ExtensionResult(
                    extension=extension,
                    success=False,
                    state=ExtensionState.FAILED,
                    operation=summary.operation,
                    error=(
                        "Required extension "
                        "was not loaded."
                    ),
                    error_type=(
                        "RequiredExtensionError"
                    ),
                )

                summary.results.append(
                    result
                )

                summary.failed += 1

        summary.duration = (
            monotonic()
            - started
        )

        security_logger.info(
            "Extension loading completed | "
            "total=%s successful=%s failed=%s "
            "skipped=%s duration=%.3fs",
            summary.total,
            summary.successful,
            summary.failed,
            summary.skipped,
            summary.duration,
        )

        return summary

    # ========================================================
    # RELOAD
    # ========================================================

    async def reload_extension(
        self,
        extension: str,
        *,
        timeout: Optional[float] = None,
    ) -> ExtensionResult:
        """
        Tek extension reload eder.
        """

        if self.closed:

            return ExtensionResult(
                extension=str(
                    extension
                ),
                success=False,
                state=ExtensionState.FAILED,
                operation="reload",
                error=(
                    "ExtensionLoader is closed."
                ),
                error_type="RuntimeError",
            )

        try:

            normalized = (
                self._normalize_extension(
                    extension
                )
            )

        except Exception as exc:

            return ExtensionResult(
                extension=str(
                    extension
                ),
                success=False,
                state=ExtensionState.FAILED,
                operation="reload",
                error=str(exc),
                error_type=type(
                    exc
                ).__name__,
            )

        lock = self._get_extension_lock(
            normalized
        )

        async with lock:

            started = monotonic()

            if (
                normalized
                not in self.bot.extensions
            ):

                return self._record_result(
                    ExtensionResult(
                        extension=normalized,
                        success=False,
                        state=ExtensionState.FAILED,
                        operation="reload",
                        duration=(
                            monotonic()
                            - started
                        ),
                        error=(
                            "Extension is not "
                            "currently loaded."
                        ),
                        error_type=(
                            "ExtensionNotLoaded"
                        ),
                    )
                )

            self.total_reloads += 1

            try:

                await self._run_with_timeout(
                    self.bot.reload_extension(
                        normalized
                    ),
                    timeout,
                    operation=(
                        f"reload:{normalized}"
                    ),
                )

                duration = (
                    monotonic()
                    - started
                )

                result = ExtensionResult(
                    extension=normalized,
                    success=True,
                    state=ExtensionState.LOADED,
                    operation="reload",
                    duration=duration,
                    message=(
                        "Extension reloaded successfully."
                    ),
                    was_loaded_before=True,
                )

                security_logger.info(
                    "Extension reloaded | "
                    "extension=%s duration=%.3fs",
                    normalized,
                    duration,
                )

                return self._record_result(
                    result
                )

            except Exception as exc:

                duration = (
                    monotonic()
                    - started
                )

                result = ExtensionResult(
                    extension=normalized,
                    success=False,
                    state=ExtensionState.FAILED,
                    operation="reload",
                    duration=duration,
                    error=str(exc)
                    or repr(exc),
                    error_type=type(
                        exc
                    ).__name__,
                    message=(
                        "Extension reload failed."
                    ),
                )

                security_logger.exception(
                    "Extension reload failed | "
                    "extension=%s error=%s",
                    normalized,
                    exc,
                )

                return self._record_result(
                    result
                )

    # ========================================================
    # RELOAD ALL
    # ========================================================

    async def reload_all(
        self,
        *,
        only_loaded: bool = True,
        extensions: Optional[
            Iterable[str]
        ] = None,
        stop_on_error: bool = False,
        timeout: Optional[float] = None,
    ) -> LoaderSummary:
        """
        Birden fazla extension reload eder.
        """

        started = monotonic()

        if extensions is None:

            if only_loaded:

                selected = sorted(
                    self.bot.extensions,
                    key=str.lower,
                )

            else:

                selected = (
                    self.discover_extensions()
                )

        else:

            selected = [
                self._normalize_extension(
                    extension
                )
                for extension in extensions
            ]

        summary = LoaderSummary(
            operation="reload_all"
        )

        summary.total = len(
            selected
        )

        for extension in selected:

            if (
                only_loaded
                and extension
                not in self.bot.extensions
            ):

                result = ExtensionResult(
                    extension=extension,
                    success=False,
                    state=ExtensionState.SKIPPED,
                    operation="reload",
                    message=(
                        "Extension is not loaded."
                    ),
                )

                summary.results.append(
                    result
                )

                summary.skipped += 1

                continue

            result = await self.reload_extension(
                extension,
                timeout=timeout,
            )

            summary.results.append(
                result
            )

            if result.success:

                summary.successful += 1

            else:

                summary.failed += 1

                if stop_on_error:
                    break

        summary.duration = (
            monotonic()
            - started
        )

        return summary

    # ========================================================
    # UNLOAD
    # ========================================================

    async def unload_extension(
        self,
        extension: str,
        *,
        timeout: Optional[float] = None,
    ) -> ExtensionResult:
        """
        Tek extension unload eder.
        """

        if self.closed:

            return ExtensionResult(
                extension=str(
                    extension
                ),
                success=False,
                state=ExtensionState.FAILED,
                operation="unload",
                error=(
                    "ExtensionLoader is closed."
                ),
                error_type="RuntimeError",
            )

        try:

            normalized = (
                self._normalize_extension(
                    extension
                )
            )

        except Exception as exc:

            return ExtensionResult(
                extension=str(
                    extension
                ),
                success=False,
                state=ExtensionState.FAILED,
                operation="unload",
                error=str(exc),
                error_type=type(
                    exc
                ).__name__,
            )

        lock = self._get_extension_lock(
            normalized
        )

        async with lock:

            started = monotonic()

            if (
                normalized
                not in self.bot.extensions
            ):

                result = ExtensionResult(
                    extension=normalized,
                    success=True,
                    state=ExtensionState.UNLOADED,
                    operation="unload",
                    duration=(
                        monotonic()
                        - started
                    ),
                    message=(
                        "Extension was not loaded."
                    ),
                    already_loaded=False,
                )

                return self._record_result(
                    result
                )

            try:

                await self._run_with_timeout(
                    self.bot.unload_extension(
                        normalized
                    ),
                    timeout,
                    operation=(
                        f"unload:{normalized}"
                    ),
                )

                duration = (
                    monotonic()
                    - started
                )

                self.total_unloads += 1

                result = ExtensionResult(
                    extension=normalized,
                    success=True,
                    state=ExtensionState.UNLOADED,
                    operation="unload",
                    duration=duration,
                    message=(
                        "Extension unloaded successfully."
                    ),
                    was_loaded_before=True,
                )

                security_logger.info(
                    "Extension unloaded | %s",
                    normalized,
                )

                return self._record_result(
                    result
                )

            except Exception as exc:

                duration = (
                    monotonic()
                    - started
                )

                result = ExtensionResult(
                    extension=normalized,
                    success=False,
                    state=ExtensionState.FAILED,
                    operation="unload",
                    duration=duration,
                    error=str(exc)
                    or repr(exc),
                    error_type=type(
                        exc
                    ).__name__,
                    message=(
                        "Extension unload failed."
                    ),
                )

                security_logger.exception(
                    "Extension unload failed | "
                    "extension=%s error=%s",
                    normalized,
                    exc,
                )

                return self._record_result(
                    result
                )

    # ========================================================
    # UNLOAD ALL
    # ========================================================

    async def unload_all(
        self,
        *,
        extensions: Optional[
            Iterable[str]
        ] = None,
        stop_on_error: bool = False,
        timeout: Optional[float] = None,
    ) -> LoaderSummary:
        """
        Tüm yüklü extension'ları unload eder.

        Reverse order kullanılır.

        Böylece dependency ihtimali olan extension'larda
        daha güvenli shutdown davranışı elde edilir.
        """

        started = monotonic()

        if extensions is None:

            selected = list(
                self.bot.extensions
            )

        else:

            selected = [
                self._normalize_extension(
                    extension
                )
                for extension in extensions
            ]

        selected = list(
            reversed(
                selected
            )
        )

        summary = LoaderSummary(
            operation="unload_all"
        )

        summary.total = len(
            selected
        )

        for extension in selected:

            result = await self.unload_extension(
                extension,
                timeout=timeout,
            )

            summary.results.append(
                result
            )

            if result.success:

                summary.successful += 1

            elif result.state == (
                ExtensionState.SKIPPED
            ):

                summary.skipped += 1

            else:

                summary.failed += 1

                if stop_on_error:
                    break

        summary.duration = (
            monotonic()
            - started
        )

        security_logger.info(
            "Extension unload completed | "
            "total=%s successful=%s failed=%s",
            summary.total,
            summary.successful,
            summary.failed,
        )

        return summary

    # ========================================================
    # TIMEOUT
    # ========================================================

    async def _run_with_timeout(
        self,
        awaitable,
        timeout: Optional[float],
        *,
        operation: str,
    ):
        """
        Awaitable işlemini timeout ile çalıştırır.
        """

        import asyncio

        effective_timeout = (
            self.timeout
            if timeout is None
            else float(timeout)
        )

        if effective_timeout <= 0:
            raise ValueError(
                "Timeout must be greater than 0."
            )

        try:

            return await asyncio.wait_for(
                awaitable,
                timeout=effective_timeout,
            )

        except asyncio.TimeoutError:

            security_logger.error(
                "Extension operation timed out | "
                "operation=%s timeout=%.2fs",
                operation,
                effective_timeout,
            )

            raise TimeoutError(
                f"Extension operation timed out: "
                f"{operation}"
            )

    # ========================================================
    # STATUS
    # ========================================================

    def is_loaded(
        self,
        extension: str,
    ) -> bool:
        """
        Extension yüklü mü?
        """

        try:

            normalized = (
                self._normalize_extension(
                    extension
                )
            )

        except (
            TypeError,
            ValueError,
        ):
            return False

        return (
            normalized
            in self.bot.extensions
        )

    def get_state(
        self,
        extension: str,
    ) -> ExtensionState:
        """
        Extension state döndürür.
        """

        try:

            normalized = (
                self._normalize_extension(
                    extension
                )
            )

        except (
            TypeError,
            ValueError,
        ):

            return ExtensionState.UNKNOWN

        if normalized in self.bot.extensions:
            return ExtensionState.LOADED

        return self._states.get(
            normalized,
            ExtensionState.UNKNOWN,
        )

    def get_result(
        self,
        extension: str,
    ) -> Optional[ExtensionResult]:
        """
        Son operation sonucunu döndürür.
        """

        try:

            normalized = (
                self._normalize_extension(
                    extension
                )
            )

        except (
            TypeError,
            ValueError,
        ):

            return None

        return self._results.get(
            normalized
        )

    def get_loaded_extensions(
        self,
    ) -> list[str]:
        """
        Yüklü extension listesini döndürür.
        """

        return sorted(
            self.bot.extensions.keys(),
            key=str.lower,
        )

    def get_failed_extensions(
        self,
    ) -> list[str]:
        """
        Son durumuna göre başarısız extension'ları döndürür.
        """

        return sorted(
            extension
            for extension, state
            in self._states.items()
            if state == ExtensionState.FAILED
        )

    def get_status(
        self,
    ) -> dict:
        """
        Panel / diagnostics için loader status.
        """

        loaded = self.get_loaded_extensions()

        failed = self.get_failed_extensions()

        discovered = self.discover_extensions()

        return {
            "initialized": self.initialized,
            "closed": self.closed,
            "root_directory": str(
                self.root_directory
            ),
            "cog_directory": str(
                self.cog_path
            ),
            "timeout": self.timeout,
            "discovered_count": len(
                discovered
            ),
            "loaded_count": len(
                loaded
            ),
            "failed_count": len(
                failed
            ),
            "loaded": loaded,
            "failed": failed,
            "statistics": {
                "total_load_attempts": (
                    self.total_load_attempts
                ),
                "successful_loads": (
                    self.total_successful_loads
                ),
                "failed_loads": (
                    self.total_failed_loads
                ),
                "reloads": (
                    self.total_reloads
                ),
                "unloads": (
                    self.total_unloads
                ),
            },
        }

    # ========================================================
    # HEALTH CHECK
    # ========================================================

    def health_check(
        self,
        *,
        required: Optional[
            Iterable[str]
        ] = None,
    ) -> dict:
        """
        Loader'ın ve kritik extension'ların sağlık kontrolünü
        gerçekleştirir.

        main.py startup sonrasında kullanılabilir.
        """

        loaded = set(
            self.bot.extensions
        )

        required_set = {
            self._normalize_extension(
                extension
            )
            for extension in (
                required or []
            )
        }

        missing = sorted(
            required_set - loaded
        )

        return {
            "healthy": not missing,
            "loader_initialized": (
                self.initialized
            ),
            "loader_closed": (
                self.closed
            ),
            "loaded_extensions": sorted(
                loaded,
                key=str.lower,
            ),
            "missing_required": missing,
            "failed_extensions": (
                self.get_failed_extensions()
            ),
        }

    # ========================================================
    # ASSERT REQUIRED
    # ========================================================

    def assert_required_loaded(
        self,
        required: Iterable[str],
    ) -> None:
        """
        Kritik extension'ların yüklü olduğunu garanti eder.

        Eksik varsa RuntimeError fırlatır.

        main.py'de startup validation için kullanılabilir.
        """

        missing: list[str] = []

        for extension in required:

            normalized = (
                self._normalize_extension(
                    extension
                )
            )

            if (
                normalized
                not in self.bot.extensions
            ):

                missing.append(
                    normalized
                )

        if missing:

            raise RuntimeError(
                "Required extensions are not loaded: "
                + ", ".join(
                    missing
                )
            )

    # ========================================================
    # RESET STATE
    # ========================================================

    def clear_runtime_state(
        self,
    ) -> None:
        """
        Loader'ın kendi sonuç/cache state'ini temizler.

        Discord extension'larını unload etmez.
        """

        self._states.clear()

        self._results.clear()

        self._load_times.clear()

        security_logger.debug(
            "ExtensionLoader runtime state cleared."
        )

    # ========================================================
    # CLOSE
    # ========================================================

    async def close(
        self,
        *,
        unload_extensions: bool = True,
    ) -> LoaderSummary | None:
        """
        Loader shutdown işlemi.

        unload_extensions=True ise tüm extension'ları
        güvenli reverse order ile unload eder.
        """

        if self.closed:
            return None

        summary = None

        if unload_extensions:

            summary = await self.unload_all()

        self.closed = True

        self._extension_locks.clear()

        security_logger.info(
            "ExtensionLoader closed."
        )

        return summary


# ============================================================
# EXPORTS
# ============================================================

__all__ = [
    "ExtensionLoader",
    "ExtensionResult",
    "LoaderSummary",
    "ExtensionState",
]