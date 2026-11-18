"""Scanner protocol, registry and bounded parallel execution."""

from __future__ import annotations

import logging
import time
from concurrent.futures import Future, ThreadPoolExecutor
from dataclasses import dataclass, field
from pathlib import Path
from typing import Protocol, runtime_checkable

from ..models import ScannerResult, utc_now

LOGGER = logging.getLogger("pipelineguard.scanners")

DEFAULT_SCANNER_TIMEOUT = 300.0


@dataclass
class ScanContext:
    """Everything a scanner needs, resolved once by the CLI."""

    root: Path
    exclude_paths: list[str] = field(default_factory=list)
    history: bool = False
    staged: bool = False
    offline: bool = False
    advisory_db: Path | None = None
    cache_dir: Path | None = None
    timeout: float = DEFAULT_SCANNER_TIMEOUT
    max_file_bytes: int = 2 * 1024 * 1024
    entropy_threshold: float = 3.5
    options: dict[str, object] = field(default_factory=dict)

    @property
    def resolved_cache_dir(self) -> Path:
        return self.cache_dir or (self.root / ".pipelineguard-cache")


@runtime_checkable
class Scanner(Protocol):
    """Contract implemented by every scanner."""

    name: str
    description: str

    def scan(self, context: ScanContext) -> ScannerResult: ...


_REGISTRY: dict[str, type] = {}
_BUILTIN_ORDER = ("secrets", "deps", "licenses", "sbom", "config")


def register(scanner_cls: type) -> type:
    """Class decorator that registers a scanner under its ``name`` attribute."""
    name = getattr(scanner_cls, "name", "")
    if not name:
        raise ValueError(f"{scanner_cls!r} is missing a scanner name")
    _REGISTRY[name] = scanner_cls
    return scanner_cls


def registry() -> dict[str, type]:
    _ensure_builtins()
    return dict(_REGISTRY)


def get_scanner(name: str) -> Scanner:
    _ensure_builtins()
    key = name.strip().lower()
    if key not in _REGISTRY:
        raise KeyError(f"unknown scanner {name!r}; available: {', '.join(sorted(_REGISTRY))}")
    return _REGISTRY[key]()


def available_scanners() -> list[str]:
    _ensure_builtins()
    ordered = [name for name in _BUILTIN_ORDER if name in _REGISTRY]
    ordered.extend(sorted(set(_REGISTRY) - set(ordered)))
    return ordered


def build_scanners(names: list[str] | None = None) -> list[Scanner]:
    if names is None:
        names = available_scanners()
    return [get_scanner(name) for name in names]


def _ensure_builtins() -> None:
    if all(name in _REGISTRY for name in _BUILTIN_ORDER):
        return
    # Imports are intentionally local: scanners import this module for the
    # protocol and the registry, so a top-level import would be circular.
    from . import config as _config  # noqa: F401
    from . import deps as _deps  # noqa: F401
    from . import licenses as _licenses  # noqa: F401
    from . import sbom as _sbom  # noqa: F401
    from . import secrets as _secrets  # noqa: F401


def run_scanners(
    scanners: list[Scanner],
    context: ScanContext,
    timeout: float | None = None,
    parallel: bool = True,
) -> list[ScannerResult]:
    """Run scanners in parallel with a per-scanner wall clock limit.

    A timed out scanner is reported as an errored :class:`ScannerResult` so the
    gate can surface it explicitly instead of hanging the build.
    """
    if not scanners:
        return []
    limit = timeout if timeout is not None else context.timeout
    if not parallel or len(scanners) == 1:
        return [_run_one(scanner, context, limit) for scanner in scanners]

    results: dict[str, ScannerResult] = {}
    pool = ThreadPoolExecutor(max_workers=min(len(scanners), 8), thread_name_prefix="pg-scan")
    futures: list[tuple[str, Future[ScannerResult]]] = [
        (scanner.name, pool.submit(_run_one, scanner, context, limit)) for scanner in scanners
    ]
    try:
        for name, future in futures:
            try:
                results[name] = future.result(timeout=limit)
            except TimeoutError:
                LOGGER.warning("scanner %s exceeded %.1fs", name, limit)
                results[name] = ScannerResult(
                    scanner=name,
                    started_at=utc_now(),
                    elapsed=limit,
                    error=f"scanner timed out after {limit:.0f}s",
                )
    finally:
        pool.shutdown(wait=False, cancel_futures=True)
    return [results[scanner.name] for scanner in scanners if scanner.name in results]


def _run_one(scanner: Scanner, context: ScanContext, limit: float) -> ScannerResult:
    started = utc_now()
    begun = time.monotonic()
    try:
        result = scanner.scan(context)
        result.elapsed = time.monotonic() - begun
        if result.started_at is None:  # pragma: no cover - defensive
            result.started_at = started
        return result
    except Exception as exc:
        LOGGER.debug("scanner %s failed", scanner.name, exc_info=True)
        return ScannerResult(
            scanner=scanner.name,
            started_at=started,
            elapsed=time.monotonic() - begun,
            error=f"{type(exc).__name__}: {exc}",
        )
