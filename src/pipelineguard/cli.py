"""Command line interface for pipelineguard."""

from __future__ import annotations

import argparse
import os
import sys
from collections.abc import Sequence
from pathlib import Path

from . import __version__
from .models import ScanReport, Severity, utc_now
from .policy import (
    Policy,
    PolicyError,
    apply_allowances,
    compare_baseline,
    default_policy,
    evaluate,
    load_baseline,
    load_policy,
    write_baseline,
)
from .report import FORMATS, console, cyclonedx, markdown, sarif
from .report import json as json_report
from .scanners.base import ScanContext, build_scanners, run_scanners
from .scanners.deps import collect_components
from .scanners.secrets import load_rule_pack

EXIT_PASS = 0
EXIT_GATE_FAIL = 1
EXIT_TOOL_ERROR = 2


class CliError(Exception):
    """A usage or environment problem that maps to exit code 2."""


DEFAULT_FILE_FORMATS = ("json", "sarif", "markdown", "cyclonedx")
ARTIFACT_NAMES = {
    "json": "results.json",
    "sarif": "results.sarif",
    "markdown": "comment.md",
    "cyclonedx": "sbom.cdx.json",
}


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="pipelineguard",
        description=(
            "The CI/CD security gate: secret scanning, dependency audit, SBOM generation "
            "and CI configuration audit in one command."
        ),
        epilog="Exit codes: 0 gate passed, 1 gate failed, 2 tool or configuration error.",
    )
    parser.add_argument("--version", action="version", version=f"pipelineguard {__version__}")
    subparsers = parser.add_subparsers(dest="command", required=True)

    scan = subparsers.add_parser(
        "scan",
        help="Run every scanner and evaluate the policy",
        description="Run secrets, deps, licenses, sbom and config scanners, then evaluate the gate.",
    )
    scan.add_argument(
        "path", nargs="?", default=".", help="Repository or directory to scan (default: .)"
    )
    scan.add_argument(
        "--format",
        default="console",
        help="Comma separated formats: console,json,sarif,markdown,cyclonedx or all (default: console)",
    )
    scan.add_argument(
        "--output-dir", help="Write results.json, results.sarif, comment.md and sbom.cdx.json here"
    )
    scan.add_argument(
        "--policy", help="Policy file (default: <path>/pipelineguard.yaml when present)"
    )
    scan.add_argument(
        "--fail-on",
        help="Override the policy threshold: critical, high, medium, low, info or none",
    )
    scan.add_argument("--offline", action="store_true", help="Disable OSV network access")
    scan.add_argument("--advisory-db", help="Local OSV advisory JSON for offline auditing")
    scan.add_argument("--history", action="store_true", help="Also scan added lines in git history")
    scan.add_argument(
        "--staged", action="store_true", help="Scan staged content instead of the working tree"
    )
    scan.add_argument("--baseline", help="Baseline report; only new findings fail the gate")
    scan.add_argument(
        "--write-baseline", help="Write an actionable-findings baseline file and continue"
    )
    scan.add_argument("--no-color", action="store_true", help="Disable ANSI color")
    scan.add_argument("--quiet", action="store_true", help="Print only the gate verdict")
    scan.add_argument(
        "--stats", action="store_true", help="Show scanner statistics in console output"
    )
    scan.add_argument(
        "--timeout",
        type=float,
        default=300.0,
        help="Per-scanner timeout in seconds (default: 300)",
    )

    sbom = subparsers.add_parser(
        "sbom",
        help="Generate a CycloneDX 1.5 SBOM",
        description="Parse supported manifests and emit a CycloneDX 1.5 JSON document.",
    )
    sbom.add_argument("path", nargs="?", default=".", help="Repository or directory (default: .)")
    sbom.add_argument("--output", "-o", help="Output file (default: stdout)")

    secrets = subparsers.add_parser(
        "secrets",
        help="Run only the secret scanner",
        description="Scan the working tree, the git index or git history for secrets.",
    )
    secrets.add_argument(
        "path", nargs="?", default=".", help="Repository or directory (default: .)"
    )
    secrets.add_argument(
        "--history", action="store_true", help="Include added lines from git history"
    )
    secrets.add_argument("--staged", action="store_true", help="Scan staged content only")
    secrets.add_argument("--offline", action="store_true", help=argparse.SUPPRESS)
    secrets.add_argument(
        "--format", default="console", help="console, json or sarif (default: console)"
    )
    secrets.add_argument("--output-dir", help="Write results.json or results.sarif here")
    secrets.add_argument("--fail-on", default="high", help="Severity threshold (default: high)")
    secrets.add_argument("--no-color", action="store_true", help="Disable ANSI color")
    secrets.add_argument("--quiet", action="store_true", help="Print only the gate verdict")

    deps = subparsers.add_parser(
        "deps",
        help="Run only the dependency scanner",
        description="Inventory supported lockfiles and audit them against OSV.",
    )
    deps.add_argument("path", nargs="?", default=".", help="Repository or directory (default: .)")
    deps.add_argument("--offline", action="store_true", help="Disable OSV network access")
    deps.add_argument("--advisory-db", help="Local OSV advisory JSON for offline auditing")
    deps.add_argument("--format", default="console", help="console or json (default: console)")
    deps.add_argument("--output-dir", help="Write results.json here")
    deps.add_argument("--fail-on", default="high", help="Severity threshold (default: high)")
    deps.add_argument("--no-color", action="store_true", help="Disable ANSI color")
    deps.add_argument("--quiet", action="store_true", help="Print only the gate verdict")

    policy = subparsers.add_parser(
        "policy",
        help="Validate a policy file",
        description="Parse a pipelineguard.yaml policy without running any scanner.",
    )
    policy_subparsers = policy.add_subparsers(dest="policy_command", required=True)
    validate = policy_subparsers.add_parser("validate", help="Validate a policy file")
    validate.add_argument("file", help="Path to pipelineguard.yaml")

    rules = subparsers.add_parser(
        "rules",
        help="List detection rules and checks",
        description="Print every rule identifier with its severity and scanner.",
    )
    rules_subparsers = rules.add_subparsers(dest="rules_command", required=True)
    rules_list = rules_subparsers.add_parser("list", help="List rules")
    rules_list.add_argument(
        "--scanner", help="Filter by scanner: secrets, deps, licenses or config"
    )

    subparsers.add_parser("version", help="Print the version")
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    parser = _build_parser()
    args = parser.parse_args(argv)
    try:
        if args.command == "scan":
            return _command_scan(args)
        if args.command == "sbom":
            return _command_sbom(args)
        if args.command == "secrets":
            return _command_secrets(args)
        if args.command == "deps":
            return _command_deps(args)
        if args.command == "policy":
            return _command_policy_validate(args)
        if args.command == "rules":
            return _command_rules_list(args)
        if args.command == "version":
            print(f"pipelineguard {__version__}")
            return EXIT_PASS
    except PolicyError as exc:
        _error("policy error")
        for message in exc.errors:
            _error(f"  {message}")
        return EXIT_TOOL_ERROR
    except CliError as exc:
        _error(f"error: {exc}")
        return EXIT_TOOL_ERROR
    except BrokenPipeError:  # pragma: no cover - shell pipeline behaviour
        return EXIT_PASS
    except KeyboardInterrupt:  # pragma: no cover - interactive
        _error("interrupted")
        return 130
    except OSError as exc:
        _error(str(exc))
        return EXIT_TOOL_ERROR
    parser.print_help()
    return EXIT_TOOL_ERROR


# ---------------------------------------------------------------------------
# scan
# ---------------------------------------------------------------------------


def _command_scan(args: argparse.Namespace) -> int:
    root, display = _resolve_path(args.path)
    formats = _parse_formats(args.format)
    output_dir = Path(args.output_dir).expanduser() if args.output_dir else None
    _validate_output_request(formats, output_dir)

    policy = _resolve_policy(args.policy, root)
    _apply_policy_overrides(policy, args)
    if args.advisory_db:
        advisory = Path(args.advisory_db).expanduser()
        if not advisory.is_file():
            raise PolicyError(f"advisory database not found: {advisory}")
    else:
        advisory = None

    report = _run_scan(
        root=root,
        display=display,
        policy=policy,
        scanner_names=None,
        history=args.history,
        staged=args.staged,
        offline=args.offline or policy.offline,
        advisory_db=advisory,
        timeout=args.timeout,
    )

    baseline_diff = None
    if args.baseline:
        baseline_path = Path(args.baseline).expanduser()
        baseline_entries = load_baseline(baseline_path)
        apply_allowances(report, policy)
        baseline_diff = compare_baseline(report, baseline_entries)
    gate = evaluate(report, policy, baseline=baseline_diff)

    if args.write_baseline:
        path = write_baseline(report, Path(args.write_baseline).expanduser())
        print(f"Wrote baseline with {len(report.findings())} fingerprint(s) to {path}")

    _write_reports(report, formats, output_dir)
    args.resolved_formats = formats
    _emit_console(report, args)
    return gate.exit_code


# ---------------------------------------------------------------------------
# sbom
# ---------------------------------------------------------------------------


def _command_sbom(args: argparse.Namespace) -> int:
    root, display = _resolve_path(args.path)
    project = collect_components(root)
    document = cyclonedx.build_bom(project.components, target_name=root.name or display)
    payload = cyclonedx.to_json(document)
    if args.output:
        path = Path(args.output).expanduser()
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(payload, encoding="utf-8")
        print(f"Wrote CycloneDX 1.5 SBOM with {len(project.components)} component(s) to {path}")
    else:
        print(payload, end="")
    if project.warnings:
        for warning in project.warnings:
            _error(f"warning: {warning}")
    return EXIT_PASS


# ---------------------------------------------------------------------------
# focused scanners
# ---------------------------------------------------------------------------


def _command_secrets(args: argparse.Namespace) -> int:
    formats = _parse_formats(args.format, allowed=("console", "json", "sarif"))
    output_dir = Path(args.output_dir).expanduser() if args.output_dir else None
    _validate_output_request(formats, output_dir)
    root, display = _resolve_path(args.path)
    policy = default_policy()
    policy.fail_on = _parse_fail_on(args.fail_on)
    report = _run_scan(
        root=root,
        display=display,
        policy=policy,
        scanner_names=["secrets"],
        history=args.history,
        staged=args.staged,
        offline=True,
        advisory_db=None,
        timeout=300.0,
    )
    gate = evaluate(report, policy)
    _write_reports(report, formats, output_dir)
    args.resolved_formats = formats
    _emit_console(report, args)
    return gate.exit_code


def _command_deps(args: argparse.Namespace) -> int:
    formats = _parse_formats(args.format, allowed=("console", "json"))
    output_dir = Path(args.output_dir).expanduser() if args.output_dir else None
    _validate_output_request(formats, output_dir)
    root, display = _resolve_path(args.path)
    policy = default_policy()
    policy.fail_on = _parse_fail_on(args.fail_on)
    if args.advisory_db:
        advisory = Path(args.advisory_db).expanduser()
        if not advisory.is_file():
            raise CliError(f"advisory database not found: {advisory}")
    else:
        advisory = None
    report = _run_scan(
        root=root,
        display=display,
        policy=policy,
        scanner_names=["deps"],
        history=False,
        staged=False,
        offline=args.offline,
        advisory_db=advisory,
        timeout=300.0,
    )
    gate = evaluate(report, policy)
    _write_reports(report, formats, output_dir)
    args.resolved_formats = formats
    _emit_console(report, args)
    return gate.exit_code


# ---------------------------------------------------------------------------
# policy and rules
# ---------------------------------------------------------------------------


def _command_policy_validate(args: argparse.Namespace) -> int:
    path = Path(args.file).expanduser()
    policy = load_policy(path, required=True)
    summary = (
        f"policy OK: {path} (fail_on={policy.fail_on.value if policy.fail_on else 'none'}, "
        f"required_scanners={policy.required_scanners or 'none'}, "
        f"allowances={len(policy.allowances)}, exclude_paths={len(policy.exclude_paths)})"
    )
    print(summary)
    return EXIT_PASS


def _command_rules_list(args: argparse.Namespace) -> int:
    from .scanners.config import CONFIG_CHECKS, DEP_RULES
    from .scanners.licenses import LICENSE_RULES

    rows: list[tuple[str, str, str, str]] = []
    if args.scanner in (None, "secrets"):
        pack = load_rule_pack()
        rows.extend((rule.id, rule.severity.value, "secrets", rule.name) for rule in pack.rules)
    if args.scanner in (None, "deps"):
        rows.extend(
            (check.id, check.severity.value, "deps", check.name) for check in DEP_RULES.values()
        )
    if args.scanner in (None, "licenses"):
        rows.extend(
            (check.id, check.severity.value, "licenses", check.name)
            for check in LICENSE_RULES.values()
        )
    if args.scanner in (None, "config"):
        rows.extend(
            (check.id, check.severity.value, "config", check.name)
            for check in CONFIG_CHECKS.values()
        )
    if not rows:
        raise PolicyError(f"unknown scanner filter {args.scanner!r}")
    rows.sort(key=lambda row: (row[2], row[0]))
    widths = [len("ID"), len("SEVERITY"), len("SCANNER")]
    for rule_id, severity, scanner, _ in rows:
        widths[0] = max(widths[0], len(rule_id))
        widths[1] = max(widths[1], len(severity))
        widths[2] = max(widths[2], len(scanner))
    header = f"{'ID':<{widths[0]}}  {'SEVERITY':<{widths[1]}}  {'SCANNER':<{widths[2]}}  CHECK"
    print(header)
    print("-" * len(header))
    for rule_id, severity, scanner, name in rows:
        print(f"{rule_id:<{widths[0]}}  {severity:<{widths[1]}}  {scanner:<{widths[2]}}  {name}")
    print(f"\n{len(rows)} rule(s).")
    return EXIT_PASS


# ---------------------------------------------------------------------------
# Shared plumbing
# ---------------------------------------------------------------------------


def _run_scan(
    root: Path,
    display: str,
    policy: Policy,
    scanner_names: list[str] | None,
    history: bool,
    staged: bool,
    offline: bool,
    advisory_db: Path | None,
    timeout: float,
) -> ScanReport:
    cache_dir = root / ".pipelineguard-cache"
    context = ScanContext(
        root=root,
        exclude_paths=list(policy.exclude_paths),
        history=history,
        staged=staged,
        offline=offline,
        advisory_db=advisory_db,
        cache_dir=cache_dir,
        timeout=timeout,
        options={"licenses": policy.licenses.to_dict()},
    )
    scanners = build_scanners(scanner_names)
    report = ScanReport(
        target=display,
        tool_version=__version__,
        started_at=utc_now(),
        policy_file=policy.source,
        history_mode=history,
        staged_mode=staged,
    )
    report.results = run_scanners(scanners, context, timeout=timeout)
    report.finished_at = utc_now()
    return report


def _resolve_path(value: str) -> tuple[Path, str]:
    path = Path(value).expanduser()
    if not path.exists():
        raise CliError(f"path does not exist: {value}")
    if not path.is_dir():
        raise CliError(f"path is not a directory: {value}")
    return path.resolve(), value


def _resolve_policy(value: str | None, root: Path) -> Policy:
    if value:
        path = Path(value).expanduser()
        return load_policy(path, required=True)
    candidate = root / "pipelineguard.yaml"
    if candidate.is_file():
        return load_policy(candidate, required=True)
    return default_policy()


def _apply_policy_overrides(policy: Policy, args: argparse.Namespace) -> None:
    if getattr(args, "fail_on", None):
        policy.fail_on = _parse_fail_on(args.fail_on)


def _parse_fail_on(value: str) -> Severity | None:
    if value.strip().lower() in {"none", "off", "false"}:
        return None
    try:
        return Severity.parse(value)
    except ValueError as exc:
        raise PolicyError(str(exc)) from exc


def _parse_formats(value: str, allowed: Sequence[str] = FORMATS) -> list[str]:
    selected: list[str] = []
    for raw in value.split(","):
        item = raw.strip().lower()
        if not item:
            continue
        if item == "all":
            selected.extend(allowed)
            continue
        if item not in allowed:
            raise CliError(f"unknown format {item!r}; available: {', '.join(allowed)}")
        selected.append(item)
    if not selected:
        selected = ["console"]
    ordered: list[str] = []
    for format_name in allowed:
        if format_name in selected and format_name not in ordered:
            ordered.append(format_name)
    return ordered


def _validate_output_request(formats: list[str], output_dir: Path | None) -> None:
    file_formats = [item for item in formats if item != "console"]
    if output_dir is None and len(file_formats) > 1:
        raise CliError("--output-dir is required when writing more than one machine format")


def _write_reports(
    report: ScanReport,
    formats: list[str],
    output_dir: Path | None,
) -> list[str]:
    artifacts: list[str] = []
    file_formats = [item for item in formats if item in ARTIFACT_NAMES]
    if output_dir is not None and file_formats:
        output_dir.mkdir(parents=True, exist_ok=True)
        artifacts = [ARTIFACT_NAMES[format_name] for format_name in file_formats]
        for format_name in file_formats:
            target = output_dir / ARTIFACT_NAMES[format_name]
            _write_single(report, format_name, target, artifacts_for_markdown=artifacts)
    else:
        for format_name in file_formats:
            print(_render_single(report, format_name, artifacts=None), end="")
    return artifacts


def _write_single(
    report: ScanReport,
    format_name: str,
    target: Path,
    artifacts_for_markdown: list[str] | None,
) -> None:
    if format_name == "json":
        json_report.write(report, target)
    elif format_name == "sarif":
        sarif.write(report, target)
    elif format_name == "markdown":
        markdown.write(report, target, artifacts=artifacts_for_markdown)
    elif format_name == "cyclonedx":
        result = report.result("sbom")
        components = result.components if result else []
        document = cyclonedx.build_bom(
            components,
            target_name=Path(report.target).name or "repository",
        )
        target.write_text(cyclonedx.to_json(document), encoding="utf-8")
    else:  # pragma: no cover - guarded by _parse_formats
        raise PolicyError(f"cannot write format {format_name}")


def _render_single(
    report: ScanReport,
    format_name: str,
    artifacts: list[str] | None,
) -> str:
    if format_name == "json":
        return json_report.render(report)
    if format_name == "sarif":
        return sarif.render(report)
    if format_name == "markdown":
        return markdown.render(report, artifacts=artifacts)
    if format_name == "cyclonedx":
        result = report.result("sbom")
        components = result.components if result else []
        document = cyclonedx.build_bom(
            components,
            target_name=Path(report.target).name or "repository",
        )
        return cyclonedx.to_json(document)
    return console.render(report)


def _emit_console(report: ScanReport, args: argparse.Namespace) -> None:
    formats = getattr(args, "resolved_formats", None)
    if formats is None:
        try:
            formats = _parse_formats(args.format)
        except CliError:
            return
    if "console" not in formats:
        return
    color = _color_enabled(args.no_color)
    sys.stdout.write(
        console.render(
            report,
            color=color,
            quiet=getattr(args, "quiet", False),
            stats=getattr(args, "stats", False),
        )
    )


def _color_enabled(no_color: bool) -> bool:
    if no_color or os.environ.get("NO_COLOR"):
        return False
    return sys.stdout.isatty()


def _error(message: str) -> None:
    print(message, file=sys.stderr)
