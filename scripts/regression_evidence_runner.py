#!/usr/bin/env python3
"""Run and validate content-bound fail-first regression evidence."""

from __future__ import annotations

import argparse
import ast
import hashlib
import json
import os
import re
import shutil
import subprocess
import sys
import time
import xml.etree.ElementTree as ET
from pathlib import Path
from typing import Any, Callable

EVIDENCE_SCHEMA = "aims.regression_evidence.v1"
DEFAULT_TIMEOUT_SECONDS = 30
HARDENED_PYTEST_BOOTSTRAP = (
    "import os,sys; import pytest; sys.path.insert(0,os.getcwd()); "
    "sys.argv=['pytest',*sys.argv[1:]]; raise SystemExit(pytest.console_main())"
)


def _normalize(path: str | Path) -> str:
    return str(path).replace("\\", "/").removeprefix("./")


def _sha256_bytes(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def _sha256_text(value: str) -> str:
    return _sha256_bytes(value.encode("utf-8"))


def _canonical_digest(value: Any) -> str:
    payload = json.dumps(
        value,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
    )
    return _sha256_text(payload)


def _local_import_candidates(source_path: Path, tree: ast.AST) -> set[Path]:
    candidates: set[Path] = set()
    source_dir = source_path.parent
    for node in ast.walk(tree):
        modules: list[tuple[str, int]] = []
        if isinstance(node, ast.Import):
            modules.extend((alias.name, 0) for alias in node.names)
        elif isinstance(node, ast.ImportFrom):
            if node.module:
                modules.append((node.module, node.level))
            elif node.level:
                modules.extend((alias.name, node.level) for alias in node.names)

        for module, level in modules:
            base = source_dir
            for _ in range(max(level - 1, 0)):
                base = base.parent
            module_path = Path(*module.split("."))
            candidates.add(base / module_path.with_suffix(".py"))
            candidates.add(base / module_path / "__init__.py")
    return candidates


def _discover_harness_files(
    pre_root: Path,
    post_root: Path,
    requested_paths: list[str],
) -> list[str]:
    queue = [_normalize(path) for path in requested_paths]
    discovered: set[str] = set()

    while queue:
        relative_path = queue.pop(0)
        if relative_path in discovered:
            continue
        pre_path = pre_root / relative_path
        post_path = post_root / relative_path
        if not pre_path.is_file() or not post_path.is_file():
            raise FileNotFoundError(relative_path)
        discovered.add(relative_path)

        if pre_path.suffix.lower() != ".py":
            continue
        try:
            tree = ast.parse(pre_path.read_text(encoding="utf-8"))
        except (OSError, SyntaxError, UnicodeError):
            continue
        for candidate in _local_import_candidates(pre_path, tree):
            try:
                candidate_relative = candidate.relative_to(pre_root)
            except ValueError:
                continue
            post_candidate = post_root / candidate_relative
            if candidate.is_file() and post_candidate.is_file():
                queue.append(candidate_relative.as_posix())

    return sorted(discovered)


def _manifest(root: Path, relative_paths: list[str]) -> list[dict[str, str]]:
    return [
        {
            "path": relative_path,
            "sha256": _sha256_bytes((root / relative_path).read_bytes()),
        }
        for relative_path in sorted(relative_paths)
    ]


def _decode_timeout_output(value: str | bytes | None) -> str:
    if value is None:
        return ""
    if isinstance(value, bytes):
        return value.decode("utf-8", errors="replace")
    return value


def _default_executor(
    command: list[str],
    *,
    cwd: Path,
    timeout_seconds: int,
) -> subprocess.CompletedProcess[str]:
    env = os.environ.copy()
    env["PYTHONDONTWRITEBYTECODE"] = "1"
    env["PYTEST_DISABLE_PLUGIN_AUTOLOAD"] = "1"
    env.pop("PYTEST_ADDOPTS", None)
    effective_command = _hardened_pytest_command(command)
    if not effective_command:
        raise ValueError("command is not a trusted pytest invocation")
    return subprocess.run(
        effective_command,
        cwd=cwd,
        env=env,
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
        timeout=timeout_seconds,
        check=False,
    )


_SUMMARY_COUNT = re.compile(
    r"(?P<count>\d+)\s+"
    r"(?P<label>passed|failed|skipped|xfailed|xpassed|error|errors)\b",
    re.IGNORECASE,
)


def _pytest_outcome(
    exit_code: int,
    stdout: str,
    stderr: str,
) -> tuple[int, str, dict[str, int]]:
    output = f"{stdout}\n{stderr}"
    counts = {
        "passedTests": 0,
        "failedTests": 0,
        "skippedTests": 0,
        "xfailedTests": 0,
        "xpassedTests": 0,
        "errorTests": 0,
    }
    if exit_code == 124 or "timed out" in output.casefold():
        return 0, "TIMEOUT", counts
    collection_banner = re.search(
        r"(?m)^_{3,}\s+ERROR collecting\b",
        output,
    )
    if exit_code == 2 or collection_banner:
        return 0, "COLLECTION", counts

    summary_matches: list[re.Match[str]] = []
    for line in reversed(output.splitlines()):
        matches = list(_SUMMARY_COUNT.finditer(line))
        if matches:
            summary_matches = matches
            break
    label_keys = {
        "passed": "passedTests",
        "failed": "failedTests",
        "skipped": "skippedTests",
        "xfailed": "xfailedTests",
        "xpassed": "xpassedTests",
        "error": "errorTests",
        "errors": "errorTests",
    }
    for match in summary_matches:
        counts[label_keys[match.group("label").lower()]] += int(match.group("count"))
    collected = sum(counts.values())

    if exit_code == 0:
        return collected, "NONE", counts
    assertion_failure = "AssertionError" in output or re.search(
        r"(?m)^E\s+assert\b",
        output,
    )
    if exit_code == 1 and collected > 0 and assertion_failure:
        return collected, "ASSERTION", counts
    return collected, "TEST_OR_ENVIRONMENT", counts


def _pytest_observation(exit_code: int, stdout: str, stderr: str) -> tuple[int, str]:
    collected, failure_kind, _ = _pytest_outcome(exit_code, stdout, stderr)
    return collected, failure_kind


def _pytest_arguments(command: list[str]) -> list[str]:
    if len(command) < 3 or command[1:3] != ["-m", "pytest"]:
        return []
    if not _is_python_executable(command[0]):
        return []
    return command[3:]


def _is_python_executable(value: str) -> bool:
    executable = Path(value)
    resolved = executable.resolve() if executable.is_absolute() else None
    if resolved is None:
        discovered = shutil.which(value)
        resolved = Path(discovered).resolve() if discovered else None
    if resolved is not None and resolved == Path(sys.executable).resolve():
        return True
    executable_name = _normalize(value).rsplit("/", 1)[-1].lower()
    return re.fullmatch(r"python(?:\d+(?:\.\d+)?)?(?:\.exe)?", executable_name) is not None


def _is_hardened_pytest_effective_command(
    command: list[str],
    effective_command: list[str],
) -> bool:
    hardened_command = _hardened_pytest_command(command)
    return (
        bool(hardened_command)
        and len(effective_command) == len(hardened_command)
        and _is_python_executable(str(effective_command[0]))
        and effective_command[1:] == hardened_command[1:]
    )


def _portable_cwd(value: str | Path) -> str:
    raw = str(value)
    if re.match(r"^[A-Za-z]:[\\/]", raw):
        return _normalize(raw)
    return _normalize(str(Path(raw).resolve()))


def _hardened_pytest_command(command: list[str]) -> list[str]:
    pytest_arguments = _pytest_arguments(command)
    if not pytest_arguments:
        return []
    return [
        sys.executable,
        "-I",
        "-c",
        HARDENED_PYTEST_BOOTSTRAP,
        *pytest_arguments,
    ]


def _command_targets_harness(command: list[str], harness_path: str) -> bool:
    pytest_arguments = _pytest_arguments(command)
    normalized_harness = _normalize(harness_path)
    if not pytest_arguments or _normalize(pytest_arguments[0]) != normalized_harness:
        return False
    collection_exclusions = {"--ignore", "--ignore-glob", "--deselect"}
    return not any(
        token in collection_exclusions
        or any(token.startswith(f"{option}=") for option in collection_exclusions)
        for token in pytest_arguments[1:]
    )


def _junit_report_path(command: list[str], cwd: Path) -> Path | None:
    pytest_arguments = _pytest_arguments(command)
    values: list[str] = []
    index = 1
    while index < len(pytest_arguments):
        token = pytest_arguments[index]
        if token in {"--junitxml", "--junit-xml"}:
            if index + 1 >= len(pytest_arguments):
                return None
            values.append(pytest_arguments[index + 1])
            index += 2
            continue
        for option in ("--junitxml=", "--junit-xml="):
            if token.startswith(option):
                values.append(token[len(option) :])
                break
        index += 1

    if len(values) != 1 or not values[0]:
        return None
    relative_path = Path(values[0])
    if relative_path.is_absolute() or relative_path.suffix.casefold() != ".xml":
        return None
    root = cwd.resolve()
    report_path = (root / relative_path).resolve()
    try:
        report_path.relative_to(root)
    except ValueError:
        return None
    return report_path


def _terminal_report(stdout: str, stderr: str) -> dict[str, str]:
    transcript = f"{stdout}\0{stderr}"
    return {
        "format": "terminal-summary",
        "sha256": _sha256_text(transcript),
    }


def _junit_report(report_path: Path, cwd: Path) -> dict[str, str]:
    try:
        xml = report_path.read_text(encoding="utf-8")
    except (OSError, UnicodeError):
        xml = ""
    return {
        "format": "junit-xml",
        "path": report_path.relative_to(cwd.resolve()).as_posix(),
        "xml": xml,
        "sha256": _sha256_text(xml),
    }


def _xml_local_name(tag: str) -> str:
    return tag.rsplit("}", 1)[-1]


def _failure_class(message: str, detail: str) -> str:
    message_value = message.strip()
    if re.match(r"^\[?XPASS(?:\(strict\))?\]?", message_value, re.IGNORECASE) or re.match(
        r"^unexpected success\b",
        message_value,
        re.IGNORECASE,
    ):
        return "XPASS"
    if (
        re.match(r"^AssertionError\b", message_value)
        or re.match(r"^assert\b", message_value)
        or message_value == "Asser..."
    ):
        return "ASSERTION"
    if not message_value and (
        re.search(r"(?mi)^(?:E\s+)?\[?XPASS(?:\(strict\))?\]?", detail)
    ):
        return "XPASS"
    if not message_value and (
        re.search(r"(?m)^(?:E\s+)?AssertionError\b", detail)
        or re.search(r"(?m)^E\s+assert\b", detail)
    ):
        return "ASSERTION"
    return "NON_ASSERTION"


def _junit_observation(xml: str) -> dict[str, Any] | None:
    if not xml:
        return None
    try:
        root = ET.fromstring(xml)
    except ET.ParseError:
        return None

    cases: list[dict[str, str]] = []
    for testcase in (
        element for element in root.iter() if _xml_local_name(element.tag) == "testcase"
    ):
        classname = testcase.get("classname", "").strip()
        name = testcase.get("name", "").strip()
        node_id = f"{classname}::{name}" if classname else name
        outcome_nodes = [
            child
            for child in testcase
            if _xml_local_name(child.tag) in {"failure", "error", "skipped"}
        ]
        if not node_id or len(outcome_nodes) > 1:
            return None
        if not outcome_nodes:
            cases.append(
                {"nodeId": node_id, "outcome": "passed", "failureClass": "NONE"}
            )
            continue

        outcome_node = outcome_nodes[0]
        outcome = _xml_local_name(outcome_node.tag)
        if outcome == "failure":
            failure_class = _failure_class(
                outcome_node.get("message", ""),
                outcome_node.text or "",
            )
            cases.append(
                {
                    "nodeId": node_id,
                    "outcome": "failed",
                    "failureClass": failure_class,
                }
            )
        else:
            cases.append(
                {
                    "nodeId": node_id,
                    "outcome": outcome,
                    "failureClass": outcome.upper(),
                }
            )

    counts = {
        "total": len(cases),
        "passed": sum(case["outcome"] == "passed" for case in cases),
        "failed": sum(case["outcome"] == "failed" for case in cases),
        "errors": sum(case["outcome"] == "error" for case in cases),
        "skipped": sum(case["outcome"] == "skipped" for case in cases),
    }
    if not cases:
        return None

    for suite in (
        element for element in root.iter() if _xml_local_name(element.tag) == "testsuite"
    ):
        direct_cases = [
            child for child in suite if _xml_local_name(child.tag) == "testcase"
        ]
        if not direct_cases:
            continue
        expected = {
            "tests": len(direct_cases),
            "failures": sum(
                any(_xml_local_name(child.tag) == "failure" for child in case)
                for case in direct_cases
            ),
            "errors": sum(
                any(_xml_local_name(child.tag) == "error" for child in case)
                for case in direct_cases
            ),
            "skipped": sum(
                any(_xml_local_name(child.tag) == "skipped" for child in case)
                for case in direct_cases
            ),
        }
        for attribute, expected_value in expected.items():
            raw_value = suite.get(attribute)
            if raw_value is None or not raw_value.isdigit():
                return None
            if int(raw_value) != expected_value:
                return None
    return {"cases": cases, "counts": counts}


_FAILED_SUMMARY = re.compile(r"^FAILED\s+.+?\s+-\s+(?P<reason>.+)$")


def _terminal_failure_classes(stdout: str, stderr: str) -> list[str]:
    classes: list[str] = []
    for line in f"{stdout}\n{stderr}".splitlines():
        match = _FAILED_SUMMARY.match(line.strip())
        if match:
            reason = match.group("reason")
            classes.append(_failure_class(reason, reason))
    return classes


def _phase_report_observation(phase: dict[str, Any]) -> dict[str, Any] | None:
    report = phase.get("pytestReport")
    stdout = phase.get("stdout")
    stderr = phase.get("stderr")
    command = phase.get("command")
    cwd_value = phase.get("cwd")
    if not isinstance(report, dict) or not isinstance(stdout, str) or not isinstance(stderr, str):
        return None
    if not isinstance(command, list) or not isinstance(cwd_value, str):
        return None

    report_format = report.get("format")
    if report_format == "junit-xml":
        xml = report.get("xml")
        if not isinstance(xml, str) or report.get("sha256") != _sha256_text(xml):
            return None
        report_path = _junit_report_path(command, Path(cwd_value))
        if report_path is None:
            return None
        if report.get("path") != report_path.relative_to(Path(cwd_value).resolve()).as_posix():
            return None
        observation = _junit_observation(xml)
        if observation is None:
            return None
        counts = observation["counts"]
        if (
            counts["total"] != phase.get("collectedTests")
            or counts["passed"] != phase.get("passedTests", 0) + phase.get("xpassedTests", 0)
            or counts["failed"] != phase.get("failedTests", 0)
            or counts["errors"] != phase.get("errorTests", 0)
            or counts["skipped"]
            != phase.get("skippedTests", 0) + phase.get("xfailedTests", 0)
        ):
            return None
        return observation

    if report_format == "terminal-summary":
        if report.get("sha256") != _sha256_text(f"{stdout}\0{stderr}"):
            return None
        failure_classes = _terminal_failure_classes(stdout, stderr)
        if len(failure_classes) != phase.get("failedTests", 0):
            return None
        return {"cases": [], "counts": {}, "failureClasses": failure_classes}
    return None


def _execute_phase(
    command: list[str],
    *,
    cwd: Path,
    timeout_seconds: int,
    ref: str,
    staged_digest: str,
    test_id: str,
    started_at_unix_ns: int,
    executor: Callable[..., subprocess.CompletedProcess[str]],
) -> dict[str, Any]:
    report_path = _junit_report_path(command, cwd)
    if report_path is not None:
        report_path.parent.mkdir(parents=True, exist_ok=True)
        report_path.unlink(missing_ok=True)
    try:
        result = executor(command, cwd=cwd, timeout_seconds=timeout_seconds)
        exit_code = int(result.returncode)
        stdout = result.stdout or ""
        stderr = result.stderr or ""
        effective_command = (
            list(result.args)
            if isinstance(result.args, (list, tuple))
            else [str(result.args)]
        )
    except subprocess.TimeoutExpired as exc:
        exit_code = 124
        stdout = _decode_timeout_output(exc.stdout)
        stderr = _decode_timeout_output(exc.stderr) + "\nexecution timed out"
        effective_command = list(command)

    collected_tests, failure_kind, outcome_counts = _pytest_outcome(
        exit_code,
        stdout,
        stderr,
    )
    pytest_report = (
        _junit_report(report_path, cwd)
        if report_path is not None
        else _terminal_report(stdout, stderr)
    )
    return {
        "command": list(command),
        "effectiveCommand": effective_command,
        "executionMode": (
            "hardened-pytest-bootstrap"
            if effective_command == _hardened_pytest_command(command)
            else "injected-direct"
        ),
        "cwd": str(cwd.resolve()),
        "timeoutSeconds": timeout_seconds,
        "ref": ref,
        "stagedDigest": staged_digest,
        "testId": test_id,
        "startedAtUnixNs": started_at_unix_ns,
        "exitCode": exit_code,
        "collectedTests": collected_tests,
        "failureKind": failure_kind,
        **outcome_counts,
        "stdout": stdout,
        "stderr": stderr,
        "stdoutSha256": _sha256_text(stdout),
        "stderrSha256": _sha256_text(stderr),
        "pytestReport": pytest_report,
    }


def run_evidence(
    pre_root: str | Path,
    post_root: str | Path,
    harness_path: str,
    command: list[str],
    *,
    dependency_paths: list[str] | None = None,
    pre_ref: str,
    post_ref: str,
    staged_digest: str,
    test_id: str,
    started_at_unix_ns: int | None = None,
    timeout_seconds: int = DEFAULT_TIMEOUT_SECONDS,
    executor: Callable[..., subprocess.CompletedProcess[str]] | None = None,
) -> dict[str, Any]:
    """Execute one immutable pytest harness against isolated pre/post roots."""
    pre = Path(pre_root).resolve()
    post = Path(post_root).resolve()
    if pre == post:
        raise ValueError("pre_root and post_root must be different isolated roots")
    normalized_harness = _normalize(harness_path)
    if not _command_targets_harness(command, normalized_harness):
        raise ValueError("command must execute the bound harness path")
    requested = list(dict.fromkeys([normalized_harness, *(dependency_paths or [])]))
    harness_files = _discover_harness_files(pre, post, requested)
    manifest = _manifest(pre, harness_files)
    started = started_at_unix_ns if started_at_unix_ns is not None else time.time_ns()
    execute = executor or _default_executor

    execution = {
        "command": list(command),
        "timeoutSeconds": timeout_seconds,
        "preCwd": str(pre),
        "postCwd": str(post),
        "preRef": pre_ref,
        "postRef": post_ref,
        "stagedDigest": staged_digest,
        "testId": test_id,
        "startedAtUnixNs": started,
    }
    pre_fix = _execute_phase(
        list(command),
        cwd=pre,
        timeout_seconds=timeout_seconds,
        ref=pre_ref,
        staged_digest=staged_digest,
        test_id=test_id,
        started_at_unix_ns=started,
        executor=execute,
    )
    post_fix = _execute_phase(
        list(command),
        cwd=post,
        timeout_seconds=timeout_seconds,
        ref=post_ref,
        staged_digest=staged_digest,
        test_id=test_id,
        started_at_unix_ns=started,
        executor=execute,
    )
    return {
        "schema": EVIDENCE_SCHEMA,
        "execution": execution,
        "harness": {
            "path": normalized_harness,
            "sha256": _sha256_bytes((pre / normalized_harness).read_bytes()),
            "files": manifest,
            "closureSha256": _canonical_digest(manifest),
        },
        "preFix": pre_fix,
        "postFix": post_fix,
    }


def _result(accepted: bool, code: str) -> dict[str, Any]:
    return {"accepted": accepted, "code": code}


def _phase_matches_observation(phase: dict[str, Any]) -> dict[str, Any] | None:
    stdout = phase.get("stdout")
    stderr = phase.get("stderr")
    exit_code = phase.get("exitCode")
    command = phase.get("command")
    effective_command = phase.get("effectiveCommand")
    execution_mode = phase.get("executionMode")
    if not isinstance(stdout, str) or not isinstance(stderr, str):
        return None
    if type(exit_code) is not int:
        return None
    if not isinstance(command, list) or not isinstance(effective_command, list):
        return None
    valid_execution = (
        execution_mode == "hardened-pytest-bootstrap"
        and _is_hardened_pytest_effective_command(command, effective_command)
    ) or (
        execution_mode == "injected-direct" and effective_command == command
    )
    if not valid_execution:
        return None
    if phase.get("stdoutSha256") != _sha256_text(stdout):
        return None
    if phase.get("stderrSha256") != _sha256_text(stderr):
        return None
    collected, failure_kind, outcome_counts = _pytest_outcome(exit_code, stdout, stderr)
    if not (
        phase.get("collectedTests") == collected
        and phase.get("failureKind") == failure_kind
        and all(phase.get(key) == value for key, value in outcome_counts.items())
    ):
        return None
    return _phase_report_observation(phase)


def validate_evidence(
    evidence: dict[str, Any],
    pre_root: str | Path,
    post_root: str | Path,
    *,
    expected_metadata: dict[str, Any],
    source_root: str | Path | None = None,
) -> dict[str, Any]:
    """Validate runner evidence with stable machine-readable rejection codes."""
    if not isinstance(evidence, dict) or evidence.get("schema") != EVIDENCE_SCHEMA:
        return _result(False, "SCHEMA_MISMATCH")
    execution = evidence.get("execution")
    harness = evidence.get("harness")
    pre_fix = evidence.get("preFix")
    post_fix = evidence.get("postFix")
    if not all(isinstance(item, dict) for item in (execution, harness, pre_fix, post_fix)):
        return _result(False, "EVIDENCE_STRUCTURE_INVALID")

    pre_cwd = _portable_cwd(pre_root)
    post_cwd = _portable_cwd(post_root)
    pre = Path(source_root).resolve() if source_root is not None else Path(pre_root).resolve()
    post = Path(source_root).resolve() if source_root is not None else Path(post_root).resolve()
    command = execution.get("command")
    if not isinstance(command, list) or command != pre_fix.get("command") or command != post_fix.get("command"):
        return _result(False, "COMMAND_MISMATCH")
    bound_harness_path = _normalize(harness.get("path", ""))
    if not _command_targets_harness(command, bound_harness_path):
        return _result(False, "COMMAND_MISMATCH")
    if _normalize(str(execution.get("preCwd"))) != pre_cwd or _normalize(str(execution.get("postCwd"))) != post_cwd:
        return _result(False, "CWD_MISMATCH")
    if _normalize(str(pre_fix.get("cwd"))) != pre_cwd or _normalize(str(post_fix.get("cwd"))) != post_cwd:
        return _result(False, "CWD_MISMATCH")
    timeout = execution.get("timeoutSeconds")
    if type(timeout) is not int or timeout <= 0:
        return _result(False, "TIMEOUT_MISMATCH")
    if pre_fix.get("timeoutSeconds") != timeout or post_fix.get("timeoutSeconds") != timeout:
        return _result(False, "TIMEOUT_MISMATCH")

    metadata_checks = (
        ("preRef", "REF_MISMATCH"),
        ("postRef", "REF_MISMATCH"),
        ("stagedDigest", "STAGED_DIGEST_MISMATCH"),
        ("testId", "TEST_ID_MISMATCH"),
        ("startedAtUnixNs", "TIMESTAMP_MISMATCH"),
    )
    for key, code in metadata_checks:
        if execution.get(key) != expected_metadata.get(key):
            return _result(False, code)
    if pre_fix.get("ref") != execution.get("preRef") or post_fix.get("ref") != execution.get("postRef"):
        return _result(False, "REF_MISMATCH")
    for phase in (pre_fix, post_fix):
        if phase.get("stagedDigest") != execution.get("stagedDigest"):
            return _result(False, "STAGED_DIGEST_MISMATCH")
        if phase.get("testId") != execution.get("testId"):
            return _result(False, "TEST_ID_MISMATCH")
        if phase.get("startedAtUnixNs") != execution.get("startedAtUnixNs"):
            return _result(False, "TIMESTAMP_MISMATCH")

    harness_path = bound_harness_path
    pre_harness = pre / harness_path
    post_harness = post / harness_path
    if not harness_path or not pre_harness.is_file() or not post_harness.is_file():
        return _result(False, "HARNESS_NOT_FOUND")
    actual_harness_digest = _sha256_bytes(pre_harness.read_bytes())
    if harness.get("sha256") != actual_harness_digest:
        return _result(False, "HARNESS_DIGEST_MISMATCH")
    if post_harness.read_bytes() != pre_harness.read_bytes():
        return _result(False, "HARNESS_DEPENDENCY_MISMATCH")

    manifest = harness.get("files")
    if not isinstance(manifest, list) or not manifest:
        return _result(False, "HARNESS_DEPENDENCY_MISMATCH")
    normalized_manifest: list[dict[str, str]] = []
    for item in manifest:
        if not isinstance(item, dict):
            return _result(False, "HARNESS_DEPENDENCY_MISMATCH")
        relative_path = _normalize(item.get("path", ""))
        pre_path = pre / relative_path
        post_path = post / relative_path
        if not relative_path or not pre_path.is_file() or not post_path.is_file():
            return _result(False, "HARNESS_DEPENDENCY_MISMATCH")
        digest = _sha256_bytes(pre_path.read_bytes())
        if item.get("sha256") != digest or _sha256_bytes(post_path.read_bytes()) != digest:
            return _result(False, "HARNESS_DEPENDENCY_MISMATCH")
        normalized_manifest.append({"path": relative_path, "sha256": digest})
    if manifest != sorted(normalized_manifest, key=lambda item: item["path"]):
        return _result(False, "HARNESS_DEPENDENCY_MISMATCH")
    if harness.get("closureSha256") != _canonical_digest(normalized_manifest):
        return _result(False, "HARNESS_DEPENDENCY_MISMATCH")

    pre_observation = _phase_matches_observation(pre_fix)
    if pre_observation is None:
        return _result(False, "PRE_FIX_RESULT_MISMATCH")
    post_observation = _phase_matches_observation(post_fix)
    if post_observation is None:
        return _result(False, "POST_FIX_RESULT_MISMATCH")
    pre_failure_classes = pre_observation.get("failureClasses")
    if not isinstance(pre_failure_classes, list):
        pre_failure_classes = [
            case.get("failureClass")
            for case in pre_observation.get("cases", [])
            if case.get("outcome") == "failed"
        ]
    if (
        pre_fix.get("exitCode") != 1
        or pre_fix.get("failureKind") != "ASSERTION"
        or type(pre_fix.get("collectedTests")) is not int
        or pre_fix.get("collectedTests") <= 0
        or type(pre_fix.get("failedTests")) is not int
        or pre_fix.get("failedTests") <= 0
        or len(pre_failure_classes) != pre_fix.get("failedTests")
        or any(failure_class != "ASSERTION" for failure_class in pre_failure_classes)
        or any(
            pre_fix.get(key) != 0
            for key in (
                "skippedTests",
                "xfailedTests",
                "xpassedTests",
                "errorTests",
            )
        )
    ):
        return _result(False, "PRE_FIX_INVALID_FAILURE_CLASS")
    if (
        post_fix.get("exitCode") != 0
        or post_fix.get("failureKind") != "NONE"
        or post_fix.get("collectedTests") != pre_fix.get("collectedTests")
        or post_fix.get("passedTests") != post_fix.get("collectedTests")
        or any(
            post_fix.get(key) != 0
            for key in (
                "failedTests",
                "skippedTests",
                "xfailedTests",
                "xpassedTests",
                "errorTests",
            )
        )
    ):
        return _result(False, "POST_FIX_RESULT_MISMATCH")
    return _result(True, "VALID")


def parse_args(argv: list[str]) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--pre-root", required=True)
    parser.add_argument("--post-root", required=True)
    parser.add_argument("--harness", required=True)
    parser.add_argument("--dependency", action="append", default=[])
    parser.add_argument("--pre-ref", required=True)
    parser.add_argument("--post-ref", required=True)
    parser.add_argument("--staged-digest", required=True)
    parser.add_argument("--test-id", required=True)
    parser.add_argument("--timeout-seconds", type=int, default=DEFAULT_TIMEOUT_SECONDS)
    parser.add_argument("--output", required=True)
    parser.add_argument("command", nargs=argparse.REMAINDER)
    return parser.parse_args(argv)


def main(argv: list[str] | None = None) -> int:
    args = parse_args(argv or sys.argv[1:])
    command = list(args.command)
    if command and command[0] == "--":
        command = command[1:]
    if not command:
        print("regression evidence command is required", file=sys.stderr)
        return 2
    if _junit_report_path(command, Path(args.pre_root).resolve()) is None:
        print(
            "regression evidence command must include one relative --junitxml path",
            file=sys.stderr,
        )
        return 2
    evidence = run_evidence(
        args.pre_root,
        args.post_root,
        args.harness,
        command,
        dependency_paths=args.dependency,
        pre_ref=args.pre_ref,
        post_ref=args.post_ref,
        staged_digest=args.staged_digest,
        test_id=args.test_id,
        timeout_seconds=args.timeout_seconds,
    )
    output = Path(args.output)
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(
        json.dumps(evidence, ensure_ascii=False, indent=2) + "\n",
        encoding="utf-8",
    )
    validation = validate_evidence(
        evidence,
        args.pre_root,
        args.post_root,
        expected_metadata={
            "preRef": args.pre_ref,
            "postRef": args.post_ref,
            "stagedDigest": args.staged_digest,
            "testId": args.test_id,
            "startedAtUnixNs": evidence["execution"]["startedAtUnixNs"],
        },
    )
    print(json.dumps(validation, ensure_ascii=False))
    return 0 if validation["accepted"] else 2


if __name__ == "__main__":
    raise SystemExit(main())
