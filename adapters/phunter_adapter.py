from __future__ import annotations

import re
from pathlib import Path

from config import (
    ANDROID_JAR,
    DEFAULT_PHUNTER_THREADS,
    DEFAULT_PHUNTER_TIMEOUT,
    JAVA_BIN,
    LOG_DIR,
    PHUNTER_DIR,
    PHUNTER_JAR,
    SUBPROCESS_HEARTBEAT_TIMEOUT,
)
from utils.runner import CommandExecutionError, run_command

_PATCH_METHODS_PATTERN = re.compile(
    r"patch-related\s+method\s+count\s*=\s*(\d+)",
    re.IGNORECASE,
)
_PRE_SIMILARITY_PATTERN = re.compile(
    r"pre\s+similarity\s*=\s*([0-9.]+)",
    re.IGNORECASE,
)
_POST_SIMILARITY_PATTERN = re.compile(
    r"post\s+similarity\s*=\s*([0-9.]+)",
    re.IGNORECASE,
)


def _write_text(path: Path, content: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(content or "", encoding="utf-8")


def _extract_float(pattern: re.Pattern[str], text: str) -> float | None:
    match = pattern.search(text)
    return float(match.group(1)) if match else None


def _extract_int(pattern: re.Pattern[str], text: str) -> int | None:
    match = pattern.search(text)
    return int(match.group(1)) if match else None


def _parse_patch_status(text: str) -> str:
    upper_text = text.upper()
    if "THE PATCH IS NOT PRESENT" in upper_text:
        return "PATCH_NOT_PRESENT"
    if "THE PATCH IS PRESENT" in upper_text:
        return "PATCH_PRESENT"
    return "UNKNOWN"


def run_phunter(apk_path: str | Path, cve_meta: dict) -> dict:
    apk_path        = Path(apk_path).expanduser().resolve()
    pre_patch_jar   = Path(cve_meta["pre_patch_jar"]).expanduser().resolve()
    post_patch_jar  = Path(cve_meta["post_patch_jar"]).expanduser().resolve()
    patch_diff      = Path(cve_meta["patch_diff"]).expanduser().resolve()

    missing_paths = [
        str(path)
        for path in (apk_path, PHUNTER_JAR, ANDROID_JAR,
                     pre_patch_jar, post_patch_jar, patch_diff)
        if not path.exists()
    ]
    if missing_paths:
        raise FileNotFoundError(
            "Missing PHunter input files: " + ", ".join(missing_paths)
        )

    cve_id = cve_meta["cve_id"]

    cmd = [
        str(JAVA_BIN),
        "-jar",
        str(PHUNTER_JAR),
        "--preTPL",   str(pre_patch_jar),
        "--postTPL",  str(post_patch_jar),
        "--threadNum", str(cve_meta.get("thread_num", DEFAULT_PHUNTER_THREADS)),
        "--androidJar", str(ANDROID_JAR),
        "--patchFiles", str(patch_diff),
        "--targetAPK",  str(apk_path),
    ]

    result = run_command(
        cmd,
        cwd=PHUNTER_DIR,
        timeout=DEFAULT_PHUNTER_TIMEOUT,
        stream_output=True,
        heartbeat_timeout=SUBPROCESS_HEARTBEAT_TIMEOUT,   # 【新增】
    )

    stdout_log = LOG_DIR / f"phunter_{apk_path.stem}_{cve_id}.stdout.log"
    stderr_log = LOG_DIR / f"phunter_{apk_path.stem}_{cve_id}.stderr.log"
    _write_text(stdout_log, result.stdout)
    _write_text(stderr_log, result.stderr)

    # 【新增】心跳超时直接返回，让上层决定如何处理
    if result.hung:
        return {
            "status":                    "hung",
            "hung":                      True,
            "cve_id":                    cve_id,
            "cmd":                       result.cmd,
            "returncode":                result.returncode,
            "patch_status":              "HUNG",
            "patch_related_method_count": None,
            "pre_similarity":            None,
            "post_similarity":           None,
            "raw_stdout":                result.stdout,
            "raw_stderr":                result.stderr,
        }

    combined    = "\n".join(p for p in (result.stdout, result.stderr) if p)
    patch_status               = _parse_patch_status(combined)
    patch_related_method_count = _extract_int(_PATCH_METHODS_PATTERN, combined)
    pre_similarity             = _extract_float(_PRE_SIMILARITY_PATTERN, combined)
    post_similarity            = _extract_float(_POST_SIMILARITY_PATTERN, combined)

    status = "success" if result.returncode == 0 else "failed"

    return {
        "status":                    status,
        "hung":                      False,
        "cve_id":                    cve_id,
        "cmd":                       result.cmd,
        "returncode":                result.returncode,
        "patch_status":              patch_status,
        "patch_related_method_count": patch_related_method_count,
        "pre_similarity":            pre_similarity,
        "post_similarity":           post_similarity,
        "raw_stdout":                result.stdout,
        "raw_stderr":                result.stderr,
    }