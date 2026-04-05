"""Adapter for PHunter CVE patch-presence detection tool."""
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
)
from utils.runner import CommandExecutionError, run_command

# ── 正则修复说明 ──────────────────────────────────────────────────────────────
# PHunter 日志大小写不固定，例如：
#   "patch-related method count = 42"
#   "Patch-Related Method Count = 42"
#   "pre similarity = 0.87"
#   "Pre Similarity = 0.87"
# 统一用 re.IGNORECASE 兼容所有变体，并在 \s* 后加 = 以容忍空格差异。
# ─────────────────────────────────────────────────────────────────────────────

_PATCH_METHODS_PATTERN = re.compile(
    r"patch[\s\-]related\s+method\s+count\s*=\s*(\d+)",
    re.IGNORECASE,
)
_PRE_SIMILARITY_PATTERN = re.compile(
    r"pre\s+similarity\s*=\s*([0-9]+(?:\.[0-9]+)?)",
    re.IGNORECASE,
)
_POST_SIMILARITY_PATTERN = re.compile(
    r"post\s+similarity\s*=\s*([0-9]+(?:\.[0-9]+)?)",
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
    """从日志文本中提取补丁是否存在的结论。

    PHunter 可能输出以下几种格式（大小写不定）：
      - "the patch IS NOT PRESENT"
      - "the patch IS PRESENT"
      - "the patch is not present"
      - "the patch is present"
    用 upper() 统一后匹配，注意先检查 NOT PRESENT（更具体的条件）。
    """
    upper_text = text.upper()
    if "THE PATCH IS NOT PRESENT" in upper_text:
        return "PATCH_NOT_PRESENT"
    if "THE PATCH IS PRESENT" in upper_text:
        return "PATCH_PRESENT"
    return "UNKNOWN"


def run_phunter(apk_path: str | Path, cve_meta: dict) -> dict:
    apk_path = Path(apk_path).expanduser().resolve()
    pre_patch_jar = Path(cve_meta["pre_patch_jar"]).expanduser().resolve()
    post_patch_jar = Path(cve_meta["post_patch_jar"]).expanduser().resolve()
    patch_diff = Path(cve_meta["patch_diff"]).expanduser().resolve()

    # ── 前置校验 ──────────────────────────────────────────────────────────
    missing_paths = [
        str(path)
        for path in (apk_path, PHUNTER_JAR, ANDROID_JAR, pre_patch_jar, post_patch_jar, patch_diff)
        if not path.exists()
    ]
    if missing_paths:
        raise FileNotFoundError(
            "Missing PHunter input files: " + ", ".join(missing_paths)
        )

    cve_id = cve_meta["cve_id"]
    thread_num = str(cve_meta.get("thread_num", DEFAULT_PHUNTER_THREADS))

    cmd = [
        str(JAVA_BIN),
        "-jar",
        str(PHUNTER_JAR),
        "--preTPL",    str(pre_patch_jar),
        "--postTPL",   str(post_patch_jar),
        "--threadNum", thread_num,
        "--androidJar",str(ANDROID_JAR),
        "--patchFiles",str(patch_diff),
        "--targetAPK", str(apk_path),
    ]

    # ── 运行 PHunter ──────────────────────────────────────────────────────
    # PHunter 以非零退出码表示"补丁不存在"等正常业务结论，故 raise_on_error=False。
    try:
        result = run_command(
            cmd,
            cwd=PHUNTER_DIR,
            timeout=DEFAULT_PHUNTER_TIMEOUT,
            stream_output=True,
            raise_on_error=False,
        )
    except CommandExecutionError:
        raise

    # ── 写日志 ───────────────────────────────────────────────────────────
    stdout_log = LOG_DIR / f"phunter_{apk_path.stem}_{cve_id}.stdout.log"
    stderr_log = LOG_DIR / f"phunter_{apk_path.stem}_{cve_id}.stderr.log"
    _write_text(stdout_log, result.stdout)
    _write_text(stderr_log, result.stderr)

    # ── 解析输出 ──────────────────────────────────────────────────────────
    # PHunter 有时把关键结论写到 stderr，合并后再解析
    combined = "\n".join(part for part in (result.stdout, result.stderr) if part)

    patch_status              = _parse_patch_status(combined)
    patch_related_method_count = _extract_int(_PATCH_METHODS_PATTERN, combined)
    pre_similarity            = _extract_float(_PRE_SIMILARITY_PATTERN, combined)
    post_similarity           = _extract_float(_POST_SIMILARITY_PATTERN, combined)

    # 真正的失败：进程崩溃且完全没有有用输出
    if result.returncode != 0 and patch_status == "UNKNOWN":
        status = "failed"
    else:
        status = "success"

    return {
        "status":                    status,
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