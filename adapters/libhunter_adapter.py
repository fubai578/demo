"""Adapter for LibHunter third-party library detection tool."""
from __future__ import annotations

import os
import re
import shutil
from pathlib import Path

from config import (
    DEFAULT_LIBHUNTER_TIMEOUT,
    LIBHUNTER_DIR,
    LIBHUNTER_SCRIPT,
    LIBHUNTER_TPLS_DEX,
    LIBHUNTER_TPLS_JAR,
    LOG_DIR,
    PYTHON_BIN,
    RAW_DIR,
    build_pythonpath,
)
from utils.normalizer import normalize_libhunter_lib
from utils.runner import CommandExecutionError, run_command

# 匹配 LibHunter 输出中的 lib/similarity 行对
# 例如：
#   lib: okhttp-3.12.0.dex
#   similarity: 0.923
_DETECTION_PATTERN = re.compile(
    r"lib:\s*(?P<lib>[^\r\n]+)\s+similarity:\s*(?P<similarity>[0-9.]+)",
    re.IGNORECASE | re.MULTILINE,
)


def _write_text(path: Path, content: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(content or "", encoding="utf-8")


def _parse_detection_text(text: str) -> list[dict]:
    detections: list[dict] = []
    for match in _DETECTION_PATTERN.finditer(text or ""):
        raw_lib = match.group("lib").strip()
        similarity = float(match.group("similarity"))
        normalized = normalize_libhunter_lib(raw_lib)
        detections.append(
            {
                "raw_lib": raw_lib,
                "library_name": normalized["library_name"],
                "detected_version": normalized["version"],
                "similarity": similarity,
            }
        )
    detections.sort(key=lambda item: item["similarity"], reverse=True)
    return detections


def run_libhunter(apk_path: str | Path) -> dict:
    apk_path = Path(apk_path).expanduser().resolve()

    # ── 前置校验：一次性列出所有缺失路径 ─────────────────────────────────
    checks = {
        "APK 文件": apk_path,
        "LibHunter 入口脚本": LIBHUNTER_SCRIPT,
        "TPL dex 特征库 (-ld)": LIBHUNTER_TPLS_DEX,
        "TPL jar 源文件 (-lf)": LIBHUNTER_TPLS_JAR,
    }
    not_found = [
        f"  {label}: {path}" for label, path in checks.items() if not path.exists()
    ]
    if not_found:
        raise FileNotFoundError(
            "以下路径不存在，请检查目录结构：\n" + "\n".join(not_found)
        )

    # ── 为每个 APK 建立独立工作区 ─────────────────────────────────────────
    run_root = RAW_DIR / "libhunter" / apk_path.stem
    apk_input_dir = run_root / "apks"
    output_dir = run_root / "outputs"
    apk_input_dir.mkdir(parents=True, exist_ok=True)
    output_dir.mkdir(parents=True, exist_ok=True)

    shutil.copy2(apk_path, apk_input_dir / apk_path.name)

    # ── 构造命令 ──────────────────────────────────────────────────────────
    # 关键修复：将 -lf / -ld 统一转成绝对路径字符串后再传入。
    # LibHunter.py 入口会对相对路径做二次拼接，我们直接传绝对路径可绕过该逻辑。
    cmd = [
        str(PYTHON_BIN),
        str(LIBHUNTER_SCRIPT),
        "detect_all",
        "-o",  str(output_dir.resolve()),
        "-af", str(apk_input_dir.resolve()),
        "-lf", str(LIBHUNTER_TPLS_JAR.resolve()),   # 绝对路径，避免二次拼接
        "-ld", str(LIBHUNTER_TPLS_DEX.resolve()),   # 绝对路径，避免二次拼接
    ]

    env = os.environ.copy()
    env["PYTHONPATH"] = build_pythonpath()

    # ── 运行 LibHunter ────────────────────────────────────────────────────
    # raise_on_error=False：LibHunter 在"未检测到任何库"时也会以非零码退出，
    # 这是正常业务情况，不应当作错误抛出；我们在后面根据 detections 是否为空来判断。
    try:
        result = run_command(
            cmd,
            cwd=LIBHUNTER_DIR,
            timeout=DEFAULT_LIBHUNTER_TIMEOUT,
            env=env,
            stream_output=True,
            raise_on_error=False,          # 允许非零退出，后续自行判断
        )
    except CommandExecutionError:
        # 超时或找不到可执行文件，属于真正的基础设施错误，直接上抛
        raise

    # ── 写日志 ───────────────────────────────────────────────────────────
    _write_text(LOG_DIR / f"libhunter_{apk_path.stem}.stdout.log", result.stdout)
    _write_text(LOG_DIR / f"libhunter_{apk_path.stem}.stderr.log", result.stderr)

    # ── 查找结果文件 ──────────────────────────────────────────────────────
    # LibHunter 可能把结果写成 demo.apk.txt 或 demo.txt，两种都尝试
    result_file = next(
        (
            f
            for f in (
                output_dir / f"{apk_path.name}.txt",   # demo.apk.txt
                output_dir / f"{apk_path.stem}.txt",   # demo.txt
            )
            if f.exists()
        ),
        None,
    )

    if result_file and result_file.exists():
        parsed_source = result_file.read_text(encoding="utf-8", errors="replace")
    else:
        # 结果文件不存在时，尝试从 stdout/stderr 中解析
        parsed_source = "\n".join(p for p in (result.stdout, result.stderr) if p)

    detections = _parse_detection_text(parsed_source)

    # ── 判断状态 ──────────────────────────────────────────────────────────
    if result.returncode != 0 and not detections:
        # 非零退出且没有解析到任何检测结果，才视为真正的失败
        status = "failed"
    elif not detections:
        status = "no_detections"
    else:
        status = "success"

    return {
        "status": status,
        "cmd": result.cmd,
        "returncode": result.returncode,
        "raw_stdout": result.stdout,
        "raw_stderr": result.stderr,
        "result_file": str(result_file) if result_file and result_file.exists() else None,
        "detections": detections,
    }