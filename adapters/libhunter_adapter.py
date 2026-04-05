from __future__ import annotations

import os
import re
import shutil
import time
from pathlib import Path

from config import (
    DEFAULT_LIBHUNTER_TIMEOUT,
    LIBHUNTER_DIR,
    LIBHUNTER_SCRIPT,
    LIBHUNTER_TPLS_DEX,
    LIBHUNTER_TPLS_JAR,
    LIB_SIMILAR_THRESHOLD,
    LOG_DIR,
    PICKLE_CACHE_DIR,
    PYTHON_BIN,
    RAW_DIR,
    SUBPROCESS_HEARTBEAT_TIMEOUT,
    build_pythonpath,
)
from utils.normalizer import normalize_libhunter_lib
from utils.runner import CommandExecutionError, run_command

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
        raw_lib    = match.group("lib").strip()
        similarity = float(match.group("similarity"))
        normalized = normalize_libhunter_lib(raw_lib)
        detections.append({
            "raw_lib":          raw_lib,
            "library_name":     normalized["library_name"],
            "detected_version": normalized["version"],
            "similarity":       similarity,
        })
    detections.sort(key=lambda item: item["similarity"], reverse=True)
    return detections


# ── 【新增】pickle 缓存预热与校验 ────────────────────────────

def _is_cache_valid(pkl_path: Path, source_dex: Path) -> bool:
    """
    校验 pickle 缓存是否仍然有效：
    - 缓存文件必须存在
    - 缓存文件的修改时间必须晚于对应 .dex 文件的修改时间
    """
    if not pkl_path.exists():
        return False
    try:
        pkl_mtime = pkl_path.stat().st_mtime
        dex_mtime = source_dex.stat().st_mtime
        return pkl_mtime >= dex_mtime
    except OSError:
        return False


def warm_up_cache(tpl_dex_dir: Path, cache_dir: Path) -> dict:
    """
    扫描 tpl_dex_dir 下的所有 .dex 文件，报告缓存命中 / 缺失情况。
    LibHunter 子进程会在运行时自动构建缺失的 pkl，这里只做预检。

    Returns
    -------
    dict with keys: total, cached, missing, stale
    """
    cache_dir.mkdir(parents=True, exist_ok=True)
    dex_files = list(tpl_dex_dir.glob("*.dex"))
    total   = len(dex_files)
    cached  = 0
    missing = 0
    stale   = 0

    for dex in dex_files:
        pkl = cache_dir / dex.with_suffix(".pkl").name
        if not pkl.exists():
            missing += 1
        elif not _is_cache_valid(pkl, dex):
            stale += 1
            pkl.unlink(missing_ok=True)   # 删除过期缓存，让子进程重建
        else:
            cached += 1

    return {"total": total, "cached": cached, "missing": missing, "stale": stale}


# ─────────────────────────────────────────────────────────────


def run_libhunter(apk_path: str | Path) -> dict:
    apk_path = Path(apk_path).expanduser().resolve()

    # 前置校验
    checks = {
        "APK 文件":              apk_path,
        "LibHunter 入口脚本":    LIBHUNTER_SCRIPT,
        "TPL dex 特征库 (-ld)":  LIBHUNTER_TPLS_DEX,
        "TPL jar 源文件 (-lf)":  LIBHUNTER_TPLS_JAR,
    }
    not_found = [
        f"  {label}: {path}"
        for label, path in checks.items()
        if not path.exists()
    ]
    if not_found:
        raise FileNotFoundError(
            "以下路径不存在，请检查目录结构：\n" + "\n".join(not_found)
        )

    # ── 【新增】缓存预热提示 ──────────────────────────────────
    cache_stats = warm_up_cache(LIBHUNTER_TPLS_DEX, PICKLE_CACHE_DIR)
    if cache_stats["total"] == 0:
        print("[libhunter] 警告: tpl_dex 目录为空，无法检测任何库。")
    else:
        miss = cache_stats["missing"] + cache_stats["stale"]
        if miss > 0:
            print(
                f"[libhunter] 缓存预热: {cache_stats['cached']}/{cache_stats['total']} 命中, "
                f"{miss} 个 pkl 将在首次运行时构建（耗时较长属正常现象）。"
            )
        else:
            print(
                f"[libhunter] 缓存预热: 全部 {cache_stats['total']} 个 pkl 命中，"
                f"跳过反编译阶段。"
            )
    # ─────────────────────────────────────────────────────────

    # 为每个 APK 建立独立工作区
    run_root      = RAW_DIR / "libhunter" / apk_path.stem
    apk_input_dir = run_root / "apks"
    output_dir    = run_root / "outputs"
    apk_input_dir.mkdir(parents=True, exist_ok=True)
    output_dir.mkdir(parents=True, exist_ok=True)

    shutil.copy2(apk_path, apk_input_dir / apk_path.name)

    cmd = [
        str(PYTHON_BIN),
        str(LIBHUNTER_SCRIPT),
        "detect_all",
        "-o",  str(output_dir),
        "-af", str(apk_input_dir),
        "-lf", str(LIBHUNTER_TPLS_JAR),
        "-ld", str(LIBHUNTER_TPLS_DEX),
    ]

    # ── 【新增】通过环境变量将配置注入子进程 ─────────────────
    env = os.environ.copy()
    env["PYTHONPATH"]      = build_pythonpath()
    env["LH_PICKLE_DIR"]   = str(PICKLE_CACHE_DIR)   # 绝对缓存路径
    env["LH_LIB_THRESHOLD"] = str(LIB_SIMILAR_THRESHOLD)  # 相似度阈值
    # ─────────────────────────────────────────────────────────

    try:
        result = run_command(
            cmd,
            cwd=LIBHUNTER_DIR,
            timeout=DEFAULT_LIBHUNTER_TIMEOUT,
            env=env,
            stream_output=True,
            heartbeat_timeout=SUBPROCESS_HEARTBEAT_TIMEOUT,   # 【新增】
        )
    except CommandExecutionError:
        raise

    _write_text(LOG_DIR / f"libhunter_{apk_path.stem}.stdout.log", result.stdout)
    _write_text(LOG_DIR / f"libhunter_{apk_path.stem}.stderr.log", result.stderr)

    # 【新增】心跳超时处理
    if result.hung:
        return {
            "status":      "hung",
            "cmd":         result.cmd,
            "returncode":  result.returncode,
            "raw_stdout":  result.stdout,
            "raw_stderr":  result.stderr,
            "result_file": None,
            "detections":  [],
        }

    # 尝试读取结果文件
    result_file = next(
        (f for f in (
            output_dir / f"{apk_path.name}.txt",
            output_dir / f"{apk_path.stem}.txt",
        ) if f.exists()),
        output_dir / f"{apk_path.name}.txt",
    )

    if result_file.exists():
        parsed_source = result_file.read_text(encoding="utf-8", errors="replace")
    else:
        parsed_source = "\n".join(p for p in (result.stdout, result.stderr) if p)

    detections = _parse_detection_text(parsed_source)

    if result.returncode != 0:
        status = "failed"
    elif not detections:
        status = "no_detections"
    else:
        status = "success"

    return {
        "status":      status,
        "cmd":         result.cmd,
        "returncode":  result.returncode,
        "raw_stdout":  result.stdout,
        "raw_stderr":  result.stderr,
        "result_file": str(result_file) if result_file.exists() else None,
        "detections":  detections,
    }