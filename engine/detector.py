"""LibHunter / PHunter 外部工具调用：统一日志、工作目录与 subprocess 行为。"""
from __future__ import annotations

import os
import re
import shlex
import shutil
import time
from pathlib import Path
from typing import Dict, List, Optional

from config import (
    DEFAULT_LIBHUNTER_TIMEOUT,
    DEFAULT_PHUNTER_THREADS,
    DEFAULT_PHUNTER_TIMEOUT,
    ANDROID_JAR,
    JAVA_BIN,
    LIBHUNTER_DIR,
    LIBHUNTER_HEARTBEAT_TIMEOUT,    
    LIBHUNTER_PROCESSES,    
    LIBHUNTER_SCRIPT,
    LIBHUNTER_TPLS_DEX,
    LIBHUNTER_TPLS_JAR,
    LIB_SIMILAR_THRESHOLD,
    LOG_DIR,
    PHUNTER_DIR,
    PHUNTER_JAR,
    PICKLE_CACHE_DIR,
    PHUNTER_HEARTBEAT_TIMEOUT,  
    PYTHON_BIN,
    RAW_DIR,
    SUBPROCESS_HEARTBEAT_TIMEOUT,
    build_pythonpath,
)
from utils.normalizer import normalize_libhunter_lib
from utils.runner import CommandResult, run_command

_DETECTION_PATTERN = re.compile(
    r"lib:\s*(?P<lib>[^\r\n]+)\s+similarity:\s*(?P<similarity>[0-9.]+)",
    re.IGNORECASE | re.MULTILINE,
)
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
_PHUNTER_RESOURCE_LIMIT_PATTERN = re.compile(
    r"(pthread_create\s+failed|unable\s+to\s+create\s+native\s+thread|EAGAIN|process/resource\s+limits\s+reached)",
    re.IGNORECASE,
)   


def _write_text(path: Path, content: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(content or "", encoding="utf-8")


def run_logged_command(
    cmd: List[str],
    *,
    cwd: Optional[Path],
    timeout: Optional[int],
    env: Optional[Dict[str, str]] = None,
    stream_output: bool = True,
    heartbeat_timeout: int = SUBPROCESS_HEARTBEAT_TIMEOUT,
    memory_limit_bytes: int = 0,
    stdout_log: Path,
    stderr_log: Path,
) -> CommandResult:
    """执行子进程并将完整输出写入指定日志文件。"""
    result = run_command(
        cmd,
        cwd=cwd,
        timeout=timeout,
        env=env,
        stream_output=stream_output,
        raise_on_error=False,
        heartbeat_timeout=heartbeat_timeout,
        memory_limit_bytes=memory_limit_bytes,
    )
    _write_text(stdout_log, result.stdout)
    _write_text(stderr_log, result.stderr)
    return result


def _parse_detection_text(text: str) -> list[dict]:
    detections: list[dict] = []
    for match in _DETECTION_PATTERN.finditer(text or ""):
        raw_lib = match.group("lib").strip()
        similarity = float(match.group("similarity"))
        normalized = normalize_libhunter_lib(raw_lib)
        detections.append({
            "raw_lib": raw_lib,
            "library_name": normalized["library_name"],
            "detected_version": normalized["version"],
            "similarity": similarity,
        })
    detections.sort(key=lambda item: item["similarity"], reverse=True)
    return detections


def _is_cache_valid(pkl_path: Path, source_dex: Path) -> bool:
    if not pkl_path.exists():
        return False
    try:
        return pkl_path.stat().st_mtime >= source_dex.stat().st_mtime
    # 如果 pkl 的修改时间 >= 源 dex 的修改时间，就认为缓存没过期。
    except OSError:
        return False

# 统计并清理缓存状态
def warm_up_cache(tpl_dex_dir: Path, cache_dir: Path) -> dict:
    cache_dir.mkdir(parents=True, exist_ok=True)
    dex_files = list(tpl_dex_dir.glob("*.dex"))
    total = len(dex_files)
    cached = missing = stale = 0

    for dex in dex_files:
        pkl = cache_dir / dex.with_suffix(".pkl").name
        if not pkl.exists():
            missing += 1
        elif not _is_cache_valid(pkl, dex):
            stale += 1
            pkl.unlink(missing_ok=True)
        else:
            cached += 1
    # 这个字典后面会被 run_libhunter() 使用
    return {"total": total, "cached": cached, "missing": missing, "stale": stale}

# 清空目录内容但保留目录本身(为LibHunter的预热工作做准备)
def ensure_clean_dir(path: Path) -> None:
    path.mkdir(parents=True, exist_ok=True)
    for child in path.iterdir():
        if child.is_dir():
            shutil.rmtree(child, ignore_errors=True)
        else:
            child.unlink(missing_ok=True)


def prewarm_tpl_pickles(*, env: Dict[str, str], timeout: int) -> CommandResult:
    run_root = RAW_DIR / "libhunter" / "_prewarm"
    apk_input_dir = run_root / "apks"
    output_dir = run_root / "outputs"
    ensure_clean_dir(apk_input_dir)
    output_dir.mkdir(parents=True, exist_ok=True)

    cmd = [
        str(PYTHON_BIN),
        str(LIBHUNTER_SCRIPT),
        "detect_all",
        "-o", str(output_dir),
        "-af", str(apk_input_dir),  # 空目录：仅触发 TPL 指纹提取与 pickle 构建
        "-p", str(LIBHUNTER_PROCESSES), # 并行进程数
        "-ld", str(LIBHUNTER_TPLS_DEX),
    ]
    if LIBHUNTER_TPLS_JAR.exists():
        cmd.extend(["-lf", str(LIBHUNTER_TPLS_JAR)])
    return run_logged_command(
        cmd,
        cwd=LIBHUNTER_DIR,
        timeout=timeout,
        env=env,
        stream_output=True,
        # 预热阶段可能长时间无输出，不应按心跳静默误判卡死
        heartbeat_timeout=0,
        stdout_log=LOG_DIR / "libhunter_prewarm.stdout.log",
        stderr_log=LOG_DIR / "libhunter_prewarm.stderr.log",
    )


def run_libhunter(apk_path: str | Path) -> dict:
    apk_path = Path(apk_path).expanduser().resolve()

    checks = {
        "APK 文件": apk_path,
        "LibHunter 入口脚本": LIBHUNTER_SCRIPT,
        "TPL dex 特征库 (-ld)": LIBHUNTER_TPLS_DEX,
    }
    not_found = [f"  {label}: {path}" for label, path in checks.items() if not path.exists()]
    if not_found:
        raise FileNotFoundError("以下路径不存在，请检查目录结构：\n" + "\n".join(not_found))
    if not LIBHUNTER_TPLS_JAR.exists():
        print(
            f"[libhunter] 提示: 未找到 tpl_jar 目录 ({LIBHUNTER_TPLS_JAR})，"
            "将仅使用 tpl_dex 执行检测。"
        )

    env = os.environ.copy()
    env["PYTHONPATH"] = build_pythonpath()
    env["LH_PICKLE_DIR"] = str(PICKLE_CACHE_DIR)
    env["LH_LIB_THRESHOLD"] = str(LIB_SIMILAR_THRESHOLD)
    env.setdefault("LH_EXEC_MODE", "mp")
    # 限制每个进程内的 BLAS/OMP 线程，避免多进程场景下线程数爆炸。
    # 把各种常见数值计算库线程数都限制成 1，比如 NumPy/OpenBLAS/MKL
    env.setdefault("OMP_NUM_THREADS", "1")
    env.setdefault("OPENBLAS_NUM_THREADS", "1")
    env.setdefault("MKL_NUM_THREADS", "1")
    env.setdefault("NUMEXPR_NUM_THREADS", "1")
    env.setdefault("VECLIB_MAXIMUM_THREADS", "1")
    env.setdefault("BLIS_NUM_THREADS", "1")

    cache_stats = warm_up_cache(LIBHUNTER_TPLS_DEX, PICKLE_CACHE_DIR)
    if cache_stats["total"] == 0:
        print("[libhunter] 警告: tpl_dex 目录为空，无法检测任何库。")
    else:
        miss = cache_stats["missing"] + cache_stats["stale"]
        if miss > 0:
            print(
                f"[libhunter] 缓存预热: {cache_stats['cached']}/{cache_stats['total']} 命中, "
                f"{miss} 个 pkl 需要构建，开始执行预热 ..."
            )
            try:
                prewarm_timeout = max(DEFAULT_LIBHUNTER_TIMEOUT, 2 * 60 * 60)
                prewarm_start = time.time()
                prewarm_result = prewarm_tpl_pickles(env=env, timeout=prewarm_timeout)
                elapsed = time.time() - prewarm_start
                cache_stats = warm_up_cache(LIBHUNTER_TPLS_DEX, PICKLE_CACHE_DIR)
                remain = cache_stats["missing"] + cache_stats["stale"]
                if prewarm_result.returncode == 0 and remain == 0:
                    print(
                        f"[libhunter] 预热完成: 全部 {cache_stats['total']} 个 pkl 就绪 "
                        f"(耗时 {elapsed:.1f}s)。"
                    )
                elif prewarm_result.returncode == 0:
                    print(
                        f"[libhunter] 预热部分完成: 剩余 {remain} 个 pkl 未就绪，"
                        "将在本轮检测中按需构建。"
                    )
                else:
                    print(
                        f"[libhunter] 预热子任务退出码={prewarm_result.returncode}，"
                        "将继续执行检测并按需构建缓存。"
                    )
            except Exception as exc:
                print(
                    f"[libhunter] 预热失败: {exc}，将继续执行检测并按需构建缓存。"
                )
        else:
            print(
                f"[libhunter] 缓存预热: 全部 {cache_stats['total']} 个 pkl 命中，"
                f"跳过反编译阶段。"
            )

    run_root = RAW_DIR / "libhunter" / apk_path.stem
    apk_input_dir = run_root / "apks"
    output_dir = run_root / "outputs"
    apk_input_dir.mkdir(parents=True, exist_ok=True)
    output_dir.mkdir(parents=True, exist_ok=True)

    shutil.copy2(apk_path, apk_input_dir / apk_path.name)

    cmd = [
        str(PYTHON_BIN),
        str(LIBHUNTER_SCRIPT),
        "detect_all",
        "-o", str(output_dir),
        "-af", str(apk_input_dir),
        "-p", str(LIBHUNTER_PROCESSES),
        "-ld", str(LIBHUNTER_TPLS_DEX),
    ]
    if LIBHUNTER_TPLS_JAR.exists():
        cmd.extend(["-lf", str(LIBHUNTER_TPLS_JAR)])

    result = run_logged_command(
        cmd,
        cwd=LIBHUNTER_DIR,
        timeout=DEFAULT_LIBHUNTER_TIMEOUT,
        env=env,
        stream_output=True,
        heartbeat_timeout=LIBHUNTER_HEARTBEAT_TIMEOUT,
        stdout_log=LOG_DIR / f"libhunter_{apk_path.stem}.stdout.log",
        stderr_log=LOG_DIR / f"libhunter_{apk_path.stem}.stderr.log",
    )

    # 如果命令“卡死”
    if result.hung:
        return {
            "status": "hung",
            "cmd": result.cmd,
            "returncode": result.returncode,
            "raw_stdout": result.stdout,
            "raw_stderr": result.stderr,
            "result_file": None,
            "detections": [],
        }

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
        "status": status,
        "cmd": result.cmd,
        "returncode": result.returncode,
        "raw_stdout": result.stdout,
        "raw_stderr": result.stderr,
        "result_file": str(result_file) if result_file.exists() else None,
        "detections": detections,
    }


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


def _is_phunter_resource_limit(text: str) -> bool:
    return bool(_PHUNTER_RESOURCE_LIMIT_PATTERN.search(text or ""))


def build_phunter_cmd(
    *,
    apk_path: Path,
    pre_patch_jar: Path,
    post_patch_jar: Path,
    patch_diff: Path,
    thread_num: int,
    java_opts: list[str] | None = None,
) -> list[str]:
    cmd = [str(JAVA_BIN)]
    if java_opts:
        cmd.extend(java_opts)
    cmd.extend([
        "-jar",
        str(PHUNTER_JAR),
        "--preTPL", str(pre_patch_jar),
        "--postTPL", str(post_patch_jar),
        "--threadNum", str(thread_num),
        "--androidJar", str(ANDROID_JAR),
        "--patchFiles", str(patch_diff),
        "--targetAPK", str(apk_path),
    ])
    return cmd


def run_phunter(apk_path: str | Path, cve_meta: dict) -> dict:
    apk_path = Path(apk_path).expanduser().resolve()
    pre_patch_jar = Path(cve_meta["pre_patch_jar"]).expanduser().resolve()
    post_patch_jar = Path(cve_meta["post_patch_jar"]).expanduser().resolve()
    patch_diff = Path(cve_meta["patch_diff"]).expanduser().resolve()

    missing_paths = [
        str(path)
        for path in (apk_path, PHUNTER_JAR, ANDROID_JAR,
                      pre_patch_jar, post_patch_jar, patch_diff)
        if not path.exists()
    ]
    if missing_paths:
        raise FileNotFoundError("Missing PHunter input files: " + ", ".join(missing_paths))

    cve_id = cve_meta["cve_id"]
    thread_num = int(cve_meta.get("thread_num", DEFAULT_PHUNTER_THREADS))
    java_opts = shlex.split(os.getenv("PHUNTER_JAVA_OPTS", ""))

    cmd = build_phunter_cmd(
        apk_path=apk_path,
        pre_patch_jar=pre_patch_jar,
        post_patch_jar=post_patch_jar,
        patch_diff=patch_diff,
        thread_num=thread_num,
        java_opts=java_opts,
    )

    result = run_logged_command(
        cmd,
        cwd=PHUNTER_DIR,
        timeout=DEFAULT_PHUNTER_TIMEOUT,
        env=None,
        stream_output=True,
        heartbeat_timeout=PHUNTER_HEARTBEAT_TIMEOUT,
        stdout_log=LOG_DIR / f"phunter_{apk_path.stem}_{cve_id}.stdout.log",
        stderr_log=LOG_DIR / f"phunter_{apk_path.stem}_{cve_id}.stderr.log",
    )

    # 如果 PHunter 卡死
    if result.hung:
        return {
            "status": "hung",
            "hung": True,
            "cve_id": cve_id,
            "cmd": result.cmd,
            "returncode": result.returncode,
            "patch_status": "HUNG",
            "patch_related_method_count": None,
            "pre_similarity": None,
            "post_similarity": None,
            "raw_stdout": result.stdout,
            "raw_stderr": result.stderr,
        }

    combined = "\n".join(p for p in (result.stdout, result.stderr) if p)
    retried = False
    # 资源不足时触发重试
    if result.returncode != 0 and _is_phunter_resource_limit(combined):
        retried = True
        # 降低线程数
        retry_thread_num = max(1, min(thread_num, 2))
        # 读取重试专用 JVM 参数
        retry_java_opts_raw = os.getenv(
            "PHUNTER_JAVA_RETRY_OPTS",  
            "-Xss256k -XX:ActiveProcessorCount=2", # -Xss256k：减小线程栈大小
            # -XX:ActiveProcessorCount=2：告诉 JVM 活跃处理器数按 2 处理
        )
        retry_java_opts = shlex.split(retry_java_opts_raw)
        retry_cmd = build_phunter_cmd(
            apk_path=apk_path,
            pre_patch_jar=pre_patch_jar,
            post_patch_jar=post_patch_jar,
            patch_diff=patch_diff,
            thread_num=retry_thread_num,
            java_opts=retry_java_opts,
        )
        retry_result = run_logged_command(
            retry_cmd,
            cwd=PHUNTER_DIR,
            timeout=DEFAULT_PHUNTER_TIMEOUT,
            env=None,
            stream_output=True,
            heartbeat_timeout=PHUNTER_HEARTBEAT_TIMEOUT,
            stdout_log=LOG_DIR / f"phunter_{apk_path.stem}_{cve_id}.retry.stdout.log",
            stderr_log=LOG_DIR / f"phunter_{apk_path.stem}_{cve_id}.retry.stderr.log",
        )
        # 如果重试后又卡死了
        if retry_result.hung:
            return {
                "status": "hung",
                "hung": True,
                "cve_id": cve_id,
                "cmd": retry_result.cmd,
                "returncode": retry_result.returncode,
                "patch_status": "HUNG",
                "patch_related_method_count": None,
                "pre_similarity": None,
                "post_similarity": None,
                "raw_stdout": retry_result.stdout,
                "raw_stderr": retry_result.stderr,
                "retried": True,
            }
        result = retry_result
        combined = "\n".join(p for p in (result.stdout, result.stderr) if p)

    patch_status = _parse_patch_status(combined)
    patch_related_method_count = _extract_int(_PATCH_METHODS_PATTERN, combined)
    pre_similarity = _extract_float(_PRE_SIMILARITY_PATTERN, combined)
    post_similarity = _extract_float(_POST_SIMILARITY_PATTERN, combined)

    if result.returncode == 0:
        status = "success"
    elif _is_phunter_resource_limit(combined):
        status = "resource_limited"
        patch_status = "RESOURCE_LIMIT"
    else:
        status = "failed"

    return {
        "status": status,
        "hung": False,
        "cve_id": cve_id,
        "cmd": result.cmd,
        "returncode": result.returncode,
        "patch_status": patch_status,
        "patch_related_method_count": patch_related_method_count,
        "pre_similarity": pre_similarity,
        "post_similarity": post_similarity,
        "raw_stdout": result.stdout,
        "raw_stderr": result.stderr,
        "retried": retried,
    }
