from __future__ import annotations

import logging
import threading
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path
from typing import Any, Dict, Optional

from adapters.apk_utils import get_apk_basic_info
from adapters.libhunter_adapter import run_libhunter
from adapters.phunter_adapter import run_phunter
from config import MAX_PHUNTER_CONCURRENT
from core.knowledge_base import KnowledgeBase
from core.models import ApkContext, TPLibrary, Vulnerability

logger = logging.getLogger(__name__)


class AndroidVulnScanner:

    def __init__(self, apk_path: str | Path):
        self.apk_path = Path(apk_path).expanduser().resolve()
        if not self.apk_path.exists():
            raise FileNotFoundError(f"找不到目标 APK: {self.apk_path}")

        raw_info = get_apk_basic_info(self.apk_path)
        self.context = ApkContext(
            path=raw_info["path"],
            name=raw_info["name"],
            sha256=raw_info["sha256"],
            file_size=raw_info["file_size"],
        )
        self.apk_info = raw_info
        self.kb = KnowledgeBase()

        # 【新增】用于限制同时运行的 JVM 数量，防止 OOM
        self._phunter_semaphore = threading.Semaphore(MAX_PHUNTER_CONCURRENT)

    def scan(self) -> Dict[str, Any]:
        print(
            f"[*] 初始化分析任务: {self.context.name} "
            f"(SHA256: {self.context.sha256[:8]}...)"
        )
        self._detect_libraries()
        self._verify_patches()
        return self._generate_report()

    # ── 阶段一：库检测（不变）────────────────────────────────

    def _detect_libraries(self) -> None:
        print("[*] 阶段一: 识别第三方库组件 (基于 LibHunter) ...")
        lib_result = run_libhunter(self.context.path)

        # 【新增】处理心跳超时状态
        if lib_result["status"] == "hung":
            print(
                "[-] LibHunter 心跳超时（长时间无输出），已强制终止。"
                "本次检测跳过库识别阶段，不影响后续流程。"
            )
            logger.warning("LibHunter hung for APK: %s", self.context.name)
            return

        if lib_result["status"] not in ("success", "no_detections"):
            print(f"[-] 组件识别异常，状态: {lib_result['status']}")
            return

        for det in lib_result.get("detections", []):
            lib = TPLibrary(
                raw_name=det.get("raw_lib", ""),
                normalized_name=det.get("library_name", ""),
                version=det.get("detected_version", ""),
                similarity=det.get("similarity", 0.0),
            )
            self.kb.match_cves(lib)
            self.context.libraries.append(lib)

        print(f"    -> 成功提取 {len(self.context.libraries)} 个组件特征")

    # ── 阶段二：CVE 补丁验证（改为并发）────────────────────────

    def _verify_patches(self) -> None:
        print("[*] 阶段二: 漏洞情报路由与补丁确诊 (基于 PHunter) ...")

        # 收集所有需要验证的 (lib, vuln) 任务对
        tasks: list[tuple[TPLibrary, Vulnerability]] = [
            (lib, vuln)
            for lib in self.context.libraries
            for vuln in lib.vulnerabilities
        ]

        total_vulns = len(tasks)
        if total_vulns == 0:
            print("    -> 当前组件均未命中已知 CVE 情报，无需打补丁，分析结束。")
            return

        print(
            f"    -> 命中 {total_vulns} 个疑似漏洞记录，"
            f"并发校验（最大 {MAX_PHUNTER_CONCURRENT} 个 JVM）..."
        )

        # ── 【新增】并发执行 PHunter ──────────────────────────
        def _run_one(lib: TPLibrary, vuln: Vulnerability) -> None:
            """在信号量保护下运行单个 PHunter 任务，结果直接写回 vuln 对象。"""
            cve_meta = {
                "cve_id":         vuln.cve_id,
                "pre_patch_jar":  vuln.pre_patch_jar,
                "post_patch_jar": vuln.post_patch_jar,
                "patch_diff":     vuln.patch_diff,
            }
            # 信号量：最多 MAX_PHUNTER_CONCURRENT 个线程同时持有
            with self._phunter_semaphore:
                print(
                    f"      - 验证 [{lib.normalized_name}] 的漏洞: "
                    f"{vuln.cve_id} ..."
                )
                try:
                    patch_result = run_phunter(str(self.context.path), cve_meta)

                    # 【新增】心跳超时处理
                    if patch_result.get("hung"):
                        print(
                            f"      [!] PHunter 心跳超时，CVE {vuln.cve_id} 跳过。"
                        )
                        logger.warning(
                            "PHunter hung for CVE %s / APK %s",
                            vuln.cve_id, self.context.name,
                        )
                        vuln.patch_status = "HUNG"
                        return

                    vuln.patch_status    = patch_result.get("patch_status", "UNKNOWN")
                    vuln.pre_similarity  = patch_result.get("pre_similarity")
                    vuln.post_similarity = patch_result.get("post_similarity")

                except Exception as exc:
                    print(f"      [!] 验证过程执行出错: {exc}")
                    logger.exception(
                        "PHunter error for CVE %s / APK %s",
                        vuln.cve_id, self.context.name,
                    )
                    vuln.patch_status = "ERROR"

        # ThreadPoolExecutor：JVM 子进程是 I/O 密集型，线程池合适
        # max_workers 由信号量二次限流，此处设稍大一点让调度更灵活
        with ThreadPoolExecutor(max_workers=MAX_PHUNTER_CONCURRENT + 1) as executor:
            futures = {
                executor.submit(_run_one, lib, vuln): (lib, vuln)
                for lib, vuln in tasks
            }
            # 等待全部完成；单个失败不影响其他任务（异常已在 _run_one 内捕获）
            for future in as_completed(futures):
                # future.result() 不会抛出（_run_one 内部已全捕获），
                # 调用它只是确保线程异常能被传播到主线程日志。
                try:
                    future.result()
                except Exception as exc:
                    lib, vuln = futures[future]
                    logger.error(
                        "Unexpected future error for CVE %s: %s",
                        vuln.cve_id, exc,
                    )
        # ─────────────────────────────────────────────────────

    # ── 阶段三：生成报告（不变）─────────────────────────────

    def _generate_report(self) -> Dict[str, Any]:
        print("[*] 阶段三: 汇总诊断报告 ...")
        used_libraries: list[dict] = []
        vulnerabilities: list[dict] = []

        for lib in self.context.libraries:
            used_libraries.append({
                "raw_name":     lib.raw_name,
                "library_name": lib.normalized_name,
                "version":      lib.version,
                "similarity":   lib.similarity,
            })
            for vuln in lib.vulnerabilities:
                vulnerabilities.append({
                    "cve_id":          vuln.cve_id,
                    "library":         lib.normalized_name,
                    "status":          vuln.patch_status,
                    "pre_similarity":  vuln.pre_similarity,
                    "post_similarity": vuln.post_similarity,
                })

        return {
            "apk_info": {
                "name":   self.context.name,
                "sha256": self.context.sha256,
                "size":   self.context.file_size,
            },
            "used_libraries": used_libraries,
            "vulnerabilities": vulnerabilities,
        }