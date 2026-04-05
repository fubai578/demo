from pathlib import Path
from typing import Dict, Any

# 问题⑤修正：原版导入路径为 adapters.apk_utils 等裸模块名，
# 在分层包结构下必须使用相对 import 或完整包路径。
# 修正：统一改用绝对包路径（从项目根 sys.path 可见）。
from adapters.apk_utils import get_apk_basic_info
from adapters.libhunter_adapter import run_libhunter
from adapters.phunter_adapter import run_phunter
from core.knowledge_base import KnowledgeBase
from core.models import ApkContext, TPLibrary


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
        self.apk_info = raw_info   # 供 cli.py 打印使用
        self.kb = KnowledgeBase()

    def scan(self) -> Dict[str, Any]:
        print(f"[*] 初始化分析任务: {self.context.name} "
              f"(SHA256: {self.context.sha256[:8]}...)")
        self._detect_libraries()
        self._verify_patches()
        return self._generate_report()

    def _detect_libraries(self) -> None:
        print("[*] 阶段一: 识别第三方库组件 (基于 LibHunter) ...")
        lib_result = run_libhunter(self.context.path)

        if lib_result["status"] != "success":
            print(f"[-] 组件识别异常或未检测到库，状态: {lib_result['status']}")
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

    def _verify_patches(self) -> None:
        print("[*] 阶段二: 漏洞情报路由与补丁确诊 (基于 PHunter) ...")
        total_vulns = sum(len(lib.vulnerabilities) for lib in self.context.libraries)
        if total_vulns == 0:
            print("    -> 当前组件均未命中已知 CVE 情报，无需打补丁，分析结束。")
            return

        print(f"    -> 命中 {total_vulns} 个疑似漏洞记录，开始控制流特征校验...")

        for lib in self.context.libraries:
            for vuln in lib.vulnerabilities:
                print(f"      - 验证 [{lib.normalized_name}] 的漏洞: {vuln.cve_id} ...")
                cve_meta = {
                    "cve_id":         vuln.cve_id,
                    "pre_patch_jar":  vuln.pre_patch_jar,
                    "post_patch_jar": vuln.post_patch_jar,
                    "patch_diff":     vuln.patch_diff,
                }
                try:
                    patch_result      = run_phunter(self.context.path, cve_meta)
                    vuln.patch_status  = patch_result.get("patch_status", "UNKNOWN")
                    vuln.pre_similarity  = patch_result.get("pre_similarity")
                    vuln.post_similarity = patch_result.get("post_similarity")
                except Exception as e:
                    print(f"      [!] 验证过程执行出错: {e}")
                    vuln.patch_status = "ERROR"

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