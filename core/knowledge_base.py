"""漏洞情报路由中心：加载 cve_kb.json，根据检测到的库名/版本下发补丁比对任务。"""
import json
from pathlib import Path

from config import BASE_DIR, CVE_KB_PATH
from core.models import TPLibrary, Vulnerability
from utils.normalizer import build_library_aliases


class KnowledgeBase:
    """
    漏洞情报路由中心。

    负责加载 cve_kb.json，并根据检测到的库名和版本，自动下发补丁比对任务。
    """

    def __init__(self):
        self._cve_records = self._load_data()

    def _load_data(self) -> list[dict]:
        if not CVE_KB_PATH.exists():
            print(f"[!] 警告: 找不到漏洞情报库文件 {CVE_KB_PATH}，将无法进行漏洞匹配。")
            return []
        with CVE_KB_PATH.open("r", encoding="utf-8") as f:
            kb = json.load(f)
        if not isinstance(kb, list):
            raise ValueError("CVE knowledge base 必须是一个 JSON 数组 (List)")
        return kb

    def _versions_match(self, detected_version: str, affected_versions: list) -> bool:
        if not affected_versions:
            return True   # 没有版本约束 = 全版本受影响
        if not detected_version:
            return False
        return detected_version in {str(v) for v in affected_versions}

    @staticmethod
    def _resolve_path(raw_path: str) -> str:
        """
        安全地解析 cve_kb.json 中的路径。

        修复：原版代码无条件执行 BASE_DIR / record["xxx_jar"]，
        当 cve_kb.json 中已经填写了绝对路径时，Path("/project") / "/abs/path"
        在 Python 3.12+ 中会直接返回 /abs/path（正确），但在 3.11 及以下版本中
        行为相同，只是容易让读者误解。更重要的是：如果 raw_path 以 "/" 开头，
        Path(base) / Path("/abs/path") 会忽略 base，直接返回 "/abs/path"，
        这其实是 Python 的正确行为，但我们显式处理以便代码意图清晰，
        且兼容未来可能的变化。
        """
        p = Path(raw_path)
        if p.is_absolute():
            return str(p.resolve())
        return str((BASE_DIR / p).resolve())

    def match_cves(self, library: TPLibrary) -> None:
        """为检测到的库匹配已知 CVE，将结果挂载到 library.vulnerabilities 上。"""
        lib_aliases = build_library_aliases(library.normalized_name, library.raw_name)

        for record in self._cve_records:
            kb_aliases = build_library_aliases(
                record.get("library_name"),
                *(record.get("aliases") or []),
            )
            if not (lib_aliases & kb_aliases):
                continue
            if not self._versions_match(library.version, record.get("affected_versions")):
                continue

            # ── 路径解析（兼容绝对/相对路径） ────────────────────────────
            try:
                pre_jar    = self._resolve_path(record["pre_patch_jar"])
                post_jar   = self._resolve_path(record["post_patch_jar"])
                patch_diff = self._resolve_path(record["patch_diff"])
            except KeyError as e:
                print(f"[!] cve_kb.json 记录 {record.get('cve_id', '?')} 缺少字段: {e}，跳过。")
                continue

            vuln = Vulnerability(
                cve_id=record["cve_id"],
                pre_patch_jar=pre_jar,
                post_patch_jar=post_jar,
                patch_diff=patch_diff,
            )
            # 去重：同一 CVE 不重复添加
            if not any(v.cve_id == vuln.cve_id for v in library.vulnerabilities):
                library.vulnerabilities.append(vuln)