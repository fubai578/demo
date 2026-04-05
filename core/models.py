from dataclasses import dataclass, field
from typing import List, Optional

@dataclass
class Vulnerability:
    """代表一个具体的CVE漏洞及其补丁状态"""
    cve_id: str
    pre_patch_jar: str     # 补丁前的目标特征库路径
    post_patch_jar: str    # 补丁后的目标特征库路径
    patch_diff: str        # 记录方法变动的 diff 文件路径
    
    # 以下为探测后生成的状态
    patch_status: str = "UNTESTED"  # 状态枚举: UNTESTED, PATCH_PRESENT, PATCH_NOT_PRESENT, UNKNOWN, ERROR
    pre_similarity: Optional[float] = None
    post_similarity: Optional[float] = None

@dataclass
class TPLibrary:
    """代表 APK 中检测出的第三方库"""
    raw_name: str          # LibHunter输出的原始名字 (如 okhttp_3.12.0)
    normalized_name: str   # 规范化名字 (如 okhttp)
    version: str           # 解析出的版本号 (如 3.12.0)
    similarity: float      # LibHunter给出的指纹匹配度分值
    
    # 核心设计：每个库对象内部直接“挂载”它可能存在的漏洞，形成树状结构
    vulnerabilities: List[Vulnerability] = field(default_factory=list)

@dataclass
class ApkContext:
    """代表当前正在分析的 APK 会话上下文"""
    path: str
    name: str
    sha256: str
    file_size: int
    libraries: List[TPLibrary] = field(default_factory=list)