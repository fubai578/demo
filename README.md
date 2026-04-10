# 本次更新总结：
### **新增 PHunter 预热模式**
支持模板预热与 APK 预热，不跑完整检测流程即可提前生成缓存。
相关入口在 main.py / engine/detector.py / PHunter signTPL.MainClass（--prewarmOnly、--prewarmAPKOnly）。

### **缓存体系重构为“上层优先，失败回退”**
默认优先使用 binary_analysis / apk_analysis（分析结果缓存）；
仅当上层失败时才回退到底层 binary（Soot 产物链路）。
这样真实 APK 检测时更偏算法层执行，减少重复反编译。

### **缓存目录规范化**
采用 _aliases + soot_cache_hash 结构，按内容 hash 组织缓存，支持稳定命中与别名映射。
缓存命中通过文件 hash + 别名映射实现，兼容“不同文件名同内容”与“同文件名更新覆盖映射”的场景。
避免后续真实 APK 与 CVE 模板无法对齐。

### **终端命令**
```
1）正常检测 APK（自动复用 LibHunter + PHunter 缓存）：
$ python3 main.py --apk /home/leejm/Andriod_hunter/inputs/demo.apk
```
```
2）全量预热 PHunter（来源：TPL-CVEs）：（后续可删除）
$ python3 main.py --prewarm-phunter --prewarm-source tpl_cves
```
```
3） 全量预热 PHunter（来源：cve_kb.json）：
$ python3 main.py --prewarm-phunter --prewarm-source cve_kb
```
```
4） 只预热某个 APK 的 PHunter 缓存（apk_analysis）：
$ python3 main.py --prewarm-apk /home/leejm/Andriod_hunter/inputs/demo.apk
```
```
5） 单条手工预热（仅模板 pre/post，不跑 patch 检测）：
$ java -jar PHunter/PHunter.jar \
  --preTPL /path/to/pre.jar \
  --postTPL /path/to/post.jar \
  --androidJar PHunter/android-31/android.jar \
  --cacheDir data/phunter_soot_cache \
  --cacheMode readwrite \
  --prewarmOnly
```
```
6） 单条手工预热（仅 APK 缓存，不跑模板/patch）：
$ java -jar PHunter/PHunter.jar \
  --targetAPK /path/to/app.apk \
  --androidJar PHunter/android-31/android.jar \
  --cacheDir data/phunter_soot_cache \
  --cacheMode readwrite \
  --prewarmAPKOnly
```

### **可选环境变量（按需）**
```
预热超时（秒），大条目建议调大：
$ export PHUNTER_PREWARM_TIMEOUT=7200
```
```
缓存模式：off | readonly | readwrite
$ export PHUNTER_CACHE_MODE=readwrite
```
```
方法级预算（防极端路径爆炸）
$ export PHUNTER_DIGEST_METHOD_BUDGET_MS=30000
$ export PHUNTER_DIGEST_METHOD_BUDGET_NODES
```

### **对应代码文件**
src/symbolicExec/MethodDigest.java（状态去重 + 方法预算裁剪）
src/analyze/BinaryAnalyzer.java
src/analyze/MethodAttr.java
src/treeEditDistance/node/PredicateNodeData.java
src/analyze/AnalyzerCacheSupport.java（新文件）
src/analyze/SootCacheSupport.java（新文件）
src/signTPL/MainClass.java（预热参数相关）
engine/detector.py（修复 .aar -> .jar 缓存就绪误判）