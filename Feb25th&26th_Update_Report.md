# AuthAnalyzer 更新报告（2 月 25–26 日）

## 一、对称采集功能实现

基于 `docs/SessionTrafficCapture-Design.md`，完成对称采集相关实现，用于在 SAME/SIMILAR 结果中筛掉平凡响应，并区分垂直/水平越权。

### 1.1 核心组件

| 组件 | 说明 |
|------|------|
| **BypassStatus** | Trivial、Vertical、Horizontal、Unknown、RUN1_ONLY、RUN2_ONLY |
| **SymmetricTrafficStore** | 存储 responseA/B、replayStatusRun1/Run2 |
| **TrivialityChecker** | 根据 Store 计算 BypassStatus |
| **IdentityMatcher** | 按 headers 判断请求是否属于当前 Original |

### 1.2 配置与数据流

- **CurrentConfig**：symmetricCaptureEnabled、symmetricRun2Mode、currentOriginalHeaders、backupTableToSymmetricStore()
- **HttpListener**：symmetricCaptureEnabled 时，仅将匹配 currentOriginalHeaders 的请求送入 Analyzer
- **RequestController**：writeToSymmetricStore() 写入 responseA/B 和 replayStatus；URL 规范化（normalizeEndpointUrl）处理查询参数顺序和尾部斜杠

### 1.3 UI 与流程

- **ConfigurationPanel**：对称采集复选框、对称采集 Run2 按钮、清空对称数据按钮、Run2 状态标签
- **performRun2Transition()**：备份、交换 Original 与 Session1、进入 Run2
- **MergedUITestingPanel.afterCrawlComplete()**：Run1 抓取完成后自动进入 Run2 并再次抓取
- **IAnalyzerHost.triggerRun2Crawl()**：程序化触发抓取

### 1.4 主表与 Result 表

- **RequestTableModel**：Run 列、匹配列（↔ Run1#ID / ↔ Run2#ID）；run2ByMapId 记录每行 Run1/Run2
- **RequestTablePanel**：Run1 / Run2 / 全部 切换按钮，按 Run 列过滤
- **ResultTableModel**：Bypass 列；仅当 responseA 和 responseB 都存在时显示 Trivial/Vertical/Horizontal，否则 RUN1_ONLY/RUN2_ONLY

### 1.5 配置持久化

- **DataStorageProvider**：持久化 symmetricCaptureEnabled
- **loadSetup**：加载 symmetricCaptureEnabled

---

## 二、问题修复与优化

### 2.1 清空表格时同步清空 SymmetricTrafficStore

**问题**：`clearTable()` 只清空主表与 Session 的 requestResponseMap，未清空 SymmetricTrafficStore，导致再次抓取时新旧数据混合。

**修复**：在 `CenterPanel.clearTable()` 和 `UITestingPanel.clearTable()` 中增加：
- 清空 SymmetricTrafficStore
- 清空 TrivialityChecker 缓存
- 将 symmetricRun2Mode 置为 false

### 2.2 MainPanel 布局下对称采集限制

**问题**：MainPanel 未实现 Original headers，`getOriginalHeadersToReplace()` 返回空，IdentityMatcher 无法按身份过滤，会采集所有请求。

**修复**：
- **IAnalyzerHost**：新增 `supportsSymmetricCapture()`，默认返回 false
- **MergedUITestingPanel**：重写为返回 true
- **ConfigurationPanel.loadSetup()**：加载时若 `symmetricCaptureEnabled=true` 且 `!host.supportsSymmetricCapture()`，则强制设为 false

### 2.3 Result 表同一 endpoint 重复行

**问题**：同一 endpoint 的 Run1 和 Run2 行都会进入 filteredList，用户看到重复记录。

**修复**：`ResultTableModel.refresh()` 中按 endpoint 去重，每个 endpoint 仅保留首次出现的行。

### 2.4 删除行时 run2ByMapId 未清理

**问题**：删除行后 run2ByMapId 仍保留对应 id，存在轻微内存泄漏。

**修复**：`RequestTableModel.deleteRequestResponse()` 中增加 `run2ByMapId.remove(requestResponse.getId())`。

### 2.5 Result 表结构更新时机

**问题**：切换对称采集开关时，Bypass 列可能稍后才更新。

**修复**：`ResultPanel` 主表监听器中增加对 `ev.getFirstRow() == TableModelEvent.HEADER_ROW` 的处理，结构变化时立即调用 `scheduleRefresh(false)`。

### 2.6 Bypass 列 RUN1_ONLY / RUN2_ONLY 显示语义

**问题**：仅运行 Run1 时显示「Run1缺」，语义不清（实际缺的是 Run2）。

**修复**：调整 BypassStatus 显示名称：
- **RUN1_ONLY**（Run1 有、Run2 无）→ 显示 **「Run2缺」**
- **RUN2_ONLY**（Run2 有、Run1 无）→ 显示 **「Run1缺」**

---

## 三、涉及文件

| 文件 | 变更类型 |
|------|----------|
| `util/BypassStatus.java` | 新增枚举；RUN1_ONLY/RUN2_ONLY 显示名称修正 |
| `util/SymmetricTrafficStore.java` | 新增 |
| `util/TrivialityChecker.java` | 新增 |
| `util/IdentityMatcher.java` | 新增 |
| `util/CurrentConfig.java` | 对称采集配置、backupTableToSymmetricStore |
| `controller/RequestController.java` | writeToSymmetricStore、normalizeEndpointUrl |
| `controller/HttpListener.java` | IdentityMatcher 过滤 |
| `gui/main/ConfigurationPanel.java` | 对称采集 UI、performRun2Transition、loadSetup 限制 |
| `gui/main/CenterPanel.java` | clearTable 清空 SymmetricTrafficStore |
| `gui/util/IAnalyzerHost.java` | supportsSymmetricCapture |
| `gui/util/RequestTableModel.java` | Run 列、匹配列、run2ByMapId、deleteRequestResponse 清理 |
| `gui/UITesting/RequestTablePanel.java` | Run1/Run2 切换 |
| `gui/UITesting/UITestingPanel.java` | clearTable 清空 SymmetricTrafficStore |
| `gui/UITesting/MergedUITestingPanel.java` | supportsSymmetricCapture、afterCrawlComplete |
| `gui/Result/ResultTableModel.java` | Bypass 列、endpoint 去重 |
| `gui/Result/ResultPanel.java` | 主表结构变化时刷新 |
| `util/DataStorageProvider.java` | symmetricCaptureEnabled 持久化 |

---

## 四、使用说明

对称采集仅在 **UI Testing 合并布局** 下完整支持（需 Original headers 配置）。在 Analyzer 独立布局（MainPanel）下，若加载含对称采集的配置，将自动关闭对称采集。

详见 `使用指南.md` 中「对称采集（平凡响应筛选）」章节。
