# 越权漏洞入口完整筛选逻辑

本文档描述 AuthAnalyzer 对越权漏洞入口的完整筛选逻辑，包括流量采集、请求过滤、差分比较、平凡性判定及 Result 表展示。供审计与论文写作参考。

---

## 研究背景

### 越权漏洞与访问控制缺陷

**越权漏洞**（Broken Access Control / IDOR）是 OWASP Top 10 中持续高位的安全风险。当应用未能正确实施访问控制时，用户 A 可能访问或操作本属于用户 B 的资源，或普通用户可能执行仅管理员可用的操作。前者为**水平越权**（Horizontal Privilege Escalation），后者为**垂直越权**（Vertical Privilege Escalation）。

现代 Web 应用普遍采用前后端分离架构，业务逻辑通过 REST API、GraphQL 等接口暴露。越权检测的核心在于：**用不同身份的凭证重放同一请求，比较响应差异**。若身份 B 的响应与身份 A 的 Original 响应相同或高度相似，则存在越权风险。

### 传统检测的局限

| 问题 | 说明 |
|------|------|
| **入口依赖** | 手工测试依赖人工触发的请求；若 API 无显式入口（如仅存在于 JS 中），易被遗漏 |
| **规模与效率** | 大型应用有数百个接口，人工逐一替换 Cookie 并比较响应不现实 |
| **响应判定** | 仅凭肉眼难以区分「完全相同」「长度相近」「内容相似」等程度差异 |
| **双身份场景** | 对称采集（A/B 双身份各跑一遍）需保证同一 endpoint 正确配对，否则无法计算 Trivial/Vertical/Horizontal |

### 自动化检测与 AuthAnalyzer 定位

AuthAnalyzer 作为 Burp Suite 扩展，将越权检测流程自动化：

1. **多源入口**：代理流量、Repeater、UI 抓取、隐藏 API 发现（JS/Swagger/GraphQL）统一送入分析器
2. **多 Session 重放**：为每个请求创建多个 Session 变体，自动替换 Cookie/Token 等并重发
3. **差分比较**：对 Original 与 Session 响应做字节级与长度级比较，输出 SAME/SIMILAR/DIFFERENT
4. **对称采集**：Run1/Run2 双身份采集，结合 responseA/responseB 与重放状态，判定 Trivial（平凡）、Vertical（垂直越权）、Horizontal（水平越权）
5. **Result 筛选**：从主表过滤出可疑条目，排除平凡响应，聚焦真实漏洞

本文档聚焦上述流程中的**入口筛选与差分逻辑**，为审计与论文写作提供形式化描述。

---

## 一、概述

越权漏洞检测的核心流程为：

1. **入口采集**：从代理、Repeater、UI 抓取等来源收集 HTTP 请求
2. **请求过滤**：按全局过滤器与 Session 级规则过滤，决定是否送入 Analyzer
3. **重放与差分**：用各 Session 的凭证重放 Original 请求，比较 Original 与 Session 响应
4. **可疑判定**：将 SAME/SIMILAR 的请求标记为潜在越权
5. **对称采集**（可选）：Run1/Run2 双身份采集，计算 BypassStatus（Trivial/Vertical/Horizontal）
6. **Result 筛选**：从主表过滤出可疑条目，可选排除 Trivial

---

## 二、入口采集

### 2.1 流量来源

| 来源 | 触发条件 | 说明 |
|------|----------|------|
| Proxy | `config.isRunning()` 且 `processHttpMessage` | 代理流量，可配置 Drop Original |
| Repeater | 同上 | 手动重放请求 |
| UI Testing 抓取 | 抓取线程 + `performAuthAnalyzerRequest` | 浏览器抓取到的请求 |
| 隐藏 API 发现 | `sendDiscoveredApisToAnalyzer` | 从 JS/Swagger 发现的端点构造请求 |

### 2.2 对称采集下的身份过滤（IdentityMatcher）

当启用对称采集时，**仅当请求 headers 包含当前 Original 身份的 `headersToReplace` 中每一行**，才送入 Analyzer。

```
输入: requestHeaders (List<String>), headersToReplace (String)
输出: boolean（true = 匹配，可送入）

1. requestHeaders 为 null → false
2. headersToReplace 为 null 或空 → true（不过滤）
3. 按 "\n" 分割 headersToReplace，对每行 trimmed：
   - 若 requestHeaders 不包含 trimmed → false
4. 全部包含 → true
```

语义：请求归属某身份，当且仅当请求 headers 包含该身份配置的每一行（如 Cookie、Authorization）。

---

## 三、请求过滤（RequestFilter）

在 `HttpListener.isFiltered` 与 `GenericHelper.repeatRequests` 中，请求需通过**所有已启用的 RequestFilter**。任一 filter 返回 true 则请求被过滤，不送入 Analyzer。

### 3.1 过滤器列表

| 过滤器 | 条件（启用时） | 默认/典型配置 |
|--------|----------------|---------------|
| **MethodFilter** | `requestMethod` 在 stringLiterals 中（忽略大小写） | OPTIONS |
| **PathFilter** | `path.toLowerCase().contains(literal.toLowerCase())` | 可配置路径片段 |
| **QueryFilter** | `query` 非空且 `query.toLowerCase().contains(literal)` | 可配置查询片段 |
| **StatusCodeFilter** | `responseInfo.getStatusCode()` 在 stringLiterals 中 | 304 |
| **FileTypeFilter** | `path.endsWith(fileType)` 或 `responseInfo.getInferredMimeType()` 匹配 | js, css, png, jpg, ... |
| **InScopeFilter** | `!callbacks.isInScope(requestInfo.getUrl())` | Burp Scope |
| **OnlyProxyFilter** | 非 Proxy 且非 Repeater 时过滤 | 仅 Proxy/Repeater 通过 |

### 3.2 过滤逻辑

```
isFiltered(toolFlag, messageInfo):
  for each filter in config.getRequestFilterList():
    if filter.filterRequest(callbacks, toolFlag, requestInfo, responseInfo):
      return true
  return false
```

---

## 四、Session 级过滤

在 `RequestController.analyze` 中，每个 Session 可额外过滤：

| 条件 | 结果 |
|------|------|
| Session 已暂停 | 标记为 NA，不重放 |
| `filterRequestsWithSameHeader` 且请求 headers 已包含该 Session 的 `headersToReplace` | 标记为 NA，不重放 |
| `restrictToScope` 且 URL 不在 Session 的 `scopeUrl` 内 | 标记为 NA，不重放 |

---

## 五、差分比较（Response Differential）

差分比较在 `RequestController.analyzeResponse` 中实现，对 Original 响应与 Session 重放响应进行字节级与长度级比较，输出 SAME/SIMILAR/DIFFERENT。仅在 Original 与 Session 均有有效响应时调用；否则直接标记为 NA。

### 5.1 比较对象

- **Original**：原始请求的响应（来自代理/抓取/发现）
- **Session**：用该 Session 的凭证（headersToReplace、Token 等）重放后的响应

比较时仅使用**响应体（Body）**，不包含 HTTP 头。通过 Burp 的 `IResponseInfo.getBodyOffset()` 切分：`response[bodyOffset : length]`。

### 5.2 判定结果（BypassConstants）

| 结果 | 含义 |
|------|------|
| SAME | 视为确定越权（响应相同） |
| SIMILAR | 视为潜在越权（响应相似） |
| DIFFERENT | 不越权 |
| NA | 未比较（被过滤、无响应等） |

### 5.3 NA 判定条件（不调用 analyzeResponse）

以下任一条件成立时，直接标记为 NA，不进行差分比较：

| 条件 | 来源 |
|------|------|
| Session 已暂停 | `RequestController.analyze` |
| `filterRequestsWithSameHeader` 且请求已包含该 Session 的 headersToReplace | 同上 |
| `restrictToScope` 且 URL 不在 Session 的 scopeUrl 内 | 同上 |
| Original 响应为 null（如 Drop Original 丢弃的请求） | 同上，第 107–118 行 |
| Session 重放请求/响应为 null（无响应或连接失败） | 同上，第 120–124 行 |

### 5.4 SAME 判定算法

```
输入: originalResponse, sessionResponse, originalResponseInfo, sessionResponseInfo

1. originalBody = Arrays.copyOfRange(originalResponse, originalResponseInfo.getBodyOffset(), originalResponse.length)
   sessionBody  = Arrays.copyOfRange(sessionResponse, sessionResponseInfo.getBodyOffset(), sessionResponse.length)

2. 若 Arrays.equals(originalBody, sessionBody)
   且（originalStatusCode == sessionStatusCode 或 !respectResponseCodeForSameStatus）
   → SAME
```

**配置**：`respectResponseCodeForSameStatus`（默认 true）为 false 时，忽略状态码差异。

### 5.5 SIMILAR 判定算法

**判定顺序**：先尝试 SAME，不满足则尝试 SIMILAR，均不满足则 DIFFERENT。

```
1. 若 originalStatusCode != sessionStatusCode 且 respectResponseCodeForSimilarStatus
   → DIFFERENT（状态码不同，不进入 SIMILAR 判定）

2. range = originalBodyLength / (100 / deviationForSimilarStatus)
   difference = originalBodyLength - sessionBodyLength

3. 若 difference ∈ [-range, range]（即 |difference| ≤ range）→ SIMILAR
   否则 → DIFFERENT
```

**配置**：
- `deviationForSimilarStatus`：默认 5，即 ±5% 长度差视为 SIMILAR；对应 `getDerivationForSimilarStatus()`（代码中方法名为 Derivation）
- `respectResponseCodeForSimilarStatus`：默认 true，状态码不同则不为 SIMILAR

**边界情况**：当 `originalBodyLength == 0` 时，`range = 0`，仅当 `sessionBodyLength == 0` 时判定为 SIMILAR。

### 5.6 公式汇总

| 判定 | 条件 |
|------|------|
| SAME | 响应体字节相等 ∧（状态码相同 ∨ 不尊重状态码） |
| SIMILAR | （状态码相同 ∨ 不尊重状态码）∧ \|Δlength\| ≤ originalLength × (deviation/100) |
| DIFFERENT | 其他 |

### 5.7 复用场景

`TrivialityChecker.isSameResponse` 在对称采集平凡性判定时，复用 `RequestController.analyzeResponse` 的 SAME 判定，用于判断 responseA 与 responseB 是否相同（Resp_A == Resp_B → TRIVIAL）。

---

## 六、对称采集（Symmetric Capture）

### 6.1 数据模型

- **Run1**：用户 A 身份，responseA、replayStatusRun1
- **Run2**：用户 B 身份，responseB、replayStatusRun2
- **endpointKey**：`normMethod + normHost + normUrl`，由 `OriginalRequestResponse.getEndpoint()` 生成

### 6.2 Endpoint 规范化

```
endpointKey = normMethod + normHost + normUrl

normMethod = method.toUpperCase()
normHost   = host.toLowerCase()   // 来自 requestResponse.getHttpService().getHost()
normUrl   = normalizeEndpointUrl(path, query)  // 在 RequestController 构造 OriginalRequestResponse 时已规范化
```

`normalizeEndpointUrl` 规则（`RequestController.normalizeEndpointUrl`）：
- path：合并连续 "/"，去掉尾部 "/"（根路径 "/" 保留）
- query：参数按 "&" 分割后字典序排序

### 6.3 平凡性判定（TrivialityChecker）

`TrivialityChecker.computeStatus` 根据 responseA、responseB、replayStatusRun1、replayStatusRun2 计算 BypassStatus：

| 条件 | BypassStatus | 含义 |
|------|--------------|------|
| hasA ∧ hasB ∧ Resp_A == Resp_B | TRIVIAL | 平凡，A/B 响应相同，无越权 |
| hasA ∧ hasB ∧ (replay1 或 replay2 为 SAME/SIMILAR) | HORIZONTAL | 水平越权 |
| hasA ∧ ¬hasB ∧ replay1 为 SAME/SIMILAR | VERTICAL | 垂直越权（B 无入口） |
| ¬hasA ∧ hasB ∧ replay2 为 SAME/SIMILAR | VERTICAL | 垂直越权（A 无入口） |
| 其他 | UNKNOWN | 未知 |

其中 `Resp_A == Resp_B` 复用 `RequestController.analyzeResponse` 的 SAME 判定（`TrivialityChecker.isSameResponse`）。

**RUN1_ONLY / RUN2_ONLY**：由 `ResultTableModel.getValueAt` 在展示 Bypass 列时单独计算，不经过 TrivialityChecker。当 `hasA ∧ ¬hasB` 时显示 RUN1_ONLY（Run2 缺），`¬hasA ∧ hasB` 时显示 RUN2_ONLY（Run1 缺）。

---

## 七、Result 表筛选逻辑

### 7.1 数据流

```
主表 (RequestTableModel)
  → ResultTableModel.refresh()
  → filteredList（展示在 Result 标签）
```

### 7.2 refresh() 算法

```
1. filteredList.clear()
2. 若 mainModel 或 sessions 为空 → return
3. seenEndpoints = ∅
4. for each orr in mainModel.getOriginalRequestResponseList():
   a. if !hasSuspiciousStatus(orr.id, sessions) → continue
   b. ep = orr.getEndpoint()
   c. if ep ∈ seenEndpoints → continue
   d. if 对称采集 ∧ hasResponseA(ep) ∧ hasResponseB(ep):
        status = TrivialityChecker.getStatus(ep)
        if excludeTrivial ∧ status == TRIVIAL → continue
   e. seenEndpoints.add(ep)
   f. filteredList.add(orr)
```

实现位置：`ResultTableModel.refresh()`。

### 7.3 hasSuspiciousStatus

```
任意 Session 对该 mapId 的 AnalyzerRequestResponse.status ∈ {SAME, SIMILAR}
→ true
```

实现位置：`ResultTableModel.hasSuspiciousStatus(int mapId, List<Session> sessions)`。

### 7.4 去重与 Trivial 排除

- **去重**：同一 endpoint 只保留首次出现的行（Run1/Run2 二选一）
- **excludeTrivial**：默认 true，排除 BypassStatus == TRIVIAL 的条目

---

## 八、配置参数汇总

| 参数 | 默认值 | 作用 |
|------|--------|------|
| respectResponseCodeForSameStatus | true | SAME 是否要求状态码相同 |
| respectResponseCodeForSimilarStatus | true | SIMILAR 是否要求状态码相同 |
| deviationForSimilarStatus | 5 | SIMILAR 的响应体长度偏差百分比（±5%） |
| excludeTrivial | true | Result 表是否排除 TRIVIAL |
| NUMBER_OF_THREADS | 5 | Analyzer 线程池大小 |
| DELAY_BETWEEN_REQUESTS | 0 | 请求间延迟（ms） |

---

## 九、视觉与展示

### 9.1 BypassConstants 着色（BypassCellRenderer）

| 值 | 背景色 |
|----|--------|
| SAME | 红 (255,51,51,80) |
| SIMILAR | 橙 (255,153,0,80) |
| DIFFERENT | 绿 (0,255,51,80) |

### 9.2 BypassStatus 着色

| 值 | 背景色 |
|----|--------|
| TRIVIAL | 灰 (180,180,180,100) |
| VERTICAL | 红 (255,100,100,100) |
| HORIZONTAL | 橙 (255,153,0,100) |
| RUN1_ONLY / RUN2_ONLY | 浅灰 (220,220,220,80) |

### 9.3 主表 Run 列

- Run1：用户 A 身份下的请求
- Run2：用户 B 身份下的请求
- 匹配列：`↔ Run1#id` / `↔ Run2#id` / `✓匹配`

---

## 十、流程总览（伪代码）

```
// 入口
onHttpMessage(toolFlag, messageInfo):
  if !config.isRunning(): return
  if isFiltered(toolFlag, messageInfo): return
  if symmetricCapture && !IdentityMatcher.requestMatchesHeaders(...): return
  performAuthAnalyzerRequest(messageInfo)

// 分析（RequestController.analyze）
analyze(originalRequestResponse):
  for each Session:
    if sessionFiltered: put NA; continue
    modifiedRequest = apply session credentials
    sessionRequestResponse = makeHttpRequest(modifiedRequest)
    if sessionRequestResponse 为 null 或无响应: put NA; continue
    if originalResponse 为 null: put NA; continue
    status = analyzeResponse(originalResponse, sessionResponse, originalResponseInfo, sessionResponseInfo)
    put AnalyzerRequestResponse(sessionRequestResponse, status, ...)
  orr = new OriginalRequestResponse(...)
  mainModel.add(orr, isRun2)
  writeToSymmetricStore(orr, mapId)

// Result 刷新（ResultTableModel.refresh）
refresh():
  for orr in mainModel:
    if !hasSuspiciousStatus(orr.id, sessions): continue
    if duplicate endpoint: continue
    if symmetric && hasBoth && excludeTrivial && status==TRIVIAL: continue
    filteredList.add(orr)
```

---

## 参考文献与相关文档

- `docs/SymmetricCapture-Algorithms.md`：对称采集算法细节
- `docs/SessionTrafficCapture-Design.md`：会话流量采集设计
- `使用指南.md`：用户操作说明

---

## 附录：差分比较相关代码位置

| 功能 | 类/方法 |
|------|---------|
| 差分比较核心逻辑 | `RequestController.analyzeResponse(byte[], byte[], IResponseInfo, IResponseInfo)` |
| 差分比较调用时机 | `RequestController.analyze` 第 107–108 行（Original 与 Session 均有响应时） |
| SAME/SIMILAR 复用（平凡性判定） | `TrivialityChecker.isSameResponse` → `requestController.analyzeResponse` |
| 配置项读取 | `CurrentConfig`：`respectResponseCodeForSameStatus`、`respectResponseCodeForSimilarStatus`、`getDerivationForSimilarStatus()` |
| 配置持久化 | `Setting.Item.STATUS_SAME_RESPONSE_CODE`、`STATUS_SIMILAR_RESPONSE_CODE`、`STATUS_SIMILAR_RESPONSE_LENGTH` |
