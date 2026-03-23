# 全 URL 子网页爬取与 LLM 风险报告 - 设计建议

本文档为「以单页为原子操作 → 搜索算法覆盖全子网页 → Result 面板 → LLM 风险打分与报告」的完整方案提供 API 清单、技术建议与实现路径。

---

## 一、可能用到的 API 清单

### 1.1 Burp Suite 扩展 API（调试现有功能必备）

| API | 类/方法 | 用途 |
|-----|---------|------|
| `BurpExtender.callbacks` | `IBurpExtenderCallbacks` | 扩展入口，获取 helpers、消息编辑器等 |
| `callbacks.getHelpers().analyzeRequest(byte[])` | `IRequestInfo` | 解析请求头、参数、body offset |
| `callbacks.getHelpers().analyzeResponse(byte[])` | `IResponseInfo` | 解析响应头、状态码、MIME、body offset |
| `callbacks.getHelpers().buildHttpMessage(headers, body)` | `byte[]` | 构造 HTTP 报文 |
| `callbacks.getHelpers().buildHttpService(host, port, protocol)` | `IHttpService` | 构造服务描述 |
| `callbacks.makeHttpRequest(service, request)` | `IHttpRequestResponse` | 发送 HTTP 请求（同步） |
| `callbacks.isInScope(url)` | `boolean` | 判断 URL 是否在 Scope |
| `callbacks.addToSiteMap(message)` | - | 将消息加入站点地图 |
| `callbacks.getSiteMap(url)` | `IHttpRequestResponse[]` | 获取站点地图中某 URL 的报文 |
| `callbacks.createMessageEditor(controller, editable)` | `IMessageEditor` | 创建请求/响应编辑器 |
| `callbacks.loadExtensionSetting(key)` | `String` | 加载扩展配置 |
| `callbacks.saveExtensionSetting(key, value)` | - | 保存扩展配置 |
| `callbacks.printError(msg)` | - | 输出错误到 Burp 控制台 |
| `callbacks.printOutput(msg)` | - | 输出到 Burp 控制台 |
| `callbacks.registerContextMenuFactory(factory)` | - | 注册右键菜单 |

### 1.2 项目内部 API（爬取与 Result 数据流）

| API | 类/方法 | 用途 |
|-----|---------|------|
| `CurrentConfig.getCurrentConfig().performAuthAnalyzerRequest(IHttpRequestResponse)` | - | 将请求送入 Analyzer 线程池（异步） |
| `CurrentConfig.getCurrentConfig().getRequestController().analyze(IHttpRequestResponse)` | - | 同步分析请求（用于 Run 模式下保证顺序） |
| `CurrentConfig.getCurrentConfig().getTableModel()` | `RequestTableModel` | 主表数据模型 |
| `RequestTableModel.getOriginalRequestResponseList()` | `List<OriginalRequestResponse>` | 主表全部条目 |
| `ResultTableModel.getFilteredList()` | `List<OriginalRequestResponse>` | Result 面板过滤后的可疑条目 |
| `ResultTableModel.refresh()` | - | 从主表刷新 Result 过滤结果 |
| `OriginalRequestResponse.getRequestResponse()` | `IHttpRequestResponse` | 原始请求/响应报文 |
| `OriginalRequestResponse.getEndpoint()` | `String` | endpointKey（method+host+url） |
| `Session.getRequestResponseMap().get(mapId)` | `AnalyzerRequestResponse` | 某 Session 对该请求的分析结果 |
| `AnalyzerRequestResponse.getStatus()` | `BypassConstants` | SAME/SIMILAR/DIFFERENT/NA |
| `UITestingPanel.sendDiscoveredApisToAnalyzer(boolean sync)` | - | 将发现的 API 送入 Analyzer |
| `ApiDiscoveryService.discoverFromJs(...)` | `List<DiscoveredEndpoint>` | 从 JS 发现隐藏 API |
| `ApiDiscoveryService.discoverFromSwagger(url)` | `List<DiscoveredEndpoint>` | 从 Swagger 发现 API |
| `SyntheticRequestBuilder.buildAndExecute(ep, baseUrl, headers, log)` | `IHttpRequestResponse` | 构造并执行发现端点的请求 |

### 1.3 UI Testing 抓取相关（子网页遍历扩展）

| API | 类/方法 | 用途 |
|-----|---------|------|
| `ProxyDriverManager.getOrStartDriver(force, host, port, headless)` | `WebDriver` | 获取/启动浏览器驱动 |
| `ProxyDriverManager.getDriver()` | `WebDriver` | 获取当前驱动 |
| `driver.get(url)` | - | 导航到 URL |
| `driver.getCurrentUrl()` | `String` | 当前 URL |
| `driver.findElements(By.xpath(...))` | `List<WebElement>` | 查找元素 |
| `((JavascriptExecutor) driver).executeScript(script, args)` | `Object` | 执行 JS（如 DOM 指纹、scrollIntoView） |
| `controls.getTargetUrl()` | `String` | 目标 URL |
| `controls.getHeadersToReplaceText()` | `String` | Cookie 等认证头 |
| `controls.isDiscoverFromJsSelected()` | `boolean` | 是否勾选 JS 发现 |
| `controls.isDiscoverFromSwaggerSelected()` | `boolean` | 是否勾选 Swagger 发现 |

### 1.4 下游 LLM 接入（待实现）

| 类型 | 说明 |
|------|------|
| HTTP Client | `HttpURLConnection` / `OkHttp` / `java.net.http.HttpClient`（Java 11+） |
| 常见 LLM API | OpenAI、Claude、通义千问、文心一言、本地 Ollama 等 REST API |
| 数据格式 | JSON（请求/响应摘要、Bypass 状态、endpoint 等） |

---

## 二、目标与现状

### 2.1 目标

1. **全子网页覆盖**：以给定 URL 为根，通过搜索算法（BFS/DFS）遍历其下所有可到达子页面，对每个页面执行现有抓取逻辑（点击 + 发现 API + 送入 Analyzer）。
2. **Result 汇总**：分析结果汇总到 Result 面板，展示 SAME/SIMILAR 的可疑条目。
3. **LLM 下游**：将 Result 中的报文摘要送入大语言模型 API，进行风险打分、排序，并生成检测报告。

### 2.2 现状

- **单页抓取**：`UITestingPanel` 当前以**单页**为原子操作，在 `targetPage` 上做状态探索（Tab 切换）和点击，不跨页面递归。
- **Result 数据源**：`ResultTableModel` 从 `RequestTableModel` 过滤出 SAME/SIMILAR 条目，与 Analyzer、UI Testing 共享主表。
- **数据导出**：`DataExporter` 支持 XML/HTML 导出，可复用其结构作为 LLM 输入格式参考。

---

## 三、技术建议

### 3.1 搜索算法：全 URL 子网页遍历

**思路**：将「单页抓取」抽象为原子操作，用队列/栈管理待探索 URL，实现 BFS 或 DFS。

| 方案 | 优点 | 缺点 |
|------|------|------|
| **BFS** | 先覆盖浅层链接，适合层级较浅站点 | 可能过早进入深层，内存占用随深度线性增长 |
| **DFS** | 适合深层探索，栈空间可控 | 可能长时间卡在某一分支 |
| **混合** | 按深度限制 + 优先级（如先同域） | 实现稍复杂 |

**建议**：优先 BFS，配合 `maxDepth`、`maxTotalUrls`、同根域过滤（`isHrefInScopeForAuth` 已有）防止爆炸。

**数据结构**：

```
visitedUrls: Set<String>           // 已探索 URL（normalize 后）
urlQueue: Queue<String>            // 待探索 URL
currentPageCrawlResult: Set<String> // 当前页抓取到的新 URL（用于入队）
```

**流程**：

```
1. urlQueue.add(rootUrl)
2. while !urlQueue.isEmpty() && count < maxTotalUrls:
     url = urlQueue.poll()
     if url in visitedUrls: continue
     visitedUrls.add(url)
     driver.get(url)
     执行现有单页抓取逻辑（collectClickableKeys → 点击 → performAuthAnalyzerRequest）
     从抓取到的请求/响应中提取新 URL（或从 DOM 的 a[href] 提取）
     对新 URL 过滤（同域、非静态、非已访问）→ urlQueue.add(...)
3. 抓取完成后 runDiscoveryAfterCrawl + sendDiscoveredApisToAnalyzer
```

**与现有代码的衔接**：

- 复用 `collectClickableKeys`、`ensureClickInSameTab`、`goToTargetState`、`performAuthAnalyzerRequest`。
- 新增「URL 提取」：从 `IHttpRequestResponse` 的请求 URL、响应中的 `Location`、或 DOM 的 `a[href]` 提取。
- 新增「跨页队列」：在 `afterCrawlComplete` 或主循环中，将新 URL 入队而非仅结束。

### 3.2 Result 面板数据获取

Result 面板数据来自 `ResultTableModel.getFilteredList()`，每条为 `OriginalRequestResponse`。下游 LLM 需要的是**报文摘要**，建议封装为 DTO：

```java
// 示例结构
public class ResultEntryForLLM {
    String endpoint;           // method + host + url
    String method;
    String host;
    String url;
    int statusCode;
    BypassConstants status;    // SAME/SIMILAR
    BypassStatus bypassStatus; // TRIVIAL/HORIZONTAL/VERTICAL（若对称采集）
    String requestSummary;     // 请求头 + 前 N 字节 body
    String responseSummary;   // 响应头 + 前 N 字节 body
}
```

**获取方式**：

- `ResultTableModel.getFilteredList()` 得到 `List<OriginalRequestResponse>`
- 对每条 `orr`：`orr.getRequestResponse()` 得到 `IHttpRequestResponse`
- `callbacks.getHelpers().analyzeRequest/analyzeResponse` 解析
- 从 `Session.getRequestResponseMap().get(orr.getId())` 取 `AnalyzerRequestResponse` 得到 status

### 3.3 LLM 下游接入

**输入**：将 `ResultEntryForLLM` 列表序列化为 JSON，可包含：

- 每条 endpoint、method、url、statusCode、Bypass 状态
- 请求/响应摘要（截断，避免超 token 限制）

**输出**：LLM 返回结构化 JSON，例如：

```json
{
  "risk_scores": [
    { "endpoint": "GET example.com/api/user/1", "score": 9, "reason": "..." },
    ...
  ],
  "report": "## 越权检测报告\n\n..."
}
```

**实现建议**：

- 新建 `LlmReportService`，封装 HTTP 调用（API Key 配置化）
- 在 Result 面板增加「发送到 LLM」按钮，触发 `getFilteredList()` → 构建 DTO → 调用 API → 解析结果 → 展示报告
- 支持异步调用，避免阻塞 UI

### 3.4 调试现有功能时常用 API

| 场景 | 推荐 API |
|------|----------|
| 查看请求/响应解析结果 | `callbacks.getHelpers().analyzeRequest/analyzeResponse` |
| 手动发送请求 | `callbacks.makeHttpRequest` |
| 确认请求是否进入 Analyzer | `performAuthAnalyzerRequest` + 主表 `RequestTableModel` 行数 |
| 确认 Result 过滤逻辑 | `ResultTableModel.refresh()`、`hasSuspiciousStatus` |
| 调试抓取流程 | `log()` 输出到 stdout、Burp 控制台 |
| 检查 Scope | `callbacks.isInScope(url)` |
| 持久化配置 | `callbacks.loadExtensionSetting` / `saveExtensionSetting` |

---

## 四、实现路径建议

| 阶段 | 内容 | 产出 |
|------|------|------|
| **1** | 抽象「单页抓取」为可复用方法，接受 `url` 参数 | `crawlSinglePage(driver, url, ...)` |
| **2** | 实现 URL 队列 + BFS 主循环，从当前页提取新 URL 入队 | 全站爬取骨架 |
| **3** | 与现有 `afterCrawlComplete`、`sendDiscoveredApisToAnalyzer` 集成 | 全站分析到 Result |
| **4** | 定义 `ResultEntryForLLM`，实现 `ResultTableModel` → DTO 转换 | 数据准备 |
| **5** | 实现 `LlmReportService`，支持配置 API 端点与 Key | LLM 调用 |
| **6** | Result 面板增加「LLM 报告」按钮与报告展示区 | 端到端流程 |

---

## 五、风险与注意事项

1. **爬取规模**：全站爬取可能产生大量请求，需限制 `maxTotalUrls`、`maxTotalClicks`，并考虑目标站点负载。
2. **登录态**：跨页时 Cookie 可能失效，需在每页或定期 `applyCookies`。
3. **LLM Token 限制**：Result 条目过多时需分批或摘要压缩，避免单次请求超限。
4. **API Key 安全**：LLM API Key 应通过配置存储，避免硬编码，可复用 `Setting` 或 `loadExtensionSetting`。

---

## 六、相关文档

- `docs/UITesting-Crawl-Audit.md`：UI Testing 抓取流程与算法
- `docs/Bypass-Entry-Screening-Logic.md`：差分比较与 Result 筛选逻辑
- `docs/SymmetricCapture-Algorithms.md`：对称采集与平凡性判定
- `项目架构与开发指南.md`：整体架构
