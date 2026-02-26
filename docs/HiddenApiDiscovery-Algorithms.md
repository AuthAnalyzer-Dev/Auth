# 隐藏 API 发现算法

本文档整理隐藏 API 发现功能中的核心算法与流程。

---

## 一、概述

**隐藏 API**：页面上没有入口（链接、按钮等）会触发的 API，可能存在于 JS 代码或 Swagger 文档中，普通用户浏览时不会发起请求。发现这些 API 后，可送入 Analyzer 进行越权检测。

**发现方式**：
1. **从 JS 提取**：解析页面加载的 JavaScript 文件，用正则提取 API 路径
2. **从 Swagger 探测**：请求常见的 Swagger/OpenAPI 文档路径，解析 JSON 获取所有 endpoint

---

## 二、从 JS 提取

### 2.1 流程

```
输入: WebDriver driver, baseUrl (String), callback
输出: List<DiscoveredEndpoint>

1. baseOrigin = getBaseOrigin(baseUrl)   // 如 https://example.com
2. scripts = driver.findElements(By.tagName("script"))
3. 对每个 script：
   a. 若 src 非空：scriptUrl = toAbsoluteUrl(src, baseOrigin)
      - 通过 HTTP GET 获取 scriptUrl 内容
   b. 否则：content = script.getAttribute("innerHTML")（内联脚本）
   c. 对 content 调用 extractFromJsContent(content, result)
4. 返回 result
```

### 2.2 正则模式（JS_PATTERNS）

| 序号 | 模式 | 捕获组 | 说明 |
|------|------|--------|------|
| 1 | `fetch\s*\(\s*['"`](/[^'"`\s]+)['"`]` | 1=path | fetch('/api/xxx') |
| 2 | `axios\.(get\|post\|put\|delete\|patch)\s*\(\s*['"`](/[^'"`\s]+)['"`]` | 1=method, 2=path | axios.get('/api/xxx') |
| 3 | `url\s*:\s*['"`](/[^'"`\s]+)['"`]` | 1=path | $.ajax({ url: '/api/xxx' }) |
| 4 | `['"`](/api/[^'"`\s?]*)[?"'`]?` | 1=path | "/api/xxx" 字符串 |
| 5 | `['"`](/v[0-9]+/[^'"`\s?]*)[?"'`]?` | 1=path | "/v3/api/xxx" 字符串 |

### 2.3 路径过滤（isRelevantPath）

```text
输入: path (String)
输出: boolean

排除条件：
  - path 为 null 或长度 < 2
  - path 以 "//" 开头
  - path 包含 ".css"、".png"、".jpg"、".ico"

保留条件（满足其一）：
  - path 以 "/api" 开头
  - path 以 "/v" 开头
  - path 以 "/internal" 开头
```

### 2.4 方法推断

- 模式 2（axios）：从捕获组 1 获取 method（get/post/put/delete/patch）
- 其他模式：默认 method = "GET"

---

## 三、从 Swagger 探测

### 3.1 探测路径（SWAGGER_PATHS）

按顺序尝试以下路径，命中即停止：

| 路径 |
|------|
| /swagger.json |
| /swagger/v1/swagger.json |
| /v2/api-docs |
| /v3/api-docs |
| /api-docs |
| /api/swagger.json |
| /openapi.json |

### 3.2 解析算法

```
输入: baseUrl (String)
输出: List<DiscoveredEndpoint>

1. baseOrigin = getBaseOrigin(baseUrl)
2. 对每个 docPath in SWAGGER_PATHS：
   a. docUrl = baseOrigin + docPath
   b. json = fetchUrlContent(docUrl)   // HTTP GET
   c. 若 json 为空，继续下一个路径
   d. root = JsonParser.parseString(json)
   e. paths = root.get("paths")
   f. 对 paths 中每个 path：
      - 对 pathObj 中每个 key（get/post/put/delete/patch）：
        - result.add(DiscoveredEndpoint(method, path, SWAGGER))
   g. 解析成功则 break
3. 返回 result
```

### 3.3 支持的 HTTP 方法

GET、POST、PUT、DELETE、PATCH

---

## 四、合成请求构造（SyntheticRequestBuilder）

将发现的端点构造为可送入 Analyzer 的 HTTP 请求。

### 4.1 流程

```
输入: DiscoveredEndpoint endpoint, baseUrl, headersToReplace
输出: IHttpRequestResponse（含 request + response）

1. fullUrl = buildFullUrl(baseUrl, endpoint.getPath())
2. url = new URL(fullUrl)
3. service = buildHttpService(host, port, https)
4. requestBytes = buildRequest(helpers, url, method, headersToReplace)
5. rr = makeHttpRequest(service, requestBytes)
6. 返回 rr
```

### 4.2 路径占位符替换

Swagger 路径可能含 `{id}` 等占位符，构造 URL 时统一替换为 `"1"`：

```
path.replaceAll("\\{[^}]+\\}", "1")
```

示例：`/api/user/{id}` → `/api/user/1`

### 4.3 请求头注入

从 `headersToReplace`（Original 的 Header(s) to Replace）解析每行，按 header 名匹配并替换或追加到请求头中，用于携带 Cookie、Authorization 等认证信息。

---

## 五、与抓取流程的集成

### 5.1 发现阶段

1. 用户配置 Target URL、Header(s) to Replace
2. 勾选「从 JS 提取」和/或「从 Swagger 探测」
3. 点击「发现隐藏 API」
4. 若勾选 JS：启动浏览器 → 注入 Cookie → 导航至 Target URL → 提取 JS → 关闭浏览器
5. 若勾选 Swagger：直接 HTTP 请求探测
6. 结果展示在「发现的隐藏 API」列表中

### 5.2 送入 Analyzer

抓取（Run1/Run2）完成后，`afterCrawlComplete` 自动执行：

```
对 discoveredApiListPanel 中每个 DiscoveredEndpoint：
  rr = SyntheticRequestBuilder.buildAndExecute(ep, baseUrl, headers)
  performAuthAnalyzerRequest(rr)
```

发现的隐藏 API 与抓取到的非隐藏 API 一并完成越权检测。

---

## 六、局限与说明

| 项目 | 说明 |
|------|------|
| **误报** | 正则可能匹配注释、字符串常量中的路径，非实际 API 调用 |
| **非隐藏** | 部分 API 可能由页面正常触发，仍会被发现并列出 |
| **真正隐藏** | 建议对比「JS 发现的 API」与「抓取时实际请求的 API」，差集为更可疑的隐藏 API |
| **路径参数** | 占位符仅替换为 "1"，复杂参数需后续扩展 |
