# 隐藏 API 发现算法

本文档整理隐藏 API 发现功能中的核心算法与流程。

---

## 一、概述

**隐藏 API**：页面上没有入口（链接、按钮等）会触发的 API，可能存在于 JS 代码、Source Map、Swagger 文档或 GraphQL Schema 中，普通用户浏览时不会发起请求。发现这些 API 后，可送入 Analyzer 进行越权检测。

**发现方式**：
1. **从 JS 提取**：解析页面加载的 JavaScript 文件，用正则提取 API 路径
2. **Source Map**：在 JS URL 后追加 `.map` 获取 Source Map，解析 `sourcesContent` 做二次提取
3. **从 Swagger 探测**：请求常见的 Swagger/OpenAPI/Actuator 文档路径，解析 JSON 获取 endpoint
4. **GraphQL 内省**：对 GraphQL 端点发送 Introspection Query，提取 Query/Mutation 名称

---

## 二、整体架构

```
┌─────────────────────────────────────────────────────────────────────────┐
│  用户输入：Target URL、Header(s) to Replace、勾选发现方式                 │
└─────────────────────────────────────────────────────────────────────────┘
                                    │
                                    ▼
┌─────────────────────────────────────────────────────────────────────────┐
│  发现阶段（4 种来源）                                                      │
│  JS 提取 → Source Map → Swagger/Actuator → GraphQL 内省                   │
└─────────────────────────────────────────────────────────────────────────┘
                                    │
                                    ▼
┌─────────────────────────────────────────────────────────────────────────┐
│  去重与展示：List<DiscoveredEndpoint>（method+path+graphqlOperation 去重） │
└─────────────────────────────────────────────────────────────────────────┘
                                    │
                                    ▼
┌─────────────────────────────────────────────────────────────────────────┐
│  合成请求：SyntheticRequestBuilder → 送入 Analyzer 做越权检测               │
└─────────────────────────────────────────────────────────────────────────┘
```

---

## 三、从 JS 提取

### 3.1 流程

```
输入: WebDriver driver, baseUrl (String), callback
输出: List<DiscoveredEndpoint>

1. baseOrigin = getBaseOrigin(baseUrl)   // 如 https://example.com
2. scripts = driver.findElements(By.tagName("script"))
3. 对每个 script：
   a. 若 src 非空：
      - scriptUrl = toAbsoluteUrl(src, baseOrigin)
      - 通过 HTTP GET 获取 scriptUrl 内容
      - extractFromJsContent(content, result, JS)
      - extractFromSourceMap(scriptUrl, result, callback)   // 二次提取
   b. 否则：content = script.getAttribute("innerHTML")（内联脚本）
      - extractFromJsContent(content, result, JS)
4. 返回 result
```

### 3.2 正则模式（JS_PATTERNS）

| 序号 | 模式 | 捕获组 | 说明 |
|------|------|--------|------|
| 1 | `fetch\s*\(\s*['"`](/[^'"`\s]+)['"`]` | 1=path | fetch('/api/xxx') |
| 2 | `axios\.(get\|post\|put\|delete\|patch)\s*\(\s*['"`](/[^'"`\s]+)['"`]` | 1=method, 2=path | axios.get('/api/xxx') |
| 3 | `url\s*:\s*['"`](/[^'"`\s]+)['"`]` | 1=path | $.ajax({ url: '/api/xxx' }) |
| 4 | `['"`](/api/[^'"`\s?]*)[?"'`]?` | 1=path | "/api/xxx" 字符串 |
| 5 | `['"`](/v[0-9]+/[^'"`\s?]*)[?"'`]?` | 1=path | "/v3/api/xxx" 字符串 |
| 6 | `['"`](/internal/[^'"`\s?]*)[?"'`]?` | 1=path | "/internal/xxx" |
| 7 | `['"`]((?:\./)?(?:api\|v[0-9]+\|internal)/[^'"`\s?]*)[?"'`]?` | 1=path | 相对路径 api/xxx、./api/xxx |
| 8 | `` `((?:/api\|/v[0-9]+\|/internal)/[^`]*)` `` | 1=path | 模板字符串，归一化 `${...}`→1 |
| 9 | `['"`]((?:/api\|/v[0-9]+\|/internal)/[^'"`]*?)['"`]\s*\+` | 1=path | 字符串拼接 "/api/" + x |
| 10 | `\$\.(get\|post)\s*\(\s*['"`](/[^'"`\s]+)['"`]` | 1=method, 2=path | $.get('/api/xxx') |

### 3.3 路径过滤（isRelevantPath）

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

### 3.4 方法推断

- 模式 2（axios）：从捕获组 1 获取 method（get/post/put/delete/patch）
- 模式 10（$.get/post）：从捕获组 1 获取 method
- 其他模式：默认 method = "GET"

### 3.5 路径归一化（normalizePathForApi）

- `${...}` → `1`
- `./`、`../` 前缀去除
- 相对路径补前导 `/`

### 3.6 动态 script 发现（extractAndFetchChunkScripts）

从 JS 内容中提取并递归获取的脚本 URL 模式：

| 模式 | 说明 |
|------|------|
| CHUNK_OR_ASSET_URL | 含 chunk/main/bundle/runtime/vendor 的路径 |
| DYNAMIC_IMPORT_URL | `import(...'path.js')`，含 Webpack 魔法注释 |
| AMD_REQUIRE_URL | `require(['path.js'])` |
| WORKER_URL | `new Worker('path')`、`new SharedWorker('path')` |
| ANY_SCRIPT_URL | 任意 `/path/*.js`（路径 ≥ 8 字符） |

递归深度：MAX_CHUNK_FETCH_DEPTH=3。DOM 收集：首次收集后等待 2.5s 再收集，合并动态注入的 script。详见 `HiddenApiDiscovery-Dynamic-Loading-Audit.md`。

---

## 四、Source Map 二次提取

### 4.1 流程

```
输入: scriptUrl (String), result (Set), callback
输出: 追加到 result

1. mapUrl = scriptUrl.endsWith(".map") ? scriptUrl : scriptUrl + ".map"
2. content = fetchUrlContent(mapUrl)   // HTTP GET
3. root = JsonParser.parseString(content)
4. sourcesContent = root.get("sourcesContent")   // JSON 数组
5. 对 sourcesContent 中每个元素：
   - extractFromJsContent(src, result, SOURCE_MAP)   // 使用相同正则
```

### 4.2 说明

压缩/混淆后的 JS 难以用正则直接提取 API；Source Map 中的 `sourcesContent` 为原始未混淆代码，用相同正则二次提取可提高发现率。

---

## 五、从 Swagger 探测

### 5.1 探测路径（SWAGGER_PATHS）

按顺序尝试以下路径，命中即停止：

| 路径 |
|------|
| /swagger.json |
| /swagger/v1/swagger.json |
| /v2/api-docs |
| /v3/api-docs |
| /v3/api-docs.yaml |
| /api-docs |
| /api/swagger.json |
| /openapi.json |
| /openapi.yaml |
| /api/openapi.json |
| /actuator/mappings |
| /actuator/env |
| /graphql |
| /v1/graphql |
| /api/graphql |

### 5.2 分支逻辑

- **路径含 `graphql`**：走 GraphQL 内省，不按 Swagger 解析
- **`/actuator/mappings`**：解析 Spring Boot Actuator 映射
- **其他**：按 Swagger/OpenAPI 解析

### 5.3 Swagger/OpenAPI 解析

```
1. json = fetchUrlContent(docUrl)
2. 若 json 不以 "{" 开头：跳过（非 JSON，如 YAML 需额外解析）
3. root = JsonParser.parseString(json)
4. paths = root.get("paths")
5. 对 paths 中每个 path：
   - 对 pathObj 中每个 key（get/post/put/delete/patch）：
     - schema = parseEndpointSchema(pathObj, method)
     - result.add(DiscoveredEndpoint(method, path, SWAGGER, schema))
```

### 5.4 Actuator 解析

```
1. 解析 contexts.*.mappings.dispatcherServlets.* 数组
2. 从 predicate 提取 method 和 path（如 "GET /api/user"）
3. 使用 ACTUATOR_METHOD_PATH 正则或手动解析 predicate.substring(0, '/') 前的 method
4. 过滤 isRelevantPath(path) 后加入 result
```

### 5.5 EndpointSchema 解析

- **path 参数**：从 `parameters` 中 `in == "path"` 的项，取 `schema.type` / `schema.format` 或 `type` / `format`
- **RequestBody**：从 `requestBody.content["application/json"].schema` 或 `parameters` 中 `in == "body"` 的 `schema`

### 5.6 支持的 HTTP 方法

GET、POST、PUT、DELETE、PATCH

---

## 六、GraphQL 内省

### 6.1 流程

```
输入: graphqlUrl (String), callback
输出: List<DiscoveredEndpoint>

1. 发送 POST 请求，body 为 Introspection Query
2. 解析 data.__schema，取 queryType、mutationType
3. 遍历 types，筛选 kind == "OBJECT" 且 name 为 queryType 或 mutationType
4. 对每个 type 的 fields，取 name 作为 operation
5. 生成：
   - 一个基础端点：POST /graphql（无 operation）
   - 每个 operation 一个端点：POST /graphql + graphqlOperation = fieldName
```

### 6.2 说明

GraphQL 端点通常为单一 URL，通过 Introspection 可获取所有 Query/Mutation 名称，作为独立探测目标。

---

## 七、合成请求构造（SyntheticRequestBuilder）

将发现的端点构造为可送入 Analyzer 的 HTTP 请求。

### 7.1 流程

```
输入: DiscoveredEndpoint endpoint, baseUrl, headersToReplace
输出: IHttpRequestResponse（含 request + response）

1. fullUrl = buildFullUrl(baseUrl, endpoint)
2. url = new URL(fullUrl)
3. service = buildHttpService(host, port, https)
4. requestBytes = buildRequest(helpers, url, endpoint, headersToReplace)
5. rr = makeHttpRequest(service, requestBytes)
6. 返回 rr
```

### 7.2 路径参数替换（buildFullUrl）

- **有 EndpointSchema 且 pathParams 非空**：调用 `SchemaBasedBodyGenerator.replacePathParams(path, schema.getPathParams())`，按 type/format 生成值
- **否则**：`path.replaceAll("\\{[^}]+\\}", "1")`

**SchemaBasedBodyGenerator 参数值规则**：

| type/format | 替换值 |
|-------------|--------|
| uuid, guid | `UUID.randomUUID()` |
| email | `test@example.com` |
| integer, int32, int64 | 1–10000 随机整数 |
| number, float, double | 0–1000 随机浮点 |
| boolean | `true` |
| 其他 | `"1"` |

### 7.3 RequestBody 生成（buildRequest）

**POST/PUT/PATCH**：

- **GraphQL**：`{"query":"query {operationName} { __typename }"}` 或 `{"query":"{ __typename }"}`
- **有 requestBodySchema**：`SchemaBasedBodyGenerator.generateRequestBody(schema)` 按 schema 生成 JSON
- **无 schema**：`{}`

**SchemaBasedBodyGenerator 的 Body 生成**：

- 遍历 `schema.properties`，按 `type` 生成：
  - `string`：按 `format` 用 email/uuid/date-time 等默认值，否则 `"test"`
  - `integer` / `number`：`1`
  - `boolean`：`true`
  - `array`：`[]`
  - `object`：递归 `buildFromSchema`

### 7.4 请求头注入

从 `headersToReplace`（Original 的 Header(s) to Replace）解析每行，按 header 名匹配并替换或追加到请求头中，用于携带 Cookie、Authorization 等认证信息。

---

## 八、与抓取流程的集成

### 8.1 发现阶段

1. 用户配置 Target URL、Header(s) to Replace
2. 勾选「从 JS 提取」和/或「从 Swagger 探测」
3. 点击「发现隐藏 API」
4. 若勾选 JS：启动浏览器 → 注入 Cookie → 导航至 Target URL → 提取 JS → Source Map 二次提取 → 关闭浏览器
5. 若勾选 Swagger：直接 HTTP 请求探测 SWAGGER_PATHS，解析 Swagger/Actuator/GraphQL
6. 结果展示在「发现的隐藏 API」列表中

### 8.2 送入 Analyzer

抓取（Run1/Run2）完成后，`afterCrawlComplete` 自动执行：

```
对 discoveredApiListPanel 中每个 DiscoveredEndpoint：
  rr = SyntheticRequestBuilder.buildAndExecute(ep, baseUrl, headers)
  performAuthAnalyzerRequest(rr)
```

发现的隐藏 API 与抓取到的非隐藏 API 一并完成越权检测。

---

## 九、数据流小结

| 阶段 | 输入 | 输出 |
|------|------|------|
| JS 提取 | driver, baseUrl | List<DiscoveredEndpoint>（Source: JS） |
| Source Map | scriptUrl | 追加到 result（Source: SOURCE_MAP） |
| Swagger 探测 | baseUrl | List<DiscoveredEndpoint>（Source: SWAGGER，含 EndpointSchema） |
| GraphQL 内省 | graphqlUrl | List<DiscoveredEndpoint>（Source: GRAPHQL，含 graphqlOperation） |
| 合成请求 | endpoint, baseUrl, headers | IHttpRequestResponse |
| 越权检测 | IHttpRequestResponse | 主表 + SAME/SIMILAR/DIFFERENT 判定 |

---

## 十、局限与说明

| 项目 | 说明 |
|------|------|
| **误报** | 正则可能匹配注释、字符串常量中的路径，非实际 API 调用 |
| **非隐藏** | 部分 API 可能由页面正常触发，仍会被发现并列出 |
| **真正隐藏** | 建议对比「JS 发现的 API」与「抓取时实际请求的 API」，差集为更可疑的隐藏 API |
| **路径参数** | 无 schema 时占位符仅替换为 "1"，未做多值探测 |
| **动态 script** | 已覆盖 import()、AMD、Worker、manifest、chunk、DOM 二次收集；未覆盖 require.ensure、完全动态路径、iframe。见 `HiddenApiDiscovery-Dynamic-Loading-Audit.md` |
| **YAML** | SWAGGER_PATHS 含 `.yaml`，已支持 SnakeYAML 解析 |

---

## 十一、技术规格与复现

完整的数据结构、上下游、审计要点与复现步骤见 `docs/HiddenApiDiscovery-Technical-Spec.md`。
