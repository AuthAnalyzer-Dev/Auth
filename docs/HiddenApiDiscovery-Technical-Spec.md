# 隐藏 API 发现功能 - 技术规格与复现指南

本文档面向技术人员，用于完整复现、审计「发现隐藏 API」功能的实现，验证方法的正确性与严谨性。

---

## 一、功能概述

| 项目 | 说明 |
|------|------|
| **目标** | 发现页面上无入口的 API，送入 Analyzer 进行越权检测 |
| **发现方式** | ① 从 JS 提取 ② Source Map 二次提取 ③ 从 Swagger/Actuator 探测 ④ GraphQL 内省 |
| **下游** | 构造 HTTP 请求 → `performAuthAnalyzerRequest` → RequestController.analyze → 主表 + 越权判定 |

---

## 二、数据流与上下游

```
┌─────────────────────────────────────────────────────────────────────────────┐
│ 上游输入                                                                      │
├─────────────────────────────────────────────────────────────────────────────┤
│ • Target URL (String)           - 目标页面，用于 baseOrigin、Cookie 注入      │
│ • Header(s) to Replace (String) - Original 认证信息，格式: "Cookie: xxx\n..." │
│ • 勾选: 从 JS 提取 / 从 Swagger 探测                                          │
└─────────────────────────────────────────────────────────────────────────────┘
                                        │
                                        ▼
┌─────────────────────────────────────────────────────────────────────────────┐
│ 发现阶段                                                                      │
├─────────────────────────────────────────────────────────────────────────────┤
│ JS 提取:    WebDriver → 注入 Cookie → 导航 → <script> 解析 → 正则提取 → Set   │
│ Source Map: scriptUrl + ".map" → sourcesContent → 正则二次提取 → Set          │
│ Swagger:    HTTP GET 探测 SWAGGER_PATHS → 解析 JSON/Actuator → Set           │
│ GraphQL:    POST Introspection → 解析 __schema → Query/Mutation → Set         │
│ 输出:       List<DiscoveredEndpoint> (去重: method+path+graphqlOperation)     │
└─────────────────────────────────────────────────────────────────────────────┘
                                        │
                                        ▼
┌─────────────────────────────────────────────────────────────────────────────┐
│ 展示与存储                                                                    │
├─────────────────────────────────────────────────────────────────────────────┤
│ DiscoveredApiListPanel / DiscoveredApiTableModel                             │
│ • endpoints: List<DiscoveredEndpoint>                                        │
│ • setEndpoints / addEndpoints / clear / getAllEndpoints                      │
└─────────────────────────────────────────────────────────────────────────────┘
                                        │
                                        ▼
┌─────────────────────────────────────────────────────────────────────────────┐
│ 下游：送入 Analyzer（抓取完成后自动触发）                                      │
├─────────────────────────────────────────────────────────────────────────────┤
│ 对每个 DiscoveredEndpoint:                                                   │
│   rr = SyntheticRequestBuilder.buildAndExecute(ep, baseUrl, headers)         │
│   CurrentConfig.performAuthAnalyzerRequest(rr)                               │
│     → RequestController.analyze(rr)                                          │
│       → 各 Session 重放、比较 → OriginalRequestResponse 入主表               │
└─────────────────────────────────────────────────────────────────────────────┘
```

---

## 三、数据结构

### 3.1 DiscoveredEndpoint

| 字段 | 类型 | 说明 |
|------|------|------|
| method | String | HTTP 方法，默认 "GET"，构造时 toUpperCase |
| path | String | 路径，如 `/v3/api/news/v1/mylist` |
| source | Source | JS、SWAGGER、SOURCE_MAP、GRAPHQL |
| endpointSchema | EndpointSchema | 仅 Swagger 来源时有值，用于智能参数替换和 Body 生成 |
| graphqlOperation | String | 仅 GraphQL 来源时可能有值，用于构造 query body |

**相等性**：`equals` 与 `hashCode` 基于 `method + path + graphqlOperation`，用于去重。

```java
// 位置: uitesting/discovery/DiscoveredEndpoint.java
@Override
public boolean equals(Object o) {
    DiscoveredEndpoint that = (DiscoveredEndpoint) o;
    if (!method.equals(that.method) || !path.equals(that.path)) return false;
    String g1 = graphqlOperation, g2 = that.graphqlOperation;
    return (g1 == null ? g2 == null : g1.equals(g2));
}
@Override
public int hashCode() {
    int h = 31 * method.hashCode() + path.hashCode();
    return graphqlOperation != null ? 31 * h + graphqlOperation.hashCode() : h;
}
```

### 3.2 EndpointSchema

| 字段 | 类型 | 说明 |
|------|------|------|
| pathParams | Map<String, ParamSchema> | 路径参数 name → type/format |
| requestBodySchema | JsonObject | OpenAPI requestBody schema |

### 3.3 上游配置（ControlsPanel）

| 配置项 | 来源 | 用途 |
|--------|------|------|
| targetUrl | targetUrlField.getText() | baseOrigin、buildFullUrl |
| headersToReplace | headersToReplaceText.getText() | Cookie 注入、buildRequest 头注入 |
| fromJs / fromSwagger | discoverFromJsCheck / discoverFromSwaggerCheck | 控制执行分支 |

### 3.4 下游接口（Burp / RequestController）

| 接口 | 输入 | 输出 |
|------|------|------|
| IHttpRequestResponse | request + response + httpService | 与 Proxy 流量格式一致 |
| performAuthAnalyzerRequest(rr) | IHttpRequestResponse | 异步入队，RequestController.analyze 处理 |
| OriginalRequestResponse | mapId, rr, method, url, ... | 主表一行，endpointKey = method+host+url |

---

## 四、核心算法

### 4.1 从 JS 提取（discoverFromJs）

**输入**：WebDriver driver, String baseUrl, DiscoveryCallback callback  
**输出**：List<DiscoveredEndpoint>

```
1. baseOrigin = getBaseOrigin(baseUrl)
   例: https://example.com/page → https://example.com

2. scripts = driver.findElements(By.tagName("script"))

3. FOR EACH script IN scripts:
   IF script.src 非空:
     scriptUrl = toAbsoluteUrl(src, baseOrigin)
     content = fetchUrlContent(scriptUrl)   // HTTP GET, 3s 超时
     IF content 非空: extractFromJsContent(content, result, JS)
     extractFromSourceMap(scriptUrl, result, callback)
   ELSE:
     content = script.getAttribute("innerHTML")
     IF content 非空: extractFromJsContent(content, result, JS)

4. RETURN result (LinkedHashSet 保证去重与顺序)
```

**extractFromJsContent**：

```
FOR EACH pattern IN JS_PATTERNS:
  matcher = pattern.matcher(content)
  WHILE matcher.find():
    path = (pattern == axios) ? group(2) : group(1)
    method = (pattern == axios) ? group(1).toUpperCase() : "GET"
    IF path != null AND isRelevantPath(path):
      result.add(DiscoveredEndpoint(method, path, source))
```

**isRelevantPath(path)**：

```
RETURN false IF: path==null OR len<2 OR startsWith("//") OR
  contains(".css") OR contains(".png") OR contains(".jpg") OR contains(".ico")
RETURN true IF: startsWith("/api") OR startsWith("/v") OR startsWith("/internal")
```

**正则模式（Java Pattern 字符串）**：

| # | 模式 | 用途 |
|---|------|------|
| 1 | `fetch\\s*\\(\\s*['"\`](/[^'"\`\\s]+)['"\`]` | fetch('/api/xxx') |
| 2 | `axios\\.(get\|post\|put\|delete\|patch)\\s*\\(\\s*['"\`](/[^'"\`\\s]+)['"\`]` | axios.get('/api/xxx') |
| 3 | `url\\s*:\\s*['"\`](/[^'"\`\\s]+)['"\`]` | url: '/api/xxx' |
| 4 | `['"\`](/api/[^'"\`\\s?]*)[?"'\`]?` | "/api/xxx" |
| 5 | `['"\`](/v[0-9]+/[^'"\`\\s?]*)[?"'\`]?` | "/v3/api/xxx" |

### 4.2 Source Map 提取（extractFromSourceMap）

```
mapUrl = scriptUrl.endsWith(".map") ? scriptUrl : scriptUrl + ".map"
content = fetchUrlContent(mapUrl)
root = JsonParser.parseString(content)
sourcesContent = root.getAsJsonArray("sourcesContent")
FOR EACH el IN sourcesContent:
  IF el.isJsonPrimitive(): extractFromJsContent(el.getAsString(), result, SOURCE_MAP)
```

### 4.3 从 Swagger 探测（discoverFromSwagger）

**输入**：String baseUrl, DiscoveryCallback callback  
**输出**：List<DiscoveredEndpoint>

```
1. baseOrigin = getBaseOrigin(baseUrl)

2. FOR docPath IN SWAGGER_PATHS:
   docUrl = baseOrigin + docPath
   content = fetchUrlContent(docUrl)
   IF content 为空: CONTINUE

   IF docPath 含 "graphql":
     result.addAll(discoverFromGraphQLIntrospection(docUrl, callback))
     CONTINUE
   IF docPath 含 "actuator/mappings":
     result.addAll(discoverFromActuatorMappings(content, baseOrigin, callback))
     CONTINUE

   IF content 不以 "{" 开头: CONTINUE   // 非 JSON
   root = JsonParser.parseString(content).getAsJsonObject()
   paths = root.getAsJsonObject("paths")
   IF paths == null: CONTINUE

   FOR path IN paths.keySet():
     pathObj = paths.getAsJsonObject(path)
     FOR method IN pathObj.keySet():
       IF method IN {get,post,put,delete,patch}:
         schema = parseEndpointSchema(pathObj, method)
         result.add(DiscoveredEndpoint(method.toUpperCase(), path, SWAGGER, schema))

   BREAK   // 命中即停止

3. RETURN result
```

**SWAGGER_PATHS**：/swagger.json, /swagger/v1/swagger.json, /v2/api-docs, /v3/api-docs, /v3/api-docs.yaml, /api-docs, /api/swagger.json, /openapi.json, /openapi.yaml, /api/openapi.json, /actuator/mappings, /actuator/env, /graphql, /v1/graphql, /api/graphql

### 4.4 GraphQL 内省（discoverFromGraphQLIntrospection）

```
POST graphqlUrl, body = Introspection Query
resp = fetchUrlContentPost(graphqlUrl, query, "application/json")
IF resp 不含 "__schema": RETURN []

schema = data.__schema
queryTypeName = schema.queryType.name
mutationTypeName = schema.mutationType.name

result.add(DiscoveredEndpoint("POST", path, GRAPHQL, null, null))   // 基础端点

FOR type IN schema.types:
  IF type.kind != "OBJECT" OR type.name 以 "__" 开头: CONTINUE
  IF type.name != queryTypeName AND type.name != mutationTypeName: CONTINUE
  FOR field IN type.fields:
    result.add(DiscoveredEndpoint("POST", path, GRAPHQL, null, field.name))
```

### 4.5 合成请求构造（SyntheticRequestBuilder.buildAndExecute）

**输入**：DiscoveredEndpoint endpoint, String baseUrl, String headersToReplace, Consumer<String> log  
**输出**：IHttpRequestResponse 或 null

```
1. fullUrl = buildFullUrl(baseUrl, endpoint)
   - 若有 EndpointSchema 且 pathParams 非空:
     path = SchemaBasedBodyGenerator.replacePathParams(path, schema.getPathParams())
   - 否则: path = path.replaceAll("\\{[^}]+\\}", "1")
   - fullUrl = origin + path

2. url = new URL(fullUrl)
   service = buildHttpService(host, port, isHttps)

3. requestBytes = buildRequest(helpers, url, endpoint, headersToReplace)
   - 若 method 为 POST/PUT/PATCH:
     - GraphQL: body = {"query":"query {op} { __typename }"} 或 {"query":"{ __typename }"}
     - 有 requestBodySchema: body = SchemaBasedBodyGenerator.generateRequestBody(schema)
     - 否则: body = "{}"
   - 若 method 为 GET: body = 空
   - baseRequest = helpers.buildHttpRequest(url)
   - 若 method != GET: 替换首行请求行为 "METHOD path HTTP/1.1"
   - 解析 headersToReplace 每行 "Name: Value"，按 header 名匹配替换或追加

4. rr = makeHttpRequest(service, requestBytes)
5. RETURN rr
```

---

## 五、关键代码位置

| 功能 | 类 | 方法/常量 |
|------|-----|-----------|
| DiscoveredEndpoint | `uitesting/discovery/DiscoveredEndpoint.java` | 全类 |
| EndpointSchema | `uitesting/discovery/EndpointSchema.java` | 全类 |
| SchemaBasedBodyGenerator | `uitesting/discovery/SchemaBasedBodyGenerator.java` | replacePathParams, generateRequestBody |
| JS 提取 | `uitesting/discovery/ApiDiscoveryService.java` | discoverFromJs, extractFromJsContent, isRelevantPath |
| Source Map | `uitesting/discovery/ApiDiscoveryService.java` | extractFromSourceMap |
| Swagger 探测 | `uitesting/discovery/ApiDiscoveryService.java` | discoverFromSwagger |
| Actuator 解析 | `uitesting/discovery/ApiDiscoveryService.java` | discoverFromActuatorMappings |
| GraphQL 内省 | `uitesting/discovery/ApiDiscoveryService.java` | discoverFromGraphQLIntrospection |
| 正则与路径 | `uitesting/discovery/ApiDiscoveryService.java` | JS_PATTERNS, SWAGGER_PATHS |
| HTTP 获取 | `uitesting/discovery/ApiDiscoveryService.java` | fetchUrlContent, fetchUrlContentPost |
| 合成请求 | `uitesting/discovery/SyntheticRequestBuilder.java` | buildAndExecute, buildFullUrl, buildRequest |
| 列表展示 | `gui/UITesting/DiscoveredApiListPanel.java` | setEndpoints, clear, getAllEndpoints |
| 发现触发 | `gui/UITesting/UITestingPanel.java` | onDiscoverClick |
| 送入 Analyzer | `gui/UITesting/UITestingPanel.java` | sendDiscoveredApisToAnalyzer |
| 抓取完成回调 | `gui/UITesting/UITestingPanel.java` | afterCrawlComplete |
| 越权分析 | `controller/RequestController.java` | analyze |
| 请求入队 | `util/CurrentConfig.java` | performAuthAnalyzerRequest |

---

## 六、审计要点

### 6.1 正确性

| 检查项 | 验证方法 |
|--------|----------|
| JS 正则是否漏报 | 在目标 JS 中手工加入 `fetch('/api/test')`，确认能发现 |
| JS 正则是否误报 | 检查注释、字符串常量中的 `/api/xxx` 是否被误匹配 |
| Source Map | 确认 scriptUrl + ".map" 可访问时，sourcesContent 被正确解析并二次提取 |
| 路径过滤 | 确认 `.css`、`.png` 等被排除，`/api`、`/v`、`/internal` 被保留 |
| Swagger 解析 | 对标准 OpenAPI 2.0/3.0 文档验证 paths 解析正确 |
| Actuator 解析 | 对 Spring Boot actuator/mappings 验证 predicate 解析正确 |
| GraphQL 内省 | 对 GraphQL 端点验证 Introspection 返回的 Query/Mutation 被正确提取 |
| 路径参数 | 有 schema 时按 type/format 替换，无 schema 时 `/api/user/{id}` → `/api/user/1` |
| RequestBody | 有 schema 时按 properties 生成 JSON，GraphQL 时生成 query body |
| 请求头注入 | 验证 Cookie 等正确注入，服务端能识别身份 |

### 6.2 严谨性

| 检查项 | 说明 |
|--------|------|
| 去重 | DiscoveredEndpoint.equals 基于 method+path+graphqlOperation，LinkedHashSet 去重 |
| 空值 | endpoint/baseUrl 为 null 时 buildAndExecute 返回 null，不抛异常 |
| 超时 | fetchUrlContent 使用 3s connect/read，避免长时间阻塞 |
| 线程 | 发现在后台线程，UI 更新经 SwingUtilities.invokeLater |
| 对称采集 | sendDiscoveredApisToAnalyzer 使用当前 Original headers，Run1/Run2 各自正确 |

### 6.3 与 Analyzer 的兼容性

| 检查项 | 说明 |
|--------|------|
| IHttpRequestResponse 格式 | buildAndExecute 返回的 rr 含 request、response、httpService |
| 无 response 时 | RequestController 支持 response==null，会标记 NA |
| endpointKey | OriginalRequestResponse 使用 method+host+url，与 normalizeEndpointUrl 一致 |

---

## 七、复现步骤（最小可验证路径）

1. **环境**：Burp + AuthAnalyzer 扩展，目标站点可访问
2. **配置**：Target URL、Header(s) to Replace（含有效 Cookie）
3. **仅 JS**：勾选「从 JS 提取」，点击「发现隐藏 API」→ 浏览器启动 → 列表更新
4. **仅 Swagger**：勾选「从 Swagger 探测」，目标有 `/swagger.json` 等 → 列表更新
5. **GraphQL**：目标有 `/graphql` 且开启内省 → 探测时自动发现 Query/Mutation
6. **送入 Analyzer**：点击「抓取并点击」→ 抓取完成 → 发现列表中的 API 自动入主表
7. **验证**：主表出现对应请求，各 Session 有 SAME/SIMILAR/DIFFERENT 判定

---

## 八、局限（审计时需知）

- **误报**：正则可能匹配注释、文档字符串中的路径
- **非隐藏**：部分 API 由页面正常触发，仍会被发现
- **路径参数**：无 schema 时 `{id}` 仅替换为 `"1"`，未做多值探测
- **动态 script**：已覆盖 import()、AMD require、Worker、manifest、chunk、DOM 二次收集；详见 `HiddenApiDiscovery-Dynamic-Loading-Audit.md`。未覆盖：require.ensure、完全动态路径、iframe 子 frame
- **YAML**：SWAGGER_PATHS 含 `.yaml`，已支持 SnakeYAML 解析

---

**文档版本**：1.1  
**最后更新**：2026-02-26
