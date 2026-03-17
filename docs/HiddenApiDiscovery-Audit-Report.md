# 隐藏 API 发现模块 - 审计报告

**审计日期**：2026-02-26  
**最后更新**：2026-03-17  
**审计范围**：ApiDiscoveryService、SyntheticRequestBuilder、SchemaBasedBodyGenerator、DiscoveredEndpoint

---

## 一、审计发现的问题

### 1. JS_PATTERNS 正则覆盖率不足

| 问题 | 说明 |
|------|------|
| **ES6 模板字符串** | 模式已支持反引号 `` ` `` 包裹的静态路径，如 `` fetch(`/api/xxx`) ``，但**动态拼接**的模板字符串如 `` fetch(`/api/${id}`) `` 无法匹配，因路径被变量分割。 |
| **动态拼接路径** | `"/api/" + basePath + "/list"`、`\`/api/\${id}\`` 等运行时拼接的路径无法被当前正则捕获。 |
| **$.ajax / jQuery** | 已有 `url: '/api/xxx'` 模式，但 `$.get('/api/xxx')`、`$.post(url)` 等简写形式未覆盖。 |
| **相对路径** | 当前模式要求路径以 `/` 开头，`api/user` 或 `./api/user` 会漏报。 |

---

### 2. SyntheticRequestBuilder / SchemaBasedBodyGenerator 潜在 NPE

| 位置 | 风险 | 状态 |
|------|------|------|
| **parseEndpointSchema** | `content.getAsJsonObject("application/json")` 等可能 NPE | ✅ 已加空值检查 |
| **buildFromSchema** | `$ref` 循环引用（A→B→A）导致栈溢出 | ✅ 已加 visitedRefs 防护 |
| **discoverFromGraphQLIntrospection** | `queryType.name` 缺失时 NPE | ✅ 已加空值检查 |
| **复杂嵌套 JSON** | 递归深度过大 | ✅ 已限制 8 层 |

---

### 3. fetchUrlContent 与 UI 线程

| 结论 | 说明 |
|------|------|
| **不阻塞 UI** | `onDiscoverClick` 已在后台线程执行，不会阻塞 Swing 主线程。 |
| **异常可观测** | ✅ 已通过 `BurpExtender.callbacks.printError()` 输出到 Extender 标签页；区分 404、Timeout 等具体原因。 |

---

### 4. 去重逻辑与 Query String

| 问题 | 说明 |
|------|------|
| **当前行为** | `equals`/`hashCode` 基于 `method + path + graphqlOperation`，path 含 query 时如 `/api/foo?id=1` 与 `/api/foo?id=2` 会视为不同端点。 |
| **影响** | 合理——同一 path 不同 query 可能对应不同资源；但若 JS 中提取到 `/api/foo` 与 `/api/foo?page=1`，会重复探测。 |

---

### 5. 无最大发现数量限制

| 问题 | 状态 |
|------|------|
| **Swagger / Actuator / GraphQL 过大** | ✅ 已设 MAX_DISCOVERED_LIMIT=2000，并在 JS、Swagger、Actuator、GraphQL 所有入口生效。 |

---

## 二、修改方案概要与实现状态

### 核心模块

| 模块 | 实现内容 |
|------|----------|
| **SchemaBasedBodyGenerator** | 路径参数按 type/format 替换；RequestBody 支持 `required` 优先；`$ref` 解析（含 components）；**$ref 循环引用防护**（visitedRefs）；递归深度限制 8 层；空值防护。 |
| **ApiDiscoveryService** | Source Map 二次提取；manifest.json / asset-manifest.json 探测；Webpack chunk 探测；GraphQL 深度发现（Arguments + 类型）；YAML 解析（SnakeYAML）；MAX_DISCOVERED_LIMIT=2000 全覆盖；fetchUrlContent 异常通过 printError 输出（404、Timeout 等）；**Source Map 额外发现数量统计**。 |
| **SyntheticRequestBuilder** | 传递 components 给 generateRequestBody；**GraphQL 使用 variables 格式**：`{"query":"query($id: ID!) { getUser(id: $id) { __typename } }","variables":{"id":"1"}}`；按参数类型生成 Mock（ID→"1", Int→1, Boolean→true 等）。 |
| **EndpointSchema** | 新增 `components` 字段用于 $ref 解析。 |
| **DiscoveredEndpoint** | 新增 `graphqlArgNames`、`graphqlArgTypes`、`graphqlOperationType`。 |

### 依赖

- ✅ SnakeYAML 2.0（YAML 解析）
