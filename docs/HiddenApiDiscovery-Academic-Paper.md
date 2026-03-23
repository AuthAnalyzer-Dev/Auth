# 隐藏 API 发现完整策略：面向 Web 应用越权检测的自动化发现方法

**文档用途**：论文展示 / 课程教学  
**目标受众**：网络安全专业教师与本科生  
**最后更新**：2026-02-26

---

## 一、背景与动机

### 1.1 什么是隐藏 API？

在现代 Web 应用中，前端页面通过 **API（应用程序接口）** 与后端服务器通信。用户点击按钮、填写表单时，浏览器会向这些 API 发送请求。然而，并非所有 API 都会在用户操作时被触发。

**隐藏 API** 是指：页面上没有明显入口（如链接、按钮、表单）会触发的接口。它们可能存在于：

- JavaScript 代码中（如 `fetch('/api/admin/users')`）
- 开发文档中（如 Swagger、OpenAPI）
- 构建产物中（如 Source Map、manifest.json）
- GraphQL Schema 中

普通用户浏览时不会发起这些请求，但攻击者一旦发现，就可能利用它们进行**越权访问**（访问本不该有的数据或操作）。

### 1.2 为什么需要自动化发现？

| 问题 | 说明 |
|------|------|
| **手工遗漏** | 大型应用有数百个 JS 文件，人工逐一查看不现实 |
| **混淆与压缩** | 生产环境 JS 往往被压缩，难以阅读 |
| **文档暴露** | Swagger、Actuator 等可能未做访问控制，暴露完整接口列表 |
| **越权检测前置** | 安全测试需先“发现”接口，才能进行越权分析 |

因此，我们需要一套**自动化、多源、健壮**的发现策略，为后续越权检测提供输入。

---

## 二、整体架构

```
┌─────────────────────────────────────────────────────────────────────────────┐
│  用户输入：目标 URL、认证信息（Cookie 等）、发现方式勾选                         │
└─────────────────────────────────────────────────────────────────────────────┘
                                        │
                                        ▼
┌─────────────────────────────────────────────────────────────────────────────┐
│  发现阶段（多源并行）                                                          │
│  ┌─────────────┐  ┌─────────────┐  ┌─────────────┐  ┌─────────────┐          │
│  │ JS 提取     │  │ Source Map  │  │ Swagger 探测 │  │ GraphQL 内省 │          │
│  │ (含静态降级) │  │ 二次提取    │  │ Actuator    │  │             │          │
│  └─────────────┘  └─────────────┘  └─────────────┘  └─────────────┘          │
└─────────────────────────────────────────────────────────────────────────────┘
                                        │
                                        ▼
┌─────────────────────────────────────────────────────────────────────────────┐
│  去重与展示：按 method + path 去重，输出 List<DiscoveredEndpoint>               │
└─────────────────────────────────────────────────────────────────────────────┘
                                        │
                                        ▼
┌─────────────────────────────────────────────────────────────────────────────┐
│  下游：构造 HTTP 请求 → 送入越权分析器 → 判定 SAME / SIMILAR / DIFFERENT       │
└─────────────────────────────────────────────────────────────────────────────┘
```

---

## 三、发现策略详解

### 3.1 从 JavaScript 提取（核心路径）

#### 3.1.1 基本思路

前端代码中常出现如下形式的 API 调用：

```javascript
fetch('/api/user/profile');
axios.get('/v3/api/news/list');
$.ajax({ url: '/api/order/create', method: 'POST' });
```

通过**正则表达式**扫描 JS 源码，可提取出路径（如 `/api/user/profile`）和 HTTP 方法（如 GET、POST）。

#### 3.1.2 正则模式

| 序号 | 匹配示例 | 说明 |
|------|----------|------|
| 1 | `fetch('/api/xxx')` | 原生 fetch API |
| 2 | `axios.get('/api/xxx')` | Axios 库，可识别 get/post/put/delete/patch |
| 3 | `url: '/api/xxx'` | jQuery / $.ajax 配置 |
| 4 | `"/api/xxx"` | 以 `/api` 开头的字符串字面量 |
| 5 | `"/v3/api/xxx"` | 以版本号开头的路径，如 `/v3/api/...` |

支持单引号、双引号、反引号包裹的路径。

#### 3.1.3 路径过滤（isRelevantPath）

并非所有匹配到的路径都是 API，需过滤：

- **排除**：`.css`、`.png`、`.jpg`、`.ico`、以 `//` 开头的绝对 URL
- **保留**：以 `/api`、`/v`、`/internal` 开头的路径

#### 3.1.4 脚本来源

| 来源 | 获取方式 |
|------|----------|
| **外部脚本** | `<script src="https://example.com/main.js">` → 通过 URL 获取内容 |
| **内联脚本** | `<script>fetch('/api/xxx')</script>` → 直接读取 innerHTML |
| **Manifest** | `/manifest.json`、`/asset-manifest.json` 中的 `files`、`entrypoints`、`main` 字段 |
| **Chunk 脚本** | 从 JS 中正则匹配 `chunk`、`main`、`bundle`、`runtime`、`vendor` 等 URL，递归获取（最多 3 层） |

---

### 3.2 动态提取与静态降级（健壮性保障）

#### 3.2.1 问题背景

JS 提取通常依赖**浏览器自动化**（如 Selenium WebDriver）：启动浏览器 → 注入 Cookie → 导航至目标页面 → 解析 `<script>` 标签。若浏览器崩溃或 session 失效（如 `invalid session id`），整个流程会中断。

#### 3.2.2 降级策略：单脚本级、优雅降级

采用**“动态尝试 → 失败则静态兜底”**的策略，而非一处报错就停止：

1. **Session 存活判断**：在提取每个 `<script>` 前，调用 `isDriverAlive(driver)`，通过 `driver.getWindowHandles()` 判断 session 是否有效。
2. **动态提取**：若 driver 存活，通过 `script.getAttribute("src")` 和 `script.getAttribute("innerHTML")` 获取脚本信息。
3. **失败触发降级**：若 driver 失效或抛出 `WebDriverException`，立即切换至**静态提取**：
   - 用 HTTP GET 直接请求页面 URL，获取 HTML
   - 用 Jsoup 解析 HTML，提取 `<script src>` 和 `<script>` 内联内容
   - 对每个脚本 URL，用 HTTP GET 获取 JS 源码（支持 Header 注入）
4. **Header 注入**：静态模式下，将用户配置的 `Header(s) to Replace`（如 Cookie、Authorization）注入到 HTTP 请求中，确保需要认证的 JS 文件仍可获取。

#### 3.2.3 流程示意

```
对每个 <script> 标签：
  ├─ isDriverAlive(driver) ?
  │   ├─ 是 → 用 driver 获取 src / innerHTML
  │   └─ 否 → 记录日志「浏览器会话已失效，切换至静态提取模式」
  │
  ├─ 获取内容时抛出 WebDriverException ?
  │   └─ 是 → 同上，切换至静态提取
  │
  └─ 静态提取：
      ├─ fetchPageHtml(pageUrl) → 获取页面 HTML
      ├─ parseScriptTagsFromHtml(html) → 解析出 script 列表
      └─ 对每个 script：fetchStaticContent(url, headersToReplace) → 获取 JS 源码
```

---

### 3.3 Source Map 二次提取

#### 3.3.1 为什么需要 Source Map？

生产环境 JS 往往经过**压缩/混淆**，如：

```javascript
// 原始代码
fetch('/api/user/profile');

// 压缩后
a("/api/user/profile");
```

正则难以匹配 `a("/api/user/profile")` 这类形式。**Source Map**（`.map` 文件）记录了压缩代码与原始代码的对应关系，其中 `sourcesContent` 数组包含原始未混淆源码。

#### 3.3.2 提取流程

1. 对每个已获取的 JS 文件 URL，构造 `scriptUrl + ".map"`（若已是 `.map` 则不变）
2. HTTP GET 获取 Source Map 内容
3. 解析 JSON，取出 `sourcesContent` 数组
4. 对数组中每个元素（原始源码字符串），调用与 JS 提取**相同的正则**进行二次提取
5. 将新发现的端点标记为 `SOURCE_MAP` 来源

---

### 3.4 从 Swagger / OpenAPI 探测

#### 3.4.1 探测路径

按顺序尝试以下常见文档路径，**命中即停止**：

| 路径 | 说明 |
|------|------|
| /swagger.json, /swagger/v1/swagger.json | Swagger 2.0 |
| /v2/api-docs, /v3/api-docs | Spring Boot 常用 |
| /api-docs, /api/swagger.json | 通用 |
| /openapi.json, /openapi.yaml | OpenAPI 3.0 |
| /actuator/mappings, /actuator/env | Spring Boot Actuator |
| /graphql, /v1/graphql, /api/graphql | GraphQL（走内省分支） |

支持 JSON 与 YAML 格式。

#### 3.4.2 解析逻辑

- **Swagger/OpenAPI**：解析 `paths` 对象，提取每个 path 下的 `get`、`post`、`put`、`delete`、`patch`，同时解析 `parameters`、`requestBody` 等，用于后续智能构造请求。
- **Actuator**：解析 `contexts.*.mappings.dispatcherServlets.*`，从 `predicate` 字段提取 `GET /api/xxx` 形式的 method 与 path。

---

### 3.5 GraphQL 内省

#### 3.5.1 背景

GraphQL 通常只有一个端点（如 `/graphql`），所有操作通过 POST 请求的 body 区分。**Introspection** 是 GraphQL 标准能力，可查询完整 Schema。

#### 3.5.2 流程

1. 向 GraphQL 端点发送 **Introspection Query**（标准查询格式）
2. 解析返回的 `__schema`，获取 `queryType`、`mutationType` 名称
3. 遍历 `types`，筛选出与 queryType/mutationType 对应的 OBJECT 类型
4. 提取每个 type 的 `fields` 的 `name`，作为 operation 名称
5. 生成：
   - 一个基础端点：`POST /graphql`（无 operation）
   - 每个 operation 一个端点：`POST /graphql` + `graphqlOperation = fieldName`
6. 若有 `args`，记录参数名与类型，用于构造带 variables 的请求体

---

## 四、合成请求与越权检测

### 4.1 请求构造

发现的端点需构造为可发送的 HTTP 请求：

| 场景 | 处理方式 |
|------|----------|
| **路径参数** | 有 Schema 时按 type/format 生成（如 uuid→随机 UUID，integer→1）；无 Schema 时 `{id}` → `1` |
| **RequestBody** | 有 Schema 时按 properties 生成 JSON；GraphQL 时生成 `{"query":"...","variables":{...}}`；否则 `{}` |
| **请求头** | 注入用户配置的 Cookie、Authorization 等 |

### 4.2 送入越权分析器

构造好的请求送入 Analyzer，与抓取到的“正常”请求一起，进行多 Session 重放与比较，判定 `SAME`、`SIMILAR`、`DIFFERENT`，识别越权风险。

---

## 五、策略小结

| 发现方式 | 输入 | 输出 | 特点 |
|----------|------|------|------|
| **JS 提取** | 页面 URL、WebDriver、Headers | 从 JS 源码正则提取 | 覆盖 fetch、axios、jQuery 等；支持 Manifest、Chunk 递归 |
| **静态降级** | 页面 URL、Headers | 同上 | 浏览器失效时用 HTTP + Jsoup 兜底，单脚本级降级 |
| **Source Map** | JS 文件 URL | 从 sourcesContent 二次提取 | 应对压缩/混淆 |
| **Swagger 探测** | 基础 URL | 从 paths 解析 | 文档完整、含 Schema |
| **Actuator** | 基础 URL | 从 mappings 解析 | Spring Boot 特有 |
| **GraphQL 内省** | GraphQL URL | Query/Mutation 名称 | 单一端点、多 operation |

---

## 六、局限与改进方向

| 局限 | 说明 |
|------|------|
| **已覆盖** | 模板字符串 `` `/api/${id}` `` → 归一化为 `/api/1`；相对路径 `api/xxx`、`./api/xxx`；字符串拼接 `"/api/" + x`；`$.get`/`$.post`；`/internal` |
| **已覆盖** | 动态加载 script：DOM 等待 2.5s 二次收集；`import()`（含 Webpack 魔法注释）；AMD `require`；`new Worker`；manifest/chunk；通用 `.js` 路径。详见 `HiddenApiDiscovery-Dynamic-Loading-Audit.md` |
| **未覆盖** | `require.ensure`、完全动态路径（变量拼接）、iframe 子 frame |
| **误报** | 注释、文档字符串中的路径可能被误匹配 |
| **路径参数** | 无 Schema 时占位符统一替换为 `"1"`，未做多值探测 |
| **YAML** | 已支持 YAML 解析，但部分边缘格式可能需额外处理 |

---

## 七、术语表（供本科生参考）

| 术语 | 解释 |
|------|------|
| **API** | 应用程序接口，前后端通信的约定 |
| **越权** | 用户访问或操作了本不该有的资源 |
| **Source Map** | 压缩代码与原始代码的映射文件 |
| **Swagger / OpenAPI** | 描述 REST API 的规范与文档格式 |
| **GraphQL** | 一种 API 查询语言，通常单端点、通过 body 区分操作 |
| **Introspection** | GraphQL 的“自省”能力，可查询 Schema |
| **Actuator** | Spring Boot 提供的运维端点，可能暴露 mappings 等信息 |
| **WebDriver** | 浏览器自动化接口（如 Selenium） |
| **正则表达式** | 用于匹配文本模式的表达式 |

---

**文档版本**：1.0  
**对应实现**：AuthAnalyzer 隐藏 API 发现模块
