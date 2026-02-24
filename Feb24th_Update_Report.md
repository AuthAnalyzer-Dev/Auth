# AuthAnalyzer 更新报告

**日期**：2026-02-24  
**范围**：UI Testing 点击策略修复与越权检测增强

---

## 一、更新概览

| 类别 | 更新内容 |
|------|----------|
| 严重修复 | Stale Element 引用导致第二个及之后链接无法点击 |
| 越权增强 | 同域过滤：跳过 mailto/tel/外部域名链接 |
| 越权增强 | 扩展可点击元素：`<button>`、`input[type=submit/button]` |
| 体验优化 | 点击前 `scrollIntoView` 确保元素在视口内 |
| 代码清理 | 移除冗余 `visited` 集合及未使用 import |
| 修复 | 「未找到元素」：waitForPageReady、图标优先 href、normalizeKey、延长等待、多次重试、finally 强制回 target |
| 修复 | 大量标签页：`target="_blank"` 链接在点击前移除，改为当前标签页打开 |
| 修复 | Cookie 无法登录：`isSecure(true)`、清除旧 Cookie、新增 access_token（父域 .ruc.edu.cn） |
| 修复 | 清空表格失灵：在 EDT 上执行 clearTable，Analyzer 运行时避免后台线程更新 UI |

---

## 二、详细更新清单

### 2.1 修改的文件

#### `UITestingPanel.java`

**2.1.1 Stale Element 修复**

- **问题**：每次 `driver.get(targetPage)` 后页面重新加载，之前收集的 `WebElement` 引用失效，从第二个链接起抛出 `StaleElementReferenceException`。
- **方案**：第一轮仅收集 key（text 或 href），不保存 `WebElement`；第二轮每次循环内在当前页重新查找元素再点击。
- **新增方法**：`findAnchorByKey(driver, key)`、`findClickableByKey(driver, key)`、`findButtonByKey(driver, key)`。

**2.1.2 同域过滤（越权检测）**

- **新增方法**：`isHrefInScopeForAuth(href, targetDomain)`
- **排除**：`mailto:`、`tel:`、`data:`、`blob:` 等非 HTTP 链接。
- **保留**：`javascript:`、`#`（可能触发 SPA/XHR）。
- **同域检查**：对 `http(s)` 链接，仅保留与 Target URL 同域的可点击项。

**2.1.3 扩展可点击元素**

- **新增方法**：`collectClickableKeys(driver, targetDomain, out)`
- **原逻辑**：仅 `<a>` 链接。
- **现逻辑**：
  - `<a>`：同域过滤后收集。
  - `<button>`：按 text 或 aria-label 作为 key。
  - `input[type="submit"]`、`input[type="button"]`：按 value 或 aria-label 作为 key。
- **Key 格式**：`a|...` 表示链接，`btn|...` 表示按钮，便于区分与去重。

**2.1.4 「未找到元素」大量出现 - 根因分析与修复**

- **根因 1：collect 与 find 的 isDisplayed 不一致**
  - 收集阶段：未检查 `isDisplayed()`，会收集隐藏元素。
  - 查找阶段：原要求 `isDisplayed()`，导致隐藏元素无法被找到。
  - **修复**：查找时**不再**要求 `isDisplayed()`，保留隐藏元素（折叠区、非激活 tab 等），因漏洞可能藏于其中。隐藏元素通过 JS click 触发。

- **根因 2：返回后等待时间过短**
  - 返回后仅 400ms 即查找，SPA 或慢页面 DOM 可能尚未渲染完成。
  - **修复**：`waitForPageReady` + sleep 1500ms（`RETURN_PAGE_WAIT_MS`）。

- **根因 3：无重试**
  - **修复**：未找到时最多重试 2 次，每次间隔 500ms（`FIND_RETRY_COUNT=2`）。

- **根因 4：图标链接 key 不稳定**
  - 图标字体、PUA 字符在不同环境 `getText()` 可能不同。
  - **修复**：`pickAnchorKey()`：当 text 长度 ≤ 2 且 href 非空时，优先用 href 作为 key。

- **根因 5：key 匹配过严**
  - **修复**：`normalizeKey()`：trim + 合并连续空白，收集与查找均使用。

- **根因 6：未强制回到 target**
  - 点击抛异常或未找到时，原逻辑不执行 `driver.get(targetPage)`，停留在新页面，后续查找在新页面上进行（key 来自 target 页，大量未找到）。
  - **修复**：`driver.get(targetPage)` 移入 `finally`，每次迭代结束无论成功/失败/未找到都回到 target。

**2.1.5 页面就绪与等待**

- **新增**：`waitForPageReady(driver)`：`WebDriverWait` 等待 `document.readyState === 'complete'`，最多 5 秒。
- **调用时机**：收集前、每次 `driver.get(targetPage)` 后。
- **常量**：`RETURN_PAGE_WAIT_MS=1500`，`FIND_RETRY_MS=500`，`FIND_RETRY_COUNT=2`。

**2.1.6 大量标签页累积 - 根因与修复**

- **根因**：`<a target="_blank">` 链接点击时会在新标签页打开，当前标签页不跳转；driver 仍停留在 target 页，`driver.get(targetPage)` 仅 reload；新标签页累积不关闭。
- **与意图不符**：技术路线为「点击 → 当前标签页跳转 → driver.get 回 target」；`target="_blank"` 破坏了该流程并产生大量标签页。
- **修复**：`ensureClickInSameTab(driver, el)`：点击前对 `<a>` 执行 `removeAttribute('target')` 并 `setAttribute('target','_self')`，使链接在当前标签页打开。

**2.1.7 Cookie 无法登录 - 根因与修复**

- **现象**：已配置 session/tiup_uid Cookie，但 target 页仍显示登录页（如 v.ruc.edu.cn）。
- **根因 1**：HTTPS 站点要求 Cookie 带 `Secure` 标志，否则浏览器不发送；原逻辑未设置 `isSecure(true)`。
- **根因 2**：浏览器中残留旧 Cookie，与新 Cookie 冲突。
- **根因 3**：微人大等站点有 `access_token` Cookie，域为 `.ruc.edu.cn`（父域），原逻辑未支持；缺少该 Cookie 导致无法登录。
- **修复**：`Cookie.Builder.isSecure(isHttps)`；设置前 `deleteAllCookies()`；新增 `access_token` 输入框，使用父域 `.ruc.edu.cn` 设置。

**2.1.8 其他改动**

- 点击前执行 `scrollIntoView({block:'center'})`，确保元素在视口内。
- 移除冗余 `visited` 集合（`LinkedHashMap` 已按 key 去重）。
- 移除未使用的 `HashSet`、`Set`、`Map` 导入。

---

## 三、点击策略流程（更新后）

```
第一轮：收集 key（不保存 WebElement，包含隐藏元素）
├── waitForPageReady
├── <a>：同域过滤；图标（text≤2）优先 href → key = "a|" + normalizeKey(...)
└── <button>、input[submit/button]：key = "btn|" + normalizeKey(...)

第二轮：逐个点击（每次迭代）
├── findClickableByKey(driver, key)，最多重试 2 次（间隔 500ms）
├── scrollIntoView
├── ensureClickInSameTab（移除 target="_blank"，当前标签页打开）
├── sleep 600ms
└── finally：driver.get(targetPage) → waitForPageReady → sleep 1500ms  // 强制回到 target
```

---

## 四、设计说明

### 4.1 为何需要同域过滤

- 越权检测关注**目标应用内**的接口与页面。
- 外部链接（如百度、mailto、tel）与目标应用无关，点击会浪费请求且无助于越权分析。
- 同域过滤使自动化聚焦目标应用，提高检测效率。

### 4.2 为何扩展 button/form submit

- 越权敏感操作多为表单提交：删除、修改、审批等。
- 原逻辑仅点击 `<a>`，会漏掉大量由按钮触发的请求。
- 增加 `<button>` 与 `input[type=submit/button]` 可覆盖更多越权入口。

### 4.3 Stale Element 原理简述

- `findElements()` 返回的 `WebElement` 是当前 DOM 的引用。
- `driver.get()` 会重新加载页面，旧 DOM 被销毁。
- 再次使用旧引用会抛出 `StaleElementReferenceException`。
- 解决：每次 `driver.get()` 后重新查找元素，不缓存 `WebElement`。

### 4.4 为何「未找到元素」会大量出现

- **collect 与 find 不一致**：收集时包含隐藏元素，查找时原要求 `isDisplayed()`，导致无法找到。
- **为何保留隐藏元素**：漏洞可能藏在折叠区、非激活 tab、`display:none` 等中（如仅管理员可见的链接），过滤会漏检。
- **修复**：查找时不要求 `isDisplayed()`；隐藏元素用 JS click 触发；延长返回后等待并增加重试。

### 4.5 为何会打开大量标签页

- **根因**：`<a target="_blank">` 链接点击时在新标签页打开，当前标签页不跳转。
- **与意图不符**：期望「点击 → 当前标签页跳转 → driver.get 回 target」；`target="_blank"` 破坏了该流程。
- **修复**：点击前移除 target 或设为 `_self`，使链接在当前标签页打开。

### 4.6 为何「在新页面上尝试点击」

- **问题**：点击抛异常或未找到时，原逻辑不执行 `driver.get(targetPage)`，停留在新页面；后续查找在新页面上进行，而 key 来自 target 页，导致大量未找到。
- **修复**：`driver.get(targetPage)` 移入 `finally`，每次迭代结束无论结果如何都回到 target。

---

## 五、相关代码位置

| 功能 | 方法 | 行号约 |
|------|------|--------|
| 当前标签页点击 | `ensureClickInSameTab` | 208-224 |
| 等待页面就绪 | `waitForPageReady` | 226-233 |
| 收集可点击 key | `collectClickableKeys` | 235-262 |
| 图标优先 href | `pickAnchorKey` | 264-271 |
| key 规范化 | `normalizeKey` | 273-277 |
| 同域过滤 | `isHrefInScopeForAuth` | 279-292 |
| 查找元素 | `findClickableByKey` | 294-305 |
| 查找链接 | `findAnchorByKey` | 307-323 |
| 查找按钮 | `findButtonByKey` | 325-338 |
