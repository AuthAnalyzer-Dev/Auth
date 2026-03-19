# UI Testing 抓取流程 - 目标与技术流（审计文档）

本文档面向审计与复现，整理 UI Testing 抓取功能的目标、技术流、数据结构及关键算法。

---

## 一、目标概述

| 项目 | 说明 |
|------|------|
| **功能** | 通过浏览器自动化抓取目标页面上的可点击元素，触发请求并送入 Analyzer 进行越权检测 |
| **核心挑战** | 处理同页多状态（如 Tab 切换「最新活动」「即将开始」），不同状态展示不同链接 |
| **设计原则** | ① 以目标状态为基准，每次点击后返回目标状态 ② 识别状态切换链接并记录 ③ 点击完成后切换至待探索状态并重复 ④ 避免重复点击（同 key 跨状态去重）⑤ 不添加 key 前后缀，保持 run1/run2 映射一致 |

---

## 二、整体技术流

```
┌─────────────────────────────────────────────────────────────────────────────┐
│ 上游输入                                                                      │
├─────────────────────────────────────────────────────────────────────────────┤
│ • Target URL (String)           - 目标页面                                    │
│ • Header(s) to Replace (String) - Cookie 等认证信息，用于注入与登出后恢复      │
└─────────────────────────────────────────────────────────────────────────────┘
                                        │
                                        ▼
┌─────────────────────────────────────────────────────────────────────────────┐
│ 初始化                                                                        │
├─────────────────────────────────────────────────────────────────────────────┤
│ driver.get(targetPage) → applyCookies → driver.get(targetPage)               │
│ statesToExplore = [ [] ]   （空 path = 初始状态）                              │
│ alreadyClicked = {}                                                          │
│ exploredStates = {}                                                           │
└─────────────────────────────────────────────────────────────────────────────┘
                                        │
                                        ▼
┌─────────────────────────────────────────────────────────────────────────────┐
│ 主循环：按状态探索                                                             │
├─────────────────────────────────────────────────────────────────────────────┤
│ 1. targetStatePath = statesToExplore.poll()                                  │
│ 2. goToTargetState(driver, targetPage, targetStatePath)                      │
│ 3. collectClickableKeys(driver, targetDomain, clickableKeys)                 │
│ 4. 对每个 key（跳过 alreadyClicked、targetStatePath 内元素）：                │
│    - 点击 → 若 URL 变化：applyCookies(若登出) → goToTargetState                │
│    - 点击 → 若 URL 不变且 hasSubstantiveDomChange：记录到 stateSwitchersFound  │
│      （DOM 指纹校验，排除点赞等无结构变化操作）→ goToTargetState               │
│ 5. 对 stateSwitchersFound 中每个 sw：                                         │
│    - nextPath = targetStatePath + [sw]                                       │
│    - 若 nextPath 未探索 → statesToExplore.add(nextPath)                      │
│ 6. 重复直到 statesToExplore 为空或达到 maxTotalClicks                         │
└─────────────────────────────────────────────────────────────────────────────┘
                                        │
                                        ▼
┌─────────────────────────────────────────────────────────────────────────────┐
│ 下游                                                                         │
├─────────────────────────────────────────────────────────────────────────────┤
│ afterCrawlComplete → runDiscoveryAfterCrawl → sendDiscoveredApisToAnalyzer     │
│ ① 抓取完成后自动运行隐藏 API 发现（复用浏览器，按勾选从 JS/Swagger 提取）         │
│ ② 将发现的隐藏 API 构造请求送入 Analyzer，与抓取到的非隐藏 API 一并越权检测       │
│ 对称采集：Run1 完成→super(发现+送入 A)→Run2；Run2 完成→送入 B（建立配对）        │
└─────────────────────────────────────────────────────────────────────────────┘
```

---

## 三、核心概念

### 3.1 目标状态（Target State）

- **定义**：当前轮次探索的页面状态，用 `List<String> targetStatePath` 表示。
- **空 path `[]`**：初始状态，即 `driver.get(targetPage)` 后的默认页面。
- **非空 path `[btn|即将开始]`**：从初始状态依次点击状态切换链接后到达的状态。
- **进入目标状态**：`goToTargetState` = `driver.get(targetPage)` + 按 path 顺序依次点击各 key。

### 3.2 状态切换链接（State Switcher）

- **定义**：点击后 URL 不变、且发生**实质性 DOM 结构变化**的元素（如 Tab 按钮）。
- **识别方式**：① URL 不变 ② `hasSubstantiveDomChange(fpBefore, fpAfter)` 为 true；或 ③ `looksLikeTabOrStateSwitcher(el)` 为 true（兜底）。
- **DOM 指纹**：`getPageContentFingerprint` 返回 `linkCount|sortedHrefs`；点击后额外等待 SAME_PAGE_DOM_WAIT_MS 以适配 Angular getList() 等异步加载。
- **记录**：满足 ② 或 ③ 时加入 `stateSwitchersFound`。

### 3.3 待探索状态

- **定义**：通过点击某个状态切换链接可到达、但尚未被探索过的状态。
- **生成**：`nextPath = targetStatePath + [sw]`，若 `!exploredStates.contains(nextPath)` 则加入 `statesToExplore`。
- **日志**：`nextPath.size() == 1` 时输出 `[Crawl] 待探索状态: <key>`，仅对一级状态打日志。

### 3.4 可点击元素 Key 格式

| 前缀 | 来源 | 示例 |
|------|------|------|
| `a|` | `<a>` 链接 | `a|最新活动`、`a|/api/news` |
| `btn|` | `<button>`、`input[type=submit/button]`、`*[@role='button']` | `btn|即将开始` |

- **规范化**：`normalizeKey` = trim + 合并连续空白。
- **不添加前后缀**：保持与 run1/run2 映射一致。

---

## 四、关键算法

### 4.1 goToTargetState

```
输入: driver, targetPage, targetStatePath (List<String>)
输出: 无（副作用：页面进入目标状态）

1. driver.get(targetPage)
2. waitForPageReady(driver)
3. Thread.sleep(300)
4. for key in targetStatePath:
     el = findClickableByKey(driver, key)
     if el != null:
       scrollIntoView(el)
       ensureClickInSameTab(driver, el)
       Thread.sleep(SAME_PAGE_DOM_WAIT_MS)
```

### 4.2 状态切换判定（含 DOM 指纹）

```
1. urlChanged = 比较 urlBefore 与 urlAfter（normalizeUrlForCompare）
2. 若 urlChanged → 导航，applyCookies(若登出)
3. 若 !urlChanged：
   fpBefore = getPageContentFingerprint(driver)  // 点击前
   fpAfter  = getPageContentFingerprint(driver)  // 点击后
   仅当 hasSubstantiveDomChange(fpBefore, fpAfter) 为 true 时，加入 stateSwitchersFound
```

**getPageContentFingerprint**：执行 JS 获取 `linkCount|sortedHrefs`（前 60 个 a[href]，排序后拼接，截断 1500 字符）。

**hasSubstantiveDomChange**：比较 linkCount 与 href 集合，任一变化则返回 true。点赞等操作通常不改变链接集合，故被排除。

### 4.3 collectClickableKeys

```
输入: driver, targetDomain, out (LinkedHashMap)
输出: 追加到 out

1. //a: 同根域过滤 isHrefInScopeForAuth，key = "a|" + pickAnchorKey(a, text, href)
2. //button | //input[@type='submit' or @type='button']: key = "btn|" + label
3. //*[@role='button' and not(self::a) and not(self::button)]: key = "btn|" + label
```

### 4.4 pickAnchorKey（含图标/无文本兜底）

```
若 text 非空：
  若 href 空 → text
  若 text 长度 ≤ 2 → href（图标链接）
  否则 → text
若 text 空且 href 非空 → href
若 text 空且 href 空（兜底）：
  依次尝试 aria-label、title、内部 img[alt]
  均空则 → null
```

用于覆盖 `<a>` 包裹 `<svg>`/`<img>` 的图标按钮，避免漏采。

### 4.5 isHrefInScopeForAuth（同根域）

```
过滤: mailto/tel/data/blob
保留: javascript:#、非 http(s)
http(s) 链接: 比较根域名 getRootDomain(hrefDomain) 与 getRootDomain(targetDomain)
```

**getRootDomain**：`www.example.com` → `example.com`，`api.sub.example.com` → `example.com`。支持 `co.uk`、`com.cn` 等多段 TLD。

### 4.6 避免重复点击

- `alreadyClicked`：全局 Set，跨状态共享。
- 同 key 在不同状态出现（如「详情」）→ 仅点击一次，后续跳过。
- `targetStatePath.contains(key)`：跳过当前目标状态路径中的元素，避免重复点击 Tab 自身。

---

## 五、数据结构

| 变量 | 类型 | 说明 |
|------|------|------|
| alreadyClicked | Set\<String\> | 已点击过的 key，跨状态去重 |
| statesToExplore | Queue\<List\<String\>\> | 待探索的状态 path 队列 |
| exploredStates | Set\<List\<String\>\> | 已探索过的状态 path |
| targetStatePath | List\<String\> | 当前轮次的目标状态 path |
| stateSwitchersFound | LinkedHashSet\<String\> | 本轮发现的状态切换 key |
| clickableKeys | LinkedHashMap\<String, Void\> | 当前状态下的可点击 key（保持 DOM 顺序） |

---

## 六、配置常量

| 常量 | 值 | 说明 |
|------|-----|------|
| RETURN_PAGE_WAIT_MS | 1500 | 返回目标页后等待 |
| FIND_RETRY_MS | 500 | 查找元素重试间隔 |
| FIND_RETRY_COUNT | 2 | 查找元素重试次数 |
| SAME_PAGE_DOM_WAIT_MS | 1000 | 同页状态切换后等待 DOM 更新（Angular 等 SPA） |
| DOM_FINGERPRINT_SCRIPT | JS 常量 | 链接数量 + 前 60 个 href 排序拼接（截断 1500 字符） |
| maxTotalClicks | 500 | 最大点击次数，防止异常页面无限循环 |

---

## 七、与 Run1/Run2 的关联

- **Run1**：抓取阶段，触发请求并记录到主表。
- **Run2**：对称采集模式，重放抓取流程，比较两次请求/响应。
- **Key 一致性**：可点击元素的 key 不添加状态前后缀，确保 Run1 与 Run2 中同一元素使用相同 key，便于建立映射关系。

---

## 八、局限与说明

| 项目 | 说明 |
|------|------|
| **等价状态** | `[tabB, tabA]` 与 `[tabA]` 可能到达同一状态，当前实现会分别探索（可接受，alreadyClicked 减少重复请求） |
| **嵌套 Tab** | 支持多级 path，如 `[tabB, tabC]`，由 statesToExplore 广度优先探索 |
| **登出** | 点击登出类 key 后 applyCookies 重新注入，再 goToTargetState |
| **同根域过滤** | isHrefInScopeForAuth 基于 getRootDomain 比较，允许 www/api 等子域 |
| **DOM 指纹** | 链接数量或 href 集合变化才视为状态切换，点赞等微调不触发 |
| **Tab 兜底** | DOM 指纹未变化时，若元素有 role=button、ng-click、btnCur 等特征，仍记为状态切换 |
| **弹窗处理** | ① 通用选择器：Bootstrap/Element UI/Ant Design 的 .close、[data-dismiss]、[aria-label] 等 ② 中英文按钮文案：确认/Confirm、取消/Cancel、关闭/Close、知道了/Got it 等 |

---

## 九、代码位置

| 功能 | 文件 | 方法/类 |
|------|------|---------|
| 抓取主循环 | UITestingPanel.java | onCrawlClick |
| 抓取后自动发现 | UITestingPanel.java | runDiscoveryAfterCrawl |
| 进入目标状态 | UITestingPanel.java | goToTargetState |
| 收集可点击元素 | UITestingPanel.java | collectClickableKeys |
| 查找元素 | UITestingPanel.java | findClickableByKey, findAnchorByKey, findButtonByKey |
| 状态切换判定 | UITestingPanel.java | getPageContentFingerprint, hasSubstantiveDomChange, looksLikeTabOrStateSwitcher |
| 弹窗关闭 | UITestingPanel.java | tryDismissBlockingOverlays, tryClickByGenericSelectors, tryClickByButtonText |
| Key 提取（含兜底） | UITestingPanel.java | pickAnchorKey, getAttributeTrimmed, getFirstImgAlt |
| 同根域过滤 | UITestingPanel.java | isHrefInScopeForAuth, isSameRootDomain, getRootDomain |
| URL 比较 | UITestingPanel.java | normalizeUrlForCompare |
| 登出后恢复 | UITestingPanel.java | applyCookies, isLogoutKey |

---

## 十、重构与增强说明（v2）

| 维度 | 问题 | 方案 |
|------|------|------|
| **状态爆炸** | 仅 `urlAfter != urlBefore` 导致点赞等无结构变化操作被误判为状态切换 | 引入 DOM 指纹 `getPageContentFingerprint`，仅当链接数量或 href 集合变化时记为状态切换 |
| **元素漏采** | `pickAnchorKey` 在 text/href 皆空时返回 null，漏掉 `<a>` 包裹 `<svg>`/`<img>` 的图标按钮 | 兜底提取 `aria-label`、`title`、内部 `img[alt]` |
| **同域过严** | `isHrefInScopeForAuth` 完全匹配域名，无法抓取 `api.xxx.com` 等子域 | 改为 `getRootDomain` 比较，允许 `www.xxx.com` 与 `api.xxx.com` 同根域 |
| **Tab 未标记** | Angular Tab（如「即将开始」「最新活动」）因 getList() 异步加载，DOM 指纹延迟变化 | ① 点击后额外等待 SAME_PAGE_DOM_WAIT_MS ② `looksLikeTabOrStateSwitcher` 兜底（role=button、ng-click、btnCur） |
| **弹窗卡住** | 浏览器版本提示等弹窗阻塞，导致点击失败或卡住 | ① 通用选择器（Bootstrap/Element UI/Ant Design）② 中英文按钮文案（Confirm/Cancel/Close 等） |
| **抓取后漏发现** | 抓取完页面链接后未自动运行隐藏 API 发现 | `runDiscoveryAfterCrawl`：抓取完成后按勾选从 JS/Swagger 提取，addEndpoints 合并后送入 Analyzer |
