# AuthAnalyzer 更新报告

**日期**：2026-02-23  
**范围**：UI Testing 模块重构与工作流简化

---

## 一、更新概览

| 类别 | 更新内容 |
|------|----------|
| 移除功能 | 「启动自动化任务」及其全部实现 |
| 移除 UI | Base URL 输入框、「启动代理 Driver」按钮 |
| 新增逻辑 | 抓取前自动设置 Cookie；抓取时自动启动代理 |
| 封装 | `ProxyDriverManager.getOrStartDriver()` |

---

## 二、详细更新清单

### 2.1 删除的文件

| 文件 | 说明 |
|------|------|
| `src/com/protect7/authanalyzer/uitesting/runner/UITestRunner.java` | 原「启动自动化任务」执行逻辑，已整体移除 |

### 2.2 修改的文件

#### `ProxyDriverManager.java`

- **新增**：`getOrStartDriver(useProxy, proxyHost, proxyPort, headless)`
  - 若 driver 未启动则自动启动
  - 返回 WebDriver 实例

#### `ControlsPanel.java`

- **移除**：Base URL 输入框及 `getBaseUrl()`
- **移除**：「启动代理 Driver」按钮
- **移除**：`setDriverButtonText()`、`setCrawlEnabled()`、`onToggleDriver()`
- **保留**：Target URL、tiup_uid Cookie、session Cookie 输入框

#### `UITestingPanel.java`

- **移除**：`onToggleDriver()` 及 `controls.onToggleDriver` 绑定
- **移除**：`UITestRunner` 相关 import 与调用
- **新增**：抓取前设置 Cookie 逻辑（`getDomainFromUrl()`、tiup_uid/session 注入）
- **修改**：`onCrawlClick` 使用 `ProxyDriverManager.getOrStartDriver()` 替代 `getDriver()`，实现抓取时自动启动代理

#### `使用指南.md`

- 删除「启动自动化任务」「启动代理 Driver」相关说明
- 删除 Base URL、停止 Driver 相关步骤
- 更新抓取流程说明（自动启动代理、自动设置 Cookie）

---

## 三、现行工作流

### 3.1 UI Testing 模块

```
步骤 1：配置测试参数
├── Target URL（必填）
├── tiup_uid Cookie（可选）
└── session Cookie（可选）

步骤 2：启动 Analyzer
└── 在 Analyzer 标签点击 ▶ Start

步骤 3：执行抓取
└── 点击「抓取并点击页面链接」
    ├── 若代理未启动 → 自动启动 Chrome（经 Burp Proxy 127.0.0.1:8080）
    ├── 导航至 Target URL
    ├── 若已配置 Cookie → 自动设置 tiup_uid、session
    ├── 查找所有 <a> 链接
    └── 逐个点击，每次点击后返回目标页面

步骤 4：查看测试结果
└── 表格显示请求，选择 Session 查看分析结果
```

### 3.2 抓取执行流程（内部）

```
点击「抓取并点击页面链接」
    ↓
ProxyDriverManager.getOrStartDriver()  // 未启动则自动启动
    ↓
校验 Target URL
    ↓
driver.get(targetPage)
    ↓
若配置了 tiup_uid/session → addCookie() → driver.get(targetPage) 刷新
    ↓
findElements(By.xpath("//a")) → 逐个 click → driver.get(targetPage) 返回
```

### 3.3 越权检测典型流程

1. 在 Analyzer 中配置多个 Session（如普通用户、管理员）
2. 在 UI Testing 中配置普通用户 Cookie，点击抓取
3. 修改 Cookie 为管理员，再次抓取
4. 在 Analyzer 中查看各 Session 的 SAME/SIMILAR 结果

---

## 四、设计说明

### 4.1 为何移除「启动自动化任务」

- 该模式使用独立 Chrome，**不经过 Burp Proxy**
- 产生的请求无法被 Analyzer 捕获
- 与越权检测目标不符，故移除

### 4.2 为何移除 Base URL

- Base URL 仅用于原 UITestRunner 设置 Cookie
- 当前抓取逻辑从 Target URL 提取域名设置 Cookie
- 单一 Target URL 即可满足需求

### 4.3 为何隐去「启动代理 Driver」按钮

- 抓取时自动启动代理，减少操作步骤
- 用户只需配置参数并点击抓取

### 4.4 抓取与越权检测的关系

- 抓取：以指定身份（Cookie）遍历页面链接，生成请求
- 请求经 Burp Proxy → Analyzer 拦截并分析
- Analyzer 用不同 Session 重放请求并比较响应
- 不同身份得到 SAME/SIMILAR 响应 → 潜在越权

---

## 五、相关文件索引

| 功能 | 文件 |
|------|------|
| 代理管理 | `uitesting/runner/ProxyDriverManager.java` |
| 抓取逻辑 | `gui/UITesting/UITestingPanel.java` |
| 控制面板 | `gui/UITesting/ControlsPanel.java` |
| 使用说明 | `使用指南.md` |
