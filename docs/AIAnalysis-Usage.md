# AI Analysis 模块使用文档

## 概述

AI Analysis 是 AuthAnalyzer 的第三个内置标签页，用于将 Analyzer 检测到的潜在越权接口（SAME / SIMILAR 状态）自动发送给大语言模型，获得逐条安全分析报告。

支持所有兼容 OpenAI Chat Completions API 格式的服务，包括：

| 服务 | API URL 示例 |
|------|-------------|
| OpenAI | `https://api.openai.com/v1` |
| Azure OpenAI | `https://<resource>.openai.azure.com/openai/deployments/<model>` |
| 本地 Ollama | `http://localhost:11434/v1` |
| DeepSeek | `https://api.deepseek.com/v1` |
| 智谱 GLM | `https://open.bigmodel.cn/api/paas/v4` |
| 通义千问 | `https://dashscope.aliyuncs.com/compatible-mode/v1` |
| 任意 OpenAI 兼容代理 | 自行填写 |

---

## 前置条件

1. 已在 **Analyzer** 标签页运行过请求拦截，产生了 SAME 或 SIMILAR 状态的条目。
2. 持有有效的 LLM API Key（或本地模型已启动）。

---

## 配置说明

切换到 **AI Analysis** 标签页，填写顶部配置区：

| 字段 | 说明 | 示例 |
|------|------|------|
| **API URL** | LLM 服务的 Base URL，不含 `/chat/completions` 后缀 | `https://api.openai.com/v1` |
| **API Key** | 服务商提供的密钥 | `sk-xxxx` |
| **Model** | 模型名称，需与服务商一致 | `gpt-4o` / `deepseek-chat` / `glm-4` |
| **System Prompt** | 发给模型的系统指令，留空则使用内置默认 Prompt | 见下方 |

> 配置在点击「开始分析」时自动保存到 Burp 扩展设置，下次加载扩展时自动恢复（API Key 同样持久化，请勿在共享 Burp 项目中使用）。

---

## 默认 System Prompt

```
你是一名专业的 Web 安全研究员，正在分析 HTTP 请求/响应对，判断是否存在越权（IDOR/BAC）漏洞。
请用中文简洁回答：
1. 该接口是否存在越权风险（高/中/低/无）
2. 理由（不超过 3 句话）
3. 如有风险，建议修复方向（一句话）
```

你可以在界面上直接修改 System Prompt，例如改为英文输出、增加 CVSS 评分要求等。

---

## 使用步骤

1. 在 **Analyzer** 标签页运行拦截，积累一定数量的请求。
2. 切换到 **Result** 标签页确认有 SAME/SIMILAR 条目。
3. 切换到 **AI Analysis** 标签页，填写 API URL、Key、Model。
4. （可选）修改 System Prompt。
5. 点击「**开始分析**」。
   - 进度条实时更新，左侧列表逐条显示分析结果摘要。
   - 点击任意一行，右侧详情区展示完整 AI 分析内容。
6. 分析完成后，可点击「**清空结果**」重新开始。
7. 若需中途停止，点击「**停止**」。

---

## 数据发送内容

每次 LLM 调用包含以下内容（超过 3000 字符自动截断）：

```
## 原始请求
<完整 HTTP 请求报文>

## 原始响应
<完整 HTTP 响应报文>

## Session[XXX] 重放请求
<修改了 Token/Header 后的请求报文>

## Session[XXX] 重放响应
<重放响应报文>

绕过状态: SAME
```

如果配置了多个 Session，每个 Session 的重放结果都会包含在同一次请求中。

---

## 并发与限速

- 默认并发数为 **2**（硬编码，防止触发 rate limit）。
- 单次 API 调用超时：连接 15 秒，读取 60 秒。
- 如遇 rate limit 错误（HTTP 429），停止当前分析，减少并发后重试。

---

## 自定义 Prompt 示例

### 英文输出 + CVSS 评分

```
You are a senior web security researcher. Analyze the following HTTP request/response pair for IDOR or broken access control vulnerabilities.
Respond in English with:
1. Risk level: Critical / High / Medium / Low / None
2. CVSS v3.1 base score estimate
3. Reason (max 3 sentences)
4. Recommended fix (1 sentence)
```

### 只关注敏感数据泄露

```
你是 Web 安全专家，专注于敏感数据泄露检测。
分析以下 HTTP 响应，判断重放请求的响应中是否包含其他用户的敏感字段（如 uid、email、phone、身份证、token 等）。
输出格式：
- 泄露风险：高/中/低/无
- 泄露字段（如有）
- 修复建议
```

---

## 注意事项

- **API Key 安全**：Key 存储在 Burp 的扩展设置中，不写入代码或日志，但请勿在共享 Burp 项目文件中使用。
- **数据隐私**：请求/响应内容会发送到第三方 LLM 服务，测试敏感系统前请确认合规。使用本地 Ollama 可完全规避此风险。
- **截断**：单条请求/响应超过 3000 字符时末尾自动截断并标注 `[已截断]`，不影响分析但可能丢失部分响应体。
- **分析范围**：仅分析 Result 标签页中 SAME/SIMILAR 的条目，DIFFERENT 条目不发送（视为无越权风险）。
