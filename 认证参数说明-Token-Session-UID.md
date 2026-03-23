# 认证参数说明：Token、Session、UID 等功能、区别与权限

本文档从 Web 安全与身份认证角度，说明 Token、Session、UID 等常见认证相关参数的功能、区别、联系，以及获取这些参数后可能获得的权限。

---

## 一、各参数功能概述

### 1.1 Token（令牌）

**功能定义：**

Token 是一种**无状态**的凭证，用于证明请求者身份或授权。服务端通过验证 Token 的有效性（签名、过期时间等）来授权访问，通常**不依赖服务端存储会话状态**。

**常见类型：**

| 类型 | 说明 | 典型位置 |
|------|------|----------|
| **Access Token** | 访问令牌，用于访问受保护资源 | `Authorization: Bearer <token>` |
| **Refresh Token** | 刷新令牌，用于获取新的 Access Token | 通常仅在认证接口返回 |
| **JWT (JSON Web Token)** | 自包含的 Token，内含用户信息与签名 | Header / Body / Cookie |
| **API Key** | 用于 API 调用的密钥 | Header / URL 参数 |
| **CSRF Token** | 防跨站请求伪造令牌 | 表单隐藏字段 / Header |
| **OAuth Token** | OAuth 授权流程中的令牌 | 多种位置 |

**典型出现位置：**

- HTTP Header：`Authorization: Bearer xxx`、`X-Auth-Token: xxx`
- Cookie：`token=xxx`
- URL 参数：`?token=xxx`
- 请求体：JSON 中的 `access_token`、`token` 等字段

---

### 1.2 Session（会话）

**功能定义：**

Session 是服务端维护的**有状态**会话，用于在多次请求之间保持用户登录状态。Session ID 是客户端持有的标识符，服务端根据该 ID 查找对应的会话数据（用户身份、权限等）。

**常见实现：**

| 实现方式 | 说明 |
|----------|------|
| **Cookie 中的 Session ID** | 如 `Cookie: session=abc123`、`Cookie: PHPSESSID=xxx` |
| **URL 重写** | Session ID 附加在 URL 中 |
| **自定义 Header** | 如 `X-Session-ID: xxx` |

**典型出现位置：**

- Cookie：`session=xxx`、`PHPSESSID=xxx`、`JSESSIONID=xxx`
- Header：`X-Session-ID`、`Session-Token`
- URL：部分老系统使用 `?session=xxx`

---

### 1.3 UID（用户标识）

**功能定义：**

UID（User ID）是**用户唯一标识符**，用于在系统中区分不同用户。UID 本身通常不直接作为认证凭证，而是与 Token/Session 配合使用，表示“当前会话属于哪个用户”。

**常见形式：**

| 名称 | 说明 |
|------|------|
| **uid** | 用户 ID，可能是数字或字符串 |
| **user_id** | 同上 |
| **userId** | 驼峰命名 |
| **sub** | JWT 中的 subject 声明，通常为用户 ID |

**典型出现位置：**

- URL 参数：`/api/user/123`、`?uid=123`
- 请求体：`{"uid": 123, "action": "..."}`
- JWT Payload：`{"sub": "user123", ...}`
- Cookie：部分系统将 uid 放在 Cookie 中（如 `tiup_uid`）

---

### 1.4 其他常见认证相关参数

| 参数 | 功能 | 典型用途 |
|------|------|----------|
| **code** | 授权码（OAuth 等） | 一次性使用，用于换取 Access Token |
| **csrf / xsrf** | 跨站请求伪造防护 | 防止未授权表单提交 |
| **pass / password** | 密码 | 登录认证，不应在请求中明文传输 |
| **key** | 密钥/API Key | API 认证、加密密钥 |
| **mail / email** | 邮箱 | 用户标识、找回密码 |
| **user** | 用户名 | 用户标识 |
| **viewstate / eventvalidation** | ASP.NET 状态 | 表单状态、防篡改 |
| **requestverificationtoken** | ASP.NET CSRF | 防 CSRF |

---

## 二、区别与联系

### 2.1 核心区别

| 维度 | Token | Session | UID |
|------|-------|---------|-----|
| **状态** | 通常无状态 | 有状态（服务端存储） | 纯标识，无状态 |
| **主要用途** | 证明身份/授权 | 维持登录会话 | 标识“谁” |
| **有效期** | 有（短期或长期） | 有（通常可配置） | 无（用户不变） |
| **服务端存储** | 一般不存（JWT 自验证） | 必须存储 | 用户表中有记录 |
| **可替代性** | 可刷新/轮换 | 可失效/重建 | 通常不可变 |

### 2.2 三者关系

```
┌─────────────────────────────────────────────────────────────┐
│                    典型认证流程                               │
├─────────────────────────────────────────────────────────────┤
│  用户登录 → 服务端创建 Session（含 UID）                      │
│           → 返回 Session ID（或 Token）给客户端               │
│           → 后续请求携带 Session ID / Token                  │
│           → 服务端解析出 UID，据此判断权限                    │
└─────────────────────────────────────────────────────────────┘

关系简图：
  Session ──包含──> UID（会话关联的用户）
  Token   ──可编码──> UID（JWT 的 sub 等）
  UID    ──独立存在──> 用户身份标识，不直接用于认证
```

- **Session 与 UID**：Session 在服务端通常绑定一个 UID，表示“这个会话属于哪个用户”。
- **Token 与 UID**：JWT 等 Token 的 payload 中常包含 `sub`/`uid`，解析 Token 即可得到用户身份。
- **Session 与 Token**：部分系统用 Token 替代传统 Session ID，实现无状态会话；也有系统同时使用（如 Token 存于 Session 中）。

---

## 三、获得各参数后可能获得的权限

### 3.1 获得 Token

| 场景 | 可能获得的权限 |
|------|----------------|
| **Access Token 泄露** | 在有效期内，以对应用户身份访问 API/资源 |
| **JWT 泄露** | 解析 payload 获取用户信息，可伪造请求（若未校验签名或算法可被篡改） |
| **API Key 泄露** | 以该 Key 身份调用 API，权限取决于 Key 的授权范围 |
| **Refresh Token 泄露** | 可不断刷新获取新 Access Token，长期维持访问 |

**风险等级：** 高。Token 通常直接代表访问权限，泄露即可能被滥用。

---

### 3.2 获得 Session ID

| 场景 | 可能获得的权限 |
|------|----------------|
| **Session 劫持** | 在 Session 有效期内，完全以该用户身份操作 |
| **Session 固定** | 诱使用户使用攻击者预设的 Session ID 登录，从而获得该用户会话 |

**风险等级：** 高。Session ID 等同于“登录凭证”，泄露后攻击者可完全接管会话。

---

### 3.3 获得 UID

| 场景 | 可能获得的权限 |
|------|----------------|
| **仅 UID，无 Token/Session** | 通常无法直接越权，但可用于枚举、探测、拼接其他攻击（如 IDOR 尝试） |
| **UID + 其他参数** | 若存在 IDOR，修改 UID 可能访问其他用户数据 |
| **UID 可预测** | 便于批量枚举用户、尝试水平越权 |

**风险等级：** 中。UID 单独泄露危害相对较小，但常与其他漏洞组合造成越权。

---

### 3.4 获得其他参数

| 参数 | 可能获得的权限 |
|------|----------------|
| **code（OAuth）** | 一次性换取 Token，需在有效期内使用，且需配合 client_secret（机密型应用） |
| **csrf / xsrf** | 单独获得价值有限，多用于构造 CSRF 攻击页面，诱使已登录用户执行操作 |
| **pass / password** | 可登录对应用户，获得该账号全部权限 |
| **key** | 视 Key 用途而定，可能是 API 访问、解密等 |

---

## 四、在 AuthAnalyzer 中的对应关系

AuthAnalyzer 用于检测认证绕过，其概念与上述参数对应如下：

| AuthAnalyzer 概念 | 对应安全参数 |
|-------------------|--------------|
| **Session** | 一组替换规则（Headers、Token 等）的集合，用于模拟不同“会话”场景 |
| **Token** | 可替换的认证相关参数，如 `token`、`session`、`csrf_token`、`uid` 等 |
| **自动提取模式** | 静态：`token,code,user,mail,pass,key,csrf,xsrf`；动态：`viewstate,eventvalidation,requestverificationtoken` |

通过配置不同的 Session 和 Token 替换策略，可以测试：

- 删除/替换 Token 后，是否仍能访问受保护资源（认证绕过）
- 使用其他用户的 Token/Session 是否可越权（水平越权）
- 修改 UID 等参数是否可访问他人数据（IDOR）

---

## 五、安全建议摘要

1. **Token**：使用 HTTPS、短期有效期、签名校验（如 JWT）、避免在 URL 中传递。
2. **Session**：使用 HttpOnly + Secure Cookie、定期轮换、绑定 IP/User-Agent 等。
3. **UID**：避免可预测、不单独作为授权依据、结合服务端权限校验防止 IDOR。
4. **通用**：敏感参数不在前端长期存储、日志中脱敏、定期审计访问与泄露风险。

---

*文档版本：1.0 | 适用于 AuthAnalyzer 及 Web 认证安全分析*
