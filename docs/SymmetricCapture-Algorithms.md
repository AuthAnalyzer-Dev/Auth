# 对称采集关键算法

本文档整理对称采集功能中用到的核心算法与判定逻辑。

---

## 一、Endpoint 规范化与匹配

### 1.1 Endpoint 键的构成

同一 API 在 Run1 与 Run2 中可能因插件修饰、不同来源（抓取 vs 发现）等造成格式差异，需统一规范化后才能正确配对。**配对要求严格**：只有同一 API 才配对；规范化仅消除格式差异，不改变语义。

**公式**：
```
endpointKey = normMethod + normHost + normUrl
```

其中：
- `normMethod`：method 转大写（HTTP 方法大小写不敏感）
- `normHost`：host 转小写（DNS 大小写不敏感）
- `normUrl`：path + query 规范化，由 `normalizeEndpointUrl(path, query)` 生成

### 1.2 URL 规范化算法

```
输入: path (String), query (String)
输出: 规范化后的 url (String)

1. 若 path 为 null，置为 ""
2. 将 path 中连续多个 "/" 合并为单个 "/"（消除 /api//users 等格式差异）
3. 若 path 长度 > 1 且以 "/" 结尾，去掉尾部斜杠
   （保留 "/" 本身，不把根路径变成空）
4. 若 query 为 null 或空，直接返回 path
5. 否则：
   a. 将 query 按 "&" 分割为参数数组
   b. 对参数数组按字典序排序（消除参数顺序差异）
   c. 拼接为 path + "?" + 排序后的参数字符串
6. 返回结果
```

**示例**：
- `/api/users?id=1&name=a` → `/api/users?id=1&name=a`（已有序）
- `/api/users?name=a&id=1` → `/api/users?id=1&name=a`（排序后）
- `/api/users/` → `/api/users`
- `/api//users` → `/api/users`
- `/` → `/`（不变）

---

## 二、身份匹配（IdentityMatcher）

用于对称采集时判断请求是否属于当前 Original 身份，仅匹配的请求才送入 Analyzer。

### 2.1 算法

```
输入: requestHeaders (List<String>), headersToReplace (String)
输出: boolean（true = 匹配，可送入 Analyzer）

1. 若 requestHeaders 为 null，返回 false
2. 若 headersToReplace 为 null 或 trim 后为空，返回 true（不过滤）
3. 将 headersToReplace 按 "\n" 分割，去掉 "\r"
4. 对每一非空行 trimmed：
   - 若 requestHeaders 不包含 trimmed，返回 false
5. 全部包含则返回 true
```

### 2.2 语义

请求归属某身份，当且仅当：**请求的 headers 包含该身份配置的 `headersToReplace` 中的每一行**。  
采用精确匹配：`requestHeaders.contains(trimmed)`。

---

## 三、响应比较（SAME / SIMILAR 判定）

用于判断 Original 响应与 Session 重放响应是否相同或相似，以及 TrivialityChecker 中 Resp_A 与 Resp_B 是否相同。

### 3.1 SAME 判定

```
条件：
  - 响应体字节数组完全相等 (Arrays.equals)
  - 且（状态码相同 或 配置为不尊重状态码）
→ 返回 SAME
```

### 3.2 SIMILAR 判定

```
条件：
  - 状态码相同 或 配置为不尊重状态码
  - 且 响应体长度差在允许范围内
    设 range = originalBodyLength / (100 / deviationForSimilarStatus)
    若 |originalLength - sessionLength| <= range
→ 返回 SIMILAR
```

默认 `deviationForSimilarStatus = 5`，即 ±5% 长度差视为 SIMILAR。

### 3.3 其他

不满足 SAME 或 SIMILAR 则返回 DIFFERENT。

---

## 四、平凡性判定（TrivialityChecker）

根据 responseA、responseB 及 replayStatusRun1、replayStatusRun2 计算 BypassStatus。

### 4.1 输入

| 变量 | 含义 |
|------|------|
| hasA | Store 中是否有 responseA |
| hasB | Store 中是否有 responseB |
| replay1 | Run1 中 Session1 重放 A 的请求 vs A 的 Original 的判定 |
| replay2 | Run2 中 Session1 重放 B 的请求 vs B 的 Original 的判定 |
| isSuspiciousReplay(x) | x ∈ {SAME, SIMILAR} |

### 4.2 判定流程

```
若 endpointKey 为 null → UNKNOWN

若 hasA && hasB：
  若 Resp_A 与 Resp_B 相同（复用 analyzeResponse 的 SAME 判定）
    → TRIVIAL（平凡，筛去）
  否则若 replay1 或 replay2 为 SAME/SIMILAR
    → HORIZONTAL（水平越权）
  否则
    → UNKNOWN

若 hasA && !hasB && replay1 为 SAME/SIMILAR
  → VERTICAL（垂直越权，B 无入口但重放拿到 A 的数据）

若 !hasA && hasB && replay2 为 SAME/SIMILAR
  → VERTICAL（垂直越权，A 无入口但重放拿到 B 的数据）

其他 → UNKNOWN
```

### 4.3 缓存

`getStatus(endpointKey)` 使用 `ConcurrentHashMap` 缓存结果，Store 清空时需调用 `clearCache()`。

---

## 五、数据写入与备份

### 5.1 writeToSymmetricStore（实时写入）

每个请求分析完成后调用：

```
若 对称采集未启用 或 Store 为 null → 返回

endpointKey = orr.getEndpoint()
response = orr 的响应体
replayStatus = Session1 对该 mapId 的 AnalyzerRequestResponse.status

若 当前为 Run2 模式：
  store.putResponseB(endpointKey, response)
  store.putReplayStatusRun2(endpointKey, replayStatus)
否则（Run1）：
  store.putResponseA(endpointKey, response)
  store.putReplayStatusRun1(endpointKey, replayStatus)
```

### 5.2 backupTableToSymmetricStore（Run2 前备份）

用户点击「对称采集 Run2」时，在交换配置前执行：

```
遍历主表每一行：
  取 endpointKey、response、Session1 的 replayStatus
  store.putResponseA(endpointKey, response)
  store.putReplayStatusRun1(endpointKey, replayStatus)

清空 TrivialityChecker 缓存
```

**说明**：Run1 期间 `writeToSymmetricStore` 已写入 responseA，backup 再次写入相同数据，确保 Run2 开始前 responseA 完整；同时补全可能遗漏的 replayStatusRun1。

---

## 六、Result 表过滤逻辑

### 6.1 refresh() 算法

```
1. 清空 filteredList
2. 若 mainModel 或 sessions 为空 → 返回
3. seenEndpoints = 空 Set
4. 遍历 mainModel 的每一行 orr：
   a. 若 !hasSuspiciousStatus(orr.id) → 跳过
   b. ep = orr.getEndpoint()
   c. 若 ep ∈ seenEndpoints → 跳过（endpoint 去重）
   d. 若 对称采集启用 且 store.hasResponseA(ep) 且 store.hasResponseB(ep)：
      - status = TrivialityChecker.getStatus(ep)
      - 若 excludeTrivial 且 status == TRIVIAL → 跳过
   e. seenEndpoints.add(ep)
   f. filteredList.add(orr)
```

### 6.2 hasSuspiciousStatus

```
任意 Session 对该 mapId 的 AnalyzerRequestResponse.status ∈ {SAME, SIMILAR}
→ 返回 true
```

### 6.3 去重策略

同一 endpoint 的 Run1 与 Run2 行只保留**首次出现**的一行，避免 Result 表中重复显示。

---

## 七、主表匹配列（getMatchLabel）

用于主表「匹配」列，显示 Run1 与 Run2 的对应关系。

### 7.1 算法

```
若 Store 为 null → "—"
若 !hasResponseA(ep) 或 !hasResponseB(ep) → "—"

thisIsRun2 = 当前行是否为 Run2
遍历主表其他行：
  若 同 endpoint 且 Run 不同（一 Run1 一 Run2）：
    若 thisIsRun2 → "↔ Run1#<对方id>"
    否则 → "↔ Run2#<对方id>"
    返回

若 hasA 且 hasB 但未找到配对行 → "✓匹配"
```

---

## 八、Bypass 列显示映射

| 条件 | BypassStatus | 显示 |
|------|--------------|------|
| hasA && hasB，Resp 相同 | TRIVIAL | Trivial |
| hasA && hasB，重放 SAME/SIMILAR | HORIZONTAL | Horizontal |
| hasA && !hasB，replay1 可疑 | VERTICAL | Vertical |
| !hasA && hasB，replay2 可疑 | VERTICAL | Vertical |
| hasA && !hasB | RUN1_ONLY | Run2缺 |
| !hasA && hasB | RUN2_ONLY | Run1缺 |
| 其他 | UNKNOWN | Unknown |
