# 引入 B 流量实现平凡响应筛选 - 设计文档

## 一、目标

在 SAME/SIMILAR 结果中，通过比较「A 为 original 的响应」与「B 为 original 的响应」，筛掉平凡响应（两者相同则视为与权限无关）。

## 二、对称采集方案（方式 A）

### 2.1 核心观察

Original 与 Sessions 的参数填写格式相同（headersToReplace 等），因此可以**对称交换**：

- **浏览器 1**：Original = A，Session1 = B（当前配置）
- **浏览器 2**：Original = B（= 原 Session1），Session1 = A（= 原 Original），其他 Session 不变

### 2.2 比较对象

比较**两个浏览器各自的 Original 响应**：

- 浏览器 1 的 Original 响应 = A 用自己身份请求时的响应
- 浏览器 2 的 Original 响应 = B 用自己身份请求时的响应

若 `Resp_A == Resp_B` → 平凡，筛去；否则保留。

### 2.3 操作流程

| 步骤 | 操作 | 数据 |
|------|------|------|
| 1 | 浏览器 1：Original=A，Session1=B。A 登录并访问目标 API | 采集 A 的流量，Analyzer 分析，得到 SAME/SIMILAR |
| 2 | 浏览器 2：**交换配置**（Original=B，Session1=A）。B 登录并访问**相同** API | 采集 B 的流量 |
| 3 | 比较 | 同一 endpoint：Resp_A vs Resp_B，相同则平凡 |

### 2.4 实现要点

- **配置交换**：提供「对称采集 Run2」或「交换 Original/Session1」按钮，临时将 Original 与 Session1 的配置互换
- **双份存储**：需同时保存 Run1（A 的 Original）和 Run2（B 的 Original）的响应，不能互相覆盖
- **身份识别**：需为 Original 维护 headers 配置（与 Session 同格式），用于判断请求属于 A 还是 B

## 三、架构设计

### 3.1 新增组件

```
SymmetricTrafficStore        # 存储 A、B 两份 Original 响应（endpoint -> responseA/B）
ConfigSwapper                # 交换 Original 与 Session1 的配置
IdentityMatcher              # 判断请求属于 A（Original）还是 B（Session1）
TrivialityChecker            # 平凡性检查逻辑（比较 responseA vs responseB）
```

### 3.2 数据流

**Run1（浏览器 1，Original=A）**：
```
[Proxy 流量]
    → IdentityMatcher：请求 headers 匹配 Original 的 headers → 视为 A 的流量
    → RequestController.analyze（现有逻辑）
    → 主表新增 A 的请求
    → SymmetricTrafficStore.putResponseA(endpointKey, A的响应)
```

**Run2（浏览器 2，交换后 Original=B）**：
```
用户点击「对称采集 Run2」→ 备份主表到 responseA → 交换配置
[Proxy 流量]
    → IdentityMatcher：请求 headers 匹配交换后的 Original（=B 的 headers）→ 视为 B 的流量
    → RequestController.analyze
    → 主表新增 B 的请求（覆盖 Run1）
    → SymmetricTrafficStore.putResponseB(endpointKey, B的响应)
```

**身份识别**：Original 与 Session1 的格式相同（headersToReplace）。需在配置中为 Original 也维护一份 headers。交换后，用「当前 Original 的 headers」匹配请求；仅当请求匹配当前 Original 时才送入 Analyzer，避免 A、B 流量混在一起。

### 3.3 Endpoint 匹配

```java
// 与 OriginalRequestResponse.getEndpoint() 一致：method + host + url
String endpointKey = orr.getMethod() + orr.getHost() + orr.getUrl();
```

## 四、身份识别（IdentityMatcher）

### 4.1 匹配规则

请求归属某身份，当且仅当：**请求的 headers 包含该身份配置的 `headersToReplace` 中的每一行**。

复用 `RequestController.isSameHeader()` 逻辑：`headers.contains(headerToReplace)` 对每行做精确匹配。

### 4.2 Original 的 headers 来源

- **需新增**：在 Analyzer 配置中为 Original 增加 headers 配置（与 Session 同格式）
- 合并布局下，Original 区域已有 Cookie 等，可复用或扩展为完整 headersToReplace
- 交换时：Original 与 Session1 的 headersToReplace 互换

### 4.3 过滤逻辑

- Run1：仅当请求匹配 Original（A）的 headers 时，送入 Analyzer
- Run2：仅当请求匹配交换后的 Original（B）的 headers 时，送入 Analyzer
- 不匹配的请求：不送入 Analyzer，不写入 SymmetricTrafficStore

## 五、SymmetricTrafficStore 设计

```java
public class SymmetricTrafficStore {
    private final Map<String, byte[]> responseA = new ConcurrentHashMap<>();
    private final Map<String, byte[]> responseB = new ConcurrentHashMap<>();
    // 各 Run 内重放比较结果：B 重放 A vs A 的 Original
    private final Map<String, BypassConstants> replayStatusRun1 = new ConcurrentHashMap<>();
    // A 重放 B vs B 的 Original
    private final Map<String, BypassConstants> replayStatusRun2 = new ConcurrentHashMap<>();
    
    void putResponseA(String endpointKey, byte[] response);
    void putResponseB(String endpointKey, byte[] response);
    void putReplayStatusRun1(String endpointKey, BypassConstants status);  // Run1 中 B 重放的结果
    void putReplayStatusRun2(String endpointKey, BypassConstants status);  // Run2 中 A 重放的结果
    boolean hasResponseA(String endpointKey);
    boolean hasResponseB(String endpointKey);
    boolean hasBoth(String endpointKey);
    void clear();
}
```

### 5.1 写入时机

- **ResponseA + ReplayStatusRun1**：Run1 时，主表每新增一条 Original（A 的）请求，写入 `responseA`；同时该条目的 Session1（B）重放结果写入 `replayStatusRun1`
- **ResponseB + ReplayStatusRun2**：Run2 时，主表每新增一条 Original（B 的）请求，写入 `responseB`；同时该条目的 Session1（A）重放结果写入 `replayStatusRun2`

### 5.2 避免覆盖与合并

- Run2 开始前，将 Run1 的主表数据（responseA、replayStatusRun1）备份完成
- Run2 时主表被 B 的流量覆盖，Run1 数据已安全存储在 Store
- **待检查 endpoint 集合**：Run1 的 SAME/SIMILAR 的 endpoint ∪ Run2 的 SAME/SIMILAR 的 endpoint，需在备份时持久化

## 六、平凡性检查流程

### 6.1 触发时机

Result 表刷新时实时检查（方案 B）。

### 6.2 Endpoint 不对称：统一处理

**Run1 有 Run2 无** 与 **Run1 无 Run2 有** 采用**相同处理**：无法比较 Original 响应，不筛去，结合各自 Run 内的重放结果自动判定垂直/水平。

### 6.3 新增 Status：垂直 / 水平

在现有 SAME/SIMILAR/DIFFERENT 基础上，增加**越权类型**标记：

| Status | 含义 |
|--------|------|
| **Trivial** | Resp_A == Resp_B，平凡，筛去 |
| **Vertical** | 疑似垂直越权（仅一方有 Original 流量，另一方通过重放拿到数据） |
| **Horizontal** | 疑似水平越权（双方都有 Original 流量，且重放得到 SAME/SIMILAR） |
| **Unknown** | 无法判定（无重放或重放为 DIFFERENT） |

### 6.4 基于重放的自动判定逻辑

需在 SymmetricTrafficStore 中额外存储每个 Run 的**重放比较结果**：

- **replayStatusRun1**：B 重放 A 的请求 → B 的响应 vs A 的 Original 响应（SAME/SIMILAR/DIFFERENT）
- **replayStatusRun2**：A 重放 B 的请求 → A 的响应 vs B 的 Original 响应（SAME/SIMILAR/DIFFERENT）

| 情况 | 重放结果 | 判定 |
|------|----------|------|
| **Run1 有、Run2 无** | Run1: B 重放 = SAME/SIMILAR | **Vertical**（仅 A 有入口，B 通过重放拿到数据） |
| **Run1 无、Run2 有** | Run2: A 重放 = SAME/SIMILAR | **Vertical**（仅 B 有入口，A 通过重放拿到数据） |
| **两者都有** | Resp_A == Resp_B | **Trivial**，筛去 |
| **两者都有** | Resp_A != Resp_B，且任一侧重放 = SAME/SIMILAR | **Horizontal**（双方都能访问，但重放拿到对方数据） |
| 其他 | 重放 = DIFFERENT 或无法比较 | **Unknown** |

### 6.5 检查逻辑

```java
// allSuspiciousEndpoints = responseA 的 key 集合 ∪ responseB 的 key 集合
for (endpoint in allSuspiciousEndpoints) {
    boolean hasA = symmetricStore.hasResponseA(endpoint);
    boolean hasB = symmetricStore.hasResponseB(endpoint);
    ReplayStatus replay1 = symmetricStore.getReplayStatusRun1(endpoint);
    ReplayStatus replay2 = symmetricStore.getReplayStatusRun2(endpoint);

    if (hasA && hasB) {
        if (ResponseComparator.isSame(respA, respB)) {
            markAsTrivial(endpoint);
        } else if (replay1 == SAME/SIMILAR || replay2 == SAME/SIMILAR) {
            markAsHorizontal(endpoint);
        } else {
            markAsUnknown(endpoint);
        }
    } else if (hasA && !hasB && (replay1 == SAME || replay1 == SIMILAR)) {
        markAsVertical(endpoint);  // B 无入口，B 重放拿到 A 的数据
    } else if (!hasA && hasB && (replay2 == SAME || replay2 == SIMILAR)) {
        markAsVertical(endpoint);  // A 无入口，A 重放拿到 B 的数据
    } else {
        markAsUnknown(endpoint);
    }
}
```

### 6.6 比较逻辑

复用 `RequestController.analyzeResponse` 的 SAME 判定逻辑。

## 七、UI 设计

### 7.1 配置项

| 位置 | 控件 | 说明 |
|------|------|------|
| Analyzer 区域 | 复选框「对称采集」 | 开启后启用双份存储与平凡性检查 |
| Analyzer 区域 | 按钮「对称采集 Run2」 | 备份 responseA、replayStatusRun1，交换配置，进入 Run2 |
| Original 区域 | headers 配置 | 与 Session 同格式，用于识别 A 的流量 |
| Result 表 | 列「Status」**（新增）** | 显示 Trivial / Vertical / Horizontal / Unknown |
| Result 表 | 筛选 | 按 Status 筛选（如排除 Trivial、仅看 Vertical） |

### 7.2 操作

- **清空对称数据**：提供「Clear Symmetric Data」清空 Store
- **恢复配置**：Run2 结束后可再次点击「交换」恢复 Original=A、Session1=B

## 八、实现步骤（建议顺序）

1. **Original headers 配置**：在 ConfigurationPanel 中为 Original 增加 headersToReplace（或复用现有 Cookie 区域）
2. **ConfigSwapper**：实现 Original 与 Session1 的配置交换
3. **SymmetricTrafficStore**：实现双份存储 + replayStatusRun1/Run2
4. **IdentityMatcher**：在 HttpListener 中，仅当请求匹配当前 Original 时送入 Analyzer
5. **RequestController 扩展**：写入 SymmetricTrafficStore（responseA/B、replayStatusRun1/Run2）
6. **BypassStatus 枚举**：新增 Trivial / Vertical / Horizontal / Unknown
7. **TrivialityChecker**：实现判定逻辑，输出 BypassStatus
8. **ResultTableModel 扩展**：新增 Status 列；默认排除 Trivial，可配置
9. **UI**：对称采集开关、Run2 按钮、Status 列、按 Status 筛选

## 九、风险与限制

| 风险 | 说明 | 缓解 |
|------|------|------|
| Original 无 headers | 当前 Original 可能无 headers 配置 | 需新增，或从 UI Testing 的 Original Cookie 映射 |
| Endpoint 不一致 | path 编码、query 顺序不同 | 统一规范化 |
| 时序问题 | Run1、Run2 顺序颠倒 | 明确提示用户先 Run1 再 Run2 |
| **Endpoint 不对称** | Run1 有 Run2 无 / Run1 无 Run2 有 | 统一处理：结合重放结果标记 Vertical；不筛去 |

## 十、后续扩展

- **Vertical 细分**：区分「B 越权拿 A 的数据」与「A 越权拿 B 的数据」，便于按方向筛选
- **置信度**：对 SIMILAR 的 Vertical/Horizontal 可标记置信度（高/中/低）
