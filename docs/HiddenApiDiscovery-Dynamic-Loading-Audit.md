# 动态加载脚本发现 - 审计报告

**审计日期**：2026-02-26  
**审计范围**：ApiDiscoveryService 中与动态 script 发现相关的实现

---

## 一、动态加载场景分类

| 类别 | 场景 | 实现覆盖 | 说明 |
|------|------|----------|------|
| **DOM 注入** | 页面加载后通过 `createElement('script')` + `appendChild` 注入 | ✅ 部分 | 通过 DOM 二次收集（2.5s 等待）捕获已注入的 script；若注入发生在 2.5s 内，可覆盖 |
| **ES6 import()** | `import('./path.js')`、`import('/static/js/app.js')` | ✅ 已覆盖 | DYNAMIC_IMPORT_URL |
| **Webpack 魔法注释** | `import(/* webpackChunkName: "xxx" */ './path.js')` | ✅ 已覆盖 | DYNAMIC_IMPORT_URL 使用 `[^)]*` 跳过注释 |
| **Chunk 引用** | 路径含 chunk/main/bundle/runtime/vendor 的 .js | ✅ 已覆盖 | CHUNK_OR_ASSET_URL |
| **Manifest** | manifest.json、asset-manifest.json 中的 files/entrypoints/main | ✅ 已覆盖 | fetchAndExtractFromManifest |
| **AMD require** | `require(['path/to/module.js'], callback)` | ✅ 已覆盖 | AMD_REQUIRE_URL |
| **Web Worker** | `new Worker('path.js')`、`new SharedWorker('path.js')` | ✅ 已覆盖 | WORKER_URL |
| **通用 .js 路径** | 任意 `/path/*.js`（路径长度 ≥ 8） | ✅ 已覆盖 | ANY_SCRIPT_URL |
| **require.ensure** | `require.ensure([], () => {}, 'chunk-name')` | ⚠️ 未覆盖 | 第三参数为 chunk 名，非 URL；需 runtime 映射，静态分析无法获取 |
| **__webpack_require__.e** | `__webpack_require__.e(chunkId)` | ⚠️ 未覆盖 | chunkId 为数字/字符串，真实 URL 在 runtime 生成 |
| **动态 import 变量** | `import('./' + route + '.js')`、`` import(`./${name}.js`) `` | ❌ 无法覆盖 | 路径含变量，静态正则无法提取 |
| **createElement 变量** | `s.src = baseUrl + '/chunk.js'` | ⚠️ 部分 | 若 baseUrl 为字面量且整体可匹配，ANY_SCRIPT_URL 可能命中；变量拼接无法覆盖 |
| **iframe 内 script** | 子 frame 中加载的 script | ❌ 未覆盖 | 当前仅处理主 frame，不遍历 iframe |
| **用户交互后加载** | 点击、路由切换后才加载的懒加载 chunk | ⚠️ 部分 | 2.5s 内未触发则漏报；可考虑延长等待或增加轮询 |
| **Service Worker 缓存** | 从 SW 缓存加载的 script | ❌ 不适用 | 仍由主线程发起，URL 通常已在主 bundle 中引用 |

---

## 二、实现细节

### 2.1 脚本 URL 提取模式（按执行顺序）

| 模式 | 正则 | 示例 |
|------|------|------|
| CHUNK_OR_ASSET_URL | 含 chunk/main/bundle/runtime/vendor 的路径 | `/static/chunk.abc.js` |
| DYNAMIC_IMPORT_URL | `import(...'path.js')`，支持魔法注释 | `import(/* ... */ './page.js')` |
| AMD_REQUIRE_URL | `require(['path.js'])` | `require(['./module.js'])` |
| WORKER_URL | `new Worker('path')` / `new SharedWorker('path')` | `new Worker('/worker.js')` |
| ANY_SCRIPT_URL | 任意 `/path/*.js`，路径 ≥ 8 字符 | `/assets/scripts/app.js` |

### 2.2 DOM 收集策略

```
1. 首次 collectScriptsFromDom → 获取初始 script 列表
2. Thread.sleep(2500)
3. 再次 collectScriptsFromDom → 合并新增 script（按 src 去重）
4. 若 driver 失效：静态降级 fetchPageHtml + parseScriptTagsFromHtml
```

### 2.3 递归深度

- `MAX_CHUNK_FETCH_DEPTH = 3`：从主 bundle 出发，最多递归 3 层获取 chunk
- 避免无限递归与请求爆炸

---

## 三、覆盖缺口与建议

| 缺口 | 影响 | 建议 |
|------|------|------|
| **require.ensure / __webpack_require__.e** | 老旧 Webpack 项目可能漏报 | 低优先级；现代项目多用 import() |
| **动态 import 变量** | 完全动态路径无法提取 | 需 AST 或运行时插桩，超出当前 scope |
| **iframe 内 script** | 嵌入页面的子 frame 可能漏报 | 可扩展 collectScriptsFromDom 遍历 iframe |
| **用户交互后加载** | 路由懒加载等可能漏报 | 可配置延长 DYNAMIC_SCRIPT_WAIT_MS 或多次轮询 |
| **createElement 变量** | `s.src = base + '/x.js'` 变量拼接难匹配 | 低优先级；多数项目 chunk 名仍为字面量 |

---

## 四、结论

当前实现覆盖了主流动态加载场景：

- **ES6 import()**（含 Webpack 魔法注释）
- **AMD require**
- **Web Worker**
- **Manifest / Chunk 引用**
- **DOM 二次收集**（2.5s 内注入的 script）
- **通用 .js 路径**（兜底）

无法覆盖的场景主要为：**完全动态路径**（变量拼接）、**require.ensure 等老旧模式**、**iframe 子 frame**。建议在技术规格与论文文档中明确标注覆盖范围与局限。

---

**文档版本**：1.0  
**最后更新**：2026-02-26
