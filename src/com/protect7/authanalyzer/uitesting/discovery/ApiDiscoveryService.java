package com.protect7.authanalyzer.uitesting.discovery;

import java.io.BufferedReader;
import java.io.InputStreamReader;
import java.io.OutputStream;
import java.net.HttpURLConnection;
import java.net.SocketTimeoutException;
import java.net.URL;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.HashSet;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import com.google.gson.Gson;
import com.google.gson.JsonArray;
import com.google.gson.JsonElement;
import com.google.gson.JsonObject;
import com.google.gson.JsonParser;
import org.openqa.selenium.By;
import org.openqa.selenium.WebDriver;
import org.openqa.selenium.WebElement;
import org.yaml.snakeyaml.Yaml;

import burp.BurpExtender;

/**
 * API 发现服务：从 JS 提取、Source Map、Swagger 探测、GraphQL 内省。
 */
public class ApiDiscoveryService {

    private static final int MAX_DISCOVERED_LIMIT = 2000;

    private static final Pattern[] JS_PATTERNS = {
        Pattern.compile("fetch\\s*\\(\\s*['\"`](/[^'\"`\\s]+)['\"`]"),
        Pattern.compile("axios\\.(get|post|put|delete|patch)\\s*\\(\\s*['\"`](/[^'\"`\\s]+)['\"`]"),
        Pattern.compile("url\\s*:\\s*['\"`](/[^'\"`\\s]+)['\"`]"),
        Pattern.compile("['\"`](/api/[^'\"`\\s?]*)[?\"'`]?"),
        Pattern.compile("['\"`](/v[0-9]+/[^'\"`\\s?]*)[?\"'`]?"),
    };

    /** 扩充后的探测路径：Swagger、Actuator、GraphQL、文档 */
    private static final String[] SWAGGER_PATHS = {
        "/swagger.json",
        "/swagger/v1/swagger.json",
        "/v2/api-docs",
        "/v3/api-docs",
        "/v3/api-docs.yaml",
        "/api-docs",
        "/api/swagger.json",
        "/openapi.json",
        "/openapi.yaml",
        "/api/openapi.json",
        "/actuator/mappings",
        "/actuator/env",
        "/graphql",
        "/v1/graphql",
        "/api/graphql",
    };

    private static final String[] DEFAULT_HTTP_METHODS = { "GET", "POST", "PUT", "DELETE" };

    private static final String GRAPHQL_INTROSPECTION_QUERY = "{\"query\":\"\\n    query IntrospectionQuery {\\n      __schema {\\n        queryType { name }\\n        mutationType { name }\\n        types {\\n          ...FullType\\n        }\\n      }\\n    }\\n    fragment FullType on __Type {\\n      kind\\n      name\\n      fields(includeDeprecated: true) {\\n        name\\n        args { name type { kind name } }\\n      }\\n    }\\n  \"}";

    private static final Pattern CHUNK_OR_ASSET_URL = Pattern.compile(
            "['\"`](/[^'\"`\\s]*(?:chunk|main|bundle|runtime|vendor)[^'\"`\\s]*\\.js)[?'\"`]?");

    private static final int MAX_CHUNK_FETCH_DEPTH = 3;

    /**
     * 从当前页面的 JS 文件中提取 API 端点。
     */
    public List<DiscoveredEndpoint> discoverFromJs(WebDriver driver, String baseUrl, DiscoveryCallback callback) {
        Set<DiscoveredEndpoint> result = new LinkedHashSet<>();
        if (driver == null || baseUrl == null) return new ArrayList<>(result);

        String baseOrigin = getBaseOrigin(baseUrl);
        Set<String> fetchedUrls = new HashSet<>();
        int[] sourceMapAdded = { 0 };

        try {
            fetchAndExtractFromManifest(baseOrigin, result, fetchedUrls, callback, sourceMapAdded);

            List<WebElement> scripts = driver.findElements(By.tagName("script"));
            for (WebElement script : scripts) {
                String src = script.getAttribute("src");
                String content = null;

                if (src != null && !src.trim().isEmpty()) {
                    String scriptUrl = toAbsoluteUrl(src, baseOrigin);
                    if (callback != null) callback.onProgress("正在获取: " + scriptUrl);
                    content = fetchUrlContent(scriptUrl);
                    if (content != null && !content.isEmpty()) {
                        extractFromJsContent(content, result, DiscoveredEndpoint.Source.JS);
                        extractAndFetchChunkScripts(content, baseOrigin, result, fetchedUrls, callback, 0, sourceMapAdded);
                    }
                    sourceMapAdded[0] += extractFromSourceMap(scriptUrl, result, callback);
                } else {
                    content = script.getAttribute("innerHTML");
                    if (content != null && !content.isEmpty()) {
                        extractFromJsContent(content, result, DiscoveredEndpoint.Source.JS);
                        extractAndFetchChunkScripts(content, baseOrigin, result, fetchedUrls, callback, 0, sourceMapAdded);
                    }
                }
            }
            if (sourceMapAdded[0] > 0 && callback != null) {
                callback.onProgress("Source Map 额外发现 " + sourceMapAdded[0] + " 个 API");
            }
        } catch (Exception e) {
            if (callback != null) callback.onError("JS 提取失败: " + e.getMessage());
        }

        return new ArrayList<>(result);
    }

    private void fetchAndExtractFromManifest(String baseOrigin, Set<DiscoveredEndpoint> result,
            Set<String> fetchedUrls, DiscoveryCallback callback, int[] sourceMapAdded) {
        for (String manifestPath : new String[] { "/manifest.json", "/asset-manifest.json" }) {
            String url = baseOrigin + manifestPath;
            if (fetchedUrls.contains(url)) continue;
            String content = fetchUrlContent(url);
            if (content == null || !content.trim().startsWith("{")) continue;
            try {
                JsonObject root = JsonParser.parseString(content).getAsJsonObject();
                for (String key : new String[] { "files", "entrypoints", "main" }) {
                    if (!root.has(key)) continue;
                    JsonElement el = root.get(key);
                    if (el == null) continue;
                    if (el.isJsonObject()) {
                        for (Map.Entry<String, JsonElement> e : el.getAsJsonObject().entrySet()) {
                            JsonElement v = e.getValue();
                            if (v != null && v.isJsonPrimitive()) {
                                String path = v.getAsString();
                                if (path != null && path.endsWith(".js")) {
                                    String fullUrl = toAbsoluteUrl(path, baseOrigin);
                                    fetchChunkAndExtract(fullUrl, baseOrigin, result, fetchedUrls, callback, 0, sourceMapAdded);
                                }
                            }
                        }
                    } else if (el.isJsonArray()) {
                        for (JsonElement v : el.getAsJsonArray()) {
                            if (v != null && v.isJsonPrimitive()) {
                                String path = v.getAsString();
                                if (path != null && path.endsWith(".js")) {
                                    String fullUrl = toAbsoluteUrl(path, baseOrigin);
                                    fetchChunkAndExtract(fullUrl, baseOrigin, result, fetchedUrls, callback, 0, sourceMapAdded);
                                }
                            }
                        }
                    }
                }
            } catch (Exception ignore) {
            }
        }
    }

    private void extractAndFetchChunkScripts(String content, String baseOrigin, Set<DiscoveredEndpoint> result,
            Set<String> fetchedUrls, DiscoveryCallback callback, int depth, int[] sourceMapAdded) {
        if (depth >= MAX_CHUNK_FETCH_DEPTH) return;
        Matcher m = CHUNK_OR_ASSET_URL.matcher(content);
        while (m.find()) {
            String path = m.group(1);
            if (path == null || !path.endsWith(".js")) continue;
            String fullUrl = toAbsoluteUrl(path, baseOrigin);
            fetchChunkAndExtract(fullUrl, baseOrigin, result, fetchedUrls, callback, depth, sourceMapAdded);
        }
    }

    private void fetchChunkAndExtract(String scriptUrl, String baseOrigin, Set<DiscoveredEndpoint> result,
            Set<String> fetchedUrls, DiscoveryCallback callback, int depth, int[] sourceMapAdded) {
        if (scriptUrl == null || fetchedUrls.contains(scriptUrl)) return;
        fetchedUrls.add(scriptUrl);
        try {
            if (callback != null) callback.onProgress("正在获取 Chunk: " + scriptUrl);
            String content = fetchUrlContent(scriptUrl);
            if (content != null && !content.isEmpty()) {
                extractFromJsContent(content, result, DiscoveredEndpoint.Source.JS);
                extractAndFetchChunkScripts(content, baseOrigin, result, fetchedUrls, callback, depth + 1, sourceMapAdded);
            }
            if (sourceMapAdded != null) sourceMapAdded[0] += extractFromSourceMap(scriptUrl, result, callback);
            else extractFromSourceMap(scriptUrl, result, callback);
        } catch (Exception ignore) {
        }
    }

    /**
     * 从 Source Map 提取未混淆代码并二次提取 API。
     * @return 本次新增的端点数量
     */
    public int extractFromSourceMap(String scriptUrl, Set<DiscoveredEndpoint> result, DiscoveryCallback callback) {
        if (scriptUrl == null || scriptUrl.isEmpty()) return 0;
        int before = result.size();
        String mapUrl = scriptUrl.endsWith(".map") ? scriptUrl : scriptUrl + ".map";
        try {
            if (callback != null) callback.onProgress("正在获取 Source Map: " + mapUrl);
            String content = fetchUrlContent(mapUrl);
            if (content == null || content.isEmpty()) return 0;

            JsonObject root = JsonParser.parseString(content).getAsJsonObject();
            JsonArray sourcesContent = root.getAsJsonArray("sourcesContent");
            if (sourcesContent == null) return 0;

            for (JsonElement el : sourcesContent) {
                if (el != null && el.isJsonPrimitive()) {
                    String src = el.getAsString();
                    if (src != null && !src.trim().isEmpty()) {
                        extractFromJsContent(src, result, DiscoveredEndpoint.Source.SOURCE_MAP);
                    }
                }
            }
        } catch (Exception ignore) {
        }
        return Math.max(0, result.size() - before);
    }

    /**
     * 从 Swagger/OpenAPI 文档探测 API 端点，含 Schema 解析。
     */
    public List<DiscoveredEndpoint> discoverFromSwagger(String baseUrl, DiscoveryCallback callback) {
        Set<DiscoveredEndpoint> result = new LinkedHashSet<>();
        if (baseUrl == null) return new ArrayList<>(result);

        String baseOrigin = getBaseOrigin(baseUrl);

        for (String docPath : SWAGGER_PATHS) {
            String docUrl = baseOrigin + docPath;
            if (callback != null) callback.onProgress("正在探测: " + docUrl);

            String content = fetchUrlContent(docUrl);
            if (content == null || content.isEmpty()) continue;

            if (docPath.contains("graphql")) {
                List<DiscoveredEndpoint> gql = discoverFromGraphQLIntrospection(baseOrigin + docPath, callback);
                for (DiscoveredEndpoint ep : gql) {
                    if (result.size() >= MAX_DISCOVERED_LIMIT) break;
                    result.add(ep);
                }
                continue;
            }

            if (docPath.contains("actuator/mappings")) {
                List<DiscoveredEndpoint> act = discoverFromActuatorMappings(content, baseOrigin, callback, MAX_DISCOVERED_LIMIT - result.size());
                for (DiscoveredEndpoint ep : act) {
                    if (result.size() >= MAX_DISCOVERED_LIMIT) break;
                    result.add(ep);
                }
                continue;
            }

            try {
                JsonObject root;
                String trimmed = content.trim();
                if (trimmed.startsWith("{")) {
                    root = JsonParser.parseString(content).getAsJsonObject();
                } else if ((trimmed.startsWith("---") || trimmed.contains("\npaths:") || docPath.endsWith(".yaml") || docPath.endsWith(".yml"))
                        && !looksLikeHtml(content)) {
                    Object yamlObj = new Yaml().load(content);
                    if (yamlObj == null) continue;
                    root = new Gson().toJsonTree(yamlObj).getAsJsonObject();
                } else {
                    continue;
                }
                JsonObject paths = root.getAsJsonObject("paths");
                if (paths == null) continue;

                JsonObject components = root.has("components") && root.get("components").isJsonObject()
                        ? root.getAsJsonObject("components") : null;

                for (String path : paths.keySet()) {
                    if (result.size() >= MAX_DISCOVERED_LIMIT) break;
                    JsonObject pathObj = paths.getAsJsonObject(path);
                    if (pathObj == null) continue;

                    for (String method : pathObj.keySet()) {
                        if (result.size() >= MAX_DISCOVERED_LIMIT) break;
                        if (!isHttpMethod(method)) continue;
                        EndpointSchema schema = parseEndpointSchema(pathObj, method, components);
                        result.add(new DiscoveredEndpoint(method.toUpperCase(), path, DiscoveredEndpoint.Source.SWAGGER, schema));
                    }
                }
                if (result.size() >= MAX_DISCOVERED_LIMIT && callback != null) {
                    callback.onProgress("已达发现上限 " + MAX_DISCOVERED_LIMIT + "，已截断");
                }
                if (callback != null) callback.onProgress("已从 Swagger 解析 " + result.size() + " 个端点");
                break;
            } catch (Exception e) {
                if (callback != null) callback.onError("解析 Swagger 失败: " + e.getMessage());
            }
        }

        return new ArrayList<>(result);
    }

    private boolean isHttpMethod(String m) {
        return "get".equalsIgnoreCase(m) || "post".equalsIgnoreCase(m) || "put".equalsIgnoreCase(m)
                || "delete".equalsIgnoreCase(m) || "patch".equalsIgnoreCase(m);
    }

    private EndpointSchema parseEndpointSchema(JsonObject pathObj, String method, JsonObject components) {
        Map<String, EndpointSchema.ParamSchema> pathParams = new LinkedHashMap<>();
        JsonObject requestBodySchema = null;

        JsonObject methodObj = pathObj != null ? pathObj.getAsJsonObject(method) : null;
        if (methodObj == null) return new EndpointSchema(pathParams, null, components);

        JsonElement paramsEl = methodObj.get("parameters");
        if (paramsEl != null && paramsEl.isJsonArray()) {
            for (JsonElement p : paramsEl.getAsJsonArray()) {
                if (p == null || !p.isJsonObject()) continue;
                JsonObject param = p.getAsJsonObject();
                String in = param.has("in") ? param.get("in").getAsString() : "";
                if (!"path".equals(in)) continue;
                String name = param.has("name") ? param.get("name").getAsString() : null;
                if (name == null) continue;

                String type = "string";
                String format = null;
                if (param.has("schema")) {
                    JsonObject schema = param.getAsJsonObject("schema");
                    type = schema.has("type") ? schema.get("type").getAsString() : type;
                    format = schema.has("format") ? schema.get("format").getAsString() : null;
                } else {
                    type = param.has("type") ? param.get("type").getAsString() : type;
                    format = param.has("format") ? param.get("format").getAsString() : null;
                }
                pathParams.put(name, new EndpointSchema.ParamSchema(type, format));
            }
        }

        JsonElement rbEl = methodObj.get("requestBody");
        if (rbEl != null && rbEl.isJsonObject()) {
            JsonObject rb = rbEl.getAsJsonObject();
            if (rb != null && rb.has("content")) {
                JsonElement contentEl = rb.get("content");
                if (contentEl != null && contentEl.isJsonObject()) {
                    JsonObject content = contentEl.getAsJsonObject();
                    JsonElement appJsonEl = content.get("application/json");
                    if (appJsonEl != null && appJsonEl.isJsonObject()) {
                        JsonObject appJson = appJsonEl.getAsJsonObject();
                        JsonElement schemaEl = appJson.get("schema");
                        if (schemaEl != null && schemaEl.isJsonObject()) {
                            requestBodySchema = schemaEl.getAsJsonObject();
                        }
                    }
                }
            }
        }

        if (requestBodySchema == null && paramsEl != null && paramsEl.isJsonArray()) {
            for (JsonElement p : paramsEl.getAsJsonArray()) {
                if (p != null && p.isJsonObject()) {
                    JsonObject param = p.getAsJsonObject();
                    String in = param.has("in") ? (param.get("in").isJsonPrimitive() ? param.get("in").getAsString() : "") : "";
                    if ("body".equals(in) && param.has("schema") && param.get("schema").isJsonObject()) {
                        requestBodySchema = param.get("schema").getAsJsonObject();
                        break;
                    }
                }
            }
        }

        return new EndpointSchema(pathParams, requestBodySchema, components);
    }

    private List<DiscoveredEndpoint> discoverFromActuatorMappings(String json, String baseOrigin, DiscoveryCallback callback, int maxItems) {
        List<DiscoveredEndpoint> result = new ArrayList<>();
        if (maxItems <= 0) return result;
        try {
            JsonObject root = JsonParser.parseString(json).getAsJsonObject();
            JsonObject contexts = root.getAsJsonObject("contexts");
            if (contexts == null) return result;
            for (String ctxName : contexts.keySet()) {
                if (result.size() >= maxItems) break;
                JsonObject ctx = contexts.getAsJsonObject(ctxName);
                if (ctx == null) continue;
                JsonObject mappings = ctx.getAsJsonObject("mappings");
                if (mappings == null) continue;
                JsonObject dispatcherServlets = mappings.getAsJsonObject("dispatcherServlets");
                if (dispatcherServlets == null) continue;
                for (String servletName : dispatcherServlets.keySet()) {
                    if (result.size() >= maxItems) break;
                    JsonElement servletEl = dispatcherServlets.get(servletName);
                    if (servletEl == null || !servletEl.isJsonArray()) continue;
                    for (JsonElement m : servletEl.getAsJsonArray()) {
                        if (result.size() >= maxItems) break;
                        if (m == null || !m.isJsonObject()) continue;
                        JsonObject h = m.getAsJsonObject();
                        String pred = h.has("predicate") ? h.get("predicate").getAsString() : "";
                        String[] methodPath = extractMethodAndPathFromPredicate(pred);
                        if (methodPath != null && methodPath[1] != null && !methodPath[1].isEmpty() && isRelevantPath(methodPath[1])) {
                            result.add(new DiscoveredEndpoint(methodPath[0], methodPath[1], DiscoveredEndpoint.Source.SWAGGER));
                        }
                    }
                }
            }
        } catch (Exception ignore) {
        }
        return result;
    }

    private static final Pattern ACTUATOR_METHOD_PATH = Pattern.compile("(GET|POST|PUT|DELETE|PATCH)?\\s*(/[^\\s\\]}\\{]*)");

    private String[] extractMethodAndPathFromPredicate(String predicate) {
        if (predicate == null || predicate.isEmpty()) return null;
        Matcher m = ACTUATOR_METHOD_PATH.matcher(predicate);
        if (m.find()) {
            String method = (m.group(1) != null && !m.group(1).isEmpty()) ? m.group(1).toUpperCase() : "GET";
            String path = m.group(2) != null ? m.group(2).trim() : null;
            return new String[] { method, path };
        }
        int start = predicate.indexOf('/');
        if (start >= 0) {
            String before = predicate.substring(0, start).trim().toUpperCase();
            String method = ("POST".equals(before) || "PUT".equals(before) || "DELETE".equals(before) || "PATCH".equals(before)) ? before : "GET";
            int end = predicate.indexOf(' ', start);
            String path = end > start ? predicate.substring(start, end).trim() : predicate.substring(start).replace("]", "").trim();
            return new String[] { method, path };
        }
        return null;
    }

    /**
     * GraphQL 内省查询，提取 Query 和 Mutation 名称。
     */
    public List<DiscoveredEndpoint> discoverFromGraphQLIntrospection(String graphqlUrl, DiscoveryCallback callback) {
        List<DiscoveredEndpoint> result = new ArrayList<>();
        try {
            if (callback != null) callback.onProgress("正在 GraphQL 内省: " + graphqlUrl);
            String resp = fetchUrlContentPost(graphqlUrl, GRAPHQL_INTROSPECTION_QUERY, "application/json");
            if (resp == null || !resp.contains("__schema")) return result;

            JsonObject root = JsonParser.parseString(resp).getAsJsonObject();
            JsonObject data = root.getAsJsonObject("data");
            if (data == null) return result;
            JsonObject schema = data.getAsJsonObject("__schema");
            if (schema == null) return result;

            String path = getPathFromUrl(graphqlUrl);
            if (path == null || path.isEmpty()) path = "/graphql";

            result.add(new DiscoveredEndpoint("POST", path, DiscoveredEndpoint.Source.GRAPHQL, null, null));

            String queryTypeName = null;
            if (schema.has("queryType") && schema.get("queryType").isJsonObject()) {
                JsonElement qn = schema.getAsJsonObject("queryType").get("name");
                if (qn != null && qn.isJsonPrimitive()) queryTypeName = qn.getAsString();
            }
            String mutationTypeName = null;
            if (schema.has("mutationType") && schema.get("mutationType").isJsonObject()) {
                JsonElement mn = schema.getAsJsonObject("mutationType").get("name");
                if (mn != null && mn.isJsonPrimitive()) mutationTypeName = mn.getAsString();
            }

            JsonArray types = schema.getAsJsonArray("types");
            if (types == null) return result;

            for (JsonElement t : types) {
                if (t == null || !t.isJsonObject()) continue;
                JsonObject type = t.getAsJsonObject();
                String kind = type.has("kind") ? type.get("kind").getAsString() : "";
                String name = type.has("name") ? type.get("name").getAsString() : null;
                if (name == null || name.startsWith("__")) continue;
                if (!"OBJECT".equals(kind)) continue;
                if (!name.equals(queryTypeName) && !name.equals(mutationTypeName)) continue;

                String opType = name.equals(mutationTypeName) ? "mutation" : "query";
                JsonArray fields = type.getAsJsonArray("fields");
                if (fields != null) {
                    for (JsonElement f : fields) {
                        if (f == null || !f.isJsonObject()) continue;
                        JsonObject field = f.getAsJsonObject();
                        JsonElement nameEl = field.get("name");
                        if (nameEl == null || !nameEl.isJsonPrimitive()) continue;
                        String fieldName = nameEl.getAsString();
                        List<String> argNames = new ArrayList<>();
                        List<String> argTypes = new ArrayList<>();
                        if (field.has("args") && field.get("args").isJsonArray()) {
                            for (JsonElement a : field.getAsJsonArray("args")) {
                                if (a != null && a.isJsonObject()) {
                                    JsonObject arg = a.getAsJsonObject();
                                    JsonElement an = arg.get("name");
                                    if (an != null && an.isJsonPrimitive()) {
                                        argNames.add(an.getAsString());
                                        argTypes.add(resolveGraphQLArgType(arg.get("type")));
                                    }
                                }
                            }
                        }
                        if (result.size() >= MAX_DISCOVERED_LIMIT) break;
                        result.add(new DiscoveredEndpoint("POST", path, DiscoveredEndpoint.Source.GRAPHQL, null, fieldName,
                                argNames.isEmpty() ? null : argNames, argTypes.isEmpty() ? null : argTypes, opType));
                    }
                }
            }
        } catch (Exception e) {
            if (BurpExtender.callbacks != null) {
                BurpExtender.callbacks.printError("[API Discovery] GraphQL 内省失败: " + e.getMessage());
            }
        }
        return result;
    }

    private String resolveGraphQLArgType(JsonElement typeEl) {
        if (typeEl == null || !typeEl.isJsonObject()) return "String";
        JsonObject type = typeEl.getAsJsonObject();
        String kind = type.has("kind") && type.get("kind").isJsonPrimitive() ? type.get("kind").getAsString() : "";
        if ("NON_NULL".equals(kind)) {
            String inner = resolveGraphQLArgType(type.get("ofType"));
            return inner + "!";
        }
        if ("LIST".equals(kind)) {
            String inner = resolveGraphQLArgType(type.get("ofType"));
            return "[" + inner + "]";
        }
        if (type.has("name") && type.get("name").isJsonPrimitive()) {
            return type.get("name").getAsString();
        }
        return "String";
    }

    private String getPathFromUrl(String urlStr) {
        try {
            URL u = new URL(urlStr);
            String p = u.getPath();
            return (p == null || p.isEmpty()) ? "/graphql" : p;
        } catch (Exception e) {
            return "/graphql";
        }
    }

    private void extractFromJsContent(String content, Set<DiscoveredEndpoint> result, DiscoveredEndpoint.Source source) {
        for (Pattern p : JS_PATTERNS) {
            Matcher m = p.matcher(content);
            while (m.find()) {
                String path;
                String method = "GET";
                if (p == JS_PATTERNS[1]) {
                    method = m.group(1) != null ? m.group(1).toUpperCase() : "GET";
                    path = m.groupCount() >= 2 ? m.group(2) : null;
                } else {
                    path = m.group(1);
                }
                if (path != null && isRelevantPath(path) && result.size() < MAX_DISCOVERED_LIMIT) {
                    result.add(new DiscoveredEndpoint(method, path, source));
                }
            }
        }
    }

    private boolean isRelevantPath(String path) {
        if (path == null || path.length() < 2) return false;
        if (path.startsWith("//")) return false;
        if (path.contains(".css") || path.contains(".png") || path.contains(".jpg") || path.contains(".ico")) return false;
        return path.startsWith("/api") || path.startsWith("/v") || path.startsWith("/internal");
    }

    private String fetchUrlContent(String urlStr) {
        HttpURLConnection conn = null;
        try {
            URL url = new URL(urlStr);
            conn = (HttpURLConnection) url.openConnection();
            conn.setRequestMethod("GET");
            conn.setConnectTimeout(3000);
            conn.setReadTimeout(3000);
            conn.setRequestProperty("User-Agent", "AuthAnalyzer/1.0");
            int code = conn.getResponseCode();
            if (code >= 200 && code < 300) {
                try (BufferedReader r = new BufferedReader(
                        new InputStreamReader(conn.getInputStream(), StandardCharsets.UTF_8))) {
                    StringBuilder sb = new StringBuilder();
                    String line;
                    while ((line = r.readLine()) != null) sb.append(line).append("\n");
                    return sb.toString();
                }
            }
            logFetchError("GET", urlStr, "HTTP " + code);
        } catch (SocketTimeoutException e) {
            logFetchError("GET", urlStr, "Timeout");
        } catch (Exception e) {
            logFetchError("GET", urlStr, e.getMessage());
        } finally {
            if (conn != null) conn.disconnect();
        }
        return null;
    }

    private boolean looksLikeHtml(String content) {
        if (content == null || content.length() < 10) return false;
        String t = content.trim();
        return t.startsWith("<") || t.startsWith("<!") || t.startsWith("<?") || t.toLowerCase().contains("<html");
    }

    private void logFetchError(String method, String urlStr, String reason) {
        if (BurpExtender.callbacks != null) {
            BurpExtender.callbacks.printError("[API Discovery] " + method + " " + urlStr + " 失败: " + reason);
        }
    }

    private String fetchUrlContentPost(String urlStr, String body, String contentType) {
        HttpURLConnection conn = null;
        try {
            URL url = new URL(urlStr);
            conn = (HttpURLConnection) url.openConnection();
            conn.setRequestMethod("POST");
            conn.setConnectTimeout(3000);
            conn.setReadTimeout(5000);
            conn.setDoOutput(true);
            conn.setRequestProperty("User-Agent", "AuthAnalyzer/1.0");
            conn.setRequestProperty("Content-Type", contentType);
            conn.setRequestProperty("Content-Length", String.valueOf(body.getBytes(StandardCharsets.UTF_8).length));
            try (OutputStream os = conn.getOutputStream()) {
                os.write(body.getBytes(StandardCharsets.UTF_8));
            }
            int code = conn.getResponseCode();
            if (code >= 200 && code < 300) {
                try (BufferedReader r = new BufferedReader(
                        new InputStreamReader(conn.getInputStream(), StandardCharsets.UTF_8))) {
                    StringBuilder sb = new StringBuilder();
                    String line;
                    while ((line = r.readLine()) != null) sb.append(line).append("\n");
                    return sb.toString();
                }
            }
            logFetchError("POST", urlStr, "HTTP " + code);
        } catch (SocketTimeoutException e) {
            logFetchError("POST", urlStr, "Timeout");
        } catch (Exception e) {
            logFetchError("POST", urlStr, e.getMessage());
        } finally {
            if (conn != null) conn.disconnect();
        }
        return null;
    }

    private String toAbsoluteUrl(String ref, String baseOrigin) {
        if (ref == null) return baseOrigin;
        ref = ref.trim();
        if (ref.startsWith("http://") || ref.startsWith("https://")) return ref;
        if (ref.startsWith("//")) return "https:" + ref;
        if (ref.startsWith("/")) return baseOrigin + ref;
        return baseOrigin + "/" + ref;
    }

    private String getBaseOrigin(String url) {
        if (url == null) return "";
        try {
            URL u = new URL(url);
            return u.getProtocol() + "://" + u.getHost()
                    + (u.getPort() > 0 && u.getPort() != 80 && u.getPort() != 443 ? ":" + u.getPort() : "");
        } catch (Exception e) {
            return url;
        }
    }

    public interface DiscoveryCallback {
        void onProgress(String msg);
        void onError(String msg);
    }
}
