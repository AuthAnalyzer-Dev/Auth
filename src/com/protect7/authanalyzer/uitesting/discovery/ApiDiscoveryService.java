package com.protect7.authanalyzer.uitesting.discovery;

import java.io.BufferedReader;
import java.io.InputStreamReader;
import java.net.HttpURLConnection;
import java.net.URL;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.HashSet;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Set;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import com.google.gson.JsonObject;
import com.google.gson.JsonParser;
import org.openqa.selenium.By;
import org.openqa.selenium.WebDriver;
import org.openqa.selenium.WebElement;

/**
 * API 发现服务：从 JS 提取、从 Swagger 探测。
 */
public class ApiDiscoveryService {

    private static final Pattern[] JS_PATTERNS = {
        // fetch('/api/xxx'), fetch("/api/xxx"), fetch(`/api/xxx`)
        Pattern.compile("fetch\\s*\\(\\s*['\"`](/[^'\"`\\s]+)['\"`]"),
        // axios.get('/api/xxx'), axios.post("/api/xxx")
        Pattern.compile("axios\\.(get|post|put|delete|patch)\\s*\\(\\s*['\"`](/[^'\"`\\s]+)['\"`]"),
        // $.ajax({ url: '/api/xxx' })
        Pattern.compile("url\\s*:\\s*['\"`](/[^'\"`\\s]+)['\"`]"),
        // "/api/xxx" 或 '/api/xxx' 作为路径（较宽松，可能误报）
        Pattern.compile("['\"`](/api/[^'\"`\\s?]*)[?\"'`]?"),
        Pattern.compile("['\"`](/v[0-9]+/[^'\"`\\s?]*)[?\"'`]?"),
    };

    private static final String[] SWAGGER_PATHS = {
        "/swagger.json",
        "/swagger/v1/swagger.json",
        "/v2/api-docs",
        "/v3/api-docs",
        "/api-docs",
        "/api/swagger.json",
        "/openapi.json",
    };

    private static final String[] DEFAULT_HTTP_METHODS = { "GET", "POST", "PUT", "DELETE" };

    /**
     * 从当前页面的 JS 文件中提取 API 端点。
     */
    public List<DiscoveredEndpoint> discoverFromJs(WebDriver driver, String baseUrl, DiscoveryCallback callback) {
        Set<DiscoveredEndpoint> result = new LinkedHashSet<>();
        if (driver == null || baseUrl == null) return new ArrayList<>(result);

        String baseOrigin = getBaseOrigin(baseUrl);

        try {
            List<WebElement> scripts = driver.findElements(By.tagName("script"));
            for (WebElement script : scripts) {
                String src = script.getAttribute("src");
                String content = null;

                if (src != null && !src.trim().isEmpty()) {
                    String scriptUrl = toAbsoluteUrl(src, baseOrigin);
                    if (callback != null) callback.onProgress("正在获取: " + scriptUrl);
                    content = fetchUrlContent(scriptUrl);
                } else {
                    content = script.getAttribute("innerHTML");
                }

                if (content != null && !content.isEmpty()) {
                    extractFromJsContent(content, result);
                }
            }

        } catch (Exception e) {
            if (callback != null) callback.onError("JS 提取失败: " + e.getMessage());
        }

        return new ArrayList<>(result);
    }

    /**
     * 从 Swagger/OpenAPI 文档探测 API 端点。
     */
    public List<DiscoveredEndpoint> discoverFromSwagger(String baseUrl, DiscoveryCallback callback) {
        Set<DiscoveredEndpoint> result = new LinkedHashSet<>();
        if (baseUrl == null) return new ArrayList<>(result);

        String baseOrigin = getBaseOrigin(baseUrl);

        for (String docPath : SWAGGER_PATHS) {
            String docUrl = baseOrigin + docPath;
            if (callback != null) callback.onProgress("正在探测: " + docUrl);

            String json = fetchUrlContent(docUrl);
            if (json == null || json.isEmpty()) continue;

            try {
                JsonObject root = JsonParser.parseString(json).getAsJsonObject();
                JsonObject paths = root.getAsJsonObject("paths");
                if (paths == null) continue;

                for (String path : paths.keySet()) {
                    JsonObject pathObj = paths.getAsJsonObject(path);
                    if (pathObj == null) continue;

                    for (String method : pathObj.keySet()) {
                        if (DEFAULT_HTTP_METHODS[0].equalsIgnoreCase(method)
                                || DEFAULT_HTTP_METHODS[1].equalsIgnoreCase(method)
                                || DEFAULT_HTTP_METHODS[2].equalsIgnoreCase(method)
                                || DEFAULT_HTTP_METHODS[3].equalsIgnoreCase(method)
                                || "patch".equalsIgnoreCase(method)) {
                            result.add(new DiscoveredEndpoint(method.toUpperCase(), path, DiscoveredEndpoint.Source.SWAGGER));
                        }
                    }
                }
                if (callback != null) callback.onProgress("已从 Swagger 解析 " + result.size() + " 个端点");
                break;
            } catch (Exception e) {
                if (callback != null) callback.onError("解析 Swagger 失败: " + e.getMessage());
            }
        }

        return new ArrayList<>(result);
    }

    private void extractFromJsContent(String content, Set<DiscoveredEndpoint> result) {
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
                if (path != null && isRelevantPath(path)) {
                    result.add(new DiscoveredEndpoint(method, path, DiscoveredEndpoint.Source.JS));
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
        } catch (Exception ignore) {
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
            return u.getProtocol() + "://" + u.getHost() + (u.getPort() > 0 && u.getPort() != 80 && u.getPort() != 443 ? ":" + u.getPort() : "");
        } catch (Exception e) {
            return url;
        }
    }

    public interface DiscoveryCallback {
        void onProgress(String msg);
        void onError(String msg);
    }
}
