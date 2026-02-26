package com.protect7.authanalyzer.uitesting.discovery;

import java.net.MalformedURLException;
import java.net.URL;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

import burp.BurpExtender;
import burp.IExtensionHelpers;
import burp.IHttpRequestResponse;
import burp.IHttpService;
import burp.IRequestInfo;

/**
 * 根据发现的端点和 Original 的 headers 构造可送入 Analyzer 的 HTTP 请求。
 */
public class SyntheticRequestBuilder {

    private static final String[] PATH_PARAM_PLACEHOLDERS = { "1", "me", "current" };

    /**
     * 构造 IHttpRequestResponse，使用 Original 的 headers 发起请求以获取 response。
     */
    public static IHttpRequestResponse buildAndExecute(DiscoveredEndpoint endpoint, String baseUrl,
            String headersToReplace, java.util.function.Consumer<String> log) {
        if (endpoint == null || baseUrl == null) return null;

        IExtensionHelpers helpers = BurpExtender.callbacks.getHelpers();
        String fullUrl = buildFullUrl(baseUrl, endpoint.getPath());
        if (fullUrl == null) return null;

        try {
            URL url = new URL(fullUrl);
            IHttpService service = helpers.buildHttpService(
                    url.getHost(),
                    url.getPort() > 0 ? url.getPort() : (url.getProtocol().equalsIgnoreCase("https") ? 443 : 80),
                    url.getProtocol().equalsIgnoreCase("https"));

            byte[] requestBytes = buildRequest(helpers, url, endpoint.getMethod(), headersToReplace);
            if (requestBytes == null) return null;

            IHttpRequestResponse rr = BurpExtender.callbacks.makeHttpRequest(service, requestBytes);
            if (rr != null && rr.getResponse() != null && rr.getResponse().length > 0) {
                return rr;
            }
            return rr;
        } catch (Exception e) {
            if (log != null) log.accept("构造请求失败 " + endpoint + ": " + e.getMessage());
            return null;
        }
    }

    private static String buildFullUrl(String baseUrl, String path) {
        try {
            URL base = new URL(baseUrl);
            String origin = base.getProtocol() + "://" + base.getHost()
                    + (base.getPort() > 0 && base.getPort() != 80 && base.getPort() != 443 ? ":" + base.getPort() : "");
            String p = path != null ? path : "/";
            if (!p.startsWith("/")) p = "/" + p;
            p = p.replaceAll("\\{[^}]+\\}", "1");
            return origin + p;
        } catch (MalformedURLException e) {
            return null;
        }
    }

    private static byte[] buildRequest(IExtensionHelpers helpers, URL url, String method, String headersToReplace) {
        byte[] baseRequest = helpers.buildHttpRequest(url);
        IRequestInfo info = helpers.analyzeRequest(baseRequest);
        List<String> headers = new ArrayList<>(info.getHeaders());
        byte[] body = Arrays.copyOfRange(baseRequest, info.getBodyOffset(), baseRequest.length);

        if (method != null && !"GET".equalsIgnoreCase(method)) {
            for (int i = 0; i < headers.size(); i++) {
                if (headers.get(i).trim().toLowerCase().startsWith("get ")) {
                    headers.set(i, method + " " + url.getPath() + (url.getQuery() != null ? "?" + url.getQuery() : "") + " HTTP/1.1");
                    break;
                }
            }
        }

        if (headersToReplace != null && !headersToReplace.trim().isEmpty()) {
            String[] lines = headersToReplace.replace("\r", "").split("\n");
            for (String line : lines) {
                line = line.trim();
                if (line.isEmpty()) continue;
                int colon = line.indexOf(':');
                if (colon <= 0) continue;
                String headerName = line.substring(0, colon).trim().toLowerCase();
                boolean replaced = false;
                for (int i = 0; i < headers.size(); i++) {
                    String h = headers.get(i);
                    int hColon = h.indexOf(':');
                    if (hColon > 0 && h.substring(0, hColon).trim().equalsIgnoreCase(headerName)) {
                        headers.set(i, line);
                        replaced = true;
                        break;
                    }
                }
                if (!replaced) headers.add(line);
            }
        }

        return helpers.buildHttpMessage(headers, body);
    }

    /**
     * 替换路径中的 {param} 占位符，生成可探测的路径变体。
     */
    public static List<String> expandPathWithParams(String path) {
        List<String> result = new ArrayList<>();
        if (path == null) return result;
        if (!path.contains("{")) {
            result.add(path);
            return result;
        }
        for (String ph : PATH_PARAM_PLACEHOLDERS) {
            result.add(path.replaceAll("\\{[^}]+\\}", ph));
        }
        return result;
    }
}
