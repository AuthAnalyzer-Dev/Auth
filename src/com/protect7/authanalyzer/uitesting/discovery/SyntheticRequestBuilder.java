package com.protect7.authanalyzer.uitesting.discovery;

import java.net.MalformedURLException;
import java.net.URL;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

import com.google.gson.Gson;

import burp.BurpExtender;
import burp.IExtensionHelpers;
import burp.IHttpRequestResponse;
import burp.IHttpService;
import burp.IRequestInfo;

/**
 * 根据发现的端点和 Original 的 headers 构造可送入 Analyzer 的 HTTP 请求。
 * 支持基于 OpenAPI Schema 的智能参数替换和 RequestBody 生成。
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
        String fullUrl = buildFullUrl(baseUrl, endpoint);
        if (fullUrl == null) return null;

        try {
            URL url = new URL(fullUrl);
            IHttpService service = helpers.buildHttpService(
                    url.getHost(),
                    url.getPort() > 0 ? url.getPort() : (url.getProtocol().equalsIgnoreCase("https") ? 443 : 80),
                    url.getProtocol().equalsIgnoreCase("https"));

            byte[] requestBytes = buildRequest(helpers, url, endpoint, headersToReplace);
            if (requestBytes == null) return null;

            IHttpRequestResponse rr = BurpExtender.callbacks.makeHttpRequest(service, requestBytes);
            return rr;
        } catch (Exception e) {
            if (log != null) log.accept("构造请求失败 " + endpoint + ": " + e.getMessage());
            return null;
        }
    }

    /**
     * 构建完整 URL，根据 EndpointSchema 智能替换路径参数。
     */
    private static String buildFullUrl(String baseUrl, DiscoveredEndpoint endpoint) {
        try {
            URL base = new URL(baseUrl);
            String origin = base.getProtocol() + "://" + base.getHost()
                    + (base.getPort() > 0 && base.getPort() != 80 && base.getPort() != 443 ? ":" + base.getPort() : "");
            String path = endpoint.getPath() != null ? endpoint.getPath() : "/";
            if (!path.startsWith("/")) path = "/" + path;

            EndpointSchema schema = endpoint.getEndpointSchema();
            if (schema != null && !schema.getPathParams().isEmpty()) {
                path = SchemaBasedBodyGenerator.replacePathParams(path, schema.getPathParams());
            } else {
                path = path.replaceAll("\\{[^}]+\\}", "1");
            }
            return origin + path;
        } catch (MalformedURLException e) {
            return null;
        }
    }

    private static byte[] buildRequest(IExtensionHelpers helpers, URL url, DiscoveredEndpoint endpoint,
            String headersToReplace) {
        String method = endpoint.getMethod();
        byte[] body;
        boolean hasBody = method != null && ("POST".equalsIgnoreCase(method) || "PUT".equalsIgnoreCase(method) || "PATCH".equalsIgnoreCase(method));

        if (hasBody) {
            if (DiscoveredEndpoint.Source.GRAPHQL.equals(endpoint.getSource())) {
                body = buildGraphQLBody(endpoint);
            } else {
                EndpointSchema schema = endpoint.getEndpointSchema();
                if (schema != null && schema.getRequestBodySchema() != null) {
                    String jsonBody = SchemaBasedBodyGenerator.generateRequestBody(
                            schema.getRequestBodySchema(), schema.getComponents());
                    body = jsonBody.getBytes(StandardCharsets.UTF_8);
                } else {
                    body = "{}".getBytes(StandardCharsets.UTF_8);
                }
            }
        } else {
            body = new byte[0];
        }

        byte[] baseRequest = helpers.buildHttpRequest(url);
        IRequestInfo info = helpers.analyzeRequest(baseRequest);
        List<String> headers = new ArrayList<>(info.getHeaders());

        if (method != null && !"GET".equalsIgnoreCase(method)) {
            for (int i = 0; i < headers.size(); i++) {
                if (headers.get(i).trim().toLowerCase().startsWith("get ")) {
                    headers.set(i, method + " " + url.getPath() + (url.getQuery() != null ? "?" + url.getQuery() : "") + " HTTP/1.1");
                    break;
                }
            }
        }

        if (hasBody && body.length > 0) {
            boolean hasContentType = false;
            for (String h : headers) {
                if (h.trim().toLowerCase().startsWith("content-type:")) {
                    hasContentType = true;
                    break;
                }
            }
            if (!hasContentType) {
                headers.add("Content-Type: application/json");
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

        if (!hasBody) {
            body = Arrays.copyOfRange(baseRequest, info.getBodyOffset(), baseRequest.length);
        }
        return helpers.buildHttpMessage(headers, body);
    }

    private static byte[] buildGraphQLBody(DiscoveredEndpoint endpoint) {
        String op = endpoint.getGraphqlOperation();
        String opType = endpoint.getGraphqlOperationType();
        if (opType == null || opType.isEmpty()) opType = "query";
        List<String> argNames = endpoint.getGraphqlArgNames();
        List<String> argTypes = endpoint.getGraphqlArgTypes();

        String query;
        Map<String, Object> variables = new LinkedHashMap<>();
        if (op != null && !op.isEmpty() && argNames != null && !argNames.isEmpty()) {
            StringBuilder varDecls = new StringBuilder();
            StringBuilder args = new StringBuilder();
            for (int i = 0; i < argNames.size(); i++) {
                String name = argNames.get(i);
                String type = (argTypes != null && i < argTypes.size()) ? argTypes.get(i) : "String";
                if (!type.endsWith("!")) type = type + "!";
                if (i > 0) {
                    varDecls.append(", ");
                    args.append(", ");
                }
                varDecls.append("$").append(name).append(": ").append(type);
                args.append(name).append(": $").append(name);
                variables.put(name, graphqlArgMockValue(type));
            }
            query = opType + " " + op + "(" + varDecls + ") { " + op + "(" + args + ") { __typename } }";
        } else if (op != null && !op.isEmpty()) {
            query = opType + " " + op + " { " + op + " { __typename } }";
        } else {
            query = "{ __typename }";
        }

        Map<String, Object> body = new LinkedHashMap<>();
        body.put("query", query);
        if (!variables.isEmpty()) body.put("variables", variables);
        return new Gson().toJson(body).getBytes(StandardCharsets.UTF_8);
    }

    private static Object graphqlArgMockValue(String type) {
        String base = type.replace("!", "").replace("[", "").replace("]", "");
        if ("ID".equals(base) || "UUID".equals(base)) return "1";
        if ("Int".equals(base) || "Long".equals(base)) return 1;
        if ("Float".equals(base) || "Decimal".equals(base)) return 1.0;
        if ("Boolean".equals(base)) return true;
        if ("DateTime".equals(base) || "Date".equals(base)) return "2024-01-01T00:00:00Z";
        return "1";
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
