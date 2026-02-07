package com.protect7.authanalyzer.uitesting.runner;

import burp.IHttpRequestResponse;
import burp.IRequestInfo;
import burp.IResponseInfo;

import java.io.PrintWriter;
import java.util.*;
import java.util.concurrent.ConcurrentHashMap;

public class DualDetectionManager {

    private static final Map<String, RequestPair> pendingRequests = new ConcurrentHashMap<>();
    private static final List<ComparisonResult> results = Collections.synchronizedList(new ArrayList<ComparisonResult>());
    private static volatile boolean enabled = false;
    private static PrintWriter stdout, stderr;

    public static class RequestPair {
        String key;
        long timestamp;
        IHttpRequestResponse requestA;
        IHttpRequestResponse requestB;

        public boolean isComplete() {
            return requestA != null && requestB != null;
        }
    }

    public static class ComparisonResult {
        String url;
        String method;
        boolean isTrivialAPI;
        String reason;
        int statusCodeA;
        int statusCodeB;
        int responseLengthA;
        int responseLengthB;
        long timestamp;

        @Override
        public String toString() {
            StringBuilder sb = new StringBuilder();
            sb.append("\n  [").append(isTrivialAPI ? "TRIVIAL" : "PROTECTED").append("] ");
            sb.append(method).append(" ").append(url);
            sb.append("\n    Reason: ").append(reason);
            sb.append("\n    Browser A: Status=").append(statusCodeA).append(", Length=").append(responseLengthA).append(" bytes");
            sb.append("\n    Browser B: Status=").append(statusCodeB).append(", Length=").append(responseLengthB).append(" bytes");
            return sb.toString();
        }
    }

    public static void setLoggers(PrintWriter out, PrintWriter err) {
        stdout = out;
        stderr = err;
    }

    public static void enable() {
        enabled = true;
        pendingRequests.clear();
        results.clear();
        log("[DualDetection] Enabled");
    }

    public static void disable() {
        enabled = false;
        log("[DualDetection] Disabled");
    }

    public static boolean isEnabled() {
        return enabled;
    }

    public static void recordRequest(IHttpRequestResponse messageInfo, IRequestInfo requestInfo) {
        if (!enabled) return;

        try {
            String userAgent = getHeader(requestInfo.getHeaders(), "User-Agent");
            if (userAgent == null) return;

            boolean isBrowserA = userAgent.contains("AuthAnalyzer-BrowserA");
            boolean isBrowserB = userAgent.contains("AuthAnalyzer-BrowserB");

            if (!isBrowserA && !isBrowserB) return;

            String method = requestInfo.getMethod();
            String url = requestInfo.getUrl().toString();
            String key = method + ":" + url;

            RequestPair pair = pendingRequests.get(key);
            if (pair == null) {
                pair = new RequestPair();
                pair.key = key;
                pair.timestamp = System.currentTimeMillis();
                pendingRequests.put(key, pair);
            }

            if (isBrowserA) {
                pair.requestA = messageInfo;
                log("[DualDetection] Recorded A: " + method + " " + url);
            } else {
                pair.requestB = messageInfo;
                log("[DualDetection] Recorded B: " + method + " " + url);
            }

            if (pair.isComplete()) {
                compareAndRecord(pair, method, url);
                pendingRequests.remove(key);
            }

        } catch (Exception e) {
            err("[DualDetection] Error: " + e.getMessage());
        }
    }

    private static void compareAndRecord(RequestPair pair, String method, String url) {
        try {
            IResponseInfo respA = burp.BurpExtender.callbacks.getHelpers().analyzeResponse(pair.requestA.getResponse());
            IResponseInfo respB = burp.BurpExtender.callbacks.getHelpers().analyzeResponse(pair.requestB.getResponse());

            ComparisonResult result = new ComparisonResult();
            result.url = url;
            result.method = method;
            result.timestamp = System.currentTimeMillis();
            result.statusCodeA = respA.getStatusCode();
            result.statusCodeB = respB.getStatusCode();

            byte[] bodyA = Arrays.copyOfRange(pair.requestA.getResponse(), respA.getBodyOffset(), pair.requestA.getResponse().length);
            byte[] bodyB = Arrays.copyOfRange(pair.requestB.getResponse(), respB.getBodyOffset(), pair.requestB.getResponse().length);

            result.responseLengthA = bodyA.length;
            result.responseLengthB = bodyB.length;

            if (result.statusCodeA != result.statusCodeB) {
                result.isTrivialAPI = false;
                result.reason = "Different status codes";
            } else if (result.statusCodeA == 401 || result.statusCodeA == 403) {
                result.isTrivialAPI = false;
                result.reason = "Both denied (auth required)";
            } else if (Arrays.equals(bodyA, bodyB)) {
                result.isTrivialAPI = true;
                result.reason = "Identical responses";
            } else {
                double lengthDiff = Math.abs(bodyA.length - bodyB.length) / (double) Math.max(bodyA.length, bodyB.length);
                if (lengthDiff < 0.05) {
                    result.isTrivialAPI = true;
                    result.reason = "Similar responses (~" + String.format("%.1f", lengthDiff * 100) + "% diff)";
                } else {
                    result.isTrivialAPI = false;
                    result.reason = "Different responses (" + String.format("%.1f", lengthDiff * 100) + "% diff)";
                }
            }

            results.add(result);
            log("[DualDetection] " + result.toString());

        } catch (Exception e) {
            err("[DualDetection] Comparison error: " + e.getMessage());
        }
    }

    public static List<ComparisonResult> getResults() {
        return new ArrayList<ComparisonResult>(results);
    }

    public static void clearResults() {
        results.clear();
        pendingRequests.clear();
    }

    public static void cleanupStale() {
        long now = System.currentTimeMillis();
        Iterator<Map.Entry<String, RequestPair>> it = pendingRequests.entrySet().iterator();
        while (it.hasNext()) {
            Map.Entry<String, RequestPair> entry = it.next();
            if (now - entry.getValue().timestamp > 30000) {
                it.remove();
            }
        }
    }

    private static String getHeader(List<String> headers, String name) {
        for (String header : headers) {
            if (header.toLowerCase().startsWith(name.toLowerCase() + ":")) {
                return header.substring(name.length() + 1).trim();
            }
        }
        return null;
    }

    private static void log(String msg) {
        if (stdout != null) stdout.println(msg);
    }

    private static void err(String msg) {
        if (stderr != null) stderr.println(msg);
    }
}
