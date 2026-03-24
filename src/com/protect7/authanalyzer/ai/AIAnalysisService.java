package com.protect7.authanalyzer.ai;

import java.io.BufferedReader;
import java.io.InputStreamReader;
import java.io.OutputStream;
import java.net.HttpURLConnection;
import java.net.URL;
import java.nio.charset.StandardCharsets;
import java.util.Arrays;
import java.util.List;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.concurrent.atomic.AtomicBoolean;

import com.google.gson.JsonArray;
import com.google.gson.JsonObject;
import com.google.gson.JsonParser;

import burp.BurpExtender;
import burp.IHttpRequestResponse;
import burp.IResponseInfo;

import com.protect7.authanalyzer.entities.AnalyzerRequestResponse;
import com.protect7.authanalyzer.entities.OriginalRequestResponse;
import com.protect7.authanalyzer.entities.Session;
import com.protect7.authanalyzer.util.CurrentConfig;

/**
 * 后台 AI 分析服务：将越权检测结果逐条发送给 OpenAI 兼容 API，返回分析摘要。
 * 纯 HttpURLConnection，无额外依赖。
 */
public class AIAnalysisService {

    /** 单条请求/响应发送给 LLM 时的最大字符数，超出则截断 */
    private static final int MAX_CONTENT_CHARS = 3000;

    private static final String DEFAULT_SYSTEM_PROMPT =
        "你是一名专业的 Web 安全研究员。\n" +
        "用户会给你提供原始 HTTP 请求/响应，以及用不同 Session（权限）重放后的请求/响应和绕过状态。\n" +
        "SAME 表示重放响应与原始响应完全相同，SIMILAR 表示高度相似，均为潜在越权。\n" +
        "请直接输出以下三行，每行都必须有实质文字内容，不得留空或省略：\n" +
        "风险等级：（填写：高 / 中 / 低 / 无，并在括号内一句话说明理由）\n" +
        "分析依据：（2-3句话，结合请求路径、参数、响应内容说明判断依据）\n" +
        "修复建议：（1句话具体建议，如无风险则写：响应差异明显，暂无越权风险）";

    private final String baseUrl;
    private final String apiKey;
    private final String model;
    private final String systemPrompt;
    private final int concurrency;

    private ExecutorService executor;
    private final AtomicBoolean running = new AtomicBoolean(false);

    public AIAnalysisService(String baseUrl, String apiKey, String model, String systemPrompt, int concurrency) {
        this.baseUrl = baseUrl.endsWith("/") ? baseUrl.substring(0, baseUrl.length() - 1) : baseUrl;
        this.apiKey = apiKey;
        this.model = model;
        this.systemPrompt = (systemPrompt == null || systemPrompt.trim().isEmpty()) ? DEFAULT_SYSTEM_PROMPT : systemPrompt;
        this.concurrency = Math.max(1, Math.min(concurrency, 5));
    }

    /**
     * 异步批量分析，对 ResultTableModel 中筛出的条目逐条调用 LLM。
     *
     * @param items    待分析的 OriginalRequestResponse 列表（应仅包含 SAME/SIMILAR）
     * @param sessions 当前所有 Session（用于获取重放请求/响应）
     * @param listener 进度与结果回调（在工作线程中调用，UI 更新需 invokeLater）
     */
    public void analyzeAsync(List<OriginalRequestResponse> items,
                             List<Session> sessions,
                             AnalysisListener listener) {
        if (running.getAndSet(true)) return; // already running
        executor = Executors.newFixedThreadPool(concurrency);

        new Thread(() -> {
            try {
                int total = items.size();
                if (listener != null) listener.onStart(total);

                int[] done = {0};
                // submit all tasks and collect futures to detect completion
                Future<?>[] futures = new Future[total];
                for (int i = 0; i < total; i++) {
                    if (!running.get()) break;
                    final OriginalRequestResponse orr = items.get(i);
                    final int idx = i;
                    futures[i] = executor.submit(() -> {
                        if (!running.get()) return;
                        String result = analyzeOne(orr, sessions);
                        synchronized (done) {
                            done[0]++;
                            if (listener != null)
                                listener.onResult(idx, orr, result, done[0], total);
                        }
                    });
                }
                // wait for all
                for (Future<?> f : futures) {
                    if (f != null) {
                        try { f.get(); } catch (Exception ignored) {}
                    }
                }
            } finally {
                running.set(false);
                executor.shutdown();
                if (listener != null) listener.onFinished();
            }
        }, "AI-Analysis-Dispatcher").start();
    }

    /** 停止正在进行的分析 */
    public void stop() {
        running.set(false);
        if (executor != null) executor.shutdownNow();
    }

    public boolean isRunning() {
        return running.get();
    }

    // -------------------------------------------------------------------------
    // 核心：分析单条记录
    // -------------------------------------------------------------------------

    private String analyzeOne(OriginalRequestResponse orr, List<Session> sessions) {
        try {
            StringBuilder sb = new StringBuilder();
            sb.append("===== 原始请求 =====\n");
            sb.append(truncate(getRequestText(orr.getRequestResponse()))).append("\n");
            sb.append("===== 原始响应 =====\n");
            sb.append(truncate(getResponseText(orr.getRequestResponse()))).append("\n");

            for (Session s : sessions) {
                AnalyzerRequestResponse arr = s.getRequestResponseMap().get(orr.getId());
                if (arr == null) continue;
                sb.append("===== Session[").append(s.getName()).append("] 重放请求 =====\n");
                sb.append(truncate(getRequestText(arr.getRequestResponse()))).append("\n");
                sb.append("===== Session[").append(s.getName()).append("] 重放响应 =====\n");
                sb.append(truncate(getResponseText(arr.getRequestResponse()))).append("\n");
                sb.append("绕过状态: ").append(arr.getStatus()).append("\n");
            }

            sb.append("\n请根据以上数据，按要求格式输出分析结论。");
            return callLLM(sb.toString());
        } catch (Exception e) {
            return "[分析失败] " + e.getMessage();
        }
    }

    // -------------------------------------------------------------------------
    // HTTP 调用 LLM
    // -------------------------------------------------------------------------

    private String callLLM(String userContent) throws Exception {
        String endpoint = baseUrl + "/chat/completions";
        URL url = new URL(endpoint);
        HttpURLConnection conn = (HttpURLConnection) url.openConnection();
        conn.setRequestMethod("POST");
        conn.setConnectTimeout(15000);
        conn.setReadTimeout(60000);
        conn.setDoOutput(true);
        conn.setRequestProperty("Content-Type", "application/json");
        conn.setRequestProperty("Authorization", "Bearer " + apiKey);

        JsonObject body = new JsonObject();
        body.addProperty("model", model);
        body.addProperty("stream", false);
        body.addProperty("max_tokens", 512);

        JsonArray messages = new JsonArray();
        JsonObject sys = new JsonObject();
        sys.addProperty("role", "system");
        sys.addProperty("content", systemPrompt);
        messages.add(sys);

        JsonObject user = new JsonObject();
        user.addProperty("role", "user");
        user.addProperty("content", userContent);
        messages.add(user);

        body.add("messages", messages);

        byte[] bodyBytes = body.toString().getBytes(StandardCharsets.UTF_8);
        try (OutputStream os = conn.getOutputStream()) {
            os.write(bodyBytes);
        }

        int code = conn.getResponseCode();
        if (code < 200 || code >= 300) {
            java.io.InputStream errStream = conn.getErrorStream();
            String errBody = "";
            if (errStream != null) {
                BufferedReader err = new BufferedReader(
                        new InputStreamReader(errStream, StandardCharsets.UTF_8));
                StringBuilder sb = new StringBuilder();
                String line;
                while ((line = err.readLine()) != null) sb.append(line);
                errBody = sb.toString();
            }
            conn.disconnect();
            // 如果是 HTML 错误页，截取前 300 字方便诊断
            String preview = errBody.length() > 300 ? errBody.substring(0, 300) + "..." : errBody;
            throw new Exception("HTTP " + code + " - " + preview);
        }

        BufferedReader reader = new BufferedReader(
                new InputStreamReader(conn.getInputStream(), StandardCharsets.UTF_8));
        StringBuilder resp = new StringBuilder();
        String line;
        while ((line = reader.readLine()) != null) resp.append(line).append("\n");
        conn.disconnect();

        return parseContent(resp.toString());
    }

    /**
     * 测试 API 连通性：发送一条最简单的 chat 请求，返回诊断信息。
     * 在后台线程调用，结果通过 callback 返回。
     */
    public void testConnectionAsync(Runnable onStart, java.util.function.Consumer<String> onResult) {
        new Thread(() -> {
            if (onStart != null) onStart.run();
            try {
                String endpoint = baseUrl + "/chat/completions";
                URL url = new URL(endpoint);
                HttpURLConnection conn = (HttpURLConnection) url.openConnection();
                conn.setRequestMethod("POST");
                conn.setConnectTimeout(10000);
                conn.setReadTimeout(20000);
                conn.setDoOutput(true);
                conn.setRequestProperty("Content-Type", "application/json");
                conn.setRequestProperty("Authorization", "Bearer " + apiKey);

                JsonObject body = new JsonObject();
                body.addProperty("model", model);
                body.addProperty("max_tokens", 5);
                JsonArray messages = new JsonArray();
                JsonObject msg = new JsonObject();
                msg.addProperty("role", "user");
                msg.addProperty("content", "hi");
                messages.add(msg);
                body.add("messages", messages);

                byte[] bodyBytes = body.toString().getBytes(StandardCharsets.UTF_8);
                try (OutputStream os = conn.getOutputStream()) { os.write(bodyBytes); }

                int code = conn.getResponseCode();
                if (code >= 200 && code < 300) {
                    BufferedReader r = new BufferedReader(
                            new InputStreamReader(conn.getInputStream(), StandardCharsets.UTF_8));
                    StringBuilder sb = new StringBuilder();
                    String l; while ((l = r.readLine()) != null) sb.append(l);
                    conn.disconnect();
                    // 尝试解析，能拿到 content 说明完全正常
                    try {
                        String content = parseContent(sb.toString());
                        onResult.accept("[连接成功] 模型响应正常。回复预览: " + content.substring(0, Math.min(40, content.length())));
                    } catch (Exception e) {
                        onResult.accept("[连接成功] HTTP 200，但响应格式异常: " + sb.substring(0, Math.min(200, sb.length())));
                    }
                } else {
                    java.io.InputStream errStream = conn.getErrorStream();
                    String errBody = "";
                    if (errStream != null) {
                        BufferedReader err = new BufferedReader(
                                new InputStreamReader(errStream, StandardCharsets.UTF_8));
                        StringBuilder sb = new StringBuilder();
                        String l; while ((l = err.readLine()) != null) sb.append(l);
                        errBody = sb.toString();
                    }
                    conn.disconnect();
                    String preview = errBody.length() > 300 ? errBody.substring(0, 300) + "..." : errBody;
                    onResult.accept("[连接失败] HTTP " + code + "\n" + preview);
                }
            } catch (Exception e) {
                onResult.accept("[连接异常] " + e.getClass().getSimpleName() + ": " + e.getMessage());
            }
        }, "AI-Connection-Test").start();
    }

    /** 从 OpenAI 格式响应中提取 choices[0].message.content */
    private String parseContent(String json) {
        try {
            JsonObject root = JsonParser.parseString(json).getAsJsonObject();
            return root.getAsJsonArray("choices")
                    .get(0).getAsJsonObject()
                    .getAsJsonObject("message")
                    .get("content").getAsString();
        } catch (Exception e) {
            // 截取前 300 字方便诊断
            String preview = json.length() > 300 ? json.substring(0, 300) + "..." : json;
            throw new RuntimeException("LLM 响应不是合法 JSON 或缺少 choices 字段。响应预览:\n" + preview, e);
        }
    }

    // -------------------------------------------------------------------------
    // 工具方法
    // -------------------------------------------------------------------------

    private String getRequestText(IHttpRequestResponse rr) {
        if (rr == null || rr.getRequest() == null) return "[无请求数据]";
        return BurpExtender.callbacks.getHelpers().bytesToString(rr.getRequest());
    }

    private String getResponseText(IHttpRequestResponse rr) {
        if (rr == null || rr.getResponse() == null) return "[无响应数据]";
        try {
            byte[] resp = rr.getResponse();
            IResponseInfo ri = BurpExtender.callbacks.getHelpers().analyzeResponse(resp);
            String head = String.join("\r\n", ri.getHeaders());
            String bodyBytes = BurpExtender.callbacks.getHelpers().bytesToString(
                    Arrays.copyOfRange(resp, ri.getBodyOffset(), resp.length));
            return head + "\r\n\r\n" + bodyBytes;
        } catch (Exception e) {
            return "[响应解析失败]";
        }
    }

    private String truncate(String s) {
        if (s == null) return "";
        return s.length() > MAX_CONTENT_CHARS ? s.substring(0, MAX_CONTENT_CHARS) + "\n...[已截断]" : s;
    }

    // -------------------------------------------------------------------------
    // 回调接口
    // -------------------------------------------------------------------------

    public interface AnalysisListener {
        /** 分析开始，total 为总条数 */
        void onStart(int total);
        /** 单条分析完成 */
        void onResult(int index, OriginalRequestResponse orr, String aiResult, int done, int total);
        /** 全部完成或被停止 */
        void onFinished();
    }

    public static String getDefaultSystemPrompt() {
        return DEFAULT_SYSTEM_PROMPT;
    }
}
