package com.protect7.authanalyzer.util;

import java.util.HashSet;
import java.util.Set;
import com.google.gson.JsonElement;
import com.google.gson.JsonObject;
import com.google.gson.JsonParser;

/**
 * JSON 结构化差分比较，用于越权检测的响应比对。
 * 解决：
 * - 漏报：B 越权拿到 A 数据，但被报错堆栈/冗余节点包裹导致长度差 > 5%
 * - 误报：公开接口 A/B 数据相同，仅 timestamp/nonce 变化导致无法判 TRIVIAL
 *
 * <p>数组支持：顶层为 JsonArray 时，
 * - deepEqualsIgnoringVolatile：数组长度不同即判 DIFFERENT（如 [A,B] vs [B]）；
 * - collectKeys：递归遍历数组内对象，扁平化收集 keys，用于 keysSimilarity。
 */
public final class JsonStructuralDiffHelper {

    private static final Set<String> VOLATILE_KEYS = new HashSet<>();
    private static final Set<String> ERROR_INDICATOR_KEYS = new HashSet<>();

    static {
        VOLATILE_KEYS.add("timestamp");
        VOLATILE_KEYS.add("nonce");
        VOLATILE_KEYS.add("requestid");
        VOLATILE_KEYS.add("request_id");
        VOLATILE_KEYS.add("_ts");
        VOLATILE_KEYS.add("updatedat");
        VOLATILE_KEYS.add("updated_at");
        VOLATILE_KEYS.add("createdat");
        VOLATILE_KEYS.add("created_at");
        VOLATILE_KEYS.add("lastmodified");
        VOLATILE_KEYS.add("etag");
        VOLATILE_KEYS.add("version");

        ERROR_INDICATOR_KEYS.add("error");
        ERROR_INDICATOR_KEYS.add("errorcode");
        ERROR_INDICATOR_KEYS.add("error_code");
        ERROR_INDICATOR_KEYS.add("code");
        ERROR_INDICATOR_KEYS.add("message");
        ERROR_INDICATOR_KEYS.add("exception");
        ERROR_INDICATOR_KEYS.add("trace");
        ERROR_INDICATOR_KEYS.add("stacktrace");
        ERROR_INDICATOR_KEYS.add("stack_trace");
    }

    private JsonStructuralDiffHelper() {}

    /**
     * 解析 JSON body，解析失败返回 null。
     */
    public static JsonElement parseJson(byte[] body, int bodyOffset, int totalLength) {
        if (body == null || bodyOffset >= totalLength) return null;
        try {
            String str = new String(body, bodyOffset, totalLength - bodyOffset, java.nio.charset.StandardCharsets.UTF_8);
            return JsonParser.parseString(str);
        } catch (Exception e) {
            return null;
        }
    }

    /**
     * 判断是否为 JSON MIME 类型。
     */
    public static boolean isJsonMimeType(String stated, String inferred) {
        if (stated == null) stated = "";
        if (inferred == null) inferred = "";
        String s = stated.toUpperCase();
        String i = inferred.toUpperCase();
        return s.contains("JSON") || i.contains("JSON") || "JSON".equals(s) || "JSON".equals(i);
    }

    /**
     * 提取 JSON 的 keys（递归，支持顶层 Object 或 Array）。
     * 若为 Array，则遍历元素并收集其内部对象的 keys，用于 keysSimilarity。
     */
    public static Set<String> collectKeys(JsonElement el) {
        Set<String> keys = new HashSet<>();
        collectKeysRecursive(el, keys, 0, 2);
        return keys;
    }

    private static void collectKeysRecursive(JsonElement el, Set<String> keys, int depth, int maxDepth) {
        if (el == null || depth > maxDepth) return;
        if (el.isJsonObject()) {
            for (java.util.Map.Entry<String, JsonElement> e : el.getAsJsonObject().entrySet()) {
                String k = e.getKey();
                keys.add(k != null ? k.toLowerCase() : "");
                collectKeysRecursive(e.getValue(), keys, depth + 1, maxDepth);
            }
        } else if (el.isJsonArray()) {
            for (JsonElement child : el.getAsJsonArray()) {
                collectKeysRecursive(child, keys, depth + 1, maxDepth);
            }
        }
    }

    /**
     * 判断是否为典型的错误响应结构（Keys 以 error 类为主）。
     */
    public static boolean looksLikeErrorResponse(JsonElement el) {
        Set<String> keys = collectKeys(el);
        int errorCount = 0;
        for (String k : keys) {
            if (k == null) continue;
            if (ERROR_INDICATOR_KEYS.contains(k.toLowerCase())) errorCount++;
        }
        return !keys.isEmpty() && errorCount >= 2;
    }

    /**
     * 结构颠覆性变化：一方是业务数据，另一方是错误响应。
     */
    public static boolean hasStructuralShift(JsonElement a, JsonElement b) {
        boolean aError = looksLikeErrorResponse(a);
        boolean bError = looksLikeErrorResponse(b);
        return aError != bError;
    }

    /**
     * Keys 集合 Jaccard 相似度。
     */
    public static double keysSimilarity(Set<String> keysA, Set<String> keysB) {
        if (keysA.isEmpty() && keysB.isEmpty()) return 1.0;
        if (keysA.isEmpty() || keysB.isEmpty()) return 0.0;
        Set<String> intersection = new HashSet<>(keysA);
        intersection.retainAll(keysB);
        Set<String> union = new HashSet<>(keysA);
        union.addAll(keysB);
        return (double) intersection.size() / union.size();
    }

    /**
     * 深度比较两个 JsonElement，忽略 VOLATILE_KEYS 的 value 差异。
     * 支持 JsonArray：数组长度不同即返回 false（如 [A,B] vs [B] 判 DIFFERENT）。
     */
    public static boolean deepEqualsIgnoringVolatile(JsonElement a, JsonElement b) {
        if (a == b) return true;
        if (a == null || b == null) return false;
        if (a.isJsonNull() && b.isJsonNull()) return true;
        if (a.isJsonPrimitive() && b.isJsonPrimitive()) return a.getAsString().equals(b.getAsString());
        if (a.isJsonArray() && b.isJsonArray()) {
            com.google.gson.JsonArray arrA = a.getAsJsonArray();
            com.google.gson.JsonArray arrB = b.getAsJsonArray();
            if (arrA.size() != arrB.size()) return false;
            for (int i = 0; i < arrA.size(); i++) {
                if (!deepEqualsIgnoringVolatile(arrA.get(i), arrB.get(i))) return false;
            }
            return true;
        }
        if (a.isJsonObject() && b.isJsonObject()) {
            JsonObject objA = a.getAsJsonObject();
            JsonObject objB = b.getAsJsonObject();
            Set<String> keysANorm = new HashSet<>();
            for (String k : objA.keySet()) keysANorm.add(k != null ? k.toLowerCase() : "");
            Set<String> keysBNorm = new HashSet<>();
            for (String k : objB.keySet()) keysBNorm.add(k != null ? k.toLowerCase() : "");
            if (!keysANorm.equals(keysBNorm)) return false;
            for (String key : objA.keySet()) {
                if (isVolatileKey(key)) continue;
                String keyB = findKeyIgnoreCase(objB, key);
                if (keyB == null) return false;
                if (!deepEqualsIgnoringVolatile(objA.get(key), objB.get(keyB))) return false;
            }
            return true;
        }
        return false;
    }

    /**
     * 判断 key 是否为 volatile（可忽略 value 差异）。
     */
    public static boolean isVolatileKey(String key) {
        return key != null && VOLATILE_KEYS.contains(key.toLowerCase());
    }

    private static String findKeyIgnoreCase(JsonObject obj, String key) {
        if (key == null) return null;
        String lower = key.toLowerCase();
        for (String k : obj.keySet()) {
            if (k != null && k.toLowerCase().equals(lower)) return k;
        }
        return null;
    }
}
